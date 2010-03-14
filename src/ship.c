/*
    Sylverant Shipgate
    Copyright (C) 2009 Lawrence Sebald

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 3 as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>

#include <openssl/rc4.h>

#include <sylverant/debug.h>
#include <sylverant/database.h>
#include <sylverant/sha4.h>
#include <sylverant/mtwist.h>
#include <sylverant/md5.h>

#include "ship.h"
#include "shipgate.h"

/* Database connection */
extern sylverant_dbconn_t conn;

static uint8_t recvbuf[65536];
static ship_t *ship_list[256] = { NULL };

/* Create a new connection, storing it in the list of ships. */
ship_t *create_connection(int sock, in_addr_t addr) {
    ship_t *rv;
    uint32_t i;

    /* Search for an open ship ID for this ship. */
    for(i = 0; i < 256; ++i) {
        if(ship_list[i] == NULL)
            break;
    }

    if(i == 256) {
        debug(DBG_ERROR, "Out of ship IDs\n");
        return NULL;
    }

    rv = (ship_t *)malloc(sizeof(ship_t));

    if(!rv) {
        perror("malloc");
        return NULL;
    }

    memset(rv, 0, sizeof(ship_t));

    /* Store basic parameters in the client structure. */
    rv->sock = sock;
    rv->conn_addr = addr;
    rv->ship_id = (i << 24) | 0x00FFFFFF;
    rv->last_message = time(NULL);

    for(i = 0; i < 4; ++i) {
        rv->ship_nonce[i] = (uint8_t)genrand_int32();
        rv->gate_nonce[i] = (uint8_t)genrand_int32();
    }

    /* Send the client the welcome packet, or die trying. */
    if(send_welcome(rv)) {
        close(sock);
        free(rv);
        return NULL;
    }

    ship_list[i] = rv;

    /* Insert it at the end of our list, and we're done. */
    TAILQ_INSERT_TAIL(&ships, rv, qentry);
    return rv;
}

/* Destroy a connection, closing the socket and removing it from the list. */
void destroy_connection(ship_t *c) {
    char query[256];
    ship_t *i;

    debug(DBG_LOG, "Closing connection with %s\n", c->name);

    TAILQ_REMOVE(&ships, c, qentry);

    /* Send a status packet to everyone */
    TAILQ_FOREACH(i, &ships, qentry) {
        send_ship_status(i, c->name, c->ship_id, c->remote_addr, c->local_addr,
                         c->port, 0);
    }
    
    /* Clear the online flag for anyone that's online on that ship. */
    sprintf(query, "UPDATE account_data SET islogged='0' WHERE "
            "lastship='%s'", c->name);

    if(sylverant_db_query(&conn, query)) {
        debug(DBG_ERROR, "Couldn't clear logged on flags for %s ship!\n",
              c->name);
    }

    /* Remove the ship from the online_ships table. */
    sprintf(query, "DELETE FROM online_ships WHERE name='%s'", c->name);

    if(sylverant_db_query(&conn, query)) {
        debug(DBG_ERROR, "Couldn't clear %s from the online_ships table\n",
              c->name);
    }

    /* Clear it out from the list of in-use ship IDs. */
    ship_list[c->ship_id >> 24] = NULL;

    /* Clean up the ship's structure. */
    if(c->sock >= 0) {
        close(c->sock);
    }

    if(c->recvbuf) {
        free(c->recvbuf);
    }

    if(c->sendbuf) {
        free(c->sendbuf);
    }

    free(c);
}

/* Handle a ship's login response. */
static int handle_shipgate_login(ship_t *c, shipgate_login_reply_pkt *pkt) {
    char query[256];
    ship_t *j;
    uint8_t key[128], hash[64];
    int idx = ntohs(pkt->ship_key), i;
    void *result;
    char **row;

    /* Attempt to grab the key for this ship. */
    sprintf(query, "SELECT * FROM ship_data WHERE idx='%u'", idx);

    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "Couldn't find ship key for index %d\n", idx);
        return -1;
    }

    if((result = sylverant_db_result_store(&conn)) == NULL ||
       (row = sylverant_db_result_fetch(result)) == NULL) {
        debug(DBG_WARN, "Invalid index %d\n", idx);
        return -1;
    }        

    /* Grab the key from the result */
    memcpy(key, row[0], 128);
    sylverant_db_result_free(result);

    /* Apply the nonces */
    for(i = 0; i < 128; i += 4) {
        key[i + 0] ^= c->gate_nonce[0];
        key[i + 1] ^= c->gate_nonce[1];
        key[i + 2] ^= c->gate_nonce[2];
        key[i + 3] ^= c->gate_nonce[3];
    }

    /* Hash the key with SHA-512, and use that as our final key. */
    sha4(key, 128, hash, 0);
    RC4_set_key(&c->gate_key, 64, hash);

    /* Calculate the final ship key. */
    for(i = 0; i < 128; i += 4) {
        key[i + 0] ^= c->ship_nonce[0];
        key[i + 1] ^= c->ship_nonce[1];
        key[i + 2] ^= c->ship_nonce[2];
        key[i + 3] ^= c->ship_nonce[3];
    }

    /* Hash the key with SHA-512, and use that as our final key. */
    sha4(key, 128, hash, 0);
    RC4_set_key(&c->ship_key, 64, hash);

    c->remote_addr = pkt->ship_addr;
    c->local_addr = pkt->int_addr;
    c->port = ntohs(pkt->ship_port);
    c->key_idx = ntohs(pkt->ship_key);
    c->connections = ntohl(pkt->connections);
    strcpy(c->name, pkt->name);

    sprintf(query, "INSERT INTO online_ships(name, players, ip, port, int_ip, "
            "ship_id) VALUES ('%s', '%d', '%u', '%hu', '%u', '%u')",
            c->name, c->connections,  ntohl(c->remote_addr), c->port,
            ntohl(c->local_addr), c->ship_id);

    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "Couldn't add %s to the online_ships table.\n",
              c->name);
        return -1;
    }

    /* Send a status packet to each of the ships. */
    TAILQ_FOREACH(j, &ships, qentry) {
        send_ship_status(j, c->name, c->ship_id, c->remote_addr, c->local_addr,
                         c->port, 1);

        /* Send this ship to the new ship, as long as that wasn't done just
           above here. */
        if(j != c) {
            send_ship_status(c, j->name, j->ship_id, j->remote_addr,
                             j->local_addr, j->port, 1);
        }
    }

    return 0;
}

/* Handle a ship's update counters packet. */
static int handle_count(ship_t *c, shipgate_cnt_pkt *pkt) {
    char query[256];

    c->connections = (uint32_t)ntohs(pkt->ccnt);

    sprintf(query, "UPDATE online_ships SET players='%u' WHERE name='%s'",
            c->connections, c->name);
    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "Couldn't update ship %s player count", c->name);
    }

    return 0;
}

/* Handle a ship's forwarded Dreamcast packet. */
static int handle_dreamcast(ship_t *c, shipgate_fw_pkt *pkt) {
    uint8_t type = pkt->pkt.pkt_type;
    ship_t *i;
    uint32_t tmp;

    debug(DBG_LOG, "DC: Received %02X\n", type);

    switch(type) {
        case SHIP_GUILD_SEARCH_TYPE:
        case SHIP_SIMPLE_MAIL_TYPE:
            /* Forward these to all ships other than the sender. */
            TAILQ_FOREACH(i, &ships, qentry) {
                if(i != c) {
                    forward_dreamcast(i, &pkt->pkt, c->ship_id);
                }
            }

            return 0;

        case SHIP_DC_GUILD_REPLY_TYPE:
            /* Send this one to the original sender. */
            tmp = ntohl(pkt->ship_id);

            TAILQ_FOREACH(i, &ships, qentry) {
                if(i->ship_id == tmp) {
                    return forward_dreamcast(i, &pkt->pkt, c->ship_id);
                }
            }

            return 0;
    }

    return -2;
}

/* Handle a ship's forwarded PC packet. */
static int handle_pc(ship_t *c, shipgate_fw_pkt *pkt) {
    uint8_t type = pkt->pkt.pkt_type;
    ship_t *i;

    debug(DBG_LOG, "PC: Received %02X\n", type);

    switch(type) {
        case SHIP_SIMPLE_MAIL_TYPE:
            /* Forward these to all ships other than the sender. */
            TAILQ_FOREACH(i, &ships, qentry) {
                if(i != c) {
                    forward_pc(i, &pkt->pkt, c->ship_id);
                }
            }

            return 0;
    }

    return -2;
}

/* Handle a ship's save character data packet. */
static int handle_cdata(ship_t *c, shipgate_char_data_pkt *pkt) {
    uint32_t gc, slot;
    char query[4096];

    gc = ntohl(pkt->guildcard);
    slot = ntohl(pkt->slot);

    /* Delete any character data already exising in that slot. */
    sprintf(query, "DELETE FROM character_data WHERE guildcard='%u' AND "
            "slot='%u'", gc, slot);

    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "Couldn't remove old character data (%u: %u)\n",
              gc, slot);
        /* XXXX: Should send some sort of failure message. */
        return 0;
    }

    /* Build up the store query for it. */
    sprintf(query, "INSERT INTO character_data(guildcard, slot, data) VALUES "
            "('%u', '%u', '", gc, slot);
    sylverant_db_escape_str(&conn, query + strlen(query), (char *)pkt->data,
                            1052);
    strcat(query, "')");

    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "Couldn't save character data (%u: %u)\n", gc, slot);
        /* XXXX: Should send some sort of failure message. */
        return 0;
    }

    return 0;
}

/* Handle a ship's character data request packet. */
static int handle_creq(ship_t *c, shipgate_char_req_pkt *pkt) {
    uint32_t gc, slot;
    char query[256];
    uint8_t data[1052];
    void *result;
    char **row;

    gc = ntohl(pkt->guildcard);
    slot = ntohl(pkt->slot);

    /* Build the query asking for the data. */
    sprintf(query, "SELECT data FROM character_data WHERE guildcard='%u' AND "
            "slot='%u'", gc, slot);

    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "Couldn't fetch character data (%u: %u)\n", gc, slot);
        /* XXXX: Should send some sort of failure message. */
        return 0;
    }

    /* Grab the data we got. */
    if((result = sylverant_db_result_store(&conn)) == NULL) {
        debug(DBG_WARN, "Couldn't fetch character data (%u: %u)\n", gc, slot);
        /* XXXX: Should send some sort of failure message. */
        return 0;
    }

    if((row = sylverant_db_result_fetch(result)) == NULL) {
        sylverant_db_result_free(result);
        debug(DBG_WARN, "No saved character data (%u: %u)\n", gc, slot);
        /* XXXX: Should send some sort of failure message. */
        return 0;
    }

    /* Grab the data from the result */
    memcpy(data, row[0], 1052);
    sylverant_db_result_free(result);

    /* Send the data back to the ship. */
    return send_cdata(c, gc, slot, data);
}

/* Handle a GM login request coming from a ship. */
static int handle_gmlogin(ship_t *c, shipgate_gmlogin_req_pkt *pkt) {
    uint32_t gc, block;
    char query[256];
    uint8_t data[1024];
    void *result;
    char **row;
    int account_id;
    int i;
    unsigned char hash[16];

    gc = ntohl(pkt->guildcard);
    block = ntohl(pkt->block);

    /* Build the query asking for the data. */
    sprintf(query, "SELECT account_id FROM guildcards WHERE guildcard='%u'",
            gc);

    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "Couldn't fetch account id (%u)\n", gc);
        return send_gmreply(c, gc, block, 0);
    }

    /* Grab the data we got. */
    if((result = sylverant_db_result_store(&conn)) == NULL) {
        debug(DBG_WARN, "Couldn't fetch account id (%u)\n", gc);
        return send_gmreply(c, gc, block, 0);
    }

    if((row = sylverant_db_result_fetch(result)) == NULL) {
        sylverant_db_result_free(result);
        debug(DBG_WARN, "No account data (%u)\n", gc);
        return send_gmreply(c, gc, block, 0);
    }

    /* Grab the data from the result */
    account_id = atoi(row[0]);
    sylverant_db_result_free(result);

    /* Now, attempt to fetch the gm status of the account. */
    sprintf(query, "SELECT password, regtime FROM account_data WHERE "
            "account_id='%d' AND username='%s' AND isgm>'0'", account_id,
            pkt->username);

    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "Couldn't lookup account data (%d)\n", account_id);
        return send_gmreply(c, gc, block, 0);
    }

    /* Grab the data we got. */
    if((result = sylverant_db_result_store(&conn)) == NULL) {
        debug(DBG_WARN, "Couldn't fetch account data (%d)\n", account_id);
        return send_gmreply(c, gc, block, 0);
    }

    if((row = sylverant_db_result_fetch(result)) == NULL) {
        sylverant_db_result_free(result);
        debug(DBG_LOG, "Failed GM login - not gm (%s: %d)\n", pkt->username,
              account_id);
        return send_gmreply(c, gc, block, 0);
    }

    /* Check the password. */
    sprintf(query, "%s_%s_salt", pkt->password, row[1]);
    md5(query, strlen(query), hash);

    query[0] = '\0';
    for(i = 0; i < 16; ++i) {
        sprintf(query, "%s%02x", query, hash[i]);
    }

    for(i = 0; i < strlen(row[0]); ++i) {
        row[0][i] = tolower(row[0][i]);
    }

    if(strcmp(row[0], query)) {
        debug(DBG_LOG, "Failed GM login - bad password (%d)\n", account_id);
        return send_gmreply(c, gc, block, 0);
    }

    /* We're done if we got this far. */
    sylverant_db_result_free(result);

    /* Send a success message. */
    return send_gmreply(c, gc, block, 1);
}

/* Handle a ban request coming from a ship. */
static int handle_ban(ship_t *c, shipgate_ban_req_pkt *pkt, uint16_t type) {
    uint32_t req, target, until;
    char query[1024];
    void *result;
    char **row;
    int account_id;
    int id;

    req = ntohl(pkt->req_gc);
    target = ntohl(pkt->target);
    until = ntohl(pkt->until);

    /* Make sure the requester has permission. */
    sprintf(query, "SELECT account_id FROM guildcards NATURAL JOIN "
            "account_data  WHERE guildcard='%u' AND isgm>'0'", req);

    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "Couldn't fetch account data (%u)\n", req);
        return 0;
    }

    /* Grab the data we got. */
    if((result = sylverant_db_result_store(&conn)) == NULL) {
        debug(DBG_WARN, "Couldn't fetch account data (%u)\n", req);
        return 0;
    }

    if((row = sylverant_db_result_fetch(result)) == NULL) {
        sylverant_db_result_free(result);
        debug(DBG_WARN, "No account data or not gm (%u)\n", req);
        return 0;
    }

    /* We've verified they're legit, continue on. */
    account_id = atoi(row[0]);
    sylverant_db_result_free(result);

    /* Build up the ban insert query. */
    sprintf(query, "INSERT INTO bans(enddate, setby, reason) VALUES "
            "('%u', '%u', '", until, account_id);
    sylverant_db_escape_str(&conn, query + strlen(query), (char *)pkt->message,
                            strlen(pkt->message));
    strcat(query, "')");

    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "Could not insert ban into database\n");
        return 0;
    }

    /* Now that we have that, add the ban to the right table... */
    switch(type) {
        case SHDR_TYPE_GCBAN:
            sprintf(query, "INSERT INTO guildcard_bans(ban_id, guildcard) "
                    "VALUES(LAST_INSERT_ID(), '%u')", ntohl(pkt->target));
            break;

        case SHDR_TYPE_IPBAN:
            sprintf(query, "INSERT INTO ip_bans(ban_id, addr) VALUES("
                    "LAST_INSERT_ID(), '%u')", ntohl(pkt->target));
            break;

        default:
            return 0;
    }

    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "Could not insert ban into database (part 2)\n");
        return 0;
    }
    
    return 0;
}

/* Process one ship packet. */
int process_ship_pkt(ship_t *c, shipgate_hdr_t *pkt) {
    uint16_t type = ntohs(pkt->pkt_type);
    uint16_t flags = ntohs(pkt->flags);

    debug(DBG_LOG, "Receieved type 0x%04X\n", type);

    switch(type) {
        case SHDR_TYPE_LOGIN:
            if(!(flags & SHDR_RESPONSE) || !(flags & SHDR_NO_ENCRYPT)) {
                debug(DBG_WARN, "Client sent invalid login response\n");
                return -1;
            }

            return handle_shipgate_login(c, (shipgate_login_reply_pkt *)pkt);

        case SHDR_TYPE_COUNT:
            return handle_count(c, (shipgate_cnt_pkt *)pkt);

        case SHDR_TYPE_DC:
            return handle_dreamcast(c, (shipgate_fw_pkt *)pkt);

        case SHDR_TYPE_PC:
            return handle_pc(c, (shipgate_fw_pkt *)pkt);

        case SHDR_TYPE_PING:
            /* If this is a ping request, reply. Otherwise, ignore it, the work
               has already been done. */
            if(!(flags & SHDR_RESPONSE)) {
                return send_ping(c, 1);
            }

            return 0;

        case SHDR_TYPE_CDATA:
            return handle_cdata(c, (shipgate_char_data_pkt *)pkt);

        case SHDR_TYPE_CREQ:
            return handle_creq(c, (shipgate_char_req_pkt *)pkt);

        case SHDR_TYPE_GMLOGIN:
            return handle_gmlogin(c, (shipgate_gmlogin_req_pkt *)pkt);

        case SHDR_TYPE_GCBAN:
        case SHDR_TYPE_IPBAN:
            return handle_ban(c, (shipgate_ban_req_pkt *)pkt, type);

        default:
            return -3;
    }
}

/* Handle incoming data to the shipgate. */
int handle_pkt(ship_t *c) {
    ssize_t sz;
    uint16_t pkt_sz;
    int rv = 0;
    unsigned char *rbp;
    void *tmp;

    /* If we've got anything buffered, copy it out to the main buffer to make
       the rest of this a bit easier. */
    if(c->recvbuf_cur) {
        memcpy(recvbuf, c->recvbuf, c->recvbuf_cur);
        
    }

    /* Attempt to read, and if we don't get anything, punt. */
    if((sz = recv(c->sock, recvbuf + c->recvbuf_cur, 65536 - c->recvbuf_cur,
                  0)) <= 0) {
        if(sz == -1) {
            perror("recv");
        }

        return -1;
    }

    sz += c->recvbuf_cur;
    c->recvbuf_cur = 0;

    /* As long as what we have is long enough, decrypt it. */
    if(sz >= 8) {
        rbp = recvbuf;

        while(sz >= 8 && rv == 0) {
            /* Grab the packet header so we know what exactly we're looking
               for, in terms of packet length. */
            if(!c->pkt.pkt_type) {
                memcpy(&c->pkt, rbp, 8);
            }

            pkt_sz = htons(c->pkt.pkt_len);

            /* We'll always need a multiple of 8 bytes. */
            if(pkt_sz & 0x07) {
                pkt_sz = (pkt_sz & 0xFFF8) + 8;
            }

            /* Do we have the whole packet? */
            if(sz >= (ssize_t)pkt_sz) {
                /* Yes, we do, decrypt it. */
                if(!(c->pkt.flags & SHDR_NO_ENCRYPT)) {
                    RC4(&c->ship_key, pkt_sz - 8, rbp + 8, rbp + 8);
                }

                memcpy(rbp, &c->pkt, 8);

                /* Pass it onto the correct handler. */
                c->last_message = time(NULL);
                rv = process_ship_pkt(c, (shipgate_hdr_t *)rbp);

                rbp += pkt_sz;
                sz -= pkt_sz;

                c->pkt.pkt_type = c->pkt.pkt_len = 0;
            }
            else {
                /* Nope, we're missing part, break out of the loop, and buffer
                the remaining data. */
                break;
            }
        }
    }

    /* If we've still got something left here, buffer it for the next pass. */
    if(sz) {
        /* Reallocate the recvbuf for the client if its too small. */
        if(c->recvbuf_size < sz) {
            tmp = realloc(c->recvbuf, sz);

            if(!tmp) {
                perror("realloc");
                return -1;
            }

            c->recvbuf = (unsigned char *)tmp;
            c->recvbuf_size = sz;
        }

        memcpy(c->recvbuf, rbp, sz);
        c->recvbuf_cur = sz;
    }
    else {
        /* Free the buffer, if we've got nothing in it. */
        free(c->recvbuf);
        c->recvbuf = NULL;
        c->recvbuf_size = 0;
    }

    return rv;
}
