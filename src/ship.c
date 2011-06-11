/*
    Sylverant Shipgate
    Copyright (C) 2009, 2010, 2011 Lawrence Sebald

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License version 3
    as published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <ctype.h>
#include <errno.h>
#include <sys/socket.h>

#include <openssl/rc4.h>
#include <openssl/sha.h>

#include <sylverant/debug.h>
#include <sylverant/database.h>
#include <sylverant/mtwist.h>
#include <sylverant/md5.h>

#include "ship.h"
#include "shipgate.h"

#define CLIENT_PRIV_LOCAL_GM    0x00000001
#define CLIENT_PRIV_GLOBAL_GM   0x00000002
#define CLIENT_PRIV_LOCAL_ROOT  0x00000004
#define CLIENT_PRIV_GLOBAL_ROOT 0x00000008

/* Database connection */
extern sylverant_dbconn_t conn;

static uint8_t recvbuf[65536];

/* Find a ship by its id */
static ship_t *find_ship(uint16_t id) {
    ship_t *i;

    TAILQ_FOREACH(i, &ships, qentry) {
        if(i->key_idx == id) {
            return i;
        }
    }

    return NULL;
}

static inline void pack_ipv6(struct in6_addr *addr, uint64_t *hi,
                             uint64_t *lo) {
    *hi = ((uint64_t)addr->s6_addr[0] << 56) |
        ((uint64_t)addr->s6_addr[1] << 48) |
        ((uint64_t)addr->s6_addr[2] << 40) |
        ((uint64_t)addr->s6_addr[3] << 32) |
        ((uint64_t)addr->s6_addr[4] << 24) |
        ((uint64_t)addr->s6_addr[5] << 16) |
        ((uint64_t)addr->s6_addr[6] << 8) |
        ((uint64_t)addr->s6_addr[7]);
    *lo = ((uint64_t)addr->s6_addr[8] << 56) |
        ((uint64_t)addr->s6_addr[9] << 48) |
        ((uint64_t)addr->s6_addr[10] << 40) |
        ((uint64_t)addr->s6_addr[11] << 32) |
        ((uint64_t)addr->s6_addr[12] << 24) |
        ((uint64_t)addr->s6_addr[13] << 16) |
        ((uint64_t)addr->s6_addr[14] << 8) |
        ((uint64_t)addr->s6_addr[15]);
}

/* Create a new connection, storing it in the list of ships. */
ship_t *create_connection(int sock, struct sockaddr *addr, socklen_t size) {
    ship_t *rv;
    uint32_t i;

    rv = (ship_t *)malloc(sizeof(ship_t));

    if(!rv) {
        perror("malloc");
        return NULL;
    }

    memset(rv, 0, sizeof(ship_t));

    /* Store basic parameters in the client structure. */
    rv->sock = sock;
    rv->last_message = time(NULL);
    memcpy(&rv->conn_addr, addr, size);

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

    if(c->key_idx) {
        /* Send a status packet to everyone telling them its gone away */
        TAILQ_FOREACH(i, &ships, qentry) {
            send_ship_status(i, c, 0);
        }

        /* Remove the ship from the online_ships table. */
        sprintf(query, "DELETE FROM online_ships WHERE ship_id='%hu'",
                c->key_idx);

        if(sylverant_db_query(&conn, query)) {
            debug(DBG_ERROR, "Couldn't clear %s from the online_ships table\n",
                  c->name);
        }

        /* Remove any clients in the online_clients table on that ship */
        sprintf(query, "DELETE FROM online_clients WHERE ship_id='%hu'",
                c->key_idx);

        if(sylverant_db_query(&conn, query)) {
            debug(DBG_ERROR, "Couldn't clear %s online_clients\n", c->name);
        }
    }

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
    int k = ntohs(pkt->ship_key), i;
    void *result;
    char **row;
    uint32_t pver = c->proto_ver = ntohl(pkt->proto_ver);
    uint16_t menu_code = ntohs(pkt->menu_code);
    int ship_number;

    /* Check the protocol version for support (packet dropped in v7) */
    if(pver < SHIPGATE_MINIMUM_PROTO_VER || pver > 6) {
        debug(DBG_WARN, "Invalid protocol version (old login): %lu\n", pver);

        send_error(c, SHDR_TYPE_LOGIN, SHDR_RESPONSE | SHDR_FAILURE,
                   ERR_LOGIN_BAD_PROTO, NULL, 0);
        return -1;
    }

    /* Attempt to grab the key for this ship. */
    sprintf(query, "SELECT rc4key, main_menu, ship_number FROM ship_data WHERE "
            "idx='%u'", k);

    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "Couldn't query the database\n");
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));
        send_error(c, SHDR_TYPE_LOGIN, SHDR_RESPONSE | SHDR_FAILURE,
                   ERR_BAD_ERROR, NULL, 0);
        return -1;
    }

    if((result = sylverant_db_result_store(&conn)) == NULL ||
       (row = sylverant_db_result_fetch(result)) == NULL) {
        debug(DBG_WARN, "Invalid index %d\n", k);
        send_error(c, SHDR_TYPE_LOGIN, SHDR_RESPONSE | SHDR_FAILURE,
                   ERR_LOGIN_BAD_KEY, NULL, 0);
        return -1;
    }

    /* Check the menu code for validity */
    if(menu_code && (!isalpha(menu_code & 0xFF) | !isalpha(menu_code >> 8))) {
        debug(DBG_WARN, "Bad menu code for id: %d\n", k);
        send_error(c, SHDR_TYPE_LOGIN, SHDR_RESPONSE | SHDR_FAILURE,
                   ERR_LOGIN_BAD_MENU, NULL, 0);
        return -1;
    }

    /* If the ship requests the main menu and they aren't allowed there, bail */
    if(!menu_code && !atoi(row[1])) {
        debug(DBG_WARN, "Invalid menu code for id: %d\n", k);
        send_error(c, SHDR_TYPE_LOGIN, SHDR_RESPONSE | SHDR_FAILURE,
                   ERR_LOGIN_INVAL_MENU, NULL, 0);
        return -1;
    }

    /* Grab the key from the result */
    memcpy(key, row[0], 128);
    ship_number = atoi(row[2]);
    sylverant_db_result_free(result);

    /* Apply the nonces */
    for(i = 0; i < 128; i += 4) {
        key[i + 0] ^= c->gate_nonce[0];
        key[i + 1] ^= c->gate_nonce[1];
        key[i + 2] ^= c->gate_nonce[2];
        key[i + 3] ^= c->gate_nonce[3];
    }

    /* Hash the key with SHA-512, and use that as our final key. */
    SHA512(key, 128, hash);
    RC4_set_key(&c->gate_key, 64, hash);

    /* Calculate the final ship key. */
    for(i = 0; i < 128; i += 4) {
        key[i + 0] ^= c->ship_nonce[0];
        key[i + 1] ^= c->ship_nonce[1];
        key[i + 2] ^= c->ship_nonce[2];
        key[i + 3] ^= c->ship_nonce[3];
    }

    /* Hash the key with SHA-512, and use that as our final key. */
    SHA512(key, 128, hash);
    RC4_set_key(&c->ship_key, 64, hash);

    c->remote_addr = pkt->ship_addr;
    c->port = ntohs(pkt->ship_port);
    c->key_idx = k;
    c->clients = ntohs(pkt->clients);
    c->games = ntohs(pkt->games);
    c->flags = ntohl(pkt->flags);
    c->menu_code = menu_code;
    strcpy(c->name, pkt->name);
    c->ship_number = ship_number;

    sprintf(query, "INSERT INTO online_ships(name, players, ip, port, int_ip, "
            "ship_id, gm_only, games, menu_code, flags, ship_number) VALUES "
            "('%s', '%hu', '%u', '%hu', '%u', '%u', '%d', '%hu', '%hu', '%u', "
            "'%d')", c->name, c->clients, ntohl(c->remote_addr), c->port, 0,
            c->key_idx, !!(c->flags & LOGIN_FLAG_GMONLY), c->games,
            c->menu_code, c->flags, ship_number);

    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "Couldn't add %s to the online_ships table.\n",
              c->name);
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));
        c->key_set = 0;
        send_error(c, SHDR_TYPE_LOGIN, SHDR_RESPONSE | SHDR_FAILURE,
                   ERR_BAD_ERROR, NULL, 0);
        return -1;
    }

    /* Hooray for misusing functions! */
    if(send_error(c, SHDR_TYPE_LOGIN, SHDR_RESPONSE, ERR_NO_ERROR, NULL, 0)) {
        return -1;
    }
    else {
        c->key_set = 1;
    }

    /* Send a status packet to each of the ships. */
    TAILQ_FOREACH(j, &ships, qentry) {
        send_ship_status(j, c, 1);

        /* Send this ship to the new ship, as long as that wasn't done just
           above here. */
        if(j != c) {
            send_ship_status(c, j, 1);
        }
    }

    return 0;
}

/* Handle a ship's login response (with IPv6 support!). */
static int handle_shipgate_login6(ship_t *c, shipgate_login6_reply_pkt *pkt) {
    char query[256];
    ship_t *j;
    uint8_t key[128], hash[64];
    int k = ntohs(pkt->ship_key), i;
    void *result;
    char **row;
    uint32_t pver = c->proto_ver = ntohl(pkt->proto_ver);
    uint16_t menu_code = ntohs(pkt->menu_code);
    int ship_number;
    uint64_t ip6_hi, ip6_lo;

    /* Check the protocol version for support (first supported in v7) */
    if(pver < 7 || pver > SHIPGATE_MAXIMUM_PROTO_VER) {
        debug(DBG_WARN, "Invalid protocol version: %lu\n", pver);

        send_error(c, SHDR_TYPE_LOGIN6, SHDR_RESPONSE | SHDR_FAILURE,
                   ERR_LOGIN_BAD_PROTO, NULL, 0);
        return -1;
    }

    /* Attempt to grab the key for this ship. */
    sprintf(query, "SELECT rc4key, main_menu, ship_number FROM ship_data WHERE "
            "idx='%u'", k);

    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "Couldn't query the database\n");
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));
        send_error(c, SHDR_TYPE_LOGIN6, SHDR_RESPONSE | SHDR_FAILURE,
                   ERR_BAD_ERROR, NULL, 0);
        return -1;
    }

    if((result = sylverant_db_result_store(&conn)) == NULL ||
       (row = sylverant_db_result_fetch(result)) == NULL) {
        debug(DBG_WARN, "Invalid index %d\n", k);
        send_error(c, SHDR_TYPE_LOGIN6, SHDR_RESPONSE | SHDR_FAILURE,
                   ERR_LOGIN_BAD_KEY, NULL, 0);
        return -1;
    }

    /* Check the menu code for validity */
    if(menu_code && (!isalpha(menu_code & 0xFF) | !isalpha(menu_code >> 8))) {
        debug(DBG_WARN, "Bad menu code for id: %d\n", k);
        send_error(c, SHDR_TYPE_LOGIN6, SHDR_RESPONSE | SHDR_FAILURE,
                   ERR_LOGIN_BAD_MENU, NULL, 0);
        return -1;
    }

    /* If the ship requests the main menu and they aren't allowed there, bail */
    if(!menu_code && !atoi(row[1])) {
        debug(DBG_WARN, "Invalid menu code for id: %d\n", k);
        send_error(c, SHDR_TYPE_LOGIN6, SHDR_RESPONSE | SHDR_FAILURE,
                   ERR_LOGIN_INVAL_MENU, NULL, 0);
        return -1;
    }

    /* Grab the key from the result */
    memcpy(key, row[0], 128);
    ship_number = atoi(row[2]);
    sylverant_db_result_free(result);

    /* Apply the nonces */
    for(i = 0; i < 128; i += 4) {
        key[i + 0] ^= c->gate_nonce[0];
        key[i + 1] ^= c->gate_nonce[1];
        key[i + 2] ^= c->gate_nonce[2];
        key[i + 3] ^= c->gate_nonce[3];
    }

    /* Hash the key with SHA-512, and use that as our final key. */
    SHA512(key, 128, hash);
    RC4_set_key(&c->gate_key, 64, hash);

    /* Calculate the final ship key. */
    for(i = 0; i < 128; i += 4) {
        key[i + 0] ^= c->ship_nonce[0];
        key[i + 1] ^= c->ship_nonce[1];
        key[i + 2] ^= c->ship_nonce[2];
        key[i + 3] ^= c->ship_nonce[3];
    }

    /* Hash the key with SHA-512, and use that as our final key. */
    SHA512(key, 128, hash);
    RC4_set_key(&c->ship_key, 64, hash);

    c->remote_addr = pkt->ship_addr4;
    memcpy(&c->remote_addr6, pkt->ship_addr6, 16);
    c->port = ntohs(pkt->ship_port);
    c->key_idx = k;
    c->clients = ntohs(pkt->clients);
    c->games = ntohs(pkt->games);
    c->flags = ntohl(pkt->flags);
    c->menu_code = menu_code;
    memcpy(c->name, pkt->name, 12);
    c->ship_number = ship_number;

    pack_ipv6(&c->remote_addr6, &ip6_hi, &ip6_lo);

    sprintf(query, "INSERT INTO online_ships(name, players, ip, port, int_ip, "
            "ship_id, gm_only, games, menu_code, flags, ship_number, "
            "ship_ip6_high, ship_ip6_low) VALUES ('%s', '%hu', '%u', '%hu', "
            "'%u', '%u', '%d', '%hu', '%hu', '%u', '%d', '%llu', '%llu')",
            c->name, c->clients, ntohl(c->remote_addr), c->port, 0, c->key_idx,
            !!(c->flags & LOGIN_FLAG_GMONLY), c->games, c->menu_code, c->flags,
            ship_number, (unsigned long long)ip6_hi,
            (unsigned long long) ip6_lo);

    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "Couldn't add %s to the online_ships table.\n",
              c->name);
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));
        c->key_set = 0;
        send_error(c, SHDR_TYPE_LOGIN6, SHDR_RESPONSE | SHDR_FAILURE,
                   ERR_BAD_ERROR, NULL, 0);
        return -1;
    }

    /* Hooray for misusing functions! */
    if(send_error(c, SHDR_TYPE_LOGIN6, SHDR_RESPONSE, ERR_NO_ERROR, NULL, 0)) {
        return -1;
    }
    else {
        c->key_set = 1;
    }

    /* Send a status packet to each of the ships. */
    TAILQ_FOREACH(j, &ships, qentry) {
        send_ship_status(j, c, 1);

        /* Send this ship to the new ship, as long as that wasn't done just
           above here. */
        if(j != c) {
            send_ship_status(c, j, 1);
        }
    }

    return 0;
}


/* Handle a ship's update counters packet. */
static int handle_count(ship_t *c, shipgate_cnt_pkt *pkt) {
    char query[256];
    ship_t *j;

    c->clients = ntohs(pkt->clients);
    c->games = ntohs(pkt->games);

    sprintf(query, "UPDATE online_ships SET players='%hu', games='%hu' WHERE "
            "ship_id='%u'", c->clients, c->games, c->key_idx);
    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "Couldn't update ship %s player/game count", c->name);
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));
    }

    /* Update all of the ships */
    TAILQ_FOREACH(j, &ships, qentry) {
        send_counts(j, c->key_idx, c->clients, c->games);
    }

    return 0;
}

static int handle_dc_mail(ship_t *c, dc_simple_mail_pkt *pkt) {
    uint32_t guildcard = LE32(pkt->gc_dest);
    char query[256];
    void *result;
    char **row;
    uint16_t ship_id;
    ship_t *s;

    /* Figure out where the user requested is */
    sprintf(query, "SELECT ship_id FROM online_clients WHERE guildcard='%u'",
            guildcard);
    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "DC Mail Error: %s", sylverant_db_error(&conn));
        return 0;
    }

    /* Grab the data we got. */
    if((result = sylverant_db_result_store(&conn)) == NULL) {
        debug(DBG_WARN, "Couldn't fetch DC mail result: %s\n",
              sylverant_db_error(&conn));
        return 0;
    }

    if(!(row = sylverant_db_result_fetch(result))) {
        /* Either the user is not online or we're dealing with a ship that does
           not support protocol v2, send the packet to any protocol v1 ships,
           just to be sure... */
        sylverant_db_result_free(result);

        TAILQ_FOREACH(s, &ships, qentry) {
            if(s != c && !(s->flags & LOGIN_FLAG_PROXY) && s->proto_ver < 2) {
                forward_dreamcast(s, (dc_pkt_hdr_t *)pkt, c->key_idx);
            }
        }

        return 0;
    }

    /* Grab the data from the result */
    errno = 0;
    ship_id = (uint16_t)strtoul(row[0], NULL, 0);
    sylverant_db_result_free(result);

    if(errno) {
        debug(DBG_WARN, "Error parsing in dc mail: %s", strerror(errno));
        return 0;
    }

    /* If we've got this far, we should have the ship we need to send to */
    s = find_ship(ship_id);
    if(!s) {
        debug(DBG_WARN, "Invalid ship?!?!\n");
        return 0;
    }

    /* Send it on, and finish up... */
    forward_dreamcast(s, (dc_pkt_hdr_t *)pkt, c->key_idx);
    return 0;
}

static int handle_pc_mail(ship_t *c, pc_simple_mail_pkt *pkt) {
    uint32_t guildcard = LE32(pkt->gc_dest);
    char query[256];
    void *result;
    char **row;
    uint16_t ship_id;
    ship_t *s;

    /* Figure out where the user requested is */
    sprintf(query, "SELECT ship_id FROM online_clients WHERE guildcard='%u'",
            guildcard);
    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "PC Mail Error: %s", sylverant_db_error(&conn));
        return 0;
    }

    /* Grab the data we got. */
    if((result = sylverant_db_result_store(&conn)) == NULL) {
        debug(DBG_WARN, "Couldn't fetch PC mail result: %s\n",
              sylverant_db_error(&conn));
        return 0;
    }

    if(!(row = sylverant_db_result_fetch(result))) {
        /* Either the user is not online or we're dealing with a ship that does
           not support protocol v2, send the packet to any protocol v1 ships,
           just to be sure... */
        sylverant_db_result_free(result);

        TAILQ_FOREACH(s, &ships, qentry) {
            if(s != c && !(s->flags & LOGIN_FLAG_PROXY) && s->proto_ver < 2) {
                forward_pc(s, (dc_pkt_hdr_t *)pkt, c->key_idx);
            }
        }

        return 0;
    }

    /* Grab the data from the result */
    errno = 0;
    ship_id = (uint16_t)strtoul(row[0], NULL, 0);
    sylverant_db_result_free(result);

    if(errno) {
        debug(DBG_WARN, "Error parsing in pc mail: %s", strerror(errno));
        return 0;
    }

    /* If we've got this far, we should have the ship we need to send to */
    s = find_ship(ship_id);
    if(!s) {
        debug(DBG_WARN, "Invalid ship?!?!?\n");
        return 0;
    }

    /* Send it on, and finish up... */
    forward_pc(s, (dc_pkt_hdr_t *)pkt, c->key_idx);
    return 0;
}

static int handle_guild_search(ship_t *c, dc_guild_search_pkt *pkt) {
    uint32_t guildcard = LE32(pkt->gc_target);
    char query[512];
    void *result;
    char **row;
    uint16_t ship_id, port;
    uint32_t lobby_id, ip, block;
    ship_t *s;
    dc_guild_reply_pkt reply;

    /* Figure out where the user requested is */
    sprintf(query, "SELECT online_clients.name, online_clients.ship_id, block, "
            "lobby, lobby_id, online_ships.name, ip, port, gm_only "
            "FROM online_clients INNER JOIN online_ships ON "
            "online_clients.ship_id = online_ships.ship_id WHERE "
            "guildcard='%u'", guildcard);
    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "Guild Search Error: %s\n", sylverant_db_error(&conn));
        return 0;
    }

    /* Grab the data we got. */
    if((result = sylverant_db_result_store(&conn)) == NULL) {
        debug(DBG_WARN, "Couldn't fetch Guild Search result: %s\n",
              sylverant_db_error(&conn));
        return 0;
    }

    if(!(row = sylverant_db_result_fetch(result))) {
        /* Either the user is not online or we're dealing with a ship that does
           not support protocol v2, send the packet to any protocol v1 ships,
           just to be sure... */
        TAILQ_FOREACH(s, &ships, qentry) {
            if(s != c && !(s->flags & LOGIN_FLAG_PROXY) && s->proto_ver < 2) {
                forward_dreamcast(s, (dc_pkt_hdr_t *)pkt, c->key_idx);
            }
        }

        goto out;
    }

    /* Make sure the user isn't on a GM only ship... if they are, bail now */
    if(atoi(row[9])) {
        goto out;
    }

    /* Grab the ship we're looking at first */
    errno = 0;
    ship_id = (uint16_t)strtoul(row[1], NULL, 0);

    if(errno) {
        debug(DBG_WARN, "Error parsing in guild ship: %s", strerror(errno));
        goto out;
    }

    /* If we've got this far, we should have the ship we need to send to */
    s = find_ship(ship_id);
    if(!s) {
        debug(DBG_WARN, "Invalid ship?!?!?!\n");
        goto out;
    }

    /* If either of these are NULL, either the ship doesn't have protocol v3
       support, or the user is not in a lobby, check which it is. If the former,
       forward the packet to it, so it can answer. If the latter, then the
       client doesn't really exist just yet. */
    if(row[4] == NULL || row[3] == NULL) {
        if(s->proto_ver < 3) {
            forward_dreamcast(s, (dc_pkt_hdr_t *)pkt, c->key_idx);
        }

        goto out;
    }

    /* Grab the data from the result */
    port = (uint16_t)strtoul(row[7], NULL, 0);
    block = (uint32_t)strtoul(row[2], NULL, 0);
    lobby_id = (uint32_t)strtoul(row[4], NULL, 0);
    ip = (uint32_t)strtoul(row[6], NULL, 0);

    if(errno) {
        debug(DBG_WARN, "Error parsing in guild search: %s", strerror(errno));
        goto out;
    }

    /* Set up the reply, we should have enough data now */
    memset(&reply, 0, DC_GUILD_REPLY_LENGTH);

    /* Fill it in */
    reply.hdr.pkt_type = GUILD_REPLY_TYPE;
    reply.hdr.pkt_len = LE16(DC_GUILD_REPLY_LENGTH);
    reply.tag = LE32(0x00010000);
    reply.gc_search = pkt->gc_search;
    reply.gc_target = pkt->gc_target;
    reply.ip = htonl(ip);
    reply.port = LE16((port + block * 4));
    reply.menu_id = LE32(0xFFFFFFFF);
    reply.item_id = LE32(lobby_id);
    strcpy(reply.name, row[0]);

    if(row[3][0] == '\t') {
        sprintf(reply.location, "%s,BLOCK%02d,%s", row[3], block, row[5]);
    }
    else {
        sprintf(reply.location, "\tE%s,BLOCK%02d,%s", row[3], block, row[5]);
    }

    /* Send it away */
    forward_dreamcast(c, (dc_pkt_hdr_t *)&reply, c->key_idx);

out:
    /* Finally, we're finished, clean up and return! */
    sylverant_db_result_free(result);
    return 0;
}

/* Handle a ship's forwarded Dreamcast packet. */
static int handle_dreamcast(ship_t *c, shipgate_fw_pkt *pkt) {
    dc_pkt_hdr_t *hdr = (dc_pkt_hdr_t *)pkt->pkt;
    uint8_t type = hdr->pkt_type;
    ship_t *i;
    uint32_t tmp;

    switch(type) {
        case GUILD_SEARCH_TYPE:
            return handle_guild_search(c, (dc_guild_search_pkt *)hdr);

        case SIMPLE_MAIL_TYPE:
            return handle_dc_mail(c, (dc_simple_mail_pkt *)hdr);

        case GUILD_REPLY_TYPE:
            /* We shouldn't get these anymore if a ship supports protocol v3 or
               higher, since we shouldn't have sent them... */
            if(c->proto_ver > 2) {
                return -1;
            }

            /* Send this one to the original sender. */
            tmp = ntohl(pkt->ship_id);

            TAILQ_FOREACH(i, &ships, qentry) {
                if(i->key_idx == tmp) {
                    return forward_dreamcast(i, hdr, c->key_idx);
                }
            }

            return 0;

        default:
            /* Warn the ship that sent the packet, then drop it */
            send_error(c, SHDR_TYPE_DC, SHDR_FAILURE, ERR_GAME_UNK_PACKET,
                       (uint8_t *)pkt, ntohs(pkt->hdr.pkt_len));
            return 0;
    }
}

/* Handle a ship's forwarded PC packet. */
static int handle_pc(ship_t *c, shipgate_fw_pkt *pkt) {
    dc_pkt_hdr_t *hdr = (dc_pkt_hdr_t *)pkt->pkt;
    uint8_t type = hdr->pkt_type;

    switch(type) {
        case SIMPLE_MAIL_TYPE:
            return handle_pc_mail(c, (pc_simple_mail_pkt *)hdr);

        default:
            /* Warn the ship that sent the packet, then drop it */
            send_error(c, SHDR_TYPE_PC, SHDR_FAILURE, ERR_GAME_UNK_PACKET,
                       (uint8_t *)pkt, ntohs(pkt->hdr.pkt_len));
            return 0;
    }
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
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));

        send_error(c, SHDR_TYPE_CDATA, SHDR_RESPONSE | SHDR_FAILURE,
                   ERR_BAD_ERROR, (uint8_t *)&pkt->guildcard, 8);
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
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));

        send_error(c, SHDR_TYPE_CDATA, SHDR_RESPONSE | SHDR_FAILURE,
                   ERR_BAD_ERROR, (uint8_t *)&pkt->guildcard, 8);
        return 0;
    }

    /* Return success (yeah, bad use of this function, but whatever). */
    return send_error(c, SHDR_TYPE_CDATA, SHDR_RESPONSE, ERR_NO_ERROR,
                      (uint8_t *)&pkt->guildcard, 8);
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
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));

        send_error(c, SHDR_TYPE_CREQ, SHDR_RESPONSE | SHDR_FAILURE,
                   ERR_BAD_ERROR, (uint8_t *)&pkt->guildcard, 8);
        return 0;
    }

    /* Grab the data we got. */
    if((result = sylverant_db_result_store(&conn)) == NULL) {
        debug(DBG_WARN, "Couldn't fetch character data (%u: %u)\n", gc, slot);
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));

        send_error(c, SHDR_TYPE_CREQ, SHDR_RESPONSE | SHDR_FAILURE,
                   ERR_BAD_ERROR, (uint8_t *)&pkt->guildcard, 8);
        return 0;
    }

    if((row = sylverant_db_result_fetch(result)) == NULL) {
        sylverant_db_result_free(result);
        debug(DBG_WARN, "No saved character data (%u: %u)\n", gc, slot);
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));

        send_error(c, SHDR_TYPE_CREQ, SHDR_RESPONSE | SHDR_FAILURE,
                   ERR_CREQ_NO_DATA, (uint8_t *)&pkt->guildcard, 8);
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
    void *result;
    char **row;
    int account_id;
    int i;
    unsigned char hash[16];
    uint8_t priv;

    gc = ntohl(pkt->guildcard);
    block = ntohl(pkt->block);

    /* Build the query asking for the data. */
    sprintf(query, "SELECT account_id FROM guildcards WHERE guildcard='%u'",
            gc);

    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "Couldn't fetch account id (%u)\n", gc);
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));

        return send_error(c, SHDR_TYPE_GMLOGIN, SHDR_FAILURE, ERR_BAD_ERROR,
                          (uint8_t *)&pkt->guildcard, 8);
    }

    /* Grab the data we got. */
    if((result = sylverant_db_result_store(&conn)) == NULL) {
        debug(DBG_WARN, "Couldn't fetch account id (%u)\n", gc);
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));

        return send_error(c, SHDR_TYPE_GMLOGIN, SHDR_FAILURE, ERR_BAD_ERROR,
                          (uint8_t *)&pkt->guildcard, 8);
    }

    if((row = sylverant_db_result_fetch(result)) == NULL) {
        sylverant_db_result_free(result);
        debug(DBG_WARN, "No account data (%u)\n", gc);

        return send_error(c, SHDR_TYPE_GMLOGIN, SHDR_FAILURE,
                          ERR_GMLOGIN_NO_ACC, (uint8_t *)&pkt->guildcard, 8);
    }

    /* Grab the data from the result */
    account_id = atoi(row[0]);
    sylverant_db_result_free(result);

    /* Now, attempt to fetch the gm status of the account. */
    sprintf(query, "SELECT password, regtime, privlevel FROM account_data WHERE"
            " account_id='%d' AND username='%s'", account_id, pkt->username);

    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "Couldn't lookup account data (%d)\n", account_id);
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));

        return send_error(c, SHDR_TYPE_GMLOGIN, SHDR_FAILURE, ERR_BAD_ERROR,
                          (uint8_t *)&pkt->guildcard, 8);
    }

    /* Grab the data we got. */
    if((result = sylverant_db_result_store(&conn)) == NULL) {
        debug(DBG_WARN, "Couldn't fetch account data (%d)\n", account_id);
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));

        return send_error(c, SHDR_TYPE_GMLOGIN, SHDR_FAILURE, ERR_BAD_ERROR,
                          (uint8_t *)&pkt->guildcard, 8);
    }

    if((row = sylverant_db_result_fetch(result)) == NULL) {
        sylverant_db_result_free(result);
        debug(DBG_LOG, "Failed login - no data? (%s: %d)\n", pkt->username,
              account_id);

        return send_error(c, SHDR_TYPE_GMLOGIN, SHDR_FAILURE,
                          ERR_GMLOGIN_NOT_GM, (uint8_t *)&pkt->guildcard, 8);
    }

    /* Check the password. */
    sprintf(query, "%s_%s_salt", pkt->password, row[1]);
    md5((unsigned char *)query, strlen(query), hash);

    query[0] = '\0';
    for(i = 0; i < 16; ++i) {
        sprintf(query, "%s%02x", query, hash[i]);
    }

    for(i = 0; i < strlen(row[0]); ++i) {
        row[0][i] = tolower(row[0][i]);
    }

    if(strcmp(row[0], query)) {
        debug(DBG_LOG, "Failed login - bad password (%d)\n", account_id);
        sylverant_db_result_free(result);

        return send_error(c, SHDR_TYPE_GMLOGIN, SHDR_FAILURE, ERR_BAD_ERROR,
                          (uint8_t *)&pkt->guildcard, 8);
    }

    /* Grab the privilege level out of the packet */
    priv = (uint8_t)atoi(row[2]);

    /* Filter out any privileges that don't make sense. Can't have global GM
       without local GM support. Also, anyone set as a root this way must have
       BOTH root bits set, not just one! */
    if(((priv & CLIENT_PRIV_GLOBAL_GM) && !(priv & CLIENT_PRIV_LOCAL_GM)) ||
       ((priv & CLIENT_PRIV_GLOBAL_ROOT) && !(priv & CLIENT_PRIV_LOCAL_ROOT)) ||
       ((priv & CLIENT_PRIV_LOCAL_ROOT) && !(priv & CLIENT_PRIV_GLOBAL_ROOT))) {
        debug(DBG_WARN, "Invalid privileges on account %d: %02x\n", account_id,
              priv);
        sylverant_db_result_free(result);

        return send_error(c, SHDR_TYPE_GMLOGIN, SHDR_FAILURE, ERR_BAD_ERROR,
                          (uint8_t *)&pkt->guildcard, 8);
    }

    /* We're done if we got this far. */
    sylverant_db_result_free(result);

    /* Send a success message. */
    return send_gmreply(c, gc, block, 1, priv);
}

/* Handle a ban request coming from a ship. */
static int handle_ban(ship_t *c, shipgate_ban_req_pkt *pkt, uint16_t type) {
    uint32_t req, target, until;
    char query[1024];
    void *result;
    char **row;
    int account_id;
    int priv, priv2;

    req = ntohl(pkt->req_gc);
    target = ntohl(pkt->target);
    until = ntohl(pkt->until);

    /* Make sure the requester has permission. */
    sprintf(query, "SELECT account_id, privlevel FROM guildcards NATURAL JOIN "
            "account_data WHERE guildcard='%u' AND privlevel>'2'", req);

    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "Couldn't fetch account data (%u)\n", req);
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));

        return send_error(c, type, SHDR_FAILURE, ERR_BAD_ERROR, 
                          (uint8_t *)&pkt->req_gc, 16);
    }

    /* Grab the data we got. */
    if((result = sylverant_db_result_store(&conn)) == NULL) {
        debug(DBG_WARN, "Couldn't fetch account data (%u)\n", req);
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));

        return send_error(c, type, SHDR_FAILURE, ERR_BAD_ERROR,
                          (uint8_t *)&pkt->req_gc, 16);
    }

    if((row = sylverant_db_result_fetch(result)) == NULL) {
        sylverant_db_result_free(result);
        debug(DBG_WARN, "No account data or not gm (%u)\n", req);

        return send_error(c, type, SHDR_FAILURE, ERR_BAN_NOT_GM,
                          (uint8_t *)&pkt->req_gc, 16);
    }

    /* We've verified they're legit, continue on. */
    account_id = atoi(row[0]);
    priv = atoi(row[1]);
    sylverant_db_result_free(result);

    /* Make sure the user isn't trying to ban someone with a higher privilege
       level than them... */
    sprintf(query, "SELECT privlevel FROM guildcards NATURAL JOIN account_data "
            "WHERE guildcard='%u'", target);

    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "Couldn't fetch account data (%u)\n", target);
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));

        return send_error(c, type, SHDR_FAILURE, ERR_BAD_ERROR, 
                          (uint8_t *)&pkt->req_gc, 16);
    }

    /* Grab the data we got. */
    if((result = sylverant_db_result_store(&conn)) == NULL) {
        debug(DBG_WARN, "Couldn't fetch account data (%u)\n", target);
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));

        return send_error(c, type, SHDR_FAILURE, ERR_BAD_ERROR,
                          (uint8_t *)&pkt->req_gc, 16);
    }

    if((row = sylverant_db_result_fetch(result))) {
        priv2 = atoi(row[0]);

        if(priv2 >= priv) {
            sylverant_db_result_free(result);
            debug(DBG_WARN, "Attempt by %u to ban %u overturned by privilege\n",
                  req, target);

            return send_error(c, type, SHDR_FAILURE, ERR_BAN_PRIVILEGE,
                              (uint8_t *)&pkt->req_gc, 16);
        }
    }

    /* We're done with that... */
    sylverant_db_result_free(result);

    /* Build up the ban insert query. */
    sprintf(query, "INSERT INTO bans(enddate, setby, reason) VALUES "
            "('%u', '%u', '", until, account_id);
    sylverant_db_escape_str(&conn, query + strlen(query), (char *)pkt->message,
                            strlen(pkt->message));
    strcat(query, "')");

    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "Could not insert ban into database\n");
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));

        return send_error(c, type, SHDR_FAILURE, ERR_BAD_ERROR,
                          (uint8_t *)&pkt->req_gc, 16);
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
            return send_error(c, type, SHDR_FAILURE, ERR_BAN_BAD_TYPE,
                              (uint8_t *)&pkt->req_gc, 16);
    }

    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "Could not insert ban into database (part 2)\n");
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));

        return send_error(c, type, SHDR_FAILURE, ERR_BAD_ERROR, 
                          (uint8_t *)&pkt->req_gc, 16);
    }

    /* Another misuse of the error function, but whatever */
    return send_error(c, type, SHDR_RESPONSE, ERR_NO_ERROR,
                      (uint8_t *)&pkt->req_gc, 16);
}

static int handle_blocklogin(ship_t *c, shipgate_block_login_pkt *pkt) {
    char query[512];
    char tmp[128];
    uint32_t gc, bl, gc2, bl2, opt;
    uint16_t ship_id;
    ship_t *c2;
    void *result;
    char **row;
    void *optpkt;
    unsigned long *lengths;

    /* Packet introduced in protocol version 2. Error to send in v1. */
    if(c->proto_ver < 2) {
        return -1;
    }

    /* Make sure the name is terminated properly */
    if(pkt->ch_name[31] != '\0') {
        return send_error(c, SHDR_TYPE_BLKLOGIN, SHDR_FAILURE,
                          ERR_BLOGIN_INVAL_NAME, (uint8_t *)&pkt->guildcard,
                          8);
    }

    /* Parse out some stuff we'll use */
    gc = ntohl(pkt->guildcard);
    bl = ntohl(pkt->blocknum);

    /* Insert the client into the online_clients table */
    sylverant_db_escape_str(&conn, tmp, pkt->ch_name, strlen(pkt->ch_name));
    sprintf(query, "INSERT INTO online_clients(guildcard, name, ship_id, "
            "block) VALUES('%u', '%s', '%hu', '%u')", gc, tmp, c->key_idx, bl);

    /* If the query fails, most likely its a primary key violation, so assume
       the user is already logged in */
    if(sylverant_db_query(&conn, query)) {
        return send_error(c, SHDR_TYPE_BLKLOGIN, SHDR_FAILURE,
                          ERR_BLOGIN_ONLINE, (uint8_t *)&pkt->guildcard, 8);
    }

    /* Find anyone that has the user in their friendlist so we can send a
       message to them */
    sprintf(query, "SELECT guildcard, block, ship_id, nickname FROM "
            "online_clients INNER JOIN friendlist ON "
            "online_clients.guildcard = friendlist.owner WHERE "
            "friendlist.friend = '%u'", gc);

    /* Query for any results */
    if(sylverant_db_query(&conn, query)) {
        /* Silently fail here (to the ship anyway), since this doesn't spell
           doom at all for the logged in user */
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));
        return 0;
    }

    /* Grab any results we got */
    if(!(result = sylverant_db_result_store(&conn))) {
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));
        return 0;
    }

    /* For each bite we get, send out a friend login packet */
    while((row = sylverant_db_result_fetch(result))) {
        gc2 = (uint32_t)strtoul(row[0], NULL, 0);
        bl2 = (uint32_t)strtoul(row[1], NULL, 0);
        ship_id = (uint16_t)strtoul(row[2], NULL, 0);
        c2 = find_ship(ship_id);

        if(c2) {
            send_friend_message(c2, 1, gc2, bl2, gc, bl, c->key_idx,
                                pkt->ch_name, row[3]);
        }
    }

    sylverant_db_result_free(result);

    /* User options first appeared in protocol version 6, so only do this if the
       ship is at least of that version. */
    if(c->proto_ver >= 6) {
        /* See what options we have to deliver to the user */
        sprintf(query, "SELECT opt, value FROM user_options WHERE "
                "guildcard='%u'", gc);

        /* Query for any results */
        if(sylverant_db_query(&conn, query)) {
            /* Silently fail here (to the ship anyway), since this doesn't spell
               doom at all for the logged in user (although, it might spell some
               inconvenience, potentially) */
            debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));
            return 0;
        }

        /* Grab any results we got */
        if(!(result = sylverant_db_result_store(&conn))) {
            debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));
            return 0;
        }

        /* Begin the options packet */
        optpkt = user_options_begin(gc, bl);

        /* Loop through each option to add it to the packet */
        while((row = sylverant_db_result_fetch(result))) {
            lengths = sylverant_db_result_lengths(result);
            opt = (uint32_t)strtoul(row[0], NULL, 0);

            optpkt = user_options_append(optpkt, opt, (uint32_t)lengths[1],
                                         (uint8_t *)row[1]);
        }

        sylverant_db_result_free(result);

        /* We're done, send it */
        send_user_options(c);
    }

    /* We're done (no need to tell the ship on success) */
    return 0;
}

static int handle_blocklogout(ship_t *c, shipgate_block_login_pkt *pkt) {
    char query[512];
    uint32_t gc, bl, gc2, bl2;
    uint16_t ship_id;
    ship_t *c2;
    void *result;
    char **row;

    /* Packet introduced in protocol version 2. Error to send in v1. */
    if(c->proto_ver < 2) {
        return -1;
    }

    /* Make sure the name is terminated properly */
    if(pkt->ch_name[31] != '\0') {
        /* Maybe send an error... Probably not worth it at this point */
        return 0;
    }

    /* Parse out some stuff we'll use */
    gc = ntohl(pkt->guildcard);
    bl = ntohl(pkt->blocknum);

    /* Delete the client from the online_clients table */
    sprintf(query, "DELETE FROM online_clients WHERE guildcard='%u' AND "
            "ship_id='%hu'", gc, c->key_idx);

    if(sylverant_db_query(&conn, query)) {
        return 0;
    }

    /* Find anyone that has the user in their friendlist so we can send a
       message to them */
    sprintf(query, "SELECT guildcard, block, ship_id, nickname FROM "
            "online_clients INNER JOIN friendlist ON "
            "online_clients.guildcard = friendlist.owner WHERE "
            "friendlist.friend = '%u'", gc);

    /* Query for any results */
    if(sylverant_db_query(&conn, query)) {
        /* Silently fail here (to the ship anyway), since this doesn't spell
           doom at all for the logged in user */
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));
        return 0;
    }

    /* Grab any results we got */
    if(!(result = sylverant_db_result_store(&conn))) {
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));
        return 0;
    }

    /* For each bite we get, send out a friend logout packet */
    while((row = sylverant_db_result_fetch(result))) {
        gc2 = (uint32_t)strtoul(row[0], NULL, 0);
        bl2 = (uint32_t)strtoul(row[1], NULL, 0);
        ship_id = (uint16_t)strtoul(row[2], NULL, 0);
        c2 = find_ship(ship_id);

        if(c2) {
            send_friend_message(c2, 0, gc2, bl2, gc, bl, c->key_idx,
                                pkt->ch_name, row[3]);
        }
    }

    sylverant_db_result_free(result);

    /* We're done (no need to tell the ship on success) */
    return 0;
}

static int handle_friendlist_add(ship_t *c, shipgate_friend_add_pkt *pkt) {
    uint32_t ugc, fgc;
    char query[256];
    char nickname[64];

    /* Packet updated in protocol version 4. */
    if(c->proto_ver < 4) {
        return -1;
    }

    /* Make sure the length is sane */
    if(pkt->hdr.pkt_len != htons(sizeof(shipgate_friend_add_pkt))) {
        return -1;
    }

    /* Parse out the guildcards */
    ugc = ntohl(pkt->user_guildcard);
    fgc = ntohl(pkt->friend_guildcard);

    /* Escape the name string */
    pkt->friend_nick[31] = 0;
    sylverant_db_escape_str(&conn, nickname, pkt->friend_nick,
                            strlen(pkt->friend_nick));

    /* Build the db query */
    sprintf(query, "INSERT INTO friendlist(owner, friend, nickname) "
            "VALUES('%u', '%u', '%s')", ugc, fgc, nickname);

    /* Execute the query */
    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));
        return send_error(c, SHDR_TYPE_ADDFRIEND, SHDR_FAILURE, ERR_BAD_ERROR,
                          (uint8_t *)&pkt->user_guildcard, 8);
    }

    /* Return success to the ship */
    return send_error(c, SHDR_TYPE_ADDFRIEND, SHDR_RESPONSE, ERR_NO_ERROR,
                      (uint8_t *)&pkt->user_guildcard, 8);
}

static int handle_friendlist(ship_t *c, shipgate_friend_upd_pkt *pkt,
                             uint16_t type) {
    uint32_t ugc, fgc;
    char query[256];

    /* Packet introduced in protocol version 2. Error to send in v1. */
    if(c->proto_ver < 2) {
        return -1;
    }

    /* If we're on protocol version 4, then this should be the new type of
       friend add packet. */
    if(c->proto_ver >= 4 && type == SHDR_TYPE_ADDFRIEND) {
        return handle_friendlist_add(c, (shipgate_friend_add_pkt *)pkt);
    }

    /* Make sure the length is sane */
    if(pkt->hdr.pkt_len != htons(sizeof(shipgate_friend_upd_pkt))) {
        return -1;
    }

    /* Parse out the guildcards */
    ugc = ntohl(pkt->user_guildcard);
    fgc = ntohl(pkt->friend_guildcard);

    /* Build the db query */
    switch(type) {
        case SHDR_TYPE_ADDFRIEND:
            sprintf(query, "INSERT INTO friendlist(owner, friend) "
                    "VALUES('%u', '%u')", ugc, fgc);
            break;

        case SHDR_TYPE_DELFRIEND:
            sprintf(query, "DELETE FROM friendlist WHERE owner='%u' AND "
                    "friend='%u'", ugc, fgc);
            break;

        default:
            return -1;
    }

    /* Execute the query */
    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));
        return send_error(c, type, SHDR_FAILURE, ERR_BAD_ERROR,
                          (uint8_t *)&pkt->user_guildcard, 8);
    }

    /* Return success to the ship */
    return send_error(c, type, SHDR_RESPONSE, ERR_NO_ERROR,
                      (uint8_t *)&pkt->user_guildcard, 8);
}

static int handle_lobby_chg(ship_t *c, shipgate_lobby_change_pkt *pkt) {
    char query[512];
    char tmp[128];
    uint32_t gc, lid;

    /* Packet introduced in protocol version 3. Error to send in v2/v1. */
    if(c->proto_ver < 3) {
        return -1;
    }

    /* Make sure the name is terminated properly */
    pkt->lobby_name[31] = 0;

    /* Parse out some stuff we'll use */
    gc = ntohl(pkt->guildcard);
    lid = ntohl(pkt->lobby_id);

    /* Update the client's entry */
    sylverant_db_escape_str(&conn, tmp, pkt->lobby_name,
                            strlen(pkt->lobby_name));
    sprintf(query, "UPDATE online_clients SET lobby_id='%u', lobby='%s' WHERE "
            "guildcard='%u' AND ship_id='%hu'", lid, tmp, gc, c->key_idx);

    /* This shouldn't ever "fail" so to speak... */
    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));
        return 0;
    }

    /* We're done (no need to tell the ship on success) */
    return 0;
}

static int handle_block_clients(ship_t *c, shipgate_block_clients_pkt *pkt) {
    char query[512];
    char tmp[128], tmp2[128];
    uint32_t gc, lid, count, bl, i;
    uint16_t len;

    /* Packet introduced in protocol version 3. Error to send in v2/v1. */
    if(c->proto_ver < 3) {
        return -1;
    }

    /* Verify the length is right */
    count = ntohl(pkt->count);
    len = ntohs(pkt->hdr.pkt_len);

    if(len != 16 + count * 72 || count < 1) {
        debug(DBG_WARN, "Invalid block clients packet received\n");
        return -1;
    }

    /* Grab the global stuff */
    bl = ntohl(pkt->block);

    /* Make sure there's nothing for this ship/block in the db */
    sprintf(query, "DELETE FROM online_clients WHERE ship_id='%hu' AND "
            "block='%u'", c->key_idx, bl);
    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));
        return -1;
    }

    /* Run through each entry */
    for(i = 0; i < count; ++i) {
        /* Make sure the names look sane */
        if(pkt->entries[i].ch_name[31] || pkt->entries[i].lobby_name[31]) {
            continue;
        }

        /* Grab the integers out */
        gc = ntohl(pkt->entries[i].guildcard);
        lid = ntohl(pkt->entries[i].lobby);        

        /* Escape the name string */
        sylverant_db_escape_str(&conn, tmp, pkt->entries[i].ch_name,
                                strlen(pkt->entries[i].ch_name));

        /* If we're not in a lobby, that's all we need */
        if(lid == 0) {
            sprintf(query, "INSERT INTO online_clients(guildcard, name, "
                    "ship_id, block) VALUES('%u', '%s', '%hu', '%u')", gc, tmp,
                    c->key_idx, bl);
        }
        else {
            sylverant_db_escape_str(&conn, tmp2, pkt->entries[i].lobby_name,
                                    strlen(pkt->entries[i].lobby_name));
            sprintf(query, "INSERT INTO online_clients(guildcard, name, "
                    "ship_id, block, lobby_id, lobby) VALUES('%u', '%s', "
                    "'%hu', '%u', '%u', '%s')", gc, tmp, c->key_idx, bl, lid,
                    tmp2);
        }

        /* Run the query */
        if(sylverant_db_query(&conn, query)) {
            debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));
            continue;
        }
    }

    /* We're done (no need to tell the ship on success) */
    return 0;
}

static int handle_kick(ship_t *c, shipgate_kick_pkt *pkt) {
    uint32_t gc, gcr, bl;
    uint16_t sid;
    char query[256];
    void *result;
    char **row;
    ship_t *c2;
    int priv, priv2;

    /* Parse out what we care about */
    gcr = ntohl(pkt->requester);
    gc = ntohl(pkt->guildcard);

    /* Make sure the requester is a GM */
    sprintf(query, "SELECT privlevel FROM account_data NATURAL JOIN guildcards "
            "WHERE privlevel>'1' AND guildcard='%u'", gcr);
    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));
        return 0;
    }

    /* Grab the data from the DB */
    if((result = sylverant_db_result_store(&conn)) == NULL) {
        debug(DBG_WARN, "Couldn't fetch GM data (%u)\n", gcr);
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));

        return 0;
    }

    /* Make sure we actually have a row, if not the ship is possibly trying to
       trick us into giving someone without GM privileges GM abilities... */
    if((row = sylverant_db_result_fetch(result)) == NULL) {
        sylverant_db_result_free(result);
        debug(DBG_WARN, "Failed kick - not gm (gc: %u ship: %hu)\n", gcr,
              c->key_idx);

        return -1;
    }

    /* Grab the privilege level of the GM doing the kick */
    priv = atoi(row[0]);

    /* We're done with the data we got */
    sylverant_db_result_free(result);

    /* Make sure the user isn't trying to kick someone with a higher privilege
       level than them... */
    sprintf(query, "SELECT privlevel FROM guildcards NATURAL JOIN account_data "
            "WHERE guildcard='%u'", gc);

    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "Couldn't fetch account data (%u)\n", gc);
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));

        return 0;
    }
    
    /* Grab the data we got. */
    if((result = sylverant_db_result_store(&conn)) == NULL) {
        debug(DBG_WARN, "Couldn't fetch account data (%u)\n", gc);
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));

        return 0;
    }

    /* See if we got anything */
    if((row = sylverant_db_result_fetch(result))) {
        priv2 = atoi(row[0]);

        if(priv2 >= priv) {
            sylverant_db_result_free(result);
            debug(DBG_WARN, "Attempt by %u to kick %u overturned by priv\n",
                  gcr, gc);

            return 0;
        }
    }

    /* We're done with that... */
    sylverant_db_result_free(result);

    /* Now that we're done with that, work on the kick */
    sprintf(query, "SELECT ship_id, block FROM online_clients WHERE "
            "guildcard='%u'", gc);
    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));
        return 0;
    }

    /* Grab the data from the DB */
    if((result = sylverant_db_result_store(&conn)) == NULL) {
        debug(DBG_WARN, "Couldn't fetch online data (%u)\n", gc);
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));

        return 0;
    }

    /* Grab the location of the user. If the user's not on, silently fail */
    if((row = sylverant_db_result_fetch(result)) == NULL) {
        sylverant_db_result_free(result);
        return 0;
    }

    /* If we're here, we have a row, so parse out what we care about */
    errno = 0;
    sid = (uint16_t)strtoul(row[0], NULL, 0);
    bl = (uint32_t)strtoul(row[1], NULL, 0);
    sylverant_db_result_free(result);

    if(errno != 0) {
        debug(DBG_WARN, "Invalid online_clients data: %s\n", strerror(errno));
        return 0;
    }

    /* Grab the ship we need to send this to */
    if(!(c2 = find_ship(sid))) {
        debug(DBG_WARN, "Invalid ship?!?\n");
        return -1;
    }

    /* Send off the message */
    send_kick(c2, gcr, gc, bl, pkt->reason);
    return 0;
}

static int handle_frlist_req(ship_t *c, shipgate_friend_list_req *pkt) {
    uint32_t gcr, block, start;
    char query[256];
    void *result;
    char **row;
    friendlist_data_t entries[5];
    int i;

    /* Parse out what we need */
    gcr = ntohl(pkt->requester);
    block = ntohl(pkt->block);
    start = ntohl(pkt->start);

    /* Grab the friendlist data */
    sprintf(query, "SELECT friend, nickname, ship_id, block FROM friendlist "
            "LEFT OUTER JOIN online_clients ON friendlist.friend = "
            "online_clients.guildcard WHERE owner='%u' ORDER BY friend "
            "LIMIT 5 OFFSET %u", gcr, start);
    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "Couldn't select friendlist for %u\n", gcr);
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));
        return 0;
    }

    /* Grab the data from the DB */
    if((result = sylverant_db_result_store(&conn)) == NULL) {
        debug(DBG_WARN, "Couldn't fetch friendlist for %u\n", gcr);
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));

        return 0;
    }

    /* Fetch our max of 5 entries... i will be left as the number found */
    for(i = 0; i < 5 && (row = sylverant_db_result_fetch(result)); ++i) {
        entries[i].guildcard = htonl(strtoul(row[0], NULL, 0));
        
        if(row[2]) {
            entries[i].ship = htonl(strtoul(row[2], NULL, 0));
        }
        else {
            entries[i].ship = 0;
        }

        if(row[3]) {
            entries[i].block = htonl(strtoul(row[3], NULL, 0));
        }
        else {
            entries[i].block = 0;
        }

        entries[i].reserved = 0;

        strncpy(entries[i].name, row[1], 31);
        entries[i].name[31] = 0;
    }

    /* We're done with that, so clean up */
    sylverant_db_result_free(result);

    /* Send the packet to the user */
    send_friendlist(c, gcr, block, i, entries);

    return 0;
}

static int handle_globalmsg(ship_t *c, shipgate_global_msg_pkt *pkt) {
    uint32_t gcr;
    uint16_t text_len;
    char query[256];
    void *result;
    char **row;
    ship_t *i;

    /* Parse out what we really need */
    gcr = ntohl(pkt->requester);
    text_len = ntohs(pkt->hdr.pkt_len) - sizeof(shipgate_global_msg_pkt);

    /* Make sure the string is NUL terminated */
    if(pkt->text[text_len - 1]) {
        debug(DBG_WARN, "Non-terminated global msg (%hu)\n", c->key_idx);
        return 0;
    }

    /* Make sure the requester is a GM */
    sprintf(query, "SELECT privlevel FROM account_data NATURAL JOIN guildcards "
            "WHERE privlevel>'1' AND guildcard='%u'", gcr);
    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));
        return 0;
    }

    /* Grab the data from the DB */
    if((result = sylverant_db_result_store(&conn)) == NULL) {
        debug(DBG_WARN, "Couldn't fetch GM data (%u)\n", gcr);
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));

        return 0;
    }

    /* Make sure we actually have a row, if not the ship is possibly trying to
       trick us into giving someone without GM privileges GM abilities... */
    if((row = sylverant_db_result_fetch(result)) == NULL) {
        sylverant_db_result_free(result);
        debug(DBG_WARN, "Failed global msg - not gm (gc: %u ship: %hu)\n", gcr,
              c->key_idx);

        return -1;
    }

    /* We're done with that... */
    sylverant_db_result_free(result);

    /* Send the packet along to all the ships that support it */
    TAILQ_FOREACH(i, &ships, qentry) {
        if(send_global_msg(i, gcr, pkt->text, text_len)) {
            i->disconnected = 1;
        }
    }

    return 0;
}

static int handle_useropt(ship_t *c, shipgate_user_opt_pkt *pkt) {
    char data[512];
    char query[1024];
    uint16_t len = htons(pkt->hdr.pkt_len);
    uint32_t ugc, optlen, opttype;
    int realoptlen;

    /* Packet introduced in protocol version 6. */
    if(c->proto_ver < 6) {
        return -1;
    }

    /* Make sure the length is sane */
    if(len < sizeof(shipgate_user_opt_pkt) + 16) {
        return -2;
    }

    /* Parse out the guildcard */
    ugc = ntohl(pkt->guildcard);
    optlen = ntohl(pkt->options[0].length);
    opttype = ntohl(pkt->options[0].option);

    /* Make sure the length matches up properly */
    if(optlen != len - sizeof(shipgate_user_opt_pkt)) {
        return -3;
    }

    /* Handle each option separately */
    switch(opttype) {
        case USER_OPT_QUEST_LANG:
            /* The full option should be 16 bytes */
            if(optlen != 16) {
                return -4;
            }

            /* However, we only pay attention to the first byte */
            realoptlen = 1;
            break;

        default:
            debug(DBG_WARN, "Ship sent unknown user option: %lu\n", opttype);
            return -5;
    }

    /* Escape the data */
    sylverant_db_escape_str(&conn, data, (const char *)pkt->options[0].data,
                            realoptlen);

    /* Build the db query... This uses a MySQL extension, so will have to be
       fixed if any other DB type is to be supported... */
    sprintf(query, "INSERT INTO user_options(guildcard, opt, value) "
            "VALUES('%u', '%u', '%s') ON DUPLICATE KEY UPDATE "
            "value=VALUES(value)", ugc, opttype, data);

    /* Execute the query */
    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));
        return send_error(c, SHDR_TYPE_USEROPT, SHDR_FAILURE, ERR_BAD_ERROR,
                          (uint8_t *)&pkt->guildcard, 24);
    }

    /* Return success to the ship */
    return send_error(c, SHDR_TYPE_USEROPT, SHDR_RESPONSE, ERR_NO_ERROR,
                      (uint8_t *)&pkt->guildcard, 24);
}

/* Process one ship packet. */
int process_ship_pkt(ship_t *c, shipgate_hdr_t *pkt) {
    uint16_t type = ntohs(pkt->pkt_type);
    uint16_t flags = ntohs(pkt->flags);

    switch(type) {
        case SHDR_TYPE_LOGIN:
            if(!(flags & SHDR_RESPONSE)) {
                debug(DBG_WARN, "Client sent invalid login response\n");
                return -1;
            }

            return handle_shipgate_login(c, (shipgate_login_reply_pkt *)pkt);

        case SHDR_TYPE_LOGIN6:
            if(!(flags & SHDR_RESPONSE)) {
                debug(DBG_WARN, "Client sent invalid login response\n");
                return -1;
            }

            return handle_shipgate_login6(c, (shipgate_login6_reply_pkt *)pkt);

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

        case SHDR_TYPE_BLKLOGIN:
            return handle_blocklogin(c, (shipgate_block_login_pkt *)pkt);

        case SHDR_TYPE_BLKLOGOUT:
            return handle_blocklogout(c, (shipgate_block_login_pkt *)pkt);

        case SHDR_TYPE_ADDFRIEND:
        case SHDR_TYPE_DELFRIEND:
            return handle_friendlist(c, (shipgate_friend_upd_pkt *)pkt, type);

        case SHDR_TYPE_LOBBYCHG:
            return handle_lobby_chg(c, (shipgate_lobby_change_pkt *)pkt);

        case SHDR_TYPE_BCLIENTS:
            return handle_block_clients(c, (shipgate_block_clients_pkt *)pkt);

        case SHDR_TYPE_KICK:
            return handle_kick(c, (shipgate_kick_pkt *)pkt);

        case SHDR_TYPE_FRLIST:
            return handle_frlist_req(c, (shipgate_friend_list_req *)pkt);

        case SHDR_TYPE_GLOBALMSG:
            return handle_globalmsg(c, (shipgate_global_msg_pkt *)pkt);

        case SHDR_TYPE_USEROPT:
            return handle_useropt(c, (shipgate_user_opt_pkt *)pkt);

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
    rbp = recvbuf;

    /* As long as what we have is long enough, decrypt it. */
    if(sz >= 8) {
        while(sz >= 8 && rv == 0) {
            /* Grab the packet header so we know what exactly we're looking
               for, in terms of packet length. */
            if(!c->hdr_read) {
                if(c->key_set) {
                    RC4(&c->ship_key, 8, rbp, (unsigned char *)&c->pkt);
                }
                else {
                    memcpy(&c->pkt, rbp, 8);
                }

                c->hdr_read = 1;
            }

            pkt_sz = htons(c->pkt.pkt_len);

            /* We'll always need a multiple of 8 bytes. */
            if(pkt_sz & 0x07) {
                pkt_sz = (pkt_sz & 0xFFF8) + 8;
            }

            /* Do we have the whole packet? */
            if(sz >= (ssize_t)pkt_sz) {
                /* Yes, we do, decrypt it. */
                if(c->key_set) {
                    RC4(&c->ship_key, pkt_sz - 8, rbp + 8, rbp + 8);
                }

                memcpy(rbp, &c->pkt, 8);

                /* Pass it onto the correct handler. */
                c->last_message = time(NULL);
                rv = process_ship_pkt(c, (shipgate_hdr_t *)rbp);

                rbp += pkt_sz;
                sz -= pkt_sz;

                c->hdr_read = 0;
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
