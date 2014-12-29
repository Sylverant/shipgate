/*
    Sylverant Shipgate
    Copyright (C) 2009, 2010, 2011, 2012, 2014 Lawrence Sebald

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
#include <iconv.h>
#include <sys/socket.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include <zlib.h>

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

#define VERSION_DC              0
#define VERSION_PC              1
#define VERSION_GC              2
#define VERSION_EP3             3
#define VERSION_BB              4

/* Database connection */
extern sylverant_dbconn_t conn;

/* iconv contexts */
extern iconv_t ic_utf8_to_utf16;
extern iconv_t ic_utf16_to_utf8;
extern iconv_t ic_sjis_to_utf8;
extern iconv_t ic_8859_to_utf8;

/* GnuTLS data... */
extern gnutls_certificate_credentials_t tls_cred;
extern gnutls_priority_t tls_prio;

/* Events... */
extern uint32_t event_count;
extern monster_event_t *events;

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

static inline void parse_ipv6(uint64_t hi, uint64_t lo, uint8_t buf[16]) {
    buf[0] = (uint8_t)(hi >> 56);
    buf[1] = (uint8_t)(hi >> 48);
    buf[2] = (uint8_t)(hi >> 40);
    buf[3] = (uint8_t)(hi >> 32);
    buf[4] = (uint8_t)(hi >> 24);
    buf[5] = (uint8_t)(hi >> 16);
    buf[6] = (uint8_t)(hi >> 8);
    buf[7] = (uint8_t)hi;
    buf[8] = (uint8_t)(lo >> 56);
    buf[9] = (uint8_t)(lo >> 48);
    buf[10] = (uint8_t)(lo >> 40);
    buf[11] = (uint8_t)(lo >> 32);
    buf[12] = (uint8_t)(lo >> 24);
    buf[13] = (uint8_t)(lo >> 16);
    buf[14] = (uint8_t)(lo >> 8);
    buf[15] = (uint8_t)lo;
}

static monster_event_t *find_current_event(uint8_t difficulty, uint8_t ver) {
    uint32_t i;
    uint8_t questing;
    time_t now;

    /* For now, just reject any challenge/battle mode updates... We don't care
       about them at all. */
    if(ver & 0xC0)
        return NULL;

    now = time(NULL);
    questing = ver & 0x20;
    ver &= 0x07;

    for(i = 0; i < event_count; ++i) {
        /* Skip all quests that don't meet the requirements passed in. */
        if(now > events[i].end_time || now < events[i].start_time)
            continue;
        if(!(events[i].versions & (1 << ver)))
            continue;
        if(!(events[i].difficulties & (1 << difficulty)))
            continue;
        if(!events[i].allow_quests && questing)
            continue;

        /* If we get here, then the event is valid, return it. */
        return events + i;
    }

    return NULL;
}

/* Create a new connection, storing it in the list of ships. */
ship_t *create_connection_tls(int sock, struct sockaddr *addr, socklen_t size) {
    ship_t *rv;
    int tmp;
    unsigned int peer_status, cert_list_size;
    gnutls_x509_crt_t cert;
    const gnutls_datum_t *cert_list;
    uint8_t hash[20];
    size_t sz = 20;
    char query[256], fingerprint[40];
    void *result;
    char **row;

    rv = (ship_t *)malloc(sizeof(ship_t));

    if(!rv) {
        perror("malloc");
        close(sock);
        return NULL;
    }

    memset(rv, 0, sizeof(ship_t));

    /* Store basic parameters in the client structure. */
    rv->sock = sock;
    rv->last_message = time(NULL);
    memcpy(&rv->conn_addr, addr, size);

    /* Create the TLS session */
    gnutls_init(&rv->session, GNUTLS_SERVER);
    gnutls_priority_set(rv->session, tls_prio);
    gnutls_credentials_set(rv->session, GNUTLS_CRD_CERTIFICATE, tls_cred);

    gnutls_certificate_server_set_request(rv->session, GNUTLS_CERT_REQUIRE);

#if (SIZEOF_INT != SIZEOF_VOIDP) && (SIZEOF_LONG_INT == SIZEOF_VOIDP)
    gnutls_transport_set_ptr(rv->session, (gnutls_transport_ptr_t)((long)sock));
#else
    gnutls_transport_set_ptr(rv->session, (gnutls_transport_ptr_t)sock);
#endif

    /* Do the TLS handshake */
    tmp = gnutls_handshake(rv->session);

    if(tmp < 0) {
        close(sock);
        gnutls_deinit(rv->session);
        free(rv);
        debug(DBG_WARN, "TLS Handshake failed: %s\n", gnutls_strerror(tmp));
        return NULL;
    }

    /* Verify that the peer has a valid certificate */
    tmp = gnutls_certificate_verify_peers2(rv->session, &peer_status);

    if(tmp < 0) {
        debug(DBG_WARN, "Error validating peer: %s\n", gnutls_strerror(tmp));
        goto err;
    }

    /* Check whether or not the peer is trusted... */
    if(peer_status & GNUTLS_CERT_INVALID) {
        debug(DBG_WARN, "Untrusted peer connection, reason below (%08x):\n",
              peer_status);

        if(peer_status & GNUTLS_CERT_SIGNER_NOT_FOUND)
            debug(DBG_WARN, "No issuer found\n");
        if(peer_status & GNUTLS_CERT_SIGNER_NOT_CA)
            debug(DBG_WARN, "Issuer is not a CA\n");
        if(peer_status & GNUTLS_CERT_NOT_ACTIVATED)
            debug(DBG_WARN, "Certificate not yet activated\n");
        if(peer_status & GNUTLS_CERT_EXPIRED)
            debug(DBG_WARN, "Certificate Expired\n");
        if(peer_status & GNUTLS_CERT_REVOKED)
            debug(DBG_WARN, "Certificate Revoked\n");
        if(peer_status & GNUTLS_CERT_INSECURE_ALGORITHM)
            debug(DBG_WARN, "Insecure certificate signature\n");

        goto err;
    }

    /* Verify that we know the peer */
    if(gnutls_certificate_type_get(rv->session) != GNUTLS_CRT_X509) {
        debug(DBG_WARN, "Invalid certificate type!\n");
        goto err;
    }

    tmp = gnutls_x509_crt_init(&cert);
    if(tmp < 0) {
        debug(DBG_WARN, "Cannot init certificate: %s\n", gnutls_strerror(tmp));
        goto err;
    }

    /* Get the peer's certificate */
    cert_list = gnutls_certificate_get_peers(rv->session, &cert_list_size);
    if(cert_list == NULL) {
        debug(DBG_WARN, "No certs found for connection!?\n");
        goto err;
    }

    tmp = gnutls_x509_crt_import(cert, &cert_list[0], GNUTLS_X509_FMT_DER);
    if(tmp < 0) {
        debug(DBG_WARN, "Cannot parse certificate: %s\n", gnutls_strerror(tmp));
        goto err;
    }

    /* Get the SHA1 fingerprint */
    tmp = gnutls_x509_crt_get_fingerprint(cert, GNUTLS_DIG_SHA1, hash, &sz);
    if(tmp < 0) {
        debug(DBG_WARN, "Cannot read hash: %s\n", gnutls_strerror(tmp));
        goto err;
    }

    /* Figure out what ship is connecting by the fingerprint */
    sylverant_db_escape_str(&conn, fingerprint, (char *)hash, 20);

    sprintf(query, "SELECT idx FROM ship_data WHERE sha1_fingerprint='%s'",
           fingerprint);

    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "Couldn't query the database\n");
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));
        goto err;
    }

    if((result = sylverant_db_result_store(&conn)) == NULL ||
       (row = sylverant_db_result_fetch(result)) == NULL) {
        debug(DBG_WARN, "Unknown SHA1 fingerprint");
        goto err;
    }

    /* Store the ship ID */
    rv->key_idx = atoi(row[0]);
    sylverant_db_result_free(result);
    gnutls_x509_crt_deinit(cert);

    /* Send the client the welcome packet, or die trying. */
    if(send_welcome(rv)) {
        goto err;
    }

    /* Insert it at the end of our list, and we're done. */
    TAILQ_INSERT_TAIL(&ships, rv, qentry);
    return rv;

err:
    gnutls_bye(rv->session, GNUTLS_SHUT_RDWR);
    close(sock);
    gnutls_deinit(rv->session);
    free(rv);
    return NULL;
}

/* Destroy a connection, closing the socket and removing it from the list. */
void destroy_connection(ship_t *c) {
    char query[256];
    ship_t *i;

    if(c->name[0]) {
        debug(DBG_LOG, "Closing connection with %s\n", c->name);
    }
    else {
        debug(DBG_LOG, "Closing connection with unknown ship\n");
    }

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

    /* Clean up the TLS resources and the socket. */
    if(c->sock >= 0) {
        gnutls_bye(c->session, GNUTLS_SHUT_RDWR);
        close(c->sock);
        gnutls_deinit(c->session);
        c->sock = -1;
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
static int handle_shipgate_login6t(ship_t *c, shipgate_login6_reply_pkt *pkt) {
    char query[512];
    ship_t *j;
    void *result;
    char **row;
    uint32_t pver = c->proto_ver = ntohl(pkt->proto_ver);
    uint16_t menu_code = ntohs(pkt->menu_code);
    int ship_number;
    uint64_t ip6_hi, ip6_lo;
    uint32_t clients = 0;

    /* Check the protocol version for support (TLS first supported in v10) */
    if(pver < SHIPGATE_MINIMUM_PROTO_VER || pver > SHIPGATE_MAXIMUM_PROTO_VER) {
        debug(DBG_WARN, "Invalid protocol version: %lu\n", pver);

        send_error(c, SHDR_TYPE_LOGIN6, SHDR_RESPONSE | SHDR_FAILURE,
                   ERR_LOGIN_BAD_PROTO, NULL, 0);
        return -1;
    }

    /* Attempt to grab the key for this ship. */
    sprintf(query, "SELECT main_menu, ship_number FROM ship_data WHERE "
            "idx='%u'", c->key_idx);

    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "Couldn't query the database\n");
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));
        send_error(c, SHDR_TYPE_LOGIN6, SHDR_RESPONSE | SHDR_FAILURE,
                   ERR_BAD_ERROR, NULL, 0);
        return -1;
    }

    if((result = sylverant_db_result_store(&conn)) == NULL ||
       (row = sylverant_db_result_fetch(result)) == NULL) {
        debug(DBG_WARN, "Invalid index %d\n", c->key_idx);
        send_error(c, SHDR_TYPE_LOGIN6, SHDR_RESPONSE | SHDR_FAILURE,
                   ERR_LOGIN_BAD_KEY, NULL, 0);
        return -1;
    }

    /* Check the menu code for validity */
    if(menu_code && (!isalpha(menu_code & 0xFF) | !isalpha(menu_code >> 8))) {
        debug(DBG_WARN, "Bad menu code for id: %d\n", c->key_idx);
        send_error(c, SHDR_TYPE_LOGIN6, SHDR_RESPONSE | SHDR_FAILURE,
                   ERR_LOGIN_BAD_MENU, NULL, 0);
        return -1;
    }

    /* If the ship requests the main menu and they aren't allowed there, bail */
    if(!menu_code && !atoi(row[0])) {
        debug(DBG_WARN, "Invalid menu code for id: %d\n", c->key_idx);
        send_error(c, SHDR_TYPE_LOGIN6, SHDR_RESPONSE | SHDR_FAILURE,
                   ERR_LOGIN_INVAL_MENU, NULL, 0);
        return -1;
    }

    /* Grab the key from the result */
    ship_number = atoi(row[1]);
    sylverant_db_result_free(result);

    /* Fill in the ship structure */
    c->remote_addr = pkt->ship_addr4;
    memcpy(&c->remote_addr6, pkt->ship_addr6, 16);
    c->port = ntohs(pkt->ship_port);
    c->clients = ntohs(pkt->clients);
    c->games = ntohs(pkt->games);
    c->flags = ntohl(pkt->flags);
    c->menu_code = menu_code;
    memcpy(c->name, pkt->name, 12);
    c->ship_number = ship_number;

    pack_ipv6(&c->remote_addr6, &ip6_hi, &ip6_lo);

    sprintf(query, "INSERT INTO online_ships(name, players, ip, port, int_ip, "
            "ship_id, gm_only, games, menu_code, flags, ship_number, "
            "ship_ip6_high, ship_ip6_low, protocol_ver) VALUES ('%s', '%hu', "
            "'%u', '%hu', '%u', '%u', '%d', '%hu', '%hu', '%u', '%d', '%llu', "
            "'%llu', '%u')", c->name, c->clients, ntohl(c->remote_addr),
            c->port, 0, c->key_idx, !!(c->flags & LOGIN_FLAG_GMONLY), c->games,
            c->menu_code, c->flags, ship_number, (unsigned long long)ip6_hi,
            (unsigned long long)ip6_lo, pver);

    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "Couldn't add %s to the online_ships table.\n",
              c->name);
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));
        send_error(c, SHDR_TYPE_LOGIN6, SHDR_RESPONSE | SHDR_FAILURE,
                   ERR_BAD_ERROR, NULL, 0);
        return -1;
    }

    /* Hooray for misusing functions! */
    if(send_error(c, SHDR_TYPE_LOGIN6, SHDR_RESPONSE, ERR_NO_ERROR, NULL, 0)) {
        return -1;
    }

    /* Send a status packet to each of the ships. */
    TAILQ_FOREACH(j, &ships, qentry) {
        send_ship_status(j, c, 1);

        /* Send this ship to the new ship, as long as that wasn't done just
           above here. */
        if(j != c) {
            send_ship_status(c, j, 1);
        }

        clients += j->clients;
    }

    /* Update the table of client counts, if it might have actually changed from
       this update packet. */
    if(c->clients) {
        sprintf(query, "INSERT INTO client_count (clients) VALUES('%" PRIu32
                "') ON DUPLICATE KEY UPDATE clients=VALUES(clients)", clients);
        if(sylverant_db_query(&conn, query)) {
            debug(DBG_WARN, "Couldn't update global player/game count");
        }
    }

    return 0;
}

/* Handle a ship's update counters packet. */
static int handle_count(ship_t *c, shipgate_cnt_pkt *pkt) {
    char query[256];
    ship_t *j;
    uint32_t clients = 0;
    uint16_t sclients = c->clients;

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
        clients += j->clients;
    }

    /* Update the table of client counts, if the number actually changed from
       this update packet. */
    if(sclients != c->clients) {
        sprintf(query, "INSERT INTO client_count (clients) VALUES('%" PRIu32
                "') ON DUPLICATE KEY UPDATE clients=VALUES(clients)", clients);
        if(sylverant_db_query(&conn, query)) {
            debug(DBG_WARN, "Couldn't update global player/game count");
        }
    }

    return 0;
}

static size_t strlen16(const uint16_t *str) {
    size_t sz = 0;

    while(*str++) ++sz;
    return sz;
}

static int save_mail(uint32_t gc, uint32_t from, void *pkt, int version) {
    char msg[512], name[64];
    static char query[2048];
    void *result;
    char **row;
    size_t in, out, nmlen;
    ICONV_CONST char *inptr;
    char *outptr;
    dc_simple_mail_pkt *dcpkt = (dc_simple_mail_pkt *)pkt;
    pc_simple_mail_pkt *pcpkt = (pc_simple_mail_pkt *)pkt;
    bb_simple_mail_pkt *bbpkt = (bb_simple_mail_pkt *)pkt;

    /* See if the user is registered first. */
    sprintf(query, "SELECT account_id FROM guildcards WHERE guildcard='%u'",
            gc);
    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "save_mail: cannot query for account: %s\n",
              sylverant_db_error(&conn));
        return 0;
    }

    /* Grab the data we got. */
    if((result = sylverant_db_result_store(&conn)) == NULL) {
        debug(DBG_WARN, "save_mail: Cannot fetch result: %s\n",
              sylverant_db_error(&conn));
        return 0;
    }

    /* Grab the result set */
    if(!(row = sylverant_db_result_fetch(result))) {
        debug(DBG_WARN, "save_mail: Invalid guildcard: %u (sent by %u)\n",
              gc, from);
        sylverant_db_result_free(result);
        return 0;
    }

    /* Is there an account_id associated with the guildcard? */
    if(row[0] == NULL) {
        /* No account associated with the guildcard, so we're done. */
        sylverant_db_result_free(result);
        return 0;
    }

    /* We're done with the result set, so clean it up. */
    sylverant_db_result_free(result);

    /* Convert the message to UTF-8 for storage. */
    switch(version) {
        case VERSION_DC:
        case VERSION_GC:
        case VERSION_EP3:
            dcpkt->stuff[144] = 0;
            in = strlen(dcpkt->stuff);
            out = 511;
            inptr = dcpkt->stuff;
            outptr = msg;

            if(inptr[0] == '\t' && inptr[1] == 'J')
                iconv(ic_sjis_to_utf8, &inptr, &in, &outptr, &out);
            else
                iconv(ic_8859_to_utf8, &inptr, &in, &outptr, &out);

            msg[511 - out] = 0;
            memcpy(name, dcpkt->name, 16);
            name[16] = 0;
            nmlen = strlen(name);
            break;

        case VERSION_PC:
            pcpkt->stuff[288] = 0;
            pcpkt->stuff[289] = 0;
            in = strlen16((uint16_t *)pcpkt->stuff) * 2;
            out = 511;
            inptr = (char *)pcpkt->stuff;
            outptr = msg;

            iconv(ic_utf16_to_utf8, &inptr, &in, &outptr, &out);

            msg[511 - out] = 0;

            in = (strlen16(pcpkt->name) * 2);
            nmlen = 0x40;
            inptr = (char *)pcpkt->name;
            outptr = name;

            iconv(ic_utf16_to_utf8, &inptr, &in, &outptr, &nmlen);
            nmlen = 64 - nmlen;
            name[nmlen] = 0;
            break;

        case VERSION_BB:
            bbpkt->unk2[0] = 0;
            bbpkt->unk2[1] = 0;
            in = strlen16(bbpkt->message) * 2;
            out = 511;
            inptr = (char *)bbpkt->message;
            outptr = msg;

            iconv(ic_utf16_to_utf8, &inptr, &in, &outptr, &out);

            msg[511 - out] = 0;

            in = (strlen16(bbpkt->name) * 2) - 4;
            nmlen = 0x40;
            inptr = (char *)&bbpkt->name[2];
            outptr = name;

            iconv(ic_utf16_to_utf8, &inptr, &in, &outptr, &nmlen);
            nmlen = 64 - nmlen;
            name[nmlen] = 0;
            break;

        default:
            /* XXXX */
            return 0;
    }

    /* Fill in the query. */
    sprintf(query, "INSERT INTO simple_mail(recipient, sender, sent_time, "
            "sender_name, message) VALUES ('%u', '%u', UNIX_TIMESTAMP(), '", gc,
            from);
    sylverant_db_escape_str(&conn, query + strlen(query), name, nmlen);

    strcat(query, "', '");
    sylverant_db_escape_str(&conn, query + strlen(query), msg, 511 - out);
    strcat(query, "');");

    /* Execute the query on the db. */
    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "Couldn't save simple mail (to: %" PRIu32 " from: %"
              PRIu32 ")\n", gc, from);
        debug(DBG_WARN, "    %s\n", sylverant_db_error(&conn));
        return 0;
    }

    /* And... we're done! */
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
        /* The user's not online, see if we should save it. */
        sylverant_db_result_free(result);
        return save_mail(guildcard, LE32(pkt->gc_sender), pkt, VERSION_DC);
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
    forward_dreamcast(s, (dc_pkt_hdr_t *)pkt, c->key_idx, 0, 0);
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
        /* The user's not online, see if we should save it. */
        sylverant_db_result_free(result);
        return save_mail(guildcard, LE32(pkt->gc_sender), pkt, VERSION_PC);
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
    forward_pc(s, (dc_pkt_hdr_t *)pkt, c->key_idx, 0, 0);
    return 0;
}

static int handle_bb_mail(ship_t *c, bb_simple_mail_pkt *pkt) {
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
        debug(DBG_WARN, "BB Mail Error: %s", sylverant_db_error(&conn));
        return 0;
    }

    /* Grab the data we got. */
    if((result = sylverant_db_result_store(&conn)) == NULL) {
        debug(DBG_WARN, "Couldn't fetch BB mail result: %s\n",
              sylverant_db_error(&conn));
        return 0;
    }

    if(!(row = sylverant_db_result_fetch(result))) {
        /* The user's not online, see if we should save it. */
        sylverant_db_result_free(result);
        return save_mail(guildcard, LE32(pkt->gc_sender), pkt, VERSION_BB);
    }

    /* Grab the data from the result */
    errno = 0;
    ship_id = (uint16_t)strtoul(row[0], NULL, 0);
    sylverant_db_result_free(result);

    if(errno) {
        debug(DBG_WARN, "Error parsing in bb mail: %s", strerror(errno));
        return 0;
    }

    /* If we've got this far, we should have the ship we need to send to */
    s = find_ship(ship_id);
    if(!s) {
        debug(DBG_WARN, "Invalid ship?!?!?\n");
        return 0;
    }

    /* Send it on, and finish up... */
    forward_bb(s, (bb_pkt_hdr_t *)pkt, c->key_idx, 0, 0);
    return 0;
}

static int handle_guild_search(ship_t *c, dc_guild_search_pkt *pkt,
                               uint32_t flags) {
    uint32_t guildcard = LE32(pkt->gc_target);
    char query[512];
    void *result;
    char **row;
    uint16_t ship_id, port;
    uint32_t lobby_id, ip, block, dlobby_id;
    uint64_t ip6_hi, ip6_lo;
    ship_t *s;
    dc_guild_reply_pkt reply;
    dc_guild_reply6_pkt reply6;
    char lobby_name[32], gname[17];

    /* Figure out where the user requested is */
    sprintf(query, "SELECT online_clients.name, online_clients.ship_id, block, "
            "lobby, lobby_id, online_ships.name, ip, port, gm_only, "
            "ship_ip6_high, ship_ip6_low, dlobby_id FROM online_clients INNER "
            "JOIN online_ships ON online_clients.ship_id = "
            "online_ships.ship_id WHERE guildcard='%u'", guildcard);
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
        /* The user's not online, give up. */
        goto out;
    }

    /* Make sure the user isn't on a GM only ship... if they are, bail now */
    if(atoi(row[8])) {
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

    /* If any of these are NULL, the user is not in a lobby. Thus, the client
       doesn't really exist just yet. */
    if(row[4] == NULL || row[3] == NULL || row[11] == NULL) {
        goto out;
    }

    /* Grab the data from the result */
    port = (uint16_t)strtoul(row[7], NULL, 0);
    block = (uint32_t)strtoul(row[2], NULL, 0);
    lobby_id = (uint32_t)strtoul(row[4], NULL, 0);
    ip = (uint32_t)strtoul(row[6], NULL, 0);
    ip6_hi = (uint64_t)strtoull(row[9], NULL, 0);
    ip6_lo = (uint64_t)strtoull(row[10], NULL, 0);
    dlobby_id = (uint32_t)strtoul(row[11], NULL, 0);

    if(errno) {
        debug(DBG_WARN, "Error parsing in guild search: %s", strerror(errno));
        goto out;
    }

    if(dlobby_id <= 15) {
        sprintf(lobby_name, "BLOCK%02d-%02d", block, dlobby_id);
    }
    else {
        sprintf(lobby_name, "BLOCK%02d-C%d", block, dlobby_id - 15);
    }

    /* Set up the reply, we should have enough data now */
    if((flags & FW_FLAG_PREFER_IPV6) && ip6_hi) {
        memset(&reply6, 0, DC_GUILD_REPLY6_LENGTH);

        /* Fill it in */
        reply6.hdr.pkt_type = GUILD_REPLY_TYPE;
        reply6.hdr.pkt_len = LE16(DC_GUILD_REPLY6_LENGTH);
        reply6.hdr.flags = 6;
        reply6.tag = LE32(0x00010000);
        reply6.gc_search = pkt->gc_search;
        reply6.gc_target = pkt->gc_target;
        parse_ipv6(ip6_hi, ip6_lo, reply6.ip);
        reply6.port = LE16((port + block * 5));

        reply6.menu_id = LE32(0xFFFFFFFF);
        reply6.item_id = LE32(dlobby_id);
        strcpy(reply6.name, row[0]);

        if(dlobby_id != lobby_id) {
            /* See if we need to truncate the team name */
            if(flags & FW_FLAG_IS_PSOPC) {
                if(row[3][0] == '\t') {
                    strncpy(gname, row[3], 14);
                    gname[14] = 0;
                }
                else {
                    strncpy(gname + 2, row[3], 12);
                    gname[0] = '\t';
                    gname[1] = 'E';
                    gname[14] = 0;
                }
            }
            else {
                if(row[3][0] == '\t') {
                    strncpy(gname, row[3], 16);
                    gname[16] = 0;
                }
                else {
                    strncpy(gname + 2, row[3], 14);
                    gname[0] = '\t';
                    gname[1] = 'E';
                    gname[16] = 0;
                }
            }

            sprintf(reply6.location, "%s,%s, ,%s", gname, lobby_name, row[5]);
        }
        else {
            sprintf(reply6.location, "%s, ,%s", lobby_name, row[5]);
        }

        /* Send it away */
        forward_dreamcast(c, (dc_pkt_hdr_t *)&reply6, c->key_idx, 0, 0);
    }
    else {
        memset(&reply, 0, DC_GUILD_REPLY_LENGTH);

        /* Fill it in */
        reply.hdr.pkt_type = GUILD_REPLY_TYPE;
        reply.hdr.pkt_len = LE16(DC_GUILD_REPLY_LENGTH);
        reply.tag = LE32(0x00010000);
        reply.gc_search = pkt->gc_search;
        reply.gc_target = pkt->gc_target;
        reply.ip = htonl(ip);
        reply.port = LE16((port + block * 5));

        reply.menu_id = LE32(0xFFFFFFFF);
        reply.item_id = LE32(dlobby_id);
        strcpy(reply.name, row[0]);

        if(dlobby_id != lobby_id) {
            /* See if we need to truncate the team name */
            if(flags & FW_FLAG_IS_PSOPC) {
                if(row[3][0] == '\t') {
                    strncpy(gname, row[3], 14);
                    gname[14] = 0;
                }
                else {
                    strncpy(gname + 2, row[3], 12);
                    gname[0] = '\t';
                    gname[1] = 'E';
                    gname[14] = 0;
                }
            }
            else {
                if(row[3][0] == '\t') {
                    strncpy(gname, row[3], 16);
                    gname[16] = 0;
                }
                else {
                    strncpy(gname + 2, row[3], 14);
                    gname[0] = '\t';
                    gname[1] = 'E';
                    gname[16] = 0;
                }
            }

            sprintf(reply.location, "%s,%s, ,%s", gname, lobby_name, row[5]);
        }
        else {
            sprintf(reply.location, "%s, ,%s", lobby_name, row[5]);
        }

        /* Send it away */
        forward_dreamcast(c, (dc_pkt_hdr_t *)&reply, c->key_idx, 0, 0);
    }

out:
    /* Finally, we're finished, clean up and return! */
    sylverant_db_result_free(result);
    return 0;
}

static int handle_bb_guild_search(ship_t *c, shipgate_fw_9_pkt *pkt) {
    bb_guild_search_pkt *p = (bb_guild_search_pkt *)pkt->pkt;
    uint32_t guildcard = LE32(p->gc_target);
    uint32_t gc_sender = ntohl(pkt->guildcard);
    uint32_t b_sender = ntohl(pkt->block);
    char query[512];
    void *result;
    char **row;
    uint16_t ship_id, port;
    uint32_t lobby_id, ip, block, dlobby_id;
    uint64_t ip6_hi, ip6_lo;
    ship_t *s;
    bb_guild_reply_pkt reply;
    size_t in, out;
    ICONV_CONST char *inptr;
    char *outptr;
    char lobby_name[32], gname[17];

    /* Figure out where the user requested is */
    sprintf(query, "SELECT online_clients.name, online_clients.ship_id, block, "
            "lobby, lobby_id, online_ships.name, ip, port, gm_only, "
            "ship_ip6_high, ship_ip6_low, dlobby_id FROM online_clients INNER "
            "JOIN online_ships ON online_clients.ship_id = "
            "online_ships.ship_id WHERE guildcard='%u'", guildcard);
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
        /* The user's not online, give up. */
        goto out;
    }

    /* Make sure the user isn't on a GM only ship... if they are, bail now */
    if(atoi(row[8])) {
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

    /* If any of these are NULL, the user is not in a lobby. Thus, the client
       doesn't really exist just yet. */
    if(row[4] == NULL || row[3] == NULL || row[11] == NULL) {
        goto out;
    }

    /* Grab the data from the result */
    port = (uint16_t)strtoul(row[7], NULL, 0);
    block = (uint32_t)strtoul(row[2], NULL, 0);
    lobby_id = (uint32_t)strtoul(row[4], NULL, 0);
    ip = (uint32_t)strtoul(row[6], NULL, 0);
    ip6_hi = (uint64_t)strtoull(row[9], NULL, 0);
    ip6_lo = (uint64_t)strtoull(row[10], NULL, 0);
    dlobby_id = (uint32_t)strtoul(row[11], NULL, 0);

    if(errno) {
        debug(DBG_WARN, "Error parsing in guild search: %s", strerror(errno));
        goto out;
    }

    /* Set up the reply, we should have enough data now */
    memset(&reply, 0, BB_GUILD_REPLY_LENGTH);

    /* Fill it in */
    reply.hdr.pkt_type = LE16(GUILD_REPLY_TYPE);
    reply.hdr.pkt_len = LE16(BB_GUILD_REPLY_LENGTH);
    reply.tag = LE32(0x00010000);
    reply.gc_search = p->gc_search;
    reply.gc_target = p->gc_target;
    reply.ip = htonl(ip);
    reply.port = LE16((port + block * 5 + 4));
    reply.menu_id = LE32(0xFFFFFFFF);
    reply.item_id = LE32(dlobby_id);

    /* Convert the name to the right encoding */
    strcpy(query, row[0]);
    in = strlen(query);
    inptr = query;

    if(query[0] == '\t' && (query[1] == 'J' || query[1] == 'E')) {
        outptr = (char *)reply.name;
        out = 0x40;
    }
    else {
        outptr = (char *)&reply.name[2];
        reply.name[0] = LE16('\t');
        reply.name[1] = LE16('J');
        out = 0x3C;
    }

    iconv(ic_utf8_to_utf16, &inptr, &in, &outptr, &out);

    /* Build the location string, and convert it */
    if(dlobby_id != lobby_id) {
        if(row[3][0] == '\t') {
            strncpy(gname, row[3], 16);
            gname[16] = 0;
        }
        else {
            strncpy(gname + 2, row[3], 14);
            gname[0] = '\t';
            gname[1] = 'E';
            gname[16] = 0;
        }

        sprintf(query, "%s,%s, ,%s", gname, lobby_name, row[5]);
    }
    else {
        sprintf(query, "%s, ,%s", lobby_name, row[5]);
    }

    in = strlen(query);
    inptr = query;
    out = 0x88;
    outptr = (char *)reply.location;
    iconv(ic_utf8_to_utf16, &inptr, &in, &outptr, &out);

    /* Send it away */
    forward_bb(c, (bb_pkt_hdr_t *)&reply, c->key_idx, gc_sender, b_sender);

out:
    /* Finally, we're finished, clean up and return! */
    sylverant_db_result_free(result);

    return 0;
}

/* Handle a Blue Burst user's request to add a guildcard to their list */
static int handle_bb_gcadd(ship_t *c, shipgate_fw_9_pkt *pkt) {
    bb_guildcard_add_pkt *gc = (bb_guildcard_add_pkt *)pkt->pkt;
    uint16_t len = LE16(gc->hdr.pkt_len);
    uint32_t sender = ntohl(pkt->guildcard);
    uint32_t fr_gc = LE32(gc->guildcard);
    char query[1024];
    char name[97];
    char team_name[65];
    char text[373];

    /* Make sure the packet is sane */
    if(len != 0x0110) {
        return -1;
    }

    /* Escape all the strings first */
    sylverant_db_escape_str(&conn, name, (char *)gc->name, 48);
    sylverant_db_escape_str(&conn, team_name, (char *)gc->team_name, 32);
    sylverant_db_escape_str(&conn, text, (char *)gc->text, 176);

    /* Add the entry in the db... */
    sprintf(query, "INSERT INTO blueburst_guildcards (guildcard, friend_gc, "
            "name, team_name, text, language, section_id, class) VALUES ('%"
            PRIu32 "', '%" PRIu32 "', '%s', '%s', '%s', '%" PRIu8 "', '%"
            PRIu8 "', '%" PRIu8 "') ON DUPLICATE KEY UPDATE "
            "name=VALUES(name), text=VALUES(text), language=VALUES(language), "
            "section_id=VALUES(section_id), class=VALUES(class)", sender,
            fr_gc, name, team_name, text, gc->language, gc->section,
            gc->char_class);

    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "Couldn't add bb guildcard (%" PRIu32 ": %" PRIu32
              ")\n", sender, fr_gc);
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));

        send_error(c, SHDR_TYPE_BB, SHDR_RESPONSE | SHDR_FAILURE,
                   ERR_BAD_ERROR, (uint8_t *)gc, len);
        return 0;
    }

    /* And, we're done... */
    return 0;
}

/* Handle a Blue Burst user's request to delete a guildcard from their list */
static int handle_bb_gcdel(ship_t *c, shipgate_fw_9_pkt *pkt) {
    bb_guildcard_del_pkt *gc = (bb_guildcard_del_pkt *)pkt->pkt;
    uint16_t len = LE16(gc->hdr.pkt_len);
    uint32_t sender = ntohl(pkt->guildcard);
    uint32_t fr_gc = LE32(gc->guildcard);
    char query[256];

    if(len != 0x000C) {
        return -1;
    }

    /* Build the query and run it */
    sprintf(query, "CALL blueburst_guildcard_delete('%" PRIu32 "', '%" PRIu32
            "')", sender, fr_gc);

    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "Couldn't delete bb guildcard (%" PRIu32 ": %" PRIu32
              ")\n", sender, fr_gc);
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));

        send_error(c, SHDR_TYPE_BB, SHDR_RESPONSE | SHDR_FAILURE,
                   ERR_BAD_ERROR, (uint8_t *)gc, len);
        return 0;
    }

    /* And, we're done... */
    return 0;
}

/* Handle a Blue Burst user's request to sort guildcards */
static int handle_bb_gcsort(ship_t *c, shipgate_fw_9_pkt *pkt) {
    bb_guildcard_sort_pkt *gc = (bb_guildcard_sort_pkt *)pkt->pkt;
    uint16_t len = LE16(gc->hdr.pkt_len);
    uint32_t sender = ntohl(pkt->guildcard);
    uint32_t fr_gc1 = LE32(gc->guildcard1);
    uint32_t fr_gc2 = LE32(gc->guildcard2);
    char query[256];

    if(len != 0x0010) {
        return -1;
    }

    /* Build the query and run it */
    sprintf(query, "CALL blueburst_guildcard_sort('%" PRIu32 "', '%" PRIu32
            "', '%" PRIu32 "')", sender, fr_gc1, fr_gc2);

    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "Couldn't sort bb guildcards (%" PRIu32 ": %" PRIu32
              " - %" PRIu32 ")\n", sender, fr_gc1, fr_gc2);
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));

        send_error(c, SHDR_TYPE_BB, SHDR_RESPONSE | SHDR_FAILURE,
                   ERR_BAD_ERROR, (uint8_t *)gc, len);
        return 0;
    }

    /* And, we're done... */
    return 0;
}

/* Handle a Blue Burst user's request to add a user to their blacklist */
static int handle_bb_blacklistadd(ship_t *c, shipgate_fw_9_pkt *pkt) {
    bb_blacklist_add_pkt *gc = (bb_blacklist_add_pkt *)pkt->pkt;
    uint16_t len = LE16(gc->hdr.pkt_len);
    uint32_t sender = ntohl(pkt->guildcard);
    uint32_t bl_gc = LE32(gc->guildcard);
    char query[1024];
    char name[97];
    char team_name[65];
    char text[373];

    /* Make sure the packet is sane */
    if(len != 0x0110) {
        return -1;
    }

    /* Escape all the strings first */
    sylverant_db_escape_str(&conn, name, (char *)gc->name, 48);
    sylverant_db_escape_str(&conn, team_name, (char *)gc->team_name, 32);
    sylverant_db_escape_str(&conn, text, (char *)gc->text, 176);

    /* Add the entry in the db... */
    sprintf(query, "INSERT INTO blueburst_blacklist (guildcard, blocked_gc, "
            "name, team_name, text, language, section_id, class) VALUES ('%"
            PRIu32 "', '%" PRIu32 "', '%s', '%s', '%s', '%" PRIu8 "', '%"
            PRIu8 "', '%" PRIu8 "') ON DUPLICATE KEY UPDATE "
            "name=VALUES(name), text=VALUES(text), language=VALUES(language), "
            "section_id=VALUES(section_id), class=VALUES(class)", sender,
            bl_gc, name, team_name, text, gc->language, gc->section,
            gc->char_class);

    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "Couldn't add blacklist entry (%" PRIu32 ": %" PRIu32
              ")\n", sender, bl_gc);
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));

        send_error(c, SHDR_TYPE_BB, SHDR_RESPONSE | SHDR_FAILURE,
                   ERR_BAD_ERROR, (uint8_t *)gc, len);
        return 0;
    }

    /* And, we're done... */
    return 0;
}

/* Handle a Blue Burst user's request to delete a user from their blacklist */
static int handle_bb_blacklistdel(ship_t *c, shipgate_fw_9_pkt *pkt) {
    bb_blacklist_del_pkt *gc = (bb_blacklist_del_pkt *)pkt->pkt;
    uint16_t len = LE16(gc->hdr.pkt_len);
    uint32_t sender = ntohl(pkt->guildcard);
    uint32_t bl_gc = LE32(gc->guildcard);
    char query[256];

    if(len != 0x000C) {
        return -1;
    }

    /* Build the query and run it */
    sprintf(query, "DELETE FROM blueburst_blacklist WHERE guildcard='%" PRIu32
            "' AND blocked_gc='%" PRIu32 "'", sender, bl_gc);

    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "Couldn't delete blacklist entry (%" PRIu32 ": %"
              PRIu32 ")\n", sender, bl_gc);
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));

        send_error(c, SHDR_TYPE_BB, SHDR_RESPONSE | SHDR_FAILURE,
                   ERR_BAD_ERROR, (uint8_t *)gc, len);
        return 0;
    }

    /* And, we're done... */
    return 0;
}

/* Handle a Blue Burst set guildcard comment packet */
static int handle_bb_set_comment(ship_t *c, shipgate_fw_9_pkt *pkt) {
    bb_guildcard_comment_pkt *gc = (bb_guildcard_comment_pkt *)pkt->pkt;
    uint16_t pkt_len = LE16(gc->hdr.pkt_len);
    uint32_t sender = ntohl(pkt->guildcard);
    uint32_t fr_gc = LE32(gc->guildcard);
    char query[512];
    char comment[0x88 * 4 + 1];
    int len = 0;

    if(pkt_len != 0x00BC) {
        return -1;
    }

    /* Scan the string for its length */
    while(len < 0x88 && gc->text[len]) ++len;
    memset(&gc->text[len], 0, (0x88 - len) * 2);
    len = (len + 1) * 2;

    sylverant_db_escape_str(&conn, comment, (char *)gc->text, len);

    /* Build the query and run it */
    sprintf(query, "UPDATE blueburst_guildcards SET comment='%s' WHERE "
            "guildcard='%" PRIu32"' AND friend_gc='%" PRIu32 "'", comment,
            sender, fr_gc);

    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "Couldn't update guildcard comment (%" PRIu32 ": %"
              PRIu32 ")\n", sender, fr_gc);
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));

        send_error(c, SHDR_TYPE_BB, SHDR_RESPONSE | SHDR_FAILURE,
                   ERR_BAD_ERROR, (uint8_t *)gc, len);
        return 0;
    }

    /* And, we're done... */
    return 0;
}

/* Handle a ship's forwarded Dreamcast packet. */
static int handle_dreamcast(ship_t *c, shipgate_fw_9_pkt *pkt) {
    dc_pkt_hdr_t *hdr = (dc_pkt_hdr_t *)pkt->pkt;
    uint8_t type = hdr->pkt_type;
    uint32_t tmp;

    switch(type) {
        case GUILD_SEARCH_TYPE:
            tmp = ntohl(pkt->fw_flags);
            return handle_guild_search(c, (dc_guild_search_pkt *)hdr, tmp);

        case SIMPLE_MAIL_TYPE:
            return handle_dc_mail(c, (dc_simple_mail_pkt *)hdr);

        case GUILD_REPLY_TYPE:
            /* We shouldn't get these anymore (as of protocol v3)... */
        default:
            /* Warn the ship that sent the packet, then drop it */
            send_error(c, SHDR_TYPE_DC, SHDR_FAILURE, ERR_GAME_UNK_PACKET,
                       (uint8_t *)pkt, ntohs(pkt->hdr.pkt_len));
            return 0;
    }
}

/* Handle a ship's forwarded PC packet. */
static int handle_pc(ship_t *c, shipgate_fw_9_pkt *pkt) {
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

static int handle_bb(ship_t *c, shipgate_fw_9_pkt *pkt) {
    bb_pkt_hdr_t *hdr = (bb_pkt_hdr_t *)pkt->pkt;
    uint16_t type = LE16(hdr->pkt_type);
    uint16_t len = LE16(hdr->pkt_len);

    switch(type) {
        case BB_ADD_GUILDCARD_TYPE:
            return handle_bb_gcadd(c, pkt);

        case BB_DEL_GUILDCARD_TYPE:
            return handle_bb_gcdel(c, pkt);

        case BB_SORT_GUILDCARD_TYPE:
            return handle_bb_gcsort(c, pkt);

        case BB_ADD_BLOCKED_USER_TYPE:
            return handle_bb_blacklistadd(c, pkt);

        case BB_DEL_BLOCKED_USER_TYPE:
            return handle_bb_blacklistdel(c, pkt);

        case SIMPLE_MAIL_TYPE:
            return handle_bb_mail(c, (bb_simple_mail_pkt *)hdr);

        case GUILD_SEARCH_TYPE:
            return handle_bb_guild_search(c, pkt);

        case BB_SET_GUILDCARD_COMMENT_TYPE:
            return handle_bb_set_comment(c, pkt);

        default:
            /* Warn the ship that sent the packet, then drop it */
            send_error(c, SHDR_TYPE_BB, SHDR_FAILURE, ERR_GAME_UNK_PACKET,
                       (uint8_t *)pkt, len);
            return 0;
    }
}

/* Handle a ship's save character data packet. */
static int handle_cdata(ship_t *c, shipgate_char_data_pkt *pkt) {
    uint32_t gc, slot;
    uint16_t len = ntohs(pkt->hdr.pkt_len) - sizeof(shipgate_char_data_pkt);
    static char query[16384];
    Bytef *cmp_buf;
    uLong cmp_sz;
    int compressed = ~Z_OK;

    gc = ntohl(pkt->guildcard);
    slot = ntohl(pkt->slot);

    /* Is it a Blue Burst character or not? */
    if(len > 1056) {
        len = sizeof(sylverant_bb_db_char_t);
    }
    else {
        len = 1052;
    }

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

    /* Compress the character data */
    cmp_sz = compressBound((uLong)len);

    if((cmp_buf = (Bytef *)malloc(cmp_sz))) {
        compressed = compress2(cmp_buf, &cmp_sz, (Bytef *)pkt->data,
                               (uLong)len, 9);
    }

    /* Build up the store query for it. */
    if(compressed == Z_OK && cmp_sz < len) {
        sprintf(query, "INSERT INTO character_data(guildcard, slot, size, "
                "data) VALUES ('%u', '%u', '%u', '", gc, slot,
                (unsigned)len);
        sylverant_db_escape_str(&conn, query + strlen(query), (char *)cmp_buf,
                                cmp_sz);
    }
    else {
        sprintf(query, "INSERT INTO character_data(guildcard, slot, data) "
                "VALUES ('%u', '%u', '", gc, slot);
        sylverant_db_escape_str(&conn, query + strlen(query), (char *)pkt->data,
                                len);
    }

    strcat(query, "')");
    free(cmp_buf);

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

static int handle_cbkup_req(ship_t *c, shipgate_char_bkup_pkt *pkt, uint32_t gc,
                            const char name[], uint32_t block) {
    char query[256];
    char name2[65];
    uint8_t *data;
    void *result;
    char **row;
    unsigned long *len;
    int sz, rv;
    uLong sz2, csz;

    /* Build the query asking for the data. */
    sylverant_db_escape_str(&conn, name2, name, strlen(name));
    sprintf(query, "SELECT data, size FROM character_backup WHERE "
            "guildcard='%u' AND name='%s'", gc, name2);

    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "Couldn't fetch character backup (%u: %s)\n", gc, name);
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));

        send_error(c, SHDR_TYPE_CBKUP, SHDR_RESPONSE | SHDR_FAILURE,
                   ERR_BAD_ERROR, (uint8_t *)&pkt->guildcard, 8);
        return 0;
    }

    /* Grab the data we got. */
    if((result = sylverant_db_result_store(&conn)) == NULL) {
        debug(DBG_WARN, "Couldn't fetch character backup (%u: %s)\n", gc, name);
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));

        send_error(c, SHDR_TYPE_CBKUP, SHDR_RESPONSE | SHDR_FAILURE,
                   ERR_BAD_ERROR, (uint8_t *)&pkt->guildcard, 8);
        return 0;
    }

    if((row = sylverant_db_result_fetch(result)) == NULL) {
        sylverant_db_result_free(result);
        debug(DBG_WARN, "No saved character backup (%u: %s)\n", gc, name);
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));

        send_error(c, SHDR_TYPE_CBKUP, SHDR_RESPONSE | SHDR_FAILURE,
                   ERR_CREQ_NO_DATA, (uint8_t *)&pkt->guildcard, 8);
        return 0;
    }

    /* Grab the length of the character data */
    if(!(len = sylverant_db_result_lengths(result))) {
        sylverant_db_result_free(result);
        debug(DBG_WARN, "Couldn't get length of character backup\n");
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));

        send_error(c, SHDR_TYPE_CBKUP, SHDR_RESPONSE | SHDR_FAILURE,
                   ERR_BAD_ERROR, (uint8_t *)&pkt->guildcard, 8);
        return 0;
    }

    /* Grab the data from the result */
    sz = (int)len[0];

    if(row[1]) {
        sz2 = (uLong)atoi(row[1]);
        csz = (uLong)sz;

        data = (uint8_t *)malloc(sz2);
        if(!data) {
            sylverant_db_result_free(result);
            debug(DBG_WARN, "Couldn't allocate mem for uncompressed backup\n");
            debug(DBG_WARN, "%s\n", strerror(errno));
            sylverant_db_result_free(result);

            send_error(c, SHDR_TYPE_CBKUP, SHDR_RESPONSE | SHDR_FAILURE,
                       ERR_BAD_ERROR, (uint8_t *)&pkt->guildcard, 8);
            return 0;
        }

        /* Decompress it */
        if(uncompress((Bytef *)data, &sz2, (Bytef *)row[0], csz) != Z_OK) {
            sylverant_db_result_free(result);
            debug(DBG_WARN, "Couldn't decompress backup\n");
            sylverant_db_result_free(result);

            send_error(c, SHDR_TYPE_CBKUP, SHDR_RESPONSE | SHDR_FAILURE,
                       ERR_BAD_ERROR, (uint8_t *)&pkt->guildcard, 8);
            return 0;
        }

        sz = sz2;
    }
    else {
        data = (uint8_t *)malloc(sz);
        if(!data) {
            sylverant_db_result_free(result);
            debug(DBG_WARN, "Couldn't allocate memory for character backup\n");
            debug(DBG_WARN, "%s\n", strerror(errno));
            sylverant_db_result_free(result);

            send_error(c, SHDR_TYPE_CBKUP, SHDR_RESPONSE | SHDR_FAILURE,
                       ERR_BAD_ERROR, (uint8_t *)&pkt->guildcard, 8);
            return 0;
        }

        memcpy(data, row[0], len[0]);
    }

    sylverant_db_result_free(result);

    /* Send the data back to the ship. */
    rv = send_cdata(c, gc, (uint32_t)-1, data, sz, block);

    /* Clean up and finish */
    free(data);
    return rv;
}

static int handle_cbkup(ship_t *c, shipgate_char_bkup_pkt *pkt) {
    static char query[16384];
    uint32_t gc, block;
    uint16_t len = ntohs(pkt->hdr.pkt_len) - sizeof(shipgate_char_bkup_pkt);
    char name[32], name2[65];
    Bytef *cmp_buf;
    uLong cmp_sz;
    int compressed = ~Z_OK;

    gc = ntohl(pkt->guildcard);
    block = ntohl(pkt->block);
    strncpy(name, (const char *)pkt->name, 32);
    name[31] = 0;

    /* Make sure the ship is of a sane version */
    if(c->proto_ver < 11) {
        debug(DBG_WARN, "%s sent character backup pkt, but shouldn't have!\n",
              c->name);
        return -1;
    }

    /* Is this a restore request or are we saving the character data? */
    if(len == 0) {
        return handle_cbkup_req(c, pkt, gc, name, block);
    }

    /* Is it a Blue Burst character or not? */
    if(len > 1056) {
        len = sizeof(sylverant_bb_db_char_t);
    }
    else {
        len = 1052;
    }

    sylverant_db_escape_str(&conn, name2, name, strlen(name));

    /* Compress the character data */
    cmp_sz = compressBound((uLong)len);

    if((cmp_buf = (Bytef *)malloc(cmp_sz))) {
        compressed = compress2(cmp_buf, &cmp_sz, (Bytef *)pkt->data,
                               (uLong)len, 9);
    }

    /* Build up the store query for it. */
    if(compressed == Z_OK && cmp_sz < len) {
        sprintf(query, "INSERT INTO character_backup(guildcard, size, name, "
                "data) VALUES ('%u', '%u', '%s', '", gc, (unsigned)len, name2);
        sylverant_db_escape_str(&conn, query + strlen(query), (char *)cmp_buf,
                                cmp_sz);
    }
    else {
        sprintf(query, "INSERT INTO character_backup(guildcard, name, data) "
                "VALUES ('%u', '%s', '", gc, name2);
        sylverant_db_escape_str(&conn, query + strlen(query), (char *)pkt->data,
                                len);
    }

    strcat(query, "') ON DUPLICATE KEY UPDATE data=VALUES(data)");
    free(cmp_buf);

    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "Couldn't save character backup (%u: %s)\n", gc, name);
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));

        send_error(c, SHDR_TYPE_CBKUP, SHDR_RESPONSE | SHDR_FAILURE,
                   ERR_BAD_ERROR, (uint8_t *)&pkt->guildcard, 8);
        return 0;
    }

    /* Return success (yeah, bad use of this function, but whatever). */
    return send_error(c, SHDR_TYPE_CBKUP, SHDR_RESPONSE, ERR_NO_ERROR,
                      (uint8_t *)&pkt->guildcard, 8);
}

/* Handle a ship's character data request packet. */
static int handle_creq(ship_t *c, shipgate_char_req_pkt *pkt) {
    uint32_t gc, slot;
    char query[256];
    uint8_t *data;
    void *result;
    char **row;
    unsigned long *len;
    int sz, rv;
    uLong sz2, csz;

    gc = ntohl(pkt->guildcard);
    slot = ntohl(pkt->slot);

    /* Build the query asking for the data. */
    sprintf(query, "SELECT data, size FROM character_data WHERE guildcard='%u' "
            "AND slot='%u'", gc, slot);

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

    /* Grab the length of the character data */
    if(!(len = sylverant_db_result_lengths(result))) {
        sylverant_db_result_free(result);
        debug(DBG_WARN, "Couldn't get length of character data\n");
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));

        send_error(c, SHDR_TYPE_CREQ, SHDR_RESPONSE | SHDR_FAILURE,
                   ERR_BAD_ERROR, (uint8_t *)&pkt->guildcard, 8);
        return 0;
    }

    /* Grab the data from the result */
    sz = (int)len[0];

    if(row[1]) {
        sz2 = (uLong)atoi(row[1]);
        csz = (uLong)sz;

        data = (uint8_t *)malloc(sz2);
        if(!data) {
            sylverant_db_result_free(result);
            debug(DBG_WARN, "Couldn't allocate for uncompressed data\n");
            debug(DBG_WARN, "%s\n", strerror(errno));
            sylverant_db_result_free(result);

            send_error(c, SHDR_TYPE_CREQ, SHDR_RESPONSE | SHDR_FAILURE,
                       ERR_BAD_ERROR, (uint8_t *)&pkt->guildcard, 8);
            return 0;
        }

        /* Decompress it */
        if(uncompress((Bytef *)data, &sz2, (Bytef *)row[0], csz) != Z_OK) {
            sylverant_db_result_free(result);
            debug(DBG_WARN, "Couldn't decompress data\n");
            sylverant_db_result_free(result);

            send_error(c, SHDR_TYPE_CREQ, SHDR_RESPONSE | SHDR_FAILURE,
                       ERR_BAD_ERROR, (uint8_t *)&pkt->guildcard, 8);
            return 0;
        }

        sz = sz2;
    }
    else {
        data = (uint8_t *)malloc(sz);
        if(!data) {
            sylverant_db_result_free(result);
            debug(DBG_WARN, "Couldn't allocate for character data\n");
            debug(DBG_WARN, "%s\n", strerror(errno));
            sylverant_db_result_free(result);

            send_error(c, SHDR_TYPE_CREQ, SHDR_RESPONSE | SHDR_FAILURE,
                       ERR_BAD_ERROR, (uint8_t *)&pkt->guildcard, 8);
            return 0;
        }

        memcpy(data, row[0], len[0]);
    }

    sylverant_db_result_free(result);

    /* Send the data back to the ship. */
    rv = send_cdata(c, gc, slot, data, sz, 0);

    /* Clean up and finish */
    free(data);
    return rv;
}

/* Handle a GM login request coming from a ship. */
static int handle_gmlogin(ship_t *c, shipgate_gmlogin_req_pkt *pkt) {
    uint32_t gc, block;
    char query[256];
    void *result;
    char **row;
    int i;
    unsigned char hash[16];
    char esc[65];
    uint16_t len;
    uint8_t priv;

    /* Check the sanity of the packet. Disconnect the ship if there's some odd
       issue with the packet's sanity. */
    len = ntohs(pkt->hdr.pkt_len);
    if(len != sizeof(shipgate_gmlogin_req_pkt)) {
        debug(DBG_WARN, "Ship %s sent invalid GM Login!?\n", c->name);
        return -1;
    }

    if(pkt->username[31] != '\0' || pkt->password[31] != '\0') {
        debug(DBG_WARN, "Ship %s sent unterminated GM Login\n", c->name);
        return -1;
    }

    /* Escape the username and grab the data we need. */
    sylverant_db_escape_str(&conn, esc, pkt->username, strlen(pkt->username));
    gc = ntohl(pkt->guildcard);
    block = ntohl(pkt->block);

    /* Build the query asking for the data. */
    sprintf(query, "SELECT password, regtime, privlevel FROM guildcards "
            "NATURAL JOIN account_data WHERE guildcard='%u' AND username='%s'",
            gc, esc);

    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "Couldn't lookup account data (user: %s, gc: %u)\n",
              pkt->username, gc);
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));

        return send_error(c, SHDR_TYPE_GMLOGIN, SHDR_FAILURE, ERR_BAD_ERROR,
                          (uint8_t *)&pkt->guildcard, 8);
    }

    /* Grab the data we got. */
    if((result = sylverant_db_result_store(&conn)) == NULL) {
        debug(DBG_WARN, "Couldn't fetch account data (user: %s, gc: %u)\n",
              pkt->username, gc);
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));

        return send_error(c, SHDR_TYPE_GMLOGIN, SHDR_FAILURE, ERR_BAD_ERROR,
                          (uint8_t *)&pkt->guildcard, 8);
    }

    if((row = sylverant_db_result_fetch(result)) == NULL) {
        sylverant_db_result_free(result);
        debug(DBG_LOG, "Failed login - no data? (user: %s, gc: %u)\n",
              pkt->username, gc);

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
        debug(DBG_LOG, "Failed login - bad password (user: %s, gc: %u)\n",
              pkt->username, gc);
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
        debug(DBG_WARN, "Invalid privileges for user %u: %02x\n", pkt->username,
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
    char name[64];
    char tmp[128];
    uint32_t gc, bl, gc2, bl2, opt;
    uint16_t ship_id;
    ship_t *c2;
    void *result;
    char **row;
    void *optpkt;
    unsigned long *lengths;
    size_t in, out;
    ICONV_CONST char *inptr;
    char *outptr;

    /* Is the name a Blue Burst-style (UTF-16) name or not? */
    if(pkt->ch_name[0] == '\t') {
        memset(name, 0, 64);
        in = 32;
        out = 64;
        inptr = pkt->ch_name;
        outptr = name;

        iconv(ic_utf16_to_utf8, &inptr, &in, &outptr, &out);
    }
    else {
        /* Make sure the name is terminated properly */
        if(pkt->ch_name[31] != '\0') {
            return send_error(c, SHDR_TYPE_BLKLOGIN, SHDR_FAILURE,
                              ERR_BLOGIN_INVAL_NAME, (uint8_t *)&pkt->guildcard,
                              8);
        }

        /* The name is ASCII, which is safe to use as UTF-8 */
        strcpy(name, pkt->ch_name);
    }

    /* Parse out some stuff we'll use */
    gc = ntohl(pkt->guildcard);
    bl = ntohl(pkt->blocknum);

    /* Insert the client into the online_clients table */
    sylverant_db_escape_str(&conn, tmp, name, strlen(name));
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
        goto skip_friends;
    }

    /* Grab any results we got */
    if(!(result = sylverant_db_result_store(&conn))) {
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));
        goto skip_friends;
    }

    /* For each bite we get, send out a friend login packet */
    while((row = sylverant_db_result_fetch(result))) {
        gc2 = (uint32_t)strtoul(row[0], NULL, 0);
        bl2 = (uint32_t)strtoul(row[1], NULL, 0);
        ship_id = (uint16_t)strtoul(row[2], NULL, 0);
        c2 = find_ship(ship_id);

        if(c2) {
            send_friend_message(c2, 1, gc2, bl2, gc, bl, c->key_idx, name,
                                row[3]);
        }
    }

    sylverant_db_result_free(result);

skip_friends:
    /* See what options we have to deliver to the user */
    sprintf(query, "SELECT opt, value FROM user_options WHERE "
            "guildcard='%u'", gc);

    /* Query for any results */
    if(sylverant_db_query(&conn, query)) {
        /* Silently fail here (to the ship anyway), since this doesn't spell
           doom at all for the logged in user (although, it might spell some
           inconvenience, potentially) */
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));
        goto skip_opts;
    }

    /* Grab any results we got */
    if(!(result = sylverant_db_result_store(&conn))) {
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));
        goto skip_opts;
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

skip_opts:
    /* See if the user has an account or not. */
    sprintf(query, "SELECT account_id FROM guildcards WHERE guildcard='%"
            PRIu32 "'", gc);

    /* Query for any results */
    if(sylverant_db_query(&conn, query)) {
        /* Silently fail here (to the ship anyway), since this doesn't spell
           doom at all for the logged in user (although, it might spell some
           inconvenience, potentially) */
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));
        goto skip_mail;
    }

    /* Grab any results we got */
    if(!(result = sylverant_db_result_store(&conn))) {
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));
        goto skip_mail;
    }

    /* Find the account_id, if any. */
    if(!(row = sylverant_db_result_fetch(result)) || !row[0])
        goto skip_mail;

    gc2 = (uint32_t)strtoul(row[0], NULL, 0);
    sylverant_db_result_free(result);

    /* See whether the user has any saved mail. */
    sprintf(query, "SELECT COUNT(*) FROM simple_mail INNER JOIN guildcards ON "
            "simple_mail.recipient = guildcards.guildcard WHERE "
            "guildcards.account_id='%" PRIu32 "' AND simple_mail.status='0'",
            gc2);

    /* Query for any results */
    if(sylverant_db_query(&conn, query)) {
        /* Silently fail here (to the ship anyway), since this doesn't spell
           doom for the logged in user */
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));
        goto skip_mail;
    }

    /* Grab any results we got */
    if(!(result = sylverant_db_result_store(&conn))) {
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));
        goto skip_mail;
    }

    /* Look at the number from the result set. */
    row = sylverant_db_result_fetch(result);
    opt = (uint32_t)strtoul(row[0], NULL, 0);

    /* Do they have any mail waiting for them? */
    if(opt) {
        if(opt > 1)
            sprintf(query, "\tEYou have %" PRIu32 " unread messages. Please "
                    "visit the server website to read your mail.", opt);
        else
            sprintf(query, "\tEYou have an unread message. Please visit the "
                    "server website to read your mail.");

        send_simple_mail(c, gc, bl, 2, "Sys.Message", query);
    }

    sylverant_db_result_free(result);

skip_mail:
    /* We're done (no need to tell the ship on success) */
    return 0;
}

static int handle_blocklogout(ship_t *c, shipgate_block_login_pkt *pkt) {
    char query[512];
    char name[32];
    uint32_t gc, bl, gc2, bl2;
    uint16_t ship_id;
    ship_t *c2;
    void *result;
    char **row;
    size_t in, out;
    ICONV_CONST char *inptr;
    char *outptr;

    /* Is the name a Blue Burst-style (UTF-16) name or not? */
    if(pkt->ch_name[0] == '\t') {
        memset(name, 0, 32);
        in = 32;
        out = 32;
        inptr = pkt->ch_name;
        outptr = name;

        iconv(ic_utf16_to_utf8, &inptr, &in, &outptr, &out);
    }
    else {
        /* Make sure the name is terminated properly */
        if(pkt->ch_name[31] != '\0') {
            /* Maybe we should send an error here... Probably not worth it. */
            return 0;
        }

        /* The name is ASCII, which is safe to use as UTF-8 */
        strcpy(name, pkt->ch_name);
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
            send_friend_message(c2, 0, gc2, bl2, gc, bl, c->key_idx, name,
                                row[3]);
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

static int handle_friendlist_del(ship_t *c, shipgate_friend_upd_pkt *pkt) {
    uint32_t ugc, fgc;
    char query[256];

    /* Make sure the length is sane */
    if(pkt->hdr.pkt_len != htons(sizeof(shipgate_friend_upd_pkt))) {
        return -1;
    }

    /* Parse out the guildcards */
    ugc = ntohl(pkt->user_guildcard);
    fgc = ntohl(pkt->friend_guildcard);

    /* Build the db query */
    sprintf(query, "DELETE FROM friendlist WHERE owner='%u' AND friend='%u'",
            ugc, fgc);

    /* Execute the query */
    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));
        return send_error(c, SHDR_TYPE_DELFRIEND, SHDR_FAILURE, ERR_BAD_ERROR,
                          (uint8_t *)&pkt->user_guildcard, 8);
    }

    /* Return success to the ship */
    return send_error(c, SHDR_TYPE_DELFRIEND, SHDR_RESPONSE, ERR_NO_ERROR,
                      (uint8_t *)&pkt->user_guildcard, 8);
}

static int handle_lobby_chg(ship_t *c, shipgate_lobby_change_pkt *pkt) {
    char query[512];
    char tmp[128];
    uint32_t gc, lid;

    /* Make sure the name is terminated properly */
    pkt->lobby_name[31] = 0;

    /* Parse out some stuff we'll use */
    gc = ntohl(pkt->guildcard);
    lid = ntohl(pkt->lobby_id);

    /* Update the client's entry */
    sylverant_db_escape_str(&conn, tmp, pkt->lobby_name,
                            strlen(pkt->lobby_name));
    if(lid > 20) {
        sprintf(query, "UPDATE online_clients SET lobby_id='%u', lobby='%s' "
                "WHERE guildcard='%u' AND ship_id='%hu'", lid, tmp, gc,
                c->key_idx);
    }
    else {
        sprintf(query, "UPDATE online_clients SET lobby_id='%u', lobby='%s', "
                "dlobby_id='%u' WHERE guildcard='%u' AND ship_id='%hu'", lid,
                tmp, lid, gc, c->key_idx);
    }

    /* This shouldn't ever "fail" so to speak... */
    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));
        return 0;
    }

    /* We're done (no need to tell the ship on success) */
    return 0;
}

static int handle_block_clients(ship_t *c, shipgate_bclients_pkt *pkt) {
    char query[512];
    char tmp[128], tmp2[128], name[64];
    uint32_t gc, lid, count, bl, i;
    uint16_t len;
    size_t in, out;
    ICONV_CONST char *inptr;
    char *outptr;

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
        /* Is the name a Blue Burst-style (UTF-16) name or not? */
        if(pkt->entries[i].ch_name[0] == '\t') {
            memset(name, 0, 64);
            in = 32;
            out = 64;
            inptr = pkt->entries[i].ch_name;
            outptr = name;

            iconv(ic_utf16_to_utf8, &inptr, &in, &outptr, &out);
        }
        else {
            /* Make sure the name is terminated properly */
            if(pkt->entries[i].ch_name[31] != '\0') {
                continue;
            }

            /* The name is ASCII, which is safe to use as UTF-8 */
            strcpy(name, pkt->entries[i].ch_name);
        }

        /* Make sure the names look sane */
        if(pkt->entries[i].lobby_name[31]) {
            continue;
        }

        /* Grab the integers out */
        gc = ntohl(pkt->entries[i].guildcard);
        lid = ntohl(pkt->entries[i].lobby);

        /* Escape the name string */
        sylverant_db_escape_str(&conn, tmp, name, strlen(name));

        /* If we're not in a lobby, that's all we need */
        if(lid == 0) {
            sprintf(query, "INSERT INTO online_clients(guildcard, name, "
                    "ship_id, block) VALUES('%u', '%s', '%hu', '%u')", gc, tmp,
                    c->key_idx, bl);
        }
        else if(lid <= 20) {
            sylverant_db_escape_str(&conn, tmp2, pkt->entries[i].lobby_name,
                                    strlen(pkt->entries[i].lobby_name));
            sprintf(query, "INSERT INTO online_clients(guildcard, name, "
                    "ship_id, block, lobby_id, lobby, dlobby_id) VALUES('%u', "
                    "'%s', '%hu', '%u', '%u', '%s', '%u')", gc, tmp, c->key_idx,
                    bl, lid, tmp2, lid);
        }
        else {
            sylverant_db_escape_str(&conn, tmp2, pkt->entries[i].lobby_name,
                                    strlen(pkt->entries[i].lobby_name));
            sprintf(query, "INSERT INTO online_clients(guildcard, name, "
                    "ship_id, block, lobby_id, lobby, dlobby_id) VALUES('%u', "
                    "'%s', '%hu', '%u', '%u', '%s', '1')", gc, tmp, c->key_idx,
                    bl, lid, tmp2);
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

static int handle_clients12(ship_t *c, shipgate_bclients_12_pkt *pkt) {
    char query[512];
    char tmp[128], tmp2[128], name[64];
    uint32_t gc, lid, dlid, count, bl, i;
    uint16_t len;
    size_t in, out;
    ICONV_CONST char *inptr;
    char *outptr;

    /* Verify the length is right */
    count = ntohl(pkt->count);
    len = ntohs(pkt->hdr.pkt_len);

    if(len != 16 + count * 80 || count < 1) {
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
        /* Is the name a Blue Burst-style (UTF-16) name or not? */
        if(pkt->entries[i].ch_name[0] == '\t') {
            memset(name, 0, 64);
            in = 32;
            out = 64;
            inptr = pkt->entries[i].ch_name;
            outptr = name;

            iconv(ic_utf16_to_utf8, &inptr, &in, &outptr, &out);
        }
        else {
            /* Make sure the name is terminated properly */
            if(pkt->entries[i].ch_name[31] != '\0') {
                continue;
            }

            /* The name is ASCII, which is safe to use as UTF-8 */
            strcpy(name, pkt->entries[i].ch_name);
        }

        /* Make sure the names look sane */
        if(pkt->entries[i].lobby_name[31]) {
            continue;
        }

        /* Grab the integers out */
        gc = ntohl(pkt->entries[i].guildcard);
        lid = ntohl(pkt->entries[i].lobby);
        dlid = ntohl(pkt->entries[i].dlobby);

        /* Escape the name string */
        sylverant_db_escape_str(&conn, tmp, name, strlen(name));

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
                    "ship_id, block, lobby_id, lobby, dlobby_id) VALUES('%u', "
                    "'%s', '%hu', '%u', '%u', '%s', '%u')", gc, tmp, c->key_idx,
                    bl, lid, tmp2, dlid);
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
        case USER_OPT_ENABLE_BACKUP:
        case USER_OPT_GC_PROTECT:
        case USER_OPT_TRACK_KILLS:
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

static int handle_bbopt_req(ship_t *c, shipgate_bb_opts_req_pkt *pkt) {
    char query[1024];
    uint32_t gc, block;
    void *result;
    char **row;
    sylverant_bb_db_opts_t opts;

    /* Parse out the guildcard */
    gc = ntohl(pkt->guildcard);
    block = ntohl(pkt->block);

    /* Build the db query */
    sprintf(query, "SELECT options FROM blueburst_options WHERE guildcard='%"
            PRIu32 "'", gc);

    /* Execute the query */
    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));
        return send_error(c, SHDR_TYPE_BBOPTS, SHDR_FAILURE, ERR_BAD_ERROR,
                          (uint8_t *)&pkt->guildcard, 8);
    }

    if(!(result = sylverant_db_result_store(&conn))) {
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));
        return send_error(c, SHDR_TYPE_BBOPTS, SHDR_FAILURE, ERR_BAD_ERROR,
                          (uint8_t *)&pkt->guildcard, 8);
    }

    if(!(row = sylverant_db_result_fetch(result))) {
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));
        sylverant_db_result_free(result);
        return send_error(c, SHDR_TYPE_BBOPTS, SHDR_FAILURE, ERR_BAD_ERROR,
                          (uint8_t *)&pkt->guildcard, 8);
    }

    /* Send the packet */
    memcpy(&opts, row[0], sizeof(sylverant_bb_db_opts_t));
    send_bb_opts(c, gc, block, &opts);

    sylverant_db_result_free(result);
    return 0;
}

static int handle_bbopts(ship_t *c, shipgate_bb_opts_pkt *pkt) {
    static char query[sizeof(sylverant_bb_db_opts_t) * 2 + 256];
    uint32_t gc;

    /* Parse out the guildcard */
    gc = ntohl(pkt->guildcard);

    /* Build the db query */
    strcpy(query, "UPDATE blueburst_options SET options='");
    sylverant_db_escape_str(&conn, query + strlen(query), (char *)&pkt->opts,
                            sizeof(sylverant_bb_db_opts_t));
    sprintf(query + strlen(query), "' WHERE guildcard='%" PRIu32 "'", gc);

    /* Execute the query */
    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));
        return send_error(c, SHDR_TYPE_BBOPTS, SHDR_FAILURE, ERR_BAD_ERROR,
                          (uint8_t *)&pkt->guildcard, 8);
    }

    return 0;
}

static int handle_mkill(ship_t *c, shipgate_mkill_pkt *pkt) {
    char query[256];
    uint32_t gc, ct, acc;
    int i;
    void *result;
    char **row;
    monster_event_t *ev;

    /* Ignore any packets that aren't version 1 or later. They're useless. */
    if(pkt->hdr.version < 1)
        return 0;

    /* See if there's an event currently running, otherwise we can safely drop
       any monster kill packets we get. */
    if(!(ev = find_current_event(pkt->difficulty, pkt->version)))
        return 0;

    /* Parse out the guildcard */
    gc = ntohl(pkt->guildcard);

    /* Find the user's account id */
    sprintf(query, "SELECT account_id FROM guildcards WHERE guildcard='%"
            PRIu32 "'", gc);

    if(sylverant_db_query(&conn, query)) {
        debug(DBG_WARN, "Couldn't fetch account data (%" PRIu32 ")\n", gc);
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));

        return send_error(c, SHDR_TYPE_MKILL, SHDR_FAILURE, ERR_BAD_ERROR,
                          (uint8_t *)&pkt->guildcard, 16);
    }

    /* Grab the data we got. */
    if((result = sylverant_db_result_store(&conn)) == NULL) {
        debug(DBG_WARN, "Couldn't fetch account data (%" PRIu32 ")\n", gc);
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));

        return send_error(c, SHDR_TYPE_MKILL, SHDR_FAILURE, ERR_BAD_ERROR,
                          (uint8_t *)&pkt->guildcard, 8);
    }

    if((row = sylverant_db_result_fetch(result)) == NULL) {
        sylverant_db_result_free(result);
        debug(DBG_WARN, "Couldn't fetch account data (%" PRIu32 ")\n", gc);
        debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));

        return send_error(c, SHDR_TYPE_MKILL, SHDR_FAILURE, ERR_BAD_ERROR,
                          (uint8_t *)&pkt->guildcard, 8);
    }

    /* If their account id in the table is NULL, then bail. No need to report an
       error for this. */
    if(!row[0]) {
        sylverant_db_result_free(result);
        return 0;
    }

    /* We've verified they've got an account, continue on. */
    acc = atoi(row[0]);
    sylverant_db_result_free(result);

    /* Are we recording all monsters, or just a few? */
    if(ev->monster_count) {
        for(i = 0; i < ev->monster_count; ++i) {
            if(ev->monsters[i].monster > 0x60)
                continue;

            ct = ntohl(pkt->counts[ev->monsters[i].monster]);

            if(!ct || pkt->episode != ev->monsters[i].episode)
                continue;

            sprintf(query, "INSERT INTO monster_kills (account_id, guildcard, "
                    "episode, difficulty, enemy, count) VALUES('%" PRIu32 "', "
                    "'%" PRIu32 "', '%u', '%u', '%d', '%" PRIu32"') ON "
                    "DUPLICATE KEY UPDATE count=count+VALUES(count)", acc, gc,
                    (unsigned int)pkt->episode, (unsigned int)pkt->difficulty,
                    i, ct);

            /* Execute the query */
            if(sylverant_db_query(&conn, query)) {
                debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));
                return send_error(c, SHDR_TYPE_MKILL, SHDR_FAILURE,
                                  ERR_BAD_ERROR, (uint8_t *)&pkt->guildcard, 8);
            }
        }

        return 0;
    }

    /* Go through each entry... */
    for(i = 0; i < 0x60; ++i) {
        ct = ntohl(pkt->counts[i]);

        if(!ct)
            continue;

        sprintf(query, "INSERT INTO monster_kills (account_id, guildcard, "
                "episode, difficulty, enemy, count) VALUES('%" PRIu32 "', "
                "'%" PRIu32 "', '%u', '%u', '%d', '%" PRIu32"') ON DUPLICATE "
                "KEY UPDATE count=count+VALUES(count)", acc, gc,
                (unsigned int)pkt->episode, (unsigned int)pkt->difficulty, i,
                ct);

        /* Execute the query */
        if(sylverant_db_query(&conn, query)) {
            debug(DBG_WARN, "%s\n", sylverant_db_error(&conn));
            return send_error(c, SHDR_TYPE_MKILL, SHDR_FAILURE, ERR_BAD_ERROR,
                              (uint8_t *)&pkt->guildcard, 8);
        }
    }

    return 0;
}

/* Process one ship packet. */
int process_ship_pkt(ship_t *c, shipgate_hdr_t *pkt) {
    uint16_t type = ntohs(pkt->pkt_type);
    uint16_t flags = ntohs(pkt->flags);

    switch(type) {
        case SHDR_TYPE_LOGIN6:
        {
            shipgate_login6_reply_pkt *p = (shipgate_login6_reply_pkt *)pkt;

            if(!(flags & SHDR_RESPONSE)) {
                debug(DBG_WARN, "Client sent invalid login response\n");
                return -1;
            }

            return handle_shipgate_login6t(c, p);
        }

        case SHDR_TYPE_COUNT:
            return handle_count(c, (shipgate_cnt_pkt *)pkt);

        case SHDR_TYPE_DC:
            return handle_dreamcast(c, (shipgate_fw_9_pkt *)pkt);

        case SHDR_TYPE_PC:
            return handle_pc(c, (shipgate_fw_9_pkt *)pkt);

        case SHDR_TYPE_BB:
            return handle_bb(c, (shipgate_fw_9_pkt *)pkt);

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
            return handle_friendlist_add(c, (shipgate_friend_add_pkt *)pkt);

        case SHDR_TYPE_DELFRIEND:
            return handle_friendlist_del(c, (shipgate_friend_upd_pkt *)pkt);

        case SHDR_TYPE_LOBBYCHG:
            return handle_lobby_chg(c, (shipgate_lobby_change_pkt *)pkt);

        case SHDR_TYPE_BCLIENTS:
            if(c->proto_ver < 12)
                return handle_block_clients(c, (shipgate_bclients_pkt *)pkt);
            else
                return handle_clients12(c, (shipgate_bclients_12_pkt *)pkt);

        case SHDR_TYPE_KICK:
            return handle_kick(c, (shipgate_kick_pkt *)pkt);

        case SHDR_TYPE_FRLIST:
            return handle_frlist_req(c, (shipgate_friend_list_req *)pkt);

        case SHDR_TYPE_GLOBALMSG:
            return handle_globalmsg(c, (shipgate_global_msg_pkt *)pkt);

        case SHDR_TYPE_USEROPT:
            return handle_useropt(c, (shipgate_user_opt_pkt *)pkt);

        case SHDR_TYPE_BBOPTS:
            return handle_bbopts(c, (shipgate_bb_opts_pkt *)pkt);

        case SHDR_TYPE_BBOPT_REQ:
            return handle_bbopt_req(c, (shipgate_bb_opts_req_pkt *)pkt);

        case SHDR_TYPE_CBKUP:
            return handle_cbkup(c, (shipgate_char_bkup_pkt *)pkt);

        case SHDR_TYPE_MKILL:
            return handle_mkill(c, (shipgate_mkill_pkt *)pkt);

        default:
            debug(DBG_WARN, "%s sent invalid packet: %hu\n", c->name, type);
            return -3;
    }
}

static ssize_t ship_recv(ship_t *c, void *buffer, size_t len) {
    return gnutls_record_recv(c->session, buffer, len);
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
    if((sz = ship_recv(c, recvbuf + c->recvbuf_cur,
                       65536 - c->recvbuf_cur)) <= 0) {
        if(sz == -1) {
            perror("ship_recv");
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
                memcpy(&c->pkt, rbp, 8);
                c->hdr_read = 1;
            }

            pkt_sz = htons(c->pkt.pkt_len);

            /* Do we have the whole packet? */
            if(sz >= (ssize_t)pkt_sz) {
                /* Yep, copy it and process it */
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
