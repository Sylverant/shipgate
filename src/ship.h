/*
    Sylverant Shipgate
    Copyright (C) 2009, 2011 Lawrence Sebald

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

#ifndef SHIP_H
#define SHIP_H

#include <time.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/queue.h>

#include <gnutls/gnutls.h>

#ifdef PACKED
#undef PACKED
#endif

#define PACKED __attribute__((packed))

/* The header that is prepended to any packets sent to the shipgate (new version
   for protocol v10 and newer). */
typedef struct shipgate_hdr {
    uint16_t pkt_len;
    uint16_t pkt_type;
    uint8_t version;
    uint8_t reserved;
    uint16_t flags;
} PACKED shipgate_hdr_t;

/* This is used for storing the friendlist data for a friend list request. */
typedef struct friendlist_data {
    uint32_t guildcard;
    uint32_t ship;
    uint32_t block;
    uint32_t reserved;
    char name[32];
} PACKED friendlist_data_t;

#undef PACKED

typedef struct ship {
    TAILQ_ENTRY(ship) qentry;

    int sock;
    int disconnected;
    uint32_t flags;
    uint32_t menu;

    struct in6_addr remote_addr6;
    struct sockaddr_storage conn_addr;

    in_addr_t remote_addr;
    uint32_t proto_ver;

    uint16_t port;
    uint16_t key_idx;
    uint16_t clients;
    uint16_t games;
    uint16_t menu_code;

    int ship_number;
    uint8_t ship_nonce[4];
    uint8_t gate_nonce[4];

    time_t last_message;
    time_t last_ping;

    unsigned char *recvbuf;
    int recvbuf_cur;
    int recvbuf_size;
    shipgate_hdr_t pkt;
    int hdr_read;

    unsigned char *sendbuf;
    int sendbuf_cur;
    int sendbuf_size;
    int sendbuf_start;

    gnutls_session_t session;

    char name[12];
} ship_t;

TAILQ_HEAD(ship_queue, ship);
extern struct ship_queue ships;

/* Create a new connection, storing it in the list of ships. */
ship_t *create_connection_tls(int sock, struct sockaddr *addr, socklen_t size);

/* Destroy a connection, closing the socket and removing it from the list. */
void destroy_connection(ship_t *c);

/* Handle incoming data to the shipgate. */
int handle_pkt(ship_t *s);

#endif /* !SHIP_H */
