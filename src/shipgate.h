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

#ifndef SHIPGATE_H
#define SHIPGATE_H

#include <inttypes.h>

#include "ship.h"
#include "ship_packets.h"

/* What version is this? */
#define VERSION "0.1.0"

#define VERSION_MAJOR 0
#define VERSION_MINOR 1
#define VERSION_MICRO 0

#ifdef PACKED
#undef PACKED
#endif

#define PACKED __attribute__((packed))

/* The request sent from the shipgate for a ship to identify itself. */
typedef struct shipgate_login {
    shipgate_hdr_t hdr;
    char msg[45];
    uint8_t ver_major;
    uint8_t ver_minor;
    uint8_t ver_micro;
    uint8_t gate_nonce[4];
    uint8_t ship_nonce[4];
} PACKED shipgate_login_pkt;

/* The reply to the login request from the shipgate. */
typedef struct shipgate_login_reply {
    shipgate_hdr_t hdr;
    char name[12];
    uint32_t ship_addr;
    uint32_t int_addr;
    uint16_t ship_port;
    uint16_t ship_key;
    uint32_t connections;
    uint32_t reserved;
} PACKED shipgate_login_reply_pkt;

/* A update of the client/games count. */
typedef struct shipgate_cnt {
    shipgate_hdr_t hdr;
    uint16_t ccnt;
    uint16_t gcnt;
    uint32_t padding;
} PACKED shipgate_cnt_pkt;

/* A forwarded player packet. */
typedef struct shipgate_fw {
    shipgate_hdr_t hdr;
    uint32_t ship_id;
    uint32_t reserved;
    dc_pkt_hdr_t pkt;
} PACKED shipgate_fw_pkt;

/* A packet telling clients that a ship has started or dropped. */
typedef struct shipgate_ship_status {
    shipgate_hdr_t hdr;
    char name[12];
    uint32_t ship_id;
    uint32_t ship_addr;
    uint32_t int_addr;
    uint16_t ship_port;
    uint16_t status;
    uint32_t reserved;
} PACKED shipgate_ship_status_pkt;

/* A packet sent to/from clients to save/restore character data. */
typedef struct shipgate_char_data {
    shipgate_hdr_t hdr;
    uint32_t guildcard;
    uint32_t slot;
    uint32_t padding;
    uint8_t data[1052];
} PACKED shipgate_char_data_pkt;

/* A packet sent to request saved character data. */
typedef struct shipgate_char_req {
    shipgate_hdr_t hdr;
    uint32_t guildcard;
    uint32_t slot;
} PACKED shipgate_char_req_pkt;

/* A packet sent to login a Global GM. */
typedef struct shipgate_gmlogin_req {
    shipgate_hdr_t hdr;
    uint32_t guildcard;
    uint32_t block;
    char username[32];
    char password[32];
} PACKED shipgate_gmlogin_req_pkt;

/* A packet replying to a Global GM login. */
typedef struct shipgate_gmlogin_reply {
    shipgate_hdr_t hdr;
    uint32_t guildcard;
    uint32_t block;
} PACKED shipgate_gmlogin_reply_pkt;

#undef PACKED

/* Size of the shipgate login packet. */
#define SHIPGATE_LOGIN_SIZE         64

/* The requisite message for the msg field of the shipgate_login_pkt. */
static const char shipgate_login_msg[] =
    "Sylverant Shipgate Copyright Lawrence Sebald";

/* Flags for the flags field of shipgate_hdr_t */
#define SHDR_NO_DEFLATE     0x0001      /* Packet was not deflate()'d */
#define SHDR_NO_ENCRYPT     0x0002      /* Packet is not encrypted */
#define SHDR_RESPONSE       0x8000      /* Response to a request */
#define SHDR_FAILURE        0x4000      /* Failure to complete request */

/* Types for the pkt_type field of shipgate_hdr_t */
#define SHDR_TYPE_DC        0x0001      /* A decrypted Dreamcast game packet */
#define SHDR_TYPE_BB        0x0002      /* A decrypted Blue Burst game packet */
#define SHDR_TYPE_PC        0x0003      /* A decrypted PCv2 game packet */
#define SHDR_TYPE_GC        0x0004      /* A decrypted Gamecube game packet */
#define SHDR_TYPE_LOGIN     0x0010      /* A login request */
#define SHDR_TYPE_COUNT     0x0011      /* A Client Count update */
#define SHDR_TYPE_SSTATUS   0x0012      /* A Ship has come up or gone down */
#define SHDR_TYPE_PING      0x0013      /* A Ping packet, enough said */
#define SHDR_TYPE_CDATA     0x0014      /* Character data */
#define SHDR_TYPE_CREQ      0x0015      /* Request saved character data */
#define SHDR_TYPE_GMLOGIN   0x0016      /* Login request for a Global GM */

/* Send a welcome packet to the given ship. */
int send_welcome(ship_t *c);

/* Forward a Dreamcast packet to the given ship, with additional metadata. */
int forward_dreamcast(ship_t *c, dc_pkt_hdr_t *pkt, uint32_t sender);

/* Send a ship up/down message to the given ship. */
int send_ship_status(ship_t *c, char name[], uint32_t sid, uint32_t addr,
                     uint32_t int_addr, uint16_t port, uint16_t status);

/* Send a ping packet to a client. */
int send_ping(ship_t *c, int reply);

/* Send the ship a character data restore. */
int send_cdata(ship_t *c, uint32_t gc, uint32_t slot, void *cdata);

/* Send a reply to a GM login request. */
int send_gmreply(ship_t *c, uint32_t gc, uint32_t block, int good);

#endif /* !SHIPGATE_H */
