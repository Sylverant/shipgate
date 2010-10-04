/*
    Sylverant Shipgate
    Copyright (C) 2009, 2010 Lawrence Sebald

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

#ifndef SHIPGATE_H
#define SHIPGATE_H

#include <inttypes.h>

#include "ship.h"
#include "ship_packets.h"

/* Minimum and maximum supported protocol ship<->shipgate protocol versions */
#define SHIPGATE_MINIMUM_PROTO_VER 1
#define SHIPGATE_MAXIMUM_PROTO_VER 2

#ifdef PACKED
#undef PACKED
#endif

#define PACKED __attribute__((packed))

/* General error packet. Individual packets can/should extend this base
   structure for more specific instances and to help match requests up with the
   error replies. */
typedef struct shipgate_error {
    shipgate_hdr_t hdr;
    uint32_t error_code;
    uint32_t reserved;
    uint8_t data[0];
} PACKED shipgate_error_pkt;

/* Error packet in reply to character data send or character request */
typedef struct shipgate_cdata_err {
    shipgate_error_pkt base;
    uint32_t guildcard;
    uint32_t slot;
} PACKED shipgate_cdata_err_pkt;

/* Error packet in reply to gm login */
typedef struct shipgate_gm_err {
    shipgate_error_pkt base;
    uint32_t guildcard;
    uint32_t block;
} PACKED shipgate_gm_err_pkt;

/* Error packet in reply to ban */
typedef struct shipgate_ban_err {
    shipgate_error_pkt base;
    uint32_t req_gc;
    uint32_t target;
    uint32_t until;
    uint32_t reserved;
} PACKED shipgate_ban_err_pkt;

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
    uint16_t clients;
    uint16_t games;
    uint32_t flags;
    uint16_t menu_code;
    uint8_t reserved[2];
    uint32_t proto_ver;
} PACKED shipgate_login_reply_pkt;

/* A update of the client/games count. */
typedef struct shipgate_cnt {
    shipgate_hdr_t hdr;
    uint16_t clients;
    uint16_t games;
    uint32_t ship_id;                   /* 0 for ship->gate */
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
    uint32_t flags;
    uint16_t clients;
    uint16_t games;
    uint16_t menu_code;
    uint16_t reserved;
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
    uint8_t priv;
    uint8_t reserved[7];
} PACKED shipgate_gmlogin_reply_pkt;

/* A packet used to set a ban. */
typedef struct shipgate_ban_req {
    shipgate_hdr_t hdr;
    uint32_t req_gc;
    uint32_t target;
    uint32_t until;
    uint32_t reserved;
    char message[256];
} PACKED shipgate_ban_req_pkt;

/* Packet used to tell the shipgate that a user has logged into/off a block */
typedef struct shipgate_block_login {
    shipgate_hdr_t hdr;
    uint32_t guildcard;
    uint32_t blocknum;
    char ch_name[32];
} PACKED shipgate_block_login_pkt;

/* Packet to tell a ship that a client's friend has logged in/out */
typedef struct shipgate_friend_login {
    shipgate_hdr_t hdr;
    uint32_t dest_guildcard;
    uint32_t dest_block;
    uint32_t friend_guildcard;
    uint32_t friend_ship;
    uint32_t friend_block;
    uint32_t reserved;
    char friend_name[32];
} PACKED shipgate_friend_login_pkt;

/* Packet to update a user's friendlist (used for either add or remove) */
typedef struct shipgate_friend_upd {
    shipgate_hdr_t hdr;
    uint32_t user_guildcard;
    uint32_t friend_guildcard;
} PACKED shipgate_friend_upd_pkt;
    
#undef PACKED

/* The requisite message for the msg field of the shipgate_login_pkt. */
static const char shipgate_login_msg[] =
    "Sylverant Shipgate Copyright Lawrence Sebald";

/* Flags for the flags field of shipgate_hdr_t */
#define SHDR_NO_DEFLATE     0x0001      /* Packet was not deflate()'d */
#define SHDR_RESPONSE       0x8000      /* Response to a request */
#define SHDR_FAILURE        0x4000      /* Failure to complete request */

/* Types for the pkt_type field of shipgate_hdr_t */
#define SHDR_TYPE_DC        0x0001      /* A decrypted Dreamcast game packet */
#define SHDR_TYPE_BB        0x0002      /* A decrypted Blue Burst game packet */
#define SHDR_TYPE_PC        0x0003      /* A decrypted PCv2 game packet */
#define SHDR_TYPE_GC        0x0004      /* A decrypted Gamecube game packet */
#define SHDR_TYPE_LOGIN     0x0010      /* A login request */
#define SHDR_TYPE_COUNT     0x0011      /* A Client/Game Count update */
#define SHDR_TYPE_SSTATUS   0x0012      /* A Ship has come up or gone down */
#define SHDR_TYPE_PING      0x0013      /* A Ping packet, enough said */
#define SHDR_TYPE_CDATA     0x0014      /* Character data */
#define SHDR_TYPE_CREQ      0x0015      /* Request saved character data */
#define SHDR_TYPE_GMLOGIN   0x0016      /* Login request for a Global GM */
#define SHDR_TYPE_GCBAN     0x0017      /* Guildcard ban */
#define SHDR_TYPE_IPBAN     0x0018      /* IP ban */
#define SHDR_TYPE_BLKLOGIN  0x0019      /* User logs into a block */
#define SHDR_TYPE_BLKLOGOUT 0x001A      /* User logs off a block */
#define SHDR_TYPE_FRLOGIN   0x001B      /* A user's friend logs onto a block */
#define SHDR_TYPE_FRLOGOUT  0x001C      /* A user's friend logs off a block */
#define SHDR_TYPE_ADDFRIEND 0x001D      /* Add a friend to a user's list */
#define SHDR_TYPE_DELFRIEND 0x001E      /* Remove a friend from a user's list */

/* Flags that can be set in the login packet */
#define LOGIN_FLAG_GMONLY   0x00000001  /* Only Global GMs are allowed */
#define LOGIN_FLAG_PROXY    0x00000002  /* Is a proxy -- exclude many pkts */

/* General error codes */
#define ERR_NO_ERROR            0x00000000
#define ERR_BAD_ERROR           0x80000001

/* Error codes in response to shipgate_login_reply_pkt */
#define ERR_LOGIN_BAD_KEY       0x00000001
#define ERR_LOGIN_BAD_PROTO     0x00000002
#define ERR_LOGIN_BAD_MENU      0x00000003  /* bad menu code (out of range) */
#define ERR_LOGIN_INVAL_MENU    0x00000004  /* menu code not allowed */

/* Error codes in response to game packets */
#define ERR_GAME_UNK_PACKET     0x00000001

/* Error codes in response to a character request */
#define ERR_CREQ_NO_DATA        0x00000001

/* Error codes in response to a gm login */
#define ERR_GMLOGIN_NO_ACC      0x00000001
#define ERR_GMLOGIN_NOT_GM      0x00000002

/* Error codes in response to a ban request */
#define ERR_BAN_NOT_GM          0x00000001
#define ERR_BAN_BAD_TYPE        0x00000002

/* Error codes in response to a block login */
#define ERR_BLOGIN_INVAL_NAME   0x00000001
#define ERR_BLOGIN_ONLINE       0x00000002

/* Send a welcome packet to the given ship. */
int send_welcome(ship_t *c);

/* Forward a Dreamcast packet to the given ship, with additional metadata. */
int forward_dreamcast(ship_t *c, dc_pkt_hdr_t *pkt, uint32_t sender);

/* Forward a PC packet to the given ship like the above function. */
int forward_pc(ship_t *c, dc_pkt_hdr_t *pc, uint32_t sender);

/* Send a ship up/down message to the given ship. */
int send_ship_status(ship_t *c, ship_t *o, uint16_t status);

/* Send a ping packet to a client. */
int send_ping(ship_t *c, int reply);

/* Send the ship a character data restore. */
int send_cdata(ship_t *c, uint32_t gc, uint32_t slot, void *cdata);

/* Send a reply to a GM login request. */
int send_gmreply(ship_t *c, uint32_t gc, uint32_t block, int good, uint8_t p);

/* Send a client/game update packet. */
int send_counts(ship_t *c, uint32_t ship_id, uint16_t clients, uint16_t games);

/* Send an error packet to a ship */
int send_error(ship_t *c, uint16_t type, uint16_t flags, uint32_t err,
               uint8_t *data, int data_sz);

/* Send a packet to tell a client that a friend has logged on or off */
int send_friend_message(ship_t *c, int on, uint32_t dest_gc,
                        uint32_t dest_block, uint32_t friend_gc,
                        uint32_t friend_block, uint32_t friend_ship,
                        const char *friend_name);

#endif /* !SHIPGATE_H */
