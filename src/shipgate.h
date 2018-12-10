/*
    Sylverant Shipgate
    Copyright (C) 2009, 2010, 2011, 2012, 2014, 2015, 2016, 2018 Lawrence Sebald

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

#include <stdint.h>

#include <sylverant/characters.h>

#include "ship.h"
#include "packets.h"

/* Minimum and maximum supported protocol ship<->shipgate protocol versions */
#define SHIPGATE_MINIMUM_PROTO_VER 10
#define SHIPGATE_MAXIMUM_PROTO_VER 16

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

/* Error packet in reply to character backup send or character backup request */
typedef struct shipgate_cbkup_err {
    shipgate_error_pkt base;
    uint32_t guildcard;
    uint32_t block;
} PACKED shipgate_cbkup_err_pkt;

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

/* Error packet in reply to a schunk */
typedef struct shipgate_schunk_err {
    shipgate_error_pkt base;
    uint8_t type;
    uint8_t reserved[3];
    char filename[32];
} PACKED shipgate_schunk_err_pkt;

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

/* The reply to the login request from the shipgate. This form is deprecated,
   and not valid in shipgate protocol v7. New ships should use the other form
   (type 0x0025) instead of this one (type 0x0010). */
typedef struct shipgate_login_reply {
    shipgate_hdr_t hdr;
    char name[12];
    uint32_t ship_addr;
    uint32_t int_addr;                  /* reserved for compatibility */
    uint16_t ship_port;
    uint16_t ship_key;
    uint16_t clients;
    uint16_t games;
    uint32_t flags;
    uint16_t menu_code;
    uint8_t reserved[2];
    uint32_t proto_ver;
} PACKED shipgate_login_reply_pkt;

/* The reply to the login request from the shipgate (with IPv6 support).
   Note that IPv4 support is still required, as PSO itself does not actually
   support IPv6 (however, proxies can alleviate this problem a bit). */
typedef struct shipgate_login6_reply {
    shipgate_hdr_t hdr;
    uint32_t proto_ver;
    uint32_t flags;
    uint8_t name[12];
    uint32_t ship_addr4;                /* IPv4 address (required) */
    uint8_t ship_addr6[16];             /* IPv6 address (optional) */
    uint16_t ship_port;
    uint16_t ship_key;                  /* Reserved in TLS clients */
    uint16_t clients;
    uint16_t games;
    uint16_t menu_code;
    uint8_t reserved[6];                /* Pad to a multiple of 8 bytes */
} PACKED shipgate_login6_reply_pkt;

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
    uint32_t fw_flags;
    uint8_t pkt[0];
} PACKED shipgate_fw_pkt;

/* A forwarded player packet (updated in proto v9). */
typedef struct shipgate_fw_9 {
    shipgate_hdr_t hdr;
    uint32_t ship_id;
    uint32_t fw_flags;
    uint32_t guildcard;
    uint32_t block;
    uint8_t pkt[0];
} PACKED shipgate_fw_9_pkt;

/* A packet telling clients that a ship has started or dropped. */
typedef struct shipgate_ship_status {
    shipgate_hdr_t hdr;
    char name[12];
    uint32_t ship_id;
    uint32_t ship_addr;
    uint32_t int_addr;                  /* reserved for compatibility */
    uint16_t ship_port;
    uint16_t status;
    uint32_t flags;
    uint16_t clients;
    uint16_t games;
    uint16_t menu_code;
    uint8_t  ship_number;
    uint8_t  reserved;
} PACKED shipgate_ship_status_pkt;

/* Updated version of the above packet, supporting IPv6. */
typedef struct shipgate_ship_status6 {
    shipgate_hdr_t hdr;
    uint8_t name[12];
    uint32_t ship_id;
    uint32_t flags;
    uint32_t ship_addr4;                /* IPv4 address (required) */
    uint8_t ship_addr6[16];             /* IPv6 address (optional) */
    uint16_t ship_port;
    uint16_t status;
    uint16_t clients;
    uint16_t games;
    uint16_t menu_code;
    uint8_t  ship_number;
    uint8_t  reserved[5];
} PACKED shipgate_ship_status6_pkt;

/* A packet sent to/from clients to save/restore character data. */
typedef struct shipgate_char_data {
    shipgate_hdr_t hdr;
    uint32_t guildcard;
    uint32_t slot;
    uint32_t block;
    uint8_t data[];
} PACKED shipgate_char_data_pkt;

/* A packet sent from clients to save their character backup or to request that
   the gate send it back to them. */
typedef struct shipgate_char_bkup {
    shipgate_hdr_t hdr;
    uint32_t guildcard;
    uint32_t block;
    uint8_t name[32];
    uint8_t data[];
} PACKED shipgate_char_bkup_pkt;

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

/* Updated version of above packet for protocol version 4 */
typedef struct shipgate_friend_login_4 {
    shipgate_hdr_t hdr;
    uint32_t dest_guildcard;
    uint32_t dest_block;
    uint32_t friend_guildcard;
    uint32_t friend_ship;
    uint32_t friend_block;
    uint32_t reserved;
    char friend_name[32];
    char friend_nick[32];
} PACKED shipgate_friend_login_4_pkt;

/* Packet to update a user's friendlist (used for either add or remove) */
typedef struct shipgate_friend_upd {
    shipgate_hdr_t hdr;
    uint32_t user_guildcard;
    uint32_t friend_guildcard;
} PACKED shipgate_friend_upd_pkt;

/* Packet to add a user to a friendlist (updated in protocol version 4) */
typedef struct shipgate_friend_add {
    shipgate_hdr_t hdr;
    uint32_t user_guildcard;
    uint32_t friend_guildcard;
    char friend_nick[32];
} PACKED shipgate_friend_add_pkt;

/* Packet to update a user's lobby in the shipgate's info */
typedef struct shipgate_lobby_change {
    shipgate_hdr_t hdr;
    uint32_t guildcard;
    uint32_t lobby_id;
    char lobby_name[32];
} PACKED shipgate_lobby_change_pkt;

/* Packet to send a list of online clients (for when a ship reconnects to the
   shipgate) */
typedef struct shipgate_block_clients {
    shipgate_hdr_t hdr;
    uint32_t count;
    uint32_t block;
    struct {
        uint32_t guildcard;
        uint32_t lobby;
        char ch_name[32];
        char lobby_name[32];
    } entries[0];
} PACKED shipgate_bclients_pkt;

typedef struct shipgate_block_clients_12 {
    shipgate_hdr_t hdr;
    uint32_t count;
    uint32_t block;
    struct {
        uint32_t guildcard;
        uint32_t lobby;
        uint32_t dlobby;
        uint32_t reserved;
        char ch_name[32];
        char lobby_name[32];
    } entries[0];
} PACKED shipgate_bclients_12_pkt;

/* A kick request, sent to or from a ship */
typedef struct shipgate_kick_req {
    shipgate_hdr_t hdr;
    uint32_t requester;
    uint32_t reserved;
    uint32_t guildcard;
    uint32_t block;                     /* 0 for ship->shipgate */
    char reason[64];
} PACKED shipgate_kick_pkt;

/* Packet to send a portion of the user's friend list to the ship, including
   online/offline status. */
typedef struct shipgate_friend_list {
    shipgate_hdr_t hdr;
    uint32_t requester;
    uint32_t block;
    friendlist_data_t entries[];
} PACKED shipgate_friend_list_pkt;

/* Packet to request a portion of the friend list be sent */
typedef struct shipgate_friend_list_req {
    shipgate_hdr_t hdr;
    uint32_t requester;
    uint32_t block;
    uint32_t start;
    uint32_t reserved;
} PACKED shipgate_friend_list_req;

/* Packet to send a global message to all ships */
typedef struct shipgate_global_msg {
    shipgate_hdr_t hdr;
    uint32_t requester;
    uint32_t reserved;
    char text[];                        /* UTF-8, padded to 8-byte boundary */
} PACKED shipgate_global_msg_pkt;

/* An individual option for the options packet */
typedef struct shipgate_user_opt {
    uint32_t option;
    uint32_t length;
    uint8_t data[];
} PACKED shipgate_user_opt_t;

/* Packet used to send a user's settings to a ship */
typedef struct shipgate_user_options {
    shipgate_hdr_t hdr;
    uint32_t guildcard;
    uint32_t block;
    uint32_t count;
    uint32_t reserved;
    shipgate_user_opt_t options[];
} PACKED shipgate_user_opt_pkt;

/* Packet used to request Blue Burst options */
typedef struct shipgate_bb_opts_req {
    shipgate_hdr_t hdr;
    uint32_t guildcard;
    uint32_t block;
} PACKED shipgate_bb_opts_req_pkt;

/* Packet used to send Blue Burst options to a user */
typedef struct shipgate_bb_opts {
    shipgate_hdr_t hdr;
    uint32_t guildcard;
    uint32_t block;
    sylverant_bb_db_opts_t opts;
} PACKED shipgate_bb_opts_pkt;

/* Packet used to send an update to the user's monster kill counts.
   Version 1 adds a client version code where there used to be a reserved byte
   in the packet. */
typedef struct shipgate_mkill {
    shipgate_hdr_t hdr;
    uint32_t guildcard;
    uint32_t block;
    uint8_t episode;
    uint8_t difficulty;
    uint8_t version;
    uint8_t reserved;
    uint32_t counts[0x60];
} PACKED shipgate_mkill_pkt;

/* Packet used to send a script chunk to a ship. */
typedef struct shipgate_schunk {
    shipgate_hdr_t hdr;
    uint8_t chunk_type;
    uint8_t reserved[3];
    uint32_t chunk_length;
    uint32_t chunk_crc;
    uint32_t reserved2;
    char filename[32];
    uint8_t chunk[];
} PACKED shipgate_schunk_pkt;

/* Packet used to communicate with a script running on the shipgate during a
   scripted event. */
typedef struct shipgate_sdata {
    shipgate_hdr_t hdr;
    uint32_t event_id;
    uint32_t data_len;
    uint32_t guildcard;
    uint32_t block;
    uint8_t episode;
    uint8_t difficulty;
    uint8_t version;
    uint8_t reserved;
    uint8_t data[];
} PACKED shipgate_sdata_pkt;

#undef PACKED

/* The requisite message for the msg field of the shipgate_login_pkt. */
static const char shipgate_login_msg[] =
    "Sylverant Shipgate Copyright Lawrence Sebald";

/* Flags for the flags field of shipgate_hdr_t */
#define SHDR_RESPONSE       0x8000      /* Response to a request */
#define SHDR_FAILURE        0x4000      /* Failure to complete request */

/* Types for the pkt_type field of shipgate_hdr_t */
#define SHDR_TYPE_DC        0x0001      /* A decrypted Dreamcast game packet */
#define SHDR_TYPE_BB        0x0002      /* A decrypted Blue Burst game packet */
#define SHDR_TYPE_PC        0x0003      /* A decrypted PCv2 game packet */
#define SHDR_TYPE_GC        0x0004      /* A decrypted Gamecube game packet */
#define SHDR_TYPE_EP3       0x0005      /* A decrypted Episode 3 packet */
#define SHDR_TYPE_LOGIN     0x0010      /* A login request */
#define SHDR_TYPE_COUNT     0x0011      /* A Client/Game Count update */
#define SHDR_TYPE_SSTATUS   0x0012      /* A Ship has come up or gone down */
#define SHDR_TYPE_PING      0x0013      /* A Ping packet, enough said */
#define SHDR_TYPE_CDATA     0x0014      /* Character data */
#define SHDR_TYPE_CREQ      0x0015      /* Request saved character data */
#define SHDR_TYPE_GMLOGIN   0x0016      /* User login request */
#define SHDR_TYPE_GCBAN     0x0017      /* Guildcard ban */
#define SHDR_TYPE_IPBAN     0x0018      /* IP ban */
#define SHDR_TYPE_BLKLOGIN  0x0019      /* User logs into a block */
#define SHDR_TYPE_BLKLOGOUT 0x001A      /* User logs off a block */
#define SHDR_TYPE_FRLOGIN   0x001B      /* A user's friend logs onto a block */
#define SHDR_TYPE_FRLOGOUT  0x001C      /* A user's friend logs off a block */
#define SHDR_TYPE_ADDFRIEND 0x001D      /* Add a friend to a user's list */
#define SHDR_TYPE_DELFRIEND 0x001E      /* Remove a friend from a user's list */
#define SHDR_TYPE_LOBBYCHG  0x001F      /* A user changes lobbies */
#define SHDR_TYPE_BCLIENTS  0x0020      /* A bulk transfer of client info */
#define SHDR_TYPE_KICK      0x0021      /* A kick request */
#define SHDR_TYPE_FRLIST    0x0022      /* Friend list request/reply */
#define SHDR_TYPE_GLOBALMSG 0x0023      /* A Global message packet */
#define SHDR_TYPE_USEROPT   0x0024      /* A user's options -- sent on login */
#define SHDR_TYPE_LOGIN6    0x0025      /* A ship login (potentially IPv6) */
#define SHDR_TYPE_BBOPTS    0x0026      /* A user's Blue Burst options */
#define SHDR_TYPE_BBOPT_REQ 0x0027      /* Request Blue Burst options */
#define SHDR_TYPE_CBKUP     0x0028      /* A character data backup packet */
#define SHDR_TYPE_MKILL     0x0029      /* Monster kill update */
#define SHDR_TYPE_TLOGIN    0x002A      /* Token-based login request */
#define SHDR_TYPE_SCHUNK    0x002B      /* Script chunk */
#define SHDR_TYPE_SDATA     0x002C      /* Script data */

/* Flags that can be set in the login packet */
#define LOGIN_FLAG_GMONLY   0x00000001  /* Only Global GMs are allowed */
#define LOGIN_FLAG_PROXY    0x00000002  /* Is a proxy -- exclude many pkts */
#define LOGIN_FLAG_NOV1     0x00000010  /* Do not allow DCv1 clients */
#define LOGIN_FLAG_NOV2     0x00000020  /* Do not allow DCv2 clients */
#define LOGIN_FLAG_NOPC     0x00000040  /* Do not allow PSOPC clients */
#define LOGIN_FLAG_NOEP12   0x00000080  /* Do not allow PSO Ep1&2 clients */
#define LOGIN_FLAG_NOEP3    0x00000100  /* Do not allow PSO Ep3 clients */
#define LOGIN_FLAG_NOBB     0x00000200  /* Do not allow PSOBB clients */
/* 0x00000400 - 0x00010000 reserved. */
#define LOGIN_FLAG_LUA      0x00020000  /* Ship supports Lua scripting */

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
#define ERR_BAN_PRIVILEGE       0x00000003

/* Error codes in response to a block login */
#define ERR_BLOGIN_INVAL_NAME   0x00000001
#define ERR_BLOGIN_ONLINE       0x00000002

/* Possible values for user options */
#define USER_OPT_QUEST_LANG     0x00000001
#define USER_OPT_ENABLE_BACKUP  0x00000002
#define USER_OPT_GC_PROTECT     0x00000003
#define USER_OPT_TRACK_KILLS    0x00000004
#define USER_OPT_LEGIT_ALWAYS   0x00000005

/* Possible values for the fw_flags on a forwarded packet */
#define FW_FLAG_PREFER_IPV6     0x00000001  /* Prefer IPv6 on reply */
#define FW_FLAG_IS_PSOPC        0x00000002  /* Client is on PSOPC */

/* Possible values for versions in packets that need them. This list should be
   kept in-sync with those in clients.h from ship_server. */
#define CLIENT_VERSION_DCV1     0
#define CLIENT_VERSION_DCV2     1
#define CLIENT_VERSION_PC       2
#define CLIENT_VERSION_GC       3
#define CLIENT_VERSION_EP3      4
#define CLIENT_VERSION_BB       5

/* Not a version, but potentially ORed with a version... */
#define CLIENT_QUESTING         0x20
#define CLIENT_CHALLENGE_MODE   0x40
#define CLIENT_BATTLE_MODE      0x80

/* Types for the script chunk packet. */
#define SCHUNK_TYPE_SCRIPT      0x01
#define SCHUNK_TYPE_MODULE      0x02
#define SCHUNK_CHECK            0x80

/* Error codes for schunk */
#define ERR_SCHUNK_NEED_SCRIPT  0x00000001

/* Send a welcome packet to the given ship. */
int send_welcome(ship_t *c);

/* Forward a Dreamcast packet to the given ship, with additional metadata. */
int forward_dreamcast(ship_t *c, dc_pkt_hdr_t *pkt, uint32_t sender,
                      uint32_t gc, uint32_t block);

/* Forward a PC packet to the given ship like the above function. */
int forward_pc(ship_t *c, dc_pkt_hdr_t *pc, uint32_t sender, uint32_t gc,
               uint32_t block);

/* Forward a Blue Burs packet to the given ship, like the above. */
int forward_bb(ship_t *c, bb_pkt_hdr_t *bb, uint32_t sender, uint32_t gc,
               uint32_t block);

/* Send a ship up/down message to the given ship. */
int send_ship_status(ship_t *c, ship_t *o, uint16_t status);

/* Send a ping packet to a client. */
int send_ping(ship_t *c, int reply);

/* Send the ship a character data restore. */
int send_cdata(ship_t *c, uint32_t gc, uint32_t slot, void *cdata, int sz,
               uint32_t block);

/* Send a reply to a GM login request. */
int send_gmreply(ship_t *c, uint32_t gc, uint32_t block, int good, uint8_t p);

/* Send a client/game update packet. */
int send_counts(ship_t *c, uint32_t ship_id, uint16_t clients, uint16_t games);

/* Send an error packet to a ship */
int send_error(ship_t *c, uint16_t type, uint16_t flags, uint32_t err,
               const uint8_t *data, int data_sz);

/* Send a packet to tell a client that a friend has logged on or off */
int send_friend_message(ship_t *c, int on, uint32_t dest_gc,
                        uint32_t dest_block, uint32_t friend_gc,
                        uint32_t friend_block, uint32_t friend_ship,
                        const char *friend_name, const char *nickname);

/* Send a kick packet */
int send_kick(ship_t *c, uint32_t requester, uint32_t user, uint32_t block,
              const char *reason);

/* Send a portion of a user's friendlist to the user */
int send_friendlist(ship_t *c, uint32_t requester, uint32_t block,
                    int count, const friendlist_data_t *entries);

/* Send a global message packet to a ship */
int send_global_msg(ship_t *c, uint32_t requester, const char *text,
                    uint16_t len);

/* Begin an options packet */
void *user_options_begin(uint32_t guildcard, uint32_t block);

/* Append an option value to the options packet */
void *user_options_append(void *p, uint32_t opt, uint32_t len,
                          const uint8_t *data);

/* Finish off a user options packet and send it along */
int send_user_options(ship_t *c);

/* Send a packet containing a user's Blue Burst options */
int send_bb_opts(ship_t *c, uint32_t gc, uint32_t block,
                 sylverant_bb_db_opts_t *opts);

/* Send a system-generated simple mail message. */
int send_simple_mail(ship_t *c, uint32_t gc, uint32_t block, uint32_t sender,
                     const char *name, const char *msg);

/* Send a script check packet. */
int send_script_check(ship_t *c, ship_script_t *scr);

/* Send a script to a ship. */
int send_script(ship_t *c, ship_script_t *scr);

#endif /* !SHIPGATE_H */
