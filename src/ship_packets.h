/*
    Sylverant Ship Server
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

#ifndef SHIPPACKETS_H
#define SHIPPACKETS_H

#include <inttypes.h>
#include <netinet/in.h>

#include <sylverant/characters.h>
#include <sylverant/encryption.h>

#if defined(WORDS_BIGENDIAN) || defined(__BIG_ENDIAN__)
#define LE16(x) (((x >> 8) & 0xFF) | ((x & 0xFF) << 8))
#define LE32(x) (((x >> 24) & 0x00FF) | \
                 ((x >>  8) & 0xFF00) | \
                 ((x & 0xFF00) <<  8) | \
                 ((x & 0x00FF) << 24))
#define LE64(x) (((x >> 56) & 0x000000FF) | \
                 ((x >> 40) & 0x0000FF00) | \
                 ((x >> 24) & 0x00FF0000) | \
                 ((x >>  8) & 0xFF000000) | \
                 ((x & 0xFF000000) <<  8) | \
                 ((x & 0x00FF0000) << 24) | \
                 ((x & 0x0000FF00) << 40) | \
                 ((x & 0x000000FF) << 56))
#else
#define LE16(x) x
#define LE32(x) x
#define LE64(x) x
#endif

#ifdef PACKED
#undef PACKED
#endif

#define PACKED __attribute__((packed))

typedef struct dc_pkt_hdr {
    uint8_t pkt_type;
    uint8_t flags;
    uint16_t pkt_len;
} PACKED dc_pkt_hdr_t;

/* The packet sent to search for a player (Dreamcast). */
typedef struct dc_guild_search {
    dc_pkt_hdr_t hdr;
    uint32_t tag;
    uint32_t gc_search;
    uint32_t gc_target;
} PACKED dc_guild_search_pkt;

/* The packet sent to reply to a guild card search (Dreamcast). */
typedef struct dc_guild_reply {
    dc_pkt_hdr_t hdr;
    uint32_t tag;
    uint32_t gc_search;
    uint32_t gc_target;
    uint32_t padding1;
    in_addr_t ip;
    uint16_t port;
    uint16_t padding2;
    char location[0x44];
    uint32_t menu_id;
    uint32_t item_id;
    char padding3[0x3C];
    char name[0x20];
} PACKED dc_guild_reply_pkt;

/* The packet sent to send/deliver simple mail (Dreamcast). */
typedef struct dc_simple_mail {
    dc_pkt_hdr_t hdr;
    uint32_t tag;
    uint32_t gc_sender;
    char name[16];
    uint32_t gc_dest;
    char stuff[0x200];
} PACKED dc_simple_mail_pkt;

#undef PACKED

#define SHIP_GUILD_SEARCH_TYPE              0x0040
#define SHIP_DC_GUILD_REPLY_TYPE            0x0041
#define SHIP_SIMPLE_MAIL_TYPE               0x0081

#define SHIP_DC_GUILD_REPLY_LENGTH          0x00C4

#endif /* !SHIPPACKETS_H */
