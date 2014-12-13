/*
    Sylverant Shipgate
    Copyright (C) 2009, 2010, 2011, 2014 Lawrence Sebald

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
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>

#include "shipgate.h"
#include "ship.h"

static uint8_t sendbuf[65536];

static ssize_t ship_send(ship_t *c, const void *buffer, size_t len) {
    return gnutls_record_send(c->session, buffer, len);
}

/* Send a raw packet away. */
static int send_raw(ship_t *c, int len) {
    ssize_t rv, total = 0;
    void *tmp;

    /* Keep trying until the whole thing's sent. */
    if(!c->sendbuf_cur) {
        while(total < len) {
            rv = ship_send(c, sendbuf + total, len - total);

            /* Did the data send? */
            if(rv < 0) {
                /* Is it an error code that might be correctable? */
                if(rv == GNUTLS_E_AGAIN || rv == GNUTLS_E_INTERRUPTED)
                    continue;
                else
                    return -1;
            }

            total += rv;
        }
    }

    rv = len - total;

    if(rv) {
        /* Move out any already transferred data. */
        if(c->sendbuf_start) {
            memmove(c->sendbuf, c->sendbuf + c->sendbuf_start,
                    c->sendbuf_cur - c->sendbuf_start);
            c->sendbuf_cur -= c->sendbuf_start;
        }

        /* See if we need to reallocate the buffer. */
        if(c->sendbuf_cur + rv > c->sendbuf_size) {
            tmp = realloc(c->sendbuf, c->sendbuf_cur + rv);

            /* If we can't allocate the space, bail. */
            if(tmp == NULL) {
                return -1;
            }

            c->sendbuf_size = c->sendbuf_cur + rv;
            c->sendbuf = (unsigned char *)tmp;
        }

        /* Copy what's left of the packet into the output buffer. */
        memcpy(c->sendbuf + c->sendbuf_cur, sendbuf + total, rv);
        c->sendbuf_cur += rv;
    }

    return 0;
}

/* Encrypt a packet, and send it away. */
static int send_crypt(ship_t *c, int len) {
    /* Make sure its at least a header in length. */
    if(len < 8) {
        return -1;
    }

    return send_raw(c, len);
}

int forward_dreamcast(ship_t *c, dc_pkt_hdr_t *dc, uint32_t sender,
                      uint32_t gc, uint32_t block) {
    shipgate_fw_9_pkt *pkt = (shipgate_fw_9_pkt *)sendbuf;
    int dc_len = LE16(dc->pkt_len);
    int full_len = sizeof(shipgate_fw_9_pkt) + dc_len;

    /* Round up the packet size, if needed. */
    if(full_len & 0x07)
        full_len = (full_len + 8) & 0xFFF8;

    /* Scrub the buffer */
    memset(pkt, 0, full_len);

    /* Fill in the shipgate header */
    pkt->hdr.pkt_len = htons(full_len);
    pkt->hdr.pkt_type = htons(SHDR_TYPE_DC);
    pkt->hdr.flags = 0;
    pkt->hdr.reserved = 0;
    pkt->hdr.version = 0;

    /* Add the metadata */
    pkt->ship_id = htonl(sender);
    pkt->guildcard = htonl(gc);
    pkt->block = htonl(block);

    /* Copy in the packet, unchanged */
    memcpy(pkt->pkt, dc, dc_len);

    /* Send the packet away */
    return send_crypt(c, full_len);
}

int forward_pc(ship_t *c, dc_pkt_hdr_t *pc, uint32_t sender, uint32_t gc,
               uint32_t block) {
    shipgate_fw_9_pkt *pkt = (shipgate_fw_9_pkt *)sendbuf;
    int pc_len = LE16(pc->pkt_len);
    int full_len = sizeof(shipgate_fw_9_pkt) + pc_len;

    /* Round up the packet size, if needed. */
    if(full_len & 0x07)
        full_len = (full_len + 8) & 0xFFF8;

    /* Scrub the buffer */
    memset(pkt, 0, full_len);

    /* Fill in the shipgate header */
    pkt->hdr.pkt_len = htons(full_len);
    pkt->hdr.pkt_type = htons(SHDR_TYPE_PC);
    pkt->hdr.flags = 0;
    pkt->hdr.reserved = 0;
    pkt->hdr.version = 0;

    /* Add the metadata */
    pkt->ship_id = htonl(sender);
    pkt->guildcard = htonl(gc);
    pkt->block = htonl(block);

    /* Copy in the packet, unchanged */
    memcpy(pkt->pkt, pc, pc_len);

    /* Send the packet away */
    return send_crypt(c, full_len);
}

int forward_bb(ship_t *c, bb_pkt_hdr_t *bb, uint32_t sender, uint32_t gc,
               uint32_t block) {
    shipgate_fw_9_pkt *pkt = (shipgate_fw_9_pkt *)sendbuf;
    int bb_len = LE16(bb->pkt_len);
    int full_len = sizeof(shipgate_fw_9_pkt) + bb_len;

    /* Round up the packet size, if needed. */
    if(full_len & 0x07)
        full_len = (full_len + 8) & 0xFFF8;

    /* Scrub the buffer */
    memset(pkt, 0, full_len);

    /* Fill in the shipgate header */
    pkt->hdr.pkt_len = htons(full_len);
    pkt->hdr.pkt_type = htons(SHDR_TYPE_BB);
    pkt->hdr.flags = 0;
    pkt->hdr.reserved = 0;
    pkt->hdr.version = 0;

    /* Add the metadata */
    pkt->ship_id = htonl(sender);
    pkt->guildcard = htonl(gc);
    pkt->block = htonl(block);

    /* Copy in the packet, unchanged */
    memcpy(pkt->pkt, bb, bb_len);

    /* Send the packet away */
    return send_crypt(c, full_len);
}

/* Send a welcome packet to the given ship. */
int send_welcome(ship_t *c) {
    shipgate_login_pkt *pkt = (shipgate_login_pkt *)sendbuf;

    /* Scrub the buffer */
    memset(pkt, 0, sizeof(shipgate_login_pkt));

    /* Fill in the header */
    pkt->hdr.pkt_len = htons(sizeof(shipgate_login_pkt));
    pkt->hdr.pkt_type = htons(SHDR_TYPE_LOGIN);
    pkt->hdr.flags = 0;
    pkt->hdr.reserved = 0;
    pkt->hdr.version = 0;

    /* Fill in the required message */
    strcpy(pkt->msg, shipgate_login_msg);

    /* Fill in the version information */
    pkt->ver_major = VERSION_MAJOR;
    pkt->ver_minor = VERSION_MINOR;
    pkt->ver_micro = VERSION_MICRO;

    /* Fill in the nonces */
    memcpy(pkt->ship_nonce, c->ship_nonce, 4);
    memcpy(pkt->gate_nonce, c->gate_nonce, 4);

    /* Send the packet away */
    return send_raw(c, sizeof(shipgate_login_pkt));
}

int send_ship_status(ship_t *c, ship_t *o, uint16_t status) {
    shipgate_ship_status6_pkt *pkt = (shipgate_ship_status6_pkt *)sendbuf;

    /* If the ship hasn't finished logging in yet, don't send this. */
    if(o->name[0] == 0) {
        return 0;
    }

    /* Scrub the buffer */
    memset(pkt, 0, sizeof(shipgate_ship_status6_pkt));

    /* Fill in the header */
    pkt->hdr.pkt_len = htons(sizeof(shipgate_ship_status6_pkt));
    pkt->hdr.pkt_type = htons(SHDR_TYPE_SSTATUS);
    pkt->hdr.flags = 0;
    pkt->hdr.reserved = 0;
    pkt->hdr.version = 0;

    /* Fill in the info */
    strcpy((char *)pkt->name, o->name);
    pkt->ship_id = htonl(o->key_idx);
    pkt->ship_addr4 = o->remote_addr;
    memcpy(pkt->ship_addr6, &o->remote_addr6, 16);
    pkt->ship_port = htons(o->port);
    pkt->status = htons(status);
    pkt->flags = htonl(o->flags);
    pkt->clients = htons(o->clients);
    pkt->games = htons(o->games);
    pkt->menu_code = htons(o->menu_code);
    pkt->ship_number = (uint8_t)o->ship_number;

    /* Send the packet away */
    return send_crypt(c, sizeof(shipgate_ship_status6_pkt));
}

/* Send a ping packet to a client. */
int send_ping(ship_t *c, int reply) {
    shipgate_hdr_t *pkt = (shipgate_hdr_t *)sendbuf;

    /* Fill in the header. */
    pkt->pkt_len = htons(sizeof(shipgate_hdr_t));
    pkt->pkt_type = htons(SHDR_TYPE_PING);
    pkt->reserved = 0;
    pkt->version = 0;

    if(reply) {
        pkt->flags = htons(SHDR_RESPONSE);
    }
    else {
        pkt->flags = 0;
    }

    /* Send it away. */
    return send_crypt(c, sizeof(shipgate_hdr_t));
}

/* Send the ship a character data restore. */
int send_cdata(ship_t *c, uint32_t gc, uint32_t slot, void *cdata, int sz,
               uint32_t block) {
    shipgate_char_data_pkt *pkt = (shipgate_char_data_pkt *)sendbuf;

    /* Fill in the header. */
    pkt->hdr.pkt_len = htons(sizeof(shipgate_char_data_pkt) + sz);
    pkt->hdr.pkt_type = htons(SHDR_TYPE_CREQ);
    pkt->hdr.flags = htons(SHDR_RESPONSE);
    pkt->hdr.reserved = 0;
    pkt->hdr.version = 0;

    /* Fill in the body. */
    pkt->guildcard = htonl(gc);
    pkt->slot = htonl(slot);
    pkt->block = block;
    memcpy(pkt->data, cdata, sz);

    /* Send it away. */
    return send_crypt(c, sizeof(shipgate_char_data_pkt) + sz);
}

/* Send a reply to a GM login request. */
int send_gmreply(ship_t *c, uint32_t gc, uint32_t block, int good, uint8_t p) {
    shipgate_gmlogin_reply_pkt *pkt = (shipgate_gmlogin_reply_pkt *)sendbuf;
    uint16_t flags = good ? SHDR_RESPONSE : SHDR_FAILURE;

    /* Clear the packet first */
    memset(pkt, 0, sizeof(shipgate_gmlogin_reply_pkt));

    /* Fill in the response. */
    pkt->hdr.pkt_len = htons(sizeof(shipgate_gmlogin_reply_pkt));
    pkt->hdr.pkt_type = htons(SHDR_TYPE_GMLOGIN);
    pkt->hdr.flags = htons(flags);
    pkt->hdr.reserved = 0;
    pkt->hdr.version = 0;

    pkt->guildcard = htonl(gc);
    pkt->block = htonl(block);
    pkt->priv = p;

    return send_crypt(c, sizeof(shipgate_gmlogin_reply_pkt));
}

/* Send a client/game update packet. */
int send_counts(ship_t *c, uint32_t ship_id, uint16_t clients, uint16_t games) {
    shipgate_cnt_pkt *pkt = (shipgate_cnt_pkt *)sendbuf;

    /* Clear the packet first */
    memset(pkt, 0, sizeof(shipgate_cnt_pkt));

    /* Fill in the response. */
    pkt->hdr.pkt_len = htons(sizeof(shipgate_cnt_pkt));
    pkt->hdr.pkt_type = htons(SHDR_TYPE_COUNT);
    pkt->hdr.flags = 0;
    pkt->hdr.reserved = 0;
    pkt->hdr.version = 0;

    pkt->clients = htons(clients);
    pkt->games = htons(games);
    pkt->ship_id = htonl(ship_id);

    return send_crypt(c, sizeof(shipgate_cnt_pkt));
}

/* Send an error packet to a ship */
int send_error(ship_t *c, uint16_t type, uint16_t flags, uint32_t err,
               const uint8_t *data, int data_sz) {
    shipgate_error_pkt *pkt = (shipgate_error_pkt *)sendbuf;
    uint16_t sz;

    /* These were first added in protocol version 1. */
    if(c->proto_ver < 1) {
        return 0;
    }

    /* Make sure the data size is valid */
    if(data_sz > 65536 - sizeof(shipgate_error_pkt)) {
        return -1;
    }

    /* Clear the header of the packet */
    memset(pkt, 0, sizeof(shipgate_error_pkt));
    sz = sizeof(shipgate_error_pkt) + data_sz;

    /* Fill it in */
    pkt->hdr.pkt_len = htons(sz);
    pkt->hdr.pkt_type = htons(type);
    pkt->hdr.flags = htons(flags);
    pkt->hdr.reserved = 0;
    pkt->hdr.version = 0;

    pkt->error_code = htonl(err);
    memcpy(pkt->data, data, data_sz);

    return send_crypt(c, sz);
}

/* Send a packet to tell a client that a friend has logged on or off */
int send_friend_message(ship_t *c, int on, uint32_t dest_gc,
                        uint32_t dest_block, uint32_t friend_gc,
                        uint32_t friend_block, uint32_t friend_ship,
                        const char *friend_name, const char *nickname) {
    shipgate_friend_login_4_pkt *pkt = (shipgate_friend_login_4_pkt *)sendbuf;

    /* Clear the packet */
    memset(pkt, 0, sizeof(shipgate_friend_login_4_pkt));

    /* Fill it in */
    pkt->hdr.pkt_len = htons(sizeof(shipgate_friend_login_4_pkt));
    pkt->hdr.pkt_type = htons((on ? SHDR_TYPE_FRLOGIN : SHDR_TYPE_FRLOGOUT));
    pkt->hdr.flags = 0;
    pkt->hdr.reserved = 0;
    pkt->hdr.version = 0;
    pkt->dest_guildcard = htonl(dest_gc);
    pkt->dest_block = htonl(dest_block);
    pkt->friend_guildcard = htonl(friend_gc);
    pkt->friend_ship = htonl(friend_ship);
    pkt->friend_block = htonl(friend_block);
    strcpy(pkt->friend_name, friend_name);

    if(nickname) {
        strncpy(pkt->friend_nick, nickname, 32);
        pkt->friend_nick[31] = 0;
    }
    else {
        memset(pkt->friend_nick, 0, 32);
    }

    return send_crypt(c, sizeof(shipgate_friend_login_4_pkt));
}

/* Send a kick packet */
int send_kick(ship_t *c, uint32_t requester, uint32_t user, uint32_t block,
              const char *reason) {
    shipgate_kick_pkt *pkt = (shipgate_kick_pkt *)sendbuf;

    /* Scrub the buffer */
    memset(pkt, 0, sizeof(shipgate_kick_pkt));

    /* Fill in the packet */
    pkt->hdr.pkt_len = htons(sizeof(shipgate_kick_pkt));
    pkt->hdr.pkt_type = htons(SHDR_TYPE_KICK);
    pkt->hdr.flags = 0;
    pkt->hdr.reserved = 0;
    pkt->hdr.version = 0;

    pkt->requester = htonl(requester);
    pkt->guildcard = htonl(user);
    pkt->block = htonl(block);

    if(reason) {
        strncpy(pkt->reason, reason, 64);
    }

    /* Send the packet away */
    return send_crypt(c, sizeof(shipgate_kick_pkt));
}

/* Send a portion of a user's friendlist to the user */
int send_friendlist(ship_t *c, uint32_t requester, uint32_t block,
                    int count, const friendlist_data_t *entries) {
    shipgate_friend_list_pkt *pkt = (shipgate_friend_list_pkt *)sendbuf;
    uint16_t len = sizeof(shipgate_friend_list_pkt) +
        sizeof(friendlist_data_t) * count;

    /* Fill in the packet */
    pkt->hdr.pkt_len = htons(len);
    pkt->hdr.pkt_type = htons(SHDR_TYPE_FRLIST);
    pkt->hdr.flags = htons(SHDR_RESPONSE);
    pkt->hdr.reserved = 0;
    pkt->hdr.version = 0;

    pkt->requester = htonl(requester);
    pkt->block = htonl(block);

    /* Copy the friend data */
    memcpy(pkt->entries, entries, sizeof(friendlist_data_t) * count);

    /* Send the packet away */
    return send_crypt(c, len);
}

/* Send a global message packet to a ship */
int send_global_msg(ship_t *c, uint32_t requester, const char *text,
                    uint16_t text_len) {
    shipgate_global_msg_pkt *pkt = (shipgate_global_msg_pkt *)sendbuf;
    uint16_t len = sizeof(shipgate_global_msg_pkt) + text_len;

    /* Fill in the packet */
    pkt->hdr.pkt_len = htons(len);
    pkt->hdr.pkt_type = htons(SHDR_TYPE_GLOBALMSG);
    pkt->hdr.flags = 0;
    pkt->hdr.reserved = 0;
    pkt->hdr.version = 0;

    pkt->requester = htonl(requester);
    pkt->reserved = 0;
    memcpy(pkt->text, text, len);

    /* Send the packet away */
    return send_crypt(c, len);
}

/* Begin an options packet */
void *user_options_begin(uint32_t guildcard, uint32_t block) {
    shipgate_user_opt_pkt *pkt = (shipgate_user_opt_pkt *)sendbuf;

    /* Fill in the packet */
    pkt->hdr.pkt_len = sizeof(shipgate_user_opt_pkt);
    pkt->hdr.pkt_type = htons(SHDR_TYPE_USEROPT);
    pkt->hdr.flags = 0;
    pkt->hdr.reserved = 0;
    pkt->hdr.version = 0;

    pkt->guildcard = htonl(guildcard);
    pkt->block = htonl(block);
    pkt->count = 0;
    pkt->reserved = 0;

    /* Return the pointer to the end of the buffer */
    return &pkt->options[0];
}

/* Append an option value to the options packet */
void *user_options_append(void *p, uint32_t opt, uint32_t len,
                          const uint8_t *data) {
    shipgate_user_opt_pkt *pkt = (shipgate_user_opt_pkt *)sendbuf;
    shipgate_user_opt_t *o = (shipgate_user_opt_t *)p;
    int padding = 8 - (len & 7);

    /* Add the new option in */
    o->option = htonl(opt);
    memcpy(o->data, data, len);

    /* Options must be a multiple of 8 bytes in length */
    while(padding--) {
        o->data[len++] = 0;
    }

    o->length = htonl(len + 8);

    /* Adjust the packet's information to account for the new option */
    pkt->hdr.pkt_len += len + 8;
    ++pkt->count;

    return (((uint8_t *)p) + len + 8);
}

/* Finish off a user options packet and send it along */
int send_user_options(ship_t *c) {
    shipgate_user_opt_pkt *pkt = (shipgate_user_opt_pkt *)sendbuf;
    uint16_t len = pkt->hdr.pkt_len;

    /* Make sure we have something to send, at least */
    if(!pkt->count) {
        return 0;
    }

    /* Swap that which we need to do */
    pkt->hdr.pkt_len = htons(len);
    pkt->count = htonl(pkt->count);

    /* Send it away */
    return send_crypt(c, len);
}

/* Send a packet containing a user's Blue Burst options */
int send_bb_opts(ship_t *c, uint32_t gc, uint32_t block,
                 sylverant_bb_db_opts_t *opts) {
    shipgate_bb_opts_pkt *pkt = (shipgate_bb_opts_pkt *)sendbuf;

    /* Fill in the packet */
    pkt->hdr.pkt_len = htons(sizeof(shipgate_bb_opts_pkt));
    pkt->hdr.pkt_type = htons(SHDR_TYPE_BBOPTS);
    pkt->hdr.reserved = 0;
    pkt->hdr.version = 0;
    pkt->hdr.flags = htons(SHDR_RESPONSE);

    pkt->guildcard = htonl(gc);
    pkt->block = htonl(block);
    memcpy(&pkt->opts, opts, sizeof(sylverant_bb_db_opts_t));

    /* Send the packet away */
    return send_crypt(c, sizeof(shipgate_bb_opts_pkt));
}

/* Send a system-generated simple mail message. */
int send_simple_mail(ship_t *c, uint32_t gc, uint32_t block, uint32_t sender,
                     const char *name, const char *msg) {
    dc_simple_mail_pkt pkt;

    /* Set up the mail. */
    memset(&pkt, 0, sizeof(pkt));
    pkt.hdr.pkt_type = SIMPLE_MAIL_TYPE;
    pkt.hdr.pkt_len = LE16(DC_SIMPLE_MAIL_LENGTH);
    pkt.tag = LE32(0x00010000);
    pkt.gc_sender = LE32(sender);
    strncpy(pkt.name, name, 16);
    pkt.gc_dest = LE32(gc);
    strncpy(pkt.stuff, msg, 0x90);

    return forward_dreamcast(c, (dc_pkt_hdr_t *)&pkt, c->key_idx, gc, block);
}
