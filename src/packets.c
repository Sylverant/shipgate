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
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>

#include "shipgate.h"
#include "ship.h"

static uint8_t sendbuf[65536];

/* Send a raw packet away. */
static int send_raw(ship_t *c, int len) {
    ssize_t rv, total = 0;
    void *tmp;

    /* Keep trying until the whole thing's sent. */
    if(!c->sendbuf_cur) {
        while(total < len) {
            rv = send(c->sock, sendbuf + total, len - total, 0);

            if(rv == -1 && errno != EAGAIN) {
                return -1;
            }
            else if(rv == -1) {
                break;
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

    if(c->key_set)
        RC4(&c->gate_key, len, sendbuf, sendbuf);

    return send_raw(c, len);
}

int forward_dreamcast(ship_t *c, dc_pkt_hdr_t *dc, uint32_t sender) {
    shipgate_fw_pkt *pkt = (shipgate_fw_pkt *)sendbuf;
    int dc_len = LE16(dc->pkt_len);
    int full_len = sizeof(shipgate_fw_pkt) + dc_len;

    /* Round up the packet size, if needed. */
    if(full_len & 0x07)
        full_len = (full_len + 8) & 0xFFF8;

    /* Scrub the buffer */
    memset(pkt, 0, full_len);

    /* Fill in the shipgate header */
    pkt->hdr.pkt_len = htons(full_len);
    pkt->hdr.pkt_type = htons(SHDR_TYPE_DC);
    pkt->hdr.pkt_unc_len = htons(full_len);
    pkt->hdr.flags = htons(SHDR_NO_DEFLATE);

    /* Add the metadata */
    pkt->ship_id = htonl(sender);

    /* Copy in the packet, unchanged */
    memcpy(pkt->pkt, dc, dc_len);

    /* Send the packet away */
    return send_crypt(c, full_len);
}

int forward_pc(ship_t *c, dc_pkt_hdr_t *pc, uint32_t sender) {
    shipgate_fw_pkt *pkt = (shipgate_fw_pkt *)sendbuf;
    int pc_len = LE16(pc->pkt_len);
    int full_len = sizeof(shipgate_fw_pkt) + pc_len;

    /* Round up the packet size, if needed. */
    if(full_len & 0x07)
        full_len = (full_len + 8) & 0xFFF8;

    /* Scrub the buffer */
    memset(pkt, 0, full_len);

    /* Fill in the shipgate header */
    pkt->hdr.pkt_len = htons(full_len);
    pkt->hdr.pkt_type = htons(SHDR_TYPE_PC);
    pkt->hdr.pkt_unc_len = htons(full_len);
    pkt->hdr.flags = htons(SHDR_NO_DEFLATE);

    /* Add the metadata */
    pkt->ship_id = htonl(sender);

    /* Copy in the packet, unchanged */
    memcpy(pkt->pkt, pc, pc_len);

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
    pkt->hdr.pkt_unc_len = htons(sizeof(shipgate_login_pkt));
    pkt->hdr.flags = htons(SHDR_NO_DEFLATE);

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

/* Send a ship up/down message to the given ship. */
int send_ship_status(ship_t *c, ship_t *o, uint16_t status) {
    shipgate_ship_status_pkt *pkt = (shipgate_ship_status_pkt *)sendbuf;

    /* Scrub the buffer */
    memset(pkt, 0, sizeof(shipgate_ship_status_pkt));

    /* Fill in the header */
    pkt->hdr.pkt_len = htons(sizeof(shipgate_ship_status_pkt));
    pkt->hdr.pkt_type = htons(SHDR_TYPE_SSTATUS);
    pkt->hdr.pkt_unc_len = htons(sizeof(shipgate_ship_status_pkt));
    pkt->hdr.flags = htons(SHDR_NO_DEFLATE);

    /* Fill in the info */
    strcpy(pkt->name, o->name);
    pkt->ship_id = htonl(o->key_idx);
    pkt->ship_addr = o->remote_addr;
    pkt->int_addr = o->local_addr;
    pkt->ship_port = htons(o->port);
    pkt->status = htons(status);
    pkt->flags = htonl(o->flags);
    pkt->clients = htons(o->clients);
    pkt->games = htons(o->games);
    pkt->menu_code = htons(o->menu_code);
    pkt->ship_number = (uint8_t)o->ship_number;

    /* Send the packet away */
    return send_crypt(c, sizeof(shipgate_ship_status_pkt));
}

/* Send a ping packet to a client. */
int send_ping(ship_t *c, int reply) {
    shipgate_hdr_t *pkt = (shipgate_hdr_t *)sendbuf;

    /* Fill in the header. */
    pkt->pkt_len = htons(sizeof(shipgate_hdr_t));
    pkt->pkt_type = htons(SHDR_TYPE_PING);
    pkt->pkt_unc_len = htons(sizeof(shipgate_hdr_t));

    if(reply) {
        pkt->flags = htons(SHDR_NO_DEFLATE | SHDR_RESPONSE);
    }
    else {
        pkt->flags = htons(SHDR_NO_DEFLATE);
    }

    /* Send it away. */
    return send_crypt(c, sizeof(shipgate_hdr_t));
}

/* Send the ship a character data restore. */
int send_cdata(ship_t *c, uint32_t gc, uint32_t slot, void *cdata) {
    shipgate_char_data_pkt *pkt = (shipgate_char_data_pkt *)sendbuf;

    /* Fill in the header. */
    pkt->hdr.pkt_len = htons(sizeof(shipgate_char_data_pkt));
    pkt->hdr.pkt_type = htons(SHDR_TYPE_CREQ);
    pkt->hdr.pkt_unc_len = htons(sizeof(shipgate_char_data_pkt));
    pkt->hdr.flags = htons(SHDR_NO_DEFLATE | SHDR_RESPONSE);

    /* Fill in the body. */
    pkt->guildcard = htonl(gc);
    pkt->slot = htonl(slot);
    pkt->padding = 0;
    memcpy(pkt->data, cdata, 1052); 

    /* Send it away. */
    return send_crypt(c, sizeof(shipgate_char_data_pkt));
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
    pkt->hdr.pkt_unc_len = htons(sizeof(shipgate_gmlogin_reply_pkt));
    pkt->hdr.flags = htons(SHDR_NO_DEFLATE | flags);

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
    pkt->hdr.pkt_unc_len = htons(sizeof(shipgate_cnt_pkt));
    pkt->hdr.flags = htons(SHDR_NO_DEFLATE);

    pkt->clients = htons(clients);
    pkt->games = htons(games);
    pkt->ship_id = htonl(ship_id);

    return send_crypt(c, sizeof(shipgate_cnt_pkt));
}

/* Send an error packet to a ship */
int send_error(ship_t *c, uint16_t type, uint16_t flags, uint32_t err,
               uint8_t *data, int data_sz) {
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
    pkt->hdr.pkt_unc_len = pkt->hdr.pkt_len;
    pkt->hdr.flags = htons(flags);
    pkt->error_code = htonl(err);
    memcpy(pkt->data, data, data_sz);

    return send_crypt(c, sz);
}

/* Send a packet to tell a client that a friend has logged on or off */
int send_friend_message(ship_t *c, int on, uint32_t dest_gc,
                        uint32_t dest_block, uint32_t friend_gc,
                        uint32_t friend_block, uint32_t friend_ship,
                        const char *friend_name, const char *nickname) {
    shipgate_friend_login_pkt *pkt = (shipgate_friend_login_pkt *)sendbuf;

    /* These were first added in protocol version 2. */
    if(c->proto_ver < 2) {
        return 0;
    }

    /* Clear the packet */
    memset(pkt, 0, sizeof(shipgate_friend_login_pkt));

    /* Fill it in */
    pkt->hdr.pkt_len = htons(sizeof(shipgate_friend_login_pkt));
    pkt->hdr.pkt_type = htons((on ? SHDR_TYPE_FRLOGIN : SHDR_TYPE_FRLOGOUT));
    pkt->hdr.pkt_unc_len = pkt->hdr.pkt_len;
    pkt->hdr.flags = htons(SHDR_NO_DEFLATE);
    pkt->dest_guildcard = htonl(dest_gc);
    pkt->dest_block = htonl(dest_block);
    pkt->friend_guildcard = htonl(friend_gc);
    pkt->friend_ship = htonl(friend_ship);
    pkt->friend_block = htonl(friend_block);
    strcpy(pkt->friend_name, friend_name);

    /* Protocol version 4 brought a slightly newer form that allows nicknames to
       be assigned to entries. */
    if(c->proto_ver >= 4) {
        shipgate_friend_login_4_pkt *pkt2 = (shipgate_friend_login_4_pkt *)pkt;

        pkt2->hdr.pkt_len = htons(sizeof(shipgate_friend_login_4_pkt));
        pkt2->hdr.pkt_unc_len = pkt2->hdr.pkt_len;

        if(nickname) {
            strncpy(pkt2->friend_nick, nickname, 32);
            pkt2->friend_nick[31] = 0;
        }
        else {
            memset(pkt2->friend_nick, 0, 32);
        }

        return send_crypt(c, sizeof(shipgate_friend_login_4_pkt));
    }
    else {
        /* Send it away */
        return send_crypt(c, sizeof(shipgate_friend_login_pkt));
    }
}

/* Send a kick packet */
int send_kick(ship_t *c, uint32_t requester, uint32_t user, uint32_t block,
              const char *reason) {
    shipgate_kick_pkt *pkt = (shipgate_kick_pkt *)sendbuf;

    /* This appeared in v3, so don't send it to earlier ships */
    if(c->proto_ver < 3) {
        return 0;
    }

    /* Scrub the buffer */
    memset(pkt, 0, sizeof(shipgate_kick_pkt));

    /* Fill in the packet */
    pkt->hdr.pkt_len = htons(sizeof(shipgate_kick_pkt));
    pkt->hdr.pkt_type = htons(SHDR_TYPE_KICK);
    pkt->hdr.pkt_unc_len = pkt->hdr.pkt_len;
    pkt->hdr.flags = htons(SHDR_NO_DEFLATE);

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
                    int count, friendlist_data_t *entries) {
    shipgate_friend_list_pkt *pkt = (shipgate_friend_list_pkt *)sendbuf;
    uint16_t len = sizeof(shipgate_friend_list_pkt) +
        sizeof(friendlist_data_t) * count;

    /* This appeared in v5, so don't send it to earlier version ships */
    if(c->proto_ver < 5) {
        return 0;
    }

    /* Fill in the packet */
    pkt->hdr.pkt_len = htons(len);
    pkt->hdr.pkt_type = htons(SHDR_TYPE_FRLIST);
    pkt->hdr.pkt_unc_len = pkt->hdr.pkt_len;
    pkt->hdr.flags = htons(SHDR_NO_DEFLATE | SHDR_RESPONSE);

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

    /* This appeared in v5, so don't send it to earlier version ships */
    if(c->proto_ver < 5) {
        return 0;
    }

    /* Fill in the packet */
    pkt->hdr.pkt_len = htons(len);
    pkt->hdr.pkt_type = htons(SHDR_TYPE_GLOBALMSG);
    pkt->hdr.pkt_unc_len = pkt->hdr.pkt_len;
    pkt->hdr.flags = htons(SHDR_NO_DEFLATE);

    pkt->requester = htonl(requester);
    pkt->reserved = 0;
    memcpy(pkt->text, text, len);

    /* Send the packet away */
    return send_crypt(c, len);
}
