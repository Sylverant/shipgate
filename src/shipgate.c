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
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <sylverant/config.h>
#include <sylverant/debug.h>
#include <sylverant/database.h>

#include "shipgate.h"
#include "ship.h"

/* Storage for our list of ships. */
struct ship_queue ships = TAILQ_HEAD_INITIALIZER(ships);

/* Configuration/database connections. */
sylverant_config_t cfg;
sylverant_dbconn_t conn;

/* Print information about this program to stdout. */
static void print_program_info() {
    printf("Sylverant Shipgate version %s\n", VERSION);
    printf("Copyright (C) 2009, 2010, 2011 Lawrence Sebald\n\n");
    printf("This program is free software: you can redistribute it and/or\n"
           "modify it under the terms of the GNU Affero General Public\n"
           "License version 3 as published by the Free Software Foundation.\n\n"
           "This program is distributed in the hope that it will be useful,\n"
           "but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
           "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
           "GNU General Public License for more details.\n\n"
           "You should have received a copy of the GNU Affero General Public\n"
           "License along with this program.  If not, see"
           "<http://www.gnu.org/licenses/>.\n");
}

/* Print help to the user to stdout. */
static void print_help(const char *bin) {
    printf("Usage: %s [arguments]\n"
           "-----------------------------------------------------------------\n"
           "--version       Print version info and exit\n"
           "--verbose       Log many messages that might help debug a problem\n"
           "--quiet         Only log warning and error messages\n"
           "--reallyquiet   Only log error messages\n"
           "--help          Print this help and exit\n\n"
           "Note that if more than one verbosity level is specified, the last\n"
           "one specified will be used. The default is --verbose.\n", bin);
}

/* Parse any command-line arguments passed in. */
static void parse_command_line(int argc, char *argv[]) {
    int i;

    for(i = 1; i < argc; ++i) {
        if(!strcmp(argv[i], "--version")) {
            print_program_info();
            exit(0);
        }
        else if(!strcmp(argv[i], "--verbose")) {
            debug_set_threshold(DBG_LOG);
        }
        else if(!strcmp(argv[i], "--quiet")) {
            debug_set_threshold(DBG_WARN);
        }
        else if(!strcmp(argv[i], "--reallyquiet")) {
            debug_set_threshold(DBG_ERROR);
        }
        else if(!strcmp(argv[i], "--help")) {
            print_help(argv[0]);
            exit(0);
        }
        else {
            printf("Illegal command line argument: %s\n", argv[i]);
            print_help(argv[0]);
            exit(1);
        }
    }
}

/* Load the configuration file and print out parameters with DBG_LOG. */
static void load_config() {
    if(sylverant_read_config(&cfg)) {
        printf("Cannot load configuration!\n");
        exit(1);
    }

    debug(DBG_LOG, "Connecting to the database...\n");

    if(sylverant_db_open(&cfg.dbcfg, &conn)) {
        debug(DBG_ERROR, "Can't connect to the database\n");
        exit(1);
    }

    debug(DBG_LOG, "Clearing online_ships...\n");
    if(sylverant_db_query(&conn, "DELETE FROM online_ships")) {
        debug(DBG_ERROR, "Error clearing online_ships\n");
        exit(1);
    }

    debug(DBG_LOG, "Clearing online_clients...\n");
    if(sylverant_db_query(&conn, "DELETE FROM online_clients")) {
        debug(DBG_ERROR, "Error clearing online_clients\n");
        exit(1);
    }
}

void run_server(int sock) {
    int nfds;
    struct sockaddr_in addr;
    int asock;
    socklen_t len;
    struct timeval timeout;
    fd_set readfds, writefds;
    ship_t *i, *tmp;
    ssize_t sent;
    time_t now;

    for(;;) {
        /* Clear the fd_sets so we can use them. */
        FD_ZERO(&readfds);
        FD_ZERO(&writefds);
        nfds = 0;
        timeout.tv_sec = 30;
        timeout.tv_usec = 0;
        now = time(NULL);

        /* Fill the sockets into the fd_set so we can use select below. */
        i = TAILQ_FIRST(&ships);
        while(i) {
            tmp = TAILQ_NEXT(i, qentry);

            /* If we haven't heard from a ship in 2 minutes, its dead.
               Disconnect it. */
            if(now > i->last_message + 120) {
                destroy_connection(i);
                i = tmp;
                continue;
            }
            /* Otherwise, if we haven't heard from it in a minute, ping it. */
            else if(now > i->last_message + 60) {
                send_ping(i, 0);
            }

            FD_SET(i->sock, &readfds);

            if(i->sendbuf_cur) {
                FD_SET(i->sock, &writefds);
            }

            nfds = nfds > i->sock ? nfds : i->sock;
            i = tmp;
        }

        /* Add the main listening socket to the read fd_set */
        FD_SET(sock, &readfds);
        nfds = nfds > sock ? nfds : sock;

        if(select(nfds + 1, &readfds, &writefds, NULL, &timeout) > 0) {
            /* Check each ship's socket for activity. */
            TAILQ_FOREACH(i, &ships, qentry) {
                /* Check if this ship was trying to send us anything. */
                if(FD_ISSET(i->sock, &readfds)) {
                    if(handle_pkt(i)) {
                        i->disconnected = 1;
                        continue;
                    }
                }

                /* If we have anything to write, check if we can. */
                if(FD_ISSET(i->sock, &writefds)) {
                    if(i->sendbuf_cur) {
                        sent = send(i->sock, i->sendbuf + i->sendbuf_start,
                                    i->sendbuf_cur - i->sendbuf_start, 0);

                        /* If we fail to send, and the error isn't EAGAIN,
                           bail. */
                        if(sent == -1) {
                            if(errno != EAGAIN) {
                                i->disconnected = 1;
                            }
                        }
                        else {
                            i->sendbuf_start += sent;

                            /* If we've sent everything, free the buffer. */
                            if(i->sendbuf_start == i->sendbuf_cur) {
                                free(i->sendbuf);
                                i->sendbuf = NULL;
                                i->sendbuf_cur = 0;
                                i->sendbuf_size = 0;
                                i->sendbuf_start = 0;
                            }
                        }
                    }
                }
            }

            /* Clean up any dead connections (its not safe to do a TAILQ_REMOVE
               in the middle of a TAILQ_FOREACH, and destroy_connection does
               indeed use TAILQ_REMOVE). */
            i = TAILQ_FIRST(&ships);
            while(i) {
                tmp = TAILQ_NEXT(i, qentry);

                if(i->disconnected) {
                    destroy_connection(i);
                }

                i = tmp;
            }

            /* Check the listening port to see if we have a ship. */
            if(FD_ISSET(sock, &readfds)) {
                len = sizeof(struct sockaddr_in);

                if((asock = accept(sock, (struct sockaddr *)&addr, &len)) < 0) {
                    perror("accept");
                }

                debug(DBG_LOG, "Accepted ship connection from %s\n",
                      inet_ntoa(addr.sin_addr));

                if(create_connection(asock, addr.sin_addr.s_addr) == NULL) {
                    close(asock);
                }
            }
        }
    }
}

int main(int argc, char *argv[]) {
    int sock;
    struct sockaddr_in addr;

    /* Parse the command line and read our configuration. */
    parse_command_line(argc, argv);
    load_config();
    
    chdir(sylverant_directory);

    /* Create the socket and listen for connections. */
    sock = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

    if(sock < 0) {
        perror("socket");
        sylverant_db_close(&conn);
        return 1;
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(3455);
    memset(addr.sin_zero, 0, 8);

    if(bind(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in))) {
        perror("bind");
        sylverant_db_close(&conn);
        close(sock);
        return 1;
    }

    if(listen(sock, 10)) {
        perror("listen");
        sylverant_db_close(&conn);
        close(sock);
        return 1;
    }

    /* Run the shipgate server. */
    run_server(sock);

    /* Clean up. */
    close(sock);
    sylverant_db_close(&conn);

    return 0;
}
