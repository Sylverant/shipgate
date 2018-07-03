/*
    Sylverant Shipgate
    Copyright (C) 2009, 2010, 2011, 2014, 2018 Lawrence Sebald

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
#include <iconv.h>
#include <pwd.h>
#include <grp.h>
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include <gnutls/gnutls.h>

#include <sylverant/config.h>
#include <sylverant/debug.h>
#include <sylverant/database.h>

#if HAVE_LIBUTIL_H == 1
#include <libutil.h>
#elif HAVE_BSD_LIBUTIL_H == 1
#include <bsd/libutil.h>
#else
/* From pidfile.c */
struct pidfh;
struct pidfh *pidfile_open(const char *path, mode_t mode, pid_t *pidptr);
int pidfile_write(struct pidfh *pfh);
int pidfile_remove(struct pidfh *pfh);
#endif

#include "shipgate.h"
#include "ship.h"

#ifndef PID_DIR
#define PID_DIR "/var/run"
#endif

#ifndef RUNAS_DEFAULT
#define RUNAS_DEFAULT "sylverant"
#endif

/* Storage for our list of ships. */
struct ship_queue ships = TAILQ_HEAD_INITIALIZER(ships);

/* Configuration/database connections. */
sylverant_config_t *cfg;
sylverant_dbconn_t conn;

/* Various iconv contexts we'll use */
iconv_t ic_utf8_to_utf16;
iconv_t ic_utf16_to_utf8;
iconv_t ic_sjis_to_utf8;
iconv_t ic_8859_to_utf8;

/* GnuTLS data... */
gnutls_certificate_credentials_t tls_cred;
gnutls_priority_t tls_prio;
static gnutls_dh_params_t dh_params;

static volatile sig_atomic_t shutting_down = 0;

/* Events... */
uint32_t event_count;
monster_event_t *events;

static const char *config_file = NULL;
static const char *custom_dir = NULL;
static int dont_daemonize = 0;
static const char *pidfile_name = NULL;
static struct pidfh *pf = NULL;
static const char *runas_user = RUNAS_DEFAULT;

/* Print information about this program to stdout. */
static void print_program_info() {
    printf("Sylverant Shipgate version %s\n", VERSION);
    printf("Copyright (C) 2009-2018 Lawrence Sebald\n\n");
    printf("This program is free software: you can redistribute it and/or\n"
           "modify it under the terms of the GNU Affero General Public\n"
           "License version 3 as published by the Free Software Foundation.\n\n"
           "This program is distributed in the hope that it will be useful,\n"
           "but WITHOUT ANY WARRANTY; without even the implied warranty of\n"
           "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the\n"
           "GNU General Public License for more details.\n\n"
           "You should have received a copy of the GNU Affero General Public\n"
           "License along with this program.  If not, see\n"
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
           "-C configfile   Use the specified configuration instead of the\n"
           "                default one.\n"
           "-D directory    Use the specified directory as the root\n"
           "--nodaemon      Don't daemonize\n"
           "-P filename     Use the specified name for the pid file to write\n"
           "                instead of the default.\n"
           "-U username     Run as the specified user instead of '%s'\n"
           "--help          Print this help and exit\n\n"
           "Note that if more than one verbosity level is specified, the last\n"
           "one specified will be used. The default is --verbose.\n", bin,
           RUNAS_DEFAULT);
}

/* Parse any command-line arguments passed in. */
static void parse_command_line(int argc, char *argv[]) {
    int i;

    for(i = 1; i < argc; ++i) {
        if(!strcmp(argv[i], "--version")) {
            print_program_info();
            exit(EXIT_SUCCESS);
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
        else if(!strcmp(argv[i], "-C")) {
            if(i == argc - 1) {
                printf("-C requires an argument!\n\n");
                print_help(argv[0]);
                exit(EXIT_FAILURE);
            }

            /* Save the config file's name. */
            config_file = argv[++i];
        }
        else if(!strcmp(argv[i], "-D")) {
            if(i == argc - 1) {
                printf("-D requires an argument!\n\n");
                print_help(argv[0]);
                exit(EXIT_FAILURE);
            }

            /* Save the custom dir */
            custom_dir = argv[++i];
        }
        else if(!strcmp(argv[i], "--nodaemon")) {
            dont_daemonize = 1;
        }
        else if(!strcmp(argv[i], "-P")) {
            if(i == argc - 1) {
                printf("-P requires an argument!\n\n");
                print_help(argv[0]);
                exit(EXIT_FAILURE);
            }

            pidfile_name = argv[++i];
        }
        else if(!strcmp(argv[i], "-U")) {
            if(i == argc - 1) {
                printf("-U requires an argument!\n\n");
                print_help(argv[0]);
                exit(EXIT_FAILURE);
            }

            runas_user = argv[++i];
        }
        else if(!strcmp(argv[i], "--help")) {
            print_help(argv[0]);
            exit(EXIT_SUCCESS);
        }
        else {
            printf("Illegal command line argument: %s\n", argv[i]);
            print_help(argv[0]);
            exit(EXIT_FAILURE);
        }
    }
}

/* Load the configuration file and print out parameters with DBG_LOG. */
static void load_config() {
    if(sylverant_read_config(config_file, &cfg)) {
        printf("Cannot load configuration!\n");
        exit(EXIT_FAILURE);
    }
}

static void init_gnutls() {
    int rv;

    /* Do the initial init */
    gnutls_global_init();

    /* Set up our credentials */
    // XXX: Check return values!
    rv = gnutls_certificate_allocate_credentials(&tls_cred);
    rv = gnutls_certificate_set_x509_trust_file(tls_cred, cfg->shipgate_ca,
                                                GNUTLS_X509_FMT_PEM);
    rv = gnutls_certificate_set_x509_key_file(tls_cred, cfg->shipgate_cert,
                                              cfg->shipgate_key,
                                              GNUTLS_X509_FMT_PEM);

    /* Generate Diffie-Hellman parameters */
    debug(DBG_LOG, "Generating Diffie-Hellman parameters...\n"
          "This may take a little while.\n");
    rv = gnutls_dh_params_init(&dh_params);
    rv = gnutls_dh_params_generate2(dh_params, 1024);
    debug(DBG_LOG, "Done!\n");

    rv = gnutls_priority_init(&tls_prio, "NORMAL:+COMP-DEFLATE", NULL);

    gnutls_certificate_set_dh_params(tls_cred, dh_params);
}

static void cleanup_gnutls() {
    gnutls_dh_params_deinit(dh_params);
    gnutls_certificate_free_credentials(tls_cred);
    gnutls_priority_deinit(tls_prio);
    gnutls_global_deinit();
}

static void free_events() {
    uint32_t i;

    for(i = 0; i < event_count; ++i) {
        free(events[i].monsters);
    }

    free(events);
}

static int read_events_table() {
    void *result;
    char **row;
    long long row_count, i, row_count2, j;
    char query[256];

    debug(DBG_LOG, "Reading events from the database...\n");
    if(sylverant_db_query(&conn, "SELECT event_id, title, start_time, "
                                 "end_time, difficulties, versions, "
                                 "allow_quests FROM monster_events WHERE "
                                 "end_time > UNIX_TIMESTAMP() ORDER BY "
                                 "start_time")) {
        debug(DBG_WARN, "Couldn't fetch events from database!\n");
        return -1;
    }

    if((result = sylverant_db_result_store(&conn)) == NULL) {
        debug(DBG_WARN, "Could not store results of event select!\n");
        return -1;
    }

    /* Make sure we have something. */
    row_count = sylverant_db_result_rows(result);
    if(row_count < 0) {
        debug(DBG_WARN, "Couldn't fetch event count!\n");
        sylverant_db_result_free(result);
        return -1;
    }
    else if(!row_count) {
        debug(DBG_LOG, "No events in database.\n");
        sylverant_db_result_free(result);
        return 0;
    }

    /* Allocate space for the events... */
    events = (monster_event_t *)malloc(row_count * sizeof(monster_event_t));
    if(!events) {
        debug(DBG_WARN, "Error allocating memory for events!\n");
        sylverant_db_result_free(result);
        return -1;
    }

    memset(events, 0, row_count * sizeof(monster_event_t));
    event_count = (uint32_t)row_count;

    /* Save each one. */
    i = 0;
    while((row = sylverant_db_result_fetch(result))) {
        /* This shouldn't ever happen... but whatever, doesn't hurt to check. */
        if(i >= row_count) {
            debug(DBG_WARN, "Got more result rows than expected?!\n");
            sylverant_db_result_free(result);
            free(events);
            return -1;
        }

        /* Copy the data over. */
        events[i].event_id = strtoul(row[0], NULL, 0);
        events[i].start_time = strtoul(row[2], NULL, 0);
        events[i].end_time = strtoul(row[3], NULL, 0);
        events[i].difficulties = (uint8_t)strtoul(row[4], NULL, 0);
        events[i].versions = (uint8_t)strtoul(row[5], NULL, 0);
        events[i].allow_quests = (uint8_t)strtoul(row[6], NULL, 0);

        if(!(events[i].event_title = strdup(row[1]))) {
            debug(DBG_WARN, "Error copying event title!\n");
            sylverant_db_result_free(result);
            free(events);
            return -1;
        }

        ++i;
    }

    sylverant_db_result_free(result);

    if(i < row_count) {
        debug(DBG_WARN, "Got less result rows than expected?!\n");
        free(events);
        return -1;
    }

    /* Run through each event and read the monster lists... */
    for(i = 0; i < row_count; ++i) {
        sprintf(query, "SELECT monster_type, episode FROM "
                       "monster_event_monsters WHERE event_id= '%" PRIu32 "'",
                events[i].event_id);

        if(sylverant_db_query(&conn, query)) {
            debug(DBG_WARN, "Couldn't fetch monsters from database!\n");
            free_events();
            return -1;
        }

        if((result = sylverant_db_result_store(&conn)) == NULL) {
            debug(DBG_WARN, "Could not store results of monster select!");
            free_events();
            return -1;
        }

        /* Make sure we have something. */
        row_count2 = sylverant_db_result_rows(result);
        events[i].monster_count = (uint32_t)row_count2;

        debug(DBG_LOG, "Event ID %" PRIu32 " (%s) - %" PRIu32 " enemies.\n",
              events[i].event_id, events[i].event_title,
              events[i].monster_count);

        if(row_count2 == 0) {
            sylverant_db_result_free(result);
            continue;
        }
        /* This shouldn't happen, but check anyway... */
        else if(row_count2 < 0 || row_count2 > 256) {
            sylverant_db_result_free(result);
            debug(DBG_WARN, "Got less than zero monsters in event?!\n");
            free_events();
            return -1;
        }

        /* Allocate space for the monsters... */
        events[i].monsters =
            (event_monster_t *)malloc(row_count2 * sizeof(event_monster_t));
        if(!events[i].monsters) {
            debug(DBG_WARN, "Error allocating memory for monsters!\n");
            sylverant_db_result_free(result);
            free_events();
            return -1;
        }

        memset(events[i].monsters, 0, row_count2 * sizeof(event_monster_t));

        j = 0;
        while((row = sylverant_db_result_fetch(result))) {
            /* Once again, shouldn't happen, but check anyway... */
            if(j >= row_count2) {
                debug(DBG_WARN, "Got more result rows than expected?!\n");
                sylverant_db_result_free(result);
                free_events();
                return -1;
            }

            events[i].monsters[j].monster = (uint16_t)strtoul(row[0], NULL, 0);
            events[i].monsters[j].episode = (uint8_t)strtoul(row[1], NULL, 0);
            ++j;
        }

        sylverant_db_result_free(result);

        /* Same warning about it shouldn't happen applies here... */
        if(j < row_count2) {
            debug(DBG_WARN, "Got less result rows than expected?!\n");
            free_events();
            return -1;
        }
    }

    debug(DBG_LOG, "Read %" PRIu32 " events successfully.\n", event_count);

    return 0;
}

static void open_db() {
    debug(DBG_LOG, "Connecting to the database...\n");

    if(sylverant_db_open(&cfg->dbcfg, &conn)) {
        debug(DBG_ERROR, "Can't connect to the database\n");
        exit(EXIT_FAILURE);
    }

    debug(DBG_LOG, "Clearing online_ships...\n");
    if(sylverant_db_query(&conn, "DELETE FROM online_ships")) {
        debug(DBG_ERROR, "Error clearing online_ships\n");
        exit(EXIT_FAILURE);
    }

    debug(DBG_LOG, "Clearing online_clients...\n");
    if(sylverant_db_query(&conn, "DELETE FROM online_clients")) {
        debug(DBG_ERROR, "Error clearing online_clients\n");
        exit(EXIT_FAILURE);
    }

    if(read_events_table()) {
        exit(EXIT_FAILURE);
    }
}

void run_server(int tsock, int tsock6) {
    int nfds;
    struct sockaddr_in addr;
    struct sockaddr_in6 addr6;
    int asock;
    socklen_t len;
    struct timeval timeout;
    fd_set readfds, writefds;
    ship_t *i, *tmp;
    ssize_t sent;
    time_t now;
    char ipstr[INET6_ADDRSTRLEN];

    for(;;) {
        /* Clear the fd_sets so we can use them. */
        FD_ZERO(&readfds);
        FD_ZERO(&writefds);
        nfds = 0;
        timeout.tv_sec = 30;
        timeout.tv_usec = 0;
        now = time(NULL);

        if(shutting_down) {
            debug(DBG_LOG, "Got shutdown signal\n");
            return;
        }

        /* Fill the sockets into the fd_set so we can use select below. */
        i = TAILQ_FIRST(&ships);
        while(i) {
            tmp = TAILQ_NEXT(i, qentry);

            /* If we haven't heard from a ship in 2 minutes, its dead.
               Disconnect it. */
            if(now > i->last_message + 120 && i->last_ping &&
               now > i->last_ping + 60) {
                destroy_connection(i);
                i = tmp;
                continue;
            }
            /* Otherwise, if we haven't heard from it in a minute, ping it. */
            else if(now > i->last_message + 60 && now > i->last_ping + 10) {
                send_ping(i, 0);
                i->last_ping = now;
            }

            FD_SET(i->sock, &readfds);

            if(i->sendbuf_cur) {
                FD_SET(i->sock, &writefds);
            }

            nfds = nfds > i->sock ? nfds : i->sock;

            /* Check GnuTLS' buffer for the connection. */
            if(gnutls_record_check_pending(i->session)) {
                if(handle_pkt(i)) {
                    i->disconnected = 1;
                }
            }

            i = tmp;
        }

        /* Add the main listening sockets to the read fd_set */
        if(tsock > -1) {
            FD_SET(tsock, &readfds);
            nfds = nfds > tsock ? nfds : tsock;
        }

        if(tsock6 > -1) {
            FD_SET(tsock6, &readfds);
            nfds = nfds > tsock6 ? nfds : tsock6;
        }

        if(select(nfds + 1, &readfds, &writefds, NULL, &timeout) > 0) {
            /* Check each ship's socket for activity. */
            TAILQ_FOREACH(i, &ships, qentry) {
                if(i->disconnected) {
                    continue;
                }

                /* Check if this ship was trying to send us anything. */
                if(FD_ISSET(i->sock, &readfds)) {
                    if(handle_pkt(i)) {
                        i->disconnected = 1;
                        continue;
                    }

                    i->last_ping = 0;
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
            if(tsock > -1 && FD_ISSET(tsock, &readfds)) {
                len = sizeof(struct sockaddr_in);

                if((asock = accept(tsock, (struct sockaddr *)&addr,
                                   &len)) < 0) {
                    perror("accept");
                    continue;
                }

                if(!create_connection_tls(asock, (struct sockaddr *)&addr,
                                          len)) {
                    continue;
                }

                if(!inet_ntop(AF_INET, &addr.sin_addr, ipstr,
                              INET6_ADDRSTRLEN)) {
                    perror("inet_ntop");
                    continue;
                }

                debug(DBG_LOG, "Accepted TLS ship connection from %s\n", ipstr);
            }

            /* If we have IPv6 support, check it too */
            if(tsock6 > -1 && FD_ISSET(tsock6, &readfds)) {
                len = sizeof(struct sockaddr_in6);

                if((asock = accept(tsock6, (struct sockaddr *)&addr6,
                                   &len)) < 0) {
                    perror("accept");
                    continue;
                }

                if(!create_connection_tls(asock, (struct sockaddr *)&addr6,
                                          len)) {
                    continue;
                }

                if(!inet_ntop(AF_INET6, &addr6.sin6_addr, ipstr,
                              INET6_ADDRSTRLEN)) {
                    perror("inet_ntop");
                    continue;
                }

                debug(DBG_LOG, "Accepted TLS ship connection from %s\n", ipstr);
            }
        }
    }
}

static void open_log() {
    FILE *dbgfp;

    dbgfp = fopen("logs/shipgate_debug.log", "a");

    if(!dbgfp) {
        debug(DBG_ERROR, "Cannot open log file\n");
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    debug_set_file(dbgfp);
}

static void reopen_log(void) {
    FILE *dbgfp;

    dbgfp = fopen("logs/shipgate_debug.log", "a");

    if(!dbgfp) {
        debug(DBG_ERROR, "Cannot open log file\n");
        perror("fopen");
        exit(EXIT_FAILURE);
    }

    /* Swap out the file pointers and close the old one. */
    dbgfp = debug_set_file(dbgfp);
    fclose(dbgfp);
}

static int open_sock(int family, uint16_t port) {
    int sock, val;
    struct sockaddr_in addr;
    struct sockaddr_in6 addr6;

    sock = socket(family, SOCK_STREAM, IPPROTO_TCP);

    if(sock < 0) {
        perror("socket");
        return -1;
    }

    /* Set SO_REUSEADDR so we don't run into issues when we kill the shipgate
       and bring it back up quickly... */
    val = 1;
    if(setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(int))) {
        perror("setsockopt SO_REUSEADDR");
        /* We can ignore this error, pretty much... its just a convenience thing
           anyway... */
    }

    if(family == AF_INET) {
        memset(&addr, 0, sizeof(struct sockaddr_in));

        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(port);

        if(bind(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in))) {
            perror("bind");
            close(sock);
            return -1;
        }

        if(listen(sock, 10)) {
            perror("listen");
            close(sock);
            return -1;
        }
    }
    else if(family == AF_INET6) {
        /* Since we create separate sockets for IPv4 and IPv6, make this one
           support ONLY IPv6. */
        val = 1;
        if(setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &val, sizeof(int))) {
            perror("setsockopt IPV6_V6ONLY");
            close(sock);
            return -1;
        }

        memset(&addr6, 0, sizeof(struct sockaddr_in6));

        addr6.sin6_family = AF_INET6;
        addr6.sin6_addr = in6addr_any;
        addr6.sin6_port = htons(port);

        if(bind(sock, (struct sockaddr *)&addr6, sizeof(struct sockaddr_in6))) {
            perror("bind");
            close(sock);
            return -1;
        }

        if(listen(sock, 10)) {
            perror("listen");
            close(sock);
            return -1;
        }
    }
    else {
        debug(DBG_ERROR, "Unknown socket family\n");
        close(sock);
        return -1;
    }

    return sock;
}

static void sighup_hnd(int signum, siginfo_t *inf, void *ptr) {
    (void)signum;
    (void)inf;
    (void)ptr;
    reopen_log();
}

static void sigterm_hnd(int signum, siginfo_t *inf, void *ptr) {
    (void)signum;
    (void)inf;
    (void)ptr;

    shutting_down = 1;
}

static void sigusr1_hnd(int signum, siginfo_t *inf, void *ptr) {
    (void)signum;
    (void)inf;
    (void)ptr;

    shutting_down = 2;
}

/* Install any handlers for signals we care about */
static void install_signal_handlers() {
    struct sigaction sa;

    memset(&sa, 0, sizeof(struct sigaction));
    sigemptyset(&sa.sa_mask);

    /* Ignore SIGPIPEs */
    sa.sa_handler = SIG_IGN;

    if(sigaction(SIGPIPE, &sa, NULL) == -1) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }

    /* Set up a SIGHUP handler to reopen the log file, if we do log rotation. */
    if(!dont_daemonize) {
        sigemptyset(&sa.sa_mask);
        sa.sa_handler = NULL;
        sa.sa_sigaction = &sighup_hnd;
        sa.sa_flags = SA_SIGINFO | SA_RESTART;

        if(sigaction(SIGHUP, &sa, NULL) < 0) {
            perror("sigaction");
            fprintf(stderr, "Can't set SIGHUP handler, log rotation may not"
                    "work.\n");
        }
    }

    /* Set up a SIGTERM handler to somewhat gracefully shutdown. */
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = NULL;
    sa.sa_sigaction = &sigterm_hnd;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;

    if(sigaction(SIGTERM, &sa, NULL) < 0) {
        perror("sigaction");
        fprintf(stderr, "Can't set SIGTERM handler.\n");
    }

    /* Set up a SIGUSR1 handler to restart... */
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = NULL;
    sa.sa_sigaction = &sigusr1_hnd;
    sa.sa_flags = SA_SIGINFO | SA_RESTART;

    if(sigaction(SIGUSR1, &sa, NULL) < 0) {
        perror("sigaction");
        fprintf(stderr, "Can't set SIGUSR1 handler.\n");
    }
}

static int drop_privs(void) {
    struct passwd *pw;
    uid_t uid;
    gid_t gid;
    int gid_count = 0;
    gid_t *groups;

    /* Make sure we're actually root, otherwise some of this will fail. */
    if(getuid() && geteuid())
        return 0;

    /* Look for users. We're looking for the user "sylverant", generally. */
    if((pw = getpwnam(runas_user))) {
        uid = pw->pw_uid;
        gid = pw->pw_gid;
    }
    else {
        debug(DBG_ERROR, "Cannot find user \"%s\". Bailing out!\n", runas_user);
        return -1;
    }

#ifdef HAVE_GETGROUPLIST
    /* Figure out what other groups the user is in... */
    getgrouplist(runas_user, gid, NULL, &gid_count);
    if(!(groups = malloc(gid_count * sizeof(gid_t)))) {
        perror("malloc");
        return -1;
    }

    if(getgrouplist(runas_user, gid, groups, &gid_count)) {
        perror("getgrouplist");
        free(groups);
        return -1;
    }

    if(setgroups(gid_count, groups)) {
        perror("setgroups");
        free(groups);
        return -1;
    }

    /* We're done with most of these, so clear this out now... */
    free(groups);
#else
    if(setgroups(1, &gid)) {
        perror("setgroups");
        return -1;
    }
#endif

    if(setgid(gid)) {
        perror("setgid");
        return -1;
    }

    if(setuid(uid)) {
        perror("setuid");
        return -1;
    }

    /* Make sure the privileges stick. */
    if(!getuid() || !geteuid()) {
        debug(DBG_ERROR, "Cannot set non-root privileges. Bailing out!\n");
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[]) {
    int tsock = -1, tsock6 = -1;
    char *initial_path;
    long size;
    pid_t op;

    /* Parse the command line and read our configuration. */
    parse_command_line(argc, argv);

    /* Save the initial path. */
    size = pathconf(".", _PC_PATH_MAX);
    if(!(initial_path = (char *)malloc(size))) {
        debug(DBG_WARN, "Out of memory, bailing out!\n");
    }
    else if(!getcwd(initial_path, size)) {
        debug(DBG_WARN, "Cannot save initial path, Restart may not work!\n");
    }

    load_config();

    if(!custom_dir) {
        chdir(sylverant_directory);
    }
    else {
        chdir(custom_dir);
    }

    /* If we're still alive and we're supposed to daemonize, do it now. */
    if(!dont_daemonize) {
        /* Attempt to open and lock the pid file. */
        if(!pidfile_name) {
            char *pn = (char *)malloc(strlen(PID_DIR) + 32);
            sprintf(pn, "%s/shipgate.pid", PID_DIR);
            pidfile_name = pn;
        }

        pf = pidfile_open(pidfile_name, 0660, &op);

        if(!pf) {
            if(errno == EEXIST) {
                debug(DBG_ERROR, "Shipgate already running? (pid: %ld)\n",
                      (long)op);
                exit(EXIT_FAILURE);
            }

            debug(DBG_WARN, "Cannot create pidfile: %s!\n", strerror(errno));
        }

        if(daemon(1, 0)) {
            debug(DBG_ERROR, "Cannot daemonize\n");
            perror("daemon");
            exit(EXIT_FAILURE);
        }

        if(drop_privs())
            exit(EXIT_FAILURE);

        open_log();

        /* Write the pid file. */
        pidfile_write(pf);
    }
    else {
        if(drop_privs())
            exit(EXIT_FAILURE);
    }

restart:
    shutting_down = 0;

    /* Initialize GnuTLS */
    init_gnutls();

    /* Create the iconv contexts we'll use */
    ic_utf8_to_utf16 = iconv_open("UTF-16LE", "UTF-8");
    if(ic_utf8_to_utf16 == (iconv_t)-1) {
        debug(DBG_ERROR, "Cannot create iconv context (UTF-8 to UTF-16)\n");
        pidfile_remove(pf);
        exit(EXIT_FAILURE);
    }

    ic_utf16_to_utf8 = iconv_open("UTF-8", "UTF-16LE");
    if(ic_utf16_to_utf8 == (iconv_t)-1) {
        debug(DBG_ERROR, "Cannot create iconv context (UTF-16 to UTF-8)\n");
        pidfile_remove(pf);
        exit(EXIT_FAILURE);
    }

    ic_sjis_to_utf8 = iconv_open("UTF-8", "SHIFT_JIS");
    if(ic_sjis_to_utf8 == (iconv_t)-1) {
        debug(DBG_ERROR, "Cannot create iconv context (Shift-JIS to UTF-8)\n");
        pidfile_remove(pf);
        exit(EXIT_FAILURE);
    }

    ic_8859_to_utf8 = iconv_open("UTF-8", "ISO-8859-1");
    if(ic_8859_to_utf8 == (iconv_t)-1) {
        debug(DBG_ERROR, "Cannot create iconv context (ISO-8859-1 to UTF-8)\n");
        pidfile_remove(pf);
        exit(EXIT_FAILURE);
    }

    /* Install signal handlers */
    install_signal_handlers();

    /* Create the socket and listen for TLS connections. */
    tsock = open_sock(AF_INET, cfg->shipgate_port);
    tsock6 = open_sock(AF_INET6, cfg->shipgate_port);

    if(tsock == -1 && tsock6 == -1) {
        debug(DBG_ERROR, "Couldn't create IPv4 or IPv6 TLS socket!\n");
        pidfile_remove(pf);
        exit(EXIT_FAILURE);
    }

    /* Clean up the DB now that we've done everything else that might fail... */
    open_db();

    /* Run the shipgate server. */
    run_server(tsock, tsock6);

    /* Clean up. */
    close(tsock);
    close(tsock6);
    free_events();
    iconv_close(ic_utf8_to_utf16);
    iconv_close(ic_utf16_to_utf8);
    sylverant_db_close(&conn);
    cleanup_gnutls();
    sylverant_free_config(cfg);

    /* Restart if we're supposed to be doing so. */
    if(shutting_down == 2) {
        load_config();
        goto restart;
    }

    free(initial_path);
    pidfile_remove(pf);

    return 0;
}
