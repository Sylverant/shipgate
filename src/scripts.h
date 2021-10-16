/*
    Sylverant Shipgate
    Copyright (C) 2011, 2016, 2018, 2021 Lawrence Sebald

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

#ifndef SCRIPTS_H
#define SCRIPTS_H

#include <stdint.h>
#include <sys/queue.h>

typedef struct ship_script {
    char *local_fn;
    char *remote_fn;
    uint32_t len;
    uint32_t crc;
    int module;
    int event;
    int deleted;
} ship_script_t;

/* Scriptable actions on the shipgate */
typedef enum script_action {
    ScriptActionInvalid = -1,
    ScriptActionFirst = 0,
    ScriptActionStartup = 0,
    ScriptActionShutdown,
    ScriptActionSData,
    ScriptActionCount
} script_action_t;

/* Argument types. */
#define SCRIPT_ARG_NONE     0
#define SCRIPT_ARG_END      SCRIPT_ARG_NONE
#define SCRIPT_ARG_INT      1
#define SCRIPT_ARG_PTR      2
#define SCRIPT_ARG_FLOAT    3
#define SCRIPT_ARG_UINT8    4
#define SCRIPT_ARG_UINT16   5
#define SCRIPT_ARG_UINT32   6
#define SCRIPT_ARG_STRING   7
#define SCRIPT_ARG_CSTRING  8

/* Call the script function for the given event with the args listed */
int script_execute(script_action_t event, ...);

void init_scripts(void);
void cleanup_scripts(void);

#endif /* !SCRIPTS_H */
