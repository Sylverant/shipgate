/*
    Sylverant Shipgate
    Copyright (C) 2011, 2016, 2018, 2019, 2021 Lawrence Sebald

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

#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/queue.h>

#include <sylverant/debug.h>
#include <sylverant/checksum.h>
#include <sylverant/config.h>

#include <libxml/parser.h>
#include <libxml/tree.h>

#include "scripts.h"

#ifdef ENABLE_LUA
#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#endif

#ifndef LIBXML_TREE_ENABLED
#error You must have libxml2 with tree support built-in.
#endif

#define XC (const xmlChar *)

#ifdef ENABLE_LUA

extern sylverant_config_t *cfg;

static lua_State *lstate;
static int scripts_ref = 0;
static int script_ids[ScriptActionCount] = { 0 };

uint32_t script_count;
ship_script_t *scripts;

/* This should be kept in sync with the same list in ship_server... */
static const xmlChar *ship_script_action_text[] = {
    XC"STARTUP",
    XC"SHUTDOWN",
    XC"SHIP_LOGIN",
    XC"SHIP_LOGOUT",
    XC"BLOCK_LOGIN",
    XC"BLOCK_LOGOUT",
    XC"UNK_SHIP_PKT",
    XC"UNK_BLOCK_PKT",
    XC"UNK_EP3_PKT",
    XC"TEAM_CREATE",
    XC"TEAM_DESTROY",
    XC"TEAM_JOIN",
    XC"TEAM_LEAVE",
    XC"ENEMY_KILL",
    XC"ENEMY_HIT",
    XC"BOX_BREAK",
    XC"UNK_COMMAND",
    XC"SDATA",
    XC"UNK_MENU",
    XC"BANK_ACTION",
    XC"CHANGE_AREA",
    XC"QUEST_SYNCREG",
    NULL
};

/* Text versions of the script actions. This must match the list in the
   script_action_t enum in scripts.h . */
static const xmlChar *script_action_text[] = {
    XC"STARTUP",
    XC"SHUTDOWN",
    XC"SDATA",
};

/* Figure out what index a given script action sits at */
static inline int ship_script_action_to_index(xmlChar *str) {
    int i;

    for(i = 0; ship_script_action_text[i]; ++i) {
        if(!xmlStrcmp(ship_script_action_text[i], str)) {
            return i;
        }
    }

    return -1;
}

static inline script_action_t script_action_to_index(xmlChar *str) {
    int i;

    for(i = 0; i < ScriptActionCount; ++i) {
        if(!xmlStrcmp(script_action_text[i], str)) {
            return (script_action_t)i;
        }
    }

    return ScriptActionInvalid;
}

static int ship_script_add(xmlChar *file, xmlChar *remote, int mod,
                           int action, uint32_t *alloc, int deleted) {
    void *tmp;
    FILE *fp;
    long len = 0;
    uint32_t crc = 0;

    /* Do we have space for this new script? */
    if(!*alloc) {
        /* This will probably be enough... At least for now. */
        scripts = (ship_script_t *)malloc(sizeof(ship_script_t) * 10);
        if(!scripts) {
            debug(DBG_ERROR, "Out of memory allocating scripts array\n");
            return -1;
        }

        *alloc = 10;
    }
    else if(*alloc == script_count) {
        tmp = realloc(scripts, sizeof(ship_script_t) * *alloc * 2);
        if(!tmp) {
            debug(DBG_ERROR, "Out of memory reallocating scripts array\n");
            return -1;
        }

        scripts = (ship_script_t *)tmp;
        *alloc *= 2;
    }

    /* Is the script deleted? */
    if(!deleted) {
        if(!(fp = fopen((char *)file, "rb"))) {
            debug(DBG_WARN, "Cannot open script file '%s'\n", file);
            return -2;
        }

        /* Figure out how long it is */
        fseek(fp, 0, SEEK_END);
        len = ftell(fp);
        fseek(fp, 0, SEEK_SET);

        if(len > 32768) {
            debug(DBG_WARN, "Script file '%s' is too long\n", file);
            fclose(fp);
            return -3;
        }

        if(!(tmp = malloc(len))) {
            debug(DBG_ERROR, "Out of memory allocating script\n");
            fclose(fp);
            return -4;
        }

        if(fread(tmp, 1, len, fp) != len) {
            debug(DBG_WARN, "Cannot read script '%s'\n", file);
            free(tmp);
            fclose(fp);
            return -4;
        }

        fclose(fp);

        crc = sylverant_crc32((const uint8_t *)tmp, len);
        free(tmp);
    }

    scripts[script_count].local_fn = (char *)file;
    scripts[script_count].remote_fn = (char *)remote;
    scripts[script_count].module = mod;
    scripts[script_count].event = action;
    scripts[script_count].len = (uint32_t)len;
    scripts[script_count].crc = crc;
    scripts[script_count].deleted = deleted;
    ++script_count;

    return 0;
}

/* Parse the XML for the script definitions */
int script_list_read(const char *fn) {
    xmlParserCtxtPtr cxt;
    xmlDoc *doc;
    xmlNode *n;
    xmlChar *file, *event, *remote, *deleted;
    int rv = 0;
    script_action_t idx;
    int sidx;
    uint32_t num_alloc = 0;
    int is_del = 0;

    /* If we're reloading, kill the old list. */
    if(scripts_ref) {
        luaL_unref(lstate, LUA_REGISTRYINDEX, scripts_ref);
    }

    /* Create an XML Parsing context */
    cxt = xmlNewParserCtxt();
    if(!cxt) {
        debug(DBG_ERROR, "Couldn't create XML parsing context for scripts\n");
        rv = -1;
        goto err;
    }

    /* Open the script list XML file for reading. */
    doc = xmlReadFile(fn, NULL, 0);
    if(!doc) {
        xmlParserError(cxt, "Error in parsing script List\n");
        rv = -2;
        goto err_cxt;
    }

    /* Make sure the document validated properly. */
    if(!cxt->valid) {
        xmlParserValidityError(cxt, "Validity Error parsing script List\n");
        rv = -3;
        goto err_doc;
    }

    /* If we've gotten this far, we have a valid document, now go through and
       add in entries for everything... */
    n = xmlDocGetRootElement(doc);

    if(!n) {
        debug(DBG_WARN, "Empty script List document\n");
        rv = -4;
        goto err_doc;
    }

    /* Make sure the list looks sane. */
    if(xmlStrcmp(n->name, XC"scripts")) {
        debug(DBG_WARN, "Script list does not appear to be the right type\n");
        rv = -5;
        goto err_doc;
    }

    /* Create a table for storing our pre-parsed scripts in... */
    lua_newtable(lstate);

    n = n->children;
    while(n) {
        if(n->type != XML_ELEMENT_NODE) {
            /* Ignore non-elements. */
            n = n->next;
            continue;
        }
        if(!xmlStrcmp(n->name, XC"script")) {
            /* See if we have all <script> elements... */
            event = xmlGetProp(n, XC"event");
            file = xmlGetProp(n, XC"file");

            if(!event || !file) {
                debug(DBG_WARN, "Incomplete script entry on line %hu\n",
                      n->line);
                goto next;
            }

            /* Figure out the entry we're looking at */
            idx = script_action_to_index(event);

            if(idx == ScriptActionInvalid) {
                debug(DBG_WARN, "Ignoring unknown event (%s) on line %hu\n",
                      (char *)event, n->line);
                goto next;
            }

            /* Issue a warning if we're redefining something */
            if(script_ids[idx]) {
                debug(DBG_WARN, "Redefining event \"%s\" on line %hu\n",
                      (char *)event, n->line);
            }

            /* Attempt to read in the script. */
            if(luaL_loadfile(lstate, (const char *)file) != LUA_OK) {
                debug(DBG_WARN, "Couldn't load script \"%s\" on line %hu\n",
                      (char *)file, n->line);
                goto next;
            }

            /* Add the script to the Lua table. */
            script_ids[idx] = luaL_ref(lstate, -2);
            debug(DBG_LOG, "Script for type %s added as ID %d\n", event,
                  script_ids[idx]);

        next:
            /* Free the memory we allocated here... */
            xmlFree(event);
            xmlFree(file);
        }
        else if(!xmlStrcmp(n->name, XC"module")) {
            /* See if we have all <module> elements... */
            file = xmlGetProp(n, XC"file");
            remote = xmlGetProp(n, XC"remote_file");
            deleted = xmlGetProp(n, XC"deleted");

            if(deleted) {
                if(!xmlStrcmp(deleted, XC"true")) {
                    is_del = 1;
                }
                else if(xmlStrcmp(deleted, XC"false")) {
                    debug(DBG_WARN, "Ignoring unknown value for deleted (%s) "
                          "on line %hu, assuming false\n", (char *)deleted,
                          n->line);
                }
            }

            /* We don't need this anymore... */
            xmlFree(deleted);

            if((!is_del && !file) || !remote) {
                debug(DBG_WARN, "Incomplete module entry on line %hu\n",
                      n->line);
                xmlFree(remote);
                xmlFree(file);
                goto next_ent;
            }

            /* Add it to the list. */
            if(ship_script_add(file, remote, 1, 0, &num_alloc, is_del)) {
                xmlFree(remote);
                xmlFree(file);
            }
            else {
                if(!is_del) {
                    debug(DBG_LOG, "Added module '%s'\n",
                          scripts[script_count - 1].local_fn);
                }
                else {
                    debug(DBG_LOG, "Added deleted module '%s'\n",
                          scripts[script_count - 1].remote_fn);
                }
            }
        }
        else if(!xmlStrcmp(n->name, XC"ship")) {
            /* See if we have all <module> elements... */
            file = xmlGetProp(n, XC"file");
            remote = xmlGetProp(n, XC"remote_file");
            event = xmlGetProp(n, XC"event");
            deleted = xmlGetProp(n, XC"deleted");

            if(deleted) {
                if(!xmlStrcmp(deleted, XC"true")) {
                    is_del = 1;
                }
                else if(xmlStrcmp(deleted, XC"false")) {
                    debug(DBG_WARN, "Ignoring unknown value for deleted (%s) "
                          "on line %hu, assuming false\n", (char *)deleted,
                          n->line);
                }
            }

            /* We don't need this anymore... */
            xmlFree(deleted);

            if((!is_del && !file) || !remote) {
                debug(DBG_WARN, "Incomplete ship entry on line %hu\n",
                      n->line);
                xmlFree(event);
                xmlFree(remote);
                xmlFree(file);
                goto next_ent;
            }

            /* If an event was provided, mark it */
            if(event) {
                /* Figure out the entry we're looking at */
                sidx = ship_script_action_to_index(event);
                if(sidx == -1) {
                    debug(DBG_WARN, "Ignoring unknown event (%s) on line %hu\n",
                          (char *)event, n->line);
                    xmlFree(event);
                    xmlFree(remote);
                    xmlFree(file);
                    goto next_ent;
                }
            }
            else {
                sidx = -1;
            }

            /* We're done with this now... */
            xmlFree(event);

            /* Add it to the list. */
            if(ship_script_add(file, remote, 0, sidx, &num_alloc, is_del)) {
                xmlFree(remote);
                xmlFree(file);
            }
            else {
                if(!is_del) {
                    debug(DBG_LOG, "Added ship script '%s'\n",
                          scripts[script_count - 1].local_fn);
                }
                else {
                    debug(DBG_LOG, "Added deleted ship script '%s'\n",
                          scripts[script_count - 1].remote_fn);
                }
            }
        }

    next_ent:
        n = n->next;
    }

    /* Store the table of scripts to the registry for later use. */
    scripts_ref = luaL_ref(lstate, LUA_REGISTRYINDEX);

    /* Cleanup/error handling below... */
err_doc:
    xmlFreeDoc(doc);
err_cxt:
    xmlFreeParserCtxt(cxt);
err:

    return rv;
}

extern int ship_register_lua(lua_State *l);

void init_scripts(void) {
    /* Not that this should happen, but just in case... */
    if(lstate) {
        debug(DBG_WARN, "Attempt to initialize scripting twice!\n");
        return;
    }

    /* Initialize the Lua interpreter */
    debug(DBG_LOG, "Initializing scripting support...\n");
    if(!(lstate = luaL_newstate())) {
        debug(DBG_ERROR, "Cannot initialize Lua!\n");
        return;
    }

    /* Load up the standard libraries. */
    luaL_openlibs(lstate);

    luaL_requiref(lstate, "shipgate", ship_register_lua, 1);
    lua_pop(lstate, 1);

    /* Set the module search path to include the scripts/modules dir. */
    (void)luaL_dostring(lstate, "package.path = package.path .. "
                        "';scripts/modules/?.lua'");

    /* Read in the configuration into our script table */
    if(cfg->sg_scripts_file) {
        if(script_list_read(cfg->sg_scripts_file)) {
            debug(DBG_WARN, "Couldn't load scripts configuration!\n");
        }
        else {
            debug(DBG_LOG, "Read script configuration\n");
        }
    }
    else {
        debug(DBG_LOG, "Scripts not configured\n");
    }
}

void cleanup_scripts(void) {
    uint32_t i;

    if(lstate) {
        /* For good measure, remove the scripts table from the registry. This
           should garbage collect everything in it, I hope. */
        if(scripts_ref)
            luaL_unref(lstate, LUA_REGISTRYINDEX, scripts_ref);

        lua_close(lstate);

        /* Clean everything back to a sensible state. */
        lstate = NULL;
        scripts_ref = 0;
        for(i = 0; i < ScriptActionCount; ++i) {
            script_ids[i] = 0;
        }

        /* Free the ship scripts */
        for(i = 0; i < script_count; ++i) {
            xmlFree(scripts[i].local_fn);
            xmlFree(scripts[i].remote_fn);
        }

        free(scripts);
        scripts = NULL;
        script_count = 0;
    }
}

int script_execute(script_action_t event, ...) {
    lua_Integer rv = 0;
    int err = 0, argtype, argcount = 0;
    va_list ap;
    const char *errmsg;

    /* Can't do anything if we don't have any scripts loaded. */
    if(!scripts_ref)
        return 0;

    /* Pull the scripts table out to the top of the stack. */
    lua_rawgeti(lstate, LUA_REGISTRYINDEX, scripts_ref);

    /* See if there's a script event defined */
    if(!script_ids[event])
        goto out;

    /* There is an script defined, grab it from the table. */
    lua_rawgeti(lstate, -1, script_ids[event]);

    /* Now, push the arguments onto the stack. */
    va_start(ap, event);
    while((argtype = va_arg(ap, int))) {
        switch(argtype) {
            case SCRIPT_ARG_INT:
            {
                int arg = va_arg(ap, int);
                lua_Integer larg = (lua_Integer)arg;
                lua_pushinteger(lstate, larg);
                break;
            }

            case SCRIPT_ARG_UINT8:
            {
                uint8_t arg = (uint8_t)va_arg(ap, int);
                lua_Integer larg = (lua_Integer)arg;
                lua_pushinteger(lstate, larg);
                break;
            }

            case SCRIPT_ARG_UINT16:
            {
                uint16_t arg = (uint16_t)va_arg(ap, int);
                lua_Integer larg = (lua_Integer)arg;
                lua_pushinteger(lstate, larg);
                break;
            }

            case SCRIPT_ARG_UINT32:
            {
                uint32_t arg = va_arg(ap, uint32_t);
                lua_Integer larg = (lua_Integer)arg;
                lua_pushinteger(lstate, larg);
                break;
            }

            case SCRIPT_ARG_FLOAT:
            {
                double arg = va_arg(ap, double);
                lua_Number larg = (lua_Number)arg;
                lua_pushnumber(lstate, larg);
                break;
            }

            case SCRIPT_ARG_PTR:
            {
                void *arg = va_arg(ap, void *);
                lua_pushlightuserdata(lstate, arg);
                break;
            }

            case SCRIPT_ARG_STRING:
            {
                size_t len = va_arg(ap, size_t);
                char *str = va_arg(ap, char *);
                lua_pushlstring(lstate, str, len);
                break;
            }

            case SCRIPT_ARG_CSTRING:
            {
                char *str = va_arg(ap, char *);
                lua_pushstring(lstate, str);
                break;
            }

            default:
                /* Fix the stack and stop trying to parse now... */
                debug(DBG_WARN, "Invalid script argument type: %d\n", argtype);
                lua_pop(lstate, argcount);
                rv = 0;
                goto out;
        }

        ++argcount;
    }
    va_end(ap);

    /* Done with that, call the function. */
    if((err = lua_pcall(lstate, argcount, 1, 0)) != LUA_OK) {
        debug(DBG_ERROR, "Error running Lua script for event %d (%d)\n",
              (int)event, err);

        if((errmsg = lua_tostring(lstate, -1))) {
            debug(DBG_ERROR, "Error message:\n%s\n", errmsg);
        }

        lua_pop(lstate, 1);
        goto out;
    }

    /* Grab the return value from the lua function (it should be of type
       integer). */
    rv = lua_tointegerx(lstate, -1, &err);
    if(!err) {
        debug(DBG_ERROR, "Script for event %d didn't return int\n",(int)event);
    }

    /* Pop off the return value. */
    lua_pop(lstate, 1);

out:
    /* Pop off the table reference that we pushed up above. */
    lua_pop(lstate, 1);
    return (int)rv;
}

#else

void init_scripts(void) {
}

void cleanup_scripts(void) {
}

int script_execute(script_action_t event, ...) {
    return 0;
}

#endif
