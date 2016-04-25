/*
 * Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdarg.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/mman.h>
#include <pwd.h>
#include <grp.h>

#include <dbuspolicy1/libdbuspolicy1.h>
#include "libdbuspolicy1-private.h"
#include "internal/internal.h"

#define KDBUS_SYSTEM_BUS_PATH "/sys/fs/kdbus/0-system/bus"
#define KDBUS_POOL_SIZE (16 * 1024UL * 1024UL)

#define ALIGN8(l) (((l) + 7) & ~7)
#define UID_INVALID ((uid_t) -1)
#define GID_INVALID ((gid_t) -1)

#define FOREACH_STRV(i,l, s, os)\
for(\
({\
i=0;\
l = strlen(s);\
name = malloc(sizeof(char*)*(l+1));\
strncpy(os, s, sizeof(char*)*(l+1)-1);\
});\
i < l;\
i++)

#define GET_NEXT_STR(i,s,os)\
        os = s+i;\
        for(;s[i] && s[i] != ' ';i++);\
        s[i] = 0;



/** A process ID */
typedef unsigned long dbus_pid_t;
/** A user ID */
typedef unsigned long dbus_uid_t;
/** A group ID */
typedef unsigned long dbus_gid_t;

struct kcreds {
    uid_t uid;
    gid_t gid;
    char* label;
    char** names;
};

struct kconn {
    int fd;
    uint64_t id;
    char *pool;
};
struct udesc {
    unsigned int bus_type;
    char user[256];
    dbus_uid_t uid;
    char group[256];
    dbus_gid_t gid;
    char label[256];
    struct kconn* conn;
};


static int kdbus_open_system_bus(void)
{
    return  open(KDBUS_SYSTEM_BUS_PATH, O_RDWR|O_NOCTTY|O_LARGEFILE|O_CLOEXEC );
}

static int kdbus_hello(struct kconn *kc, uint64_t hello_flags, uint64_t attach_flags_send, uint64_t attach_flags_recv)
{
    struct kdbus_cmd_hello kcmd_hello;
    int r;

    memset(&kcmd_hello, 0, sizeof(kcmd_hello));
    kcmd_hello.flags = hello_flags;
    kcmd_hello.attach_flags_send = attach_flags_send;
    kcmd_hello.attach_flags_recv = attach_flags_recv;
    kcmd_hello.size = sizeof(kcmd_hello);
    kcmd_hello.pool_size = KDBUS_POOL_SIZE;

    r = ioctl(kc->fd, KDBUS_CMD_HELLO, &kcmd_hello);
    if (r < 0)
        return -errno;

    kc->id = (uint64_t)kcmd_hello.id;
    kc->pool = mmap(NULL, KDBUS_POOL_SIZE, PROT_READ, MAP_SHARED, kc->fd, 0);
    if (kc->pool == MAP_FAILED)
        return -errno;

    return 0;
}

static int kdbus_is_unique_id(const char* name)
{
    return (strlen(name)>3 && name[0]==':' && isdigit(name[1]) && name[2]=='.');
}

static int kdbus_get_creds_from_name(struct kconn* kc, struct kcreds* kcr, const char* name)
{
    unsigned long long int unique_id;
    struct kdbus_cmd_info* cmd;
    struct kdbus_info* conn_info;
    struct kdbus_item *item;
    char** tmp_names;
    int j, r, l, counter;
    unsigned int size;

    counter = 0;
    kcr->names = calloc(counter+1, sizeof(char *));

    kcr->uid = UID_INVALID;
    kcr->gid = GID_INVALID;
    kcr->label = NULL;

    if (kdbus_is_unique_id(name)) {
        l = sizeof(unique_id);
        unique_id = strtoull(name+3, NULL, 10);
        size = sizeof(struct kdbus_cmd_info);
        cmd = aligned_alloc(8, size);
        memset(cmd, 0, sizeof(struct kdbus_cmd_info));
        cmd->id = unique_id;
        cmd->size = size;
        cmd->attach_flags  = KDBUS_ATTACH_CREDS | KDBUS_ATTACH_SECLABEL | KDBUS_ATTACH_NAMES;
    } else {
        l = strlen(name) + 1;
        size = offsetof(struct kdbus_cmd_info, items) + ALIGN8((l) + offsetof(struct kdbus_item, data));
        cmd = aligned_alloc(8, size);
        memset(cmd, 0, sizeof(struct kdbus_cmd_info));
        cmd->items[0].size =  l + offsetof(struct kdbus_item, data);
        cmd->items[0].type = KDBUS_ITEM_NAME;
        memcpy(cmd->items[0].str, name, l);
        cmd->size = size;
        cmd->attach_flags  = KDBUS_ATTACH_CREDS | KDBUS_ATTACH_SECLABEL | KDBUS_ATTACH_NAMES;
    }

    r = ioctl(kc->fd, KDBUS_CMD_CONN_INFO, cmd);
    if (r < 0)
        return -errno;

    conn_info = (struct kdbus_info *) ((uint8_t *) kc->pool + cmd->offset);

    for(item = conn_info->items;
        ((uint8_t *)(item) < (uint8_t *)(conn_info) + (conn_info)->size) &&
        ((uint8_t *) item >= (uint8_t *) conn_info);
        item = ((typeof(item))(((uint8_t *)item) + ALIGN8((item)->size))) )
        {
            switch (item->type)
            {
                case KDBUS_ITEM_CREDS:
                    if (item->creds.euid != UID_INVALID)
                    {
                         kcr->uid = (uid_t) item->creds.euid;
                    }
                    if (item->creds.egid != GID_INVALID)
                    {
                        kcr->gid = (gid_t) item->creds.egid;
                    }
                break;
            case KDBUS_ITEM_SECLABEL:
                kcr->label = strdup(item->str);
            break;
            case KDBUS_ITEM_OWNED_NAME:
                counter++;
                tmp_names = calloc(counter+1, sizeof(char*));
                for (j = 0;kcr->names[j]; j++)
                {
                    tmp_names[j] = kcr->names[j];
                }
                tmp_names[j] = strdup(item->name.name);
                free(kcr->names);
                kcr->names = tmp_names;
            break;
        }
    }

    return 0;
}

static void kcreds_free(struct kcreds* kcr)
{
    int i = 0;
    if (kcr == NULL)
        return;

    free(kcr->label);
    for (i=0; kcr->names[i];i++)
        free(kcr->names[i]);
    free(kcr->names[i]);
    free(kcr->names);
    free(kcr);
}

static int dbuspolicy_init_udesc(struct kconn* kc, unsigned int bus_type, struct udesc* p_udesc)
{
     struct passwd pwent;
     struct passwd *pwd;
     struct group grent;
     struct group *gg;
     char buf[1024];
     int attr_fd;
     int r;
     int len;

     attr_fd = open("/proc/self/attr/current", O_RDONLY);
     if (attr_fd < 0)
	  return -1;
     r = read(attr_fd, p_udesc->label, 256);

     close(attr_fd);

     if (r < 0) /* read */
	  return -1;

     if (getpwuid_r(p_udesc->uid, &pwent, buf, sizeof(buf), &pwd))
	  return -1;

     if (getgrgid_r(p_udesc->gid, &grent, buf, sizeof(buf), &gg))
	  return -1;

     if (!pwd || !gg)
          return -1;

     len = sizeof(p_udesc->user) - 1;
     strncpy(p_udesc->user, pwd->pw_name, len);
     p_udesc->group[len] = 0;

     len = sizeof(p_udesc->group) - 1;
     strncpy(p_udesc->group, gg->gr_name, len);
     p_udesc->group[len] = 0;

     p_udesc->bus_type = bus_type;
     p_udesc->uid = getuid();
     p_udesc->gid = getgid();
     p_udesc->conn = kc;

     return 0;
}

/**
 * dbuspolicy1_init
 * @config_name: name of the XML configuration file
 *
 * Set the configuration file used by the calling application
 **/
DBUSPOLICY1_EXPORT void* dbuspolicy1_init(unsigned int bus_type)
{
     uint64_t hello_flags = 0;
     uint64_t attach_flags_send =  _KDBUS_ATTACH_ANY;
     uint64_t attach_flags_recv =  _KDBUS_ATTACH_ALL;
     struct kconn* kc = NULL;
     struct udesc* p_udesc = NULL;

     kc = (struct kconn*) calloc(1, sizeof(struct kconn));
     p_udesc = (struct udesc*)malloc(sizeof(struct udesc));
     if (!kc || !p_udesc)
	  goto err;

     if ((kc->fd = kdbus_open_system_bus()) < 0)
	  goto err;

     if (kdbus_hello(kc, hello_flags, attach_flags_send, attach_flags_recv) < 0)
	  goto err;

     if (__internal_init(bus_type, (bus_type == SYSTEM_BUS) ? SYSTEM_BUS_CONF_FILE_PRIMARY : SESSION_BUS_CONF_FILE_PRIMARY) < 0
	 && __internal_init(bus_type, (bus_type == SYSTEM_BUS) ? SYSTEM_BUS_CONF_FILE_SECONDARY : SESSION_BUS_CONF_FILE_SECONDARY) < 0)
	  goto err;

     if (dbuspolicy_init_udesc(kc, bus_type, p_udesc) < 0)
	  goto err;

     return p_udesc;

err:
     dbuspolicy1_free(p_udesc);
     if (kc && kc->fd != -1)
	  close(kc->fd);
     free(kc);

     return NULL;
}

DBUSPOLICY1_EXPORT void dbuspolicy1_free(void* configuration)
{
    struct udesc* p_udesc = (struct udesc*)configuration;
    if(p_udesc) {
	close(p_udesc->conn->fd);
        free(p_udesc->conn);
        free(p_udesc);
        p_udesc = NULL;
    }
}

/**
 * dbuspolicy1_can_send
 * @param: <>
 * @return: <>
 *
 * Description.
 **/
DBUSPOLICY1_EXPORT int dbuspolicy1_check_out(void* configuration,
        const char        *destination,
        const char        *sender,
        const char        *path,
        const char        *interface,
        const char        *member,
        int               message_type,
        const char        *error_name,
        int               reply_serial,
        int               requested_reply)
{
    struct udesc* const p_udesc = (struct udesc*)configuration;
    int i, rs, rr, l,  r = 0;
    struct kcreds* p_creds = NULL;
    char gid[25], uid[25];
    char* name = NULL;
    char  empty_names = 1;

    rs = 0;
    rr = 1;

    if (message_type != DBUSPOLICY_MESSAGE_TYPE_SIGNAL || (destination != NULL && *destination != '\0') ) {
        p_creds = calloc(1, sizeof(struct kcreds));
        r = kdbus_get_creds_from_name(p_udesc->conn, p_creds, destination);
        if(r < 0) {
            kcreds_free(p_creds);
            return 0;
        }

        snprintf(uid, 24, "%lu", (unsigned long int)p_creds->uid);
        snprintf(gid, 24, "%lu", (unsigned long int)p_creds->gid);
        if (!p_creds->names[0])
            empty_names = 0;

        for (i=0;p_creds->names[i];i++)
        {
            rs = __internal_can_send(p_udesc->bus_type, p_udesc->user, p_udesc->group, p_udesc->label, p_creds->names[i], path, interface, member, message_type);
            if (rs > 0)
                break;
        }
    }

    if (empty_names)
        rs = __internal_can_send(p_udesc->bus_type, p_udesc->user, p_udesc->group, p_udesc->label, destination, path, interface, member, message_type);

    if (message_type != DBUSPOLICY_MESSAGE_TYPE_SIGNAL) {
        rr = 0;

        if (!sender || !(*sender))
            rr = __internal_can_recv(p_udesc->bus_type, uid, gid, p_creds->label, sender, path, interface, member, message_type);
        else
            FOREACH_STRV(i, l, sender, name) {
                char* source;
                GET_NEXT_STR(i, name, source);
                rr = __internal_can_recv(p_udesc->bus_type, uid, gid, p_creds->label, source, path, interface, member, message_type);
                if (rr > 0)
                    break;
            }
    }

    free(name);
    kcreds_free(p_creds);

    if(rs > 0 && rr > 0) { r = 1; }
    if(rs < 0 || rr < 0) { r = -1; }
    return r;
}
/**
 * dbuspolicy1_can_send
 * @param: <>
 * @return: <>
 *
 * Description.
 **/
DBUSPOLICY1_EXPORT int dbuspolicy1_check_in(void* configuration,
        const char        *destination,
        const char        *sender,
        const char        *sender_label,
        uid_t             sender_uid,
        gid_t             sender_gid,
        const char        *path,
        const char        *interface,
        const char        *member,
        int               message_type,
        const char        *error_name,
        int               reply_serial,
        int               requested_reply)
{
    struct udesc* const p_udesc = (struct udesc*)configuration;
    int i, rs, rr, l, r = 0;
    struct kcreds* p_creds = NULL;
    char gid[25], uid[25];
    char* name = NULL;

    rs = 0;
    rr = 1;

    snprintf(uid, 24, "%lu", (unsigned long int)sender_uid);
    snprintf(gid, 24, "%lu", (unsigned long int)sender_gid);

    if (!destination || !(*destination))
         rs = __internal_can_send(p_udesc->bus_type, uid, gid, sender_label, destination, path, interface, member, message_type);
    else
        FOREACH_STRV(i, l, destination, name) {
            char* dest;
            GET_NEXT_STR(i, name, dest);

            rs = __internal_can_send(p_udesc->bus_type, uid, gid, sender_label, dest, path, interface, member, message_type);
            if (rs > 0)
                break;
        }
    free(name);
    name = NULL;

    if(message_type != DBUSPOLICY_MESSAGE_TYPE_SIGNAL) {
        rr = 0;

        if (!sender || !(*sender))
            rr = __internal_can_recv(p_udesc->bus_type, p_udesc->user, p_udesc->group, p_udesc->label, sender, path, interface, member, message_type);
        else
            FOREACH_STRV(i, l, sender, name) {
                char* source;
                GET_NEXT_STR(i, name, source);
                rr = __internal_can_recv(p_udesc->bus_type, p_udesc->user, p_udesc->group, p_udesc->label, source, path, interface, member, message_type);
                if(rr > 0)
                    break;
            }
        free(name);
    }
    kcreds_free(p_creds);

    if(rs > 0 && rr > 0) { r = 1; }
    if(rs < 0 || rr < 0) { r = -1; }
    return r;
}


/**
 * dbuspolicy1_can_send
 * @param: <>
 * @return: <>
 *
 * Description.
 **/
DBUSPOLICY1_EXPORT int dbuspolicy1_can_own(void* configuration, const char* const service)
{
    struct udesc* const p_udesc = (struct udesc*)configuration;
    return  __internal_can_own(p_udesc->bus_type, p_udesc->user, p_udesc->group, service);
}
