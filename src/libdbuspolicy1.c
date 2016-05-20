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
#include <limits.h>
#include <pthread.h>

#include <dbuspolicy1/libdbuspolicy1.h>
#include "libdbuspolicy1-private.h"
#include "internal/internal.h"

#define KDBUS_PATH_PREFIX "/sys/fs/kdbus/"
#define KDBUS_SYSTEM_BUS_PATH "/sys/fs/kdbus/0-system/bus"
#define KDBUS_POOL_SIZE (1024UL * 1024UL)

#define SYSTEM_BUS   0
#define SESSION_BUS  1

#define ALIGN8(l) (((l) + 7) & ~7)
#define ALIGNDN8(l) ((l) & ~7)
#define UID_INVALID ((uid_t) -1)
#define GID_INVALID ((gid_t) -1)

/** A process ID */
typedef unsigned long dbus_pid_t;
/** A user ID */
typedef unsigned long dbus_uid_t;
/** A group ID */
typedef unsigned long dbus_gid_t;

struct kconn {
	int fd;
	uint64_t id;
	char *pool;
} g_conn[2];

struct udesc {
	char user[256];
	dbus_uid_t uid;
	char group[256];
	dbus_gid_t gid;
	char label[256];
} g_udesc;

static int kdbus_open_bus(const char *path)
{
	return open(path, O_RDWR|O_NOCTTY|O_LARGEFILE|O_CLOEXEC);
}

static int kdbus_hello(bool bus_type, uint64_t hello_flags, uint64_t attach_flags_send, uint64_t attach_flags_recv)
{
	struct kdbus_cmd_hello cmd;
	int fd = g_conn[bus_type].fd;

	cmd.size = sizeof(cmd);
	cmd.flags = hello_flags;
	cmd.attach_flags_send = attach_flags_send;
	cmd.attach_flags_recv = attach_flags_recv;
	cmd.pool_size = KDBUS_POOL_SIZE;

	if (ioctl(fd, KDBUS_CMD_HELLO, &cmd) < 0)
		return -errno;

	g_conn[bus_type].id = cmd.id;
	if (MAP_FAILED == (g_conn[bus_type].pool = mmap(NULL, KDBUS_POOL_SIZE, PROT_READ, MAP_SHARED, fd, 0)))
		return -errno;

	return 0;
}

static bool kdbus_is_unique_id(const char* name)
{
	return ':' == name[0];
}

static uint64_t kdbus_unique_id(char const *name)
{
	uint64_t res;
	unsigned i = 2;
	int c;
	while (!(c = name[++i] - '0'));
	res = c;
	while ((c = (int)(name[++i]) - '0') > 0)
		res = res*10 + c;
	return res;
}

static bool dbuspolicy_init_once(void)
{
	struct passwd pwent;
	struct passwd *pwd;
	struct group grent;
	struct group *gg;
	char buf[1024];
	int attr_fd;
	int r;

	attr_fd = open("/proc/self/attr/current", O_RDONLY);
	if (attr_fd < 0)
		return -1;
	r = read(attr_fd, buf, sizeof(buf));

	close(attr_fd);

	if (r < 0 || r >= (long int)sizeof(g_udesc.label)) /* read */
		return true;

	g_udesc.uid = getuid();
	g_udesc.gid = getgid();

	snprintf(g_udesc.label, r + 1 /* additional byte for \0 */, "%s", buf);
	if (getpwuid_r(g_udesc.uid, &pwent, buf, sizeof(buf), &pwd))
		return true;

	if (getgrgid_r(g_udesc.gid, &grent, buf, sizeof(buf), &gg))
		return true;

	if (!pwd || !gg)
		return false;

	snprintf(g_udesc.user, sizeof(g_udesc.user), "%s", pwd->pw_name);
	snprintf(g_udesc.group, sizeof(g_udesc.group), "%s", gg->gr_name);

	__internal_init_once();

	return false;
}

static int bus_path_resolve(const char *bus_path, char *resolved_path, unsigned resolved_path_size, unsigned int *bus_type)
{
	char rp[PATH_MAX];
	char *p;
	const char user_suffix[] = "-user/bus";
	int suffix_pos;

	p = realpath(bus_path, rp);
	if (!p)
		return -1;

	if (0 != strncmp(p, KDBUS_PATH_PREFIX, strlen(KDBUS_PATH_PREFIX)))
		return -1;

	if (0 == strcmp(p, KDBUS_SYSTEM_BUS_PATH)) {
		*bus_type = SYSTEM_BUS;
	} else {
		suffix_pos = strlen(p) - strlen(user_suffix);
		if (suffix_pos < 0)
			return -1;

		if (0 != strcmp(p + suffix_pos, user_suffix))
			return -1;

		*bus_type = SESSION_BUS;
	}

	snprintf(resolved_path, resolved_path_size, "%s", p);
	return 0;
}

static bool init_once_done = false;

DBUSPOLICY1_EXPORT void* dbuspolicy1_init(const char *bus_path)
{
	unsigned int bus_type = -1;
	char resolved_path[PATH_MAX] = { 0 };
	int rp, rs;
	bool rb;

	_Static_assert(SYSTEM_BUS == 0, "SYSTEM_BUS not 0");
	_Static_assert(SESSION_BUS == 1, "SESSION_BUS not 0");

	if (bus_path_resolve(bus_path, resolved_path, sizeof(resolved_path), &bus_type) < 0)
		return NULL;

	if (bus_type)
		bus_type = SESSION_BUS;

	rb = false;
	pthread_mutex_lock(&g_mutex);
	if (!init_once_done) {
		init_once_done = true;
		rb = dbuspolicy_init_once();
	}
	if (rb)
		goto err_close;

	if ((g_conn[bus_type].fd = kdbus_open_bus(resolved_path)) < 0)
		goto err;

	if (kdbus_hello(bus_type, 0, _KDBUS_ATTACH_ALL, 0) < 0)
		goto err_close;

	rp = __internal_init(bus_type, (bus_type == SYSTEM_BUS) ? SYSTEM_BUS_CONF_FILE_PRIMARY : SESSION_BUS_CONF_FILE_PRIMARY);
	rs = __internal_init(bus_type, (bus_type == SYSTEM_BUS) ? SYSTEM_BUS_CONF_FILE_SECONDARY : SESSION_BUS_CONF_FILE_SECONDARY);
	__internal_init_flush_logs();

	if ((rp & rs) < 0) /* when both negative */
		goto err_close;

	pthread_mutex_unlock(&g_mutex);
	return &g_conn[bus_type];

err_close:
	close(g_conn[bus_type].fd);
err:
	pthread_mutex_unlock(&g_mutex);
	return NULL;
}

DBUSPOLICY1_EXPORT void dbuspolicy1_free(void* configuration)
{
    if (configuration)
		close(((typeof(&g_conn[0]))configuration)->fd);
}

#ifdef LIBDBUSPOLICY_TESTS_API
DBUSPOLICY1_EXPORT void __dbuspolicy1_change_creds(void* configuration, uid_t uid, gid_t gid,const char* label) {
	g_udesc.uid = uid;
	g_udesc.gid = gid;
	if (label)
		strcpy (g_udesc.label, label);
}
#endif

static bool configuration_bus_type(struct kconn const *configuration) { return configuration != g_conn; }

/**
 * dbuspolicy1_can_send
 * @param: <>
 * @return: <>
 *
 * Description.
 **/
DBUSPOLICY1_EXPORT int dbuspolicy1_check_out(void* configuration,
											 const char *destination,
											 const char *sender,
											 const char *path,
											 const char *interface,
											 const char *member,
											 int         message_type,
											 const char *error_name,
											 int         reply_serial,
											 int         requested_reply)
{
	char const *label = NULL;
	const char* k_names[KDBUS_CONN_MAX_NAMES+1];
	int k_i = 0;
	int r;
	uid_t uid_n = UID_INVALID;
	gid_t gid_n = GID_INVALID;
	bool free_offset = false;
	bool empty_names = true;
	bool bus_type = configuration_bus_type(configuration);
	union {
		struct kdbus_cmd_info cmd_info;
		struct kdbus_cmd_free cmd_free;
		uint8_t _buffer_[sizeof(struct kdbus_cmd_info) + offsetof(struct kdbus_item, data) + ALIGN8(MAX_DBUS_NAME_LEN+1)];
	} cmd;

	__internal_enter();

    if (DBUSPOLICY_MESSAGE_TYPE_SIGNAL != message_type || (destination && *destination)) {
		struct kdbus_info *conn_info;
		struct kdbus_item *item;
		uintptr_t items_end;

		cmd.cmd_info.flags = 0;
		cmd.cmd_info.attach_flags = KDBUS_ATTACH_CREDS | KDBUS_ATTACH_NAMES | (DBUSPOLICY_MESSAGE_TYPE_SIGNAL != message_type ? KDBUS_ATTACH_SECLABEL : 0);

		if (kdbus_is_unique_id(destination)) {
			cmd.cmd_info.size = sizeof(cmd.cmd_info);
			cmd.cmd_info.id = kdbus_unique_id(destination);
		} else {
			int l = strlen(destination);
			cmd.cmd_info.size = sizeof(struct kdbus_cmd_info) + offsetof(struct kdbus_item, data) + ALIGN8(l+1);
			cmd.cmd_info.id = 0;
			cmd.cmd_info.items->size =  offsetof(struct kdbus_item, data) + l+1;
			cmd.cmd_info.items->type = KDBUS_ITEM_NAME;
			*(uint64_t*)ALIGNDN8((uintptr_t)cmd.cmd_info.items->str + l) = 0; /* trailing zero + padding */
			memcpy(cmd.cmd_info.items->str, destination, l);
		}

		r = ioctl(g_conn[bus_type].fd, KDBUS_CMD_CONN_INFO, &cmd.cmd_info);
		if (r < 0) {
			r = -errno;
			goto end;
		}

		cmd.cmd_free.size = sizeof(cmd.cmd_free);
		/* flags already 0 */
		_Static_assert(sizeof(cmd.cmd_info.flags) == sizeof(cmd.cmd_free.flags), "cmd_info/cmd_free: flag sizeof differs");
		_Static_assert(offsetof(typeof(cmd.cmd_info), flags) == offsetof(typeof(cmd.cmd_free), flags), "cmd_info/cmd_free: flag offsetof differs");
		cmd.cmd_free.offset = cmd.cmd_info.offset;

		free_offset = true;

		conn_info = (struct kdbus_info *) ((uint8_t *) g_conn[bus_type].pool + cmd.cmd_info.offset);
		items_end = (uintptr_t)conn_info + (unsigned)conn_info->size;

		_Static_assert((unsigned)KDBUS_ITEM_CREDS == KDBUS_ITEM_CREDS, "KDBUS_ITEM_CREDS not preserved when cast to unsigned");
		_Static_assert((unsigned)KDBUS_ITEM_SECLABEL == KDBUS_ITEM_SECLABEL, "KDBUS_ITEM_SECLABEL not preserved when cast to unsigned");
		_Static_assert((unsigned)KDBUS_ITEM_OWNED_NAME == KDBUS_ITEM_OWNED_NAME, "KDBUS_ITEM_OWNED_NAME not preserved when cast to unsigned");

		for (item = conn_info->items; (uintptr_t)item < items_end; item = (typeof(item))ALIGN8((uintptr_t)item + (unsigned)item->size))
			switch ((unsigned)item->type)
			{
			case KDBUS_ITEM_CREDS:
				uid_n = item->creds.euid;
				gid_n = item->creds.egid;
				break;
			case KDBUS_ITEM_SECLABEL:
				label = item->str;
				break;
			case KDBUS_ITEM_OWNED_NAME:
				empty_names = false;
				if (r <= 0)
					k_names[k_i++] = item->name.name;
				break;
			}
	}

	if (empty_names)
		r = __internal_can_send(bus_type, g_udesc.uid, g_udesc.gid, g_udesc.label, destination, path, interface, member, message_type);
	else {
		k_names[k_i++] = NULL;
        r = __internal_can_send_multi_dest(bus_type, g_udesc.uid, g_udesc.gid, g_udesc.label, k_names, path, interface, member, message_type);
	}
	if (r <= 0)
		goto end;

	if (message_type != DBUSPOLICY_MESSAGE_TYPE_SIGNAL)
		r = __internal_can_recv(bus_type, uid_n, gid_n, label, sender, path, interface, member, message_type);

end:
	if (free_offset)
		ioctl(g_conn[bus_type].fd, KDBUS_CMD_FREE, &cmd.cmd_free);

	__internal_exit();
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
											const char *destination,
											const char *sender,
											const char *sender_label,
											uid_t       sender_uid,
											gid_t       sender_gid,
											const char *path,
											const char *interface,
											const char *member,
											int         message_type,
											const char *error_name,
											int         reply_serial,
											int         requested_reply)
{
	int r;
	bool bus_type = configuration_bus_type(configuration);

	__internal_enter();

	r = __internal_can_send(bus_type, sender_uid, sender_gid, sender_label, destination, path, interface, member, message_type);
	if (r <= 0)
		goto end;

	if (message_type != DBUSPOLICY_MESSAGE_TYPE_SIGNAL) {
		r = __internal_can_recv(bus_type, g_udesc.uid, g_udesc.gid, g_udesc.label, sender, path, interface, member, message_type);
		if (r <= 0)
			goto end;
	}
end:
	__internal_exit();
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
	int r;
	bool bus_type = configuration_bus_type(configuration);
	__internal_enter();
	r = __internal_can_own(bus_type, g_udesc.uid, g_udesc.gid, g_udesc.label, service);
	__internal_exit();
	return r;
}
