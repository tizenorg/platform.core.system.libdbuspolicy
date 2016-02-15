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
#include <stdint.h>
#include <unistd.h>
#include <errno.h>

#include <dbuspolicy1/libdbuspolicy1.h>

#define DBUSPOLICY1_EXPORT __attribute__ ((visibility("default")))

DBUSPOLICY1_EXPORT void* dbuspolicy1_init(unsigned int bus_type)
{
    static const unsigned long opaque_blob = 0xfeeddead;

    return &opaque_blob;
}

DBUSPOLICY1_EXPORT void dbuspolicy1_free(void* configuration)
{
	(void)configuration;
}

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
    return 1;
}

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
    return 1;
}

DBUSPOLICY1_EXPORT int dbuspolicy1_can_own(void* configuration, const char* const service)
{
    return 1;
}
