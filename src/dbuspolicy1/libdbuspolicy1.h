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

#ifndef _LIBDBUSPOLICY1_H_
#define _LIBDBUSPOLICY1_H_

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SYSTEM_BUS_CONF_FILE_PRIMARY  "/usr/share/dbus-1/system.conf"
#define SESSION_BUS_CONF_FILE_PRIMARY "/usr/share/dbus-1/session.conf"

#define SYSTEM_BUS_CONF_FILE_SECONDARY  "/etc/dbus-1/system-local.conf"
#define SESSION_BUS_CONF_FILE_SECONDARY "/etc/dbus-1/session-local.conf"

#define SYSTEM_BUS   0
#define SESSION_BUS  1

/** used when check policy for message prepared to send */
#define DBUSPOLICY_DIRECTION_SENDING 0

 /** used when check policy for message read from bus */
#define DBUSPOLICY_DIRECTION_RECEIVING 1

#define DBUSPOLICY_MESSAGE_TYPE_METHOD_CALL     1
#define DBUSPOLICY_MESSAGE_TYPE_METHOD_RETURN   2
#define DBUSPOLICY_MESSAGE_TYPE_ERROR           3
#define DBUSPOLICY_MESSAGE_TYPE_SIGNAL          4

struct udesc;

/*!
  Initialize libdbuspolicy configuration context
  \param bus_path path to the kdbus bus (system or session)

  \note This function should be called only on well known kdbus buses
  - the system bus (/sys/fs/kdbus/0-system/bus) and session bus
  (/sys/fs/kdbus/getuid()-user/bus).  If any other bus is specified
  function will not succeed.

  \return On success pointer to configuration context is returned.  On
  error NULL is returned.
 */
void* dbuspolicy1_init(const char *bus_path);

/*!
  Free libdbuspolicy configuration context
  \param configuration pointer with policy configuration acquired using dbuspolicy1_init
 */
void dbuspolicy1_free(void* configuration);

/*!
  Check policy for outgoing message
  \param configuration pointer with policy configuration
  \param destination list of message destinations
  \param sender list of message sender names
  \param path path
  \param interface interface name
  \param member member name
  \param message_type message type
  \param error_name (future implementation)
  \param reply_serial (future implementation)
  \param requested_reply (future implementation)
 */
int dbuspolicy1_check_out(void* configuration,
        const char        *destination,
        const char        *sender,
        const char        *path,
        const char        *interface,
        const char        *member,
        int               message_type,
        const char        *error_name,
        int               reply_serial,
        int               requested_reply);

/*!
  Check policy for incoming message
  \param configuration pointer with policy configuration
  \param destination list of message destinations
  \param sender list of message sender names
  \param sender_label sender label (should be manually extracted from incomming message)
  \param sender_uid sender uid (should be manually extracted from incomming message)
  \param sender_gid sender gid (should be manually extracted from incomming message)
  \param path path
  \param interface interface name
  \param member member name
  \param message_type message type
  \param error_name (future implementation)
  \param reply_serial (future implementation)
  \param requested_reply (future implementation)
 */
int dbuspolicy1_check_in(void* configuration,
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
        int               requested_reply);

/*!
  Check policy for service ownership
  \param configuration pointer with policy configuration
  \param service service name
 */
int dbuspolicy1_can_own(void* configuration, const char* const service);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
