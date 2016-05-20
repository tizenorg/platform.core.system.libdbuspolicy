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

#ifndef _LIBDBUSPOLICY1_INTERNAL_H_
#define _LIBDBUSPOLICY1_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#define KDBUS_CONN_MAX_NAMES 256

int __internal_init(bool bus_type, const char* const config_name);
void __internal_init_once(void);
extern pthread_mutex_t g_mutex;
void __internal_init_flush_logs(void);
void __internal_enter(void);
void __internal_exit(void);

int __internal_can_send(bool bus_type,
						const uid_t  user,
						const gid_t  group,
						const char* const label,
						const char* const destination,
						const char* const path,
						const char* const interface,
						const char* const member,
						int type);

int __internal_can_send_multi_dest(bool bus_type,
								   const uid_t user,
								   const gid_t group,
								   const char* const label,
								   const char** const destination,
								   const char* const path,
								   const char* const interface,
								   const char* const member,
								   int type);

int __internal_can_recv(bool bus_type,
						uid_t user,
						gid_t group,
						const char* const label,
						const char* const sender,
						const char* const path,
						const char* const interface,
						const char* const member,
						int type);

int __internal_can_own(bool bus_type,
					   uid_t user,
					   gid_t group,
					   const char* const label,
					   const char* const service);
#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
