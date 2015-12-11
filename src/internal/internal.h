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

int __internal_init(unsigned int bus_type, const char* const config_name);

int __internal_can_send(unsigned int bus_type,
                            const char* const user,
                            const char* const group,
                            const char* const label,
                            const char* const destination,
                            const char* const path,
                            const char* const interface,
                            const char* const member,
                            int type);

int __internal_can_recv(unsigned int bus_type,
                            const char* const user,
                            const char* const group,
                            const char* const label,
                            const char* const sender,
                            const char* const path,
                            const char* const interface,
                            const char* const member,
                            int type);

int __internal_can_own(unsigned int bus_type,
                            const char* const user,
                            const char* const group,
                            const char* const service);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
