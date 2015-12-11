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

#include <iostream>
#include <string>
#include <dbuspolicy1/libdbuspolicy1.h>
#include "xml_parser.hpp"

#ifdef __cplusplus
extern "C" {
#endif

static const char* get_bus(int bus_type) {
    return (bus_type == SYSTEM_BUS) ? "SYSTEM" : "SESSION";
}

static const char* get_str(const char* const szstr) {
    return (szstr != NULL) ? szstr : "";
}

static const char* get_message_type(int type) {
    const char* sztype;
    switch(type) {
        case DBUSPOLICY_MESSAGE_TYPE_METHOD_CALL:   sztype = "method_call";     break;
        case DBUSPOLICY_MESSAGE_TYPE_METHOD_RETURN: sztype = "method_return";   break;
        case DBUSPOLICY_MESSAGE_TYPE_ERROR:         sztype = "error";           break;
        case DBUSPOLICY_MESSAGE_TYPE_SIGNAL:        sztype = "signal";          break;
        default:                                    sztype = "";                break;
    }
    return sztype;
}

int __internal_init(unsigned int bus_type, const char* const config_name)
{
    _ldp_xml_parser::XmlAsyncParser p;
    auto err = p.parse_policy(get_bus(bus_type), get_str(config_name), std::chrono::milliseconds(10000));
    return err.get();
}

int __internal_can_send(unsigned int bus_type,
                            const char* const user,
                            const char* const group,
                            const char* const label,
                            const char* const destination,
                            const char* const path,
                            const char* const interface,
                            const char* const member,
                            int type)
{
    _ldp_xml_parser::XmlAsyncParser p;
    auto err = p.can_send(get_bus(bus_type), get_str(user), get_str(group), get_str(label), get_str(destination), get_str(path), get_str(interface), get_str(member), get_message_type(type));
    return err.get();
}

int __internal_can_recv(unsigned int bus_type,
                            const char* const user,
                            const char* const group,
                            const char* const label,
                            const char* const sender,
                            const char* const path,
                            const char* const interface,
                            const char* const member,
                            int type)
{
    _ldp_xml_parser::XmlAsyncParser p;
    auto err = p.can_recv(get_bus(bus_type), get_str(user), get_str(group), get_str(label), get_str(sender), get_str(path), get_str(interface), get_str(member), get_message_type(type));
    return err.get();
}

int __internal_can_own(unsigned int bus_type,
                            const char* const user,
                            const char* const group,
                            const char* const service)
{
    _ldp_xml_parser::XmlAsyncParser p;
    auto err = p.can_own(get_bus(bus_type), get_str(user), get_str(group), get_str(service));
    return err.get();
}

#ifdef __cplusplus
} /* extern "C" */
#endif
