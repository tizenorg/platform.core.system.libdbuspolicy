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
#include "policy.hpp"
#include "naive_policy_checker.hpp"
#include "internal.h"

#include "../libdbuspolicy1-private.h"

static ldp_xml_parser::NaivePolicyChecker policy_checker;

static const char* get_str(const char* const szstr) {
    return (szstr != NULL) ? szstr : "";
}

int __internal_init(bool bus_type, const char* const config_name)
{
    ldp_xml_parser::XmlParser p;
	p.registerAdapter(policy_checker.generateAdapter());
    auto err = p.parsePolicy(bus_type, get_str(config_name));
    return err.get();
}

pthread_mutex_t g_mutex = PTHREAD_MUTEX_INITIALIZER;

void __internal_init_once()
{
	tslog::init();
}

void __internal_init_flush_logs()
{
	if (tslog::enabled()) {
		pthread_mutex_lock(&g_mutex);
		std::cout << std::flush;
		pthread_mutex_unlock(&g_mutex);
	}
}

void __internal_enter()
{
	if (tslog::enabled())
		pthread_mutex_lock(&g_mutex);
}
void __internal_exit()
{
	if (tslog::enabled())
		pthread_mutex_unlock(&g_mutex);
}

int __internal_can_send(bool bus_type,
						const uid_t user,
						const gid_t group,
						const char* const label,
						const char* const destination,
						const char* const path,
						const char* const interface,
						const char* const member,
						int type)
{
	ldp_xml_parser::MatchItemSR matcher (interface, member, path, static_cast<ldp_xml_parser::MessageType>(type), ldp_xml_parser::MessageDirection::SEND);
	if (!matcher.addNames(destination)) {
		if (tslog::verbose())
			std::cout << "Destination too long: "<<destination<<std::endl;
		return false;
	}
	return policy_checker.check(bus_type, user, group, label, matcher, ldp_xml_parser::ItemType::SEND);
}

int __internal_can_send_multi_dest(bool bus_type,
								   const uid_t user,
								   const gid_t group,
								   const char* const label,
								   const char** const destination,
								   const char* const path,
								   const char* const interface,
								   const char* const member,
								   int type)
{
	int i = 0;
	ldp_xml_parser::MatchItemSR matcher (interface, member, path, static_cast<ldp_xml_parser::MessageType>(type), ldp_xml_parser::MessageDirection::SEND);
	if (destination)
		while (destination[i++]) {
			matcher.addName(destination[i]);
		}
	return policy_checker.check(bus_type, user, group, label, matcher, ldp_xml_parser::ItemType::SEND);
}

int __internal_can_recv(bool bus_type,
						const uid_t user,
						const gid_t group,
						const char* const label,
						const char* const sender,
						const char* const path,
						const char* const interface,
						const char* const member,
						int type)
{
	ldp_xml_parser::MatchItemSR matcher (interface, member, path, static_cast<ldp_xml_parser::MessageType>(type), ldp_xml_parser::MessageDirection::RECEIVE);
	if (!matcher.addNames(sender)) {
		if (tslog::verbose())
			std::cout << "Sender too long: "<<sender<<std::endl;
		return false;
	}
	return policy_checker.check(bus_type, user, group, label, matcher, ldp_xml_parser::ItemType::RECEIVE);
}

int __internal_can_own(bool bus_type,
					   const uid_t user,
					   const gid_t group,
					   const char* const label,
					   const char* const service)
{
	return policy_checker.check(bus_type, user, group, label, service);
}
