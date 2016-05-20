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
#ifndef _NAIVE_DECISIONER_H
#define _NAIVE_DECISIONER_H

#include "policy.hpp"
#include "naive_policy_db.hpp"

namespace  _ldp_xml_parser
{
	class NaivePolicyChecker : public IPolicyChecker {
	private:
		NaivePolicyDb m_system_db;
		NaivePolicyDb m_session_db;
		DbAdapter* m_adapter;
		NaivePolicyDb& getPolicyDb(bool type);
		Decision checkPolicy(const NaivePolicyDb::Policy& policy,
							 const Item& item,
							 const char*& privilege);
		bool parseDecision(Decision decision,
						   uid_t uid,
						   const char* label,
						   const char* privilege);
		bool checkItem(bool bus_type,
					   uid_t uid,
					   gid_t gid,
					   const char* label,
					   const Item& item);
	public:
		~NaivePolicyChecker();
		virtual DbAdapter& generateAdapter();
		virtual bool check(bool bus_type,
						   uid_t uid,
						   gid_t gid,
						   const char* const label,
						   const char* const name);
		virtual bool check(bool bus_type,
						   uid_t uid,
						   gid_t gid,
						   const char* const label,
						   const char** const names,
						   const char* const interface,
						   const char* const member,
						   const char* const path,
						   MessageType message_type,
						   MessageDirection message_dir);
	};
}
#endif
