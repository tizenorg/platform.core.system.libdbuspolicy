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
#include "cynara.hpp"
#include "tslog.hpp"

namespace ldp_xml_parser
{
	class NaivePolicyChecker {
	private:
		NaivePolicyDb m_bus_db[2];
		DbAdapter* m_adapter;
		NaivePolicyDb& getPolicyDb(bool type);

		Decision checkPolicySR(const NaivePolicyDb::PolicySR& policy,
							 const MatchItemSR& item,
							 const char*& privilege);

		Decision checkPolicyOwn(const NaivePolicyDb::PolicyOwn& policy,
							 const ItemOwn& item,
							 const char*& privilege);


		bool parseDecision(Decision decision,
						   uid_t uid,
						   const char* label,
						   const char* privilege);

		bool checkItemSR(bool bus_type,
					   uid_t uid,
					   gid_t gid,
					   const char* label,
					   const MatchItemSR& item,
					   const ItemType type);

		bool checkItemOwn(bool bus_type,
					   uid_t uid,
					   gid_t gid,
					   const char* label,
					   const ItemOwn& item,
					   const ItemType type);
	public:
		~NaivePolicyChecker();
		DbAdapter& generateAdapter();
		bool check(bool bus_type,
				   uid_t uid,
				   gid_t gid,
				   const char* const label,
				   const char* const name);
		bool check(bool bus_type,
				   uid_t uid,
				   gid_t gid,
				   const char* const label,
				   MatchItemSR& matcher,
				   ItemType type);
	};


static	void __log_item(const char* item)
{
	std::cout << "checkpolicy for ownership=" << item <<std::endl;
}

static	void __log_item(const MatchItemSR& item)
{
	char tmp[MAX_LOG_LINE];
	const char* i_str = item.toString(tmp);
	std::cout << "checkpolicy for: " << i_str <<std::endl;
}

}
#endif
