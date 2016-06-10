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
		template <typename T, class C>
		Decision checkPolicy(const NaivePolicyDb::Policy<C>& policy,
							 const T& item,
							 const char*& privilege);
		bool parseDecision(Decision decision,
						   uid_t uid,
						   const char* label,
						   const char* privilege);
		template <typename T, class C>
		bool checkItem(bool bus_type,
					   uid_t uid,
					   gid_t gid,
					   const char* label,
					   const T& item,
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

template <typename T, class C>
Decision NaivePolicyChecker::checkPolicy(const NaivePolicyDb::Policy<C>& policy,
										 const T& item,
										 const char*& privilege)
{
	if (tslog::verbose()) {
		__log_item(item);
	}

	for (auto i : policy) {
		if (tslog::verbose()) {
			char tmp[MAX_LOG_LINE];
			const char* i_str = i->getDecision().toString(tmp);
			std::cout << "-readed: " << i_str;
			i_str = i->toString(tmp);
			std::cout << " " << i_str <<std::endl;
		}
		if (i->match(item)) {
			if (tslog::verbose()) {
				char tmp[MAX_LOG_LINE];
				const char* i_str = i->getDecision().toString(tmp);
				std::cout << "-matched: " << i_str;
				const char* i_str2 = i->toString(tmp);
				std::cout << " " << i_str2 <<std::endl;
			}
			privilege = i->getDecision().getPrivilege();
			return i->getDecision().getDecision();
		}
	}

	return Decision::ANY;
}

template <typename T, class C>
bool NaivePolicyChecker::checkItem(bool bus_type, uid_t uid, gid_t gid, const char* label, const T& item, const ItemType type) {
	NaivePolicyDb& policy_db = getPolicyDb(bus_type);
	Decision ret = Decision::ANY;
	const char* privilege;
	const NaivePolicyDb::Policy<C>* curr_policy = NULL;

	if (ret == Decision::ANY) {
		if (policy_db.getPolicy(type, PolicyType::CONTEXT, PolicyTypeValue(ContextType::MANDATORY), curr_policy))
			ret = checkPolicy<T, C>(*curr_policy, item, privilege);
	}

	if (ret == Decision::ANY) {
		if (policy_db.getPolicy(type, PolicyType::USER, PolicyTypeValue(uid), curr_policy))
			ret = checkPolicy<T, C>(*curr_policy, item, privilege);
	}

	if (ret == Decision::ANY) {
		if (policy_db.getPolicy(type, PolicyType::GROUP, PolicyTypeValue(gid), curr_policy))
			ret = checkPolicy<T, C>(*curr_policy, item, privilege);
	}

	if (ret == Decision::ANY) {
		if (policy_db.getPolicy(type, PolicyType::CONTEXT, PolicyTypeValue(ContextType::DEFAULT), curr_policy))
			ret = checkPolicy<T, C>(*curr_policy, item, privilege);
	}

	if (ret != Decision::ANY)
		return parseDecision(ret, uid, label, privilege);
	else
		return false;
}
}
#endif
