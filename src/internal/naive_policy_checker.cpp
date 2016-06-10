#include "naive_policy_checker.hpp"
using namespace ldp_xml_parser;



DbAdapter& NaivePolicyChecker::generateAdapter() {
	if (!m_adapter)
		m_adapter = new DbAdapter (m_bus_db[0], m_bus_db[1]);

	return *m_adapter;
}



NaivePolicyDb& NaivePolicyChecker::getPolicyDb(bool type) {
	return m_bus_db[type];
}

bool NaivePolicyChecker::parseDecision(Decision decision,
									   uid_t uid,
									   const char* label,
									   const char* privilege) {

	char uid_str[17];
	if (tslog::verbose()) {
		std::cout<<"----Decision made\n";
	}
	switch (decision)
	{
	case Decision::ALLOW:
		return true;
	case Decision::ANY:
	case Decision::DENY:
		return false;
	case Decision::CHECK:
		std::snprintf(uid_str, sizeof(uid_str) - 1, "%lu", (unsigned long)uid);
		return ldp_cynara::Cynara::check(label, privilege, uid_str) == ldp_cynara::CynaraResult::ALLOW;
	}

	return false;
}

NaivePolicyChecker::~NaivePolicyChecker() {
	delete m_adapter;
}



bool NaivePolicyChecker::check(bool bus_type,
							   uid_t uid,
							   gid_t gid,
							   const char* const label,
							   const char* const name) {
	return this->checkItemOwn(bus_type, uid, gid, label, name, ItemType::OWN);
}

bool NaivePolicyChecker::check(bool bus_type,
							   uid_t uid,
							   gid_t gid,
							   const char* const label,
							   MatchItemSR& matcher,
							   ItemType type) {
	return this->checkItemSR(bus_type, uid, gid, label, matcher, type);
}

Decision NaivePolicyChecker::checkPolicySR(const NaivePolicyDb::PolicySR& policy,
										 const MatchItemSR& item,
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

Decision NaivePolicyChecker::checkPolicyOwn(const NaivePolicyDb::PolicyOwn& policy, const ItemOwn& item, const char*& privilege) {

	const char *name = item.getName();
	const struct TreeNode *node = policy.getTreeRoot();
	int childIndex = 0;
	assert(node);
	Decision ret = Decision::ANY;


	while((name != NULL)&& (*name != '\0')){


		childIndex = char_map[*name];

		/*Current node is prefix, remeber decision*/
		if(node->__is_prefix){
			ret = node->__decisionItem.getDecision();;
			privilege = node->__decisionItem.getPrivilege();
		}

		/*Node for this letter dont exist*/
		if(node->children[childIndex] == NULL){
			goto out;
		}
		else{/*if it exists check for next letter in its child*/
			node = node->children[childIndex];
		}

		name++;

	}
out:
	if(ret == Decision::ANY){
		privilege = node->__decisionItem.getPrivilege();
		return node->__decisionItem.getDecision();
	}
	else

		return ret;

}




bool NaivePolicyChecker::checkItemOwn(bool bus_type, uid_t uid, gid_t gid, const char* label, const ItemOwn& item, const ItemType type) {

	NaivePolicyDb& policy_db = getPolicyDb(bus_type);
	Decision ret = Decision::ANY;
	const char* privilege;
	const NaivePolicyDb::PolicyOwn* curr_policy = NULL;
	if (ret == Decision::ANY) {

		if (policy_db.getPolicy(type, PolicyType::CONTEXT, PolicyTypeValue(ContextType::MANDATORY), curr_policy))

			ret = checkPolicyOwn(*curr_policy, item, privilege);
	}

	if (ret == Decision::ANY) {

		if (policy_db.getPolicy(type, PolicyType::USER, PolicyTypeValue(uid), curr_policy))

			ret = checkPolicyOwn(*curr_policy, item, privilege);
	}

	if (ret == Decision::ANY) {

		if (policy_db.getPolicy(type, PolicyType::GROUP, PolicyTypeValue(gid), curr_policy))

			ret = checkPolicyOwn(*curr_policy, item, privilege);
	}

	if (ret == Decision::ANY) {

		if (policy_db.getPolicy(type, PolicyType::CONTEXT, PolicyTypeValue(ContextType::DEFAULT), curr_policy))

			ret = checkPolicyOwn(*curr_policy, item, privilege);
	}
	if (ret != Decision::ANY){

		return parseDecision(ret, uid, label, privilege);
	}
	else{
		return false;
	}
}


bool NaivePolicyChecker::checkItemSR(bool bus_type, uid_t uid, gid_t gid, const char* label, const MatchItemSR& item, const ItemType type) {
	NaivePolicyDb& policy_db = getPolicyDb(bus_type);
	Decision ret = Decision::ANY;
	const char* privilege;
	const NaivePolicyDb::PolicySR* curr_policy = NULL;

	if (ret == Decision::ANY) {
		if (policy_db.getPolicy(type, PolicyType::CONTEXT, PolicyTypeValue(ContextType::MANDATORY), curr_policy))
			ret = checkPolicySR(*curr_policy, item, privilege);
	}

	if (ret == Decision::ANY) {
		if (policy_db.getPolicy(type, PolicyType::USER, PolicyTypeValue(uid), curr_policy))
			ret = checkPolicySR(*curr_policy, item, privilege);
	}

	if (ret == Decision::ANY) {
		if (policy_db.getPolicy(type, PolicyType::GROUP, PolicyTypeValue(gid), curr_policy))
			ret = checkPolicySR(*curr_policy, item, privilege);
	}

	if (ret == Decision::ANY) {
		if (policy_db.getPolicy(type, PolicyType::CONTEXT, PolicyTypeValue(ContextType::DEFAULT), curr_policy))
			ret = checkPolicySR(*curr_policy, item, privilege);
	}

	if (ret != Decision::ANY)
		return parseDecision(ret, uid, label, privilege);
	else
		return false;
}
