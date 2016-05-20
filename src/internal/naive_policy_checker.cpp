#include "naive_policy_checker.hpp"
#include "cynara.hpp"
#include "tslog.hpp"
using namespace ldp_xml_parser;

DbAdapter& NaivePolicyChecker::generateAdapter() {
	if (!m_adapter)
		m_adapter = new DbAdapter (m_system_db, m_session_db);

	return *m_adapter;
}

Decision NaivePolicyChecker::checkPolicy(const NaivePolicyDb::Policy& policy,
										 const Item& item,
										 const char*& privilege)
{
	if (tslog::verbose()) {
		char tmp[1024];
		const char* i_str = item.toString(tmp);
		std::cout << "checkpolicy for: " << i_str <<std::endl;
	}
	for(auto i : policy) {
		if (tslog::verbose()) {
			char tmp[1024];
			const char* i_str = i->toString(tmp);
			std::cout << "-readed: " << i_str <<std::endl;
		}
		if (i->match(&item)) {
			if (tslog::verbose()) {
				char tmp[1024];
				const char* i_str = i->toString(tmp);
				std::cout << "-matched: " << i_str <<std::endl;
			}
			privilege = i->getPrivilege();
			return i->getDecision();
		}
	}

	return NO_DECISION;
}

NaivePolicyDb& NaivePolicyChecker::getPolicyDb(bool type) {
	if (type)
		return m_session_db;
	else
		return m_system_db;
}

bool NaivePolicyChecker::parseDecision(Decision decision,
									   uid_t uid,
									   const char* label,
									   const char* privilege) {

	char uid_str[256];
	if (tslog::verbose()) {
		std::cout<<"----Decision made\n";
	}
	std::sprintf(uid_str, "%lu", (unsigned long)uid);
	switch (decision)
	{
	case DECISION_ALLOW:
		return true;
	case NO_DECISION:
	case DECISION_DENY:
		return false;
	case DECISION_CYNARA_CHECK:
		return _ldp_cynara::Cynara::check(label, privilege, uid_str);
	}

	return false;
}

NaivePolicyChecker::~NaivePolicyChecker() {
	delete m_adapter;
}

bool NaivePolicyChecker::checkItem(bool bus_type, uid_t uid, gid_t gid, const char* label, const Item& item) {
	NaivePolicyDb& policy_db = getPolicyDb(bus_type);
	ItemType type = item.getType();
	Decision ret = NO_DECISION;
	const char* privilege;
	const NaivePolicyDb::Policy* curr_policy = NULL;

	if (ret == NO_DECISION) {
		curr_policy = policy_db.getPolicy(type, POLICY_CONTEXT, PolicyTypeValue(CONTEXT_MANDATORY));
		if (curr_policy)
			ret = checkPolicy(*curr_policy, item, privilege);
	}

	if (ret == NO_DECISION) {
		curr_policy = policy_db.getPolicy(type, POLICY_USER, PolicyTypeValue(uid));
		if (ret == NO_DECISION && curr_policy)
			ret = checkPolicy(*curr_policy, item, privilege);
	}

	if (ret == NO_DECISION) {
		curr_policy = policy_db.getPolicy(type, POLICY_GROUP, PolicyTypeValue(gid));
		if (ret == NO_DECISION && curr_policy)
			ret = checkPolicy(*curr_policy, item, privilege);
	}

	if (ret == NO_DECISION) {
		curr_policy = policy_db.getPolicy(type, POLICY_CONTEXT, PolicyTypeValue(CONTEXT_DEFAULT));
		if (ret == NO_DECISION && curr_policy)
			ret = checkPolicy(*curr_policy, item, privilege);
	}

	if (ret != NO_DECISION)
		return parseDecision(ret, uid, label, privilege);
	else
		return false;
}

bool NaivePolicyChecker::check(bool bus_type,
							   uid_t uid,
							   gid_t gid,
							   const char* const label,
							   const char* const name) {
	try {
		ItemOwn item = ItemOwn(name);
		return checkItem(bus_type, uid, gid, label, item);
	} catch (std::runtime_error& err) {
		if (tslog::enabled())
			std::cout << err.what() << std::endl;
	}
	return false;
}

bool NaivePolicyChecker::check(bool bus_type,
							   uid_t uid,
							   gid_t gid,
							   const char* const label,
							   const char** const names,
							   const char* const interface,
							   const char* const member,
							   const char* const path,
							   MessageType message_type,
							   MessageDirection message_dir) {
	try {
		ItemSendReceive item = ItemSendReceive(names, interface, member, path, message_type, message_dir);
		return checkItem(bus_type, uid, gid, label, item);
	} catch (std::runtime_error& err) {
		if (tslog::enabled())
			std::cout << err.what() << std::endl;
	}
	return false;
}
