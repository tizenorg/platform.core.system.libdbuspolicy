#include "naive_policy_checker.hpp"
#include "cynara.hpp"
#include "tslog.hpp"
using namespace ldp_xml_parser;

DbAdapter& NaivePolicyChecker::generateAdapter() {
	if (!m_adapter)
		m_adapter = new DbAdapter (m_bus_db[0], m_bus_db[1]);

	return *m_adapter;
}

Decision NaivePolicyChecker::checkPolicy(const NaivePolicyDb::Policy& policy,
										 const Item& item,
										 const char*& privilege)
{
	if (tslog::verbose()) {
		char tmp[MAX_LOG_LINE];
		const char* i_str = item.toString(tmp);
		std::cout << "checkpolicy for: " << i_str <<std::endl;
	}
	for (auto i : policy) {
		if (tslog::verbose()) {
			char tmp[MAX_LOG_LINE];
			const char* i_str = i->toString(tmp);
			std::cout << "-readed: " << i_str <<std::endl;
		}
		if (i->match(&item)) {
			if (tslog::verbose()) {
				char tmp[MAX_LOG_LINE];
				const char* i_str = i->toString(tmp);
				std::cout << "-matched: " << i_str <<std::endl;
			}
			privilege = i->getPrivilege();
			return i->getDecision();
		}
	}

	return Decision::ANY;
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
		std::sprintf(uid_str, "%lu", (unsigned long)uid);
		return ldp_cynara::Cynara::check(label, privilege, uid_str) == ldp_cynara::CynaraResult::ALLOW;
	}

	return false;
}

NaivePolicyChecker::~NaivePolicyChecker() {
	delete m_adapter;
}

bool NaivePolicyChecker::checkItem(bool bus_type, uid_t uid, gid_t gid, const char* label, const Item& item) {
	NaivePolicyDb& policy_db = getPolicyDb(bus_type);
	ItemType type = item.getType();
	Decision ret = Decision::ANY;
	const char* privilege;
	const NaivePolicyDb::Policy* curr_policy = NULL;

	if (ret == Decision::ANY) {
		curr_policy = policy_db.getPolicy(type, PolicyType::CONTEXT, PolicyTypeValue(ContextType::MANDATORY));
		if (curr_policy)
			ret = checkPolicy(*curr_policy, item, privilege);
	}

	if (ret == Decision::ANY) {
		curr_policy = policy_db.getPolicy(type, PolicyType::USER, PolicyTypeValue(uid));
		if (curr_policy)
			ret = checkPolicy(*curr_policy, item, privilege);
	}

	if (ret == Decision::ANY) {
		curr_policy = policy_db.getPolicy(type, PolicyType::GROUP, PolicyTypeValue(gid));
		if (curr_policy)
			ret = checkPolicy(*curr_policy, item, privilege);
	}

	if (ret == Decision::ANY) {
		curr_policy = policy_db.getPolicy(type, PolicyType::CONTEXT, PolicyTypeValue(ContextType::DEFAULT));
		if (curr_policy)
			ret = checkPolicy(*curr_policy, item, privilege);
	}

	if (ret != Decision::ANY)
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
