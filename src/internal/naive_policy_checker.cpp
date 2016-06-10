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
		std::sprintf(uid_str, "%lu", (unsigned long)uid);
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
	return this->template checkItem<const char*, ItemOwn>(bus_type, uid, gid, label, name, ItemType::OWN);
}

bool NaivePolicyChecker::check(bool bus_type,
							   uid_t uid,
							   gid_t gid,
							   const char* const label,
							   MatchItemSR& matcher,
							   ItemType type) {
	return this->template checkItem<MatchItemSR, ItemSendReceive>(bus_type, uid, gid, label, matcher, type);
}
