#include "policy.hpp"
#include "naive_policy_db.hpp"
#include <cstdlib>
#include <sys/types.h>
#include <grp.h>
#include <pwd.h>

using namespace ldp_xml_parser;

static const char* message_type[] = { "ANY", "METHOD_CALL", "METHOD_RETURN", "ERROR", "SIGNAL"};
static const char* message_dir[] = { "ANY", "SEND", "RECEIVE"};
static const char* message_decision[] = {"NO_DECISION", "ALLOW", "DENY", "CHECK"};

static MessageType __str_to_message_type(const char* str) {
	if (!std::strcmp(str, "method_call"))
		return MessageType::METHOD_CALL;
	else if (!std::strcmp(str, "method_return"))
		return MessageType::METHOD_RETURN;
	else if (!std::strcmp(str, "error"))
		return MessageType::ERROR;
	else if (!std::strcmp(str, "signal"))
		return MessageType::SIGNAL;

	return MessageType::ANY;
}

static inline const char* __message_type_to_str(MessageType type) {
	return message_type[static_cast<std::size_t>(type)];
}

static inline const char* __message_dir_to_str(MessageDirection type) {
	return message_dir[static_cast<std::size_t>(type)];
}

static inline const char* __decision_to_str(Decision dec) {
	return message_decision[static_cast<std::size_t>(dec)];
}

DbAdapter::DbAdapter(NaivePolicyDb& system, NaivePolicyDb& session)
	: __system_db(system), __session_db(session), __attr(false), __tag_state(NONE) {
}

uid_t DbAdapter::convertToUid(const char* user) {
	errno = 0;
	long val = std::strtol(user, NULL, 10);
	if (!errno)
		return (uid_t)val;

	struct passwd pwent;
	struct passwd *pwd;
	char buf[1024];
	if (getpwnam_r(user, &pwent, buf, sizeof(buf), &pwd) || !pwd)
		return (uid_t)-1;

	return pwd->pw_uid;
}

gid_t DbAdapter::convertToGid(const char* group) {
	errno = 0;
	long val = std::strtol(group, NULL, 10);
	if (!errno)
		return (gid_t)val;
	struct group grent;
	struct group *gg;
	char buf[1024];
	if (getgrnam_r(group, &grent, buf, sizeof(buf), &gg) || !gg)
		return (gid_t)-1;

	return gg->gr_gid;
}

static bool field_has(const boost::property_tree::ptree::value_type& v, const std::string& substr) {
	return (v.first.find(substr) != std::string::npos);
}

void DbAdapter::updateDecision(const boost::property_tree::ptree::value_type& v,
							   PolicyType& policy_type,
							   PolicyTypeValue& policy_type_value,
							   state& t,
							   bool& attr) {
	const char* value = NULL;
	if(v.first == "allow" && t == POLICY) {
		__builder.reset();
		__builder.addDecision(Decision::ALLOW);
		t = ALLOW_DENY_CHECK;
		attr = false;
	} else if(v.first == "deny" && t == POLICY) {
		__builder.reset();
		__builder.addDecision(Decision::DENY);
		t = ALLOW_DENY_CHECK;
		attr = false;
	} else if(v.first == "check" && t == POLICY) {
		__builder.reset();
		__builder.addDecision(Decision::CHECK);
		t = ALLOW_DENY_CHECK;
	    attr = false;
	} else if(v.first == "<xmlattr>") {
		attr = true;
	} else if(attr && t == POLICY) {
		if (v.second.data() != "*")
			value = v.second.data().c_str();

		if(v.first == "context") {
			if(std::strcmp(value,"mandatory") == 0 ) {
				policy_type = PolicyType::CONTEXT;
				policy_type_value.context = ContextType::MANDATORY;
			} else if(std::strcmp(value, "default") == 0) {
				policy_type = PolicyType::CONTEXT;
				policy_type_value.context = ContextType::DEFAULT;
			}
		} else if(v.first == "user") {
			policy_type = PolicyType::USER;
			policy_type_value.user = convertToUid(value);
		} else if(v.first == "group") {
			policy_type = PolicyType::GROUP;
			policy_type_value.group = convertToGid(value);
		} else {
			attr = false;
			t = NONE;
		}
	} else if (attr && t == ALLOW_DENY_CHECK) {
		if (v.second.data() != "*")
			value = v.second.data().c_str();

		if(field_has(v, "send_")) {
			__builder.addDirection(MessageDirection::SEND);
		} else if(field_has(v, "receive_")) {
			__builder.addDirection(MessageDirection::RECEIVE);
		} else if(v.first == "own") {
			__builder.addOwner(value);
			__builder.setPrefix(false);
		} else if(v.first == "own_prefix") {
			__builder.addOwner(value);
			__builder.setPrefix(true);
		} else if(v.first == "privilege")
			__builder.addPrivilege(value);

		if(field_has(v, "_destination"))
			__builder.addName(value);
		else if(field_has(v, "_sender"))
			__builder.addName(value);
		else if(field_has(v, "_path"))
			__builder.addPath(value);
		else if(field_has(v, "_interface"))
			__builder.addInterface(value);
		else if(field_has(v, "_member"))
			__builder.addMember(value);
		else if(field_has(v, "_type"))
			__builder.addMessageType(__str_to_message_type(value));
	} else {
		attr = false;
		t = NONE;
	}
}

void DbAdapter::xmlTraversal(bool bus,
							 const boost::property_tree::ptree& pt,
							 DbAdapter::state tag,
							 PolicyType& policy_type,
							 PolicyTypeValue& policy_type_value,
							 bool attr,
							 int level) {
	static const int Q_XML_MAX_LEVEL = 10;
	if(level < Q_XML_MAX_LEVEL) {
		for(const auto& v : pt) {
			if(v.first == "<xmlcomment>") { continue; }
			state t = tag;
			updateDecision(v, policy_type, policy_type_value, t, attr);
			xmlTraversal(bus, v.second, t, policy_type, policy_type_value, attr, level + 1);
		}

		if(!pt.empty() && level > 1) {
			if (bus)
				__builder.generateItem(__session_db, policy_type, policy_type_value);
			else
				__builder.generateItem(__system_db, policy_type, policy_type_value);
		}
	}
}

void DbAdapter::updateDb(bool bus, boost::property_tree::ptree& xmlTree, std::vector<std::string>& incl_dirs) {
	const auto& children = xmlTree.get_child("busconfig");
	PolicyType policy_type;
	PolicyTypeValue policy_type_value;
	for(const auto& x : children) {
		if(x.first == "policy") {
			__tag_state = POLICY;
			__attr = false;
			xmlTraversal(bus, x.second, POLICY, policy_type, policy_type_value);
		} else if (x.first == "includedir") {
			incl_dirs.push_back(x.second.data());
		}
	}
}

DecisionItem::DecisionItem(Decision decision, const char* privilege)
	: __decision(decision), __privilege(privilege)
{
}

DecisionItem::~DecisionItem()
{
	if (__privilege)
		delete[] __privilege;
}

Decision DecisionItem::getDecision() const {
	return __decision;
}

const char* DecisionItem::getPrivilege() const {
	return __privilege;
}

ItemType DecisionItem::getType() const {
	return ItemType::GENERIC;
}

const char* DecisionItem::toString(char* str) const {
	snprintf(str, MAX_LOG_LINE, "Item: dec(%s) priv(%s)", __decision_to_str(__decision), __privilege);
	return str;
}

ItemOwn::ItemOwn(const char* name,
				 Decision decision,
				 const char* privilege)
	:   __decision(DecisionItem(decision, privilege)), __name(name) {

}

ItemOwn::~ItemOwn() {
	if (__name)
		delete[] __name;
}

ItemType ItemOwn::getType() const {
	return ItemType::OWN;
}

bool ItemOwn::match(const char* const item) const {

	if (__is_prefix) {
		int i = 0;
		if (!__name)
			return false;

		for (i = 0; __name[i] && item[i]; i++)
			if (__name[i] != item[i])
				return false;

		if (__name[i] != 0)
			return false;

		return true;
	} else if (!__name)
		return true;
	else {
		return std::strcmp(__name, item) == 0;
	}
}

const char* ItemOwn::toString(char* str) const {
	snprintf(str, MAX_LOG_LINE, "ItemOwn: service(%s), pref(%d)", __name, __is_prefix);
	return str;
}


const DecisionItem& ItemOwn::getDecision() const {
	return __decision;
}

NameSR::NameSR(const char* m, int l) : name(m), len(l)
{
}

MatchItemSR::MatchItemSR(const char* i, const char* me, const char* p, MessageType t, MessageDirection d)
	: names_num(0), interface(i), member(me), path(p), type(t), direction(d) {
}

MatchItemSR::~MatchItemSR(){
}

void MatchItemSR::addName(const char* name) {
	names[names_num++] = NameSR(name, std::strlen(name));
}

bool MatchItemSR::addNames(const char* name) {
	int i = 0;
	int j = 0;

	if (name) {
		assert((name[i] > 'a'&& name[i] < 'z') || (name[i] > 'A'&& name[i] < 'Z') || (name[i] > '0'&& name[i] < '9'));
		while (name[i] && names_num < KDBUS_CONN_MAX_NAMES + 1) {
			char c;
			int len;
			j = i;
			while ((c = name[i++]) && ' ' != c);
			if (!c) {
				--i;
				len = i-j;
			} else
				len = i-j-1;
			names[names_num++] = NameSR(name + j, len);
	    }
		if (names_num >= KDBUS_CONN_MAX_NAMES + 1)
			return false;
	}
	return true;
}

ItemSendReceive::ItemSendReceive(const char* name,
								 const char* interface,
								 const char* member,
								 const char* path,
								 MessageType type,
								 MessageDirection direction,
								 Decision decision,
								 const char* privilege)
	: 	__name(NameSR(name, name?std::strlen(name):0)),
		__interface(interface),
		__member(member),
		__path(path),
		__type(type),
		__direction(direction) {

}

const char* ItemSendReceive::toString(char* str) const {
	snprintf(str, MAX_LOG_LINE, "ItemSR: name(%s), inter(%s), member(%s), path(%s), type(%s), dir(%s)", __name.name, __interface, __member, __path, __message_type_to_str(__type), __message_dir_to_str(__direction));
	return str;
}

ItemSendReceive::~ItemSendReceive() {
	delete[] __interface;
	delete[] __member;
	delete[] __path;

	if (__name.len > 0) {
		delete[] __name.name;
	}
}

bool ItemSendReceive::match(const MatchItemSR& item) const {

	if (__type != MessageType::ANY && __type != item.type)
		return false;

	if (__direction != item.direction)
		return false;

	if (__interface && item.interface && std::strcmp(__interface, item.interface))
		return false;

	if (__path && item.path && std::strcmp(__path, item.path))
		return false;

	if (__member && item.member && std::strcmp(__member, item.member))
		return false;

	if (__name.len > 0 ) {
		int  i = 0;
		bool f = false;
		if (item.names_num > 0) {
			while (i < item.names_num) {
				if (item.names[i].len == __name.len &&
					!memcmp(item.names[i].name, __name.name, item.names[i].len)) {
					f = true;
					break;
				}
				i++;
			}
			if (!f)
				return false;
		}
	}

	return true;
}

ItemType ItemSendReceive::getType() const {
	if (__direction == MessageDirection::SEND)
		return ItemType::SEND;
	else
		return ItemType::RECEIVE;
}


MessageDirection ItemSendReceive::getDirection() const {
	return __direction;
}

const DecisionItem& ItemSendReceive::getDecision() const {
	return __decision;
}

void ItemBuilder::prepareItem()
{
}

ItemOwn* ItemBuilder::getOwnItem() {
	if (!__current_own) {
		__current_own = new ItemOwn();
		prepareItem();
	}
	return __current_own;
}

ItemSendReceive* ItemBuilder::getSendReceiveItem() {
	if (!__current_sr) {
		__current_sr = new ItemSendReceive();
		prepareItem();
	}
	return __current_sr;
}

ItemBuilder::ItemBuilder() : __current_own(NULL), __current_sr(NULL) {
}

ItemBuilder::~ItemBuilder(){
	if (__current_sr)
		delete __current_sr;

	if (__current_own)
		delete __current_own;
}

void ItemBuilder::reset() {
	__decision.__decision = Decision::ANY;
	__decision.__privilege = NULL;
	__current_sr = NULL;
	__current_own = NULL;
}

char* ItemBuilder::duplicate(const char* str) {
	char* ret;
	int i = 0;
	int len;

	if (!str)
		return NULL;

	len = strlen(str) + 1;
	ret = new char[len];
	for (i = 0; i < len; i++)
		ret[i] = str[i];

	return ret;
}

void ItemBuilder::generateItem(NaivePolicyDb& db, PolicyType& policy_type, PolicyTypeValue& policy_type_value) {
	if (__current_own) {
		__current_own->__decision = __decision;
		db.addItem(policy_type, policy_type_value, __current_own);
	} else if (__current_sr) {
		__current_sr->__decision = __decision;
		db.addItem(policy_type, policy_type_value, __current_sr);
	}
	reset();
}

void ItemBuilder::addOwner(const char* owner) {
	ItemOwn* o = getOwnItem();
	if (o->__name)
		delete o->__name;
	o->__name = duplicate(owner);
}

void ItemBuilder::addName(const char* name) {
	ItemSendReceive* sr = getSendReceiveItem();
	if (sr->__name.len > 0) {
		delete[] sr->__name.name;
		sr->__name.len = 0;
	}

	if (!name)
		sr->__name.name = NULL;
	else {
		sr->__name.name = duplicate(name);
		sr->__name.len  = std::strlen(name);
	}
}

const char* MatchItemSR::toString(char* str) const {
	char tmp[MAX_LOG_LINE];
	tmp[0]  = 0;
	for (int i = 0; i < names_num; i++) {
		std::strcat(tmp, names[i].name);
		std::strcat(tmp, " ");
	}
	snprintf(str, MAX_LOG_LINE, "matcher: services(%s), interface(%s), member(%s), path(%s), type(%s), direction(%s)", tmp, interface, member, path, __message_type_to_str(type), __message_dir_to_str(direction) );
	return str;
}

void ItemBuilder::addInterface(const char* interface) {
	ItemSendReceive* sr = getSendReceiveItem();
	sr->__interface = duplicate(interface);
}

void ItemBuilder::addMember(const char* member) {
	ItemSendReceive* sr = getSendReceiveItem();
	sr->__member = duplicate(member);
}

void ItemBuilder::addPath(const char* path) {
	ItemSendReceive* sr = getSendReceiveItem();
	sr->__path = duplicate(path);
}

void ItemBuilder::addMessageType(MessageType type) {
	ItemSendReceive* sr = getSendReceiveItem();
	sr->__type = type;
}

void ItemBuilder::addDirection(MessageDirection direction) {
	ItemSendReceive* sr = getSendReceiveItem();
	sr->__direction = direction;
}

void ItemBuilder::addPrivilege(const char* privilege) {
	__decision.__privilege = duplicate(privilege);
}

void ItemBuilder::addDecision(Decision decision) {
	__decision.__decision = decision;
}

void ItemBuilder::setPrefix(bool value) {
	ItemOwn* o = getOwnItem();
	o->__is_prefix = value;
}

PolicyTypeValue::PolicyTypeValue() : context(ContextType::DEFAULT) {
}

PolicyTypeValue::PolicyTypeValue(ContextType type) : context(type) {
}

PolicyTypeValue::PolicyTypeValue(uid_t us) : user(us) {
}
