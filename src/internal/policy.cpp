#include "policy.hpp"
//#include "tslog.hpp"
#include <cstdlib>
#include <sys/types.h>
#include <grp.h>
#include <pwd.h>
#define MAX_LOG_LINE 1024

using namespace ldp_xml_parser;

static const char* message_type[] = { "ANY", "METHOD_CALL", "METHOD_RETURN", "ERROR", "SIGNAL"};
static const char* message_dir[] = { "ANY", "SEND", "RECEIVE"};
static const char* message_decision[] = {"NO_DECISION", "ALLOW", "DENY", "CHECK"};

static bool __compare_str(const char* a, const char* b) {

	while(*a && *b && *a != ' ' && *b != ' ') {
		if (*a != *b)
			return false;
		a++; b++;
	}
	return ((*a == 0 || *a == ' ') && (*b == 0 || *b != ' '));
}

static MessageType __str_to_message_type(const char* str) {
	if (!std::strcmp(str, "method_call"))
		return METHOD_CALL;
	else if (!std::strcmp(str, "method_return"))
		return METHOD_RETURN;
	else if (!std::strcmp(str, "error"))
		return ERROR;
	else if (!std::strcmp(str, "signal"))
		return SIGNAL;

	return ANY;
}

static inline const char* __message_type_to_str(MessageType type) {
	return message_type[type];
}

static inline const char* __message_dir_to_str(MessageDirection type) {
	return message_dir[type];
}

static inline const char* __decision_to_str(Decision dec) {
	return message_decision[dec];
}

DbAdapter::DbAdapter(IPolicyDb& system, IPolicyDb& session)
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
	if (getpwnam_r(user, &pwent, buf, sizeof(buf), &pwd) && pwd)
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
	if (getgrnam_r(group, &grent, buf, sizeof(buf), &gg) && gg)
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
		__builder.addDecision(DECISION_ALLOW);
		t = ALLOW_DENY_CHECK;
		attr = false;
	} else if(v.first == "deny" && t == POLICY) {
		__builder.reset();
		__builder.addDecision(DECISION_DENY);
		t = ALLOW_DENY_CHECK;
		attr = false;
	} else if(v.first == "check" && t == POLICY) {
		__builder.reset();
		__builder.addDecision(DECISION_CYNARA_CHECK);
		t = ALLOW_DENY_CHECK;
	    attr = false;
	} else if(v.first == "<xmlattr>") {
		attr = true;
	} else if(attr && t == POLICY) {
		if (v.second.data() != "*")
			value = v.second.data().c_str();

		if(v.first == "context") {
			if(std::strcmp(value,"mandatory") == 0 ) {
				policy_type = POLICY_CONTEXT;
				policy_type_value.context = CONTEXT_MANDATORY;
			} else if(std::strcmp(value, "default") == 0) {
				policy_type = POLICY_CONTEXT;
				policy_type_value.context = CONTEXT_DEFAULT;
			}
		} else if(v.first == "user") {
			policy_type = POLICY_USER;
			policy_type_value.user = convertToUid(value);
		} else if(v.first == "group") {
			policy_type = POLICY_GROUP;
			policy_type_value.group = convertToGid(value);
		} else {
			attr = false;
			t = NONE;
		}
	} else if (attr && t == ALLOW_DENY_CHECK) {
		if (v.second.data() != "*")
			value = v.second.data().c_str();

		if(field_has(v, "send_")) {
			__builder.addDirection(DIRECTION_SEND);
		} else if(field_has(v, "receive_")) {
			__builder.addDirection(DIRECTION_RECEIVE);
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
			Item* it = __builder.generateItem();
			if (it) {
				if (bus)
					__session_db.addItem(policy_type, policy_type_value, it);
				else
					__system_db.addItem(policy_type, policy_type_value, it);
			}
		}
	}
}

void DbAdapter::updateDb(bool bus, boost::property_tree::ptree& xmlTree) {
	const auto& children = xmlTree.get_child("busconfig");
	PolicyType policy_type;
	PolicyTypeValue policy_type_value;
	for(const auto& x : children) {
		if(x.first == "policy") {
			__tag_state = POLICY;
			__attr = false;
			xmlTraversal(bus, x.second, POLICY, policy_type, policy_type_value);
		}
	}
}

Item::Item(Decision decision, const char* privilege, bool isOwner)
	: _decision(decision), _privilege(privilege), _is_owner(isOwner) {

}

Item::~Item() {
	if (_is_owner) {
		delete[] _privilege;
	}
}

bool Item::match(const Item& item) const {
	return match(&item);
}

bool Item::match(const Item* item) const {
	return true;
}

Decision Item::getDecision() const {
	return _decision;
}

const char* Item::getPrivilege() const {
	return _privilege;
}

ItemType Item::getType() const {
	return ITEM_GENERIC;
}

const char* Item::toString(char* str) const {
	snprintf(str, MAX_LOG_LINE, "Item: dec(%s) owner(%d) priv(%s)", __decision_to_str(_decision), _is_owner, _privilege);
	return str;
}

ItemOwn::ItemOwn(const char* name,
				 bool is_prefix,
				 Decision decision,
				 const char* privilege)
: Item(decision, privilege), __name(name), __is_prefix(is_prefix) {
}

ItemOwn::~ItemOwn() {
	if (_is_owner) {
		delete[] __name;
	}
}
ItemType ItemOwn::getType() const {
	return ITEM_OWN;
}
bool ItemOwn::match(const Item* item) const {
	const ItemOwn* it = dynamic_cast<const ItemOwn*>(item);
	if (__is_prefix) {
		int i = 0;
		if (!__name)
			return false;

		for (i = 0; __name[i] && it->__name[i]; i++)
			if (__name[i] != it->__name[i])
				return false;

		if (__name[i] != 0)
			return false;

		return true;
	} else if (!__name)
		return true;
	else {
		return std::strcmp(__name, it->__name) == 0;
	}
}

const char* ItemOwn::toString(char* str) const {
	char parent[MAX_LOG_LINE];
	const char* t = Item::toString(parent);
	snprintf(str, MAX_LOG_LINE, "ItemOwn: service(%s), pref(%d) <- %s", __name, __is_prefix, t);
	return str;
}

ItemUser::ItemUser(const char* name, Decision decision, const char* privilege)
	:  Item(decision, privilege), __name(name) {
}

ItemUser::~ItemUser() {
	if (_is_owner) {
		delete[] __name;
	}
}

bool ItemUser::match(const Item* item) const {
	const ItemUser* it = dynamic_cast<const ItemUser*>(item);
	return std::strcmp(__name, it->__name) == 0;
}

ItemType ItemUser::getType() const {
	return ITEM_USER;
}

ItemGroup::ItemGroup(const char* name, Decision decision, const char* privilege)
	: Item(decision, privilege), __name(name) {
}

ItemGroup::~ItemGroup() {
	if (_is_owner) {
		delete[] __name;
	}
}

bool ItemGroup::match(const Item* item) const {
	const ItemGroup* it = dynamic_cast<const ItemGroup*>(item);
	return std::strcmp(__name, it->__name) == 0;
}

ItemType ItemGroup::getType() const {
	return ITEM_GROUP;
}

ItemSendReceive::ItemSendReceive(const char** names,
												  const char* interface,
												  const char* member, const char* path,
												  MessageType type, MessageDirection direction,
												  Decision decision,
												  const char* privilege)
	: Item(decision, privilege),
	  __names(names),
	  __interface(interface),
	  __member(member),
	  __path(path),
	  __type(type),
	  __direction(direction) {
}
const char* ItemSendReceive::toString(char* str) const {
	char parent[MAX_LOG_LINE];
	char buff[MAX_LOG_LINE];
	char* curr = buff;
	const char* t = Item::toString(parent);
	int i = 0;
	int k = 0;
	while(__names && __names[i]){
		for (k = 0; __names[i][k] && __names[i][k] != ' ';k++){
			*curr = __names[i][k];
			curr +=1;
		}
		*curr = ' ';
		curr += 1;
		i++;
	}
	*curr = 0;
	curr += 1;
	snprintf(str, MAX_LOG_LINE, "ItemSR: name(%s), inter(%s), member(%s), path(%s), type(%s), dir(%s) <- %s", buff, __interface, __member, __path, __message_type_to_str(__type), __message_dir_to_str(__direction), t);
	return str;
}
ItemSendReceive::~ItemSendReceive() {
	if (_is_owner) {
		delete[] __interface;
		delete[] __member;
		delete[] __path;

		if (__names) {
			int i = 0;
			while (__names[i])
				delete[] __names[i++];
			delete[] __names;
		}
	}
}

bool ItemSendReceive::match(const Item* item) const {
	const ItemSendReceive* it = dynamic_cast<const ItemSendReceive*>(item);

	if (__names && __names[0]) {
		int  i = 0;
		bool f = false;
		if (it->__names) {
			while (it->__names[i]) {
				if (__compare_str(it->__names[i++], __names[0])) {
					f = true;
					break;
				}
			}
			if (!f)
				return false;
		}
	}

	if (__type != ANY && __type != it->__type)
		return false;

	if (__direction != it->__direction)
		return false;

	if (__interface && it->__interface && std::strcmp(__interface, it->__interface))
		return false;

	if (__path && it->__path && std::strcmp(__path, it->__path))
		return false;

	if (__member && it->__member && std::strcmp(__member, it->__member))
		return false;

	return true;
}

ItemType ItemSendReceive::getType() const {
	if (__direction == DIRECTION_SEND)
		return ITEM_SEND;
	else
		return ITEM_RECEIVE;
}


MessageDirection ItemSendReceive::getDirection() const {
	return __direction;
}

ItemOwn* ItemBuilder::getOwnItem() {
	if (!__current) {
		__current = new ItemOwn();
		prepareItem();
	}
	return dynamic_cast<ItemOwn*>(__current);
}

ItemSendReceive* ItemBuilder::getSendReceiveItem() {
	if (!__current) {
		__current = new ItemSendReceive();
		prepareItem();
	}
	return dynamic_cast<ItemSendReceive*>(__current);
}

ItemUser* ItemBuilder::getUserItem() {
	if (!__current) {
		__current = new ItemUser();
		prepareItem();
	}
	return dynamic_cast<ItemUser*>(__current);
}

ItemGroup* ItemBuilder::getGroupItem() {
	if (!__current) {
		__current = new ItemGroup();
		prepareItem();
	}
	return dynamic_cast<ItemGroup*>(__current);
}

ItemBuilder::ItemBuilder() : __current(NULL), __delayed_privilege(NULL) {
}

ItemBuilder::~ItemBuilder(){
	if (__delayed_privilege)
		delete[] __delayed_privilege;
	if (__current)
		delete __current;
}

void ItemBuilder::reset() {
	if (__delayed_privilege)
		delete[] __delayed_privilege;
	if (__current)
		delete __current;

	__current = NULL;
	__delayed_privilege = NULL;
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

void ItemBuilder::prepareItem() {
		__current->_is_owner = true;
		if (__delayed_privilege)
			__current->_privilege = __delayed_privilege;

		__current->_decision = __delayed_decision;
		__delayed_privilege = NULL;
}

Item* ItemBuilder::generateItem() {
	Item* ret = __current;
	__current = NULL;
	__delayed_decision = NO_DECISION;
	__delayed_privilege = NULL;
	return ret;
}

void ItemBuilder::addUser(const char* name) {
	ItemUser* u = getUserItem();
	if (u->__name)
		delete u->__name;
	u->__name = duplicate(name);
}

void ItemBuilder::addGroup(const char* name) {
	ItemUser* g = getUserItem();
	if (g->__name)
		delete g->__name;
	g->__name = duplicate(name);
}

void ItemBuilder::addOwner(const char* owner) {
	ItemOwn* o = getOwnItem();
	if (o->__name)
		delete o->__name;
	o->__name = duplicate(owner);
}

void ItemBuilder::addName(const char* name) {
	ItemSendReceive* sr = getSendReceiveItem();
	if (sr->__names) {
		delete sr->__names[0];
		delete[] sr->__names;
	}
	if (!name)
		sr->__names = NULL;
	else {
		sr->__names = new const char*[2];
		sr->__names[0] = duplicate(name);
		sr->__names[1] = NULL;
	}
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
	if (!__current)
		__delayed_privilege = duplicate(privilege);
	else
		__current->_privilege = duplicate(privilege);
}

void ItemBuilder::addDecision(Decision decision) {
	if (!__current)
		__delayed_decision = decision;
	else
		__current->_decision = decision;
}

void ItemBuilder::setPrefix(bool value) {
	ItemOwn* o = getOwnItem();
	o->__is_prefix = value;
}

PolicyTypeValue::PolicyTypeValue() : context(CONTEXT_DEFAULT) {
}

PolicyTypeValue::PolicyTypeValue(ConsoleType type) : console(type) {
}

PolicyTypeValue::PolicyTypeValue(ContextType type) : context(type) {
}

PolicyTypeValue::PolicyTypeValue(uid_t us) : user(us) {
}
