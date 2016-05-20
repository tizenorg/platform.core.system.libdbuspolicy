#include "policy.hpp"
//#include "tslog.hpp"
#include <cstdlib>
#include <sys/types.h>
#include <grp.h>
#include <pwd.h>
#define MAX_LOG_LINE 1024

using namespace _ldp_xml_parser;

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

_ldp_xml_parser::DbAdapter::DbAdapter(PolicyDb& system, PolicyDb& session)
	: m_system_db(system), m_session_db(session), m_attr(false), m_tag_state(NONE) {
}

uid_t _ldp_xml_parser::DbAdapter::convertToUid(const char* user) {
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

gid_t _ldp_xml_parser::DbAdapter::convertToGid(const char* group) {
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

void _ldp_xml_parser::DbAdapter::updateDecision(const boost::property_tree::ptree::value_type& v,
												PolicyType& policy_type,
												PolicyTypeValue& policy_type_value,
												state& t,
												bool& attr) {
	const char* value = NULL;
	if(v.first == "allow" && t == POLICY) {
		m_builder.reset();
		m_builder.addDecision(ALLOW);
		t = ALLOW_DENY_CHECK;
		attr = false;
	} else if(v.first == "deny" && t == POLICY) {
		m_builder.reset();
		m_builder.addDecision(DENY);
		t = ALLOW_DENY_CHECK;
		attr = false;
	} else if(v.first == "check" && t == POLICY) {
		m_builder.reset();
		m_builder.addDecision(CYNARA_CHECK);
		t = ALLOW_DENY_CHECK;
	    attr = false;
	} else if(v.first == "<xmlattr>") {
		attr = true;
	} else if(attr && t == POLICY) {
		if (v.second.data() != "*")
			value = v.second.data().c_str();

		if(v.first == "context") {
			if(std::strcmp(value,"mandatory") == 0 ) {
				policy_type = CONTEXT;
				policy_type_value.context = MANDATORY;
			} else if(std::strcmp(value, "default") == 0) {
				policy_type = CONTEXT;
				policy_type_value.context = DEFAULT;
			}
		} else if(v.first == "user") {
			policy_type = USER;
			policy_type_value.user = convertToUid(value);
		} else if(v.first == "group") {
			policy_type = GROUP;
			policy_type_value.group = convertToGid(value);
		} else {
			attr = false;
			t = NONE;
		}
	} else if (attr && t == ALLOW_DENY_CHECK) {
		if (v.second.data() != "*")
			value = v.second.data().c_str();

		if(field_has(v, "send_")) {
			m_builder.addDirection(DIRECTION_SEND);
		} else if(field_has(v, "receive_")) {
			m_builder.addDirection(DIRECTION_RECEIVE);
		} else if(v.first == "own") {
			m_builder.addOwner(value);
			m_builder.setPrefix(false);
		} else if(v.first == "own_prefix") {
			m_builder.addOwner(value);
			m_builder.setPrefix(true);
		} else if(v.first == "privilege")
			m_builder.addPrivilege(value);

		if(field_has(v, "_destination"))
			m_builder.addName(value);
		else if(field_has(v, "_sender"))
			m_builder.addName(value);
		else if(field_has(v, "_path"))
			m_builder.addPath(value);
		else if(field_has(v, "_interface"))
			m_builder.addInterface(value);
		else if(field_has(v, "_member"))
			m_builder.addMember(value);
		else if(field_has(v, "_type"))
			m_builder.addMessageType(__str_to_message_type(value));
	} else {
		attr = false;
		t = NONE;
	}
}

void _ldp_xml_parser::DbAdapter::xmlTraversal(bool bus,
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
			Item* it = m_builder.generateItem();
			if (it) {
				if (bus)
					m_session_db.addItem(policy_type, policy_type_value, it);
				else
					m_system_db.addItem(policy_type, policy_type_value, it);
			}
		}
	}
}

void _ldp_xml_parser::DbAdapter::updateDb(bool bus, boost::property_tree::ptree& xmlTree) {
	const auto& children = xmlTree.get_child("busconfig");
	PolicyType policy_type;
	PolicyTypeValue policy_type_value;
	for(const auto& x : children) {
		if(x.first == "policy") {
			m_tag_state = POLICY;
			m_attr = false;
			xmlTraversal(bus, x.second, POLICY, policy_type, policy_type_value);
		}
	}
}

_ldp_xml_parser::Item::Item(Decision decision, const char* privilege, bool isOwner)
	: m_decision(decision), m_privilege(privilege), m_isOwner(isOwner) {

}

_ldp_xml_parser::Item::~Item() {
	if (m_isOwner) {
		delete[] m_privilege;
	}
}

bool _ldp_xml_parser::Item::match(const Item& item) const {
	return match(&item);
}

bool _ldp_xml_parser::Item::match(const Item* item) const {
	return true;
}

Decision _ldp_xml_parser::Item::getDecision() const {
	return m_decision;
}

const char* _ldp_xml_parser::Item::getPrivilege() const {
	return m_privilege;
}

ItemType _ldp_xml_parser::Item::getType() const {
	return ITEM_GENERIC;
}

const char* _ldp_xml_parser::Item::toString(char* str) const {
	snprintf(str, MAX_LOG_LINE, "Item: dec(%s) owner(%d) priv(%s)", __decision_to_str(m_decision), m_isOwner, m_privilege);
	return str;
}

_ldp_xml_parser::ItemOwn::ItemOwn(const char* name,
								  bool is_prefix,
								  Decision decision,
								  const char* privilege)
: Item(decision, privilege), m_name(name), m_is_prefix(is_prefix) {
}

_ldp_xml_parser::ItemOwn::~ItemOwn() {
	if (m_isOwner) {
		delete[] m_name;
	}
}
ItemType _ldp_xml_parser::ItemOwn::getType() const {
	return ITEM_OWN;
}
bool _ldp_xml_parser::ItemOwn::match(const Item* item) const {
	const ItemOwn* it = dynamic_cast<const ItemOwn*>(item);
	if (m_is_prefix) {
		int i = 0;
		if (!m_name)
			return false;

		for (i = 0; m_name[i] && it->m_name[i]; i++)
			if (m_name[i] != it->m_name[i])
				return false;

		if (m_name[i] != 0)
			return false;

		return true;
	} else if (!m_name)
		return true;
	else {
		return std::strcmp(m_name, it->m_name) == 0;
	}
}

const char* _ldp_xml_parser::ItemOwn::toString(char* str) const {
	char parent[MAX_LOG_LINE];
	const char* t = Item::toString(parent);
	snprintf(str, MAX_LOG_LINE, "ItemOwn: service(%s), pref(%d) <- %s", m_name, m_is_prefix, t);
	return str;
}

_ldp_xml_parser::ItemUser::ItemUser(const char* name, Decision decision, const char* privilege)
	:  Item(decision, privilege), m_name(name) {
}

_ldp_xml_parser::ItemUser::~ItemUser() {
	if (m_isOwner) {
		delete[] m_name;
	}
}

bool _ldp_xml_parser::ItemUser::match(const Item* item) const {
	const ItemUser* it = dynamic_cast<const ItemUser*>(item);
	return std::strcmp(m_name, it->m_name) == 0;
}

ItemType _ldp_xml_parser::ItemUser::getType() const {
	return ITEM_USER;
}

_ldp_xml_parser::ItemGroup::ItemGroup(const char* name, Decision decision, const char* privilege)
	: Item(decision, privilege), m_name(name) {
}

_ldp_xml_parser::ItemGroup::~ItemGroup() {
	if (m_isOwner) {
		delete[] m_name;
	}
}

bool _ldp_xml_parser::ItemGroup::match(const Item* item) const {
	const ItemGroup* it = dynamic_cast<const ItemGroup*>(item);
	return std::strcmp(m_name, it->m_name) == 0;
}

ItemType _ldp_xml_parser::ItemGroup::getType() const {
	return ITEM_GROUP;
}

_ldp_xml_parser::ItemSendReceive::ItemSendReceive(const char** names,
												  const char* interface,
												  const char* member, const char* path,
												  MessageType type, MessageDirection direction,
												  Decision decision,
												  const char* privilege)
	: Item(decision, privilege),
	  m_names(names),
	  m_interface(interface),
	  m_member(member),
	  m_path(path),
	  m_type(type),
	  m_direction(direction) {
}
const char* _ldp_xml_parser::ItemSendReceive::toString(char* str) const {
	char parent[MAX_LOG_LINE];
	char buff[MAX_LOG_LINE];
	char* curr = buff;
	const char* t = Item::toString(parent);
	int i = 0;
	int k = 0;
	while(m_names && m_names[i]){
		for (k = 0; m_names[i][k] && m_names[i][k] != ' ';k++){
			*curr = m_names[i][k];
			curr +=1;
		}
		*curr = ' ';
		curr += 1;
		i++;
	}
	*curr = 0;
	curr += 1;
	snprintf(str, MAX_LOG_LINE, "ItemSR: name(%s), inter(%s), member(%s), path(%s), type(%s), dir(%s) <- %s", buff, m_interface, m_member, m_path, __message_type_to_str(m_type), __message_dir_to_str(m_direction), t);
	return str;
}
_ldp_xml_parser::ItemSendReceive::~ItemSendReceive() {
	if (m_isOwner) {
		delete[] m_interface;
		delete[] m_member;
		delete[] m_path;

		if (m_names) {
			int i = 0;
			while (m_names[i])
				delete[] m_names[i++];
			delete[] m_names;
		}
	}
}

bool _ldp_xml_parser::ItemSendReceive::match(const Item* item) const {
	const ItemSendReceive* it = dynamic_cast<const ItemSendReceive*>(item);

	if (m_names && m_names[0]) {
		int  i = 0;
		bool f = false;
		if (it->m_names) {
			while (it->m_names[i]) {
				if (__compare_str(it->m_names[i++], m_names[0])) {
					f = true;
					break;
				}
			}
			if (!f)
				return false;
		}
	}

	if (m_type != ANY && m_type != it->m_type)
		return false;

	if (m_direction != it->m_direction)
		return false;

	if (m_interface && it->m_interface && std::strcmp(m_interface, it->m_interface))
		return false;

	if (m_path && it->m_path && std::strcmp(m_path, it->m_path))
		return false;

	if (m_member && it->m_member && std::strcmp(m_member, it->m_member))
		return false;

	return true;
}

ItemType _ldp_xml_parser::ItemSendReceive::getType() const {
	if (m_direction == DIRECTION_SEND)
		return ITEM_SEND;
	else
		return ITEM_RECEIVE;
}


MessageDirection _ldp_xml_parser::ItemSendReceive::getDirection() const {
	return m_direction;
}

ItemOwn* _ldp_xml_parser::ItemBuilder::getOwnItem() {
	if (!m_current) {
		m_current = new ItemOwn();
		prepareItem();
	}
	return dynamic_cast<ItemOwn*>(m_current);
}

ItemSendReceive* _ldp_xml_parser::ItemBuilder::getSendReceiveItem() {
	if (!m_current) {
		m_current = new ItemSendReceive();
		prepareItem();
	}
	return dynamic_cast<ItemSendReceive*>(m_current);
}

ItemUser* _ldp_xml_parser::ItemBuilder::getUserItem() {
	if (!m_current) {
		m_current = new ItemUser();
		prepareItem();
	}
	return dynamic_cast<ItemUser*>(m_current);
}

ItemGroup* _ldp_xml_parser::ItemBuilder::getGroupItem() {
	if (!m_current) {
		m_current = new ItemGroup();
		prepareItem();
	}
	return dynamic_cast<ItemGroup*>(m_current);
}

_ldp_xml_parser::ItemBuilder::ItemBuilder() : m_current(NULL), m_delayed_privilege(NULL) {
}

_ldp_xml_parser::ItemBuilder::~ItemBuilder(){
	if (m_delayed_privilege)
		delete[] m_delayed_privilege;
	if (m_current)
		delete m_current;
}

void _ldp_xml_parser::ItemBuilder::reset() {
	if (m_delayed_privilege)
		delete[] m_delayed_privilege;
	if (m_current)
		delete m_current;

	m_current = NULL;
	m_delayed_privilege = NULL;
}

char* _ldp_xml_parser::ItemBuilder::duplicate(const char* str) {
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

void _ldp_xml_parser::ItemBuilder::prepareItem() {
		m_current->m_isOwner = true;
		if (m_delayed_privilege)
			m_current->m_privilege = m_delayed_privilege;

		m_current->m_decision = m_delayed_decision;
		m_delayed_privilege = NULL;
}

Item* _ldp_xml_parser::ItemBuilder::generateItem() {
	Item* ret = m_current;
	m_current = NULL;
	m_delayed_decision = NO_DECISION;
	m_delayed_privilege = NULL;
	return ret;
}

void _ldp_xml_parser::ItemBuilder::addUser(const char* name) {
	ItemUser* u = getUserItem();
	if (u->m_name)
		delete u->m_name;
	u->m_name = duplicate(name);
}

void _ldp_xml_parser::ItemBuilder::addGroup(const char* name) {
	ItemUser* g = getUserItem();
	if (g->m_name)
		delete g->m_name;
	g->m_name = duplicate(name);
}

void _ldp_xml_parser::ItemBuilder::addOwner(const char* owner) {
	ItemOwn* o = getOwnItem();
	if (o->m_name)
		delete o->m_name;
	o->m_name = duplicate(owner);
}

void _ldp_xml_parser::ItemBuilder::addName(const char* name) {
	ItemSendReceive* sr = getSendReceiveItem();
	if (sr->m_names) {
		delete sr->m_names[0];
		delete[] sr->m_names;
	}
	if (!name)
		sr->m_names = NULL;
	else {
		sr->m_names = new const char*[2];
		sr->m_names[0] = duplicate(name);
		sr->m_names[1] = NULL;
	}
}

void _ldp_xml_parser::ItemBuilder::addInterface(const char* interface) {
	ItemSendReceive* sr = getSendReceiveItem();
	sr->m_interface = duplicate(interface);
}

void _ldp_xml_parser::ItemBuilder::addMember(const char* member) {
	ItemSendReceive* sr = getSendReceiveItem();
	sr->m_member = duplicate(member);
}

void _ldp_xml_parser::ItemBuilder::addPath(const char* path) {
	ItemSendReceive* sr = getSendReceiveItem();
	sr->m_path = duplicate(path);
}

void _ldp_xml_parser::ItemBuilder::addMessageType(MessageType type) {
	ItemSendReceive* sr = getSendReceiveItem();
	sr->m_type = type;
}

void _ldp_xml_parser::ItemBuilder::addDirection(MessageDirection direction) {
	ItemSendReceive* sr = getSendReceiveItem();
	sr->m_direction = direction;
}

void _ldp_xml_parser::ItemBuilder::addPrivilege(const char* privilege) {
	if (!m_current)
		m_delayed_privilege = duplicate(privilege);
	else
		m_current->m_privilege = duplicate(privilege);
}

void _ldp_xml_parser::ItemBuilder::addDecision(Decision decision) {
	if (!m_current)
		m_delayed_decision = decision;
	else
		m_current->m_decision = decision;
}

void _ldp_xml_parser::ItemBuilder::setPrefix(bool value) {
	ItemOwn* o = getOwnItem();
	o->m_is_prefix = value;
}

_ldp_xml_parser::PolicyTypeValue::PolicyTypeValue() : context(DEFAULT) {
}

_ldp_xml_parser::PolicyTypeValue::PolicyTypeValue(ConsoleType type) : console(type) {
}

_ldp_xml_parser::PolicyTypeValue::PolicyTypeValue(ContextType type) : context(type) {
}

_ldp_xml_parser::PolicyTypeValue::PolicyTypeValue(uid_t us) : user(us) {
}
