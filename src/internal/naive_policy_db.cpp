#include "naive_policy_db.hpp"
#include <cstdlib>
#include "tslog.hpp"

using namespace _ldp_xml_parser;

NaivePolicyDb::Policy::PolicyConstIterator::PolicyConstIterator(const std::vector<Item*>& items, int position)
	: m_items(items), m_index(position) {
}

 Item* const& NaivePolicyDb::Policy::PolicyConstIterator::operator*() const {
	return m_items[m_index];
}

NaivePolicyDb::Policy::PolicyConstIterator& NaivePolicyDb::Policy::PolicyConstIterator::operator++() {
	if (m_index >= 0)
		--m_index;
	return *this;
}

bool NaivePolicyDb::Policy::PolicyConstIterator::operator!=(const PolicyConstIterator& it) const {
	return m_index != it.m_index;
}

NaivePolicyDb::Policy::PolicyIterator::PolicyIterator(std::vector<Item*>& items, int position)
	: m_items(items), m_index(position) {
}

Item*& NaivePolicyDb::Policy::PolicyIterator::operator*() {
	return m_items[m_index];
}

NaivePolicyDb::Policy::PolicyIterator& NaivePolicyDb::Policy::PolicyIterator::operator++() {
	if (m_index >= 0)
		--m_index;
	return *this;
}

bool NaivePolicyDb::Policy::PolicyIterator::operator!=(const PolicyIterator& it) const {
	return m_index != it.m_index;
}

NaivePolicyDb::Policy::PolicyIterator NaivePolicyDb::Policy::begin() {
	int s = m_items.size() - 1;
	return NaivePolicyDb::Policy::PolicyIterator(m_items, s);
}
NaivePolicyDb::Policy::PolicyIterator NaivePolicyDb::Policy::end() {
	return NaivePolicyDb::Policy::PolicyIterator(m_items, -1);
}
NaivePolicyDb::Policy::PolicyConstIterator NaivePolicyDb::Policy::begin() const {
	int s = m_items.size() - 1;
	return NaivePolicyDb::Policy::PolicyConstIterator(m_items, s);
}
NaivePolicyDb::Policy::PolicyConstIterator NaivePolicyDb::Policy::end() const {
	return NaivePolicyDb::Policy::PolicyConstIterator(m_items, -1);
}

void NaivePolicyDb::Policy::addItem(Item* item) {
	m_items.push_back(item);
}

NaivePolicyDb::~NaivePolicyDb() {

}

const NaivePolicyDb::Policy* NaivePolicyDb::getPolicy(const ItemType item_type,
													  const PolicyType policy_type,
													  const PolicyTypeValue policy_type_value) {
	PolicyTypeSet* set = NULL;
	switch (item_type) {
	case ITEM_OWN:
		set = &m_own_set;
		break;
	case ITEM_SEND:
		set = &m_send_set;
		break;
	case ITEM_RECEIVE:
		set = &m_receive_set;
		break;
	default:
		break;
	}
	if (tslog::enabled())
		std::cout<<"---policy_type =";
	switch (policy_type) {
	case POLICY_CONTEXT:
		if (tslog::enabled())
			std::cout << "CONTEXT =" << (int)policy_type_value.context << std::endl;
		return &set->context[policy_type_value.context];
	case POLICY_USER:
		if (tslog::enabled())
			std::cout << "USER =" << (int)policy_type_value.user << std::endl;
		return &set->user[policy_type_value.user];
	case POLICY_GROUP:
		if (tslog::enabled())
			std::cout << "GROUP = " << (int)policy_type_value.group << std::endl;
		return &set->group[policy_type_value.group];
	case POLICY_CONSOLE:
		if (tslog::enabled())
			std::cout << "CONSOLE" << std::endl;
		return &set->console[policy_type_value.console];
	}
	if (tslog::enabled())
		std::cout << "NO POLICY\n";
	return NULL;
}

void NaivePolicyDb::addItem(NaivePolicyDb::PolicyTypeSet& set,
											 const PolicyType policy_type,
											 const PolicyTypeValue policy_type_value,
											 Item* const item) {
	switch (policy_type) {
	case POLICY_CONTEXT:
		set.context[policy_type_value.context].addItem(item);
		break;
	case POLICY_USER:
		set.user[policy_type_value.user].addItem(item);
		break;
	case POLICY_GROUP:
		set.group[policy_type_value.group].addItem(item);
		break;
	case POLICY_CONSOLE:
		set.user[policy_type_value.console].addItem(item);
		break;
	}
}

void NaivePolicyDb::addItem(const PolicyType policy_type,
							const PolicyTypeValue policy_type_value,
							Item* const item) {
	const ItemSendReceive* it;

	if (tslog::enabled()) {
		char tmp[1024];
		const char* i_str = item->toString(tmp);
		std::cout<<"Add item: "<< i_str <<std::endl;
	}

	if (dynamic_cast<const ItemOwn*>(item))
		addItem(m_own_set, policy_type, policy_type_value, item);
	else if ((it = dynamic_cast<const ItemSendReceive*>(item))) {
		const MessageDirection dir = it->getDirection();
		if (dir == DIRECTION_SEND)
			addItem(m_send_set, policy_type, policy_type_value, item);
		else if (dir == DIRECTION_RECEIVE)
			addItem(m_receive_set, policy_type, policy_type_value, item);
		else {
			addItem(m_send_set, policy_type, policy_type_value, item);
			addItem(m_receive_set, policy_type, policy_type_value, item);
		}
	}
}
