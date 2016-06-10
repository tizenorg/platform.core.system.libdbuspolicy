#include "naive_policy_db.hpp"


using namespace ldp_xml_parser;



NaivePolicyDb::~NaivePolicyDb() {

}


void NaivePolicyDb::addItem(const PolicyType policy_type,
							const PolicyTypeValue policy_type_value,
							ItemSendReceive* const item) {
	if (tslog::enabled()) {
		char tmp[MAX_LOG_LINE];
		const char* i_str = item->toString(tmp);
		std::cout<<"Add item: "<< i_str <<std::endl;
	}

	const MessageDirection dir = item->getDirection();
	if (dir == MessageDirection::SEND)
		addItem<ItemSendReceive>(m_send_set, policy_type, policy_type_value, item);
	else if (dir == MessageDirection::RECEIVE)
		addItem<ItemSendReceive>(m_receive_set, policy_type, policy_type_value, item);
	else {
		addItem<ItemSendReceive>(m_send_set, policy_type, policy_type_value, item);
		addItem<ItemSendReceive>(m_receive_set, policy_type, policy_type_value, item);
	}
}

void NaivePolicyDb::addItem(const PolicyType policy_type,
							const PolicyTypeValue policy_type_value,
							ItemOwn* const item) {
	if (tslog::enabled()) {
		char tmp[MAX_LOG_LINE];
		const char* i_str = item->toString(tmp);
		std::cout<<"Add item: "<< i_str <<std::endl;
	}

	addItem<ItemOwn>(m_own_set, policy_type, policy_type_value, item);
}



bool NaivePolicyDb::getPolicy(const ItemType item_type,
							  const PolicyType policy_type,
							  const PolicyTypeValue policy_type_value,
							  const NaivePolicyDb::Policy<ItemOwn>*& policy) const {
	return this->template getPolicy<ItemOwn>(m_own_set, policy_type, policy_type_value, policy);
}

bool NaivePolicyDb::getPolicy(const ItemType item_type,
							  const PolicyType policy_type,
							  const PolicyTypeValue policy_type_value,
							  const NaivePolicyDb::Policy<ItemSendReceive>*& policy) const {
	switch (item_type) {
	case ItemType::SEND:
		return this->template getPolicy<ItemSendReceive>(m_send_set, policy_type, policy_type_value, policy);
	case ItemType::RECEIVE:
		return this->template getPolicy<ItemSendReceive>(m_receive_set, policy_type, policy_type_value, policy);
	default:
		return false;
	}
}
