#include "naive_policy_db.hpp"

using namespace ldp_xml_parser;



NaivePolicyDb::~NaivePolicyDb() {
}

NaivePolicyDb::PolicyOwn::PolicyOwn(){
	treeRootPtr = new struct TreeNode;
	treeRootPtr->__decisionItem = {Decision::ANY, NULL};
	treeRootPtr->__nameChar = '\0';
	treeRootPtr->__is_prefix = false;
	for(int i = 0; i < MAX_CHILDREN; i++){
		treeRootPtr->children[i] = NULL;
	}
}

NaivePolicyDb::PolicyOwn::~PolicyOwn(){
	nodeRemove(&treeRootPtr);
}

void NaivePolicyDb::PolicyOwn::nodeRemove(TreeNode **node){
	if (!*node) {
		return;
	}
	for(int i = 0 ; i < MAX_CHILDREN; i++){
		if ((*node)->children[i] != NULL) {
			nodeRemove(&(*node)->children[i]);
		}
	}
	delete *node;
	*node = NULL;
}

void NaivePolicyDb::addItem(const PolicyType policy_type,
							const PolicyTypeValue policy_type_value,
							ItemSendReceive* const item) {
	if (tslog::enabled()) {
		char tmp[MAX_LOG_LINE];
		const char* i_str = item->toString(tmp);
		std::cout << "Add item: " << i_str << std::endl;
	}

	const MessageDirection dir = item->getDirection();
	if (dir == MessageDirection::SEND) {
		addItem(m_send_set, policy_type, policy_type_value, item);
	} else if (dir == MessageDirection::RECEIVE) {
		addItem(m_receive_set, policy_type, policy_type_value, item);
	} else {
		addItem(m_send_set, policy_type, policy_type_value, item);
		addItem(m_receive_set, policy_type, policy_type_value, item);
	}
}

void NaivePolicyDb::addItem(const PolicyType policy_type,
							const PolicyTypeValue policy_type_value,
							ItemOwn* const item) {
	if (tslog::enabled()) {
		char tmp[MAX_LOG_LINE];
		const char* i_str = item->toString(tmp);
		std::cout << "Add item: " << i_str << std::endl;
	}

	addItem(m_own_set, policy_type, policy_type_value, item);
}



bool NaivePolicyDb::getPolicy(const ItemType item_type,
							  const PolicyType policy_type,
							  const PolicyTypeValue policy_type_value,
							  const NaivePolicyDb::PolicyOwn*& policy) const {
	return this->getPolicyOwn(m_own_set, policy_type, policy_type_value, policy);
}

bool NaivePolicyDb::getPolicy(const ItemType item_type,
							  const PolicyType policy_type,
							  const PolicyTypeValue policy_type_value,
							  const NaivePolicyDb::PolicySR*& policy) const {
	switch (item_type) {
	case ItemType::SEND:
		return this->getPolicySR(m_send_set, policy_type, policy_type_value, policy);
	case ItemType::RECEIVE:
		return this->getPolicySR(m_receive_set, policy_type, policy_type_value, policy);
	default:
		return false;
	}
}


NaivePolicyDb::PolicySR::PolicyConstIterator::PolicyConstIterator(const std::vector< ItemSendReceive* > & items, int position)
	: m_items(items), m_index(position) {
}

ItemSendReceive* const& NaivePolicyDb::PolicySR::PolicyConstIterator::operator*() const {
	return m_items[m_index];
}


typename NaivePolicyDb::PolicySR::PolicyConstIterator& NaivePolicyDb::PolicySR::PolicyConstIterator::operator++() {
	if (m_index >= 0)
		--m_index;
	return *this;
}


bool NaivePolicyDb::PolicySR::PolicyConstIterator::operator!=(const PolicyConstIterator& it) const {
	return m_index != it.m_index;
}


NaivePolicyDb::PolicySR::PolicyIterator::PolicyIterator(std::vector< ItemSendReceive* > & items, int position)
	: m_items(items), m_index(position) {
}


ItemSendReceive*& NaivePolicyDb::PolicySR::PolicyIterator::operator*() {
	return m_items[m_index];
}


typename NaivePolicyDb::PolicySR::PolicyIterator& NaivePolicyDb::PolicySR::PolicyIterator::operator++() {
	if (m_index >= 0)
		--m_index;
	return *this;
}


bool NaivePolicyDb::PolicySR::PolicyIterator::operator!=(const PolicyIterator& it) const {
	return m_index != it.m_index;
}


NaivePolicyDb::PolicySR::PolicyIterator NaivePolicyDb::PolicySR::begin() {
	int s = m_items.size() - 1;
	return NaivePolicyDb::PolicySR::PolicyIterator(m_items, s);
}


NaivePolicyDb::PolicySR::PolicyIterator NaivePolicyDb::PolicySR::end() {
	return NaivePolicyDb::PolicySR::PolicyIterator(m_items, -1);
}


NaivePolicyDb::PolicySR::PolicyConstIterator NaivePolicyDb::PolicySR::begin() const {
	int s = m_items.size() - 1;
	return NaivePolicyDb::PolicySR::PolicyConstIterator(m_items, s);
}


NaivePolicyDb::PolicySR::PolicyConstIterator NaivePolicyDb::PolicySR::end() const {
	return NaivePolicyDb::PolicySR::PolicyConstIterator(m_items, -1);
}


void NaivePolicyDb::PolicySR::addItem(ItemSendReceive* item) {
	m_items.push_back(item);
}


const struct TreeNode* NaivePolicyDb::PolicyOwn::getTreeRoot() const{
	assert(treeRootPtr);
	return treeRootPtr;
}
void NaivePolicyDb::PolicyOwn::addItem(ItemOwn* item) {
	const char *name = item->getName();
	/*TODO move this few layers up*/
	if(!name){
		return;
	}

	struct TreeNode *node = treeRootPtr;
	assert(node);

	const char *tmp = name;
	while (tmp && *tmp != '\0') {
		if (char_map[*tmp] > 64) {
			/*Forbidden char*/
			return;
		}
		tmp++;
	}
	int childIndex = 0;
	while (name && *name != '\0') {
		childIndex = char_map[*name];
		if (node->children[childIndex] == NULL){
			node->children[childIndex] = new struct TreeNode;
			node->children[childIndex]->__decisionItem = {Decision::ANY, NULL};
			node->children[childIndex]->__nameChar = *name;
			node->children[childIndex]->__is_prefix = false;
			for(int k = 0; k < MAX_CHILDREN; k++){
				node->children[childIndex]->children[k] = NULL;
			}

			node = node->children[childIndex];
		} else {
			node = node->children[childIndex];
		}
		name++;
	}
	node->__decisionItem = item->getDecision();
	node->__is_prefix = item->isPrefix();
}


bool NaivePolicyDb::getPolicySR(const NaivePolicyDb::PolicyTypeSetSR& set,
							  const PolicyType policy_type,
							  const PolicyTypeValue policy_type_value,
							  const NaivePolicyDb::PolicySR*& policy) const
{
	if (tslog::enabled())
		std::cout << "---policy_type =";
	try {
		switch (policy_type) {
		case PolicyType::CONTEXT:
			if (tslog::enabled())
				std::cout << "CONTEXT =" << (int)policy_type_value.context << std::endl;
			policy = &set.context[static_cast<std::size_t>(policy_type_value.context) ];
			return true;
		case PolicyType::USER:
			if (tslog::enabled())
				std::cout << "USER =" << (int)policy_type_value.user << std::endl;
			policy = &set.user.at(policy_type_value.user);
			return true;
		case PolicyType::GROUP:
			if (tslog::enabled())
				std::cout << "GROUP = " << (int)policy_type_value.group << std::endl;
			policy = &set.group.at(policy_type_value.group);
			return true;
		}
	} catch (std::out_of_range&)
	{
		if (tslog::verbose())
			std::cout << "GetPolicy: Out of Range exception\n";
	}
	if (tslog::enabled())
		std::cout << "NO POLICY\n";
	return false;
}


void NaivePolicyDb::addItem(NaivePolicyDb::PolicyTypeSetSR& set,
							const PolicyType policy_type,
							const PolicyTypeValue policy_type_value,
							ItemSendReceive* const item) {
	switch (policy_type) {
	case PolicyType::CONTEXT:
		set.context[static_cast<std::size_t>(policy_type_value.context)].addItem(item);
		break;
	case PolicyType::USER:
		set.user[policy_type_value.user].addItem(item);
		break;
	case PolicyType::GROUP:
		set.group[policy_type_value.group].addItem(item);
		break;
	}
}


bool NaivePolicyDb::getPolicyOwn(const NaivePolicyDb::PolicyTypeSetOwn& set,
							  const PolicyType policy_type,
							  const PolicyTypeValue policy_type_value,
							  const NaivePolicyDb::PolicyOwn*& policy) const
{
	if (tslog::enabled())
		std::cout << "---policy_type =";
	try {
		switch (policy_type) {
		case PolicyType::CONTEXT:
			if (tslog::enabled())
				std::cout << "CONTEXT =" << (int)policy_type_value.context << std::endl;
			policy = &set.context[static_cast<std::size_t>(policy_type_value.context) ];
			return true;
		case PolicyType::USER:
			if (tslog::enabled())
				std::cout << "USER =" << (int)policy_type_value.user << std::endl;
			policy = &set.user.at(policy_type_value.user);
			return true;
		case PolicyType::GROUP:
			if (tslog::enabled())
				std::cout << "GROUP = " << (int)policy_type_value.group << std::endl;
			policy = &set.group.at(policy_type_value.group);
			return true;
		}
	} catch (std::out_of_range&)
	{
		if (tslog::verbose())
			std::cout << "GetPolicy: Out of Range exception\n";
	}
	if (tslog::enabled())
		std::cout << "NO POLICY\n";
	return false;
}


void NaivePolicyDb::addItem(NaivePolicyDb::PolicyTypeSetOwn& set,
							const PolicyType policy_type,
							const PolicyTypeValue policy_type_value,
							ItemOwn* const item) {
	switch (policy_type) {
	case PolicyType::CONTEXT:
		set.context[static_cast<std::size_t>(policy_type_value.context)].addItem(item);
		break;
	case PolicyType::USER:
		set.user[policy_type_value.user].addItem(item);
		break;
	case PolicyType::GROUP:
		set.group[policy_type_value.group].addItem(item);
		break;
	}
}
