/*
 * Copyright (c) 2015 Samsung Electronics Co., Ltd All Rights Reserved
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
*/
#ifndef _NAIVE_DB_H
#define _NAIVE_DB_H

#include <map>
#include <vector>
#include "policy.hpp"
#include <cstdlib>
#include "tslog.hpp"

namespace ldp_xml_parser
{
	class NaivePolicyDb {
	public:
		template <class T>
		class Policy {
		private:
			std::vector<T*> m_items;
		public:
			class PolicyConstIterator {
			private:
				const std::vector<T*>& m_items;
				int m_index;
			public:
				PolicyConstIterator(const std::vector<T*>& items, int position);
				T* const& operator*() const;
				PolicyConstIterator& operator++();
				bool operator!=(const PolicyConstIterator& it) const;
			};

			class PolicyIterator {
			private:
				std::vector<T*>& m_items;
				int m_index;
			public:
				PolicyIterator(std::vector<T*>& items, int position);
				T*& operator*();
				PolicyIterator& operator++();
				bool operator!=(const PolicyIterator& it) const;
			};

			PolicyIterator begin();
			PolicyIterator end();
			PolicyConstIterator begin() const;
			PolicyConstIterator end() const;
			void addItem(T* item);
		};

		~NaivePolicyDb();

		bool getPolicy(const ItemType item_type,
					   const PolicyType policy_type,
					   const PolicyTypeValue policy_type_value,
					   const Policy<ItemOwn>*& policy) const;

		bool getPolicy(const ItemType item_type,
					   const PolicyType policy_type,
					   const PolicyTypeValue policy_type_value,
					   const Policy<ItemSendReceive>*& policy) const;

		void addItem(const PolicyType policy_type,
					 const PolicyTypeValue policy_type_value,
					 ItemOwn* const item);

		void addItem(const PolicyType policy_type,
					 const PolicyTypeValue policy_type_value,
					 ItemSendReceive* const item);
	private:
		template <class T>
		struct PolicyTypeSet {
			Policy<T> context[static_cast<std::size_t>(ContextType::MAX)];
			std::map<uid_t, Policy<T> > user;
			std::map<gid_t, Policy<T> > group;
		};

		PolicyTypeSet<ItemOwn> m_own_set;
		PolicyTypeSet<ItemSendReceive> m_send_set;
		PolicyTypeSet<ItemSendReceive> m_receive_set;
		template <class T>
		void addItem(PolicyTypeSet<T>& set,
					 const PolicyType policy_type,
					 const PolicyTypeValue policy_type_value,
					 T* const item);
		template <class T>
		bool getPolicy(const PolicyTypeSet<T>& set,
					   const PolicyType policy_type,
					   const PolicyTypeValue policy_type_value,
					   const Policy<T>*& policy) const;
	};


template <class T>
NaivePolicyDb::Policy<T>::PolicyConstIterator::PolicyConstIterator(const std::vector< T* > & items, int position)
	: m_items(items), m_index(position) {
}

template <class T>
T* const& NaivePolicyDb::Policy<T>::PolicyConstIterator::operator*() const {
	return m_items[m_index];
}

template <class T>
typename NaivePolicyDb::Policy<T>::PolicyConstIterator& NaivePolicyDb::Policy<T>::PolicyConstIterator::operator++() {
	if (m_index >= 0)
		--m_index;
	return *this;
}

template <class T>
bool NaivePolicyDb::Policy<T>::PolicyConstIterator::operator!=(const PolicyConstIterator& it) const {
	return m_index != it.m_index;
}

template <class T>
NaivePolicyDb::Policy<T>::PolicyIterator::PolicyIterator(std::vector< T* > & items, int position)
	: m_items(items), m_index(position) {
}

template <class T>
T*& NaivePolicyDb::Policy<T>::PolicyIterator::operator*() {
	return m_items[m_index];
}

template <class T>
typename NaivePolicyDb::Policy<T>::PolicyIterator& NaivePolicyDb::Policy<T>::PolicyIterator::operator++() {
	if (m_index >= 0)
		--m_index;
	return *this;
}

template <class T>
bool NaivePolicyDb::Policy<T>::PolicyIterator::operator!=(const PolicyIterator& it) const {
	return m_index != it.m_index;
}

template <class T>
typename NaivePolicyDb::Policy<T>::PolicyIterator NaivePolicyDb::Policy<T>::begin() {
	int s = m_items.size() - 1;
	return NaivePolicyDb::Policy<T>::PolicyIterator(m_items, s);
}

template <class T>
typename NaivePolicyDb::Policy<T>::PolicyIterator NaivePolicyDb::Policy<T>::end() {
	return NaivePolicyDb::Policy<T>::PolicyIterator(m_items, -1);
}

template <class T>
typename NaivePolicyDb::Policy<T>::PolicyConstIterator NaivePolicyDb::Policy<T>::begin() const {
	int s = m_items.size() - 1;
	return NaivePolicyDb::Policy<T>::PolicyConstIterator(m_items, s);
}

template <class T>
typename NaivePolicyDb::Policy<T>::PolicyConstIterator NaivePolicyDb::Policy<T>::end() const {
	return NaivePolicyDb::Policy<T>::PolicyConstIterator(m_items, -1);
}

template <class T>
void NaivePolicyDb::Policy<T>::addItem(T* item) {
	m_items.push_back(item);
}

template <class T>
bool NaivePolicyDb::getPolicy(const NaivePolicyDb::PolicyTypeSet<T>& set,
							  const PolicyType policy_type,
							  const PolicyTypeValue policy_type_value,
							  const NaivePolicyDb::Policy<T>*& policy) const
{
	if (tslog::enabled())
		std::cout<<"---policy_type =";
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
	} catch (...)
	{
	}
	if (tslog::enabled())
		std::cout << "NO POLICY\n";
	return false;
}

template <class T>
void NaivePolicyDb::addItem(NaivePolicyDb::PolicyTypeSet<T>& set,
							const PolicyType policy_type,
							const PolicyTypeValue policy_type_value,
							T* const item) {
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

}

#endif
