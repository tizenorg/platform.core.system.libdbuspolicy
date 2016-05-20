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

namespace ldp_xml_parser
{
	class NaivePolicyDb {
	public:
		class Policy {
		private:
			std::vector<Item*> m_items;
		public:
			class PolicyConstIterator {
			private:
				const std::vector<Item*>& m_items;
				int m_index;
			public:
				PolicyConstIterator(const std::vector<Item*>& items, int position);
				Item* const& operator*() const;
				PolicyConstIterator& operator++();
				bool operator!=(const PolicyConstIterator& it) const;
			};

			class PolicyIterator {
			private:
				std::vector<Item*>& m_items;
				int m_index;
			public:
				PolicyIterator(std::vector<Item*>& items, int position);
				Item*& operator*();
				PolicyIterator& operator++();
				bool operator!=(const PolicyIterator& it) const;
			};

			PolicyIterator begin();
			PolicyIterator end();
			PolicyConstIterator begin() const;
			PolicyConstIterator end() const;
			void addItem(Item* item);
		};

		~NaivePolicyDb();

		const Policy* getPolicy(const ItemType item_type,
								const PolicyType policy_type,
								const PolicyTypeValue policy_type_value);

		void addItem(const PolicyType policy_type,
					 const PolicyTypeValue policy_type_value,
					 Item* const item);
	private:
		struct PolicyTypeSet {
			Policy context[static_cast<std::size_t>(ContextType::MAX)];
			std::map<uid_t, Policy> user;
			std::map<gid_t, Policy> group;
		};

		PolicyTypeSet m_own_set;
		PolicyTypeSet m_send_set;
		PolicyTypeSet m_receive_set;
		void addItem(PolicyTypeSet& set,
							 const PolicyType policy_type,
							 const PolicyTypeValue policy_type_value,
							 Item* const item);
	};
}

#endif
