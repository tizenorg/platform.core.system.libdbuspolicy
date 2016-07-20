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

		class PolicySR {
		private:
			std::vector<ItemSendReceive*> m_items;
		public:
			class PolicyConstIterator {
			private:
				const std::vector<ItemSendReceive*>& m_items;
				int m_index;
			public:
				PolicyConstIterator(const std::vector<ItemSendReceive*>& items, int position);
				ItemSendReceive* const& operator*() const;
				PolicyConstIterator& operator++();
				bool operator!=(const PolicyConstIterator& it) const;
			};

			class PolicyIterator {
			private:
				std::vector<ItemSendReceive*>& m_items;
				int m_index;
			public:
				PolicyIterator(std::vector<ItemSendReceive*>& items, int position);
				ItemSendReceive*& operator*();
				PolicyIterator& operator++();
				bool operator!=(const PolicyIterator& it) const;
			};

			PolicyIterator begin();
			PolicyIterator end();
			PolicyConstIterator begin() const;
			PolicyConstIterator end() const;
			void addItem(ItemSendReceive* item);
		};


		class PolicyOwn {
			private:
				struct TreeNode *treeRootPtr = NULL;
				void nodeRemove(TreeNode **node);
			public:
				PolicyOwn();
				~PolicyOwn();
				void addItem(ItemOwn* item);
				const TreeNode* getTreeRoot() const;
		};

		~NaivePolicyDb();

		bool getPolicy(const ItemType item_type,
					   const PolicyType policy_type,
					   const PolicyTypeValue policy_type_value,
					   const PolicyOwn*& policy) const;

		bool getPolicy(const ItemType item_type,
					   const PolicyType policy_type,
					   const PolicyTypeValue policy_type_value,
					   const PolicySR*& policy) const;

		void addItem(const PolicyType policy_type,
					 const PolicyTypeValue policy_type_value,
					 ItemOwn* const item);

		void addItem(const PolicyType policy_type,
					 const PolicyTypeValue policy_type_value,
					 ItemSendReceive* const item);

	private:

		struct PolicyTypeSetOwn {
			PolicyOwn context[static_cast<std::size_t>(ContextType::MAX)];
			std::map<uid_t, PolicyOwn > user;
			std::map<gid_t, PolicyOwn > group;
		};

		struct PolicyTypeSetSR {
			PolicySR context[static_cast<std::size_t>(ContextType::MAX)];
			std::map<uid_t, PolicySR > user;
			std::map<gid_t, PolicySR > group;
		};

		PolicyTypeSetOwn m_own_set;
		PolicyTypeSetSR m_send_set;
		PolicyTypeSetSR m_receive_set;

		void addItem(PolicyTypeSetSR& set,
					 const PolicyType policy_type,
					 const PolicyTypeValue policy_type_value,
					 ItemSendReceive* const item);

		bool getPolicySR(const PolicyTypeSetSR& set,
					   const PolicyType policy_type,
					   const PolicyTypeValue policy_type_value,
					   const PolicySR*& policy) const;

		void addItem(PolicyTypeSetOwn& set,
					 const PolicyType policy_type,
					 const PolicyTypeValue policy_type_value,
					 ItemOwn* const item);

		bool getPolicyOwn(const PolicyTypeSetOwn& set,
					   const PolicyType policy_type,
					   const PolicyTypeValue policy_type_value,
					   const PolicyOwn*& policy) const;

	};


}
#endif
