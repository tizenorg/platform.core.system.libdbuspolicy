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
#ifndef _POLICY_H
#define _POLICY_H

#include <boost/tokenizer.hpp>
#include <boost/property_tree/ptree.hpp>
#include <string>
#define MAX_LOG_LINE 1024

namespace  _ldp_xml_parser
{
	enum class MessageType : uint8_t {
		ANY = 0,
		METHOD_CALL,
		METHOD_RETURN,
		ERROR,
		SIGNAL
	};

	enum class MessageDirection : uint8_t {
		ANY,
		SEND,
		RECEIVE
	};

	enum class ItemType : uint8_t{
		GENERIC,
		OWN,
		SEND,
		RECEIVE
	};

	enum class PolicyType : uint8_t {
		CONTEXT,
		USER,
		GROUP
	};

	enum class ContextType : uint8_t {
		DEFAULT,
		MANDATORY,
		MAX
	};

	enum class Decision : uint8_t {
		ANY,
		ALLOW,
		DENY,
		CHECK
	};

	union PolicyTypeValue {
		PolicyTypeValue();
		PolicyTypeValue(ContextType type);
		PolicyTypeValue(uid_t us);
		ContextType context;
		uid_t user;
		gid_t group;
	};

	class ItemBuilder;

	class Item {
	protected:
		Decision _decision;
		const char* _privilege;
		bool _is_owner;
	public:
		friend class ItemBuilder;
		Item(Decision decision = Decision::ANY, const char* privilege = NULL, bool isOwner = false);
		virtual ~Item();
		virtual bool match(const Item& item) const;
		virtual bool match(const Item* item) const;
		virtual Decision getDecision() const;
		virtual const char*  getPrivilege() const;
		virtual ItemType getType() const;
		virtual const char* toString(char* str) const;
	};

	class ItemOwn : public Item {
	private:
		const char* __name;
		bool __is_prefix;
	public:
		friend class ItemBuilder;
		ItemOwn(const char* name = NULL,
				bool is_prefix = false,
				Decision decision = Decision::ANY,
				const char* privilege = NULL);
		virtual ~ItemOwn();
		virtual bool match(const Item* item) const;
		virtual ItemType getType() const;
		virtual const char* toString(char* str) const;
	};

	class ItemSendReceive : public Item {
		const char** __names;
		const char* __interface;
		const char* __member;
		const char* __path;
		MessageType __type;
		MessageDirection __direction;
	public:
		friend class ItemBuilder;
		ItemSendReceive(const char** names = NULL,
						const char* interface = NULL,
						const char* member = NULL,
						const char* path = NULL,
						MessageType type = MessageType::ANY,
						MessageDirection direction = MessageDirection::ANY,
						Decision decision = Decision::ANY,
						const char* privilege = NULL);
		virtual ~ItemSendReceive();
		virtual bool match(const Item* item) const;
		MessageDirection getDirection() const;
		virtual ItemType getType() const;
		virtual const char* toString(char* str) const;
	};

	class ItemBuilder {
	private:
		Item* __current;
		Decision __delayed_decision;
		const char* __delayed_privilege;
		ItemOwn* getOwnItem();
		ItemSendReceive* getSendReceiveItem();
		char* duplicate(const char* str);
		void prepareItem();
	public:
		ItemBuilder();
		~ItemBuilder();
		Item* generateItem();
		void reset();
		void addUser(const char* name);
		void addGroup(const char* name);
		void addOwner(const char* owner);
		void addName(const char* name);
		void addInterface(const char* interface);
		void addMember(const char* member);
		void addPath(const char* path);
		void addMessageType(MessageType type);
		void addDirection(MessageDirection direction);
		void addPrivilege(const char* privilege);
		void addDecision(Decision decision);
		void setPrefix(bool value);
	};

	class NaivePolicyDb;
	class DbAdapter {
	private:
		enum state {
			NONE,
			POLICY,
			ALLOW_DENY_CHECK
		};
		NaivePolicyDb& __system_db;
		NaivePolicyDb& __session_db;
		bool __attr;
		state __tag_state;
		ItemBuilder __builder;
		void updateDecision(const boost::property_tree::ptree::value_type& v,
							PolicyType& policy_type,
							PolicyTypeValue& policy_type_value,
							state& tag,
							bool& attr);
		void xmlTraversal(bool bus,
						  const boost::property_tree::ptree& pt,
						  state tag,
						  PolicyType& policy_type,
						  PolicyTypeValue& policy_type_value,
						  bool attr = false,
						  int level = 0);
	public:
		DbAdapter(NaivePolicyDb& system, NaivePolicyDb& session);
		void updateDb(bool bus, boost::property_tree::ptree& xmlTree);
		static uid_t convertToUid(const char* user);
		static gid_t convertToGid(const char* group);
	};
}
#endif
