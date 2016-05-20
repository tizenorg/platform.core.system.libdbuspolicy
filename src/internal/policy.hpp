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

namespace  _ldp_xml_parser
{
	enum MessageType {
		ANY = 0,
		METHOD_CALL,
		METHOD_RETURN,
		ERROR,
		SIGNAL
	};

	enum MessageDirection {
		DIRECTION_ANY,
		DIRECTION_SEND,
		DIRECTION_RECEIVE
	};

	enum ItemType {
		ITEM_GENERIC,
		ITEM_OWN,
		ITEM_USER,
		ITEM_GROUP,
		ITEM_SEND,
		ITEM_RECEIVE,
	};

	enum PolicyType {
		POLICY_CONTEXT,
		POLICY_USER,
		POLICY_GROUP,
		POLICY_CONSOLE,
	};

	enum ContextType {
		CONTEXT_DEFAULT,
		CONTEXT_MANDATORY,
		CONTEXT_TYPE_MAX
	};

	enum ConsoleType {
		CONSOLE_ON,
		CONSOLE_OFF,
		CONSOLE_TYPE_MAX
	};

	enum Decision {
		NO_DECISION,
		DECISION_ALLOW,
		DECISION_DENY,
		DECISION_CYNARA_CHECK
	};

	union PolicyTypeValue {
		PolicyTypeValue();
		PolicyTypeValue(ConsoleType type);
		PolicyTypeValue(ContextType type);
		PolicyTypeValue(uid_t us);
		ConsoleType console;
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
		Item(Decision decision = NO_DECISION, const char* privilege = NULL, bool isOwner = false);
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
				Decision decision = NO_DECISION,
				const char* privilege = NULL);
		virtual ~ItemOwn();
		virtual bool match(const Item* item) const;
		virtual ItemType getType() const;
		virtual const char* toString(char* str) const;
	};

	class ItemUser : public Item {
	private:
		const char* __name;
	public:
		friend class ItemBuilder;
		ItemUser(const char* name = NULL,
				 Decision decision = NO_DECISION,
				 const char* privilege = NULL);
		virtual ~ItemUser();
		virtual bool match(const Item* item) const;
		virtual ItemType getType() const;
	};

	class ItemGroup : Item {
	private:
		const char* __name;
	public:
		friend class ItemBuilder;
		ItemGroup(const char* name = NULL,
				  Decision decision = NO_DECISION,
				  const char* privilege = NULL);
		virtual ~ItemGroup();
		virtual bool match(const Item* item) const;
		virtual ItemType getType() const;
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
						MessageType type = ANY,
						MessageDirection direction = DIRECTION_ANY,
						Decision decision = NO_DECISION,
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
		ItemUser* getUserItem();
		ItemGroup* getGroupItem();
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

	class IPolicyDb;
	class DbAdapter {
	private:
		enum state {
			NONE,
			POLICY,
			ALLOW_DENY_CHECK
		};
		IPolicyDb& __system_db;
		IPolicyDb& __session_db;
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
		DbAdapter(IPolicyDb& system, IPolicyDb& session);
		void updateDb(bool bus, boost::property_tree::ptree& xmlTree);
		static uid_t convertToUid(const char* user);
		static gid_t convertToGid(const char* group);
	};

/* Interfaces */
	class IPolicyDb {
	public:
		virtual void addItem(const PolicyType policy_type,
							 const PolicyTypeValue policy_type_value,
							 Item* const item) = 0;
	};

	class IPolicyChecker {
	public:
		virtual DbAdapter& generateAdapter() = 0;
		virtual bool check(bool bus_type,
						   uid_t uid,
						   gid_t gid,
						   const char* const label,
						   const char* const name) = 0;
		virtual bool check(bool bus_type,
						   uid_t uid,
						   gid_t gid,
						   const char* const label,
						   const char** const names,
						   const char* const interface,
						   const char* const member,
						   const char* const path,
						   MessageType message_type,
						   MessageDirection message_dir) = 0;
	};
}
#endif
