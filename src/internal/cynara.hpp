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

#ifndef _CYNARA_HPP
#define _CYNARA_HPP

#include <cynara-client.h>
#include <cynara-session.h>
#include <string>

#include <pthread.h>

namespace ldp_cynara {
	enum class CynaraResult : uint8_t {
		ALLOW,
		DENY,
		ERROR_CHECK,
		ERROR_INIT
	};
    class Cynara {
	private:
		static pthread_mutex_t __mutex;
		cynara* __cynara;
		const char* __session;
		bool __inited;
		Cynara();
		~Cynara();

		bool init();
		static Cynara& getInstance();
	public:

		static CynaraResult check(const char* label, const char* privilege, const char* uid);
    };
} //namespace
#endif
