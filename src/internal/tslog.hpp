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

#ifndef _TSLOG_HPP
#define _TSLOG_HPP

#include <iostream>
#include <thread>
#include <pthread.h>
#include <stdlib.h>

typedef std::ostream& (*t_ManFun)(std::ostream&);

namespace tslog
{
	int8_t g_verbosity; // <0 disable 0 brief >0 verbose

	bool get_log_env(char const *name) {
		char const *ldp_log_mode = getenv(name);
		return ldp_log_mode && '0' != *ldp_log_mode;
	}

	void init() {
		g_verbosity = get_log_env("LDP_LOG") ? get_log_env("LDP_VERBOSE") : -1;
	}

	bool enabled() { return g_verbosity >= 0; }
	bool verbose() { return g_verbosity > 0; }
}

#endif
