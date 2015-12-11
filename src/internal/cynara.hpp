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
//#include <unistd.h>
//#include <stdio.h>

namespace _ldp_cynara {
    class Cynara {
        private:
            cynara* __cynara;
            std::string __session;

            Cynara() {
                int r = cynara_initialize(&__cynara, NULL);
                if (r != CYNARA_API_SUCCESS)
                    throw std::runtime_error("Cynara initialization failed");

                __session = cynara_session_from_pid(getpid());
            }

            ~Cynara() {
                int r = cynara_finish(__cynara);
                if (r != CYNARA_API_SUCCESS) {
                    //TODO: reaction
                }
            }

            static Cynara& get_instance() {
                static Cynara __self;
                return __self;
            }

        public:
            static std::string get_session() {
                Cynara& c = Cynara::get_instance();
                c.__session = cynara_session_from_pid(getpid());
                return c.__session;
            }

            static bool check(std::string label, std::string privilege, std::string uid, std::string session = "") {
                Cynara& c = Cynara::get_instance();
                const char* _label="";
                const char* _session="";
                const char* _uid="";
                const char* _privilege="";

                /**
                workaround. C-str() returns wrong pointer to str
                when std::string == ""
                */
                if (!label.empty())
                    _label=label.c_str();

                if (session == "")
                    session =  c.__session;
                if (!session.empty())
                    _session=session.c_str();

                if (!privilege.empty())
                    _privilege=privilege.c_str();

                if (!uid.empty())
                    _uid=uid.c_str();

                int r = cynara_check (c.__cynara, _label, _session, _uid, _privilege);
                if (r == CYNARA_API_ACCESS_ALLOWED)
                    return true;
                else if (r == CYNARA_API_ACCESS_DENIED)
                    return false;
                else
                    throw std::runtime_error("Cynara check failed");
            }
    };
} //namespace
#endif
