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

#ifndef _LIBDBUSPOLICY1_PRIVATE_HPP
#define _LIBDBUSPOLICY1_PRIVATE_HPP

#include <string>

namespace {
    class ErrCode {
        int m_err;
        std::string m_err_str;
        ErrCode(int e, const std::string& s) : m_err(e), m_err_str(s) {}
        public:
            ErrCode() : m_err(0), m_err_str("") {}
            virtual ~ErrCode() {}

            static ErrCode ok() {
                return ErrCode(0, "OK");
            }

            template<typename T>
            static ErrCode ok(T e) {
                return ErrCode((e > 0) ? e : 0, "OK");
            }

            static ErrCode error(const std::string& what) {
                return ErrCode(-1, what);
            }

            static ErrCode timeout(const std::string& what) {
                return ErrCode(-99, std::string("Timeout: ") + what);
            }

            int get() const {
                return m_err;
            }

            const std::string& get_str() const {
                return m_err_str;
            }

            bool is_ok() const {
                return (m_err >= 0);
            }

            bool is_true() const {
                return (m_err > 0);
            }

            bool is_false() const {
                return (m_err == 0);
            }

            bool is_error() const {
                return (m_err < 0);
            }

    };
} //namespace

#endif
