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
#include <mutex>

namespace _ldp_tslog
{
    typedef std::ostream& (*t_ManFun)(std::ostream&);

    namespace {
        static constexpr bool LOG_ENABLE = false;
        static constexpr bool LOG_VERBOSE = false;
    }

    const bool get_verbose() {
        return LOG_VERBOSE;
    }

    const bool get_enable() {
        return LOG_ENABLE;
    }

    class TsLog
    {
        private:
            static bool m_verbose;
            static std::mutex m_mtx;
            std::ostream& m_os;
            bool m_enable;

            template<typename T>
                TsLog& lckLog(const T& t) {
                    if(m_enable) {
                        std::unique_lock<std::mutex> lck(m_mtx);
                        m_os << t;
                    }
                    return *this;
                }

        public:
            TsLog() = delete;

            explicit TsLog(std::ostream& os, bool enable = true)
                : m_os(os), m_enable(enable) {}

            virtual ~TsLog() {}

            template<typename T>
                TsLog& operator<< (const T& t) {
                    return lckLog<T>(t);
                }

            TsLog& operator<< (t_ManFun f) {
                return lckLog<t_ManFun>(f);
            }

    };
    std::mutex TsLog::m_mtx;
}

namespace {
    //Thread-safe loggers
    _ldp_tslog::TsLog tout(std::cout, _ldp_tslog::get_enable());
    _ldp_tslog::TsLog terr(std::cerr, _ldp_tslog::get_enable());

    namespace verbose {
        _ldp_tslog::TsLog tout(std::cout, _ldp_tslog::get_enable() && _ldp_tslog::get_verbose());
        _ldp_tslog::TsLog terr(std::cerr, _ldp_tslog::get_enable() && _ldp_tslog::get_verbose());
    }
} //namespace

#endif
