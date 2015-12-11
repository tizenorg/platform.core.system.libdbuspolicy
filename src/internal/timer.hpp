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

#ifndef _TIMER_HPP
#define _TIMER_HPP

namespace _ldp_timer
{
    template<typename BaseTimeUnit = std::chrono::nanoseconds>
        class Duration : public BaseTimeUnit {
            public:
                void setNanoTime(std::chrono::nanoseconds nano) {
                    BaseTimeUnit d = std::chrono::duration_cast<BaseTimeUnit>(nano);
                    BaseTimeUnit::operator =(d);
                }

                double getSeconds() {
                    typename BaseTimeUnit::period p;
                    return 1.0 * BaseTimeUnit::count() * p.num/p.den;
                }

                uint64_t getNativeTime() {
                    return BaseTimeUnit::count();
                }

                friend std::ostream& operator<< (std::ostream& os,
                        const Duration<BaseTimeUnit>& d) {
                    typename BaseTimeUnit::period p;
                    std::string unit;
                    switch(p.den/p.num) {
                        case 1000000000:    unit = "ns"; break;
                        case 1000000:       unit = "us"; break;
                        case 1000:          unit = "ms"; break;
                        case 1:             unit = "s";  break;
                    }

                    os << d.count() << " " << unit;
                    return os;
                }
        };

    typedef Duration<std::chrono::nanoseconds> nanosec;
    typedef Duration<std::chrono::microseconds> microsec;
    typedef Duration<std::chrono::milliseconds> millisec;
    typedef Duration<std::chrono::seconds> sec;

    template<typename _T = nanosec>
        class Timer {
            typedef std::chrono::steady_clock CLK;
            CLK::time_point tbegin;
            _T* const pOT;
            public:
            Timer(_T* const pTP)
                : tbegin(CLK::now()), pOT(pTP) {}

            virtual ~Timer() {
                if(pOT)
                    pOT->setNanoTime(CLK::now() - tbegin);
            }
        };
}

#endif // _TIMER_HPP
