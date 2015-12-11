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

#ifndef _XML_PARSER_HPP
#define _XML_PARSER_HPP

#include <map>
#include <thread>
#include <future>
#include <boost/noncopyable.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <boost/functional/hash.hpp>
#include <dirent.h>
#include <libgen.h>
#include "timer.hpp"
#include "xml_policy.hpp"

namespace _ldp_xml_parser
{
    class XmlAsyncParser : boost::noncopyable
    {
        public:
            XmlAsyncParser() {
            }

            virtual ~XmlAsyncParser() {
            }

            ErrCode parse_policy(const std::string bus, const std::string fname, const std::chrono::milliseconds timeout) {
                set_policy_bus_filename(bus, fname);
                m_xml_policy.init();
                ErrCode err = parse(timeout);
                return err;
            }

            ErrCode can_send(const std::string bus,
                    const std::string user,
                    const std::string group,
                    const std::string label,
                    const std::string destination,
                    const std::string path,
                    const std::string interface,
                    const std::string member,
                    const std::string type) {
                std::vector<std::string> idx_v = { user, group, destination, path, interface, member, type };
                return m_xml_policy.can_send_to(bus, idx_v, label);
            }

            ErrCode can_recv(const std::string bus,
                    const std::string user,
                    const std::string group,
                    const std::string label,
                    const std::string sender,
                    const std::string path,
                    const std::string interface,
                    const std::string member,
                    const std::string type) {
                std::vector<std::string> idx_v = { user, group, sender, path, interface, member, type };
                return m_xml_policy.can_recv_from(bus, idx_v, label);
            }

            ErrCode can_own(const std::string bus,
                    const std::string user,
                    const std::string group,
                    const std::string service) {
                std::vector<std::string> idx_v = { user, group, service };
                return m_xml_policy.can_own_what(bus, idx_v);
            }


        private:
            //IO operation
            std::string m_bus;
            std::string m_filename;
            static std::map<std::string, std::size_t> m_hashes;
            static std::mutex m_io_xml_mtx;

            //Data obtained from XML
            static XmlPolicy m_xml_policy;

            //Called by calling user thread
            void set_policy_bus_filename(const std::string& bus, const std::string& fname) {
                m_filename = fname;
                m_bus = bus;
            }

            const std::string& get_policy_bus() const {
                return m_bus;
            }

            const std::string& get_policy_filename() const {
                return m_filename;
            }

            ErrCode parse(const std::chrono::milliseconds timeout) {
                ErrCode err;
                std::vector<std::string> incl_files;

                err = parse(get_policy_filename(), incl_files, timeout);
                if(err.is_ok()) {
                    for(const auto& x : incl_files) {
                        err = parse(x, incl_files, timeout);
                        if(err.is_error()) { break; }
                    }
                }

                if(err.is_ok()) {
                    m_xml_policy.print_decision_trees();
                }

                return err;
            }

            ErrCode parse(const std::string& filename, std::vector<std::string>& included_files, const std::chrono::milliseconds timeout) {
                std::pair<ErrCode, std::string> errparam;

                verbose::tout << "=== XML PARSING BEGIN === : " << filename << std::endl;

                auto fut = std::async(std::launch::async, &XmlAsyncParser::async_xml_parse, this, filename);

                auto r = fut.wait_for(timeout);
                if(r == std::future_status::ready) {
                    errparam = fut.get();
                    if(errparam.first.get() >= 0) {
                        get_included_files(filename, errparam.second, included_files);
                    }
                } else if(r == std::future_status::timeout) {
                    errparam.first = ErrCode::timeout("XML parsing timeout");
                }

                verbose::tout << "=== XML PARSING END ===" << std::endl << std::endl;
                tout << "Processing of " << filename << " -> [" << errparam.first.get() << ", " << errparam.first.get_str() << "]" << std::endl;
                return errparam.first;
            }

            //Get all the .conf files within included subdirectory, POSIX style as boost::filesystem is not header-only
            void get_included_files(const std::string& filename, const std::string& incldir, std::vector<std::string>& files) {
                if(get_policy_filename() == filename && incldir != "") {
                    DIR *dir;
                    struct dirent *ent;
                    std::string fname;
                    std::copy(filename.begin(), filename.end(), fname.begin());
                    std::string dname = dirname(const_cast<char*>(fname.c_str()));
                    dname += (std::string("/") + incldir);
                    files.clear();
                    if((dir = opendir(dname.c_str())) != NULL) {
                        while((ent = readdir(dir)) != NULL) {
                            std::string s(ent->d_name);
                            if(s.find(".conf") != std::string::npos) {
                                files.push_back(dname + std::string("/") + s);
                            }
                        }
                        closedir(dir);

                        tout << std::endl << "includedir for " << filename << " is " << incldir << ", " << files.size() << " included files found:" << std::endl;
                        if(_ldp_tslog::get_enable()) { std::copy(files.begin(), files.end(), std::ostream_iterator<std::string>(std::cout, "\n")); }
                        tout << std::endl;
                    } else {
                        terr << "could not open directory " << dname << std::endl;
                    }
                }
            }

            //All 'async_*' methods are executed in library's internal worker threads
            std::pair<ErrCode, std::string> async_xml_parse(const std::string& filename) {
                std::pair<ErrCode, std::string> ret;
                _ldp_timer::microsec latency;

                try {
                    boost::property_tree::ptree pt;

                    //XML file IO critical section
                    {
                        std::unique_lock<std::mutex> lck(m_io_xml_mtx);
                        _ldp_timer::Timer<_ldp_timer::microsec> t(&latency);

                        std::size_t hash;
                        if(async_xml_parsing_needed(filename, hash)) {
                            read_xml(filename, pt);
                            async_xml_hash_update(filename, hash);
                        }
                    }

                    m_xml_policy.update(get_policy_bus(), pt);

                    ret.second = pt.get("busconfig.includedir", "");

                    ret.first = ErrCode::ok();
                } catch(const boost::property_tree::xml_parser::xml_parser_error& ex) {
                    ret.first = ErrCode::error(ex.what());
                } catch(const boost::property_tree::ptree_error& ex) {
                    ret.first = ErrCode::error(ex.what());
                } catch(...) {
                    ret.first = ErrCode::error(filename + std::string(": unknown error while parsing XML"));
                }

                tout << "XML processing latency: " << latency << std::endl;
                return ret;
            }

            std::size_t async_xml_hash(const std::string& filename) {
                std::size_t seed = 0;
                std::ifstream ifs(filename);
                for(std::string line; getline(ifs, line); ) {
                    boost::hash_combine(seed, line);
                }
                ifs.close();

                return seed;
            }

            void async_xml_hash_update(const std::string& filename, const std::size_t hash) {
                auto r = m_hashes.insert(std::pair<std::string, std::size_t>(filename, hash));
                if(r.second == false) {
                    auto it = r.first;
                    it->second = hash;
                }
            }

            bool async_xml_parsing_needed(const std::string& filename, std::size_t& hash) {
                bool ret = false;
                hash = async_xml_hash(filename);
                auto it = m_hashes.find(filename);
                if(it != m_hashes.end()) {
                    if(hash == it->second) {
                        ret = false;
                    } else {
                        ret = true;
                    }
                } else {
                    ret = true;
                }
                return ret;
            }

    };
    std::map<std::string, std::size_t> XmlAsyncParser::m_hashes;
    std::mutex XmlAsyncParser::m_io_xml_mtx;
    XmlPolicy XmlAsyncParser::m_xml_policy;
} //namespace

#endif
