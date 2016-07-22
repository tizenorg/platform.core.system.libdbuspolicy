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

#include <set>
#include <boost/noncopyable.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/xml_parser.hpp>
#include <dirent.h>
#include <libgen.h>
#include "libdbuspolicy1-private.hpp"
#include "tslog.hpp"
#include "policy.hpp"

namespace ldp_xml_parser
{
    class XmlParser : boost::noncopyable
    {
        public:
            ErrCode parsePolicy(bool bus,
                    std::string const &fname) {
                ErrCode err = parse(bus, fname);
                return err;
            }

            void registerAdapter(DbAdapter& adapter) {
			    __adapter = &adapter;
            }

        private:
            //IO operation
            static std::set<std::string> __parsed;

            DbAdapter* __adapter;
            //Data obtained from XML

            ErrCode parse(bool bus, std::string const &filename) {
                ErrCode err;
                std::vector<std::string> incl_files;

                err = parse(bus, true, filename, incl_files);
                if (err.is_ok())
                    for(const auto& x : incl_files) {
                        err = parse(bus, false, x, incl_files);
                        if (err.is_error()) break;
                    }
                return err;
            }

            ErrCode parse(bool bus, bool first, const std::string& filename, std::vector<std::string>& included_files) {
                std::pair<ErrCode, std::string> errparam;
				std::vector<std::string> incl_dirs;
				if (tslog::verbose())
					std::cout << "=== XML PARSING BEGIN === : " << filename << '\n';

                errparam = parseXml(bus, filename, incl_dirs);
				for (int i = 0; i < incl_dirs.size(); i++) {
					getIncludedFiles(filename, incl_dirs[i], included_files);
				}

				if (tslog::enabled()) {
					if (tslog::verbose())
						std::cout << "=== XML PARSING END ===\n\n";
					std::cout << "Processing of " << filename << " -> [" << errparam.first.get() << ", " << errparam.first.get_str() << "]\n";
				}
                return errparam.first;
            }

            //Get all the .conf files within included subdirectory, POSIX style as boost::filesystem is not header-only
            void getIncludedFiles(const std::string& filename, const std::string& incldir, std::vector<std::string>& files) {
				DIR *dir;
				struct dirent *ent;
				std::string fname(filename);
				std::string dname = dirname(const_cast<char*>(fname.c_str()));
				if (incldir[0] != '/')
					dname += (std::string("/") + incldir);
				else
					dname = incldir;
				files.clear();
				if((dir = opendir(dname.c_str())) != NULL) {
					while((ent = readdir(dir)) != NULL) {
						std::string s(ent->d_name);
						if(s.find(".conf") != std::string::npos) {
							files.push_back(dname + std::string("/") + s);
						}
					}
					closedir(dir);

					if (tslog::enabled()) {
						std::cout << "\nincludedir for " << filename << " is " << incldir << ", " << files.size() << " included files found:\n";
						std::copy(files.begin(), files.end(), std::ostream_iterator<std::string>(std::cout, "\n"));
						std::cout << '\n';
					}
				} else if (tslog::enabled())
					std::cout << "could not open directory " << dname << '\n';
            }

		std::pair<ErrCode, std::string> parseXml(bool bus, const std::string& filename, std::vector<std::string>& incl_dirs) {
                std::pair<ErrCode, std::string> ret;

				if (__parsed.insert(filename).second)
					try {
						boost::property_tree::ptree pt;
						read_xml(filename, pt);
						if (!pt.empty()) {
                            __adapter->updateDb(bus, pt, incl_dirs);
						}
					} catch(const boost::property_tree::xml_parser::xml_parser_error& ex) {
						ret.first = ErrCode::error(ex.what());
					} catch(const boost::property_tree::ptree_error& ex) {
						ret.first = ErrCode::error(ex.what());
					} catch(...) {
						ret.first = ErrCode::error(filename + std::string(": unknown error while parsing XML"));
					}

                return ret;
            }
    };
} //namespace

#endif
