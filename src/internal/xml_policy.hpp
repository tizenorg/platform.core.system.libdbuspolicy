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

#ifndef _XML_POLICY_HPP
#define _XML_POLICY_HPP

#include <boost/noncopyable.hpp>
#include <boost/tokenizer.hpp>
#include <boost/property_tree/ptree.hpp>
#include <map>
#include "libdbuspolicy1-private.hpp"
#include "tslog.hpp"
#include "cynara.hpp"

enum class TreeType : uint8_t {
	SEND,
	RECV,
	OWN
};

namespace _ldp_xml_parser
{
    namespace {
        static const std::string ROOT_FIELD = "busconfig";
        static const std::string ROOT_POLICY = "policy";
    } //namespace

    class XmlPolicy : boost::noncopyable
    {
        enum class CtxType { DEFAULT, SPECIFIC, MANDATORY };

        class Key {
            public:
                static constexpr const char* ANY = "__";
                static constexpr const char* MRY = "!!";
                static constexpr const char* DEF = "??";
                static constexpr const char DELIM = '\\';
                static const size_t IDX_USER = 0;
                static const size_t IDX_GROUP = 1;
                static const size_t IDX_DEST = 2;
                static const size_t IDX_SENDER = IDX_DEST;
                static const size_t IDX_SERVICE = IDX_DEST;
                static const size_t IDX_PATH = 3;
                static const size_t IDX_IFACE = 4;
                static const size_t IDX_MEMBER = 5;
                static const size_t IDX_TYPE = 6;

                static const size_t IDX_TOTAL_LENGTH = IDX_TYPE + 1;
                static const size_t IDX_OWN_LENGTH = IDX_SERVICE + 1;
                static const size_t IDX_DEFAULT = IDX_GROUP + 1;

                std::vector<std::string> m_path_content;
                std::string m_privilege;
                bool m_bsend;
                bool m_brecv;
                bool m_bown;
                bool m_bcheck;
                bool m_ballow;
                static size_t m_weight;

                Key(bool bus)
                    : m_path_content(std::vector<std::string>(IDX_TOTAL_LENGTH, ANY)),
                    m_bsend(false),
                    m_brecv(false),
                    m_bown(false),
                    m_bcheck(false),
                    m_ballow(false) {}

                ~Key() {}

                void reset_attributes() {
                    m_bsend = m_brecv = m_bown = m_bcheck = m_ballow = false;
                    std::fill(m_path_content.begin() + IDX_DEFAULT, m_path_content.end(), ANY);
                }

                const std::string get_path() const {
                    std::string path = "R";
                    auto it_cend = m_bown ? m_path_content.cbegin() + IDX_OWN_LENGTH : m_path_content.cend();
                    for(auto it = m_path_content.cbegin(); it != it_cend; ++it)
                        (path += Key::DELIM) += *it;
                    return path;
                }
        };

        class Leaf {
            bool m_decision;
            bool m_check;
            std::string m_privilege;
            size_t m_weight;

            public:
            Leaf() : m_decision(false), m_check(false), m_privilege(""), m_weight(0) {};

            Leaf(bool decision, bool check, const std::string& privilege, size_t weight)
                : m_decision(decision), m_check(check), m_privilege(privilege), m_weight(weight) {}

            bool get_decision() const {
                return m_decision;
            }

            bool get_check() const {
                return m_check;
            }

            const std::string& get_privilege() const {
                return m_privilege;
            }

            size_t get_weight() const {
                return m_weight;
            }

            friend std::ostream& operator<<(std::ostream& os, const Leaf& lf) {
                if(lf.m_check)
                    os << "check," << lf.m_privilege << "," << lf.m_weight;
                else
                    os << (lf.m_decision ? "true" : "false") << "," << lf.m_weight;
                return os;
            }

            friend std::istream& operator>>(std::istream& is, Leaf& lf) {
                std::string s;
                is >> s;
                boost::char_separator<char> sep(",");
                boost::tokenizer<boost::char_separator<char>> tokens(s, sep);
                const auto size = std::distance(tokens.begin(), tokens.end());
                for(auto it = tokens.begin(); it != tokens.end(); ++it) {
                    const auto it_last = std::next(tokens.begin(), size - 1);
                    if(it == tokens.begin()) {
                        if(size > 2)
                            lf.m_check = (*it == "check") ? true : false;
                        else
                            lf.m_decision = (*it == "true") ? true : false;
                    } else if(it == it_last)
                        lf.m_weight = std::stoul(*it);
                    else if(size > 2)
						lf.m_privilege = *it;
                }
                return is;
            }
        };

        static char const *get_context_str(const CtxType& ctx_type) {
            switch(ctx_type) {
                case CtxType::DEFAULT: return "(default)"; break;
                case CtxType::SPECIFIC: return "(specific)"; break;
                case CtxType::MANDATORY: return "(mandatory)"; break;
                default: return ""; break;
            }
        }

        static const std::string get_field_str(const std::string& field) {
            return field == "" ? Key::ANY : field;
        }

        //Data obtained from XML parsing - decision trees
        boost::property_tree::ptree m_dec_trees[2][3];

        boost::property_tree::ptree &get_decision_tree(bool bus, TreeType tree_type) {
            return m_dec_trees[bus][static_cast<unsigned>(tree_type)];
        }

        boost::property_tree::ptree* get_decision_tree(bool bus, const Key& key) {
            TreeType tree_type;
            if(key.m_bsend) tree_type = TreeType::SEND;
            else if(key.m_brecv) tree_type = TreeType::RECV;
            else if(key.m_bown) tree_type = TreeType::OWN;
			else return NULL;

            return &get_decision_tree(bus, tree_type);
        }

        void print_decision_tree(const boost::property_tree::ptree& pt, int level = 0) {
            for(const auto& v : pt) {
                print_field(v, level);
                print_decision_tree(v.second, level + 1);
            }
        }

        void print_decision_key(bool bus, const Key& key) {
            if (tslog::verbose()) {
                std::string s = bus + " ";
                if(key.m_bsend && !key.m_brecv) s += "--> #";
                if(!key.m_bsend && key.m_brecv) s += "<-- #";
                if(!key.m_bsend && !key.m_brecv && key.m_bown) s += "OWN #";
                std::string prv = key.m_bcheck ? key.m_privilege : "";
                std::cout << s
                    << (key.m_bcheck ? "check " : std::to_string(key.m_ballow))
                    << prv
                    << " : "
                    << key.get_path()
                    << "    (weight: "
                    << key.m_weight
                    << ")\n";
            }
        }

        void update_decision_tree(bool bus, const Key& key) {
            if(!key.get_path().empty()) {
                print_decision_key(bus, key);

                //update
                boost::property_tree::ptree* const p_tree = get_decision_tree(bus, key);
                if(p_tree) {
                    boost::property_tree::ptree::path_type tpath(key.get_path(), Key::DELIM);
                    p_tree->put(tpath, Leaf(key.m_ballow, key.m_bcheck, key.m_privilege, key.m_weight));
                }
            }
        }

        void update_decision_path(const boost::property_tree::ptree::value_type& v,
                Key& key,
                CtxType& current_ctx,
                bool& allden,
                bool& bcheck,
                bool& attr) {
            if(v.first == "allow") {
                allden = true;
                bcheck = false;
                attr = false;
                key.reset_attributes();
            } else if(v.first == "deny") {
                allden = false;
                bcheck = false;
                attr = false;
                key.reset_attributes();
            } else if(v.first == "check") {
                allden = false;
                bcheck = true;
                attr = false;
                key.reset_attributes();
            } else if(v.first == "<xmlattr>") {
                attr = true;
                ++key.m_weight;
            } else {
                if(attr) {
                    std::string data_str = v.second.data() == "*" ? Key::ANY : v.second.data();
                    if(v.first == "context") {
                        if(data_str == "mandatory") {
                            key.m_path_content[Key::IDX_USER] = Key::MRY;
                            key.m_path_content[Key::IDX_GROUP] = Key::MRY;
                            current_ctx = CtxType::MANDATORY;
                        } else if(data_str == "default") {
                            key.m_path_content[Key::IDX_USER] = Key::DEF;
                            key.m_path_content[Key::IDX_GROUP] = Key::DEF;
                            current_ctx = CtxType::DEFAULT;
                        }
                    } else if(v.first == "user") {
                        if(current_ctx == CtxType::SPECIFIC)
                            key.m_path_content[Key::IDX_USER] = data_str;
                    } else if(v.first == "group") {
                        if(current_ctx == CtxType::SPECIFIC)
                            key.m_path_content[Key::IDX_GROUP] = data_str;
                    } else {
                        if(field_has(v, "send_"))
                            key.m_bsend = true;
                        if(field_has(v, "receive_"))
                            key.m_brecv = true;
                        if(v.first == "own") {
                            key.m_bown = true;
                            key.m_path_content[Key::IDX_SERVICE] = data_str;
                        }
                        if(v.first == "own_prefix") {
                            key.m_bown = true;
                            key.m_path_content[Key::IDX_SERVICE] = data_str + "*";
                        }
                        if(field_has(v, "_destination"))
                            key.m_path_content[Key::IDX_DEST] = data_str;
                        if(field_has(v, "_sender"))
                            key.m_path_content[Key::IDX_SENDER] = data_str;
                        if(field_has(v, "_path"))
                            key.m_path_content[Key::IDX_PATH] = data_str;
                        if(field_has(v, "_interface"))
                            key.m_path_content[Key::IDX_IFACE] = data_str;
                        if(field_has(v, "_member"))
                            key.m_path_content[Key::IDX_MEMBER] = data_str;
                        if(field_has(v, "_type"))
                            key.m_path_content[Key::IDX_TYPE] = data_str;
                        if(v.first == "privilege")
                            key.m_privilege = data_str;

                        key.m_bcheck = bcheck;
                        key.m_ballow = allden;
                    }
                }
            }
        }

        bool field_has(const boost::property_tree::ptree::value_type& v, const std::string& substr) {
            return (v.first.find(substr) != std::string::npos);
        }

        void print_field(const boost::property_tree::ptree::value_type& v, int level) {
			std::cout << ((level > 0) ? std::string((level - 1) * 8, ' ') + std::string(8, '.') : "")
				<< v.first
				<< " : "
				<< v.second.data()
				<< '\n';
        }

        void xml_traversal(bool bus,
				const boost::property_tree::ptree& pt,
                Key& key,
                CtxType& current_ctx,
                bool allden = false,
                bool bcheck = false,
                bool attr = false,
                int level = 0) {
            static const int Q_XML_MAX_LEVEL = 10;

            if(level < Q_XML_MAX_LEVEL) {
                for(const auto& v : pt) {
                    if(v.first == "<xmlcomment>") { continue; }

                    update_decision_path(v, key, current_ctx, allden, bcheck, attr);
                    //if (tslog::verbose()) print_field(v, level);
                    xml_traversal(bus, v.second, key, current_ctx, allden, bcheck, attr, level + 1);
                }

                if(!pt.empty() && attr && level > 1)
                    update_decision_tree(bus, key);
            } else if (tslog::enabled())
                std::cout << "XML traversal max level reached: " << level << '\n';
        }

        void print_indexing_path(size_t idx, const std::string& path, const Leaf& leaf = Leaf(), bool empty = true) {
            if (tslog::verbose()) {
                std::string s;
                if(!empty) {
                    s = "    : <";
                    s += (leaf.get_check()
                        ? std::string("check: ") + std::to_string(leaf.get_check()) + ", privilege: " + leaf.get_privilege()
                        : std::string("decision: ") + std::to_string(leaf.get_decision()));
                    s += (std::string(", weight: ") + std::to_string(leaf.get_weight()));
                    s += std::string(">");
                }

				std::cout << "path #"
					<< idx
					<< " : "
					<< path
					<< s
					<< '\n';
            }
        }

        void prepare_indexing_path(const std::vector<std::string>& idx_v,
                size_t pattern,
                const size_t usrgrp_obfuscate_order,
                const bool obfuscate_params,
                const CtxType& ctx_type,
                std::string& path) {

            constexpr size_t offset = Key::IDX_DEFAULT;
            path = "R";

            if(ctx_type == CtxType::SPECIFIC) {
				path += Key::DELIM;
				if (usrgrp_obfuscate_order & 1) // 1 3
					path += Key::ANY;
				else
					path += get_field_str(idx_v[Key::IDX_USER]);
				path += Key::DELIM;
				if ((usrgrp_obfuscate_order+1) & 2) // 1 2
					path += get_field_str(idx_v[Key::IDX_GROUP]);
				else
					path += Key::ANY;
            } else
                for(size_t i = 0; i < offset; ++i)
                    (path += Key::DELIM) += ctx_type == CtxType::MANDATORY ? Key::MRY : Key::DEF;

            const size_t n = idx_v.size() - offset;
            for (size_t i = 0; i < n; ++i) {
                path += Key::DELIM;
				if (obfuscate_params && pattern & 1)
					path += Key::ANY;
				else
					path += get_field_str(idx_v[i + offset]);
				pattern >>= 1;
            }
        }

        ErrCode service_leaf_found(const Leaf& leaf, const std::string& label, const std::vector<std::string>& idx_v) {
            ErrCode err;
            if(leaf.get_check()) {
				if (tslog::verbose())
					std::cout << __func__
						<< ": cynara check needed for privilege " << leaf.get_privilege()
						<< ", weight " << leaf.get_weight()
						<< '\n';

                //cynara check
                try {
                    bool br = _ldp_cynara::Cynara::check(label, leaf.get_privilege(), idx_v[Key::IDX_USER]);
                    err = ErrCode::ok(br);
                } catch(const std::runtime_error& ex) {
                    err = ErrCode::error(ex.what());
                }
            } else {
                err = ErrCode::ok(leaf.get_decision());
            }

            return err;
        }

        ErrCode index_decision_tree(const boost::property_tree::ptree& pt,
            const std::vector<std::string>& idx_v,
            const std::string& label,
            const bool obfuscate_params,
            const CtxType& ctx_type) {
            ErrCode err;
            bool found = false;
            size_t weight = 0;
            const size_t offset = Key::IDX_DEFAULT;
            const size_t m = (ctx_type == CtxType::SPECIFIC) ? (1 << offset) : 1;
            for(size_t usrgrp_ob_or = 0; usrgrp_ob_or < m; ++usrgrp_ob_or) {
                Leaf leaf_found;
                const size_t n = 1 << (idx_v.size() - offset);
                for(size_t p = 0; p < n; ++p) {
                    std::string path;
                    try {
                        prepare_indexing_path(idx_v, p, usrgrp_ob_or, obfuscate_params, ctx_type, path);
                        boost::property_tree::ptree::path_type tpath(path, Key::DELIM);

                        auto dec = pt.get<Leaf>(tpath);

                        print_indexing_path(p, path, dec, false);
                        found = true;
                        if(dec.get_weight() >= weight) {
                            weight = dec.get_weight();
                            leaf_found = dec;
                        }
                    } catch(const boost::property_tree::ptree_error& ex) {
                        //Path doesn't exist, continue
                        print_indexing_path(p, path);
                        if(!found) { err = ErrCode::error("No path"); }
                    } catch(...) {
                        print_indexing_path(p, path);
						if (tslog::verbose())
							std::cout << "Unknown exception while indexing decision tree!\n";
                        if(!found) { err = ErrCode::error("Unknown err, no path"); }
                    }
                }

                if(found) {
                    err = service_leaf_found(leaf_found, label, idx_v);
					if (tslog::verbose())
						std::cout << __func__ << ": returning decision #" << err.get() << " " << err.get_str() << ", weight " << leaf_found.get_weight() << '\n';
                    break;
                }
            }

            return err;
        }

        ErrCode index_decision_tree_lat(const boost::property_tree::ptree& pt,
            const std::vector<std::string>& idx_v,
            const std::string& label,
            const bool obfuscate_params,
            const CtxType& ctx_type) {
            ErrCode err;

			if (tslog::enabled()) {
				std::cout << "context: " << get_context_str(ctx_type) << ",  indexing arguments: ";
				std::copy(idx_v.begin(), idx_v.end(), std::ostream_iterator<std::string>(std::cout, ", "));
				std::cout << '\n';
			}

            //Examine policy data and make decision
			err = index_decision_tree(pt, idx_v, label, obfuscate_params, ctx_type);

			if (tslog::enabled())
				std::cout << __func__ << ": #" << err.get() << " " << err.get_str() << " " << get_context_str(ctx_type) << '\n';
            return err;
        }

        ErrCode can_do_action(bool bus,
                TreeType tree_type,
                const std::vector<std::string>& idx_v,
                const std::string& label = "",
                const bool analyze_prefix = false) {
            ErrCode err;
            boost::property_tree::ptree const &p_tree = get_decision_tree(bus, tree_type);
			err = index_decision_tree_lat(p_tree, idx_v, label, !analyze_prefix, CtxType::MANDATORY);
			if(!err.is_ok()) {
				err = index_decision_tree_lat(p_tree, idx_v, label, !analyze_prefix, CtxType::SPECIFIC);
				if(!err.is_ok())
					err = index_decision_tree_lat(p_tree, idx_v, label, !analyze_prefix, CtxType::DEFAULT);
			}
			if (tslog::enabled())
				std::cout << __func__ << ": #" << err.get()  << " " << err.get_str() << '\n';
            return err;
        }

        public:
        XmlPolicy() {
            Key::m_weight = 0;
        }

        void update(bool bus, const boost::property_tree::ptree& pt) {
			const auto& children = pt.get_child(ROOT_FIELD);
			for(const auto& x : children) {
				if(x.first == ROOT_POLICY) {
					Key key(bus);
					CtxType current_ctx = CtxType::SPECIFIC;
					xml_traversal(bus, x.second, key, current_ctx);
				}
			}
        }

        ErrCode can_send_to(bool bus, const std::vector<std::string>& idx_v, const std::string label) {
            return can_do_action(bus, TreeType::SEND, idx_v, label);
        }

        ErrCode can_recv_from(bool bus, const std::vector<std::string>& idx_v, const std::string label) {
            return can_do_action(bus, TreeType::RECV, idx_v, label);
        }

        ErrCode can_own_what(bool bus, const std::vector<std::string>& idx_v) {
            ErrCode err;

            //Evaluate own_prefix
            std::vector<std::string> iv = idx_v;
            const std::string srv = iv[iv.size() - 1];
            const size_t srv_size = srv.size();
            for(size_t n = 1; n <= srv_size; ++n) {
                const std::string sub = srv.substr(0, n) + "*";
				if (tslog::enabled())
					std::cout << "own_prefix: " << sub << '\n';
                iv.pop_back();
                iv.push_back(sub);
                err = can_do_action(bus, TreeType::OWN, iv, "", true);
                if(err.is_ok())
                    break;
            }

            //Evaluate own
            if(err.is_error())
                err = can_do_action(bus, TreeType::OWN, idx_v);

            return err;
        }

        void print_decision_trees(bool bus) {
            if (tslog::verbose())
				for (unsigned i = 0; i < TABSIZE(m_dec_trees[bus]); ++i)
                    for(auto const& y : m_dec_trees[bus][i]) {
                        std::cout << i << " " << y.first << " " << (y.second.empty() ? "(empty)" : "") << '\n';
                        print_decision_tree(y.second);
                    }
        }

    }; //XmlPolicy
    size_t XmlPolicy::Key::m_weight = 0;
} //namespace

#endif
