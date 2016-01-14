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
#include "libdbuspolicy1-private.hpp"
#include "timer.hpp"
#include "tslog.hpp"
#include "cynara.hpp"

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

                std::string m_bus;
                std::vector<std::string> m_path_content;
                std::string m_privilege;
                bool m_bsend;
                bool m_brecv;
                bool m_bown;
                bool m_bcheck;
                bool m_ballow;
                static size_t m_weight;

                Key(const std::string& bus)
                    : m_bus(bus),
                    m_path_content(std::vector<std::string>(IDX_TOTAL_LENGTH, ANY)),
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
                    for(auto it = m_path_content.cbegin(); it != it_cend; ++it) {
                        path += (std::string(1, Key::DELIM) + *it);
                    }
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
                if(lf.m_check) {
                    os << "check," << lf.m_privilege << "," << lf.m_weight;
                } else {
                    os << (lf.m_decision ? "true" : "false") << "," << lf.m_weight;
                }
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
                        if(size > 2) {
                            lf.m_check = (*it == "check") ? true : false;
                        } else {
                            lf.m_decision = (*it == "true") ? true : false;
                        }
                    } else if(it == it_last) {
                        lf.m_weight = std::stoul(*it);
                    } else {
                        if(size > 2) {
                            lf.m_privilege = *it;
                        }
                    }
                }
                return is;
            }
        };

        static const std::string get_context_str(const CtxType& ctx_type) {
            switch(ctx_type) {
                case CtxType::DEFAULT: return "(default)"; break;
                case CtxType::SPECIFIC: return "(specific)"; break;
                case CtxType::MANDATORY: return "(mandatory)"; break;
                default: return ""; break;
            }
        }

        static const std::string get_field_str(const std::string& field) {
            return (field == "") ? Key::ANY : field;
        }

        //Data obtained from XML parsing - decision trees
        typedef std::map<std::string, boost::property_tree::ptree> Trees_t;
        std::map<std::string, Trees_t> m_dec_trees;
        std::mutex m_xml_policy_mtx;

        boost::property_tree::ptree* get_decision_tree(const std::string& bus, const std::string& tree_type) {
            boost::property_tree::ptree* p_tree = NULL;

            auto it1 = m_dec_trees.find(bus);
            if(it1 != m_dec_trees.end()) {
                auto it2 = it1->second.find(tree_type);
                if(it2 != it1->second.end()) {
                    p_tree = &it2->second;
                }
            }
            return p_tree;
        }

        boost::property_tree::ptree* get_decision_tree(const Key& key) {
            std::string tree_type;
            if(key.m_bsend) { tree_type = "SEND"; }
            else if(key.m_brecv) { tree_type = "RECV"; }
            else if(key.m_bown) { tree_type = "OWN"; }

            return get_decision_tree(key.m_bus, tree_type);
        }

        void print_decision_tree(const boost::property_tree::ptree& pt, int level = 0) {
            for(const auto& v : pt) {
                print_field(v, level);
                print_decision_tree(v.second, level + 1);
            }
        }

        void print_decision_key(const Key& key) {
            if(_ldp_tslog::get_verbose()) {
                std::string s = key.m_bus + " ";
                if(key.m_bsend && !key.m_brecv) { s += "--> #"; }
                if(!key.m_bsend && key.m_brecv) { s += "<-- #"; }
                if(!key.m_bsend && !key.m_brecv && key.m_bown) { s += "OWN #"; }
                std::string prv = key.m_bcheck ? key.m_privilege : "";
                verbose::tout << s
                    << (key.m_bcheck ? "check " : std::to_string(key.m_ballow))
                    << prv
                    << " : "
                    << key.get_path()
                    << "    (weight: "
                    << key.m_weight
                    << ")"
                    << std::endl;
            }
        }

        void update_decision_tree(const Key& key) {
            if(!key.get_path().empty()) {
                print_decision_key(key);

                //update
                boost::property_tree::ptree* const p_tree = get_decision_tree(key);
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
                    std::string data_str = (v.second.data() == "*") ? Key::ANY : v.second.data();
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
                        if(current_ctx == CtxType::SPECIFIC) {
                            key.m_path_content[Key::IDX_USER] = data_str;
                        }
                    } else if(v.first == "group") {
                        if(current_ctx == CtxType::SPECIFIC) {
                            key.m_path_content[Key::IDX_GROUP] = data_str;
                        }
                    } else {
                        if(field_has(v, "send_")) {
                            key.m_bsend = true;
                        }
                        if(field_has(v, "receive_")) {
                            key.m_brecv = true;
                        }
                        if(v.first == "own") {
                            key.m_bown = true;
                            key.m_path_content[Key::IDX_SERVICE] = data_str;
                        }
                        if(v.first == "own_prefix") {
                            key.m_bown = true;
                            key.m_path_content[Key::IDX_SERVICE] = data_str + "*";
                        }
                        if(field_has(v, "_destination")) {
                            key.m_path_content[Key::IDX_DEST] = data_str;
                        }
                        if(field_has(v, "_sender")) {
                            key.m_path_content[Key::IDX_SENDER] = data_str;
                        }
                        if(field_has(v, "_path")) {
                            key.m_path_content[Key::IDX_PATH] = data_str;
                        }
                        if(field_has(v, "_interface")) {
                            key.m_path_content[Key::IDX_IFACE] = data_str;
                        }
                        if(field_has(v, "_member")) {
                            key.m_path_content[Key::IDX_MEMBER] = data_str;
                        }
                        if(field_has(v, "_type")) {
                            key.m_path_content[Key::IDX_TYPE] = data_str;
                        }
                        if(v.first == "privilege") {
                            key.m_privilege = data_str;
                        }

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
            verbose::tout    << ((level > 0) ? std::string((level - 1) * 8, ' ') + std::string(8, '.') : "")
                << v.first
                << " : "
                << v.second.data()
                << std::endl;
        }

        void xml_traversal(const boost::property_tree::ptree& pt,
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
                    //print_field(v, level);
                    xml_traversal(v.second, key, current_ctx, allden, bcheck, attr, level + 1);
                }

                if(!pt.empty() && attr && level > 1) {
                    update_decision_tree(key);
                }
            } else {
                terr << "XML traversal max level reached: " << level << std::endl;
            }
        }

        void print_indexing_path(size_t idx, const std::string& path, const Leaf& leaf = Leaf(), bool empty = true) {
            if(_ldp_tslog::get_verbose()) {
                std::string s;
                if(!empty) {
                    s = "    : <";
                    s += (leaf.get_check()
                        ? std::string("check: ") + std::to_string(leaf.get_check()) + ", privilege: " + leaf.get_privilege()
                        : std::string("decision: ") + std::to_string(leaf.get_decision()));
                    s += (std::string(", weight: ") + std::to_string(leaf.get_weight()));
                    s += std::string(">");
                }

                verbose::tout << "path #"
                    << idx
                    << " : "
                    << path
                    << s
                    << std::endl;
            }
        }

        void prepare_indexing_path(const std::vector<std::string>& idx_v,
                const size_t pattern,
                const size_t obfuscate_order,
                const CtxType& ctx_type,
                std::string& path) {

            const size_t offset = Key::IDX_DEFAULT;
            path = "R";

            if(ctx_type == CtxType::SPECIFIC) {
                switch(obfuscate_order) {
                    case 0:
                        path += (std::string(1, Key::DELIM) + get_field_str(idx_v[Key::IDX_USER]));
                        path += (std::string(1, Key::DELIM) + Key::ANY);
                    break;
                    case 1:
                        path += (std::string(1, Key::DELIM) + Key::ANY);
                        path += (std::string(1, Key::DELIM) + get_field_str(idx_v[Key::IDX_GROUP]));
                    break;
                    case 2:
                        path += (std::string(1, Key::DELIM) + get_field_str(idx_v[Key::IDX_USER]));
                        path += (std::string(1, Key::DELIM) + get_field_str(idx_v[Key::IDX_GROUP]));
                    break;
                    case 3:
                    default:
                        path += (std::string(1, Key::DELIM) + Key::ANY);
                        path += (std::string(1, Key::DELIM) + Key::ANY);
                    break;
                }
            } else {
                for(size_t i = 0; i < offset; ++i) {
                    const std::string as = (ctx_type == CtxType::MANDATORY) ? Key::MRY : Key::DEF;
                    path += (std::string(1, Key::DELIM) + as);
                }
            }

            const size_t m = 1;
            const size_t n = idx_v.size() - offset;
            for(size_t i = 0; i < n; ++i) {
                std::string s = get_field_str(idx_v[i + offset]);
                path += Key::DELIM;
                if(pattern & (m << i)) {
                    path += Key::ANY;
                } else {
                    path += s;
                }
            }
        }

        ErrCode service_leaf_found(const Leaf& leaf, const std::string& label, const std::vector<std::string>& idx_v) {
            ErrCode err;
            if(leaf.get_check()) {
                verbose::tout << __func__
                    << ": cynara check needed for privilege " << leaf.get_privilege()
                    << ", weight " << leaf.get_weight()
                    << std::endl;

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
            const CtxType& ctx_type) {
            ErrCode err;
            bool found = false;
            size_t weight = 0;
            const size_t offset = Key::IDX_DEFAULT;
            const size_t m = (ctx_type == CtxType::SPECIFIC) ? (1 << offset) : 1;
            for(size_t ob_or = 0; ob_or < m; ++ob_or) {
                Leaf leaf_found;
                const size_t n = 1 << (idx_v.size() - offset);
                for(size_t p = 0; p < n; ++p) {
                    std::string path;
                    try {
                        prepare_indexing_path(idx_v, p, ob_or, ctx_type, path);
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
                        verbose::tout << "Unknown exception while indexing decision tree!" << std::endl;
                        if(!found) { err = ErrCode::error("Unknown err, no path"); }
                    }
                }

                if(found) {
                    err = service_leaf_found(leaf_found, label, idx_v);
                    verbose::tout << __func__ << ": returning decision #" << err.get() << " " << err.get_str() << ", weight " << leaf_found.get_weight() << std::endl;
                    break;
                }
            }

            return err;
        }

        ErrCode index_decision_tree_lat(const boost::property_tree::ptree& pt,
            const std::vector<std::string>& idx_v,
            const std::string& label,
            const CtxType& ctx_type) {
            ErrCode err;

            tout << "context: " << get_context_str(ctx_type) << ",  indexing arguments: ";
            if(_ldp_tslog::get_enable()) { std::copy(idx_v.begin(), idx_v.end(), std::ostream_iterator<std::string>(std::cout, ", ")); }
            tout << std::endl;

            //Examine policy data and make decision
            _ldp_timer::microsec latency;
            {
                _ldp_timer::Timer<_ldp_timer::microsec> t(&latency);
                err = index_decision_tree(pt, idx_v, label, ctx_type);
            }

            tout << __func__ << ": #" << err.get() << " " << err.get_str() << " " << get_context_str(ctx_type) << std::endl;
            tout << "tree indexing latency: " << latency << std::endl;
            return err;
        }

        ErrCode can_do_action(const std::string& bus, const std::string& tree_type, const std::vector<std::string>& idx_v, const std::string& label = "") {
            std::unique_lock<std::mutex> lck(m_xml_policy_mtx);
            ErrCode err;
            boost::property_tree::ptree* const p_tree = get_decision_tree(bus, tree_type);
            if(p_tree) {
                err = index_decision_tree_lat(*p_tree, idx_v, label, CtxType::MANDATORY);
                if(!err.is_ok()) {
                    err = index_decision_tree_lat(*p_tree, idx_v, label, CtxType::SPECIFIC);
                    if(!err.is_ok()) {
                        err = index_decision_tree_lat(*p_tree, idx_v, label, CtxType::DEFAULT);
                    }
                }
            } else {
                err = ErrCode::error("Get decision tree returned NULL ptr");
            }
            tout << __func__ << ": #" << err.get()  << " " << err.get_str() << std::endl;
            return err;
        }

        public:
        XmlPolicy() {
            Trees_t t;
            t.emplace("SEND", typename Trees_t::mapped_type());
            t.emplace("RECV", typename Trees_t::mapped_type());
            t.emplace("OWN", typename Trees_t::mapped_type());
            m_dec_trees.emplace("SYSTEM", t);
            m_dec_trees.emplace("SESSION", t);
        }

        virtual ~XmlPolicy() {}

        void init() {
            std::unique_lock<std::mutex> lck(m_xml_policy_mtx);
            Key::m_weight = 0;
        }

        void update(const std::string& bus, const boost::property_tree::ptree& pt) {
            if(!pt.empty()) {
                std::unique_lock<std::mutex> lck(m_xml_policy_mtx);
                const auto& children = pt.get_child(ROOT_FIELD);
                for(const auto& x : children) {
                    if(x.first == ROOT_POLICY) {
                        Key key(bus);
                        CtxType current_ctx = CtxType::SPECIFIC;
                        xml_traversal(x.second, key, current_ctx);
                    }
                }
            }
        }

        ErrCode can_send_to(const std::string bus, const std::vector<std::string>& idx_v, const std::string label) {
            return can_do_action(bus, "SEND", idx_v, label);
        }

        ErrCode can_recv_from(const std::string bus, const std::vector<std::string>& idx_v, const std::string label) {
            return can_do_action(bus, "RECV", idx_v, label);
        }

        ErrCode can_own_what(const std::string bus, const std::vector<std::string>& idx_v) {
            ErrCode err;

            //Evaluate own_prefix
            std::vector<std::string> iv = idx_v;
            const std::string srv = iv[iv.size() - 1];
            const size_t srv_size = srv.size();
            for(size_t n = 1; n <= srv_size; ++n) {
                const std::string sub = srv.substr(0, n) + "*";
                verbose::tout << "own_prefix: " << sub << std::endl;
                iv.pop_back();
                iv.push_back(sub);
                err = can_do_action(bus, "OWN", iv);
                if(err.is_ok()) {
                    break;
                }
            }

            //Evaluate own
            if(err.is_error()) {
                err = can_do_action(bus, "OWN", idx_v);
            }

            return err;
        }

        void print_decision_trees() {
            if(_ldp_tslog::get_verbose()) {
                std::unique_lock<std::mutex> lck(m_xml_policy_mtx);

                for(const auto& x : m_dec_trees) {
                    for(const auto& y : x.second) {
                        verbose::tout << x.first << " " << y.first << " " << (y.second.empty() ? "(empty)" : "") << std::endl;
                        print_decision_tree(y.second);
                    }
                }
            }
        }

    }; //XmlPolicy
    size_t XmlPolicy::Key::m_weight = 0;
} //namespace

#endif
