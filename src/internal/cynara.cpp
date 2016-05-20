#include "cynara.hpp"
#include "libdbuspolicy1-private.hpp"
#include <sys/types.h>
#include <unistd.h>
#include <stdexcept>

using namespace _ldp_cynara;

Cynara::Cynara() {
	int r = cynara_initialize(&__cynara, NULL);
	if (r != CYNARA_API_SUCCESS)
		throw std::runtime_error("Cynara initialization failed");

	__session = cynara_session_from_pid(getpid());
}

Cynara::~Cynara() {
	int r = cynara_finish(__cynara);
	if (r != CYNARA_API_SUCCESS) {
		//TODO: reaction
	}
}

Cynara& Cynara::get_instance() {
	static Cynara __self;
	return __self;
}

std::string Cynara::get_session() {
	Cynara& c = Cynara::get_instance();
	c.__session = cynara_session_from_pid(getpid());
	return c.__session;
}

bool Cynara::check(std::string label, std::string privilege, std::string uid, std::string session) {
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
