#include "cynara.hpp"
#include "libdbuspolicy1-private.hpp"
#include <sys/types.h>
#include <unistd.h>
#include <stdexcept>
#include <cstdlib>

using namespace ldp_cynara;

pthread_mutex_t Cynara::__mutex = PTHREAD_MUTEX_INITIALIZER;

Cynara::Cynara() : __inited(false) {
}

Cynara::~Cynara() {
	int r = cynara_finish(__cynara);
	if (r != CYNARA_API_SUCCESS) {
		//TODO: reaction
		//destructor is usually called when proccess is closed
		//there is no good way to serve this case.
	}
}

bool Cynara::init() {
	if (!__inited) {
		int r = cynara_initialize(&__cynara, NULL);
		if (r != CYNARA_API_SUCCESS)
			return false;

		__session = cynara_session_from_pid(getpid());
		__inited = true;
	}
	return true;
}

Cynara& Cynara::getInstance() {
	static Cynara __self;
	return __self;
}

CynaraResult Cynara::check(const char* label, const char* privilege, const char* uid) {

	const char* _label="";
	const char* _uid="";
	const char* _privilege="";
	CynaraResult ret;

	if (label)
		_label=label;

	if (privilege)
		_privilege=privilege;

	if (uid)
		_uid=uid;

	pthread_mutex_lock(&__mutex);
	Cynara& c = Cynara::getInstance();
	if (!c.init())
		ret = CynaraResult::ERROR_INIT;
	else {
		int r = cynara_check (c.__cynara, _label, c.__session, _uid, _privilege);
		if (r == CYNARA_API_ACCESS_ALLOWED)
			ret = CynaraResult::ALLOW;
		else if (r == CYNARA_API_ACCESS_DENIED)
			ret = CynaraResult::DENY;
		else
			ret = CynaraResult::ERROR_CHECK;
	}
	pthread_mutex_unlock(&__mutex);
	return ret;
}
