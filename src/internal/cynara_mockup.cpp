#include "cynara.hpp"
#include "libdbuspolicy1-private.hpp"
#include <sys/types.h>
#include <unistd.h>
#include <stdexcept>

using namespace _ldp_cynara;

Cynara::Cynara() {
}

Cynara::~Cynara() {
}

bool Cynara::init() {
	return true;
}

Cynara& Cynara::getInstance() {
	static Cynara __self;
	return __self;
}


CynaraResult Cynara::check(const char* label, const char* privilege, const char* uid) {
	return CynaraResult::ALLOW;
}
