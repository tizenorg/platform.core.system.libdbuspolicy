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

Cynara& Cynara::get_instance() {
	static Cynara __self;
	return __self;
}

std::string Cynara::get_session() {
	return "";
}

bool Cynara::check(std::string label, std::string privilege, std::string uid, std::string session) {
	return true;
}
