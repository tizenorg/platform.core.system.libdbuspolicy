#include "tslog.hpp"

namespace tslog {
int8_t g_verbosity;
}

bool tslog::get_log_env(char const *name) {
	char const *ldp_log_mode = getenv(name);
	return ldp_log_mode && '0' != *ldp_log_mode;
}

void tslog::init() {
	g_verbosity = get_log_env("LDP_LOG") ? get_log_env("LDP_VERBOSE") : -1;
}

bool tslog::enabled() { return g_verbosity > 0; }
bool tslog::verbose() { return g_verbosity > 0; }
