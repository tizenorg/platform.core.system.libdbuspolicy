
#include <iostream>
#include <string>
#include <sys/types.h>
#include <dbuspolicy1/libdbuspolicy1.h>
#include "internal/internal.h"

const char* system_path =  "tests/system.conf";

struct SignalTest {
	bool expected_result;
	uid_t user;
	gid_t group;
	const char* label;
	const char* dest;
	const char* interface;
};

struct SignalTest signal_tests[]={
	(struct SignalTest){true,  0,    0, "test", "bli.bla.blubb test.test1 test.tes3", "/an/object/path"},
	(struct SignalTest){false,  5010, 0, "test", "bli.bla.blubb", "/an/object/path"},
};

void signalTest_print(struct SignalTest* t, bool result) {
	printf("uid = %lu, gid = %lu, label = %s, dest = %s, interface = %s, expected = %d, result = %d",
		   (unsigned long)t->user, (unsigned long)t->group, t->label, t->dest, t->interface, !((int)t->expected_result), (int)result);
}

bool signal_test() {
	unsigned  i = 0;
	bool flag = true;
	bool ret = true;
	__internal_init(false, "tests/system.conf");
	for (i = 0;i < sizeof(signal_tests)/sizeof(struct SignalTest);i++) {
		ret = __internal_can_send(false, signal_tests[i].user, signal_tests[i].group, signal_tests[i].label, signal_tests[i].dest, NULL, signal_tests[i].interface, NULL, DBUSPOLICY_MESSAGE_TYPE_SIGNAL);
		if ( (int)((signal_tests[i].expected_result)) != ret) {
			printf("[ERROR][%d] signal test failed: %d %d ", i, (int)((signal_tests[i].expected_result)), ret);
			signalTest_print(&signal_tests[i], ret);
			printf("\n");
			flag = false;
		}
	}
	return flag;
}

int main () {
	__internal_init_once();
	if (!signal_test())
		return -1;
return 0;
}
