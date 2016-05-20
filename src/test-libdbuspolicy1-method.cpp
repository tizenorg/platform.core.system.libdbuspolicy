
#include <iostream>
#include <string>
#include <sys/types.h>
#include <dbuspolicy1/libdbuspolicy1.h>
#include "internal/internal.h"
#include "internal/policy.hpp"

using namespace _ldp_xml_parser;

const char* system_path =  "tests/system.conf";

struct MethodTest {
	bool expected_result;
	uid_t user;
	gid_t group;
	const char* label;
	const char* name;
	const char* path;
	const char* interface;
	const char* member;
	int type;
	int recv_send;
};

struct MethodTest method_tests[]={
	(struct MethodTest){true,    0,    0, "test", "org.test.test2",  NULL, "org.test.Itest1", "DoIt", METHOD_CALL, DIRECTION_SEND},
	(struct MethodTest){true,    0,    0, "test", "org.test.test3",  NULL, "org.test.Itest1", "DoIt", METHOD_CALL, DIRECTION_RECEIVE},

	(struct MethodTest){true,    5001, 100, "test", "org.test.test3",  NULL, "org.test.Itest1", "DoIt", METHOD_CALL, DIRECTION_RECEIVE},
	(struct MethodTest){true,    0,    0, "test", "org.test.test2",  NULL, "org.test.Itest1", "DoIt", METHOD_CALL, DIRECTION_SEND},

	(struct MethodTest){false,   0,    0, "test", "org.test.test2",  NULL, "org.test.Itest1", "DontDoIt", METHOD_CALL, DIRECTION_SEND},
	(struct MethodTest){true,    0,    0, "test", "org.test.test3",  NULL, "org.test.Itest1", "DontDoIt", METHOD_CALL, DIRECTION_RECEIVE},

	(struct MethodTest){false,   0,    0, "test", "org.test.test2",  NULL, "org.test.Itest1", "DontDoIt", METHOD_CALL, DIRECTION_SEND},
	(struct MethodTest){false,    5001,    100, "test", "org.test.test3",  NULL, "org.test.Itest1", "DontDoIt", METHOD_CALL, DIRECTION_RECEIVE},

	(struct MethodTest){true,   0,    0, "test", "test.te34.fg4 a.b.c.d.e org.test.test2",  NULL, "org.test.Itest1", "NotKnown", METHOD_CALL, DIRECTION_SEND},
	(struct MethodTest){false,   0,    0, "test", "test.te34.fg4 a.b.c.d.e",  NULL, "org.test.Itest1", "NotKnown", METHOD_CALL, DIRECTION_SEND},
	(struct MethodTest){true,   0,    0, "test", "org.test.test3",  NULL, "org.test.Itest1", "NotKnown", METHOD_CALL, DIRECTION_RECEIVE},

	(struct MethodTest){true,   0,    0, "test", "org.test.test2",  NULL, "org.test.Itest1", "NotKnown", METHOD_CALL, DIRECTION_SEND},
	(struct MethodTest){false,   5001, 100, "test", "org.test.test3",  NULL, "org.test.Itest1", "NotKnown", METHOD_CALL, DIRECTION_RECEIVE},

	(struct MethodTest){false,   0,    0, "test", "org.test.test2",  NULL, "org.test.Itest2", "NotKnown", METHOD_CALL, DIRECTION_SEND},
	(struct MethodTest){true,   5001, 100, "test", "org.test.test3",  NULL, "org.test.Itest2", "NotKnown", METHOD_CALL, DIRECTION_RECEIVE},
};

void methodTest_print(struct MethodTest* t, bool result) {
	printf("uid = %lu, gid = %lu, label = %s, name = %s, path = %s, interface = %s, member = %s, expected = %d, result = %d  (type=%d)",
		   (unsigned long)t->user, (unsigned long)t->group, t->label, t->name, t->path, t->interface, t->member, !((int)t->expected_result), (int)result, t->recv_send);
}

bool method_test() {
	unsigned  i = 0;
	bool flag = true;
	bool ret = true;
	__internal_init(false, "tests/system.conf");
	for (i = 0;i < sizeof(method_tests)/sizeof(struct MethodTest);i++) {
		if (method_tests[i].recv_send == DIRECTION_SEND)
		{
			ret = __internal_can_send(false, method_tests[i].user, method_tests[i].group, method_tests[i].label, method_tests[i].name,  method_tests[i].path, method_tests[i].interface, method_tests[i].member, method_tests[i].type);
		} else if (method_tests[i].recv_send == DIRECTION_RECEIVE) {
			ret = __internal_can_recv(false, method_tests[i].user,  method_tests[i].group, method_tests[i].label,  method_tests[i].name, method_tests[i].path, method_tests[i].interface, method_tests[i].member, method_tests[i].type);
		}
		if ( (int)((method_tests[i].expected_result)) != ret) {
			printf("[ERROR][%d] method test failed: %d %d ", i, (int)((method_tests[i].expected_result)), ret);
			methodTest_print(&method_tests[i], ret);
			printf("\n");
			flag = false;
		}
	}
	return flag;
}

int main () {
	__internal_init_once();
	if (!method_test())
		return -1;
return 0;
}
