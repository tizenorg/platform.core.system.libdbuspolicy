
#include <iostream>
#include <string>
#include <sys/types.h>
#include <dbuspolicy1/libdbuspolicy1.h>
#include "internal/internal.h"

const char* system_path =  "tests/system.conf";

struct OwnershipTest {
	bool expected_result;
	uid_t user;
	gid_t group;
	const char* label;
	const char* service;
};

struct OwnershipTest ownership_tests[]={
	(struct OwnershipTest){true,  0,    0, "test", "org.test.test1"},
	(struct OwnershipTest){true,  5009, 0, "test", "org.test.test1"},

	(struct OwnershipTest){false, 0,    0, "test", "org.test.test2"},
	(struct OwnershipTest){false, 5009, 0, "test", "org.test.test2"},

	(struct OwnershipTest){false, 0,    0, "test", "org.test.test3"},
	(struct OwnershipTest){false, 5009, 0, "test", "org.test.test3"},

	(struct OwnershipTest){false, 0,    0, "test", "org.test.test4"},
	(struct OwnershipTest){true,  5009, 0, "test", "org.test.test4"},

	(struct OwnershipTest){false, 0,    0, "test", "org.test.test5"},

	(struct OwnershipTest){true,  0,    0, "test", "org.test.test6"},

	(struct OwnershipTest){true,  0,    0, "test", "org.test.test7"},

	(struct OwnershipTest){true,  0,    0, "test", "a.b.c"},
	(struct OwnershipTest){true,  0,    0, "test", "a.b"},
	(struct OwnershipTest){false, 0,    0, "test", "c"},
	(struct OwnershipTest){false, 0,    0, "test", "a.c"},
	(struct OwnershipTest){false, 0,    0, "test", "b.c"},
};

void ownershipTest_print(struct OwnershipTest* t, bool result) {
	printf("uid = %lu, gid = %lu, label = %s, service = %s, expected = %d, result = %d",
		   (unsigned long)t->user, (unsigned long)t->group, t->label, t->service, !((int)t->expected_result), (int)result);
}

bool ownership_test() {
	unsigned  i = 0;
	bool flag = true;
	bool ret = true;
	__internal_init(false, "tests/system.conf");
	for (i = 0;i < sizeof(ownership_tests)/sizeof(struct OwnershipTest);i++) {
		ret = __internal_can_own(false, ownership_tests[i].user,  ownership_tests[i].group,  ownership_tests[i].label,  ownership_tests[i].service);
		if ( (int)((ownership_tests[i].expected_result)) != ret) {
			printf("[ERROR][%d] ownership test failed: %d %d ", i, (int)((ownership_tests[i].expected_result)), ret);
			ownershipTest_print(&ownership_tests[i], ret);
			printf("\n");
			flag = false;
		}
	}
	return flag;
}

int main () {
	__internal_init_once();
	if (!ownership_test())
		return -1;
return 0;
}
