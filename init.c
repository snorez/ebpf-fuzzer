#include "ebpf_fuzzer.h"

extern struct ebpf_fuzz_target kern_5_8;

static LIST_HEAD(fuzzer_targets);

static int register_target(struct ebpf_fuzz_target *target)
{
	struct ebpf_fuzz_target *tmp;
	list_for_each_entry(tmp, &fuzzer_targets, sibling) {
		if (!strcmp(tmp->target_name, target->target_name))
			return -1;
	}

	list_add_tail(&target->sibling, &fuzzer_targets);
	return 0;
}

int init(void)
{
	int err = 0;
	err = kern_5_8.init(&kern_5_8);
	if (err == -1) {
		err_dbg(0, "kern_5_8.init() err");
		return -1;
	}

	err = register_target(&kern_5_8);
	if (err == -1) {
		err_dbg(0, "register_target err");
		return -1;
	}

	return 0;
}

struct ebpf_fuzz_target *find_target(char *version)
{
	struct ebpf_fuzz_target *tmp;
	list_for_each_entry(tmp, &fuzzer_targets, sibling) {
		if (!strcmp(tmp->target_name, version))
			return tmp;
	}

	return NULL;
}
