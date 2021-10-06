#include "ebpf_fuzzer.h"

static char *qemu_fuzzlib_user_name = "ebpf_fuzzer";
static u64 qemu_fuzzlib_userid = 0;

static char *target_version = NULL;
static char *qemu_exec_path = NULL;
static char *bzImage_path = NULL;
static char *osImage_path = NULL;
static char *rsa_path = NULL;
static u32 idle_sec = 0;
static char *host_ip = NULL;
static u32 instance_nr = 0;
static u32 instance_memsz = 0;
static u32 instance_core = 0;
static char *env_workdir = NULL;
static char *guest_workdir = NULL;
static char *guest_user = NULL;
static char *guest_sh_file = NULL;
static char *guest_c_file = NULL;
static char *sample_fname = NULL;
static char *db_file = NULL;
static u32 body1_len = 0x18;

struct ebpf_fuzz_target *target;

static int db_init(struct qemu_fuzzlib_env *env)
{
	return 0;
}

static int mutate(struct qemu_fuzzlib_env *env, char *outfile)
{
	int err = 0;
	size_t sz = 0;
	char body[BODY_LEN];

	int outfd = open(outfile, O_WRONLY | O_CREAT | O_TRUNC, S_IRWXU);
	if (outfd == -1) {
		err_dbg(1, "open err");
		return QEMU_FUZZLIB_MUTATE_ERR;
	}

	err = target->gen_sample_body(body, BODY_LEN, body1_len);
	if (err == -1) {
		close(outfd);
		return QEMU_FUZZLIB_MUTATE_DONE;
	}

	sz = strlen(target->sample_header);
	err = write(outfd, target->sample_header, sz);
	if (err != sz) {
		if (err == -1)
			err_dbg(1, "write err");
		close(outfd);
		return QEMU_FUZZLIB_MUTATE_ERR;
	}

	sz = strlen(body);
	err = write(outfd, body, sz);
	if (err != sz) {
		if (err == -1)
			err_dbg(1, "write err");
		close(outfd);
		return QEMU_FUZZLIB_MUTATE_ERR;
	}

	sz = strlen(target->sample_tail);
	err = write(outfd, target->sample_tail, sz);
	if (err != sz) {
		if (err == -1)
			err_dbg(1, "write err");
		close(outfd);
		return QEMU_FUZZLIB_MUTATE_ERR;
	}

	/* TODO: update database */
	close(outfd);
	return QEMU_FUZZLIB_MUTATE_OK;
}

static void usage(char *argv[])
{
	fprintf(stderr, "Usage: %s config is_test\n", argv[0]);
}

static int validate_args(int argc, char *argv[])
{
	if (argc != 3) {
		return -1;
	}

	if (!path_exists(argv[1])) {
		err_dbg(0, "%s not exists", argv[1]);
		return -1;
	}

	return 0;
}

static int parse_conf_kv(char *key, char *val)
{
	char *p = NULL;

	p = strdup(val);
	if (!p) {
		err_dbg(1, "strdup err");
		return -1;
	}

	if (!strcmp(key, "version")) {
		target_version = p;
	} else if (!strcmp(key, "qemu_exec_path")) {
		qemu_exec_path = p;
	} else if (!strcmp(key, "bzImage_path")) {
		bzImage_path = p;
	} else if (!strcmp(key, "osImage_path")) {
		osImage_path = p;
	} else if (!strcmp(key, "rsa_path")) {
		rsa_path = p;
	} else if (!strcmp(key, "host_ip")) {
		host_ip = p;
	} else if (!strcmp(key, "instance_nr")) {
		instance_nr = atoi(p);
		free(p);
	} else if (!strcmp(key, "instance_memsz")) {
		instance_memsz = atoi(p);
		free(p);
	} else if (!strcmp(key, "instance_core")) {
		instance_core = atoi(p);
		free(p);
	} else if (!strcmp(key, "env_workdir")) {
		env_workdir = p;
	} else if (!strcmp(key, "guest_workdir")) {
		guest_workdir = p;
	} else if (!strcmp(key, "guest_user")) {
		guest_user = p;
	} else if (!strcmp(key, "guest_sh_file")) {
		guest_sh_file = p;
	} else if (!strcmp(key, "guest_c_file")) {
		guest_c_file = p;
	} else if (!strcmp(key, "sample_fname")) {
		sample_fname = p;
	} else if (!strcmp(key, "db_file")) {
		db_file = p;
	} else if (!strcmp(key, "idle_sec")) {
		idle_sec = atoi(p);
		free(p);
	} else if (!strcmp(key, "body1_len")) {
		body1_len = (u32)atoi(p);
		free(p);
	} else {
		err_dbg(0, "{%s:%s} not recognised", key, val);
		free(p);
		return -1;
	}

	return 0;
}

static int parse_conf(const char *conf)
{
	int err = 0;
	struct list_head conf_head;

	INIT_LIST_HEAD(&conf_head);
	err = clib_json_load(conf, &conf_head);
	if (err == -1) {
		err_dbg(0, "clib_json_load err");
		return -1;
	}

	struct clib_json *tmp;
	tmp = list_first_entry_or_null(&conf_head, struct clib_json, sibling);
	if (!tmp) {
		err_dbg(0, "no json entry");
		goto err_out;
	}

	struct clib_json_kv *cur;
	list_for_each_entry(cur, &tmp->kvs, sibling) {
		if (cur->val_type != CJVT_STRING) {
			err_dbg(0, "json format err");
			goto err_out;
		}

		char *bs_key = cur->key;
		char *bs_val = cur->value.value;

		err = parse_conf_kv(bs_key, bs_val);
		if (err == -1) {
			err_dbg(0, "parse_conf_kv err");
			goto err_out;
		}
	}

	clib_json_cleanup(&conf_head);
	return 0;

err_out:
	clib_json_cleanup(&conf_head);
	return -1;
}

static void cleanup(void)
{
	free(target_version);
	free(qemu_exec_path);
	free(bzImage_path);
	free(osImage_path);
	free(rsa_path);
	free(host_ip);
	free(env_workdir);
	free(guest_workdir);
	free(guest_user);
	free(guest_sh_file);
	free(guest_c_file);
	free(sample_fname);
	free(db_file);
}

static void do_test(void)
{
	char *outfile = "/tmp/test_sample.c";
	(void)mutate(NULL, outfile);
}

int main(int argc, char *argv[])
{
	int err = 0;
	char *conf = NULL;
	int is_test = 0;
	struct qemu_fuzzlib_env *env;

	enable_dbg_mode();

	err = init();
	if (err == -1) {
		err_dbg(0, "init err");
		return -1;
	}

	err = validate_args(argc, argv);
	if (err == -1) {
		usage(argv);
		return -1;
	}

	conf = argv[1];
	is_test = atoi(argv[2]);

	err = parse_conf(conf);
	if (err == -1) {
		err_dbg(0, "parse_conf err");
		return -1;
	}

	target = find_target(target_version);
	if (!target) {
		err_dbg(0, "Target %s not found\n");
		return -1;
	}

	if (!is_test) {
		fprintf(stderr, "qemu_fuzzlib_env_setup ...");
		env = qemu_fuzzlib_env_setup(qemu_fuzzlib_user_name,
						qemu_fuzzlib_userid,
						qemu_exec_path, bzImage_path,
						osImage_path, rsa_path, host_ip,
						instance_nr, idle_sec,
						instance_memsz,
						instance_core, env_workdir,
						guest_workdir, guest_user,
						guest_sh_file, guest_c_file,
						sample_fname, db_file, db_init,
						mutate);
		if (env) {
			fprintf(stderr, "done\n");
			qemu_fuzzlib_env_run(env);
			qemu_fuzzlib_env_destroy(env);
		} else {
			fprintf(stderr, "failed\n");
		}
	} else {
		do_test();
	}

	cleanup();
	return 0;
}
