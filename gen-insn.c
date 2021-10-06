#include "ebpf_fuzzer.h"

static int invalid_reg_used = 0;
static int extra0_reg_used = 0;
static __maybe_unused struct reg_usage regs[MAX_BPF_REG];	/* TODO */

enum jmp_ops {
	JMP_OPS_MIN,
	JMP_OPS_JNE,
	JMP_OPS_JLT,
	JMP_OPS_JLE,
	JMP_OPS_JSGT,
	JMP_OPS_JSGE,
	JMP_OPS_JSLT,
	JMP_OPS_JSLE,
	JMP_OPS_JA,
	JMP_OPS_JEQ,
	JMP_OPS_JGT,
	JMP_OPS_JGE,
	JMP_OPS_JSET,
	JMP_OPS_MAX,
};

int jmp_ops_codes[] = {
	[JMP_OPS_JNE] = BPF_JNE,
	[JMP_OPS_JLT] = BPF_JLT,
	[JMP_OPS_JLE] = BPF_JLE,
	[JMP_OPS_JSGT] = BPF_JSGT,
	[JMP_OPS_JSGE] = BPF_JSGE,
	[JMP_OPS_JSLT] = BPF_JSLT,
	[JMP_OPS_JSLE] = BPF_JSLE,
	[JMP_OPS_JA] = BPF_JA,
	[JMP_OPS_JEQ] = BPF_JEQ,
	[JMP_OPS_JGT] = BPF_JGT,
	[JMP_OPS_JGE] = BPF_JGE,
	[JMP_OPS_JSET] = BPF_JSET,
};

enum alu_ops {
	ALU_OPS_MIN,
	ALU_OPS_ADD,
	ALU_OPS_SUB,
	ALU_OPS_MUL,
	ALU_OPS_DIV,
	ALU_OPS_OR,
	ALU_OPS_AND,
	ALU_OPS_LSH,
	ALU_OPS_RSH,
	ALU_OPS_NEG,
	ALU_OPS_MOD,
	ALU_OPS_XOR,
	ALU_OPS_MAX,
};

int alu_ops_codes[] = {
	[ALU_OPS_ADD] = BPF_ADD,
	[ALU_OPS_SUB] = BPF_SUB,
	[ALU_OPS_MUL] = BPF_MUL,
	[ALU_OPS_DIV] = BPF_DIV,
	[ALU_OPS_OR] = BPF_OR,
	[ALU_OPS_AND] = BPF_AND,
	[ALU_OPS_LSH] = BPF_LSH,
	[ALU_OPS_RSH] = BPF_RSH,
	[ALU_OPS_NEG] = BPF_NEG,
	[ALU_OPS_MOD] = BPF_MOD,
	[ALU_OPS_XOR] = BPF_XOR,
};

enum insn_generator_idx {
	INSN_GENERATOR_MIN,
	INSN_GENERATOR_JMP,
	INSN_GENERATOR_ALU,
	INSN_GENERATOR_MOV,
	INSN_GENERATOR_LD,
	INSN_GENERATOR_NON,
	INSN_GENERATOR_MAX,
};

static inline int rand_ops(int *arr, int min, int max)
{
	int idx = rand_range(min, max);
	return arr[idx];
}

static inline int rand_jmp_ops(void)
{
	return rand_ops(jmp_ops_codes, JMP_OPS_MIN+1, JMP_OPS_MAX);
}

static inline int rand_alu_ops(void)
{
	return rand_ops(alu_ops_codes, ALU_OPS_MIN+1, ALU_OPS_MAX);
}

typedef int		(*insn_generator)(struct bpf_insn *insns, int *idx);
static int gen_jmp_insn(struct bpf_insn *insns, int *idx);
static int gen_alu_insn(struct bpf_insn *insns, int *idx);
static int gen_mov_insn(struct bpf_insn *insns, int *idx);
static int gen_ld_insn(struct bpf_insn *insns, int *idx);
static int gen_last_insn(struct bpf_insn *insns, int *idx);
static insn_generator generators[] = {
	[INSN_GENERATOR_JMP] = gen_jmp_insn,
	[INSN_GENERATOR_ALU] = gen_alu_insn,
	[INSN_GENERATOR_MOV] = gen_mov_insn,
	[INSN_GENERATOR_LD] = gen_ld_insn,
	[INSN_GENERATOR_NON] = gen_non_insn,
	[INSN_GENERATOR_MAX] = gen_last_insn,
};

static int gen_body0_min_bound(struct bpf_insn *insns, int *idx, long minv,
				int _signed, int _64bit)
{
	int __idx = *idx;
	int reg = SPECIAL_REG;

	COPY_INSNS(insns, __idx, BPF_MOV64_IMM(BPF_REG_0, 0));
	if (_64bit) {
		if (_signed)
			COPY_INSNS(insns, __idx, BPF_JMP_IMM(BPF_JSGT, reg, minv, 1));
		else
			COPY_INSNS(insns, __idx, BPF_JMP_IMM(BPF_JGT, reg, minv, 1));
	} else {
		if (_signed)
			COPY_INSNS(insns, __idx, BPF_JMP32_IMM(BPF_JSGT, reg, minv, 1));
		else
			COPY_INSNS(insns, __idx, BPF_JMP32_IMM(BPF_JGT, reg, minv, 1));
	}
	COPY_INSNS(insns, __idx, BPF_EXIT_INSN());

	*idx = __idx;
	return 0;
}

static int gen_body0_max_bound(struct bpf_insn *insns, int *idx, long maxv,
				 int _signed, int _64bit)
{
	int __idx = *idx;
	int reg = SPECIAL_REG;

	COPY_INSNS(insns, __idx, BPF_MOV64_IMM(BPF_REG_0, 0));
	if (s_rand32() % 2)
		COPY_INSNS(insns, __idx, BPF_MOV64_IMM(UMAX_REG, maxv));
	else
		COPY_INSNS(insns, __idx, BPF_MOV32_IMM(UMAX_REG, maxv));

	if (_64bit) {
		if (_signed)
			COPY_INSNS(insns, __idx, BPF_JMP_REG(BPF_JSLT, reg, UMAX_REG, 1));
		else
			COPY_INSNS(insns, __idx, BPF_JMP_REG(BPF_JLT, reg, UMAX_REG, 1));
	} else {
		if (_signed)
			COPY_INSNS(insns, __idx, BPF_JMP32_REG(BPF_JSLT, reg, UMAX_REG, 1));
		else
			COPY_INSNS(insns, __idx, BPF_JMP32_REG(BPF_JLT, reg, UMAX_REG, 1));
	}
	COPY_INSNS(insns, __idx, BPF_EXIT_INSN());

	*idx = __idx;
	return 0;
}

static long gen_min_val(void)
{
	long v;
	v = rand_range(-FUZZ_MAP_SIZE, FUZZ_MAP_SIZE+1);

	return v;
}

static long gen_max_val(void)
{
	long v;
	static unsigned range = 0x100;
	static unsigned max_bits = 64;
	int bits = rand_range(0, max_bits);
	int range_v = rand_range(-range, range+1);
	v = (1ULL<<bits);
	v += range_v;

	return v;
}

static int gen_body0(struct bpf_insn *insns, int *cnt, unsigned long special_v)
{
	int err = 0;
	int idx = 0;

	unsigned long umin = gen_min_val();
	unsigned long umax = gen_max_val();
	int _signed_max = s_rand32() % 2;
	int _64bit_max = s_rand32() % 2;
	int _signed_min = s_rand32() % 2;
	int _64bit_min = s_rand32() % 2;

	COPY_INSNS(insns, idx, BPF_LDX_MEM(BPF_DW, SPECIAL_REG, STORAGE_REG, 0));

	if (s_rand32() % 2) {
		err = gen_body0_max_bound(insns, &idx, umax, _signed_max,
					  _64bit_max);
		if (err < 0) {
			return -1;
		}
	}

	if (s_rand32() % 2) {
		err = gen_body0_min_bound(insns, &idx, umin, _signed_min,
					  _64bit_min);
		if (err < 0) {
			return -1;
		}
	}

	*cnt = idx;
	return 0;
}

static int gen_jmp_insn(struct bpf_insn *insns, int *idx)
{
	int __idx = *idx;
	int err = 0;

	int _64bit = s_rand32() % 2;
	int is_imm = s_rand32() % 2;
	int op_code = rand_jmp_ops();

	if (is_imm) {
		long imm_v;
		if (_64bit)
			imm_v = s_rand64();
		else
			imm_v = s_rand32();

		int reg;
		int reg_id = 0;

		if (extra0_reg_used) {
			reg_id = s_rand32() % 2;
		}

		if (!reg_id) {
			if (invalid_reg_used)
				if (s_rand32() % 2)
					reg = INVALID_P_REG;
				else
					reg = SPECIAL_REG;
			else
				reg = SPECIAL_REG;
		} else {
			reg = EXTRA0_REG;
		}

		err = gen_jmp_insn_common(insns, &__idx, is_imm, _64bit, reg,
					  0, imm_v, op_code);
		if (err < 0) {
			return -1;
		}
	} else {
		/*
		 * XXX: pick up two registers in EXTRA0_REG, SPECIAL_REG.
		 * if INVALID_P_REG is in use, take it instead of SPECIAL_REG.
		 */
		int reg0, reg1;
		if (invalid_reg_used) {
			if (s_rand32() % 2)
				reg0 = INVALID_P_REG;
			else
				reg0 = SPECIAL_REG;
		} else {
			reg0 = SPECIAL_REG;
		}

		if (!extra0_reg_used) {
			/* XXX: set the EXTRA0_REG first */
			if (s_rand32() % 2) {
				err = gen_ld_insn_common(insns, &__idx,
							 EXTRA0_REG,
							 s_rand64());
			} else {
				err = gen_mov_insn_common(insns, &__idx, 1,
							  s_rand32() % 2,
							  EXTRA0_REG, 0,
							  s_rand64());
			}
			if (err < 0) {
				return -1;
			}
			extra0_reg_used = 1;
		}

		if (s_rand32() % 2) {
			reg1 = reg0;
			reg0 = EXTRA0_REG;
		} else {
			reg1 = EXTRA0_REG;
		}
		err = gen_jmp_insn_common(insns, &__idx, is_imm, _64bit,
					  reg0,	reg1, 0, op_code);
		if (err < 0) {
			return -1;
		}
	}

	*idx = __idx;
	return 0;
}

static int gen_alu_insn(struct bpf_insn *insns, int *idx)
{
	int __idx = *idx;
	int err = 0;

	int _64bit = s_rand32() % 2;
	int is_imm = s_rand32() % 2;
	int op_code = rand_alu_ops();

	if (is_imm) {
		long imm_v;
		if (_64bit)
			imm_v = s_rand64();
		else
			imm_v = s_rand32();

		int reg;
		int reg_id = 0;

		if (extra0_reg_used) {
			reg_id = s_rand32() % 2;
		}

		if (!reg_id) {
			if (invalid_reg_used)
				if (s_rand32() % 2)
					reg = INVALID_P_REG;
				else
					reg = SPECIAL_REG;
			else
				reg = SPECIAL_REG;
		} else {
			reg = EXTRA0_REG;
		}

		err = gen_alu_insn_common(insns, &__idx, is_imm, _64bit, reg,
					  0, imm_v, op_code);
		if (err < 0) {
			return -1;
		}
	} else {
		int reg0, reg1;
		if (invalid_reg_used) {
			if (s_rand32() % 2)
				reg0 = INVALID_P_REG;
			else
				reg0 = SPECIAL_REG;
		} else {
			reg0 = SPECIAL_REG;
		}

		if (!extra0_reg_used) {
			if (s_rand32() % 2) {
				err = gen_ld_insn_common(insns, &__idx,
							 EXTRA0_REG,
							 s_rand64());
			} else {
				err = gen_mov_insn_common(insns, &__idx, 1,
							  s_rand32() % 2,
							  EXTRA0_REG, 0,
							  s_rand64());
			}

			if (err < 0) {
				return -1;
			}
			extra0_reg_used = 1;
		}

		if (s_rand32() % 2) {
			reg1 = reg0;
			reg0 = EXTRA0_REG;
		} else {
			reg1 = EXTRA0_REG;
		}

		err = gen_alu_insn_common(insns, &__idx, is_imm, _64bit,
					  reg0, reg1, 0, op_code);
		if (err < 0) {
			return -1;
		}
	}

	*idx = __idx;
	return 0;
}

static int gen_mov_insn(struct bpf_insn *insns, int *idx)
{
	int __idx = *idx;
	int err = 0;

	int _64bit = s_rand32() % 2;
	int is_imm = s_rand32() % 2;

	if (is_imm) {
		long imm_v;
		if (_64bit)
			imm_v = s_rand64();
		else
			imm_v = s_rand32();

		int reg;
		int reg_id = s_rand32() % 2;

		if (!reg_id) {
			if (invalid_reg_used)
				if (s_rand32() % 2)
					reg = INVALID_P_REG;
				else
					reg = SPECIAL_REG;
			else
				reg = SPECIAL_REG;
		} else {
			reg = EXTRA0_REG;
		}

		err = gen_mov_insn_common(insns, &__idx, is_imm, _64bit, reg,
					  0, imm_v);
		if (err < 0) {
			return -1;
		}

		if ((reg == EXTRA0_REG) && (!extra0_reg_used)) {
			extra0_reg_used = 1;
		}
	} else {
		int reg0, reg1;
		int is_src = s_rand32() % 2;
		int sort_cases = s_rand32() % 3;

		switch (sort_cases) {
		case 0:
		{
			/* INVALID_P_REG and SPECIAL_REG */
			reg0 = INVALID_P_REG;
			reg1 = SPECIAL_REG;
			break;
		}
		case 1:
		{
			/* INVALID_P_REG and EXTRA0_REG */
			reg0 = INVALID_P_REG;
			reg1 = EXTRA0_REG;
			break;
		}
		case 2:
		{
			/* SPECIAL_REG and EXTRA0_REG */
			reg0 = SPECIAL_REG;
			reg1 = EXTRA0_REG;
			break;
		}
		default:
		{
			BUG();
			break;
		}
		}

		if (is_src) {
			int tmp;
			tmp = reg0;
			reg0 = reg1;
			reg1 = tmp;
		}

		if ((reg1 == INVALID_P_REG) && (!invalid_reg_used)) {
			if (s_rand32() % 2) {
				err = gen_ld_insn_common(insns, &__idx,
							 reg1, s_rand64());
			} else {
				err = gen_mov_insn_common(insns, &__idx, 1,
							  s_rand32() % 2,
							  reg1, 0,
							  s_rand64());
			}

			if (err < 0) {
				return -1;
			}
			invalid_reg_used = 1;
		}

		if ((reg1 == EXTRA0_REG) && (!extra0_reg_used)) {
			if (s_rand32() % 2) {
				err = gen_ld_insn_common(insns, &__idx,
							 reg1, s_rand64());
			} else {
				err = gen_mov_insn_common(insns, &__idx, 1,
							  s_rand32() % 2,
							  reg1, 0,
							  s_rand64());
			}

			if (err < 0) {
				return -1;
			}
			extra0_reg_used = 1;
		}

		err = gen_mov_insn_common(insns, &__idx, is_imm, _64bit, reg0,
					  reg1, 0);
		if (err < 0) {
			return -1;
		}
	}

	*idx = __idx;
	return 0;
}

static int gen_ld_insn(struct bpf_insn *insns, int *idx)
{
	int __idx = *idx;
	int err = 0;

	/* for now, just set EXTRA0_REG */
	if (extra0_reg_used) {
		return 0;
	}

	err = gen_ld_insn_common(insns, &__idx, EXTRA0_REG, s_rand64());
	if (err < 0) {
		return -1;
	}

	extra0_reg_used = 1;
	*idx = __idx;
	return 0;
}

static int gen_last_insn(struct bpf_insn *insns, int *idx)
{
	if (invalid_reg_used) {
		return 0;
	}

	int __idx = *idx;
	if (s_rand32() % 2)
		COPY_INSNS(insns, __idx, BPF_MOV64_REG(INVALID_P_REG, SPECIAL_REG));
	else
		COPY_INSNS(insns, __idx, BPF_MOV32_REG(INVALID_P_REG, SPECIAL_REG));

	*idx = __idx;
	return 0;
}

static int gen_body1(struct bpf_insn *insns, int *cnt, u32 max_body_insn)
{
	int idx = 0;
	int err = 0;

	invalid_reg_used = 0;
	extra0_reg_used = 0;

	while (1) {
		int insn_idx = rand_range(INSN_GENERATOR_MIN+1, INSN_GENERATOR_MAX);
		err = generators[insn_idx](insns, &idx);
		if (err < 0)
			return -1;

		if (idx > max_body_insn) {
			err = generators[INSN_GENERATOR_MAX](insns, &idx);
			if (err < 0)
				return -1;
			break;
		}
	}

	*cnt = idx;
	return 0;
}

static int insn_body(struct bpf_insn *insns, int *idx, int max,
				unsigned long special_val, u32 body1_max)
{
	int err = 0;

	struct bpf_insn header[BPF_MAXINSNS];
	struct bpf_insn body[BPF_MAXINSNS];
	int header_cnt = 0;
	int body_cnt = 0;

	err = gen_body0(header, &header_cnt, special_val);
	if (err < 0) {
		return -1;
	}

	err = gen_body1(body, &body_cnt, body1_max);
	if (err < 0) {
		return -1;
	}

	unsigned insn_cnt = header_cnt + body_cnt;
	struct bpf_insn this_insns[insn_cnt];
	for (unsigned i = 0; i < header_cnt; i++) {
		this_insns[i] = header[i];
	}
	for (unsigned i = 0; i < body_cnt; i++) {
		this_insns[i+header_cnt] = body[i];
	}

	err = insn_add(insns, idx, max, this_insns, insn_cnt);
	if (err < 0) {
		return -1;
	}

	return 0;
}

static int insn_alu_map_ptr(struct bpf_insn *insns, int *idx, int max)
{
	int err = 0;

	struct bpf_insn this_insns[] = {
		BPF_ALU64_REG(BPF_SUB, CORRUPT_REG, INVALID_P_REG),
	};

	err = insn_add(insns, idx, max, this_insns, ARRAY_CNT(this_insns));
	if (err < 0) {
		return -1;
	}

	return 0;
}

static int insn_write_mem(struct bpf_insn *insns, int *idx, int max)
{
	int err = 0;
	struct bpf_insn this_insns[] = {
		BPF_LDX_MEM(BPF_DW, LEAKED_V_REG, CORRUPT_REG, 0),
		BPF_STX_MEM(BPF_DW, STORAGE_REG, LEAKED_V_REG, 8),
		BPF_MOV64_IMM(BPF_REG_0, 1),
	};

	err = insn_add(insns, idx, max, this_insns, ARRAY_CNT(this_insns));
	if (err < 0) {
		return -1;
	}

	return 0;
}

static int insn_exit(struct bpf_insn *insns, int *idx, int max)
{
	struct bpf_insn this_insns[] = {
		BPF_EXIT_INSN(),
	};

	return insn_add(insns, idx, max, this_insns, ARRAY_CNT(this_insns));
}

static char *sample_header = ""
"#include <stdio.h>\n"
"#include <stdlib.h>\n"
"#include <string.h>\n"
"#include <stdint.h>\n"
"#include <errno.h>\n"
"#include <assert.h>\n"
"#include <unistd.h>\n"
"#include <sys/types.h>\n"
"#include <sys/wait.h>\n"
"#include <sys/time.h>\n"
"#include <fcntl.h>\n"
"#include <sys/syscall.h>\n"
"#include <sys/ioctl.h>\n"
"#include <sys/stat.h>\n"
"#include <sys/socket.h>\n"
"#include <signal.h>\n"
"#include <netinet/in.h>\n"
"#include <arpa/inet.h>\n"
"#include <linux/bpf.h>\n"
"#include <linux/bpf_common.h>\n"
"#include <sys/prctl.h>\n"
"\n"
"enum qemu_fuzzlib_inst_res {\n"
"	QEMU_FUZZLIB_INST_INVALID = -1,\n"
"	QEMU_FUZZLIB_INST_NOT_TESTED = 0,\n"
"	QEMU_FUZZLIB_INST_VALID,\n"
"	QEMU_FUZZLIB_INST_BOOM,\n"
"};\n"
"\n"
"typedef __s8	s8;\n"
"typedef __s16	s16;\n"
"typedef __s32	s32;\n"
"typedef __s64	s64;\n"
"typedef __u8	u8;\n"
"typedef __u16	u16;\n"
"typedef __u32	u32;\n"
"typedef __u64	u64;\n"
"\n"
"struct xmsg {\n"
"	unsigned long		special_value;\n"
"	unsigned long		insn_cnt;\n"
"	struct bpf_insn		insns[BPF_MAXINSNS];\n"
"};\n"
"\n"
"#ifndef BPF_JMP32\n"
"#define	BPF_JMP32	0x06\n"
"#endif\n"
"\n"
"/* ArgX, context and stack frame pointer register positions. Note,\n"
" * Arg1, Arg2, Arg3, etc are used as argument mappings of function\n"
" * calls in BPF_CALL instruction.\n"
" */\n"
"#define BPF_REG_ARG1	BPF_REG_1\n"
"#define BPF_REG_ARG2	BPF_REG_2\n"
"#define BPF_REG_ARG3	BPF_REG_3\n"
"#define BPF_REG_ARG4	BPF_REG_4\n"
"#define BPF_REG_ARG5	BPF_REG_5\n"
"#define BPF_REG_CTX	BPF_REG_6\n"
"#define BPF_REG_FP	BPF_REG_10\n"
"\n"
"/* Additional register mappings for converted user programs. */\n"
"#define BPF_REG_A	BPF_REG_0\n"
"#define BPF_REG_X	BPF_REG_7\n"
"#define BPF_REG_TMP	BPF_REG_2	/* scratch reg */\n"
"#define BPF_REG_D	BPF_REG_8	/* data, callee-saved */\n"
"#define BPF_REG_H	BPF_REG_9	/* hlen, callee-saved */\n"
"\n"
"/* Kernel hidden auxiliary/helper register. */\n"
"#define BPF_REG_AX		MAX_BPF_REG\n"
"#define MAX_BPF_EXT_REG		(MAX_BPF_REG + 1)\n"
"#define MAX_BPF_JIT_REG		MAX_BPF_EXT_REG\n"
"\n"
"/* unused opcode to mark special call to bpf_tail_call() helper */\n"
"#define BPF_TAIL_CALL	0xf0\n"
"\n"
"/* unused opcode to mark call to interpreter with arguments */\n"
"#define BPF_CALL_ARGS	0xe0\n"
"\n"
"/* As per nm, we expose JITed images as text (code) section for\n"
" * kallsyms. That way, tools like perf can find it to match\n"
" * addresses.\n"
" */\n"
"#define BPF_SYM_ELF_TYPE	't'\n"
"\n"
"/* BPF program can access up to 512 bytes of stack space. */\n"
"#define MAX_BPF_STACK	512\n"
"\n"
"/* Helper macros for filter block array initializers. */\n"
"\n"
"/* ALU ops on registers, bpf_add|sub|...: dst_reg += src_reg */\n"
"\n"
"#define BPF_ALU64_REG(OP, DST, SRC)				\\\n"
"	((struct bpf_insn) {					\\\n"
"		.code  = BPF_ALU64 | BPF_OP(OP) | BPF_X,	\\\n"
"		.dst_reg = DST,					\\\n"
"		.src_reg = SRC,					\\\n"
"		.off   = 0,					\\\n"
"		.imm   = 0 })\n"
"\n"
"#define BPF_ALU32_REG(OP, DST, SRC)				\\\n"
"	((struct bpf_insn) {					\\\n"
"		.code  = BPF_ALU | BPF_OP(OP) | BPF_X,		\\\n"
"		.dst_reg = DST,					\\\n"
"		.src_reg = SRC,					\\\n"
"		.off   = 0,					\\\n"
"		.imm   = 0 })\n"
"\n"
"/* ALU ops on immediates, bpf_add|sub|...: dst_reg += imm32 */\n"
"\n"
"#define BPF_ALU64_IMM(OP, DST, IMM)				\\\n"
"	((struct bpf_insn) {					\\\n"
"		.code  = BPF_ALU64 | BPF_OP(OP) | BPF_K,	\\\n"
"		.dst_reg = DST,					\\\n"
"		.src_reg = 0,					\\\n"
"		.off   = 0,					\\\n"
"		.imm   = IMM })\n"
"\n"
"#define BPF_ALU32_IMM(OP, DST, IMM)				\\\n"
"	((struct bpf_insn) {					\\\n"
"		.code  = BPF_ALU | BPF_OP(OP) | BPF_K,		\\\n"
"		.dst_reg = DST,					\\\n"
"		.src_reg = 0,					\\\n"
"		.off   = 0,					\\\n"
"		.imm   = IMM })\n"
"\n"
"/* Endianess conversion, cpu_to_{l,b}e(), {l,b}e_to_cpu() */\n"
"\n"
"#define BPF_ENDIAN(TYPE, DST, LEN)				\\\n"
"	((struct bpf_insn) {					\\\n"
"		.code  = BPF_ALU | BPF_END | BPF_SRC(TYPE),	\\\n"
"		.dst_reg = DST,					\\\n"
"		.src_reg = 0,					\\\n"
"		.off   = 0,					\\\n"
"		.imm   = LEN })\n"
"\n"
"/* Short form of mov, dst_reg = src_reg */\n"
"\n"
"#define BPF_MOV64_REG(DST, SRC)					\\\n"
"	((struct bpf_insn) {					\\\n"
"		.code  = BPF_ALU64 | BPF_MOV | BPF_X,		\\\n"
"		.dst_reg = DST,					\\\n"
"		.src_reg = SRC,					\\\n"
"		.off   = 0,					\\\n"
"		.imm   = 0 })\n"
"\n"
"#define BPF_MOV32_REG(DST, SRC)					\\\n"
"	((struct bpf_insn) {					\\\n"
"		.code  = BPF_ALU | BPF_MOV | BPF_X,		\\\n"
"		.dst_reg = DST,					\\\n"
"		.src_reg = SRC,					\\\n"
"		.off   = 0,					\\\n"
"		.imm   = 0 })\n"
"\n"
"/* Short form of mov, dst_reg = imm32 */\n"
"\n"
"#define BPF_MOV64_IMM(DST, IMM)					\\\n"
"	((struct bpf_insn) {					\\\n"
"		.code  = BPF_ALU64 | BPF_MOV | BPF_K,		\\\n"
"		.dst_reg = DST,					\\\n"
"		.src_reg = 0,					\\\n"
"		.off   = 0,					\\\n"
"		.imm   = IMM })\n"
"\n"
"#define BPF_MOV32_IMM(DST, IMM)					\\\n"
"	((struct bpf_insn) {					\\\n"
"		.code  = BPF_ALU | BPF_MOV | BPF_K,		\\\n"
"		.dst_reg = DST,					\\\n"
"		.src_reg = 0,					\\\n"
"		.off   = 0,					\\\n"
"		.imm   = IMM })\n"
"\n"
"/* Special form of mov32, used for doing explicit zero extension on dst. */\n"
"#define BPF_ZEXT_REG(DST)					\\\n"
"	((struct bpf_insn) {					\\\n"
"		.code  = BPF_ALU | BPF_MOV | BPF_X,		\\\n"
"		.dst_reg = DST,					\\\n"
"		.src_reg = DST,					\\\n"
"		.off   = 0,					\\\n"
"		.imm   = 1 })\n"
"\n"
"/* BPF_LD_IMM64 macro encodes single 'load 64-bit immediate' insn */\n"
"#define BPF_LD_IMM64(DST, IMM)					\\\n"
"	BPF_LD_IMM64_RAW(DST, 0, IMM)\n"
"\n"
"#define BPF_LD_IMM64_RAW(DST, SRC, IMM)				\\\n"
"	((struct bpf_insn) {					\\\n"
"		.code  = BPF_LD | BPF_DW | BPF_IMM,		\\\n"
"		.dst_reg = DST,					\\\n"
"		.src_reg = SRC,					\\\n"
"		.off   = 0,					\\\n"
"		.imm   = (__u32) (IMM) }),			\\\n"
"	((struct bpf_insn) {					\\\n"
"		.code  = 0, /* zero is reserved opcode */	\\\n"
"		.dst_reg = 0,					\\\n"
"		.src_reg = 0,					\\\n"
"		.off   = 0,					\\\n"
"		.imm   = ((__u64) (IMM)) >> 32 })\n"
"\n"
"/* pseudo BPF_LD_IMM64 insn used to refer to process-local map_fd */\n"
"#define BPF_LD_MAP_FD(DST, MAP_FD)				\\\n"
"	BPF_LD_IMM64_RAW(DST, BPF_PSEUDO_MAP_FD, MAP_FD)\n"
"\n"
"/* Short form of mov based on type, BPF_X: dst_reg = src_reg, BPF_K: dst_reg = imm32 */\n"
"\n"
"#define BPF_MOV64_RAW(TYPE, DST, SRC, IMM)			\\\n"
"	((struct bpf_insn) {					\\\n"
"		.code  = BPF_ALU64 | BPF_MOV | BPF_SRC(TYPE),	\\\n"
"		.dst_reg = DST,					\\\n"
"		.src_reg = SRC,					\\\n"
"		.off   = 0,					\\\n"
"		.imm   = IMM })\n"
"\n"
"#define BPF_MOV32_RAW(TYPE, DST, SRC, IMM)			\\\n"
"	((struct bpf_insn) {					\\\n"
"		.code  = BPF_ALU | BPF_MOV | BPF_SRC(TYPE),	\\\n"
"		.dst_reg = DST,					\\\n"
"		.src_reg = SRC,					\\\n"
"		.off   = 0,					\\\n"
"		.imm   = IMM })\n"
"\n"
"/* Direct packet access, R0 = *(uint *) (skb->data + imm32) */\n"
"\n"
"#define BPF_LD_ABS(SIZE, IMM)					\\\n"
"	((struct bpf_insn) {					\\\n"
"		.code  = BPF_LD | BPF_SIZE(SIZE) | BPF_ABS,	\\\n"
"		.dst_reg = 0,					\\\n"
"		.src_reg = 0,					\\\n"
"		.off   = 0,					\\\n"
"		.imm   = IMM })\n"
"\n"
"/* Indirect packet access, R0 = *(uint *) (skb->data + src_reg + imm32) */\n"
"\n"
"#define BPF_LD_IND(SIZE, SRC, IMM)				\\\n"
"	((struct bpf_insn) {					\\\n"
"		.code  = BPF_LD | BPF_SIZE(SIZE) | BPF_IND,	\\\n"
"		.dst_reg = 0,					\\\n"
"		.src_reg = SRC,					\\\n"
"		.off   = 0,					\\\n"
"		.imm   = IMM })\n"
"\n"
"/* Memory load, dst_reg = *(uint *) (src_reg + off16) */\n"
"\n"
"#define BPF_LDX_MEM(SIZE, DST, SRC, OFF)			\\\n"
"	((struct bpf_insn) {					\\\n"
"		.code  = BPF_LDX | BPF_SIZE(SIZE) | BPF_MEM,	\\\n"
"		.dst_reg = DST,					\\\n"
"		.src_reg = SRC,					\\\n"
"		.off   = OFF,					\\\n"
"		.imm   = 0 })\n"
"\n"
"/* Memory store, *(uint *) (dst_reg + off16) = src_reg */\n"
"\n"
"#define BPF_STX_MEM(SIZE, DST, SRC, OFF)			\\\n"
"	((struct bpf_insn) {					\\\n"
"		.code  = BPF_STX | BPF_SIZE(SIZE) | BPF_MEM,	\\\n"
"		.dst_reg = DST,					\\\n"
"		.src_reg = SRC,					\\\n"
"		.off   = OFF,					\\\n"
"		.imm   = 0 })\n"
"\n"
"/* Atomic memory add, *(uint *)(dst_reg + off16) += src_reg */\n"
"\n"
"#define BPF_STX_XADD(SIZE, DST, SRC, OFF)			\\\n"
"	((struct bpf_insn) {					\\\n"
"		.code  = BPF_STX | BPF_SIZE(SIZE) | BPF_XADD,	\\\n"
"		.dst_reg = DST,					\\\n"
"		.src_reg = SRC,					\\\n"
"		.off   = OFF,					\\\n"
"		.imm   = 0 })\n"
"\n"
"/* Memory store, *(uint *) (dst_reg + off16) = imm32 */\n"
"\n"
"#define BPF_ST_MEM(SIZE, DST, OFF, IMM)				\\\n"
"	((struct bpf_insn) {					\\\n"
"		.code  = BPF_ST | BPF_SIZE(SIZE) | BPF_MEM,	\\\n"
"		.dst_reg = DST,					\\\n"
"		.src_reg = 0,					\\\n"
"		.off   = OFF,					\\\n"
"		.imm   = IMM })\n"
"\n"
"/* Conditional jumps against registers, if (dst_reg 'op' src_reg) goto pc + off16 */\n"
"\n"
"#define BPF_JMP_REG(OP, DST, SRC, OFF)				\\\n"
"	((struct bpf_insn) {					\\\n"
"		.code  = BPF_JMP | BPF_OP(OP) | BPF_X,		\\\n"
"		.dst_reg = DST,					\\\n"
"		.src_reg = SRC,					\\\n"
"		.off   = OFF,					\\\n"
"		.imm   = 0 })\n"
"\n"
"/* Conditional jumps against immediates, if (dst_reg 'op' imm32) goto pc + off16 */\n"
"\n"
"#define BPF_JMP_IMM(OP, DST, IMM, OFF)				\\\n"
"	((struct bpf_insn) {					\\\n"
"		.code  = BPF_JMP | BPF_OP(OP) | BPF_K,		\\\n"
"		.dst_reg = DST,					\\\n"
"		.src_reg = 0,					\\\n"
"		.off   = OFF,					\\\n"
"		.imm   = IMM })\n"
"\n"
"/* Like BPF_JMP_REG, but with 32-bit wide operands for comparison. */\n"
"\n"
"#define BPF_JMP32_REG(OP, DST, SRC, OFF)			\\\n"
"	((struct bpf_insn) {					\\\n"
"		.code  = BPF_JMP32 | BPF_OP(OP) | BPF_X,	\\\n"
"		.dst_reg = DST,					\\\n"
"		.src_reg = SRC,					\\\n"
"		.off   = OFF,					\\\n"
"		.imm   = 0 })\n"
"\n"
"/* Like BPF_JMP_IMM, but with 32-bit wide operands for comparison. */\n"
"\n"
"#define BPF_JMP32_IMM(OP, DST, IMM, OFF)			\\\n"
"	((struct bpf_insn) {					\\\n"
"		.code  = BPF_JMP32 | BPF_OP(OP) | BPF_K,	\\\n"
"		.dst_reg = DST,					\\\n"
"		.src_reg = 0,					\\\n"
"		.off   = OFF,					\\\n"
"		.imm   = IMM })\n"
"\n"
"/* Unconditional jumps, goto pc + off16 */\n"
"\n"
"#define BPF_JMP_A(OFF)						\\\n"
"	((struct bpf_insn) {					\\\n"
"		.code  = BPF_JMP | BPF_JA,			\\\n"
"		.dst_reg = 0,					\\\n"
"		.src_reg = 0,					\\\n"
"		.off   = OFF,					\\\n"
"		.imm   = 0 })\n"
"\n"
"/* Relative call */\n"
"\n"
"#define BPF_CALL_REL(TGT)					\\\n"
"	((struct bpf_insn) {					\\\n"
"		.code  = BPF_JMP | BPF_CALL,			\\\n"
"		.dst_reg = 0,					\\\n"
"		.src_reg = BPF_PSEUDO_CALL,			\\\n"
"		.off   = 0,					\\\n"
"		.imm   = TGT })\n"
"\n"
"#define	__bpf_call_base 0\n"
"#define BPF_EMIT_CALL(FUNC)					\\\n"
"	((struct bpf_insn) {					\\\n"
"		.code  = BPF_JMP | BPF_CALL,			\\\n"
"		.dst_reg = 0,					\\\n"
"		.src_reg = 0,					\\\n"
"		.off   = 0,					\\\n"
"		.imm   = ((FUNC) - __bpf_call_base) })\n"
"\n"
"/* Raw code statement block */\n"
"\n"
"#define BPF_RAW_INSN(CODE, DST, SRC, OFF, IMM)			\\\n"
"	((struct bpf_insn) {					\\\n"
"		.code  = CODE,					\\\n"
"		.dst_reg = DST,					\\\n"
"		.src_reg = SRC,					\\\n"
"		.off   = OFF,					\\\n"
"		.imm   = IMM })\n"
"\n"
"/* Program exit */\n"
"\n"
"#define BPF_EXIT_INSN()						\\\n"
"	((struct bpf_insn) {					\\\n"
"		.code  = BPF_JMP | BPF_EXIT,			\\\n"
"		.dst_reg = 0,					\\\n"
"		.src_reg = 0,					\\\n"
"		.off   = 0,					\\\n"
"		.imm   = 0 })\n"
"\n"
"#define	LISTENER_PORT		(1337)\n"
"#define	LISTENER_BACKLOG	(0x30)\n"
"#define	STORAGE_MAP_SIZE	(8192)\n"
"#define	FUZZ_MAP_SIZE		(8192)\n"
"\n"
"#define	ARRAY_CNT(arr)	(sizeof(arr) / sizeof(arr[0]))\n"
"\n"
"#define	CORRUPT_FD_CONST	10\n"
"#define	STORAGE_FD_CONST	11\n"
"#define	CORRUPT_REG		BPF_REG_9\n"
"#define	STORAGE_REG		BPF_REG_8\n"
"#define	SPECIAL_REG		BPF_REG_7\n"
"#define	INVALID_P_REG		BPF_REG_6\n"
"#define	LEAKED_V_REG		BPF_REG_5\n"
"#define	UMAX_REG		BPF_REG_4\n"
"#define	EXTRA0_REG		BPF_REG_3\n"
"#define	EXTRA1_REG		BPF_REG_2\n"
"#define	EXTRA2_REG		BPF_REG_1\n"
"#define	MAGIC_VAL1		0x4142434445464748\n"
"#define	MAGIC_VAL2		0x494a4b4c4d4e4f40\n"
"\n"
"static int bpf(unsigned int cmd, union bpf_attr *attr, size_t size)\n"
"{\n"
"	return syscall(SYS_bpf, cmd, attr, size);\n"
"}\n"
"\n"
"static int update_storage_map(int fd, unsigned long special_val)\n"
"{\n"
"	uint64_t key = 0;\n"
"	unsigned long buf[STORAGE_MAP_SIZE / sizeof(long)];\n"
"	buf[0] = special_val;\n"
"	for (int i = 1; i < (STORAGE_MAP_SIZE / sizeof(long)); i++) {\n"
"		buf[i] = MAGIC_VAL2;\n"
"	}\n"
"	union bpf_attr attr = {\n"
"		.map_fd = fd,\n"
"		.key = (uint64_t)&key,\n"
"		.value = (uint64_t)&buf,\n"
"	};\n"
"\n"
"	return bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));\n"
"}\n"
"\n"
"static int update_corrupt_map(int fd)\n"
"{\n"
"	uint64_t key = 0;\n"
"	unsigned long buf[STORAGE_MAP_SIZE / sizeof(long)];\n"
"	for (int i = 0; i < (STORAGE_MAP_SIZE / sizeof(long)); i++) {\n"
"		buf[i] = MAGIC_VAL1;\n"
"	}\n"
"	union bpf_attr attr = {\n"
"		.map_fd = fd,\n"
"		.key = (uint64_t)&key,\n"
"		.value = (uint64_t)&buf,\n"
"	};\n"
"\n"
"	return bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));\n"
"}\n"
"\n"
"static int init_maps(int *corrupt_map_fd, int *storage_map_fd)\n"
"{\n"
"	union bpf_attr corrupt_map = {\n"
"		.map_type = BPF_MAP_TYPE_ARRAY,\n"
"		.key_size = 4,\n"
"		.value_size = STORAGE_MAP_SIZE,\n"
"		.max_entries = 1,\n"
"	};\n"
"	strcpy(corrupt_map.map_name, \"corrupt_map\");\n"
"	*corrupt_map_fd = (int)bpf(BPF_MAP_CREATE, &corrupt_map,\n"
"				   sizeof(corrupt_map));\n"
"	if (*corrupt_map_fd < 0)\n"
"		return -1;\n"
"\n"
"	if (update_corrupt_map(*corrupt_map_fd) < 0)\n"
"		return -1;\n"
"\n"
"	union bpf_attr storage_map = {\n"
"		.map_type = BPF_MAP_TYPE_ARRAY,\n"
"		.key_size = 4,\n"
"		.value_size = STORAGE_MAP_SIZE,\n"
"		.max_entries = 1,\n"
"	};\n"
"	strcpy(corrupt_map.map_name, \"storage_map\");\n"
"	*storage_map_fd = (int)bpf(BPF_MAP_CREATE, &storage_map,\n"
"				   sizeof(storage_map));\n"
"	if (*storage_map_fd < 0)\n"
"		return -1;\n"
"\n"
"	if (update_storage_map(*storage_map_fd, 0) < 0)\n"
"		return -1;\n"
"\n"
"	return 0;\n"
"}\n"
"\n"
"static int read_map(int fd, void *buf, size_t size)\n"
"{\n"
"	assert(size <= (STORAGE_MAP_SIZE));\n"
"\n"
"	unsigned long lk[STORAGE_MAP_SIZE / sizeof(long)];\n"
"	memset(lk, 0, sizeof(lk));\n"
"	uint64_t key = 0;\n"
"	union bpf_attr lookup_map = {\n"
"		.map_fd = fd,\n"
"		.key = (uint64_t)&key,\n"
"		.value = (uint64_t)&lk,\n"
"	};\n"
"\n"
"	int err = bpf(BPF_MAP_LOOKUP_ELEM, &lookup_map, sizeof(lookup_map));\n"
"	if (err < 0) {\n"
"		return -1;\n"
"	}\n"
"\n"
"	memcpy(buf, lk, size);\n"
"\n"
"	return 0;\n"
"}\n"
"\n"
"static int setup_listener_sock(int port, int backlog)\n"
"{\n"
"	int sock_fd = socket(AF_INET,\n"
"				SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC,\n"
"				0);\n"
"	if (sock_fd < 0) {\n"
"		return sock_fd;\n"
"	}\n"
"\n"
"	struct sockaddr_in servaddr;\n"
"	servaddr.sin_family = AF_INET;\n"
"	servaddr.sin_port = htons(port);\n"
"	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);\n"
"\n"
"	int err = bind(sock_fd, (struct sockaddr *)&servaddr, sizeof(servaddr));\n"
"	if (err < 0) {\n"
"		close(sock_fd);\n"
"		return err;\n"
"	}\n"
"\n"
"	err = listen(sock_fd, backlog);\n"
"	if (err < 0) {\n"
"		close(sock_fd);\n"
"		return err;\n"
"	}\n"
"\n"
"	return sock_fd;\n"
"}\n"
"\n"
"static int setup_send_sock(void)\n"
"{\n"
"	return socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);\n"
"}\n"
"\n"
"#define	LOG_BUF_SIZE	65536\n"
"static char bpf_log_buf[LOG_BUF_SIZE];\n"
"\n"
"static int load_prog(struct bpf_insn *insns, size_t insn_count)\n"
"{\n"
"	union bpf_attr prog = {};\n"
"	prog.license = (uint64_t)\"GPL\";\n"
"	strcpy(prog.prog_name, \"ebpf_fuzzer\");\n"
"	prog.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;\n"
"	prog.insn_cnt = insn_count;\n"
"	prog.insns = (uint64_t)insns;\n"
"	prog.log_buf = (uint64_t)bpf_log_buf;\n"
"	prog.log_size = LOG_BUF_SIZE;\n"
"	prog.log_level = 1;\n"
"\n"
"	int prog_fd = bpf(BPF_PROG_LOAD, &prog, sizeof(prog));\n"
"	if (prog_fd < 0) {\n"
"		return -1;\n"
"	}\n"
"\n"
"	return prog_fd;\n"
"}\n"
"\n"
"static int exec_prog(int prog_fd, int *_err)\n"
"{\n"
"	int listener_sock = setup_listener_sock(LISTENER_PORT, LISTENER_BACKLOG);\n"
"	int send_sock = setup_send_sock();\n"
"\n"
"	if ((listener_sock < 0) || (send_sock < 0)) {\n"
"		return -1;\n"
"	}\n"
"\n"
"	if (setsockopt(listener_sock, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd,\n"
"			sizeof(prog_fd)) < 0) {\n"
"		return -1;\n"
"	}\n"
"\n"
"	struct sockaddr_in servaddr;\n"
"	servaddr.sin_family = AF_INET;\n"
"	servaddr.sin_port = htons(LISTENER_PORT);\n"
"	servaddr.sin_addr.s_addr = htonl(INADDR_ANY);\n"
"\n"
"	int err;\n"
"	err = connect(send_sock, (struct sockaddr *)&servaddr, sizeof(servaddr));\n"
"	if (err < 0) {\n"
"		*_err = errno;\n"
"	}\n"
"\n"
"	close(listener_sock);\n"
"	close(send_sock);\n"
"	return (err < 0) ? 1 : 0;\n"
"}\n"
"\n"
"static int detect_oob(char *buf0, char *buf1, size_t size)\n"
"{\n"
"	char *b = &buf1[8];\n"
"	unsigned long *_b = (unsigned long *)buf1;\n"
"	for (int i = 0; i < 8; i++) {\n"
"		if ((b[i] > 0x4f) || (b[i] < 0x40)) {\n"
"			fprintf(stderr, \"[1]: %lx\\n\", _b[1]);\n"
"			return 1;\n"
"		}\n"
"	}\n"
"\n"
"	fprintf(stderr, \"[2]: %lx\\n\", _b[2]);\n"
"	return 0;\n"
"}\n"
"\n"
"static int repro_xmsg(int corrupt_map_fd, int storage_map_fd, struct xmsg *msg)\n"
"{\n"
"	int err = 0;\n"
"	char buf0[STORAGE_MAP_SIZE];\n"
"	char buf1[STORAGE_MAP_SIZE];\n"
"\n"
"	err = update_storage_map(storage_map_fd, msg->special_value);\n"
"	if (err < 0) {\n"
"		fprintf(stderr, \"update_storage_map err\\n\");\n"
"		return -1;\n"
"	}\n"
"	fprintf(stderr, \"update_storage_map done.\\n\");\n"
"\n"
"	err = read_map(storage_map_fd, buf0, STORAGE_MAP_SIZE);\n"
"	if (err < 0) {\n"
"		fprintf(stderr, \"read_map err\\n\");\n"
"		return -1;\n"
"	}\n"
"\n"
"	/* load and execute prog */\n"
"	int prog_fd = load_prog(msg->insns, msg->insn_cnt);\n"
"	if (prog_fd < 0) {\n"
"		//fprintf(stderr, \"load_prog() err\\n\");\n"
"		return -1;\n"
"	}\n"
"	fprintf(stderr, \"%ld, %s.\\n\", strlen(bpf_log_buf), bpf_log_buf);\n"
"\n"
"	int connect_err;\n"
"	err = exec_prog(prog_fd, &connect_err);\n"
"	if (err != 1) {\n"
"		/* prog not execute successfully */\n"
"		return 0;\n"
"	}\n"
"	fprintf(stderr, \"exec_prog done.\\n\");\n"
"\n"
"	/* read the map again, check the content */\n"
"	err = read_map(storage_map_fd, buf1, STORAGE_MAP_SIZE);\n"
"	if (err < 0) {\n"
"		fprintf(stderr, \"read_map err\\n\");\n"
"		return -1;\n"
"	}\n"
"\n"
"	if (detect_oob(buf0, buf1, STORAGE_MAP_SIZE)) {\n"
"		return 1;\n"
"	}\n"
"\n"
"	return 0;\n"
"}\n"
"\n"
"int main(int argc, char *argv[])\n"
"{\n"
"	struct xmsg msg;\n"
"	int corrupt_map_fd, storage_map_fd;\n"
"	int err;\n"
"\n"
"	err = init_maps(&corrupt_map_fd, &storage_map_fd);\n"
"	if (err < 0) {\n"
"		fprintf(stderr, \"init_maps err\\n\");\n"
"		return QEMU_FUZZLIB_INST_NOT_TESTED;\n"
"	}\n"
"	dup2(corrupt_map_fd, CORRUPT_FD_CONST);\n"
"	dup2(storage_map_fd, STORAGE_FD_CONST);\n"
"	close(corrupt_map_fd);\n"
"	close(storage_map_fd);\n"
"	corrupt_map_fd = CORRUPT_FD_CONST;\n"
"	storage_map_fd = STORAGE_FD_CONST;\n"
"	memset(&msg, 0, sizeof(msg));\n"
"\n"
"	struct bpf_insn __insns[] = {\n";

static char *sample_tail = ""
"	msg.insn_cnt = ARRAY_CNT(__insns);\n"
"	memcpy(msg.insns, __insns, msg.insn_cnt * sizeof(struct bpf_insn));\n"
"\n"
"	err = repro_xmsg(corrupt_map_fd, storage_map_fd, &msg);\n"
"	if (err == 1) {\n"
"		fprintf(stderr, \"repro done\\n\");\n"
"		return QEMU_FUZZLIB_INST_BOOM;\n"
"	} else if (err == 0) {\n"
"		fprintf(stderr, \"repro failed\\n\");\n"
"		return QEMU_FUZZLIB_INST_VALID;\n"
"	} else if (err == -1) {\n"
"		fprintf(stderr, \"repro failed\\n\");\n"
"		return QEMU_FUZZLIB_INST_INVALID;\n"
"	}\n"
"}\n";

#define BODY_FORMAT "%s\t};\n\n\tmsg.special_value = 0x%lx;\n"
static int gen_sample_body(char *b, size_t len, u32 body1_max)
{
	int err;
	struct bpf_insn insns[BPF_MAXINSNS];
	int idx = 0;
	char insn_buf[BODY_LEN];
	memset(insn_buf, 0, BODY_LEN);

	/* 1 stage, gen special val */
	unsigned long this_special = s_rand64();

	/* 2 stage, gen insns */
	err = insn_get_map_ptr(insns, &idx, BPF_MAXINSNS, CORRUPT_FD_CONST,
				CORRUPT_REG);
	if (err < 0) {
		return -1;
	}

	err = insn_get_map_ptr(insns, &idx, BPF_MAXINSNS, STORAGE_FD_CONST,
				STORAGE_REG);
	if (err < 0) {
		return -1;
	}

	err = insn_body(insns, &idx, BPF_MAXINSNS, this_special, body1_max);
	if (err < 0) {
		return -1;
	}

	err = insn_alu_map_ptr(insns, &idx, BPF_MAXINSNS);
	if (err < 0) {
		return -1;
	}

	err = insn_write_mem(insns, &idx, BPF_MAXINSNS);
	if (err < 0) {
		return -1;
	}

	err = insn_exit(insns, &idx, BPF_MAXINSNS);
	if (err < 0) {
		return -1;
	}

	err = insn_print_common(insn_buf, BODY_LEN, insns, idx);
	if (err < 0) {
		return -1;
	}

	snprintf(b, len, BODY_FORMAT, insn_buf, this_special);
	return 0;
}

static int this_init(struct ebpf_fuzz_target *target)
{
	target->sample_header = sample_header;
	target->sample_tail = sample_tail;
	return 0;
}

struct ebpf_fuzz_target kern_5_8 = {
	.target_name = "general",
	.init = this_init,
	.gen_sample_body = gen_sample_body,
};
