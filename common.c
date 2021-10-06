#include "./common.h"

char *bpf_reg_str[] = {
	[0] = "BPF_REG_0",
	[1] = "BPF_REG_1",
	[2] = "BPF_REG_2",
	[3] = "BPF_REG_3",
	[4] = "BPF_REG_4",
	[5] = "BPF_REG_5",
	[6] = "BPF_REG_6",
	[7] = "BPF_REG_7",
	[8] = "BPF_REG_8",
	[9] = "BPF_REG_9",
	[10] = "BPF_REG_10",
};

char *bpf_alu_op_str[] = {
	[BPF_ADD] = "BPF_ADD",
	[BPF_SUB] = "BPF_SUB",
	[BPF_MUL] = "BPF_MUL",
	[BPF_DIV] = "BPF_DIV",
	[BPF_OR] = "BPF_OR",
	[BPF_AND] = "BPF_AND",
	[BPF_LSH] = "BPF_LSH",
	[BPF_RSH] = "BPF_RSH",
	[BPF_NEG] = "BPF_NEG",
	[BPF_MOD] = "BPF_MOD",
	[BPF_XOR] = "BPF_XOR",
	[BPF_MOV] = "BPF_MOV",
	[BPF_ARSH] = "BPF_ARSH",
};

char *bpf_jmp_op_str[] = {
	[BPF_JA] = "BPF_JA",
	[BPF_JEQ] = "BPF_JEQ",
	[BPF_JGT] = "BPF_JGT",
	[BPF_JGE] = "BPF_JGE",
	[BPF_JSET] = "BPF_JSET",
	[BPF_JNE] = "BPF_JNE",
	[BPF_JLT] = "BPF_JLT",
	[BPF_JLE] = "BPF_JLE",
	[BPF_JSGT] = "BPF_JSGT",
	[BPF_JSGE] = "BPF_JSGE",
	[BPF_JSLT] = "BPF_JSLT",
	[BPF_JSLE] = "BPF_JSLE",
	[BPF_CALL] = "BPF_CALL",
	[BPF_EXIT] = "BPF_EXIT",
};

char *bpf_size_str[] = {
	[BPF_W] = "BPF_W",
	[BPF_H] = "BPF_H",
	[BPF_B] = "BPF_B",
	[BPF_DW] = "BPF_DW",
};
