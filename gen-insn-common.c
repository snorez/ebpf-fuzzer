#include "ebpf_fuzzer.h"

int gen_non_insn(struct bpf_insn *insns, int *idx)
{
	unsigned __idx = *idx;
	COPY_INSNS(insns, __idx, BPF_MOV64_IMM(BPF_REG_0, 0));
	*idx = __idx;
	return 0;
}

int gen_jmp_insn_common(struct bpf_insn *insns, int *idx, int is_imm, int is_64,
			int reg0, int reg1, long imm_v, int op)
{
	unsigned __idx = *idx;

	if (is_64 && is_imm) {
		COPY_INSNS(insns, __idx, BPF_JMP_IMM(op, reg0, imm_v, 1));
	} else if (is_64 && (!is_imm)) {
		COPY_INSNS(insns, __idx, BPF_JMP_REG(op, reg0, reg1, 1));
	} else if ((!is_64) && is_imm) {
		COPY_INSNS(insns, __idx, BPF_JMP32_IMM(op, reg0, imm_v, 1));
	} else if ((!is_64) && (!is_imm)) {
		COPY_INSNS(insns, __idx, BPF_JMP32_REG(op, reg0, reg1, 1));
	}
	COPY_INSNS(insns, __idx, BPF_EXIT_INSN());

	*idx = __idx;
	return 0;
}

int gen_alu_insn_common(struct bpf_insn *insns, int *idx, int is_imm, int is_64,
			int reg0, int reg1, long imm_v, int op)
{
	unsigned __idx = *idx;

	if (is_64 && is_imm) {
		COPY_INSNS(insns, __idx, BPF_ALU64_IMM(op, reg0, imm_v));
	} else if (is_64 && (!is_imm)) {
		COPY_INSNS(insns, __idx, BPF_ALU64_REG(op, reg0, reg1));
	} else if ((!is_64) && is_imm) {
		COPY_INSNS(insns, __idx, BPF_ALU32_IMM(op, reg0, imm_v));
	} else if ((!is_64) && (!is_imm)) {
		COPY_INSNS(insns, __idx, BPF_ALU32_REG(op, reg0, reg1));
	}

	*idx = __idx;
	return 0;
}

int gen_mov_insn_common(struct bpf_insn *insns, int *idx, int is_imm, int is_64,
			int reg0, int reg1, long imm_v)
{
	unsigned __idx = *idx;

	if (is_64 && is_imm) {
		COPY_INSNS(insns, __idx, BPF_MOV64_IMM(reg0, imm_v));
	} else if (is_64 && (!is_imm)) {
		COPY_INSNS(insns, __idx, BPF_MOV64_REG(reg0, reg1));
	} else if ((!is_64) && is_imm) {
		COPY_INSNS(insns, __idx, BPF_MOV32_IMM(reg0, imm_v));
	} else if ((!is_64) && (!is_imm)) {
		COPY_INSNS(insns, __idx, BPF_MOV32_REG(reg0, reg1));
	}

	*idx = __idx;
	return 0;
}

int gen_ld_insn_common(struct bpf_insn *insns, int *idx, int reg0, long imm_v)
{
	unsigned __idx = *idx;

	COPY_INSNS(insns, __idx, BPF_LD_IMM64(reg0, imm_v));

	*idx = __idx;
	return 0;
}
