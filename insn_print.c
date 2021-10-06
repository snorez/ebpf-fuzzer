#include "common.h"

static char *print_buf;
static size_t print_buflen;
static size_t print_bufidx;

#define	PRINT_TAIL(buf, IDX, cnt) \
	({\
	 if (print_bufidx + strlen(buf) > print_buflen)\
		return -1;\
	 memcpy(print_buf + print_bufidx, buf, strlen(buf));\
	 print_bufidx += strlen(buf);\
	 *idx = IDX + cnt;\
	 return 0;\
	 })

/* BPF_MOV64_REG */
static int do_mov64_reg_print(struct bpf_insn *insn, size_t cnt,
				size_t *idx)
{
	char buf[0x100];
	char *i = "BPF_MOV64_REG";
	size_t _idx = *idx;
	struct bpf_insn _insn0 = insn[_idx];
	snprintf(buf, 0x100, "%s(%s, %s),\n", i,
			bpf_reg_str[_insn0.dst_reg],
			bpf_reg_str[_insn0.src_reg]);

	PRINT_TAIL(buf, _idx, 1);
}

static int do_mov64_imm_print(struct bpf_insn *insn, size_t cnt,
				size_t *idx)
{
	char buf[0x100];
	char *i = "BPF_MOV64_IMM";
	size_t _idx = *idx;
	struct bpf_insn _insn0 = insn[_idx];
	snprintf(buf, 0x100, "%s(%s, 0x%x),\n", i,
			bpf_reg_str[_insn0.dst_reg],
			_insn0.imm);

	PRINT_TAIL(buf, _idx, 1);
}

static int do_alu64_reg_print(struct bpf_insn *insn, size_t cnt,
				size_t *idx)
{
	char buf[0x100];
	char *i = "BPF_ALU64_REG";
	size_t _idx = *idx;
	struct bpf_insn _insn0 = insn[_idx];
	snprintf(buf, 0x100, "%s(%s, %s, %s),\n", i,
			bpf_alu_op_str[BPF_OP(_insn0.code)],
			bpf_reg_str[_insn0.dst_reg],
			bpf_reg_str[_insn0.src_reg]);

	PRINT_TAIL(buf, _idx, 1);
}

static int do_alu64_imm_print(struct bpf_insn *insn, size_t cnt,
				size_t *idx)
{
	char buf[0x100];
	char *i = "BPF_ALU64_IMM";
	size_t _idx = *idx;
	struct bpf_insn _insn0 = insn[_idx];
	snprintf(buf, 0x100, "%s(%s, %s, 0x%x),\n", i,
			bpf_alu_op_str[BPF_OP(_insn0.code)],
			bpf_reg_str[_insn0.dst_reg],
			_insn0.imm);

	PRINT_TAIL(buf, _idx, 1);
}

static int do_alu64_print(struct bpf_insn *insn, size_t cnt, size_t *idx)
{
	u8 code = insn[*idx].code;
	if (BPF_OP(code) == BPF_MOV) {
		if (BPF_SRC(code) == BPF_X) {
			return do_mov64_reg_print(insn, cnt, idx);
		} else if (BPF_SRC(code) == BPF_K) {
			return do_mov64_imm_print(insn, cnt, idx);
		} else {
			fprintf(stderr, "%d\n", __LINE__);
			return -1;
		}
	} else if (BPF_SRC(code) == BPF_X) {
		return do_alu64_reg_print(insn, cnt, idx);
	} else if (BPF_SRC(code) == BPF_K) {
		return do_alu64_imm_print(insn, cnt, idx);
	} else {
		fprintf(stderr, "%d\n", __LINE__);
		return -1;
	}
}

static int do_end_print(struct bpf_insn *insn, size_t cnt, size_t *idx)
{
	char buf[0x100];
	char *i = "BPF_ENDIAN";
	size_t _idx = *idx;
	struct bpf_insn _insn0 = insn[_idx];
	snprintf(buf, 0x100, "%s(%s, %s, 0x%x),\n", i,
			bpf_alu_op_str[BPF_SRC(_insn0.code)],
			bpf_reg_str[_insn0.dst_reg],
			_insn0.imm);

	PRINT_TAIL(buf, _idx, 1);
}

static int do_mov32_reg_print(struct bpf_insn *insn, size_t cnt,
				size_t *idx)
{
	char buf[0x100];
	char *i = "BPF_MOV32_REG";
	size_t _idx = *idx;
	struct bpf_insn _insn0 = insn[_idx];
	snprintf(buf, 0x100, "%s(%s, %s),\n", i,
			bpf_reg_str[_insn0.dst_reg],
			bpf_reg_str[_insn0.src_reg]);

	PRINT_TAIL(buf, _idx, 1);
}

static int do_mov32_imm_print(struct bpf_insn *insn, size_t cnt,
				size_t *idx)
{
	char buf[0x100];
	char *i = "BPF_MOV32_IMM";
	size_t _idx = *idx;
	struct bpf_insn _insn0 = insn[_idx];
	snprintf(buf, 0x100, "%s(%s, 0x%x),\n", i,
			bpf_reg_str[_insn0.dst_reg],
			_insn0.imm);

	PRINT_TAIL(buf, _idx, 1);
}

static int do_alu32_reg_print(struct bpf_insn *insn, size_t cnt,
				size_t *idx)
{
	char buf[0x100];
	char *i = "BPF_ALU32_REG";
	size_t _idx = *idx;
	struct bpf_insn _insn0 = insn[_idx];
	snprintf(buf, 0x100, "%s(%s, %s, %s),\n", i,
			bpf_alu_op_str[BPF_OP(_insn0.code)],
			bpf_reg_str[_insn0.dst_reg],
			bpf_reg_str[_insn0.src_reg]);

	PRINT_TAIL(buf, _idx, 1);
}

static int do_alu32_imm_print(struct bpf_insn *insn, size_t cnt,
				size_t *idx)
{
	char buf[0x100];
	char *i = "BPF_ALU32_IMM";
	size_t _idx = *idx;
	struct bpf_insn _insn0 = insn[_idx];
	snprintf(buf, 0x100, "%s(%s, %s, 0x%x),\n", i,
			bpf_alu_op_str[BPF_OP(_insn0.code)],
			bpf_reg_str[_insn0.dst_reg],
			_insn0.imm);

	PRINT_TAIL(buf, _idx, 1);
}

static int do_alu32_print(struct bpf_insn *insn, size_t cnt, size_t *idx)
{
	u8 code = insn[*idx].code;
	if (BPF_OP(code) == BPF_END) {
		return do_end_print(insn, cnt, idx);
	} else if (BPF_OP(code) == BPF_MOV) {
		if (BPF_SRC(code) == BPF_X) {
			return do_mov32_reg_print(insn, cnt, idx);
		} else if (BPF_SRC(code) == BPF_K) {
			return do_mov32_imm_print(insn, cnt, idx);
		} else {
			fprintf(stderr, "%d\n", __LINE__);
			return -1;
		}
	} else if (BPF_SRC(code) == BPF_X) {
		return do_alu32_reg_print(insn, cnt, idx);
	} else if (BPF_SRC(code) == BPF_K) {
		return do_alu32_imm_print(insn, cnt, idx);
	} else {
		fprintf(stderr, "%d\n", __LINE__);
		return -1;
	}
}

static int do_ld_map_fd_print(struct bpf_insn *insn, size_t cnt,
				size_t *idx)
{
	/* XXX: no check */
	char buf[0x100];
	char *i = "BPF_LD_MAP_FD";
	size_t _idx = *idx;
	struct bpf_insn _insn0 = insn[_idx];
	struct bpf_insn _insn1 = insn[_idx+1];
	snprintf(buf, 0x100, "%s(%s, 0x%llx),\n", i,
			bpf_reg_str[_insn0.dst_reg],
			(u64)_insn1.imm | (u64)_insn0.imm);

	PRINT_TAIL(buf, _idx, 2);
}

static int do_ld_imm64_print(struct bpf_insn *insn, size_t cnt,
				size_t *idx)
{
	char buf[0x100];
	char *i = "BPF_LD_IMM64";
	size_t _idx = *idx;
	struct bpf_insn _insn0 = insn[_idx];
	struct bpf_insn _insn1 = insn[_idx+1];
	snprintf(buf, 0x100, "%s(%s, 0x%llx),\n", i,
			bpf_reg_str[_insn0.dst_reg],
			(((u64)_insn1.imm) << 32) | (u64)_insn0.imm);

	PRINT_TAIL(buf, _idx, 2);
}

static int do_ld_imm64_raw_print(struct bpf_insn *insn,
			     size_t cnt, size_t *idx)
{
	if (insn[*idx].src_reg == BPF_PSEUDO_MAP_FD) {
		return do_ld_map_fd_print(insn, cnt, idx);
	} else if (insn[*idx].src_reg == 0) {
		return do_ld_imm64_print(insn, cnt, idx);
	} else {
		fprintf(stderr, "%d\n", __LINE__);
		return -1;
	}
}

static int do_ld_abs_print(struct bpf_insn *insn, size_t cnt,
				size_t *idx)
{
	char buf[0x100];
	char *i = "BPF_LD_ABS";
	size_t _idx = *idx;
	struct bpf_insn _insn0 = insn[_idx];
	snprintf(buf, 0x100, "%s(%s, 0x%x),\n", i,
			bpf_size_str[BPF_SIZE(_insn0.code)],
			_insn0.imm);

	PRINT_TAIL(buf, _idx, 1);
}

static int do_ld_ind_print(struct bpf_insn *insn, size_t cnt,
				size_t *idx)
{
	char buf[0x100];
	char *i = "BPF_LD_IND";
	size_t _idx = *idx;
	struct bpf_insn _insn0 = insn[_idx];
	snprintf(buf, 0x100, "%s(%s, %s, 0x%x),\n", i,
			bpf_size_str[BPF_SIZE(_insn0.code)],
			bpf_reg_str[_insn0.src_reg],
			_insn0.imm);

	PRINT_TAIL(buf, _idx, 1);
}

static int do_ld_print(struct bpf_insn *insn, size_t cnt, size_t *idx)
{
	u8 code = insn[*idx].code;
	if ((BPF_SIZE(code) == BPF_DW) && (BPF_MODE(code) == BPF_IMM)) {
		return do_ld_imm64_raw_print(insn, cnt, idx);
	} else if (BPF_MODE(code) == BPF_ABS) {
		return do_ld_abs_print(insn, cnt, idx);
	} else if (BPF_MODE(code) == BPF_IND) {
		return do_ld_ind_print(insn, cnt, idx);
	} else {
		fprintf(stderr, "%d\n", __LINE__);
		return -1;
	}
}

static int do_ldx_mem_print(struct bpf_insn *insn, size_t cnt,
				size_t *idx)
{
	char buf[0x100];
	char *i = "BPF_LDX_MEM";
	size_t _idx = *idx;
	struct bpf_insn _insn0 = insn[_idx];
	snprintf(buf, 0x100, "%s(%s, %s, %s, %hd),\n", i,
			bpf_size_str[BPF_SIZE(_insn0.code)],
			bpf_reg_str[_insn0.dst_reg],
			bpf_reg_str[_insn0.src_reg],
			_insn0.off);

	PRINT_TAIL(buf, _idx, 1);
}

static int do_ldx_print(struct bpf_insn *insn, size_t cnt, size_t *idx)
{
	u8 code = insn[*idx].code;
	if (BPF_MODE(code) == BPF_MEM) {
		return do_ldx_mem_print(insn, cnt, idx);
	} else {
		fprintf(stderr, "%d\n", __LINE__);
		return -1;
	}
}

static int do_stx_mem_print(struct bpf_insn *insn, size_t cnt,
				size_t *idx)
{
	char buf[0x100];
	char *i = "BPF_STX_MEM";
	size_t _idx = *idx;
	struct bpf_insn _insn0 = insn[_idx];
	snprintf(buf, 0x100, "%s(%s, %s, %s, %hd),\n", i,
			bpf_size_str[BPF_SIZE(_insn0.code)],
			bpf_reg_str[_insn0.dst_reg],
			bpf_reg_str[_insn0.src_reg],
			_insn0.off);

	PRINT_TAIL(buf, _idx, 1);
}

static int do_stx_xadd_print(struct bpf_insn *insn, size_t cnt,
				size_t *idx)
{
	char buf[0x100];
	char *i = "BPF_STX_XADD";
	size_t _idx = *idx;
	struct bpf_insn _insn0 = insn[_idx];
	snprintf(buf, 0x100, "%s(%s, %s, %s, %hd),\n", i,
			bpf_size_str[BPF_SIZE(_insn0.code)],
			bpf_reg_str[_insn0.dst_reg],
			bpf_reg_str[_insn0.src_reg],
			_insn0.off);

	PRINT_TAIL(buf, _idx, 1);
}

static int do_stx_print(struct bpf_insn *insn, size_t cnt, size_t *idx)
{
	u8 code = insn[*idx].code;
	if (BPF_MODE(code) == BPF_MEM) {
		return do_stx_mem_print(insn, cnt, idx);
	} else if (BPF_MODE(code) == BPF_XADD) {
		return do_stx_xadd_print(insn, cnt, idx);
	} else {
		fprintf(stderr, "%d\n", __LINE__);
		return -1;
	}
}

static int do_st_mem_print(struct bpf_insn *insn, size_t cnt,
				size_t *idx)
{
	char buf[0x100];
	char *i = "BPF_ST_MEM";
	size_t _idx = *idx;
	struct bpf_insn _insn0 = insn[_idx];
	snprintf(buf, 0x100, "%s(%s, %s, %hd, 0x%x),\n", i,
			bpf_size_str[BPF_SIZE(_insn0.code)],
			bpf_reg_str[_insn0.dst_reg],
			_insn0.off,
			_insn0.imm);

	PRINT_TAIL(buf, _idx, 1);
}

static int do_st_print(struct bpf_insn *insn, size_t cnt, size_t *idx)
{
	u8 code = insn[*idx].code;
	if (BPF_MODE(code) == BPF_MEM) {
		return do_st_mem_print(insn, cnt, idx);
	} else {
		fprintf(stderr, "%d\n", __LINE__);
		return -1;
	}
}

static int do_jmp_reg_print(struct bpf_insn *insn, size_t cnt,
				size_t *idx)
{
	char buf[0x100];
	char *i = "BPF_JMP_REG";
	size_t _idx = *idx;
	struct bpf_insn _insn0 = insn[_idx];
	snprintf(buf, 0x100, "%s(%s, %s, %s, %hd),\n", i,
			bpf_jmp_op_str[BPF_OP(_insn0.code)],
			bpf_reg_str[_insn0.dst_reg],
			bpf_reg_str[_insn0.src_reg],
			_insn0.off);

	PRINT_TAIL(buf, _idx, 1);
}

static int do_jmp_imm_print(struct bpf_insn *insn, size_t cnt,
				size_t *idx)
{
	char buf[0x100];
	char *i = "BPF_JMP_IMM";
	size_t _idx = *idx;
	struct bpf_insn _insn0 = insn[_idx];
	snprintf(buf, 0x100, "%s(%s, %s, 0x%x, %hd),\n", i,
			bpf_jmp_op_str[BPF_OP(_insn0.code)],
			bpf_reg_str[_insn0.dst_reg],
			_insn0.imm,
			_insn0.off);

	PRINT_TAIL(buf, _idx, 1);
}

static int do_jmp_a_print(struct bpf_insn *insn, size_t cnt,
				size_t *idx)
{
	char buf[0x100];
	char *i = "BPF_JMP_A";
	size_t _idx = *idx;
	struct bpf_insn _insn0 = insn[_idx];
	snprintf(buf, 0x100, "%s(%hd),\n", i,
			_insn0.off);

	PRINT_TAIL(buf, _idx, 1);
}

static int do_call_rel_print(struct bpf_insn *insn, size_t cnt,
				size_t *idx)
{
	char buf[0x100];
	char *i = "BPF_CALL_REL";
	size_t _idx = *idx;
	struct bpf_insn _insn0 = insn[_idx];
	snprintf(buf, 0x100, "%s(0x%x),\n", i,
			_insn0.imm);

	PRINT_TAIL(buf, _idx, 1);
}

static int do_emit_call_print(struct bpf_insn *insn, size_t cnt,
				size_t *idx)
{
	char buf[0x100];
	char *i = "BPF_EMIT_CALL";
	size_t _idx = *idx;
	struct bpf_insn _insn0 = insn[_idx];
	snprintf(buf, 0x100, "%s(0x%x),\n", i,
			_insn0.imm);

	PRINT_TAIL(buf, _idx, 1);
}

static int do_call_print(struct bpf_insn *insn, size_t cnt,
				size_t *idx)
{
	if (insn[*idx].src_reg == BPF_PSEUDO_CALL) {
		return do_call_rel_print(insn, cnt, idx);
	} else if (insn[*idx].src_reg == 0) {
		return do_emit_call_print(insn, cnt, idx);
	} else {
		fprintf(stderr, "%d\n", __LINE__);
		return -1;
	}
}

static int do_exit_print(struct bpf_insn *insn, size_t cnt, size_t *idx)
{
	char buf[0x100];
	char *i = "BPF_EXIT_INSN";
	size_t _idx = *idx;
	snprintf(buf, 0x100, "%s(),\n", i);

	PRINT_TAIL(buf, _idx, 1);
}

static int do_jmp64_print(struct bpf_insn *insn, size_t cnt, size_t *idx)
{
	u8 code = insn[*idx].code;
	if (BPF_OP(code) == BPF_CALL) {
		return do_call_print(insn, cnt, idx);
	} else if (BPF_OP(code) == BPF_EXIT) {
		return do_exit_print(insn, cnt, idx);
	} else 	if (BPF_SRC(code) == BPF_X) {
		return do_jmp_reg_print(insn, cnt, idx);
	} else if (BPF_SRC(code) == BPF_K) {
		return do_jmp_imm_print(insn, cnt, idx);
	} else if (BPF_OP(code) == BPF_JA) {
		return do_jmp_a_print(insn, cnt, idx);
	} else {
		fprintf(stderr, "%d\n", __LINE__);
		return -1;
	}
}

static int do_jmp32_reg_print(struct bpf_insn *insn, size_t cnt,
				size_t *idx)
{
	char buf[0x100];
	char *i = "BPF_JMP32_REG";
	size_t _idx = *idx;
	struct bpf_insn _insn0 = insn[_idx];
	snprintf(buf, 0x100, "%s(%s, %s, %s, %hd),\n", i,
			bpf_jmp_op_str[BPF_OP(_insn0.code)],
			bpf_reg_str[_insn0.dst_reg],
			bpf_reg_str[_insn0.src_reg],
			_insn0.off);

	PRINT_TAIL(buf, _idx, 1);
}

static int do_jmp32_imm_print(struct bpf_insn *insn, size_t cnt,
				size_t *idx)
{
	char buf[0x100];
	char *i = "BPF_JMP32_IMM";
	size_t _idx = *idx;
	struct bpf_insn _insn0 = insn[_idx];
	snprintf(buf, 0x100, "%s(%s, %s, 0x%x, %hd),\n", i,
			bpf_jmp_op_str[BPF_OP(_insn0.code)],
			bpf_reg_str[_insn0.dst_reg],
			_insn0.imm,
			_insn0.off);

	PRINT_TAIL(buf, _idx, 1);
}

static int do_jmp32_print(struct bpf_insn *insn, size_t cnt, size_t *idx)
{
	u8 code = insn[*idx].code;
	if (BPF_SRC(code) == BPF_X) {
		return do_jmp32_reg_print(insn, cnt, idx);
	} else if (BPF_SRC(code) == BPF_K) {
		return do_jmp32_imm_print(insn, cnt, idx);
	} else {
		fprintf(stderr, "%d\n", __LINE__);
		return -1;
	}
}

static int do_insn_print(struct bpf_insn *insn, size_t cnt)
{
	size_t idx = 0;
	int err = 0;
	u8 code;

	while (idx < cnt) {
		code = insn[idx].code;
		if (BPF_CLASS(code) == BPF_ALU64) {
			err = do_alu64_print(insn, cnt, &idx);
		} else if (BPF_CLASS(code) == BPF_ALU) {
			err = do_alu32_print(insn, cnt, &idx);
		} else if (BPF_CLASS(code) == BPF_LD) {
			err = do_ld_print(insn, cnt, &idx);
		} else if (BPF_CLASS(code) == BPF_LDX) {
			err = do_ldx_print(insn, cnt, &idx);
		} else if (BPF_CLASS(code) == BPF_STX) {
			err = do_stx_print(insn, cnt, &idx);
		} else if (BPF_CLASS(code) == BPF_ST) {
			err = do_st_print(insn, cnt, &idx);
		} else if (BPF_CLASS(code) == BPF_JMP) {
			err = do_jmp64_print(insn, cnt, &idx);
		} else if (BPF_CLASS(code) == BPF_JMP32) {
			err = do_jmp32_print(insn, cnt, &idx);
		} else {
			fprintf(stderr, "%d\n", __LINE__);
			err = -1;
		}

		if (err == -1)
			break;
	}

	return err;
}

int insn_print_common(char *buf, size_t buflen, struct bpf_insn *insn,
			size_t cnt)
{
	/* choose the right handler to print the insn */
	print_buf = buf;
	print_buflen = buflen;
	print_bufidx = 0;

	return do_insn_print(insn, cnt);
}
