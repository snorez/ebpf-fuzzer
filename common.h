#ifndef COMMON_H_AVKWXLV7
#define COMMON_H_AVKWXLV7

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <sys/prctl.h>

typedef __s8	s8;
typedef __s16	s16;
typedef __s32	s32;
typedef __s64	s64;
typedef __u8	u8;
typedef __u16	u16;
typedef __u32	u32;
typedef __u64	u64;

extern char *bpf_reg_str[];
extern char *bpf_alu_op_str[];
extern char *bpf_jmp_op_str[];
extern char *bpf_size_str[];

#endif /* end of include guard: COMMON_H_AVKWXLV7 */
