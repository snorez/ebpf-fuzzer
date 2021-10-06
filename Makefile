SELF_CFLAGS_N = 2
NEED_CLIB = 1
SELF_DEBUG = 1
BUILD_LIB = 0

export MAKE_OPT := --no-print-directory
export Q :=
#export Q := @
export CC = gcc
export CXX = g++
export MAKE = make
export RM = rm -f
export INSTALL = install
export CC_ECHO = 	"  CC   "
export CXX_ECHO = 	"  CXX  "
export LD_ECHO = 	"  LD   "
export GEN_ECHO = 	"  GEN  "
export CLEAN_ECHO = 	" CLEAN "
export INSTALL_ECHO = 	"INSTALL"
export SRC_ECHO = 	" <== "

export ARCH = $(shell getconf LONG_BIT)
export SCRIPT_DIR = $(dirname $(readlink -f "$0"))

ifeq ($(Q), @)
export MAKE_OPT += -s
endif

ifeq ($(NEED_CLIB), 1)
export CLIB_PATH = /home/$(LOGNAME)/workspace/clib
export CLIB_INC = $(CLIB_PATH)/include
export CLIB_LIB = $(CLIB_PATH)/lib
export CLIB_SO = clib$(ARCH)
endif

GCC_VER_MAJ := $(shell expr `gcc -dumpversion | cut -f1 -d.`)
GCC_PLUGIN_BASE = /usr/lib/gcc/x86_64-linux-gnu
export GCC_PLUGIN_INC = $(GCC_PLUGIN_BASE)/$(GCC_VER_MAJ)/plugin/include

SELF_CFLAGS =

ifeq ($(SELF_DEBUG), 1)
SELF_CFLAGS += -g
endif

ifeq ($(BUILD_LIB), 1)
SELF_CFLAGS += -shared
endif

SELF_CFLAGS += -fPIC -rdynamic
SELF_CFLAGS += -Wall -O$(SELF_CFLAGS_N)
# TODO: Put SELF_CFLAGS here



export CFLAGS = -std=gnu11 $(SELF_CFLAGS) $(EXTRA_CFLAGS)
export CXXFLAGS = -std=gnu++11 $(SELF_CFLAGS) $(EXTRA_CFLAGS)

# TODO: Put rules here
CC_SRCS = ebpf_fuzzer.c \
	  init.c \
	  common.c \
	  insn_print.c \
	  gen-insn-common.c \
	  gen-insn.c

CC_OBJS = $(CC_SRCS:.c=.o)

CXX_SRCS =

CXX_OBJS = $(CXX_SRCS:%.cc=%.o)

# _SO = $(_SRCS:%.c:%.so)
OUTFILE = ebpf_fuzzer

# INSTALLS = $(addprefix $(OUTDIR)/,$(OUTFILE))
INSTALLS =

CFLAGS += 

all: $(OUTFILE)

# $(Q)$(CC) $(CFLAGS) $(CC_OBJS) $(CXX_OBJS) -L$(CLIB_LIB) -l$(CLIB_SO) -o $(OUTFILE) -Wl,-rpath $(CLIB_LIB)
$(OUTFILE): $(CC_OBJS) $(CXX_OBJS)
	$(Q)$(CC) $(CFLAGS) $(CC_OBJS) $(CXX_OBJS) -L$(CLIB_LIB) -l$(CLIB_SO) -o $(OUTFILE) -Wl,-rpath $(CLIB_LIB)

# $(Q)$(CC) $(CFLAGS) -I$(CLIB_INC) -c -o $@ $<
$(CC_OBJS): %.o: %.c
	$(Q)$(CC) $(CFLAGS) -I$(CLIB_INC) -c -o $@ $<

# $(Q)$(CXX) $(CXXFLAGS) -I$(CLIB_INC) -c -o $@ $<
$(CXX_OBJS): %.o: %.cc
	# TODO

install: $(INSTALLS)

clean:
	$(Q)$(RM) $(CC_OBJS)
	$(Q)$(RM) $(CXX_OBJS)
	$(Q)$(RM) $(OUTFILE)

distclean: clean
	$(Q)$(RM) $(INSTALLS)
