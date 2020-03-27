# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2018, Oracle and/or its affiliates. All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# as published by the Free Software Foundation.
#
# Adapted from https://github.com/bpftools/linux-observability-with-bpf
#


OBJS = write_errors.o

LLC ?= llc
CLANG ?= clang
INC_FLAGS = -nostdinc -isystem `$(CLANG) -print-file-name=include`
EXTRA_CFLAGS ?= -O2

linuxhdrs ?= /kernel-src

LINUXINCLUDE = -I$(linuxhdrs)/arch/x86/include \
	       -I$(linuxhdrs)/include/ 

all: $(OBJS)

.PHONY: clean

clean:
	rm -f $(OBJS)

$(OBJS):  %.o:%.c
	$(CLANG) -D__KERNEL__ -emit-llvm  $(INC_CFLAGS) -I../include -include asm_goto_workaround.h \
		$(LINUXINCLUDE) $(EXTRA_CFLAGS) -c $< -o -|llc -march=bpf -mcpu=probe -filetype=obj -o $@
