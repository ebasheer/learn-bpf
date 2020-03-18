# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2018, Oracle and/or its affiliates. All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# as published by the Free Software Foundation.
#
# Build bpf userspace code out-of-tree by referencing local copies of
# bpf .c and .h files.
#
# - bpf.[ch] are copies of tools/lib/bpf/bpf.[ch]
# - bpf_load.[ch] are copies are samples/bpf/bpf_load.[ch], with references
#   to #include the unneeded libbpf.h removed, replaced by references to bpf.h
# - bpf_util.h is a copy of tools/testing/selftests/bpf/bpf_util.h
# - perf-sys.h is a copy of tools/perf/perf-sys.h
#

COMMONOBJS = bpf.o bpf_load.o

USERPROG = loader
USEROBJ = $(USERPROG).o
PROGS= $(USERPROG)
OBJS= $(COMMONOBJS) $(USEROBJ)

linuxhdrs ?= /kernel-src

LINUXINCLUDE =  -I$(linuxhdrs)/arch/x86/include/uapi \
                -I$(linuxhdrs)/arch/x86/include/generated/uapi \
                -I$(linuxhdrs)/include/generated/uapi \
                -I$(linuxhdrs)/include/uapi \
                -I$(linuxhdrs)/include \
                -I$(linuxhdrs)/tools/lib

prefix ?= /usr/local

INSTALLPATH = $(prefix)/bin

install_PROGRAM = install
install_DIR = install -d

LDLIBS = -lelf

all: $(USERPROG)

.PHONY: clean

clean:
	rm -f $(OBJS) $(PROGS)

%.o: %.c
	$(CC) -g -Wno-unused-variable -I../include $(LINUXINCLUDE) -c -o $@ $< $(CFLAGS)

$(PROGS): $(OBJS)
	$(CC) -g -o $@ $(@).o $(COMMONOBJS) $(CFLAGS) $(LDLIBS)

install: $(PROGS)
	$(install_DIR) -d $(INSTALLPATH) ; \
	$(install_PROGRAM) $^ -t $(INSTALLPATH)

uninstall: $(PROGS)
	cd $(INSTALLPATH); rm -f $^
