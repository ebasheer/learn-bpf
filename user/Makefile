# SPDX-License-Identifier: GPL-2.0
#
# Copyright (c) 2018, Oracle and/or its affiliates. All rights reserved.
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# as published by the Free Software Foundation.
#
#
#


USERPROG = loader
USEROBJ = $(USERPROG).o
PROGS= $(USERPROG)
OBJS= $(USEROBJ)

linuxhdrs ?= /kernel-src

LINUXINCLUDE = -I$(linuxhdrs)/tools/include \
	       -I$(linuxhdrs)/tools/lib \
	       -I$(linuxhdrs)/usr/include/ \
	       -I/usr/include/ 

LDLIBS = -lelf -lbcc

all: $(USERPROG)

.PHONY: clean

clean:
	rm -f $(OBJS) $(PROGS)

%.o: %.c
	$(CC) -g -Wno-unused-variable --include $(linuxhdrs)/include/generated/autoconf.h -I../include $(LINUXINCLUDE) -c -o $@ $< $(CFLAGS)

$(PROGS): $(OBJS)
	$(CC) -g -o $@ $(@).o $(CFLAGS) $(LDLIBS)
