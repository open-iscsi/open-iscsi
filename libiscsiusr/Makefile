# Makefile
#
# Copyright (C) 2017 Red Hat, Inc.
# Gris Ge <fge@redhat.com>

ifeq ($(TOPDIR),)
	TOPDIR = ..
endif

LIBISCSI_USR_DIR=$(TOPDIR)/libiscsiusr

LIBISCSI_USR_VERSION_MAJOR=0
LIBISCSI_USR_VERSION=0.1.0
SONAME=$(LIBISCSI_USR_VERSION)
DEVLIB = libiscsiusr.so
LIBS = $(DEVLIB).$(SONAME)
LIBS_MAJOR = $(DEVLIB).$(LIBISCSI_USR_VERSION_MAJOR)
PKGFILE = libiscsiusr.pc
HEADERS = libiscsiusr/libiscsiusr.h
TESTS = tests/test_session

OBJS = context.o session.o misc.o sysfs.o iface.o

CFLAGS ?= -O2 -g
CFLAGS += -Wall -Werror -Wextra -fvisibility=hidden -fPIC

LIBADD =

all: $(LIBS) $(LIBS_MAJOR)

$(LIBS): $(OBJS)
	$(CC) $(LDFLAGS) -shared -Wl,-soname=$@ -o $@ $(OBJS) $(LIBADD)
	ln -sf $@ $(DEVLIB)

$(LIBS_MAJOR):
	ln -sf $(LIBS) $@

clean:
	$(RM) vgcore* core *.a *.o *.gz *.so *.so.* $(TESTS)

$(TESTS): CFLAGS = -I$(TOPDIR)/libiscsiusr -g
$(TESTS): LDFLAGS += $(LIBADD) -L$(TOPDIR)/libiscsiusr -liscsiusr
$(TESTS): $(LIBS)

check: $(TESTS)
	sudo env LD_LIBRARY_PATH=$(LIBISCSI_USR_DIR) \
		tests/runtest.sh || exit 1;
