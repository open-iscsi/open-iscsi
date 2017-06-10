# Makefile
#
# Copyright (C) 2017 Red Hat, Inc.
# Gris Ge <fge@redhat.com>

ifeq ($(TOPDIR),)
	TOPDIR	= ..
endif

LIBISCSI_USR_DIR=$(TOPDIR)/usr
LIBISCSI_DIR=$(TOPDIR)/libiscsi

LIBISCSI_VERSION_MAJOR=0
LIBISCSI_VERSION=0.1.0
SONAME=$(LIBISCSI_VERSION)
DEVLIB = libiscsi.so
LIBS = $(DEVLIB).$(SONAME)
LIBS_MAJOR = $(DEVLIB).$(LIBISCSI_VERSION_MAJOR)
PKGFILE = libiscsi.pc
HEADERS = libiscsi.h
TESTS = tests/test_discovery_sendtargets tests/test_discovery_firmware
TESTS += tests/test_set_auth tests/test_get_auth
TESTS += tests/test_login tests/test_logout tests/test_params
TESTS += tests/test_fw_get_network_config tests/test_fw_get_initiator_name

OBJS = libiscsi.o

CFLAGS ?= -O2 -g
CFLAGS += -Wall -Werror -Wextra -fvisibility=hidden -fPIC \
	  -I$(TOPDIR)/include -I$(LIBISCSI_USR_DIR) \
	  $(shell pkg-config --cflags python2)

LIBADD = -L$(LIBISCSI_USR_DIR) -liscsi_usr

all: $(LIBS) $(LIBS_MAJOR)

$(LIBS): $(OBJS)
	$(CC) $(LDFLAGS) -shared -Wl,-soname=$@ -o $@ $(OBJS) $(LIBADD)
	ln -sf $@ $(DEVLIB)

$(LIBS_MAJOR):
	ln -sf $(LIBS) $@

clean:
	$(RM) core *.a *.o *.gz *.so *.so.* $(TESTS)

$(TESTS): CFLAGS = -I$(TOPDIR)/libiscsi -g
$(TESTS): LDFLAGS += $(LIBADD) -L$(TOPDIR)/libiscsi -liscsi
$(TESTS): $(LIBS)

check: $(TESTS)
	sudo env LD_LIBRARY_PATH=$(LIBISCSI_USR_DIR):$(LIBISCSI_DIR) \
		tests/runtest.sh || exit 1;

html: libiscsi.h libiscsi.doxy
	doxygen libiscsi.doxy
