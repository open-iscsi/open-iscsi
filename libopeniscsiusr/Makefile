# Makefile
#
# Copyright (C) 2017 Red Hat, Inc.
# Gris Ge <fge@redhat.com>
#

ifeq ($(TOPDIR),)
	TOPDIR = ..
endif

DESTDIR ?=
prefix ?= /usr
INSTALL ?= install

ifndef LIB_DIR
	ifeq ($(shell test -d /lib64 && echo 1),1)
		LIB_DIR=$(prefix)/lib64
	else
		LIB_DIR=$(prefix)/lib
	endif
endif

INCLUDE_DIR ?= $(prefix)/include
PKGCONF_DIR ?= $(LIB_DIR)/pkgconfig

PKG_CONFIG = /usr/bin/pkg-config

LIBISCSI_USR_DIR=$(TOPDIR)/libopeniscsiusr

LIBISCSI_USR_VERSION_MAJOR=0
LIBISCSI_USR_VERSION=0.2.0
SONAME=$(LIBISCSI_USR_VERSION)
DEVLIB = libopeniscsiusr.so
LIBS = $(DEVLIB).$(SONAME)
LIBS_MAJOR = $(DEVLIB).$(LIBISCSI_USR_VERSION_MAJOR)
PKGFILE = libopeniscsiusr.pc
HEADERS = libopeniscsiusr/libopeniscsiusr.h \
	  libopeniscsiusr/libopeniscsiusr_common.h \
	  libopeniscsiusr/libopeniscsiusr_session.h \
	  libopeniscsiusr/libopeniscsiusr_iface.h \
	  libopeniscsiusr/libopeniscsiusr_node.h
TESTS = tests/test_context tests/test_session tests/test_iface tests/test_node
EXTRA_MAN_FILES = libopeniscsiusr.h.3

OBJS = context.o misc.o session.o sysfs.o iface.o idbm.o node.o default.o

CFLAGS ?= -O2 -g
CFLAGS += -Wall -Werror -Wextra -fvisibility=hidden -fPIC
CFLAGS += $(shell $(PKG_CONFIG) --cflags libkmod)

LDFLAGS += $(shell $(PKG_CONFIG) --libs libkmod)

LIBADD =

all: $(LIBS) $(LIBS_MAJOR) $(TESTS) doc

$(LIBS): $(OBJS)
	@echo CFLAGS= $(CFLAGS)
	$(CC) $(CFLAGS) -shared -Wl,-soname=$@ -o $@ $(OBJS) $(LDFLAGS) $(LIBADD)
	ln -sf $@ $(DEVLIB)

$(LIBS_MAJOR): $(LIBS)
	ln -sf $(LIBS) $@

clean:
	$(RM) vgcore* core *.a *.o *.gz *.so *.so.* $(TESTS)
	$(RM) -r docs/man

$(TESTS): $(LIBS)
$(TESTS): CFLAGS += -I$(TOPDIR)/libopeniscsiusr -g
$(TESTS): LDFLAGS += $(LIBADD) -L$(TOPDIR)/libopeniscsiusr -lopeniscsiusr

check: $(LIBS) $(TESTS)
	sudo env LD_LIBRARY_PATH=$(LIBISCSI_USR_DIR) TESTS="$(TESTS)" \
		tests/runtest.sh || exit 1;

install: $(LIBS) $(LIBS_MAJOR)
	$(INSTALL) -d $(DESTDIR)/$(LIB_DIR)/
	$(INSTALL) -d $(DESTDIR)/$(INCLUDE_DIR)/
	$(INSTALL) $(LIBS) $(DESTDIR)$(LIB_DIR)/
	ln -sf $(LIBS) $(DESTDIR)/$(LIB_DIR)/$(DEVLIB)
	ln -sf $(LIBS) $(DESTDIR)/$(LIB_DIR)/$(LIBS_MAJOR)
	$(INSTALL) $(HEADERS) $(DESTDIR)$(INCLUDE_DIR)/
	$(INSTALL) -m 644 -D $(PKGFILE).in $(DESTDIR)$(PKGCONF_DIR)/$(PKGFILE)
	perl -i -pe 's|__VERSION__|$(LIBNVME_VERSION)|g' \
		$(DESTDIR)$(PKGCONF_DIR)/$(PKGFILE)
	perl -i -pe 's|__LIB_DIR__|$(LIB_DIR)|g' \
		$(DESTDIR)$(PKGCONF_DIR)/$(PKGFILE)
	perl -i -pe 's|__INCLUDE_DIR__|$(INCLUDE_DIR)|g' \
		$(DESTDIR)$(PKGCONF_DIR)/$(PKGFILE)

doc: docs/man/$(EXTRA_MAN_FILES).gz

TEMPFILE := $(shell mktemp)

docs/man/$(EXTRA_MAN_FILES).gz: $(HEADERS)
	@for file in $(EXTRA_MAN_FILES); do \
		$(INSTALL) -v -m 644 -D docs/$$file docs/man/$$file; \
	done
	cat $(HEADERS) | \
	    perl docs/doc-preclean.pl > "$(TEMPFILE)"
	perl docs/kernel-doc -man "$(TEMPFILE)" | \
	    perl docs/split-man.pl docs/man
	-rm -f "$(TEMPFILE)"
	@for file in docs/man/*.3; do \
		gzip -f $$file; \
	done
	find docs/man -type f -name \*[0-9].gz
