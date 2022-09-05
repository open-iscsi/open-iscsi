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
exec_prefix =
etcdir = /etc
SBINDIR ?= $(exec_prefix)/sbin
DBROOT ?= $(etcdir)/iscsi

ifndef LIB_DIR
	ifeq ($(shell test -d /lib64 && echo 1),1)
		LIB_DIR=$(prefix)/lib64
	else
		LIB_DIR=$(prefix)/lib
	endif
endif

INCLUDE_DIR ?= $(prefix)/include
PKGCONF_DIR ?= $(LIB_DIR)/pkgconfig
MAN_DIR = $(prefix)/share/man

PKG_CONFIG ?= /usr/bin/pkg-config

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
EXTRA_MAN_FILE = libopeniscsiusr.h.3

OBJS = context.o misc.o session.o sysfs.o iface.o idbm.o node.o default.o

CFLAGS ?= -O2 -g
CFLAGS += -Wall -Werror -Wextra -fvisibility=hidden -fPIC
CFLAGS += $(shell $(PKG_CONFIG) --cflags libkmod)
CFLAGS += -DSBINDIR=\"$(SBINDIR)\"
CFLAGS += -DISCSI_DB_ROOT=\"$(DBROOT)\"
CFLAGS += -DISCSI_VERSION_STR=\"$(ISCSI_VERSION_STR)\"

LDFLAGS += $(shell $(PKG_CONFIG) --libs libkmod)

LIBADD =

all: $(LIBS) $(LIBS_MAJOR) $(TESTS) doc

$(LIBS): $(OBJS)
	$(CC) $(CFLAGS) -shared -Wl,-soname=$@ -o $@ $(OBJS) $(LDFLAGS) $(LIBADD)
	ln -sf $@ $(DEVLIB)

$(LIBS_MAJOR): $(LIBS)
	ln -sf $(LIBS) $@

clean:
	$(RM) vgcore* core *.a *.o *.so *.so.* $(TESTS)
	$(RM) -r docs/man

distclean: ;

$(TESTS): $(LIBS)
$(TESTS): CFLAGS += -I$(TOPDIR)/libopeniscsiusr -g
$(TESTS): LDFLAGS += $(LIBADD) -L$(TOPDIR)/libopeniscsiusr -lopeniscsiusr

check: $(LIBS) $(TESTS)
	sudo env LD_LIBRARY_PATH=$(LIBISCSI_USR_DIR) TESTS="$(TESTS)" \
		tests/runtest.sh || exit 1;

install: install_libs install_docs install_pkg_files

install_libs: $(LIBS) $(LIBS_MAJOR)
	$(INSTALL) -d $(DESTDIR)$(LIB_DIR)/
	$(INSTALL) -d $(DESTDIR)$(INCLUDE_DIR)/
	$(INSTALL) $(LIBS) $(DESTDIR)$(LIB_DIR)/
	ln -sf $(LIBS) $(DESTDIR)$(LIB_DIR)/$(DEVLIB)
	ln -sf $(LIBS) $(DESTDIR)$(LIB_DIR)/$(LIBS_MAJOR)
	$(INSTALL) -m 644 $(HEADERS) $(DESTDIR)$(INCLUDE_DIR)/

install_docs: doc
	$(INSTALL) -d $(DESTDIR)$(MAN_DIR)/man3
	$(INSTALL) -m 644 docs/man/*.3 $(DESTDIR)$(MAN_DIR)/man3/

install_pkg_files:
	$(INSTALL) -m 644 -D $(PKGFILE).in $(DESTDIR)$(PKGCONF_DIR)/$(PKGFILE)
	perl -i -pe 's|__VERSION__|$(LIBISCSI_USR_VERSION)|g' \
		$(DESTDIR)$(PKGCONF_DIR)/$(PKGFILE)
	perl -i -pe 's|__LIB_DIR__|$(LIB_DIR)|g' \
		$(DESTDIR)$(PKGCONF_DIR)/$(PKGFILE)
	perl -i -pe 's|__INCLUDE_DIR__|$(INCLUDE_DIR)|g' \
		$(DESTDIR)$(PKGCONF_DIR)/$(PKGFILE)

doc: docs/man/$(EXTRA_MAN_FILE)

# install the static man page, and generate lots of lib man pages
# note: the last line just prints out the man page names
docs/man/$(EXTRA_MAN_FILE): $(HEADERS)
	$(INSTALL) -v -m 644 -D docs/$(EXTRA_MAN_FILE) $@
	@echo generating library man pages ...
	@for h in $(HEADERS); do \
	    for f in `docs/list-man-pages.sh $$h`; do \
		docs/kernel-doc -module libopeniscsiusr \
			-man -function $$f $$h >docs/man/$$f.3 ; \
	    done; \
	done
	find docs/man -type f -name \*[0-9]

.PHONY: all install clean distclean doc install_pkg_files install_docs \
	install_libs check
