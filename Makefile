#
# Makefile for the Open-iSCSI Initiator
#

# if you are packaging open-iscsi, set this variable to the location
# that you want everything installed into.
DESTDIR ?=

# our VERSION String
ISCSI_VERSION_STR ?= 2.1.8

prefix = /usr
exec_prefix =
mandir = $(prefix)/share/man
etcdir = /etc

SBINDIR = $(exec_prefix)/sbin
HOMEDIR = $(etcdir)/iscsi
DBROOT = $(etcdir)/iscsi
RULESDIR = $(etcdir)/udev/rules.d

INSTALL = /usr/bin/install

# pass these on to sub-Makefiles
export DESTDIR prefix INSTALL SBINDIR HOMEDIR DBROOT RULESDIR ISCSI_VERSION_STR

# Compatibility: parse old OPTFLAGS argument
ifdef OPTFLAGS
CFLAGS = $(OPTFLAGS)
endif

# Export it so configure of iscsiuio will
# pick it up.
ifneq (,$(CFLAGS))
export CFLAGS
endif

# export systemd disablement if set
ifneq ($(NO_SYSTEMD),)
export NO_SYSTEMD
WITHOUT_ARG = --without-systemd
else
WITHOUT_ARG =
endif

# Random comments:
# using '$(MAKE)' instead of just 'make' allows make to run in parallel
# over multiple makefile.

all: user

make_utils:
	$(MAKE) $(MFLAGS) -C utils

deprecation_msg:
	@echo "***"
	@echo "*** Warning: using 'make' is being deprecated, in favor of 'meson'"
	@echo "***    Please see the README file for more information."
	@echo "***"

user: deprecation_msg iscsiuio/Makefile
	$(MAKE) $(MFLAGS) -C libopeniscsiusr
	$(MAKE) $(MFLAGS) -C sysdeps
	$(MAKE) $(MFLAGS) -C usr
	$(MAKE) $(MFLAGS) -C utils
	$(MAKE) $(MFLAGS) -C etc
	$(MAKE) $(MFLAGS) -C iscsiuio
	$(MAKE) $(MFLAGS) -C doc
	@echo
	@echo "Compilation complete                 Output file"
	@echo "-----------------------------------  ----------------"
	@echo "Built iSCSI daemon:                  usr/iscsid"
	@echo "Built management application:        usr/iscsiadm"
	@echo "Built boot tool:                     usr/iscsistart"
	@echo "Built iscsiuio daemon:               iscsiuio/src/unix/iscsiuio"
	@echo "Built libopeniscsiusr library:       libopeniscsiusr/libopeniscsiusr.so"
	@echo
	@echo "Read README file for detailed information."

iscsiuio/Makefile: iscsiuio/configure iscsiuio/Makefile.in
	cd iscsiuio; ./configure $(WITHOUT_ARG) --sbindir=$(SBINDIR)

iscsiuio/configure: iscsiuio/configure.ac iscsiuio/Makefile.am
	cd iscsiuio; autoreconf --install

force: ;

clean distclean:
	$(MAKE) $(MFLAGS) -C sysdeps $@
	$(MAKE) $(MFLAGS) -C utils $@
	$(MAKE) $(MFLAGS) -C usr $@
	$(MAKE) $(MFLAGS) -C etc $@
	$(MAKE) $(MFLAGS) -C libopeniscsiusr $@
	$(MAKE) $(MFLAGS) -C doc $@
	[ ! -f iscsiuio/Makefile ] || $(MAKE) $(MFLAGS) -C iscsiuio $@

# this is for safety
# now -jXXX will still be safe
# note that make may still execute the blocks in parallel
.NOTPARALLEL: install_user install_programs install_initd \
	install_initd_redhat install_initd_debian \
	install_doc install_iname install_etc install_etc_all

install: install_programs install_doc \
	install_systemd install_iname install_libopeniscsiusr \
	install_iscsiuio install_etc_all

install_iscsiuio:
	$(MAKE) $(MFLAGS) -C iscsiuio install

install_user: install_programs install_doc install_systemd install_iname

install_udev_rules:
	$(MAKE) $(MFLAGS) -C utils $@

install_programs:
	$(MAKE) $(MFLAGS) -C utils install
	$(MAKE) $(MFLAGS) -C usr install

install_initd install_initd_redhat install_initd_debian install_iface install_systemd install_etc install_iname:
	$(MAKE) $(MFLAGS) -C etc $@

install_etc_all:
	$(MAKE) $(MFLAGS) -C etc install

install_doc:
	$(MAKE) $(MFLAGS) -C doc $@

install_libopeniscsiusr:
	$(MAKE) $(MFLAGS) -C libopeniscsiusr install

depend:
	for dir in usr utils utils/fwparam_ibft sysdeps; do \
		$(MAKE) $(MFLAGS) -C $$dir $@; \
	done

.PHONY: all user install force clean install_user install_udev_rules install_systemd \
	install_programs install_initrd install_initrd_redhat install_initrd_debian \
	install_doc install_iname install_libopeniscsiusr install_etc install_etc_all \
	distclean depend install_initd install_initd_redhat install_initd_debian \
	install_iscsiuio
