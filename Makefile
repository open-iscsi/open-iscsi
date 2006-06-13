#
# Makefile for the Open-iSCSI Initiator
#

# if you are packaging open-iscsi, set this variable to the location
# that you want everything installed into.
DESTDIR ?= 

prefix = /usr
exec_prefix = /
sbindir = $(exec_prefix)/sbin
bindir = $(exec_prefix)/bin
mandir = $(prefix)/share/man
etcdir = /etc
initddir = $(etcdir)/init.d

MANPAGES = doc/iscsid.8 doc/iscsiadm.8
PROGRAMS = usr/iscsid usr/iscsiadm utils/iscsi_discovery
INSTALL = install
ETCFILES = etc/iscsid.conf

# Random comments:
# using '$(MAKE)' instead of just 'make' allows make to run in parallel
# over multiple makefile.

all:
	$(MAKE) -C usr
	$(MAKE) -C kernel
	@echo
	@echo "Compilation complete                Output file"
	@echo "----------------------------------- ----------------"
	@echo "Built iSCSI Open Interface module:  kernel/scsi_transport_iscsi.ko"
	@echo "Built iSCSI library module:         kernel/libiscsi.ko"
	@echo "Built iSCSI over TCP kernel module: kernel/iscsi_tcp.ko"
	@echo "Built iSCSI daemon:                 usr/iscsid"
	@echo "Built management application:       usr/iscsiadm"
	@echo
	@echo Read README file for detailed information.

clean:
	$(MAKE) -C usr clean
	$(MAKE) -C kernel clean

# this is for safety
# now -jXXX will still be safe
# note that make may still execute the blocks in parallel
.NOTPARALLEL: install_usr install_programs install_initd \
	install_initd_suse install_initd_redhat install_initd_debian \
	install_etc install_doc install_kernel

install: install_kernel install_programs install_doc install_etc \
	install_initd

install_programs:  $(PROGRAMS)
	$(INSTALL) -d $(DESTDIR)$(sbindir)
	$(INSTALL) -m 755 $^ $(DESTDIR)$(sbindir)

# ugh, auto-detection is evil
# Gentoo maintains their own init.d stuff
install_initd:
	if [ -f /etc/debian_version ]; then \
		$(MAKE) install_initd_debian ; \
	elif [ -f /etc/redhat-release ]; then \
		$(MAKE) install_initd_redhat ; \
	elif [ -f /etc/SuSE-release ]; then \
		$(MAKE) install_initd_suse ; \
	fi

# these are external targets to allow bypassing distribution detection
install_initd_suse:
	$(INSTALL) -d $(DESTDIR)$(initddir)
	$(INSTALL) -m 755 etc/initd/initd.suse \
		$(DESTDIR)$(initddir)/open-iscsi

install_initd_redhat:
	$(INSTALL) -d $(DESTDIR)$(initddir)
	$(INSTALL) -m 755 etc/initd/initd.redhat \
		$(DESTDIR)$(initddir)/open-iscsi

install_initd_debian:
	$(INSTALL) -d $(DESTDIR)$(initddir)
	$(INSTALL) -m 755 etc/initd/initd.debian \
		$(DESTDIR)$(initddir)/open-iscsi

install_etc: $(ETCFILES)
	$(INSTALL) -d $(DESTDIR)$(etcdir)
	$(INSTALL) $^ $(DESTDIR)$(etcdir)

install_doc: $(MANPAGES)
	$(INSTALL) -d $(DESTDIR)$(mandir)/man8
	$(INSTALL) -m 644 $^ $(DESTDIR)$(mandir)/man8

install_kernel:
	$(MAKE) -C kernel install_kernel

# vim: ft=make tw=72 sw=4 ts=4:
