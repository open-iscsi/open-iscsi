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

MANPAGES = doc/iscsid.8 doc/iscsiadm.8 doc/iscsi_discovery.8 doc/iscsistart.8 doc/iscsi-iname.8 iscsiuio/docs/iscsiuio.8
PROGRAMS = usr/iscsid usr/iscsiadm utils/iscsi_discovery utils/iscsi-iname usr/iscsistart iscsiuio/src/unix/iscsiuio
INSTALL = install
ETCFILES = etc/iscsid.conf
IFACEFILES = etc/iface.example

# Random comments:
# using '$(MAKE)' instead of just 'make' allows make to run in parallel
# over multiple makefile.

all: user

user: utils/open-isns/Makefile iscsiuio/Makefile
	$(MAKE) -C utils/open-isns
	$(MAKE) -C utils/sysdeps
	$(MAKE) -C utils/fwparam_ibft
	$(MAKE) -C usr
	$(MAKE) -C utils
	$(MAKE) -C iscsiuio
	@echo
	@echo "Compilation complete                 Output file"
	@echo "-----------------------------------  ----------------"
	@echo "Built iSCSI daemon:                  usr/iscsid"
	@echo "Built management application:        usr/iscsiadm"
	@echo "Built boot tool:                     usr/iscsistart"
	@echo "Built iscsiuio daemon:               iscsiuio/src/unix/iscsiuio"
	@echo
	@echo "Read README file for detailed information."

utils/open-isns/Makefile: utils/open-isns/configure utils/open-isns/Makefile.in
	cd utils/open-isns; ./configure CFLAGS="$(OPTFLAGS)" --with-security=no

iscsiuio/Makefile: iscsiuio/configure iscsiuio/Makefile.in
	cd iscsiuio; ./configure

kernel: force
	$(MAKE) -C kernel
	@echo "Kernel Compilation complete          Output file"
	@echo "-----------------------------------  ----------------"
	@echo "Built iSCSI Open Interface module:   kernel/scsi_transport_iscsi.ko"
	@echo "Built iSCSI library module:          kernel/libiscsi.ko"
	@echo "Built iSCSI over TCP library module: kernel/libiscsi_tcp.ko"
	@echo "Built iSCSI over TCP kernel module:  kernel/iscsi_tcp.ko"

force: ;

clean:
	$(MAKE) -C utils/sysdeps clean
	$(MAKE) -C utils/fwparam_ibft clean
	$(MAKE) -C utils clean
	$(MAKE) -C usr clean
	$(MAKE) -C kernel clean
	$(MAKE) -C iscsiuio clean
	$(MAKE) -C utils/open-isns clean
	$(MAKE) -C utils/open-isns distclean

# this is for safety
# now -jXXX will still be safe
# note that make may still execute the blocks in parallel
.NOTPARALLEL: install_user install_programs install_initd \
	install_initd_suse install_initd_redhat install_initd_debian \
	install_etc install_iface install_doc install_kernel install_iname

install: install_programs install_doc install_etc \
	install_initd install_iname install_iface

install_user: install_programs install_doc install_etc \
	install_initd install_iname install_iface

install_programs:  $(PROGRAMS)
	$(INSTALL) -d $(DESTDIR)$(sbindir)
	$(INSTALL) -m 755 $^ $(DESTDIR)$(sbindir)

# ugh, auto-detection is evil
# Gentoo maintains their own init.d stuff
install_initd:
	if [ -f $(DESTDIR)$(etcdir)/debian_version ]; then \
		$(MAKE) install_initd_debian ; \
	elif [ -f $(DESTDIR)$(etcdir)/redhat-release ]; then \
		$(MAKE) install_initd_redhat ; \
	elif [ -f $(DESTDIR)$(etcdir)/SuSE-release ]; then \
		$(MAKE) install_initd_suse ; \
	fi

# these are external targets to allow bypassing distribution detection
install_initd_suse:
	$(INSTALL) -d $(DESTDIR)$(initddir)
	$(INSTALL) -m 755 etc/initd/initd.suse \
		$(DESTDIR)$(initddir)/open-iscsi
	$(INSTALL) -m 755 etc/initd/boot.suse \
		$(DESTDIR)$(initddir)/boot.open-iscsi

install_initd_redhat:
	$(INSTALL) -d $(DESTDIR)$(initddir)
	$(INSTALL) -m 755 etc/initd/initd.redhat \
		$(DESTDIR)$(initddir)/open-iscsi

install_initd_debian:
	$(INSTALL) -d $(DESTDIR)$(initddir)
	$(INSTALL) -m 755 etc/initd/initd.debian \
		$(DESTDIR)$(initddir)/open-iscsi

install_iface: $(IFACEFILES)
	$(INSTALL) -d $(DESTDIR)$(etcdir)/iscsi/ifaces
	$(INSTALL) -m 644 $^ $(DESTDIR)$(etcdir)/iscsi/ifaces

install_etc: $(ETCFILES)
	if [ ! -f $(DESTDIR)$(etcdir)/iscsi/iscsid.conf ]; then \
		$(INSTALL) -d $(DESTDIR)$(etcdir)/iscsi ; \
		$(INSTALL) -m 644 $^ $(DESTDIR)$(etcdir)/iscsi ; \
	fi

install_doc: $(MANPAGES)
	$(INSTALL) -d $(DESTDIR)$(mandir)/man8
	$(INSTALL) -m 644 $^ $(DESTDIR)$(mandir)/man8

install_kernel:
	$(MAKE) -C kernel install_kernel

install_iname:
	if [ ! -f $(DESTDIR)$(etcdir)/iscsi/initiatorname.iscsi ]; then \
		echo "InitiatorName=`$(DESTDIR)$(sbindir)/iscsi-iname`" > $(DESTDIR)$(etcdir)/iscsi/initiatorname.iscsi ; \
		echo "***************************************************" ; \
		echo "Setting InitiatorName to `cat $(DESTDIR)$(etcdir)/iscsi/initiatorname.iscsi`" ; \
		echo "To override edit $(etcdir)/iscsi/initiatorname.iscsi" ; \
		echo "***************************************************" ; \
	fi

depend:
	for dir in usr utils utils/fwparam_ibft; do \
		$(MAKE) -C $$dir $@; \
	done

# vim: ft=make tw=72 sw=4 ts=4:
