#
# Makefile for the Open-iSCSI Initiator
#

# if you are packaging open-iscsi, set this variable to the location
# that you want everything installed into.
DESTDIR ?=

SED = /usr/bin/sed

prefix = /usr
exec_prefix = /
sbindir = $(exec_prefix)/sbin
bindir = $(exec_prefix)/bin
mandir = $(prefix)/share/man
etcdir = /etc
initddir = $(etcdir)/init.d
rulesdir = $(etcdir)/udev/rules.d
systemddir = $(prefix)/lib/systemd/system

MANPAGES = doc/iscsid.8 doc/iscsiadm.8 doc/iscsi_discovery.8 \
		iscsiuio/docs/iscsiuio.8 doc/iscsi_fw_login.8 doc/iscsi-iname.8 \
		doc/iscsistart.8 doc/iscsi-gen-initiatorname.8
PROGRAMS = usr/iscsid usr/iscsiadm utils/iscsi-iname iscsiuio/src/unix/iscsiuio \
		   usr/iscsistart
SCRIPTS = utils/iscsi_discovery utils/iscsi_fw_login utils/iscsi_offload \
		  utils/iscsi-gen-initiatorname
INSTALL = install
ETCFILES = etc/iscsid.conf
IFACEFILES = etc/iface.example
RULESFILES = utils/50-iscsi-firmware-login.rules
SYSTEMDFILES = etc/systemd/iscsi.service \
			   etc/systemd/iscsi-init.service \
			   etc/systemd/iscsid.service etc/systemd/iscsid.socket \
			   etc/systemd/iscsiuio.service etc/systemd/iscsiuio.socket

export DESTDIR prefix INSTALL

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

user: iscsiuio/Makefile
	$(MAKE) -C libopeniscsiusr SBINDIR=$(sbindir)
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
	@echo "Built libopeniscsiusr library:       libopeniscsiusr/libopeniscsiusr.so"
	@echo
	@echo "Read README file for detailed information."

iscsiuio/Makefile: iscsiuio/configure iscsiuio/Makefile.in
	cd iscsiuio; ./configure $(WITHOUT_ARG)

iscsiuio/configure iscsiuio/Makefile.in: iscsiuio/configure.ac iscsiuio/Makefile.am
	cd iscsiuio; autoreconf --install

force: ;

clean:
	$(MAKE) -C utils/sysdeps clean
	$(MAKE) -C utils/fwparam_ibft clean
	$(MAKE) -C utils clean
	$(MAKE) -C usr clean
	$(MAKE) -C libopeniscsiusr clean
	[ ! -f iscsiuio/Makefile ] || $(MAKE) -C iscsiuio clean
	[ ! -f iscsiuio/Makefile ] || $(MAKE) -C iscsiuio distclean

# this is for safety
# now -jXXX will still be safe
# note that make may still execute the blocks in parallel
.NOTPARALLEL: install_user install_programs install_initd \
	install_initd_suse install_initd_redhat install_initd_debian \
	install_etc install_iface install_doc install_iname

install: install_programs install_doc install_etc \
	install_initd install_iname install_iface install_libopeniscsiusr

install_user: install_programs install_doc install_etc \
	install_initd install_iname install_iface

install_udev_rules:
	$(INSTALL) -d $(DESTDIR)$(rulesdir)
	$(INSTALL) -m 644 $(RULESFILES) $(DESTDIR)/$(rulesdir)
	for f in $(RULESFILES); do \
		p=$(DESTDIR)/$(rulesdir)/$${f##*/}; \
		$(SED) -i -e 's:@SBINDIR@:$(sbindir):' $$p; \
	done

install_systemd:
	$(INSTALL) -d $(DESTDIR)$(systemddir)/system
	$(INSTALL) -m 644 $(SYSTEMDFILES) $(DESTDIR)/$(systemddir)/system
	for f in $(SYSTEMDFILES); do \
		p=$(DESTDIR)/$(systemddir)/system/$${f##*/}; \
		$(SED) -i -e 's:@SBINDIR@:$(sbindir):' $$p; \
	done

install_programs: $(PROGRAMS) $(SCRIPTS)
	$(INSTALL) -d $(DESTDIR)$(sbindir)
	$(INSTALL) -m 755 $^ $(DESTDIR)$(sbindir)
	for f in $(SCRIPTS); do \
		p=$(DESTDIR)/$(sbindir)/$${f##*/}; \
		$(SED) -i -e 's:@SBINDIR@:$(sbindir):' $$p; \
	done

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
	if [ ! -f $(DESTDIR)/etc/iscsi/iscsid.conf ]; then \
		$(INSTALL) -d $(DESTDIR)$(etcdir)/iscsi ; \
		$(INSTALL) -m 644 $^ $(DESTDIR)$(etcdir)/iscsi ; \
	fi

install_doc: $(MANPAGES)
	$(INSTALL) -d $(DESTDIR)$(mandir)/man8
	$(INSTALL) -m 644 $^ $(DESTDIR)$(mandir)/man8

install_iname:
	if [ ! -f $(DESTDIR)/etc/iscsi/initiatorname.iscsi ]; then \
		echo "InitiatorName=`$(DESTDIR)$(sbindir)/iscsi-iname`" > $(DESTDIR)/etc/iscsi/initiatorname.iscsi ; \
		echo "***************************************************" ; \
		echo "Setting InitiatorName to `cat $(DESTDIR)/etc/iscsi/initiatorname.iscsi`" ; \
		echo "To override edit $(DESTDIR)/etc/iscsi/initiatorname.iscsi" ; \
		echo "***************************************************" ; \
	fi

install_libopeniscsiusr:
	$(MAKE) -C libopeniscsiusr install

depend:
	for dir in usr utils utils/fwparam_ibft; do \
		$(MAKE) -C $$dir $@; \
	done

# vim: ft=make tw=72 sw=4 ts=4:
