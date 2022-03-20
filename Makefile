#
# Makefile for the Open-iSCSI Initiator
#

# if you are packaging open-iscsi, set this variable to the location
# that you want everything installed into.
DESTDIR ?=

prefix = /usr
exec_prefix =
sbindir ?= $(exec_prefix)/sbin
mandir = $(prefix)/share/man

MANPAGES = doc/iscsid.8 doc/iscsiadm.8 doc/iscsi_discovery.8 \
		iscsiuio/docs/iscsiuio.8 doc/iscsi_fw_login.8 doc/iscsi-iname.8 \
		doc/iscsistart.8 doc/iscsi-gen-initiatorname.8
INSTALL = install

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
	$(MAKE) $(MFLAGS) -C libopeniscsiusr SBINDIR=$(sbindir)
	$(MAKE) $(MFLAGS) -C utils/sysdeps
	$(MAKE) $(MFLAGS) -C utils/fwparam_ibft
	$(MAKE) $(MFLAGS) -C usr SBINDIR=$(sbindir)
	$(MAKE) $(MFLAGS) -C utils SBINDIR=$(sbindir)
	$(MAKE) $(MFLAGS) -C etc SBINDIR=$(sbindir)
	$(MAKE) $(MFLAGS) -C iscsiuio
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
	$(MAKE) $(MFLAGS) -C utils/sysdeps clean
	$(MAKE) $(MFLAGS) -C utils/fwparam_ibft clean
	$(MAKE) $(MFLAGS) -C utils clean
	$(MAKE) $(MFLAGS) -C usr clean
	$(MAKE) $(MFLAGS) -C etc clean
	$(MAKE) $(MFLAGS) -C libopeniscsiusr clean
	[ ! -f iscsiuio/Makefile ] || $(MAKE) $(MFLAGS) -C iscsiuio clean
	[ ! -f iscsiuio/Makefile ] || $(MAKE) $(MFLAGS) -C iscsiuio distclean

# this is for safety
# now -jXXX will still be safe
# note that make may still execute the blocks in parallel
.NOTPARALLEL: install_user install_programs install_initd \
	install_initd_redhat install_initd_debian \
	install_etc install_iface install_doc install_iname

install: install_programs install_doc install_etc \
	install_systemd install_iname install_iface install_libopeniscsiusr \
	install_iscsiuio

install_iscsiuio:
	$(MAKE) $(MFLAGS) -C iscsiuio install

install_user: install_programs install_doc install_etc \
	install_systemd install_iname install_iface

install_udev_rules:
	$(MAKE) $(MFLAGS) -C utils $@

install_programs:
	$(MAKE) $(MFLAGS) -C utils install
	$(MAKE) $(MFLAGS) -C usr install

install_initd install_initd_redhat install_initd_debian install_ifae install_etc install_systemd install_iface:
	$(MAKE) $(MFLAGS) -C etc $@

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
	$(MAKE) $(MFLAGS) -C libopeniscsiusr install

depend:
	for dir in usr utils utils/fwparam_ibft; do \
		$(MAKE) $(MFLAGS) -C $$dir $@; \
	done

.PHONY: all user install force clean install_user install_udev_rules install_systemd \
	install_programs install_initrd install_initrd_redhat install_initrd_debian \
	install_etc install_doc install_iname install_libopeniscsiusr

# vim: ft=make tw=72 sw=4 ts=4:
