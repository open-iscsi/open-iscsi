#
# gnu Makefile for the etc subdirectory, including
# 	initd and systemd subdirectories
#

prefix = /usr
DESTDIR ?=
SBINDIR ?= $(DESTDIR)/sbin

systemddir ?= $(DESTDIR)$(prefix)/lib/systemd
etcdir = $(DESTDIR)/etc
initddir ?= $(etcdir)/init.d

HOMEDIR ?= $(etcdir)/iscsi

SED = /usr/bin/sed
INSTALL = install

SYSTEMD_SOURCE_FILES	= iscsid.socket iscsiuio.socket
SYSTEMD_SOURCES		= $(addprefix systemd/,$(SYSTEMD_SOURCE_FILES))
SYSTEMD_TEMPLATE_FILES	= iscsi-init.service.template \
			  iscsid.service.template \
			  iscsi.service.template \
			  iscsiuio.service.template
SYSTEMD_TEMPLATES	= $(addprefix systemd/,$(SYSTEMD_TEMPLATE_FILES))
SYSTEMD_GENERATED_SERVICE_FILES	= $(SYSTEMD_TEMPLATES:.template=)
SYSTEMD_DEST_FILES	= $(addprefix $(systemddir)/system/,$(notdir $(SYSTEMD_SOURCES))) \
			  $(addprefix $(systemddir)/system/,$(notdir $(SYSTEMD_GENERATED_SERVICE_FILES)))
IFACE_FILES		= iface.example
IFACE_DEST_FILES	= $(addprefix $(HOMEDIR)/ifaces/,$(IFACE_FILES))
ETC_FILES		= iscsid.conf
ETC_DEST_FILES		= $(addprefix $(HOMEDIR)/,$(ETC_FILES))

all: $(SYSTEMD_SOURCES) $(SYSTEMD_GENERATED_SERVICE_FILES)

$(SYSTEMD_GENERATED_SERVICE_FILES): systemd/%.service: systemd/%.service.template
	$(SED) -e 's:@SBINDIR@:$(SBINDIR):' $? > $@

install: install_systemd install_iface install_etc

install_iface: $(IFACE_DEST_FILES)

$(IFACE_DEST_FILES): $(HOMEDIR)/ifaces/%: %
	$(INSTALL) -m 644 $? $@

install_etc: $(ETC_DEST_FILES)

$(ETC_DEST_FILES): $(HOMEDIR)/%: %
	$(INSTALL) -m 644 $? $@

install_initd_distro = $(INSTALL) -m 755 $(1) $(initddir)/open-iscsi/

install_initd: $(initddir)/open-iscsi
	@if [ -f /etc/debian_version ]; then \
		$(call install_initd_distro,initd/initd.redhat) ; \
	elif [ -f /etc/redhat-release ]; then \
		$(call install_initd_distro,initd/initd.debian) ; \
	fi

$(initddir)/open-iscsi:
	[ -d $@ ] || $(INSTALL) -d $@

install_initd_redhat: $(initddir)/open-iscsi
	$(call install_initd_distro,initd/initd.redhat)

install_initd_debian: $(initddir)/open-iscsi
	$(call install_initd_distro,initd/initd.debian)

install_systemd: $(systemddir)/system $(SYSTEMD_DEST_FILES)

$(systemddir)/system:
	[ -d $@ ] || $(INSTALL) -d -m 775 $@

$(SYSTEMD_DEST_FILES): $(systemddir)/system/%: systemd/%
	$(INSTALL) $? $@

clean:
	$(RM) $(SYSTEMD_GENERATED_SERVICE_FILES)

.PHONY: all clean install install_iface install_initd install_initd_redhat \
	install_initd_debian install_systemd
