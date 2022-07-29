#
# gnu Makefile for the etc subdirectory, including
# 	initd and systemd subdirectories
#

ifeq ($(TOPDIR),)
	TOPDIR = ..
endif

prefix = /usr
DESTDIR ?=
SBINDIR ?= /sbin

ISCSI_INAME ?= $(TOPDIR)/utils/iscsi-iname

systemddir ?= $(prefix)/lib/systemd
etcdir = /etc
initddir ?= $(etcdir)/init.d

HOMEDIR ?= $(etcdir)/iscsi

SED ?= sed
INSTALL = install

SYSTEMD_SOURCE_FILES	= iscsid.socket iscsiuio.socket
SYSTEMD_SOURCES		= $(addprefix systemd/,$(SYSTEMD_SOURCE_FILES))
SYSTEMD_TEMPLATE_FILES	= iscsi-init.service.template \
			  iscsid.service.template \
			  iscsi.service.template \
			  iscsiuio.service.template
SYSTEMD_TEMPLATES	= $(addprefix systemd/,$(SYSTEMD_TEMPLATE_FILES))
SYSTEMD_RULES_FILES	= ibft-rule-generator
SYSTEMD_RULES_SOURCES	= $(addprefix systemd/,$(SYSTEMD_RULES_FILES))
SYSTEMD_GENERATED_SERVICE_FILES	= $(SYSTEMD_TEMPLATES:.template=)
SYSTEMD_DEST_SVC_FILES	= $(addprefix $(DESTDIR)$(systemddir)/system/,$(SYSTEMD_SOURCE_FILES)) \
			  $(addprefix $(DESTDIR)$(systemddir)/system/,$(notdir $(SYSTEMD_GENERATED_SERVICE_FILES)))
SYSTEMD_DEST_GEN_FILES	= $(addprefix $(DESTDIR)$(systemddir)/system-generators/,$(notdir $(SYSTEMD_RULES_SOURCES)))
IFACE_FILES		= iface.example
IFACE_DEST_FILES	= $(addprefix $(DESTDIR)$(DBROOT)/ifaces/,$(IFACE_FILES))
ETC_FILES		= iscsid.conf
ETC_DEST_FILES		= $(addprefix $(DESTDIR)$(HOMEDIR)/,$(ETC_FILES))

INAME_DEST_FILE		= $(DESTDIR)$(HOMEDIR)/initiatorname.iscsi

all: $(SYSTEMD_SOURCES) $(SYSTEMD_GENERATED_SERVICE_FILES)

$(SYSTEMD_GENERATED_SERVICE_FILES): systemd/%.service: systemd/%.service.template
	$(SED) -e 's:@SBINDIR@:$(SBINDIR):' $? > $@

install: install_systemd install_iface install_etc

install_iface: $(DESTDIR)$(DBROOT)/ifaces $(IFACE_DEST_FILES)

$(IFACE_DEST_FILES): $(DESTDIR)$(DBROOT)/ifaces/%: %
	$(INSTALL) -m 644 $? $@

install_etc: $(DESTDIR)$(HOMEDIR) $(ETC_DEST_FILES)

$(ETC_DEST_FILES): $(DESTDIR)$(HOMEDIR)/%: %
	$(INSTALL) -m 644 $? $@

install_initd_distro = $(INSTALL) -m 755 $(1) $(DESTDIR)$(initddir)/open-iscsi/

install_initd: $(DESTDIR)$(initddir)/open-iscsi
	@if [ -f /etc/debian_version ]; then \
		$(call install_initd_distro,initd/initd.redhat) ; \
	elif [ -f /etc/redhat-release ]; then \
		$(call install_initd_distro,initd/initd.debian) ; \
	fi

install_initd_redhat: $(DESTDIR)$(initddir)/open-iscsi
	$(call install_initd_distro,initd/initd.redhat)

install_initd_debian: $(DESTDIR)$(initddir)/open-iscsi
	$(call install_initd_distro,initd/initd.debian)

install_systemd: install_systemd_service_files install_systemd_generator_files

install_systemd_service_files: $(DESTDIR)$(systemddir)/system $(SYSTEMD_DEST_SVC_FILES)

install_systemd_generator_files: $(DESTDIR)$(systemddir)/system-generators $(SYSTEMD_DEST_GEN_FILES)

$(SYSTEMD_DEST_SVC_FILES): $(DESTDIR)$(systemddir)/system/%: systemd/%
	$(INSTALL) -m 644 $? $@

$(SYSTEMD_DEST_GEN_FILES): $(DESTDIR)$(systemddir)/system-generators/%: systemd/%
	$(INSTALL) -m 755 $? $@

install_iname: $(DESTDIR)$(HOMEDIR) $(ISCSI_INAME)
	if [ ! -f $(INAME_DEST_FILE) ]; then \
		INAME="`$(ISCSI_INAME)`" ; \
		echo "InitiatorName=$$INAME" > $(INAME_DEST_FILE) ; \
		echo "***************************************************" ; \
		echo "Setting InitiatorName to $$INAME" ; \
		echo "To override edit $(INAME_DEST_FILE)" ; \
		echo "***************************************************" ; \
	fi

$(ISCSI_INAME):
	$(MAKE) $(MFLAGS) -c $(TOPDIR)/utils $(notdir $@)

# make needed directories
$(DESTDIR)$(systemddir)/system $(DESTDIR)$(systemddir)/system-generators $(DESTDIR)$(HOMEDIR) \
		$(DESTDIR)$(DBROOT)/ifaces $(DESTDIR)$(initddir)/open-iscsi:
	[ -d $@ ] || $(INSTALL) -d -m 775 $@

clean: ;

distclean:
	$(RM) $(SYSTEMD_GENERATED_SERVICE_FILES)

.PHONY: all clean install install_iface install_initd install_initd_redhat \
	install_initd_debian install_systemd distclean install_iname \
	install_systemd_generator_files install_systemd_service_files \
	install_initd_distro install_etc
