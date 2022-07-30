# This Makefile will work only with GNU make.
#
# Make file for the doc sub-directory
#

ifeq ($(TOPDIR),)
	TOPDIR = ..
endif

SED ?= sed
INSTALL = install

DESTDIR ?=
etcdir = /etc
DBROOT ?= $(etcdir)/iscsi
HOMEDIR ?= $(etcdir)/iscsi

prefix ?= /usr
mandir ?= $(prefix)/share/man

MAN8DIR = $(DESTDIR)$(mandir)/man8

MANPAGES_SOURCES	= iscsi_discovery.8 \
			  iscsi_fw_login.8 \
			  iscsi-iname.8
MANPAGES_TEMPLATES	= iscsid.8.template \
			  iscsiadm.8.template \
			  iscsi-gen-initiatorname.8 \
			  iscsistart.8.template
MANPAGES_GENERATED	= $(MANPAGES_TEMPLATES:.template=)
MANPAGES_DEST		= $(addprefix $(MAN8DIR)/,$(MANPAGES_GENERATED)) \
			  $(addprefix $(MAN8DIR)/,$(MANPAGES_SOURCES))

all: $(MANPAGES_GENERATED)

install: install_doc

install_doc: $(MAN8DIR) $(MANPAGES_DEST)

$(MANPAGES_GENERATED): %.8: %.8.template
	$(SED) -e 's:@HOMEDIR@:$(HOMEDIR):' -e 's:@DBROOT@:$(DBROOT):' $? > $@

$(MANPAGES_DEST): $(MAN8DIR)/%: %
	$(INSTALL) -m 644 $? $@


$(MAN8DIR):
	[ -d $@ ] || $(INSTALL) -d $@

clean: ;

distclean:
	$(RM) $(MANPAGES_GENERATED)

.PHONY: all install install_doc clean distclean
