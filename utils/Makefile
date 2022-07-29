# This Makefile will work only with GNU make.
#
# Make file for the util sub-directory
#
# This make file does not control the sysdeps
# subdirectory, which is controlled
# from the top-level make file.
#

SED ?= sed
INSTALL = install
CHMOD = chmod

DESTDIR ?=
SBINDIR ?= /sbin
etcdir = /etc
HOMEDIR ?= $(etcdir)/iscsi

RULESDIR ?= $(etcdir)/udev/rules.d

CFLAGS ?= -O2 -fno-inline -g
CFLAGS += -Wall -Wextra -Wstrict-prototypes

PROGRAMS	= iscsi-iname
PROGRAMS_DEST	= $(addprefix $(DESTDIR)$(SBINDIR)/,$(PROGRAMS))

SCRIPTS_SOURCES		= iscsi_discovery.sh iscsi_offload.sh
SCRIPTS_TEMPLATES	= iscsi_fw_login.sh.template iscsi-gen-initiatorname.sh.template
SCRIPTS_GENERATED	= $(SCRIPTS_TEMPLATES:.template=)
SCRIPTS_DEST		= $(addprefix $(DESTDIR)$(SBINDIR)/,$(basename $(SCRIPTS_GENERATED))) \
			  $(addprefix $(DESTDIR)$(SBINDIR)/,$(basename $(SCRIPTS_SOURCES)))

RULESFILES_TEMPLATES	= 50-iscsi-firmware-login.rules.template
RULESFILES_GENERATED	= $(RULESFILES_TEMPLATES:.template=)
RULESFILES_DEST		= $(addprefix $(DESTDIR)$(RULESDIR)/,$(RULESFILES_GENERATED))

OBJS = iscsi-iname.o md5.o

all: $(PROGRAMS) $(SCRIPTS_GENERATED) $(RULESFILES_GENERATED)

$(SCRIPTS_GENERATED): %.sh: %.sh.template
	$(SED) -e 's:@SBINDIR@:$(SBINDIR):' -e 's:@HOMEDIR@:$(HOMEDIR):' $? > $@
	$(CHMOD) 755 $@

$(RULESFILES_GENERATED): %.rules: %.rules.template
	$(SED) -e 's:@SBINDIR@:$(SBINDIR):' $? > $@

iscsi-iname: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ $(DBM_LIB) -o $@

install: $(DESTDIR)$(SBINDIR) $(DESTDIR)$(RULESDIR) \
	$(PROGRAMS_DEST) $(SCRIPTS_DEST) $(RULESFILES_DEST)

$(PROGRAMS_DEST): $(DESTDIR)$(SBINDIR)/%: %
	$(INSTALL) -m 755 $? $@

$(SCRIPTS_DEST): $(DESTDIR)$(SBINDIR)/%: %.sh
	$(INSTALL) -m 755 $? $@

install_udev_rules: $(RULESFILES_DEST)

$(RULESFILES_DEST): $(DESTDIR)$(RULESDIR)/%: %
	$(INSTALL) -m 644 $? $@

$(DESTDIR)$(SBINDIR) $(DESTDIR)$(RULESDIR):
	[ -d $@ ] || $(INSTALL) -d $@

clean:
	$(RM) $(OBJS)
	$(RM) $(PROGRAMS)
	$(RM) .depend

distclean:
	$(RM) $(SCRIPTS_GENERATED)
	$(RM) $(RULESFILES_GENERATED)

.PHONY: all install clean distclean depend install_udev_rules

depend:
	$(CC) $(CFLAGS) -M `ls *.c` > .depend

-include .depend
