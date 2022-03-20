# This Makefile will work only with GNU make.
#
# Make file for the util sub-directory
#
# This make file does not control the fwparam_ibft
# or sysdeps subdirectories. Those are still controlled
# from the top-level make file.
#

SED = /usr/bin/sed
INSTALL = install
CHMOD = chmod

DESTDIR ?=
SBINDIR ?= $(DESTDIR)/sbin

ETCDIR = $(DESTDIR)/etc
RULESDIR = $(ETCDIR)/udev/rules.d

CFLAGS ?= -O2 -fno-inline -g
CFLAGS += -Wall -Wextra -Wstrict-prototypes

PROGRAMS	= iscsi-iname
PROGRAMS_DEST	= $(addprefix $(SBINDIR)/,$(PROGRAMS))

SCRIPTS_SOURCES		= iscsi_discovery.sh iscsi_offload.sh
SCRIPTS_TEMPLATES	= iscsi_fw_login.sh.template iscsi-gen-initiatorname.sh.template
SCRIPTS_GENERATED	= $(SCRIPTS_TEMPLATES:.template=)
SCRIPTS_DEST		= $(addprefix $(SBINDIR)/,$(basename $(SCRIPTS_GENERATED))) \
			  $(addprefix $(SBINDIR)/,$(basename $(SCRIPTS_SOURCES)))

RULESFILES_TEMPLATES	= 50-iscsi-firmware-login.rules.template
RULESFILES_GENERATED	= $(RULESFILES_TEMPLATES:.template=)
RULESFILES_DEST		= $(addprefix $(RULESDIR)/,$(RULESFILES_GENERATED))

OBJS = iscsi-iname.o md5.o

all: $(PROGRAMS) $(SCRIPTS_GENERATED) $(RULESFILES_GENERATED)

$(SCRIPTS_GENERATED): %.sh: %.sh.template
	$(SED) -e 's:@SBINDIR@:$(SBINDIR):' $? > $@
	$(CHMOD) 755 $@

$(RULESFILES_GENERATED): %.rules: %.rules.template
	$(SED) -e 's:@SBINDIR@:$(SBINDIR):' $? > $@

iscsi-iname: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) $^ $(DBM_LIB) -o $@

install: $(SBINDIR) $(RULESDIR) $(PROGRAMS_DEST) $(SCRIPTS_DEST) $(RULESFILES_DEST)

$(PROGRAMS_DEST): $(SBINDIR)/%: %
	$(INSTALL) -m 755 $? $@

$(SCRIPTS_DEST): $(SBINDIR)/%: %.sh
	$(INSTALL) -m 755 $? $@

install_udev_rules: $(RULESFILES_DEST)

$(RULESFILES_DEST): $(RULESDIR)/%: %
	$(INSTALL) -m 644 $? $@

$(SBINDIR) $(RULESDIR):
	[ -d $@ ] || $(INSTALL) -d $@

clean:
	$(RM) $(OBJS)
	$(RM) $(PROGRAMS)
	$(RM) $(SCRIPTS_GENERATED)
	$(RM) $(RULESFILES_GENERATED)
	$(RM) .depend

depend:
	gcc $(CFLAGS) -M `ls *.c` > .depend

-include .depend
