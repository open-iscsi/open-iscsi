# This Makefile will work only with GNU make.

ifeq ($(TOPDIR),)
	TOPDIR = ..
endif

INSTALL = install

DESTDR ?=
SBINDIR ?= /sbin
etcdir = /etc

OSNAME=$(shell uname -s)

# allow users to override these
# eg to compile for a kernel that you aren't currently running
KERNELRELEASE ?= $(shell uname -r)
KSRC ?= /lib/modules/$(KERNELRELEASE)/build

KSUBLEVEL=$(shell cat $(KSRC)/Makefile | awk -F= '/^SUBLEVEL =/ {print $$2}' | \
			sed 's/^[ \t]*//;s/[ \t]*$$//')

ifeq ($(OSNAME),Linux)
	ifeq ($(KSUBLEVEL),11)
		IPC_CFLAGS=-DNETLINK_ISCSI=12 -D_GNU_SOURCE
	else
	ifeq ($(KSUBLEVEL),12)
		IPC_CFLAGS=-DNETLINK_ISCSI=12 -D_GNU_SOURCE
	else
		IPC_CFLAGS=-DNETLINK_ISCSI=8 -D_GNU_SOURCE
	endif
	endif
IPC_OBJ=netlink.o
else
ifeq ($(OSNAME),FreeBSD)
IPC_CFLAGS=
IPC_OBJ=ioctl.o
endif
endif

DBROOT ?= $(etcdir)/iscsi
HOMEDIR ?= $(etcdir)/iscsi

PKG_CONFIG ?= /usr/bin/pkg-config

CFLAGS ?= -O2 -g
WARNFLAGS ?= -Wall -Wextra -Werror -Wstrict-prototypes -fno-common
CFLAGS += $(WARNFLAGS) -I../include -I. -D_GNU_SOURCE \
	  -I$(TOPDIR)/libopeniscsiusr \
	  -DISCSI_VERSION_STR=\"$(ISCSI_VERSION_STR)\"
CFLAGS += $(shell $(PKG_CONFIG) --cflags libkmod)
CFLAGS += $(shell $(PKG_CONFIG) --cflags libsystemd)
ISCSI_LIB = -L$(TOPDIR)/libopeniscsiusr -lopeniscsiusr
LDFLAGS += $(shell $(PKG_CONFIG) --libs libkmod)
ifeq ($(NO_SYSTEMD),)
LDFLAGS += $(shell $(PKG_CONFIG) --libs libsystemd)
else
CFLAGS += -DNO_SYSTEMD
endif
CFLAGS += -DISCSI_DB_ROOT=\"$(DBROOT)\"
CFLAGS += -DISCSI_CONFIG_ROOT=\"$(HOMEDIR)\"

PROGRAMS	= iscsid iscsiadm iscsistart
PROGRAMS_DEST	= $(addprefix $(DESTDIR)$(SBINDIR)/,$(PROGRAMS))

ISCSID_OBJS	= iscsid.o session_mgmt.o discoveryd.o mntcheck.o
ISCSIADM_OBJS	= iscsiadm.o session_mgmt.o mntcheck.o
ISCSISTART_OBJS	= iscsistart.o

# libc compat files
SYSDEPS_DIR = $(TOPDIR)/sysdeps
SYSDEPS_OBJS = $(SYSDEPS_DIR)/sysdeps.o
# sources shared between iscsid, iscsiadm and iscsistart
ISCSI_LIB_OBJS = iscsi_util.o io.o auth.o iscsi_timer.o login.o log.o \
	iface.o idbm.o sysfs.o host.o session_info.o iscsi_sysfs.o \
	iscsi_net_util.o iscsid_req.o transport.o iser.o cxgbi.o be2iscsi.o \
	initiator_common.o iscsi_err.o flashnode.o uip_mgmt_ipc.o \
	netlink.o
# core initiator files
INITIATOR_OBJS = initiator.o scsi.o actor.o event_poll.o mgmt_ipc.o kern_err_table.o

# fw boot files
FW_BOOT_DIR = fwparam_ibft
FW_BOOT_OBJ_FILES = fw_entry.o fwparam_sysfs.o prom_lex.o prom_parse.tab.o fwparam_ppc.o
FW_BOOT_OBJS = $(addprefix $(FW_BOOT_DIR)/,$(FW_BOOT_OBJ_FILES))

# core discovery files
DISCOVERY_OBJS = local_strings.o discovery.o

all: $(PROGRAMS)

iscsid: $(ISCSI_LIB_OBJS) $(SYSDEPS_OBJS) $(INITIATOR_OBJS) $(DISCOVERY_OBJS) $(FW_BOOT_OBJS) \
	$(ISCSID_OBJS)
	$(CC) $(CFLAGS) $^ -o $@  -lisns -lcrypto -lrt -lmount $(LDFLAGS) $(ISCSI_LIB)

iscsiadm: $(ISCSI_LIB_OBJS) $(SYSDEPS_OBJS) $(DISCOVERY_OBJS) $(FW_BOOT_OBJS) \
	$(ISCSIADM_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ -lisns -lcrypto -lmount $(LDFLAGS) $(ISCSI_LIB)

iscsistart: $(ISCSI_LIB_OBJS) $(SYSDEPS_OBJS) $(INITIATOR_OBJS) $(FW_BOOT_OBJS) \
	$(ISCSISTART_OBJS)
	$(CC) $(CFLAGS) $^ -o $@ -lcrypto -lrt $(LDFLAGS) $(ISCSI_LIB)

install: $(DESTDIR)$(SBINDIR) $(PROGRAMS_DEST)

$(DESTDIR)$(SBINDIR):
	[ -d $@ ] || $(INSTALL) -d $@

$(PROGRAMS_DEST): $(DESTDIR)$(SBINDIR)/%: %
	$(INSTALL) -m 755 $? $@

$(SYSDEPS_OBJS):
	$(MAKE) $(MFLAGS) -C $(SYSDEPS_DIR)

$(FW_BOOT_OBJS):
	$(MAKE) $(MFLAGS) -C $(FW_BOOT_DIR)

clean:
	$(RM) $(ISCSI_LIB_OBJS) $(INITIATOR_OBJS) $(DISCOVERY_OBJS) \
		$(ISCSISTART_OBJS) $(ISCSID_OBJS) $(ISCSIADM_OBJS) \
		$(PROGRAMS) .depend
	$(MAKE) $(MFLAGS) -C $(FW_BOOT_DIR) clean

distclean: ;

.PHONY: all install clean distclean depend

depend:
	$(CC) $(CFLAGS) -M `ls *.c` > .depend
	$(MAKE) $(MFLAGS) -C $(FW_BOOT_DIR) depend

-include .depend
