# This Makefile will work only with GNU make.

ifeq ($(TOPDIR),)
	TOPDIR = ..
endif

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

PKG_CONFIG = /usr/bin/pkg-config

CFLAGS ?= -O2 -g
WARNFLAGS ?= -Wall -Wextra -Werror -Wstrict-prototypes -fno-common
CFLAGS += $(WARNFLAGS) -I../include -I. -D_GNU_SOURCE \
	  -I$(TOPDIR)/libopeniscsiusr
CFLAGS += $(shell $(PKG_CONFIG) --cflags libkmod)
ISCSI_LIB = -L$(TOPDIR)/libopeniscsiusr -lopeniscsiusr
LDFLAGS += $(shell $(PKG_CONFIG) --libs libkmod)
ifeq ($(NO_SYSTEMD),)
LDFLAGS += $(shell $(PKG_CONFIG) --libs libsystemd)
endif
PROGRAMS = iscsid iscsiadm iscsistart

# libc compat files
SYSDEPS_SRCS = $(sort $(wildcard ../utils/sysdeps/*.o))
# sources shared between iscsid, iscsiadm and iscsistart
ISCSI_LIB_SRCS = iscsi_util.o io.o auth.o iscsi_timer.o login.o log.o \
	iface.o idbm.o sysfs.o host.o session_info.o iscsi_sysfs.o \
	iscsi_net_util.o iscsid_req.o transport.o iser.o cxgbi.o be2iscsi.o \
	initiator_common.o iscsi_err.o flashnode.o uip_mgmt_ipc.o \
	netlink.o $(SYSDEPS_SRCS)
# core initiator files
INITIATOR_SRCS = initiator.o scsi.o actor.o event_poll.o mgmt_ipc.o kern_err_table.o

# fw boot files
FW_BOOT_SRCS = $(sort $(wildcard ../utils/fwparam_ibft/*.o))

# core discovery files
DISCOVERY_SRCS = $(FW_BOOT_SRCS) local_strings.o discovery.o

all: $(PROGRAMS)

iscsid: $(ISCSI_LIB_SRCS) $(INITIATOR_SRCS) $(DISCOVERY_SRCS) \
	iscsid.o session_mgmt.o discoveryd.o mntcheck.o
	$(CC) $(CFLAGS) $^ -o $@  -lisns -lcrypto -lrt -lmount $(LDFLAGS) $(ISCSI_LIB)

iscsiadm: $(ISCSI_LIB_SRCS) $(DISCOVERY_SRCS) iscsiadm.o session_mgmt.o mntcheck.o
	$(CC) $(CFLAGS) $^ -o $@ -lisns -lcrypto -lmount $(LDFLAGS) $(ISCSI_LIB)

iscsistart: $(ISCSI_LIB_SRCS) $(INITIATOR_SRCS) $(FW_BOOT_SRCS) \
		iscsistart.o statics.o
	$(CC) $(CFLAGS) $^ -o $@ -lcrypto -lrt $(LDFLAGS) $(ISCSI_LIB)
clean:
	rm -f *.o $(PROGRAMS) .depend $(LIBSYS)

depend:
	gcc $(CFLAGS) -M `ls *.c` > .depend

-include .depend
