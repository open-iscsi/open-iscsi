# This Makefile will work only with GNU make.

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

CFLAGS ?= -O2 -g
WARNFLAGS ?= -Wall -Wstrict-prototypes
CFLAGS += $(WARNFLAGS) -I../include -I. -D$(OSNAME) $(IPC_CFLAGS)
PROGRAMS = iscsid iscsiadm iscsistart

# libc compat files
SYSDEPS_SRCS = $(sort $(wildcard ../utils/sysdeps/*.o))
# sources shared between iscsid, iscsiadm and iscsistart
ISCSI_LIB_SRCS = iscsi_util.o io.o auth.o iscsi_timer.o login.o log.o md5.o \
	sha1.o iface.o idbm.o sysfs.o host.o session_info.o iscsi_sysfs.o \
	iscsi_net_util.o iscsid_req.o transport.o iser.o cxgbi.o be2iscsi.o \
	initiator_common.o iscsi_err.o flashnode.o uip_mgmt_ipc.o \
	$(IPC_OBJ)  $(SYSDEPS_SRCS)
# core initiator files
INITIATOR_SRCS = initiator.o scsi.o actor.o event_poll.o mgmt_ipc.o kern_err_table.o

# fw boot files
FW_BOOT_SRCS = $(sort $(wildcard ../utils/fwparam_ibft/*.o))

# core discovery files
DISCOVERY_SRCS = $(FW_BOOT_SRCS) strings.o discovery.o

all: $(PROGRAMS)

iscsid: $(ISCSI_LIB_SRCS) $(INITIATOR_SRCS) $(DISCOVERY_SRCS) \
	iscsid.o session_mgmt.o discoveryd.o mntcheck.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@  -lisns -lcrypto -lrt -lmount

iscsiadm: $(ISCSI_LIB_SRCS) $(DISCOVERY_SRCS) iscsiadm.o session_mgmt.o mntcheck.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ -lisns -lcrypto -lmount

iscsistart: $(ISCSI_LIB_SRCS) $(INITIATOR_SRCS) $(FW_BOOT_SRCS) \
		iscsistart.o statics.o
	$(CC) $(CFLAGS) $(LDFLAGS) $^ -o $@ -lrt
clean:
	rm -f *.o $(PROGRAMS) .depend $(LIBSYS)

depend:
	gcc $(CFLAGS) -M `ls *.c` > .depend

-include .depend
