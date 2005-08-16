# This Makefile will work only with GNU make.

OSNAME=$(shell uname -s)
KSRC=/lib/modules/`uname -r`/build
KVER=$(shell cat $(KSRC)/Makefile | awk -F= '/^SUBLEVEL =/ {print $$2}' | \
			sed 's/^[ \t]*//;s/[ \t]*$$//')

ifeq ($(OSNAME),Linux)
	ifeq ($(KVER),11)
		IPC_CFLAGS=-DNETLINK_ISCSI=12
	else
	ifeq ($(KVER),12)
		IPC_CFLAGS=-DNETLINK_ISCSI=12
	else
		IPC_CFLAGS=-DNETLINK_ISCSI=8
	endif
	endif
IPC_OBJ=netlink.o
DBM_LIB=-ldb
else
ifeq ($(OSNAME),FreeBSD)
IPC_CFLAGS=
IPC_OBJ=ioctl.o
DBM_LIB=
endif
endif

CFLAGS += -O2 -fno-inline -Wall -Wstrict-prototypes -g -I../include \
	  -D$(OSNAME) $(IPC_CFLAGS)
PROGRAMS = iscsid iscsiadm

# sources shared between iscsid and iscsiadm
COMMON_SRCS = io.o auth.o login.o log.o md5.o sha1.o idbm.o

all: $(PROGRAMS)

iscsid: $(COMMON_SRCS) $(IPC_OBJ) iscsid.o mgmt_ipc.o initiator.o \
				  actor.o queue.o
	$(CC) $^ $(DBM_LIB) -o $@

iscsiadm: $(COMMON_SRCS) strings.o discovery.o iscsiadm.o
	$(CC) $^ $(DBM_LIB) -o $@

clean:
	rm -f *.o $(PROGRAMS)
