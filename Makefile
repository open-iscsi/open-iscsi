#
# Makefile for the Linux Kernel iSCSI Initiator
#

EXTRA_CFLAGS += -I$(obj)

obj-m = iscsi.o
iscsi-y = iscsi_control.o iscsi_tcp.o

#KSRC ?= /lib/modules/`uname -r`/build
KSRC ?= /usr/src/linux-2.6.10-um
KARCH ?= ARCH=um

all:
	make -C $(KSRC) SUBDIRS=`pwd` $(KARCH)

clean:
	rm -f *.mod.c .*cmd *.o *.ko
