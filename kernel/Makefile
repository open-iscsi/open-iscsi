#
# Makefile for the Linux Kernel iSCSI Initiator
#

EXTRA_CFLAGS += -I$(obj) -I$(obj)/../include

obj-m = iscsi.o
iscsi-y = iscsi_tcp.o iscsi_if.o

KSRC ?= /lib/modules/`uname -r`/build

all:
	make -C $(KSRC) SUBDIRS=`pwd` $(KARCH)

clean:
	rm -f *.mod.c .*cmd *.o *.ko
