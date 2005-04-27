#
# Makefile for the Linux Kernel iSCSI Initiator
#

EXTRA_CFLAGS += -I$(obj) -I$(obj)/../include -DNETLINK_ISCSI=10

obj-m = iscsi_if.o iscsi_tcp.o 

KSRC ?= /lib/modules/`uname -r`/build

all:
	make -C $(KSRC) SUBDIRS=`pwd` $(KARCH)

clean:
	rm -f -r *.mod.c .*cmd *.o *.ko .tmp_versions
