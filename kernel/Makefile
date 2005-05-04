#
# Makefile for the Linux Kernel iSCSI Initiator
#

EXTRA_CFLAGS += -I$(obj) -I$(obj)/../include -DNETLINK_ISCSI=10

# Note: For kernels >= 2.6.11 use iscsi_if.o (depricated)
#       For kernels >= 2.6.12-rc3 use scsi_transport_iscsi.o
obj-m = scsi_transport_iscsi.o iscsi_tcp.o 

KSRC ?= /lib/modules/`uname -r`/build

all:
	make -C $(KSRC) SUBDIRS=`pwd` $(KARCH)

clean:
	rm -f -r *.mod.c .*cmd *.o *.ko .tmp_versions
