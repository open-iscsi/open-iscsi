#
# Makefile for the Linux Kernel iSCSI Initiator
#

EXTRA_CFLAGS += -I$(obj) -I$(obj)/../include -DNETLINK_ISCSI=10

obj-m = scsi_transport_iscsi.o iscsi_tcp.o 

KSRC ?= /lib/modules/`uname -r`/build

all:
ifeq ($(shell cat $(KSRC)/Makefile | awk -F= '/^SUBLEVEL =/ {print $$2}' | \
		sed 's/^[ \t]*//;s/[ \t]*$$//'),11)
	@if cat scsi_transport_iscsi.c | \
	    grep transport_container_register > /dev/null; then  \
	    echo "kernel check... FAILED"; \
	    echo "Please apply backward-compile-2.6.11.patch first!"; exit 1; fi
	@echo "kernel check... OK"
else
	@echo "kernel check... OK"
endif
	make -C $(KSRC) SUBDIRS=`pwd` $(KARCH)

clean:
	rm -f -r *.mod.c .*cmd *.o *.ko .tmp_versions
