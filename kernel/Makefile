#
# Makefile for the Linux Kernel iSCSI Initiator
#

EXTRA_CFLAGS += -I$(obj) -I$(obj)/../include 

obj-m = scsi_transport_iscsi.o iscsi_tcp.o 

KSRC ?= /lib/modules/`uname -r`/build

KVER = $(shell cat $(KSRC)/Makefile | awk -F= '/^SUBLEVEL =/ {print $$2}' | \
		sed 's/^[ \t]*//;s/[ \t]*$$//')

ifeq ($(KVER), 11)
EXTRA_CFLAGS += -DNETLINK_ISCSI=12
else
ifeq ($(KVER), 12)
EXTRA_CFLAGS += -DNETLINK_ISCSI=12
endif
endif

all:
ifeq ($(KVER),11)
	@if cat scsi_transport_iscsi.c | \
	    grep transport_container_register > /dev/null; then  \
	    echo "kernel check... FAILED"; \
	    echo "Please apply backward-compile-2.6.11.patch first!"; exit 1; fi
	@echo "kernel check... OK"
else
ifeq ($(KVER),12)
	@if cat scsi_transport_iscsi.c | \
	    grep "__nlmsg_put.*, 0);" > /dev/null; then  \
	    echo "kernel check... FAILED"; \
	    echo "Please apply backward-compile-2.6.12.patch first!"; exit 1; fi
	@echo "kernel check... OK"
else
	@echo "kernel check... OK"
endif
endif
	make -C $(KSRC) SUBDIRS=`pwd` $(KARCH)

clean:
	rm -f -r *.mod.c .*cmd *.o *.ko .tmp_versions
