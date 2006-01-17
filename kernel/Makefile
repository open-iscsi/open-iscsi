#
# Makefile for the Linux Kernel iSCSI Initiator
#

EXTRA_CFLAGS += -I$(obj) -I$(obj)/../include 

obj-m				+= scsi_transport_iscsi.o
obj-m				+= iscsi_tcp.o 

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

#TODO: learn how to program Makefiles!
all:
ifeq ($(KVER),11)
	@if ! cat scsi_transport_iscsi.c | \
	    grep iscsi_compat > /dev/null; then  \
	    echo "kernel check... FAILED"; \
	    echo "Apply the 2.6.11-compat.patch first!"; exit 1; fi
	@echo "kernel check... OK"
else
ifeq ($(KVER),12)
	@if ! cat scsi_transport_iscsi.c | \
	    grep iscsi_compat > /dev/null; then  \
	    echo "kernel check... FAILED"; \
	    echo "Apply the 2.6.12-and-2.6.13-compat.patch first!"; exit 1; fi
	@echo "kernel check... OK"
else
ifeq ($(KVER),13)
	@if ! cat scsi_transport_iscsi.c | \
	    grep iscsi_compat > /dev/null; then  \
	    echo "kernel check... FAILED"; \
	    echo "Apply the 2.6.12-and-2.6.13-compat.patch first!"; exit 1; fi
	@echo "kernel check... OK"
else
ifeq ($(KVER),14)
	@if ! cat scsi_transport_iscsi.c | \
	    grep iscsi_compat > /dev/null; then  \
	    echo "kernel check... FAILED"; \
	    echo "Apply the 2.6.14-and-2.6.15-compat.patch first!"; exit 1; fi
	@echo "kernel check... OK"
else
ifeq ($(KVER),15)
	@if ! cat scsi_transport_iscsi.c | \
	    grep iscsi_compat > /dev/null; then  \
	    echo "kernel check... FAILED"; \
	    echo "Apply the 2.6.14-and-2.6.15-compat.patch first!"; exit 1; fi
	@echo "kernel check... OK"
else
	@echo "kernel check... OK"
endif
endif
endif
endif
endif
	make -C $(KSRC) SUBDIRS=`pwd` $(KARCH)

clean:
	rm -f -r *.mod.c .*cmd *.o *.ko .tmp_versions
