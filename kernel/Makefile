#
# Makefile for the Linux Kernel iSCSI Initiator
#
# This Makefile invokes KBuild from outside the kernel directory when
# used from the main open-iscsi package. It also contains all of the
# KBuild stuff needed to build the the modules.
#

# Kbuild stuff, the following is the only part of this file that KBuild
# actually uses itself.
EXTRA_CFLAGS += -I$(obj) -I$(obj)/../include 

ifeq ($(DEBUG_SCSI), 1)
EXTRA_CFLAGS += -DDEBUG_SCSI=1
endif

ifeq ($(DEBUG_TCP), 1)
EXTRA_CFLAGS += -DDEBUG_TCP=1
endif

obj-m				+= scsi_transport_iscsi.o
obj-m				+= libiscsi.o
obj-m				+= iscsi_tcp.o

# Everything beyond this point is used to call KBuild or handle support
# for multiple kernel versions.

# Kbuild verbosity
V ?= 0

# allow users to override these
# eg to compile for a kernel that you aren't currently running
KERNELRELEASE ?= $(shell uname -r)
KSRC ?= /lib/modules/$(KERNELRELEASE)/build
KBUILD_OUTPUT ?= 
# this is the basic Kbuild invocation, just append your make target
KBUILD_BASE = +$(MAKE) -C $(KSRC) M=`pwd` KBUILD_OUTPUT=$(KBUILD_OUTPUT) $(KARCH) V=$(V)

# fun stuff for maintaining multiple versions
KSUBLEVEL = $(shell cat $(KSRC)/Makefile | awk -F= '/^SUBLEVEL =/ {print $$2}' | \
		sed 's/^[ \t]*//;s/[ \t]*$$//')

ifeq ($(KSUBLEVEL), 11)
EXTRA_CFLAGS += -DNETLINK_ISCSI=12
else
ifeq ($(KSUBLEVEL), 12)
EXTRA_CFLAGS += -DNETLINK_ISCSI=12
endif
endif

all: kernel_check
	$(KBUILD_BASE) modules

# ====== BEGIN code for kernel_check


# generic make function
# syntax:
# @$(call generic_check_command, CHECKING-COMMAND, PATCHNAME)
generic_check_command = if $(1) ; then \
				echo "kernel check... FAILED"; \
				echo "Apply the $(2) first!"; exit 1; fi ; \
				echo "kernel check... OK"

# this variable defines how we check for iscsi_compat
check_iscsi_compat_command =  ! grep iscsi_compat scsi_transport_iscsi.c >/dev/null 
# this variable is the actual make function
check_iscsi_compat = $(call generic_check_command, $(check_iscsi_compat_command), $(1))
# syntax:
# @$(call check_iscsi_compat, PATCHNAME)

# this if-else ladder is horrible
# but I don't know any quick way to clean it up
# since Make doesn't support a switch construct
.NOTPARALLEL: kernel_check
kernel_check:
ifeq ($(KSUBLEVEL),16)
	echo "kernel check... OK"
else
ifeq ($(KSUBLEVEL),17)
	echo "kernel check... OK"
else
ifeq ($(KSUBLEVEL),18)
	echo "kernel check... OK"
else
	@echo "kernel check... UNSUPPORTED KERNEL DETECTED"
	exit 1;
endif
endif
endif

# ====== END code for kernel_check

clean:
	$(KBUILD_BASE) clean
#echo rm -f -r *.mod.c .*cmd *.o *.ko .tmp_versions

# the following is only for convienience
# do not submit to Linus
# it's also called from the toplevel makefile

# INSTALL_MOD_DIR is set so that the drivers go into the correct location using Kbuild
# it defaults to 'extra' otherwise
INSTALL_MOD_DIR ?= kernel/drivers/scsi

# this allows packaging of modules
ifdef DESTDIR
INSTALL_MOD_PATH=$(DESTDIR)
else
INSTALL_MOD_PATH=
endif

# this evil rule ensures that the modules get build if you specify $(ko)
# as a dependancy.
ko = $(patsubst %.o,%.ko,$(obj-m))
$(ko): all

# now the actual command
install_kernel: $(ko)
	$(KBUILD_BASE) modules_install INSTALL_MOD_DIR=$(INSTALL_MOD_DIR) INSTALL_MOD_PATH=$(INSTALL_MOD_PATH)

# vim: ft=make tw=72 sw=4 ts=4:
