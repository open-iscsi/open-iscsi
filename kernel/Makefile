#
# Makefile for the Linux Kernel iSCSI Initiator
#
# This Makefile invokes KBuild from outside the kernel directory when
# used from the main open-iscsi package. It also contains all of the
# KBuild stuff needed to build the modules.
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

all: kernel_check
	$(KBUILD_BASE) modules

# ============ BEGIN code for kernel_check and source patching ================
# We calculate the Linux version for compilation. Than according to version,
# if needed, we patch source-code to match the compiling kernel.
# if you need a new kernel sub-version just add a target below.
#
# IMPORTANT: do "make clean" before submitting to SVN so source is in unpatched
#            form.

#some constants
13_patch=2.6.13_compat.patch
14to15_patch=2.6.14-and-2.6.15-compat.patch
16to18_patch=2.6.16-18_compat.patch
19_patch=2.6.19_compat.patch
all_patches=13_patch 14to15_patch 16to18_patch 19_patch
cur_patched=cur_patched

## fun stuff for maintaining multiple versions

# check to see if code is unpatched 
unpatch_code=$(shell test -e $(cur_patched) && echo do_unpatch_code )

KSUBLEVEL = $(shell cat $(KSRC)/Makefile | awk -F= '/^SUBLEVEL =/ {print $$2}' | \
		sed 's/^[ \t]*//;s/[ \t]*$$//')

KERNEL_TARGET=linux_2_6_$(KSUBLEVEL)
kernel_check: $(KERNEL_TARGET)


linux_2_6_13: has_13_patch

linux_2_6_14: has_14to15_patch

linux_2_6_15: has_14to15_patch

linux_2_6_16: has_16to18_patch

linux_2_6_17: has_16to18_patch

linux_2_6_18: has_16to18_patch

linux_2_6_19: has_19_patch

linux_2_6_20: $(unpatch_code)

linux_2_6_21: $(unpatch_code)

do_unpatch_code:
	echo "Un-patching source code for use with linux-2.6.20 and up ..."
	patch -R -E -p1 < $(cur_patched)
	rm -f `readlink $(cur_patched)`
	rm -f $(cur_patched)

# these below targets must be the same as the variable name prefixed by has_
# otherwise below compat_patch: target will not work
has_13_patch: $(13_patch)
	echo "Patching source code for linux-2.6.13 ..."
	if [ -e $(cur_patched) ]; then \
		make -C . clean; \
	fi
	patch -p1 < $(13_patch)
	cp $(13_patch) $@
	ln -s $@ $(cur_patched)

has_14to15_patch: $(14to15_patch)
	echo "Patching source code for linux-2.6.14-15 ..."
	if [ -e $(cur_patched) ]; then \
		make -C . clean; \
	fi
	patch -p1 < $(14to15_patch)
	cp $(14to15_patch) $@
	ln -s $@ $(cur_patched)

has_16to18_patch: $(16to18_patch)
	echo "Patching source code for linux-2.6.16-18 ..."
	if [ -e $(cur_patched) ]; then \
		make -C . clean; \
	fi
	patch -p1 < $(16to18_patch)
	cp $(16to18_patch) $@
	ln -s $@ $(cur_patched)

has_19_patch: $(19_patch)
	echo "Patching source code for linux-2.6.19 ..."
	if [ -e $(cur_patched) ]; then \
		make -C . clean; \
	fi
	patch -p1 < $(19_patch)
	cp $(19_patch) $@
	ln -s $@ $(cur_patched)

# ============ END code for kernel_check and source patching =================

clean: $(unpatch_code)
	$(KBUILD_BASE) clean
	rm -f Module.symvers

## The folowing compat_patch target is what we need to do to prepare a clean
# compat_patch set after new code is check-in to svn. To keep patches fuzzless.
# the new patches are writen into .new files so svn diff of next file will
# not trip on them.
compat_patch: $(unpatch_code)
	test -z "$(svn diff|head)" || { \
		echo "please run make compat_patch after changse are submited to svn"; \
		exit 1; \
	}
	for the_patch in all_patches ; do \
		make -C . has_$(the_patch); \
		svn diff > ${!the_patch}.new; \
	done

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
