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
obj-m				+= libiscsi_tcp.o
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
14to23_patch=2.6.14-23_compat.patch
24_patch=2.6.24_compat.patch
26_patch=2.6.26_compat.patch
27_patch=2.6.27_compat.patch
28to32_patch=2.6.28-32_compat.patch
33to34_patch=2.6.33-34_compat.patch
all_patches=14to21_patch 20to21_patch 24_patch 26_patch 27_patch 28to32_patch 33to34_patch
cur_patched=cur_patched

## fun stuff for maintaining multiple versions

# check to see if code is unpatched 
unpatch_code=$(shell test -e $(cur_patched) && echo do_unpatch_code )

KSUBLEVEL = $(shell cat $(KSRC)/Makefile | awk -F= '/^SUBLEVEL =/ {print $$2}' | \
		sed 's/^[ \t]*//;s/[ \t]*$$//')


KERNEL_TARGET=linux_2_6_$(KSUBLEVEL)
kernel_check: $(KERNEL_TARGET)

linux_2_6_14: has_14to23_patch

linux_2_6_15: has_14to23_patch

linux_2_6_16: has_14to23_patch

linux_2_6_17: has_14to23_patch

linux_2_6_18: has_14to23_patch

linux_2_6_19: has_14to23_patch

linux_2_6_20: has_14to23_patch

linux_2_6_21: has_14to23_patch

linux_2_6_22: has_14to23_patch

linux_2_6_23: has_14to23_patch

linux_2_6_24: has_24_patch

linux_2_6_25: has_24_patch

linux_2_6_26: has_26_patch

linux_2_6_27: has_27_patch

linux_2_6_28: has_28to32_patch

linux_2_6_29: has_28to32_patch

linux_2_6_30: has_28to32_patch

linux_2_6_31: has_28to32_patch

linux_2_6_32: has_28to32_patch

linux_2_6_33: has_33to34_patch

linux_2_6_34: has_33to34_patch

linux_2_6_35: $(unpatch_code)

do_unpatch_code:
	echo "Un-patching source code for use with linux-2.6.14 and up ..."
	patch -R -E -p1 < $(cur_patched)
	rm -f `readlink $(cur_patched)`
	rm -f $(cur_patched)

# these below targets must be the same as the variable name prefixed by has_
# otherwise below compat_patch: target will not work
has_14to23_patch: $(14to23_patch)
	echo "Patching source code for linux-2.6.14-23 ..."
	if [ -e $(cur_patched) ]; then \
		make -C . clean; \
	fi
	patch -p1 < $(14to23_patch)
	cp $(14to23_patch) $@
	ln -s $@ $(cur_patched)

has_24_patch: $(24_patch)
	echo "Patching source code for linux-2.6.24-25 ..."
	if [ -e $(cur_patched) ]; then \
		make -C . clean; \
	fi
	patch -p1 < $(24_patch)
	cp $(24_patch) $@
	ln -s $@ $(cur_patched)

has_26_patch: $(26_patch)
	echo "Patching source code for linux-2.6.26 ..."
	if [ -e $(cur_patched) ]; then \
		make -C . clean; \
	fi
	patch -p1 < $(26_patch)
	cp $(26_patch) $@
	ln -s $@ $(cur_patched)

has_27_patch: $(27_patch)
	echo "Patching source code for linux-2.6.27 ..."
	if [ -e $(cur_patched) ]; then \
		make -C . clean; \
	fi
	patch -p1 < $(27_patch)
	cp $(27_patch) $@
	ln -s $@ $(cur_patched)

has_28to32_patch: $(28to32_patch)
	echo "Patching source code for linux-2.6.28-33 ..."
	if [ -e $(cur_patched) ]; then \
		make -C . clean; \
	fi
	patch -p1 < $(28to32_patch)
	cp $(28to32_patch) $@
	ln -s $@ $(cur_patched)

has_33to34_patch: $(33to34_patch)
	echo "Patching source code for linux-2.6.33-34 ..."
	if [ -e $(cur_patched) ]; then \
		make -C . clean; \
	fi
	patch -p1 < $(33to34_patch)
	cp $(33to34_patch) $@
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

dpkg_divert:
	for module in $(ko) ; do \
		dpkg-divert --rename /lib/modules/$(KERNELRELEASE)/$(INSTALL_MOD_DIR)/$$module ; \
	done

# vim: ft=make tw=72 sw=4 ts=4:
