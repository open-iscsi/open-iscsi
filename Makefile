#
# Makefile for the Open-iSCSI Initiator
#

all:
	make -C usr
	make -C kernel
	@echo
	@echo "Compilation complete                Output file"
	@echo "--------------------------------    ----------------"
	@echo "Built iSCSI Linux kernel module:    kernel/iscsi.ko"
	@echo "Built iSCSI daemon:                 usr/iscsid"
	@echo "Built mangement application:        usr/iscsiadm"
	@echo
	@echo Read INSTALL file for detailed information.

clean:
	make -C usr clean
	make -C kernel clean
