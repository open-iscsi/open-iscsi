#
# Makefile for the Open-iSCSI Initiator
#

all:
	make -C usr
	make -C kernel
	@echo
	@echo "Compilation complete                Output file"
	@echo "----------------------------------- ----------------"
	@echo "Built iSCSI Open Interface module:  kernel/scsi_transport_iscsi.ko"
	@echo "Built iSCSI over TCP kernel module: kernel/iscsi_tcp.ko"
	@echo "Built iSCSI daemon:                 usr/iscsid"
	@echo "Built mangement application:        usr/iscsiadm"
	@echo
	@echo Read README file for detailed information.

clean:
	make -C usr
	make -C kernel clean
