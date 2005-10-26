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
	@echo "Built management application:       usr/iscsiadm"
	@echo
	@echo Read README file for detailed information.

clean:
	make -C usr clean
	make -C kernel clean

install: kernel/iscsi_tcp.ko kernel/scsi_transport_iscsi.ko usr/iscsid usr/iscsiadm
	@install -vD usr/iscsid /usr/sbin/iscsid
	@install -vD usr/iscsiadm /usr/sbin/iscsiadm
	if [ -f /etc/debian_version ]; then \
		install -vD -m 755 etc/initd/initd.debian /etc/init.d/open-iscsi; \
	elif [ -f /etc/redhat-release ]; then \
		install -vD -m 755 etc/initd/initd.redhat /etc/init.d/open-iscsi; \
	fi
	install -vD kernel/iscsi_tcp.ko /lib/modules/`uname -r`/kernel/drivers/scsi/iscsi_tcp.ko
	install -vD kernel/scsi_transport_iscsi.ko /lib/modules/`uname -r`/kernel/drivers/scsi/scsi_transport_iscsi.ko
	-depmod -aq
