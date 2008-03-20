#!/bin/bash
#
# Open-iSCSI Regression Test Utility
# Copyright (C) 2004 Dmitry Yusupov
# maintained by open-iscsi@googlegroups.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published
# by the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# See the file COPYING included with this distribution for more details.
#

PATH=".:${PATH}"
FSTYPE="${FSTYPE:-ext3}"
DEFAULTMOUNTOPTS='-o _netdev'
[ -z "${MOUNTOPTS}" ] && MOUNTOPTS="${DEFAULTMOUNTOPTS}"
# to avoid mount looking for fstype
MOUNTOPTIONS="${MOUNTOPTIONS} -t ${FSTYPE}"
MKFSCMD="${MKFSCMD:-mkfs.${FSTYPE}} ${MKFSOPTS}"
PARTITIONSUFFIX="1"
BONNIEPARAMS="${BONNIEPARAMS:--r0 -n10:0:0 -s16 -uroot -f -q}"

trap regress_signal INT QUIT TERM
regress_signal() {
    printf "\nterminating, restore defaults: "
	# use the other function to clean up
	imm_data_en="Yes"
	initial_r2t_en="No"
	hdrdgst_en="None,CRC32C"
	datdgst_en="None,CRC32C"
	c="${iscsiadm} -m node -T $target -p $ipnr -o update"
	first_burst="$((256*1024))"
	max_burst="$((16*1024*1024-1024))"
	max_recv_dlength="$((128*1024))"
	max_r2t="1"
	update_cfg
	${iscsiadm} -m node -T $target -p $ipnr --logout 2>/dev/null >/dev/null
    printf "done\n"
    exit 0
}

function update_cfg() {
	c="${iscsiadm} -m node -T $target -p $ipnr -o update"
	$c -n node.session.iscsi.ImmediateData -v $imm_data_en
	$c -n node.session.iscsi.InitialR2T -v $initial_r2t_en
	$c -n node.conn[0].iscsi.HeaderDigest -v $hdrdgst_en
	$c -n node.conn[0].iscsi.DataDigest -v $datdgst_en
	$c -n node.session.iscsi.FirstBurstLength -v $first_burst
	$c -n node.session.iscsi.MaxBurstLength -v $max_burst
	$c -n node.conn[0].iscsi.MaxRecvDataSegmentLength -v $max_recv_dlength
	$c -n node.session.iscsi.MaxOutstandingR2T -v $max_r2t
}

function disktest_run() {
	bsizes="512 1024 2048 4096 8192 16384 32768 65536 131072 1000000"
	test "x$bsize" != x && bsizes=$bsize
	test "x$bsize" = xbonnie && return 0;
	for bs in $bsizes; do
		echo -n "disktest -T2 -K8 -B$bs -r -ID $device: "
		if ! ${disktest} -T2 -K8 -B$bs -r -ID $device >/dev/null; then
			echo "FAILED"
			return 1;
		fi
		echo "PASSED"
		echo -n "disktest -T2 -K8 -B$bs -E16 -w -ID $device: "
		if ! ${disktest} -T2 -K8 -B$bs -E16 -w -ID $device >/dev/null;then
			echo "FAILED"
			return 1;
		fi
		echo "PASSED"
	done
	return 0;
}

function fdisk_run() {
	echo -n "sfdisk -Lqf $device: "
	sfdisk -Lqf $device >/dev/null 2>/dev/null <<-EOF
	0,
	;
	;
	;
	EOF
	rc=$?
	if [ $rc -ne 0 ]; then
		echo "FAILED"
		return 1;
	fi
	echo "PASSED"
	return 0;
}

function mkfs_run() {
	echo -n "${MKFSCMD} $device_partition: "
	if ! ${MKFSCMD} $device_partition 2>/dev/null >/dev/null; then
		echo "FAILED"
		return 1;
	fi
	echo "PASSED"
	return 0;
}

function bonnie_run() {
	dir="/tmp/iscsi.bonnie.regression.$record.$RANDOM"
	umount $dir 2>/dev/null >/dev/null
	rm -rf $dir; mkdir $dir
	echo -n "mount $dir: "
	if ! mount ${MOUNTOPTIONS} $device_partition $dir; then
		echo "FAILED"
		return 1;
	fi
	echo "PASSED"
	echo -n "bonnie++ ${BONNIEPARAMS}: "
	pushd $dir >/dev/null
	${bonnie} ${BONNIEPARAMS} 2>/dev/null >/dev/null
	rc=$?
	popd >/dev/null
	umount $dir 2>/dev/null >/dev/null
	rmdir ${dir}
	if [ $rc -ne 0 ]; then
		echo "FAILED"
		return 1;
	fi
	echo "PASSED"
	return 0;
}

function fatal() {
	echo "regression.sh: $1"
	echo "Usage: regression.sh [-f | <targetname> <ipnumber#> ] <device> [test#[:#]] [bsize]"
	exit 1
}

############################ main ###################################

disktest=`which disktest`
iscsiadm=`which iscsiadm`
bonnie=`which bonnie++`
datfile=`dirname $0`"/regression.dat"
test ! -e ${datfile} && fatal "can not find regression.dat"
test ! -e ${disktest} && fatal "can not find disktest"
test ! -e ${iscsiadm} && fatal "can not find iscsiadm"
test ! -e ${bonnie} && fatal "can not find bonnie++"

if test x$1 = "x-f" -o x$1 = "x--format"; then
	test x$2 = x && fatal "SCSI device parameter error"
	device=$2
else
	test x$1 = x && fatal "target name parameter error"
	test x$2 = x && fatal "ipnumber parameter error"
	test x$3 = x && fatal "SCSI device parameter error"

	target="$1"
	ipnr="$2"
	device=$3
fi

device_dir="$(dirname ${device})"
device_partition=''
case "${device_dir}" in
	# /dev/sdaX
	/dev) device_partition="${device}1" ;;
	# /dev/disk/by-id/scsi-${ID_SERIAL}-part1
	# where ID_SERIAL is SCSI disk SERIAL from scsi_id
	/dev/disk/by-id|/dev/disk/by-path) device_partition="${device}-part1" ;;
	# upcoming stuff
	/dev/iscsi/*) device_partition="${device}-part1" ;;
esac

if test x$1 = "x-f" -o x$1 = "x--format"; then
	mkfs_run
	exit
fi

if [ -z "${device_partition}" ]; then
	echo 'Unable to find device name for first partition.' >&2
	exit 1
fi

test "x$4" != x && begin="$4"
test "x$5" != x && bsize="$5"

if test "x$begin" != "x"; then
	end="${begin/*:}"
	begin="${begin/:*}"
fi

# don't say we didn't warn you
if [ -z "${SKIP_WARNING}" ]; then
	cat <<-EOF
	BIG FAT WARNING!
	
	Open-iSCSI Regression Test Suite is about to start. It is going
	to use "$device" for its testing. iSCSI session could be re-opened
	during the tests several times and as the result device name could
	not match provided device name if some other SCSI activity happened
	during the test.
	
	Are you sure you want to continue? [y/n]:
	EOF
	read line
	if test x$line = xn -o x$line = xN -o x$line = xno -o x$line = xNO; then
		echo "aborting..."
		exit
	fi
fi

i=0
cat ${datfile} | while read line; do
	if echo $line | grep "^#" >/dev/null; then continue; fi
	if echo $line | grep "^$" >/dev/null; then continue; fi
	if test x$begin != x; then
		if test x$begin != x$i -a x$end = x; then
			let i=i+1
			continue
		elif test x$begin != x -a x$end != x; then
			if test $i -lt $begin -o $i -gt $end; then
				let i=i+1
				continue
			fi
		fi
	fi
	imm_data_en=`echo $line | awk '/^[YesNo]+/ {print $1}'`
	if test x$imm_data_en = x; then continue; fi
	initial_r2t_en=`echo $line | awk '{print $2}'`
	hdrdgst_en=`echo $line | awk '{print $3}'`
	datdgst_en=`echo $line | awk '{print $4}'`
	first_burst=`echo $line | awk '{print $5}'`
	max_burst=`echo $line | awk '{print $6}'`
	max_recv_dlength=`echo $line | awk '{print $7}'`
	max_r2t=`echo $line | awk '{print $8}'`
	# ensure we are logged out
	${iscsiadm} -m node -T $target -p $ipnr --logout 2>/dev/null >/dev/null
	# set parameters for next run
	update_cfg
	echo "================== TEST #$i BEGIN ===================="
	echo "ImmediateData = $imm_data_en"
	echo "InitialR2T = $initial_r2t_en"
	echo "HeaderDigest = $hdrdgst_en"
	echo "DataDigest = $datdgst_en"
	echo "FirstBurstLength = $first_burst"
	echo "MaxBurstLength = $max_burst"
	echo "MaxRecvDataSegmentLength = $max_recv_dlength"
	echo "MaxOutstandingR2T = $max_r2t"
	# login for new test
	# catch errors on this
	if ! ${iscsiadm} -m node -T $target -p $ipnr --login; then break; fi
	while [ ! -e $device ] ; do sleep 1 ; done
	if ! disktest_run; then break; fi
	if ! fdisk_run; then break; fi
	if ! mkfs_run; then break; fi
	if ! bonnie_run; then break; fi
	let i=i+1
done
regress_signal
echo
echo "===================== THE END ========================"
