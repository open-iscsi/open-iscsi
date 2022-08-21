#!/bin/sh
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
BONNIEPARAMS="${BONNIEPARAMS:--r0 -n10:0:0 -s16 -uroot -f -q}"

trap regress_signal INT QUIT TERM
regress_signal() {
    printf '\nterminating, restore defaults: '
	# use the other function to clean up
	imm_data_en="Yes"
	initial_r2t_en="No"
	hdrdgst_en="None,CRC32C"
	datdgst_en="None,CRC32C"
	first_burst="$((256*1024))"
	max_burst="$((16*1024*1024-1024))"
	max_recv_dlength="$((128*1024))"
	max_r2t="1"
	update_cfg
	"${iscsiadm}" -m node -T "$target" -p "$ipnr" --logout 2>/dev/null >/dev/null
    echo 'done'
    exit 0
}

update_cfg() {
	c() { "${iscsiadm}" -m node -T "$target" -p "$ipnr" -o update "$@"; }
	c -n node.session.iscsi.ImmediateData -v $imm_data_en
	c -n node.session.iscsi.InitialR2T -v $initial_r2t_en
	c -n node.conn[0].iscsi.HeaderDigest -v $hdrdgst_en
	c -n node.conn[0].iscsi.DataDigest -v $datdgst_en
	c -n node.session.iscsi.FirstBurstLength -v $first_burst
	c -n node.session.iscsi.MaxBurstLength -v $max_burst
	c -n node.conn[0].iscsi.MaxRecvDataSegmentLength -v $max_recv_dlength
	c -n node.session.iscsi.MaxOutstandingR2T -v $max_r2t
}

disktest_run() {
	bsizes="512 1024 2048 4096 8192 16384 32768 65536 131072 1000000"
	[ -z "$bsize" ] && bsizes=$bsize
	[ "$bsize" = "bonnie" ] && return 0;
	for bs in $bsizes; do
		printf '%s' "disktest -T2 -K8 -B$bs -r -ID $device: "
		#if ! "${disktest}" -T2 -K8 -B$bs -r -ID $device >/dev/null; then
		if ! "${disktest}" -T2 -K8 -B"$bs" -r -ID "$device"; then
			echo "FAILED"
			return 1;
		fi
		echo "PASSED"
		#printf '%s' "disktest -T2 -K8 -B$bs -E16 -w -ID $device: "
		#if ! "${disktest}" -T2 -K8 -B$bs -E16 -w -ID $device >/dev/null;then
		printf '%s' "disktest -T2 -K8 -B$bs -E16 -ID $device: "
		if ! "${disktest}" -T2 -K8 -B"$bs" -E16 -ID "$device"; then
			echo "FAILED"
			return 1;
		fi
		echo "PASSED"
	done
	return 0;
}

fdisk_run() {
	printf '%s' "sfdisk -qf $device: "
	#if ! printf '%s\n' . quit | sfdisk -Lqf "$device" >/dev/null 2>/dev/null; then
	if ! printf '%s\n' . quit | sfdisk -Lqf "$device"; then
		echo "FAILED"
		return 1;
	fi
	echo "PASSED"
	return 0;
}

mkfs_run() {
	printf '%s' "${MKFSCMD} $device_partition: "
	#if ! ${MKFSCMD} "$device_partition" 2>/dev/null >/dev/null; then
	if ! ${MKFSCMD} "$device_partition" ; then
		echo "FAILED"
		return 1;
	fi
	echo "PASSED"
	return 0;
}

bonnie_run() {
	dir="$(mktemp -t /tmp/iscsi.bonnie.regression.XXXXXXXX)"
	umount "$dir" 2>/dev/null >/dev/null
	rm -rf "$dir"; mkdir "$dir"
	printf '%s' "mount $dir: "
	# shellcheck disable=SC2086
	if ! mount ${MOUNTOPTIONS} "$device_partition" "$dir"; then
		echo "FAILED"
		return 1;
	fi
	echo "PASSED"
	printf '%s' "bonnie++ ${BONNIEPARAMS}: "
	# shellcheck disable=SC2086
	(cd "$dir" && "${bonnie}" ${BONNIEPARAMS} 2>/dev/null >/dev/null)
	rc=$?
	umount "$dir" 2>/dev/null >/dev/null
	rmdir "$dir"
	if [ $rc -ne 0 ]; then
		echo "FAILED"
		return 1;
	fi
	echo "PASSED"
	return 0;
}

fatal() {
	echo "regression.sh: $1"
	echo "Usage: regression.sh [-f | <targetname> <ipnumber#> ] <device> [test#[:#]] [bsize]"
	exit 1
}

############################ main ###################################

disktest="$(command -v disktest)"
iscsiadm="$(command -v iscsiadm)"
bonnie="$(command -v bonnie++)"
datfile="$(dirname "$0")/regression.dat"
[ -e "${datfile}"  ] || fatal "can not find regression.dat"
[ -e "${disktest}" ] || fatal "can not find disktest"
[ -e "${iscsiadm}" ] || fatal "can not find iscsiadm"
[ -e "${bonnie}"   ] || fatal "can not find bonnie++"

if [ "$1" = "-f" ] || [ "$1" = "--format" ]; then
	[ -n "$2" ] || fatal "SCSI device parameter error"
	device=$2
else
	[ -n "$1" ] || fatal "target name parameter error"
	[ -n "$2" ] || fatal "ipnumber parameter error"
	[ -n "$3" ] || fatal "SCSI device parameter error"

	target="$1"
	ipnr="$2"
	device=$3
fi

device_dir="$(dirname "${device}")"
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

if [ "$1" = "-f" ] || [ "$1" = "--format" ]; then
	mkfs_run
	exit
fi

if [ -z "${device_partition}" ]; then
	echo 'Unable to find device name for first partition.' >&2
	exit 1
fi

[ -n "$4" ] && begin="$4"
[ -n "$5" ] && bsize="$5"

if [ -n "$begin" ]; then
	end="${begin##*:}"
	begin="${begin%%:*}"
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

	Are you sure you want to continue? [Y/n]:
	EOF
	read -r line
	case "$line" in
		[nN0]*)
			echo "aborting..."
			exit
			;;
	esac
fi

i=0
while read -r imm_data_en initial_r2t_en hdrdgst_en datdgst_en first_burst max_burst max_recv_dlength max_r2t; do
	[ -z "${line}" ] && continue
	[ "${line#'#'}" != "$line" ] && continue
	if [ -n "$begin" ]; then
		if [ "$begin" != "$i" ] && [ -z "$end" ]; then
			i=$(( i + 1 ))
			continue
		elif [ -n "$end" ]; then
			if [ "$i" -lt "$begin" ] || [ "$i" -gt "$end" ]; then
				i=$(( i + 1 ))
				continue
			fi
		fi
	fi
	case "$imm_data_en" in
		[YesNo][YesNo]*) ;;
		*) continue ;;
	esac
	# ensure we are logged out
	"${iscsiadm}" -m node -T "$target" -p "$ipnr" --logout 2>/dev/null >/dev/null
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
	"${iscsiadm}" -m node -T "$target" -p "$ipnr" --login || break
	while [ ! -e "$device" ]; do sleep 1; done
	disktest_run || break
	fdisk_run || break
	mkfs_run || break
	bonnie_run || break
	i=$(( i + 1 ))
done < "${datfile}"
regress_signal
echo
echo "===================== THE END ========================"
