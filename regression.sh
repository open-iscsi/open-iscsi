#!/bin/bash
#
# iSCSI Regression Test Utility
# Copyright (C) 2004 Dmitry Yusupov, Alex Aizman
# maintained by open-iscsi@@googlegroups.com
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

PATH=$PATH:.

function write_cfg() {
cat << EOF > iscsi.conf
initiator_name = "iqn.com.dima"
initiator_alias = "dima-um"
isid = '012345'
first_burst = $first_burst
max_recv_dlength = $max_recv_dlength
max_burst = $max_burst
max_r2t = $max_r2t
max_cnx = $max_cnx
erl = 0
initial_r2t_en = $initial_r2t_en
imm_data_en  = $imm_data_en
hdrdgst_en = 0
datadgst_en = 0
ifmarker_en = 0
ofmarker_en = 0
pdu_inorder_en = 1
dataseq_inorder_en = 1
time2wait = 5
time2retain = 20
EOF
}

function disktest() {
	for bs in "512 1024 2048 4096 8192 16384 32768 65536 131072 1000000"; do
		disktest -T2 -K8 -B65536 -r -ID /dev/sda
		disktest -T2 -K8 -B65536 -E16 -w -ID /dev/sda
	done
}

function fatal() {
	echo "regression.sh: $1"
	exit 1
}

############################ main ###################################

test ! -e regression.dat && fatal "can not find regression.dat"
test ! -e disktest && fatal "can not find disktest"
test ! -e iscsiadm && fatal "can not find iscsiadm"

i=0
cat regression.dat | while read line; do
	imm_data_en=`echo $line | awk '/^[0-9]/ {print $1}'`
	if test x$imm_data_en = x; then continue; fi
	initial_r2t_en=`echo $line | awk '/^[0-9]/ {print $2}'`
	first_burst=`echo $line | awk '/^[0-9]/ {print $3}'`
	max_burst=`echo $line | awk '/^[0-9]/ {print $4}'`
	max_recv_dlength=`echo $line | awk '/^[0-9]/ {print $5}'`
	max_r2t=`echo $line | awk '/^[0-9]/ {print $6}'`
	max_cnx=`echo $line | awk '/^[0-9]/ {print $7}'`
	write_cfg
	echo "================== TEST #$i BEGIN ===================="
	echo "imm_data_en = $imm_data_en"
	echo "initial_r2t_en = $initial_r2t_en"
	echo "first_burst = $first_burst"
	echo "max_burst = $max_burst"
	echo "max_recv_dlength = $max_recv_dlength"
	echo "max_r2t = $max_r2t"
	echo "max_cnx = $max_cnx"
	iscsiadm -f iscsi.conf -r1
	iscsiadm -f iscsi.conf -d 172.10.7.7:3260
	disktest
	let i=i+1
done
echo "===================== THE END ========================"
