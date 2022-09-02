#!/bin/sh
#
# Copyright (C) Voltaire Ltd. 2006.  ALL RIGHTS RESERVED.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
# Author: Dan Bar Dov <danb@voltaire.com>

# iscsi_discovery:
#    * does a send-targets discovery to the given IP
#    * set the transport type to the preferred transport (or tcp is -t flag is not used)
#    * tries to login
#    * if succeeds,
#          o logout,
#          o mark record autmatic (unless -m flag is used)
#    * else
#          o reset transport type to TCP
#          o try to login
#          o if succeeded
#                + logout
#                + mark record automatic (unless -m flag is used)
#

usage()
{
	echo "Usage: $0 <IP> [-p <port>] [-d] [-t <tcp|iser> [-f]] [-m] [-l]"
	echo "Options:"
	echo  "-p		set the port number (default is 3260)."
	echo  "-d		print debugging information"
	echo  "-t		set transport (default is tcp)."
	echo  "-f		force specific transport -disable the fallback to tcp (default is fallback enabled)."
	echo  "			force the transport specified by the argument of the -t flag."
	echo  "-m		manual startup - will set manual startup (default is automatic startup)."
	echo  "-l		login to the new discovered nodes (default is false)."
	exit 1
}

dbg()
{
	$debug && echo "$@"
}

initialize()
{
	trap "exit" INT
	debug=false
	force=
	log_out="1"
	startup_manual=
	#set default transport to tcp
	transport=tcp
	#set default port to 3260
	port=3260;
}

parse_cmdline()
{
	[ $# -lt 1 ] && usage

	# check if the IP address is valid
	ip="$1"
	if echo "$ip" | awk -F'.' '$1 != "" && $1 <=255 && $2 != "" && $2 <= 255 && $3 != "" && $3 <= 255 && $4 != "" && $4 <= 255 {exit 1}'; then
		echo "$1 is not a vaild IP address!"
		exit 1
	fi
	shift
	while getopts "dfmlt:p:" options; do
	 case "$options" in
		d ) debug=true;;
		f ) force="1";;
		t ) transport=$OPTARG;;
		p ) port=$OPTARG;;
		m ) startup_manual="1";;
		l ) log_out=;;
		* ) usage;;
	 esac
	done
}

discover()
{
	# If open-iscsi is already logged in to the portal, exit
	if iscsiadm -m session | grep -qF "${ip}:${port}"; then
		echo "Please logout from all targets on ${ip}:${port} before trying to run discovery on that portal"
		exit 2
	fi

	connected=0
	discovered=0

	dbg "starting discovery to $ip"
	iscsiadm -m discovery --type sendtargets --portal "${ip}:${port}" | {
		discovered=
		while read -r portal target; do
			portal="${portal%,*}"
			select_transport
			discovered=1
		done

		if [ -n "${discovered}" ]; then
			echo "failed to discover targets at ${ip}"
			exit 2
		else
			echo "discovered ${discovered} targets at ${ip}"
		fi
	}
}

try_login()
{
	if [ -z "$startup_manual" ]; then
		iscsiadm -m node --targetname "${target}" --portal "${portal}" --op update -n node.conn[0].startup -v automatic
	fi
	iscsiadm -m node --targetname "${target}" --portal "${portal}" --login >/dev/null 2>&1
	ret=$?
	if [ ${ret} -eq 0 ]; then
		echo "Set target ${target} to automatic login over ${transport} to portal ${portal}"
		connected=$(( connected + 1 ))
		[ -n "$log_out" ] && iscsiadm -m node --targetname "${target}" --portal "${portal}" --logout
	else
		echo "Cannot login over ${transport} to portal ${portal}"
		iscsiadm -m node --targetname "${target}" --portal "${portal}" --op update -n node.conn[0].startup -v manual
	fi
	return ${ret}
}

set_transport()
{
	transport=$1
	case "$transport" in
	iser)
		# iSER does not use digest
		iscsiadm -m node --targetname "${target}" --portal "${portal}" \
			--op update -n node.conn[0].iscsi.HeaderDigest -v None
		iscsiadm -m node --targetname "${target}" --portal "${portal}" \
			--op update -n node.conn[0].iscsi.DataDigest -v None
		;;
	cxgb3i)
		# cxgb3i supports <= 16K packet (BHS + AHS + pdu payload + digests)
		iscsiadm -m node --targetname "${target}" --portal "${portal}" \
			--op update -n node.conn[0].iscsi.MaxRecvDataSegmentLength \
			-v 8192
		;;
	esac
	transport_name="$(iscsiadm  -m node -p "${portal}" -T "${target}" | awk '/transport_name/ {print $1}')"
	iscsiadm -m node --targetname "${target}" --portal "${portal}" \
			--op update -n "${transport_name}" -v "${transport}"
}

select_transport()
{
	set_transport "$transport"
	dbg "Testing $transport-login to target ${target} portal ${portal}"
	if ! try_login && [ -z "$force" ]; then
		set_transport tcp
		dbg "starting to test tcp-login to target ${target} portal ${portal}"
		try_login;
	fi
}

check_iscsid()
{
	# check if iscsid is running
	if ! pidof iscsid > /dev/null 2>&1; then
		echo "iscsid is not running"
		echo "Exiting..."
		exit 1
	fi
}

check_iscsid
initialize
parse_cmdline "$@"
discover
