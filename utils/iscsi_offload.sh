#!/bin/sh
#
# iscsi_offload
#
# Configure iSCSI offload engines for use with open-iscsi
# Usage:
#    iscsi_offload [-d | -f | -i <ipaddr> | -t ] <nic>
#
# Copyright (c) 2011 Hannes Reinecke, SUSE Labs
# This script is licensed under the GPL.
#
# The script creates an open-iscsi interface definition
# in the style <nic>-<module>, where <nic> matches the
# network interface passed on the commandline.
# If '-t' (test mode) is passed as an option, the script
# will not create nor modify any setting but just print
# the currently active ones.
#
# Currently the script works with Broadcom (bnx2i) and
# Chelsio T3 (cxgbi) iSCSI offload engines.
# Should work with Chelsio T4, but has not been tested.
# ServerEngines (be2iscsi) and QLogic (qla4xxx) can only
# be configured via BIOS, open-iscsi support is still in
# development.
#

#
# Return codes:
#    0: Success
#    1: Invalid command line parameter
#    2: iSCSI offloading not supported
#    3: Error during module loading
#    4: Cannot configure interface via iscsiadm, use BIOS setup
#    5: internal error running iscsiadm
#
# Output:
#    <mac> [none|dhcp|ip <ipaddr>|ibft]
# where
#    <mac>: MAC Address of the iSCSI offload engine
#    none:  No IP configuration set for the iSCSI offload engine
#    dhcp:  iSCSI offload engine configured for DHCP
#    ip:    iSCSI offload engine configured with static IP address <ipaddr>
#    ibft:  iSCSI offload engine configured from iBFT values
#

#
# Figure out the MAC address of the iSCSI offload engine
# corresponding to a NIC from a given PCI device.
# bnx2 is using one PCI device per port for both network and iSCSI offloading
# cxgb3 is using one PCI device for everything.
#
iscsi_macaddress_from_pcidevice()
{
    path=$1
    if=$2

    for h in "$path"/host*; do
	[ -d "$h" ] || continue
	host=${h##*/}
	read -r netdev < "/sys/class/iscsi_host/$host/netdev"
	if [ "$netdev" = "$IFNAME" ] ; then
	    read -r mac < "/sys/class/iscsi_host/$host/hwaddress"
	    [ "$mac" != "00:00:00:00:00:00" ] && echo "$mac"
	    break;
	fi
    done
}

#
# Figure out the MAC address of the iSCSI offload engine
# corresponding to a NIC from a given PCI function.
# It is assumed that the MAC address of the iSCSI offload
# engine is equal of the MAC address of the NIC plus one.
# Suitable for be2iscsi and qla4xxx
#
iscsi_macaddress_from_pcifn()
{
    if=$1
    olemacoffset=$2

    ifmac=$(ip addr show dev "$if" | sed -n 's/ *link\/ether \(.*\) brd.*/\1/p')
    m5=$(( 0x${ifmac##*:} ))
    m5=$(( m5 + olemacoffset ))
    ifmac=$(printf "%s:%02x" "${ifmac%:*}" "$m5")
    for host in /sys/class/iscsi_host/host* ; do
	[ -L "$host" ] || continue
	read -r mac < "$host/hwaddress"
	if [ "$mac" = "$ifmac" ] ; then
	    echo "$mac"
	    break;
	fi
    done
}

update_iface_setting() {
    iface="$1"
    name="$2"
    value="$3"

    iface_value=$(iscsiadm -m iface -I "$iface" | sed -n "s/$name = //p")
    [ "$iface_value" = "<empty>" ] && iface_value=

    if [ "$iface_value" != "$value" ] ; then
	if ! iscsiadm -m iface -I "$iface" -o update -n "$name" -v "$value" ; then
	    return 1
	fi
    fi
    return 0
}

while getopts di:t options ; do
    case $options in
	d ) mode=dhcp;;
	i ) mode=static
	    optaddr=$OPTARG
	    ;;
	t ) dry_run=1;;
	? ) echo "Usage: $0 [-d|-t|-i ipaddr|-f] ifname"
	    exit 1;;
    esac
done
shift $(( OPTIND - 1 ))

IFNAME=$1
ibft_mode="none"

if [ -z "$IFNAME" ] ; then
    echo "No interface specified"
    exit 1
fi

if [ -n "$dry_run" ] ; then
    case "$mode" in
	dhcp|static)
	    echo "-t specified, ignoring -ds"
	    ;;
    esac
    mode=
fi

if ! [ -L "/sys/class/net/$IFNAME" ] ; then
    echo "Interface $IFNAME not found"
    exit 1
fi

if [ -n "$optaddr" ] && ! ip route get "$optaddr" ; then
    echo "Invalid IP address $optaddr"
    exit 1
fi


pcipath="/sys/class/net/$IFNAME/device"
if [ -d "$pcipath" ] ; then
    drvlink=$(cd -P "$pcipath/driver" && pwd)
    driver=${drvlink##*/}
fi

if [ -z "$driver" ] ; then
    echo "No driver found for interface $IFNAME"
    exit 1
fi

case "$driver" in
    bnx2*)
	mod=bnx2i
	;;
    cxgb*)
	mod=cxgb3i
	;;
    be2*)
	mod=be2iscsi
	;;
    qla*)
	mod=qla4xxx
	;;
    qed*)
	mod=qedi
	;;
esac

if [ -z "$mod" ] ; then
    echo "iSCSI offloading not supported on interface $IFNAME"
    exit 2
fi

# Check if the required modules are already loaded
grep -q "^$mod" /proc/modules || modprobe "$mod"
if ! grep -q "^$mod" /proc/modules ; then
    echo "Loading of $mod.ko failed, please check dmesg"
    exit 3
fi

# Get the correct MAC address for the various devices
case "$mod" in
    bnx2i)     mac=$(iscsi_macaddress_from_pcidevice "$pcipath" "$IFNAME") ;;
    cxgb3i)    mac=$(iscsi_macaddress_from_pcidevice "$pcipath" "$IFNAME") ;;
    be2iscsi)  mac=$(iscsi_macaddress_from_pcifn                "$IFNAME" 1) ;;
    qla4xxx)   mac=$(iscsi_macaddress_from_pcifn                "$IFNAME" 1) ;;
    qede|qedi) mac=$(iscsi_macaddress_from_pcifn                "$IFNAME" 4) ;;
esac

if [ -z "$mac" ] ; then
    echo "iSCSI offloading not supported on interface $IFNAME"
    exit 2
fi

gen_iface="$mod.$mac"
ioe_iface="${IFNAME}-${mod}"

# Get existing settings
if iscsiadm -m iface -I "$ioe_iface" > /dev/null 2>&1 ; then
    ioe_mac=$(iscsiadm -m iface -I "$ioe_iface" 2> /dev/null | sed -n 's/iface\.hwaddress = //p')
    ioe_mod=$(iscsiadm -m iface -I "$ioe_iface" 2> /dev/null | sed -n 's/iface\.transport_name = //p')
    ipaddr=$( iscsiadm -m iface -I "$ioe_iface" 2> /dev/null | sed -n 's/iface\.ipaddress = //p')
    [ "$ipaddr" = "<empty>" ] && ipaddr=
elif [ "$mod" = "be2iscsi" ] ; then
    ioe_mac=$mac
    ioe_mod=$mod
else
    # Create new interface
    iscsiadm -m iface -I "$ioe_iface" --op=new 2> /dev/null
    ioe_mac=
    ioe_mod=
    ipaddr=
fi

if [ -z "$dry_run" ] ; then
    if [ "$ioe_mac" != "$mac" ] ; then
	if [ -n "$ioe_mac" ] ; then
	    echo "Warning: Updating MAC address on iface $ioe_iface"
	fi
	update_iface_setting "$ioe_iface" iface.hwaddress "$mac"
    fi

    if [ "$ioe_mod" != "$mod" ] ; then
	if [ -n "$ioe_mod" ] ; then
	    echo "Warning: Update transport on iface $ioe_iface"
	fi
	update_iface_setting "$ioe_iface" iface.transport_name "$mod"
    fi
elif [ -z "$ipaddr" ] ; then
    ipaddr=$(iscsiadm -m iface -I "$gen_iface" 2> /dev/null | sed -n "s/iface\.ipaddress = //p")
    if [ "$ipaddr" = "<empty>" ] ; then
	ipaddr=
    fi
elif [ "$ioe_mod" != "$mod" ] ; then
    echo "Warning: Transport mismatch on iface $ioe_iface: $ioe_mod should be $mod"
fi

# Check iBFT setting
for d in /sys/firmware/* ; do
    [ -d "$d/ethernet0" ] || continue
    iboot_dir=$d
done
if [ -n "$iboot_dir" ] ; then
    for if in "${iboot_dir}"/ethernet* ; do
	read -r ibft_mac < "$if/mac"
	[ "$ibft_mac" = "$mac" ] || continue
	ibft_origin=0
	[ -f "${if}/origin" ] && read -r ibft_origin < "$if/origin"
	case "$ibft_origin" in
	    1 ) ibft_mode="static" ;;
	    3 ) ibft_mode="dhcp" ;;
	esac
	[ -f "$if/dhcp" ] && read -r ibft_dhcp < "$if/dhcp"
	[ -n "$ibft_dhcp" ] && [ "$ibft_mode" != "dhcp" ] && ibft_mode=dhcp
	if [ "$ibft_mode" = "dhcp" ] ; then
	    ibft_ipaddr="0.0.0.0"
	    ibft_gateway=
	    ibft_mask=
	else
	    [ -f "$if/ip-addr"     ] && read -r ibft_ipaddr  < "$if/ip-addr"
	    [ -f "$if/gateway"     ] && read -r ibft_gateway < "$if/gateway"
	    [ -f "$if/subnet-mask" ] && read -r ibft_mask    < "$if/subnet-mask"
	fi
	break
    done
fi

[ -z "$optaddr" ] && [ -n "$ibft_ipaddr" ] && optaddr=$ibft_ipaddr

# Check if the interface needs to be configured
if [ -z "$mode" ] ; then
    if [ "$ibft_mode" != "none" ] ; then
	echo "$mac ibft"
	mode="ibft"
    elif [ -z "$ipaddr" ] ; then
	echo "$mac none"
	mode="none"
    elif [ "$ipaddr" = "0.0.0.0" ] ; then
	echo "$mac dhcp"
	ipaddr=
	mode="dhcp"
    else
	echo "$mac ip $ipaddr"
	mode="static"
    fi
    [ -n "$dry_run" ] && exit 0
elif [ "$mode" = "dhcp" ] ; then
    if [ "$ipaddr" = "0.0.0.0" ] ; then
	echo "$mac dhcp"
	exit 0
    fi
    optaddr="0.0.0.0"
elif [ "$mode" = "static" ] && [ "$ipaddr" = "$optaddr" ] ; then
    echo "$mac ip $ipaddr"
    exit 0
fi

if [ "$mod" = "be2iscsi" ] ; then
    exit 4
fi

if ! update_iface_setting "$ioe_iface" iface.ipaddress "$optaddr" ; then
    echo "Failed to set IP address: $?"
    exit 1
fi
if ! update_iface_setting "$gen_iface" iface.ipaddress "$optaddr" ; then
    echo "Failed to set IP address for generic interface: $?"
    exit 1
fi

if ! update_iface_setting "$ioe_iface" iface.gateway "$ibft_gateway" ; then
    echo "Failed to set gateway address: $?"
    exit 1
fi

if ! update_iface_setting "$gen_iface" iface.gateway "$ibft_gateway" ; then
    echo "Failed to set gateway address for generic interface: $?"
    exit 1
fi

if ! update_iface_setting "$ioe_iface" iface.subnet_mask "$ibft_mask" ; then
    echo "Failed to set subnet mask: $?"
    exit 1
fi

if ! update_iface_setting "$gen_iface" iface.subnet_mask "$ibft_mask" ; then
    echo "Failed to set subnet mask for generic interface: $?"
    exit 1
fi

[ "$mod" = "qla4xxx" ] && iscsiadm -m iface -H "$mac" -o applyall

ip link set dev "$IFNAME" up

exit 0
