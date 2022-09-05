/*
 * Copyright (C) 2017 Red Hat, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Author: Gris Ge <fge@redhat.com>
 */

#ifndef _LIB_OPEN_ISCSI_USR_IFACE_H_
#define _LIB_OPEN_ISCSI_USR_IFACE_H_

#include <stdint.h>
#include <stdbool.h>

#include "libopeniscsiusr_common.h"

/**
 * iscsi_iface_ipaddress_get() - Retrieve IP address of specified
 * iSCSI interface
 *
 * Retrieve the IP address of specified iSCSI interface.
 *
 * @iface:
 *	Pointer of 'struct iscsi_iface'.
 *	If this pointer is NULL, your program will be terminated by assert.
 *
 * Return:
 *	const char *.
 *	No need to free this memory, the resources will get freed by
 *	iscsi_session_free() or iscsi_sessions_free().
 */
__DLL_EXPORT const char *iscsi_iface_ipaddress_get(struct iscsi_iface *iface);

/**
 * iscsi_iface_hwaddress_get() - Retrieve hardware address of specified
 * iSCSI interface
 *
 * Retrieve the hardware address of specified iSCSI interface.
 *
 * @iface:
 *	Pointer of 'struct iscsi_iface'.
 *	If this pointer is NULL, your program will be terminated by assert.
 *
 * Return:
 *	const char *.
 *	No need to free this memory, the resources will get freed by
 *	iscsi_session_free() or iscsi_sessions_free().
 */
__DLL_EXPORT const char *iscsi_iface_hwaddress_get(struct iscsi_iface *iface);

/**
 * iscsi_iface_netdev_get() - Retrieve network device name of specified
 * iSCSI interface
 *
 * Retrieve the network device name of specified iSCSI interface.
 *
 * @iface:
 *	Pointer of 'struct iscsi_iface'.
 *	If this pointer is NULL, your program will be terminated by assert.
 *
 * Return:
 *	const char *.
 *	No need to free this memory, the resources will get freed by
 *	iscsi_session_free() or iscsi_sessions_free().
 */
__DLL_EXPORT const char *iscsi_iface_netdev_get(struct iscsi_iface *iface);

/**
 * iscsi_iface_transport_name_get() - Retrieve transport name of specified
 * iSCSI interface
 *
 * Retrieve the transport name of specified iSCSI interface.
 * Examples:
 *
 *	* "tcp" (Software iSCSI over TCP/IP)
 *	* "iser" (Software iSCSI over infinniband
 *	* "qla4xxx" (Qlogic QLA4XXX HBAs)
 *	* "bnx2i" (Broadcom bnx iSCSI HBAs);
 *	* "cxgb3i" (Chelsio cxgb S3 iSCSI HBAs);
 *
 * @iface:
 *	Pointer of 'struct iscsi_iface'.
 *	If this pointer is NULL, your program will be terminated by assert.
 *
 * Return:
 *	const char *.
 *	No need to free this memory, the resources will get freed by
 *	iscsi_session_free() or iscsi_sessions_free().
 */
__DLL_EXPORT const char *iscsi_iface_transport_name_get
	(struct iscsi_iface *iface);

/**
 * iscsi_iface_iname_get() - Retrieve initiator name of specified
 * iSCSI interface
 *
 * Retrieve the initiator name of specified iSCSI interface.
 *
 * @iface:
 *	Pointer of 'struct iscsi_iface'.
 *	If this pointer is NULL, your program will be terminated by assert.
 *
 * Return:
 *	const char *.
 *	No need to free this memory, the resources will get freed by
 *	iscsi_session_free() or iscsi_sessions_free().
 */
__DLL_EXPORT const char *iscsi_iface_iname_get(struct iscsi_iface *iface);

/**
 * iscsi_iface_port_state_get() - Retrieve network port state of specified
 * iSCSI interface
 *
 * Retrieve the network port state of specified iSCSI interface.
 *
 * @iface:
 *	Pointer of 'struct iscsi_iface'.
 *	If this pointer is NULL, your program will be terminated by assert.
 *
 * Return:
 *	const char *. Possible values are :
 *
 *	* "LINK_UP"
 *
 *	* "LINK_DOWN"
 *
 *	* "unknown"
 *
 *	No need to free this memory, the resources will get freed by
 *	iscsi_session_free() or iscsi_sessions_free().
 */
__DLL_EXPORT const char *iscsi_iface_port_state_get(struct iscsi_iface *iface);

/**
 * iscsi_iface_port_speed_get() - Retrieve network port speed of specified
 * iSCSI interface
 *
 * Retrieve the network port speed of specified iSCSI interface.
 * Returned string format is '[0-9]+ [MGT]bps', example: '10 Mbps' or '10 Gbps'.
 *
 * @iface:
 *	Pointer of 'struct iscsi_iface'.
 *	If this pointer is NULL, your program will be terminated by assert.
 *
 * Return:
 *	const char *. Set to "unknown" if unknown.
 *	No need to free this memory, the resources will get freed by
 *	iscsi_session_free() or iscsi_sessions_free().
 */
__DLL_EXPORT const char *iscsi_iface_port_speed_get(struct iscsi_iface *iface);

/**
 * iscsi_iface_name_get() - Retrieve name of specified iSCSI interface
 *
 * Retrieve the name of specified iSCSI interface.
 *
 * @iface:
 *	Pointer of 'struct iscsi_iface'.
 *	If this pointer is NULL, your program will be terminated by assert.
 *
 * Return:
 *	const char *.
 *	No need to free this memory, the resources will get freed by
 *	iscsi_session_free() or iscsi_sessions_free().
 */
__DLL_EXPORT const char *iscsi_iface_name_get(struct iscsi_iface *iface);

/**
 * iscsi_iface_dump_config() - Dump all configurations of specified iSCSI
 * interface.
 *
 * Dump all configurations of specified iSCSI interface. Will skip empty
 * configuration so that output string could be saved directly to
 * /etc/iscsi/ifaces/<iface_name> file.
 *
 * @iface:
 *	Pointer of 'struct iscsi_iface'.
 *	If this pointer is NULL, your program will be terminated by assert.
 *
 * Return:
 *	const char *.
 *	Need to free this memory by free().
 */
__DLL_EXPORT const char *iscsi_iface_dump_config(struct iscsi_iface *iface);

/**
 * iscsi_iface_print_config() - Print all configurations of specified iSCSI
 * interface to STDOUT.
 *
 * Print all configurations of specified iSCSI interface.
 * For empty configuration, it will be shown as "name = <empty>".
 *
 * @iface:
 *	Pointer of 'struct iscsi_iface'.
 *	If this pointer is NULL, your program will be terminated by assert.
 *
 * Return:
 *	void
 */
__DLL_EXPORT void iscsi_iface_print_config(struct iscsi_iface *iface);

/**
 * iscsi_is_default_iface() - Whether specified iSCSI interface is default
 * interface.
 *
 * Check whether specified iSCSI interface is one of the default interfaces.
 * Currently, default interfaces are :
 *
 *   * Interface 'default' using 'iscsi_tcp' kernel module.
 *
 *   * Interface 'iser' is using 'ib_iser' kernel module.
 *
 * @iface:
 *	Pointer of 'struct iscsi_iface'.
 *
 * Return:
 *	bool.
 */
__DLL_EXPORT bool iscsi_is_default_iface(struct iscsi_iface *iface);

#endif /* End of _LIB_OPEN_ISCSI_USR_IFACE_H_ */
