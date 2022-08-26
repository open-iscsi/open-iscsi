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

#ifndef _LIB_OPEN_ISCSI_USR_NODE_H_
#define _LIB_OPEN_ISCSI_USR_NODE_H_

#include "libopeniscsiusr_common.h"

/**
 * iscsi_node_dump_config() - Dump all configurations of specified iSCSI
 * node.
 *
 * Dump all configurations of specified iSCSI node. Will skip empty
 * configuration.
 *
 * @node:
 *	Pointer of 'struct iscsi_node'.
 *	If this pointer is NULL, your program will be terminated by assert.
 * @show_secret:
 *	Whether show CHAP secret. If set as false, will show password as
 *	"********"
 *
 * Return:
 *	const char *.
 *	Need to free this memory by free().
 */
__DLL_EXPORT const char *iscsi_node_dump_config(struct iscsi_node *node,
						bool show_secret);

/**
 * iscsi_node_print_config() - Print all configurations of specified iSCSI
 * node to STDOUT.
 *
 * Print all configurations of specified iSCSI node.
 * For empty configuration, it will be shown as "name = <empty>".
 *
 * @node:
 *	Pointer of 'struct iscsi_node'.
 *	If this pointer is NULL, your program will be terminated by assert.
 * @show_secret:
 *	Whether show CHAP secret. If set as false, will show password as
 *	"********"
 *
 * Return:
 *	void
 */
__DLL_EXPORT void iscsi_node_print_config(struct iscsi_node *node,
					  bool show_secret);

/**
 * iscsi_node_target_name_get() - Retrieve target name of specified iSCSI node.
 *
 * Retrieve the target name of specified iSCSI node.
 * Examples: "iqn.2003-01.org.linux-iscsi.org:iscsi-targetcli"
 *
 * @node:
 *	Pointer of 'struct iscsi_node'.
 *	If this pointer is NULL, your program will be terminated by assert.
 *
 * Return:
 *	const char *.
 *	No need to free this memory, the resources will get freed by
 *	iscsi_node_free() or iscsi_nodes_free().
 */
__DLL_EXPORT const char *iscsi_node_target_name_get
	(struct iscsi_node *node);

/**
 * iscsi_node_conn_is_ipv6() - Check whether specified node is using ipv6
 * connection.
 *
 * Check whether specified node is using ipv6 connection.
 *
 * @node:
 *	Pointer of 'struct iscsi_node'.
 *	If this pointer is NULL, your program will be terminated by assert.
 *
 * Return:
 *	bool
 */
__DLL_EXPORT bool iscsi_node_conn_is_ipv6(struct iscsi_node *node);

/**
 * iscsi_node_conn_address_get() - Retrieve connection address of specified
 * iSCSI node.
 *
 * Retrieve the iscsi connection target address of specified iSCSI node.
 * Examples: "192.168.1.1"
 *
 * @node:
 *	Pointer of 'struct iscsi_node'.
 *	If this pointer is NULL, your program will be terminated by assert.
 *
 * Return:
 *	const char *.
 *	No need to free this memory, the resources will get freed by
 *	iscsi_node_free() or iscsi_nodes_free().
 */
__DLL_EXPORT const char *iscsi_node_conn_address_get(struct iscsi_node *node);

/**
 * iscsi_node_conn_port_get() - Retrieve connection port of specified iSCSI
 * node.
 *
 * Retrieve the iscsi connection target port of specified iSCSI node.
 * Examples: "3260"
 *
 * @node:
 *	Pointer of 'struct iscsi_node'.
 *	If this pointer is NULL, your program will be terminated by assert.
 *
 * Return:
 *	uint32_t
 */
__DLL_EXPORT uint32_t iscsi_node_conn_port_get(struct iscsi_node *node);

/**
 * iscsi_node_portal_get() - Retrieve connection portal of specified
 * iSCSI node.
 *
 * Retrieve the iscsi connection target portal of specified iSCSI node.
 * Just a combination of iscsi_node_conn_address_get() and
 * iscsi_node_conn_port_get().
 * Examples: "192.168.1.1:3260" and "[::1]:3260"
 *
 * @node:
 *	Pointer of 'struct iscsi_node'.
 *	If this pointer is NULL, your program will be terminated by assert.
 *
 * Return:
 *	const char *.
 *	No need to free this memory, the resources will get freed by
 *	iscsi_node_free() or iscsi_nodes_free().
 */
__DLL_EXPORT const char *iscsi_node_portal_get(struct iscsi_node *node);

/**
 * iscsi_node_tpgt_get() - Retrieve target portal group tag of specified
 * iSCSI node.
 *
 * Retrieve the target portal group tag of specified iSCSI node.
 *
 * @node:
 *	Pointer of 'struct iscsi_node'.
 *	If this pointer is NULL, your program will be terminated by assert.
 *
 * Return:
 *	int32_t. -1 for unknown.
 */
__DLL_EXPORT int32_t iscsi_node_tpgt_get(struct iscsi_node *node);

/**
 * iscsi_node_iface_name_get() - Retrieve interface name of specified iSCSI
 * node.
 *
 * Retrieve the interface name of specified iSCSI node.
 * Examples: "default" for iscsi tcp interface.
 *
 * @node:
 *	Pointer of 'struct iscsi_node'.
 *	If this pointer is NULL, your program will be terminated by assert.
 *
 * Return:
 *	const char *.
 *	No need to free this memory, the resources will get freed by
 *	iscsi_node_free() or iscsi_nodes_free().
 */
__DLL_EXPORT const char *iscsi_node_iface_name_get(struct iscsi_node *node);

#endif /* End of _LIB_OPEN_ISCSI_USR_NODE_H_ */
