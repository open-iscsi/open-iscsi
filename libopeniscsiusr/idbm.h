/*
 * Copyright (C) 2017-2018 Red Hat, Inc.
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

#ifndef _GNU_SOURCE
#define _GNU_SOURCE			/* For NI_MAXHOST */
#endif

#ifndef __ISCSI_OPEN_USR_IDBM_H__
#define __ISCSI_OPEN_USR_IDBM_H__

#include <stdio.h>
#include <stdbool.h>
#include <netdb.h>

#include "libopeniscsiusr/libopeniscsiusr_common.h"

#ifndef ISCSI_DB_ROOT
#define ISCSI_DB_ROOT "/etc/iscsi"
#endif

#define	IFACE_CONFIG_DIR	ISCSI_DB_ROOT"/ifaces"

#define AUTH_STR_MAX_LEN	256
#define BOOT_NAME_MAXLEN	256
#define IDBM_DUMP_SIZE		8192


struct __DLL_LOCAL idbm;

struct idbm {
	int		refs;
};

enum iscsi_auth_method {
	ISCSI_AUTH_METHOD_NONE,
	ISCSI_AUTH_METHOD_CHAP,
};

enum iscsi_chap_algs {
	ISCSI_AUTH_CHAP_ALG_MD5 = 5,
	ISCSI_AUTH_CHAP_ALG_SHA1 = 6,
	ISCSI_AUTH_CHAP_ALG_SHA256 = 7,
	ISCSI_AUTH_CHAP_ALG_SHA3_256 = 8,
	AUTH_CHAP_ALG_MAX_COUNT = 5,
};

enum iscsi_startup_type {
	ISCSI_STARTUP_MANUAL,
	ISCSI_STARTUP_AUTOMATIC,
	ISCSI_STARTUP_ONBOOT,
};

enum discovery_type {
	DISCOVERY_TYPE_SENDTARGETS,
	DISCOVERY_TYPE_ISNS,
	DISCOVERY_TYPE_OFFLOAD_SENDTARGETS,
	DISCOVERY_TYPE_SLP,
	DISCOVERY_TYPE_STATIC,
	DISCOVERY_TYPE_FW,
};

enum leading_login_type {
	LEADING_LOGIN_NO,
	LEADING_LOGIN_YES,
};

enum init_scan_type {
	INIT_SCAN_MANUAL,
	INIT_SCAN_AUTO,
};

enum digest_type {
	DIGEST_NEVER,
	DIGEST_ALWAYS,
	DIGEST_PREFER_ON,
	DIGEST_PREFER_OFF,
};

/* all authentication-related options should be added to this structure.
 * this structure is per-session, and can be configured
 * by TargetName but not Subnet.
 */
struct iscsi_auth_config {
	enum iscsi_auth_method			authmethod;
	char					username[AUTH_STR_MAX_LEN];
	unsigned char				password[AUTH_STR_MAX_LEN];
	uint32_t				password_length;
	char					username_in[AUTH_STR_MAX_LEN];
	unsigned char				password_in[AUTH_STR_MAX_LEN];
	uint32_t				password_in_length;
	unsigned int				chap_algs[AUTH_CHAP_ALG_MAX_COUNT];
};

/* all TCP options go in this structure.
 * this structure is per-portal, and can be configured
 * both by TargetName and Subnet.
 */
struct iscsi_tcp_config {
	int64_t					window_size;
	int64_t					type_of_service;
	/* ^ try to set IP TOS bits */
};

/* all per-session timeouts go in this structure.
 * this structure is per-session, and can be configured
 * by TargetName but not by Subnet.
 */
struct iscsi_session_tmo_cfg {
	int64_t					replacement_timeout;
};

/* all error handling timeouts go in this structure.
 * this structure is per-portal, and can be configured
 * both by TargetName and Subnet.
 */
struct iscsi_error_tmo_cfg {
	int64_t					abort_timeout;
	int64_t					host_reset_timeout;
	int64_t					lu_reset_timeout;
	int64_t					tgt_reset_timeout;
};

/* all per-connection timeouts go in this structure.
 * this structure is per-portal, and can be configured
 * both by TargetName and Subnet.
 */
struct iscsi_conn_tmo_cfg {
	int64_t					login_timeout;
	int64_t					logout_timeout;
	int64_t					auth_timeout;
	int64_t					active_timeout;
	int64_t					noop_out_interval;
	int64_t					noop_out_timeout;
};

struct iscsi_conn_op_cfg {
	int64_t					MaxRecvDataSegmentLength;
	int64_t					MaxXmitDataSegmentLength;
	enum digest_type			HeaderDigest;
	enum digest_type			DataDigest;
	bool					IFMarker;
	bool					OFMarker;
};

struct iscsi_conn {
	enum iscsi_startup_type			startup;
	char					address[NI_MAXHOST];
	int32_t					port;
	struct iscsi_tcp_config			tcp;
	struct iscsi_conn_tmo_cfg		tmo;
	struct iscsi_conn_op_cfg		op_cfg;
	bool					is_ipv6;
};

/* all iSCSI operational params go in this structure.
 * this structure is per-portal, and can be configured
 * both by TargetName and Subnet.
 */
struct iscsi_session_op_cfg {
	int64_t					DataPDUInOrder;
	int64_t					DataSequenceInOrder;
	int64_t					protocol;
	bool					InitialR2T;
	bool					ImmediateData;
	int64_t					FirstBurstLength;
	int64_t					MaxBurstLength;
	int64_t					DefaultTime2Wait;
	int64_t					DefaultTime2Retain;
	int64_t					MaxConnections;
	int64_t					MaxOutstandingR2T;
	int64_t					ERL;
	bool					FastAbort;
};

struct iscsi_session_idbm {
	uint32_t				initial_cmdsn;
	int64_t					reopen_max;
	int64_t					initial_login_retry_max;
	int64_t					xmit_thread_priority;
	uint16_t				cmds_max;
	uint16_t				queue_depth;
	int64_t					nr_sessions;
	enum init_scan_type			scan;
	struct iscsi_auth_config		auth;
	struct iscsi_session_tmo_cfg		tmo;
	struct iscsi_error_tmo_cfg		err_tmo;
	struct iscsi_session_op_cfg		op_cfg;
	struct iscsi_session			*se;
	uint32_t				sid;
	/*
	 * This is a flag passed to iscsid.  If set, multiple sessions are
	 * allowed to be initiated on this record
	 */
	unsigned char				multiple;
	char					boot_root[BOOT_NAME_MAXLEN];
	char					boot_nic[BOOT_NAME_MAXLEN];
	char					boot_target[BOOT_NAME_MAXLEN];

};

__DLL_LOCAL struct idbm *_idbm_new(void);
__DLL_LOCAL void _idbm_free(struct idbm *db);
__DLL_LOCAL int _idbm_lock(struct iscsi_context *ctx);
__DLL_LOCAL void _idbm_unlock(struct iscsi_context *ctx);
__DLL_LOCAL void _idbm_iface_print(struct iscsi_iface *iface, FILE *f);
__DLL_LOCAL int _idbm_iface_get(struct iscsi_context *ctx,
				const char *iface_name,
				struct iscsi_iface **iface);
__DLL_LOCAL int _idbm_node_get(struct iscsi_context *ctx,
				const char *target_name,
				const char *portal,
				const char *iface_name,
				struct iscsi_node **node);
__DLL_LOCAL void _idbm_node_print(struct iscsi_node *node, FILE *f,
				  bool show_secret);

#endif /* End of __ISCSI_OPEN_USR_IDBM_H__ */
