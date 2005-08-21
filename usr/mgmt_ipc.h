/*
 * iSCSI Daemon/Admin Management IPC
 *
 * Copyright (C) 2004 Dmitry Yusupov, Alex Aizman
 * maintained by open-iscsi@googlegroups.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * See the file COPYING included with this distribution for more details.
 */
#ifndef MGMT_IPC_H
#define MGMT_IPC_H

#include "types.h"

#define ISCSIADM_NAMESPACE	"ISCSIADM_ABSTRACT_NAMESPACE"

typedef enum mgmt_ipc_err {
	MGMT_IPC_OK			= 0,
	MGMT_IPC_ERR			= 1,
	MGMT_IPC_ERR_NOT_FOUND		= 2,
	MGMT_IPC_ERR_NOMEM		= 3,
	MGMT_IPC_ERR_TCP_FAILURE	= 4,
	MGMT_IPC_ERR_LOGIN_FAILURE	= 5,
	MGMT_IPC_ERR_IDBM_FAILURE	= 6,
	MGMT_IPC_ERR_INVAL		= 7,
	MGMT_IPC_ERR_TCP_TIMEOUT	= 8,
	MGMT_IPC_ERR_INTERNAL		= 9,
	MGMT_IPC_ERR_LOGOUT_FAILURE	= 10,
	MGMT_IPC_ERR_PDU_TIMEOUT	= 11,
	MGMT_IPC_ERR_TRANS_NOT_FOUND	= 12,
	MGMT_IPC_ERR_ACCESS		= 13,
	MGMT_IPC_ERR_TRANS_CAPS		= 14,
} mgmt_ipc_err_e;

typedef enum iscsiadm_cmd {
	MGMT_IPC_UNKNOWN		= 0,
	MGMT_IPC_SESSION_LOGIN		= 1,
	MGMT_IPC_SESSION_LOGOUT		= 2,
	MGMT_IPC_SESSION_ACTIVELIST	= 3,
	MGMT_IPC_SESSION_ACTIVESTAT	= 4,
	MGMT_IPC_CONN_ADD		= 5,
	MGMT_IPC_CONN_REMOVE		= 6,
	MGMT_IPC_SESSION_STATS		= 7,
	MGMT_IPC_CONFIG_INAME		= 8,
	MGMT_IPC_CONFIG_IALIAS		= 9,
	MGMT_IPC_CONFIG_FILE		= 10,
} iscsiadm_cmd_e;

/* IPC Request */
typedef struct iscsiadm_req {
	iscsiadm_cmd_e command;

	union {
		/* messages */
		struct msg_session {
			int rid;
			int sid;
		} session;
		struct msg_conn {
			int rid;
			int sid;
			int cid;
		} conn;
	} u;
} iscsiadm_req_t;

/* IPC Response */
typedef struct iscsiadm_rsp {
	iscsiadm_cmd_e command;
	mgmt_ipc_err_e err;

	union {
		struct msg_activelist {
#define MGMT_IPC_ACTIVELIST_MAX		64
			int sids[MGMT_IPC_ACTIVELIST_MAX];
			int rids[MGMT_IPC_ACTIVELIST_MAX];
			int cnt;
		} activelist;
#define MGMT_IPC_GETSTATS_BUF_MAX	(sizeof(struct iscsi_uevent) + \
					sizeof(struct iscsi_stats) + \
					sizeof(struct iscsi_stats_custom) * \
						ISCSI_STATS_CUSTOM_MAX)
		struct msg_getstats {
			struct iscsi_uevent ev;
			struct iscsi_stats stats;
			char custom[sizeof(struct iscsi_stats_custom) *
					ISCSI_STATS_CUSTOM_MAX];
		} getstats;
		struct msg_config {
			char var[VALUE_MAXLEN];
		} config;
	} u;
} iscsiadm_rsp_t;

int mgmt_ipc_handle(int accept_fd);
int mgmt_ipc_listen(void);
void mgmt_ipc_close(int fd);

#endif /* MGMT_IPC_H */
