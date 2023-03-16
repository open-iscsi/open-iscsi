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
#include "iscsi_if.h"
#include "config.h"

#define ISCSIADM_NAMESPACE	"ISCSIADM_ABSTRACT_NAMESPACE"
#define PEERUSER_MAX		64

typedef enum iscsiadm_cmd {
	MGMT_IPC_UNKNOWN		= 0,
	MGMT_IPC_SESSION_LOGIN		= 1,
	MGMT_IPC_SESSION_LOGOUT		= 2,
	MGMT_IPC_SESSION_ACTIVESTAT	= 4,
	MGMT_IPC_CONN_ADD		= 5,
	MGMT_IPC_CONN_REMOVE		= 6,
	MGMT_IPC_SESSION_STATS		= 7,
	MGMT_IPC_CONFIG_INAME		= 8,
	MGMT_IPC_CONFIG_IALIAS		= 9,
	MGMT_IPC_CONFIG_FILE		= 10,
	MGMT_IPC_IMMEDIATE_STOP		= 11,
	MGMT_IPC_SESSION_SYNC		= 12,
	MGMT_IPC_SESSION_INFO		= 13,
	MGMT_IPC_ISNS_DEV_ATTR_QUERY	= 14,
	MGMT_IPC_SEND_TARGETS		= 15,
	MGMT_IPC_NOTIFY_ADD_NODE	= 16,
	MGMT_IPC_NOTIFY_DEL_NODE	= 17,
	MGMT_IPC_NOTIFY_ADD_PORTAL	= 18,
	MGMT_IPC_NOTIFY_DEL_PORTAL	= 19,

	__MGMT_IPC_MAX_COMMAND
} iscsiadm_cmd_e;

/* IPC Request */
typedef struct iscsiadm_req {
	iscsiadm_cmd_e command;
	uint32_t payload_len;

	union {
		/* messages */
		struct ipc_msg_session {
			int sid;
			node_rec_t rec;
		} session;
		struct ipc_msg_conn {
			int sid;
			int cid;
		} conn;
		struct ipc_msg_send_targets {
			int host_no;
			int do_login;
			struct sockaddr_storage ss;
		} st;
		struct ipc_msg_set_host_param {
			int host_no;
			int param;
			/* TODO: make this variable len to support */
			char value[IFNAMSIZ + 1];

		} set_host_param;
	} u;
} iscsiadm_req_t;

/* IPC Response */
typedef struct iscsiadm_rsp {
	iscsiadm_cmd_e command;
	int err;	/* ISCSI_ERR value */

	union {
#define MGMT_IPC_GETSTATS_BUF_MAX	(sizeof(struct iscsi_uevent) + \
					sizeof(struct iscsi_stats) + \
					sizeof(struct iscsi_stats_custom) * \
						ISCSI_STATS_CUSTOM_MAX)
		struct ipc_msg_getstats {
			struct iscsi_uevent ev;
			struct iscsi_stats stats;
			char custom[sizeof(struct iscsi_stats_custom) *
					ISCSI_STATS_CUSTOM_MAX];
		} getstats;
		struct ipc_msg_config {
			char var[VALUE_MAXLEN];
		} config;
		struct ipc_msg_session_state {
			int session_state;
			int conn_state;
		} session_state;
	} u;
} iscsiadm_rsp_t;

struct queue_task;
typedef int mgmt_ipc_fn_t(struct queue_task *);

struct queue_task;
void mgmt_ipc_write_rsp(struct queue_task *qtask, int err);
int mgmt_ipc_listen(void);
int mgmt_ipc_systemd(void);
void mgmt_ipc_close(int fd);
void mgmt_ipc_handle(int accept_fd);
void mgmt_ipc_handle_legacy(int accept_fd);

#endif /* MGMT_IPC_H */
