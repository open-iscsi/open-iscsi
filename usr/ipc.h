/*
 * iSCSI Daemon/Admin IPC
 *
 * Copyright (C) 2004 Dmitry Yusupov, Alex Aizman
 * maintained by open-iscsi@@googlegroups.com
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
#ifndef IPC_H
#define IPC_H

#include "types.h"

#define ISCSIADM_NAMESPACE	"ISCSIADM_ABSTRACT_NAMESPACE"

typedef enum ipc_err {
	IPC_OK			= 0,
	IPC_ERR			= 1,
	IPC_ERR_NOT_FOUND	= 2,
	IPC_ERR_NOMEM		= 3,
	IPC_ERR_TCP_FAILURE	= 4,
	IPC_ERR_LOGIN_FAILURE	= 5,
	IPC_ERR_IDBM_FAILURE	= 6,
	IPC_ERR_INVAL		= 7,
	IPC_ERR_TCP_TIMEOUT	= 8,
	IPC_ERR_INTERNAL	= 9,
} ipc_err_e;

typedef enum iscsiadm_cmd {
	IPC_UNKNOWN		= 0,
	IPC_SESSION_LOGIN	= 1,
	IPC_SESSION_LOGOUT	= 2,
	IPC_CONN_ADD		= 3,
	IPC_CONN_REMOVE		= 4,
} iscsiadm_cmd_e;

/* IPC Request */
typedef struct iscsiadm_req {
	iscsiadm_cmd_e command;

	union {
		/* messages */
		struct msg_session {
			int rid;
		} session;
		struct msg_conn {
			int rid;
			int cid;
		} conn;
	} u;
} iscsiadm_req_t;

/* IPC Response */
typedef struct iscsiadm_rsp {
	ipc_err_e err;
} iscsiadm_rsp_t;

int ipc_handle(int accept_fd);
int ipc_listen(void);
void ipc_close(int fd);

#endif /* IPC_H */
