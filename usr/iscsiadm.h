/*
 * iSCSI Administration Utility
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
#ifndef ISCSIADM_H
#define ISCSIADM_H

/* ipc.c */
#define ISCSIADM_NAMESPACE	"ISCSIADM_ABSTRACT_NAMESPACE"
#define ISCSIADM_NAME_LEN	128

typedef enum iscsiadm_cmd {
	C_SESSION_ADD,
	C_SESSION_REMOVE,
} iscsiadm_cmd_e;

/* IPC Request */
typedef struct iscsiadm_req {
	iscsiadm_cmd_e command;

	union {
		/* messages */
	} u;
} iscsiadm_req_t;

/* IPC Response */
typedef struct iscsiadm_rsp {
	int err;
} iscsiadm_rsp_t;

int ipc_handle(int accept_fd);
int ipc_listen(void);
void ipc_close(int fd);

#endif /* ISCSIADM_H */
