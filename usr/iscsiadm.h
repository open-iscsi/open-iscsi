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

#include "types.h"

/* ipc.c */
#define ISCSIADM_NAMESPACE	"ISCSIADM_ABSTRACT_NAMESPACE"
#define ISCSIADM_NAME_LEN	128

typedef enum iscsiadm_cmd {
	IPC_SESSION_ADD,
	IPC_SESSION_REMOVE,
	IPC_CONN_ADD,
	IPC_CONN_REMOVE,
} iscsiadm_cmd_e;

typedef struct msg_session_add {
	char name[ISCSIADM_NAME_LEN];
	char alias[ISCSIADM_NAME_LEN];
} msg_session_add_t;

typedef struct msg_session_rm {
	int sid;
} msg_session_rm_t;

typedef struct msg_conn_add {
        uint8_t ip_address[16];
        int port;
} msg_conn_add_t;

typedef struct msg_conn_rm {
	int sid;
	int cid;
} msg_conn_rm_t;

/* IPC Request */
typedef struct iscsiadm_req {
	iscsiadm_cmd_e command;

	union {
		/* messages */
		msg_session_add_t s_add;
		msg_session_rm_t s_rm;
		msg_conn_add_t c_add;
		msg_conn_rm_t c_rm;
	} u;
} iscsiadm_req_t;

/* IPC Response */
typedef struct iscsiadm_rsp {
	int err;
} iscsiadm_rsp_t;

int ipc_handle(int accept_fd);
int ipc_listen(void);
void ipc_close(int fd);

struct iscsi_discovery_process {
	struct iscsi_discovery_process *volatile prev;
	struct iscsi_discovery_process *volatile next;
	struct iscsi_config_entry *entry;
	pid_t pid;
	int order;
	int pipe_fd;
	int in_progress;
	int remove;		/* kill and remove this from the
				 * list at the next opportunity */
	int restart;		/* restart if the pid is 0 */
	unsigned short flag;	/* UNICAST or MULTICAST */
};

/* daemon config */
struct iscsi_daemon_config {
	char *config_file;
	char *pid_file;
	char *initiator_name_file;
	char *initiator_name;
	char *initiator_alias;
};

extern struct iscsi_daemon_config *dconfig;

#endif /* ISCSIADM_H */
