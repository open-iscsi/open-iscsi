/*
 * iSCSI Initiator Daemon
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

#ifndef ISCSID_H
#define ISCSID_H

/* IPC API */
extern struct iscsi_ipc *ipc;

/* iscsid.c: daemon config */
struct iscsi_daemon_config {
	char *config_file;
	char *pid_file;
	char *initiator_name;
	char *initiator_alias;
};
extern struct iscsi_daemon_config *dconfig;
extern int control_fd;

#endif	/* ISCSID_H */
