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

#include <sys/types.h>
#include <sys/ioctl.h>

#include "initiator.h"
#include "idbm.h"

#define BHS_SIZE	48

typedef struct iscsi_pdu {
	struct iscsi_hdr bhs;
	void *ahs;
	unsigned int ahssize;
	void *data;
	unsigned int datasize;
} iscsi_pdu_t;

/* ctldev: Ioctl/IPC/NETLINK/etc */
extern int ctldev_open(void);
extern void ctldev_close(int fd);
extern int ctldev_handle(int fd);
extern int ctldev_writev(int fd, iscsi_uevent_e type, struct iovec *iov,
			int count);
extern int ctldev_read(int fd, char *data, int count);

/* iscsid.c: daemon config */
struct iscsi_daemon_config {
	char *config_file;
	char *pid_file;
	char *initiator_name_file;
	char *initiator_name;
	char *initiator_alias;
};
extern struct iscsi_daemon_config *dconfig;
extern int control_fd;

#endif	/* ISCSID_H */
