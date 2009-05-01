/*
 * iSCSI event poll/loop 
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
#ifndef EVENT_POLL_H
#define EVENT_POLL_H

struct iscsi_ipc;

void need_reap(void);
void event_loop(struct iscsi_ipc *ipc, int control_fd, int mgmt_ipc_fd,
		int isns_fd);
void event_loop_exit(void);

#endif
