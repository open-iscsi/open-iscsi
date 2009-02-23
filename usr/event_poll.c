/*
 * iSCSI daemon event handler 
 *
 * Copyright (C) 2004 Dmitry Yusupov, Alex Aizman
 * Copyright (C) 2006 Mike Christie
 * Copyright (C) 2006 Red Hat, Inc. All rights reserved.
 * maintained by open-iscsi@googlegroups.com
 *
 * Originally based on:
 * (C) 2004 FUJITA Tomonori <tomof@acm.org>
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
#include <stdlib.h>
#include <errno.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "mgmt_ipc.h"
#include "iscsi_ipc.h"
#include "sysfs.h"
#include "iscsid.h"
#include "log.h"
#include "iscsi_ipc.h"
#include "actor.h"
#include "initiator.h"

static int reap_count;

void need_reap(void)
{
	reap_count++;
}

static void reaper(void)
{
	int rc;

	/*
	 * We don't really need reap_count, but calling wait() all the
	 * time seems execessive.
	 */
	if (reap_count) {
		rc = waitpid(0, NULL, WNOHANG);
		if (rc > 0) {
			reap_count--;
			log_debug(6, "reaped pid %d, reap_count now %d",
				  rc, reap_count);
		}
	}
}

#define POLL_CTRL	0
#define POLL_IPC	1
#define POLL_ISNS	2
#define POLL_MAX	3

static int event_loop_stop;

void event_loop_exit(void)
{
	event_loop_stop = 1;
}

void event_loop(struct iscsi_ipc *ipc, int control_fd, int mgmt_ipc_fd,
		int isns_fd)
{
	struct pollfd poll_array[POLL_MAX];
	int res;

	poll_array[POLL_CTRL].fd = control_fd;
	poll_array[POLL_CTRL].events = POLLIN;
	poll_array[POLL_IPC].fd = mgmt_ipc_fd;
	poll_array[POLL_IPC].events = POLLIN;

	if (isns_fd < 0)
		poll_array[POLL_ISNS].fd = poll_array[POLL_ISNS].events = 0;
	else {
		poll_array[POLL_ISNS].fd = isns_fd;
		poll_array[POLL_ISNS].events = POLLIN;
	}

	event_loop_stop = 0;
	while (!event_loop_stop) {
		res = poll(poll_array, POLL_MAX, ACTOR_RESOLUTION);
		if (res > 0) {
			log_debug(6, "poll result %d", res);
			if (poll_array[POLL_CTRL].revents)
				ipc->ctldev_handle();

			if (poll_array[POLL_IPC].revents)
				mgmt_ipc_handle(mgmt_ipc_fd);

			if (poll_array[POLL_ISNS].revents)
				isns_handle(isns_fd);

		} else if (res < 0) {
			if (errno == EINTR) {
				log_debug(1, "event_loop interrupted");
			} else {
				log_error("got poll() error (%d), errno (%d), "
					  "exiting", res, errno);
				break;
			}
		} else
			actor_poll();
		reaper();
		/*
		 * flush sysfs cache since kernel objs may
		 * have changed as a result of handling op
		 */
		sysfs_cleanup();
	}
}
