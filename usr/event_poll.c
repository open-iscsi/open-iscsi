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

void reap_inc(void)
{
	reap_count++;
}

void reap_proc(void)
{
	int rc, i, max_reaps;

	/*
	 * We don't really need reap_count, but calling wait() all the
	 * time seems execessive.
	 */
	max_reaps = reap_count;
	for (i = 0; i < max_reaps; i++) {
		rc = waitpid(0, NULL, WNOHANG);
		if (rc > 0) {
			reap_count--;
			log_debug(6, "reaped pid %d, reap_count now %d",
				  rc, reap_count);
		}
	}
}

static LIST_HEAD(shutdown_callbacks);

struct shutdown_callback {
	struct list_head list;
	pid_t pid;
};

int shutdown_callback(pid_t pid)
{
	struct shutdown_callback *cb;

	cb = calloc(1, sizeof(*cb));
	if (!cb)
		return ENOMEM;

	INIT_LIST_HEAD(&cb->list);
	cb->pid = pid;
	log_debug(1, "adding %d for shutdown cb\n", pid);
	list_add_tail(&cb->list, &shutdown_callbacks);
	return 0;
}

static void shutdown_notify_pids(void)
{
	struct shutdown_callback *cb;

	list_for_each_entry(cb, &shutdown_callbacks, list) {
		log_debug(1, "Killing %d\n", cb->pid);
		kill(cb->pid, SIGTERM);
	}
}

static int shutdown_wait_pids(void)
{
	struct shutdown_callback *cb, *tmp;

	list_for_each_entry_safe(cb, tmp, &shutdown_callbacks, list) {
		/*
		 * the proc reaper could clean it up, so wait for any
		 * sign that it is gone.
		 */
		if (waitpid(cb->pid, NULL, WNOHANG)) {
			log_debug(1, "%d done\n", cb->pid);
			list_del(&cb->list);
			free(cb);
		}
	}

	return list_empty(&shutdown_callbacks);
}

#define POLL_CTRL	0
#define POLL_IPC	1
#define POLL_MAX	2

static int event_loop_stop;
static queue_task_t *shutdown_qtask; 


void event_loop_exit(queue_task_t *qtask)
{
	shutdown_qtask = qtask;
	event_loop_stop = 1;
}

void event_loop(struct iscsi_ipc *ipc, int control_fd, int mgmt_ipc_fd)
{
	struct pollfd poll_array[POLL_MAX];
	int res, has_shutdown_children = 0;

	poll_array[POLL_CTRL].fd = control_fd;
	poll_array[POLL_CTRL].events = POLLIN;
	poll_array[POLL_IPC].fd = mgmt_ipc_fd;
	poll_array[POLL_IPC].events = POLLIN;

	event_loop_stop = 0;
	while (1) {
		if (event_loop_stop) {
			if (!has_shutdown_children) {
				has_shutdown_children = 1;
				shutdown_notify_pids();
			}
			if (shutdown_wait_pids())
				break;
		}

		res = poll(poll_array, POLL_MAX, ACTOR_RESOLUTION);
		if (res > 0) {
			log_debug(6, "poll result %d", res);
			if (poll_array[POLL_CTRL].revents)
				ipc->ctldev_handle();

			if (poll_array[POLL_IPC].revents)
				mgmt_ipc_handle(mgmt_ipc_fd);
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
		reap_proc();
		/*
		 * flush sysfs cache since kernel objs may
		 * have changed as a result of handling op
		 */
		sysfs_cleanup();
	}
	if (shutdown_qtask)
		mgmt_ipc_write_rsp(shutdown_qtask, MGMT_IPC_OK);
}
