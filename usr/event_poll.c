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
#include <poll.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include "mgmt_ipc.h"
#include "iscsi_ipc.h"
#include "sysfs.h"
#include "iscsid.h"
#include "log.h"
#include "iscsi_ipc.h"
#include "actor.h"
#include "initiator.h"
#include "iscsi_err.h"

static unsigned int reap_count;

/* track pid of reload fork, while running */
static pid_t reload_pid = 0;
static void (*reload_callback)(void);

#define REAP_WAKEUP 1000 /* in millisecs */

void reap_inc(void)
{
	reap_count++;
}

/* track the reload process to be reaped, when done */
void reap_track_reload_process(pid_t reload_proc_pid, void (*reload_done_callback)(void))
{
	reload_pid = reload_proc_pid;
	reload_callback = reload_done_callback;
	reap_inc();
}

void reap_proc(void)
{
	int i, max_reaps;
	pid_t rc;

	/*
	 * We don't really need reap_count, but calling wait() all the
	 * time seems excessive.
	 */
	max_reaps = reap_count;
	for (i = 0; i < max_reaps; i++) {
		rc = waitpid(0, NULL, WNOHANG);
		if (rc > 0) {
			if (rc == reload_pid) {
				log_debug(6, "reaped reload process");
				reload_callback();
			}
			reap_count--;
			log_debug(6, "reaped pid %d, reap_count now %d",
				  (int)rc, reap_count);
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
	log_debug(1, "adding %d for shutdown cb", pid);
	list_add_tail(&cb->list, &shutdown_callbacks);
	return 0;
}

static void shutdown_notify_pids(void)
{
	struct shutdown_callback *cb;

	list_for_each_entry(cb, &shutdown_callbacks, list) {
		log_debug(1, "Killing %d", cb->pid);
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
			log_debug(1, "%d done", cb->pid);
			list_del(&cb->list);
			free(cb);
		}
	}

	return list_empty(&shutdown_callbacks);
}

#define POLL_CTRL	0
#define POLL_IPC	1
#define POLL_ALARM	2
#define POLL_MAX	3

static volatile int event_loop_stop;
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
	sigset_t sigset;
	int sig_fd;

	/* Mask off SIGALRM so we can recv it via signalfd */
	sigemptyset(&sigset);
	sigaddset(&sigset, SIGALRM);
	sigprocmask(SIG_SETMASK, &sigset, NULL);

	sig_fd = signalfd(-1, &sigset, SFD_NONBLOCK);
	if (sig_fd == -1) {
		log_error("signalfd failed: %m");
		return;
	}

	poll_array[POLL_CTRL].fd = control_fd;
	poll_array[POLL_CTRL].events = POLLIN;
	poll_array[POLL_IPC].fd = mgmt_ipc_fd;
	poll_array[POLL_IPC].events = POLLIN;
	poll_array[POLL_ALARM].fd = sig_fd;
	poll_array[POLL_ALARM].events = POLLIN;

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

		/* Runs actors and may set alarm for future actors */
		actor_poll();

		res = poll(poll_array, POLL_MAX, reap_count ? REAP_WAKEUP : -1);

		if (res > 0) {
			log_debug(6, "poll result %d", res);
			if (poll_array[POLL_CTRL].revents)
				ipc->ctldev_handle();

			if (poll_array[POLL_IPC].revents) {
				switch (ipc->auth_type) {
				case ISCSI_IPC_AUTH_UID:
					mgmt_ipc_handle_uid_only(mgmt_ipc_fd);
					break;
				default:
					mgmt_ipc_handle(mgmt_ipc_fd);
					break;
				}
			}

			if (poll_array[POLL_ALARM].revents) {
				struct signalfd_siginfo si;

				if (read(sig_fd, &si, sizeof(si)) == -1) {
					log_error("got sigfd read() error, errno (%d), "
						  "exiting", errno);
					break;
				} else {
					log_debug(1, "Poll was woken by an alarm");
				}
			}
		} else if (res < 0) {
			if (errno == EINTR) {
				log_debug(1, "event_loop interrupted");
			} else {
				log_error("got poll() error (%d), errno (%d), "
					  "exiting", res, errno);
				break;
			}
		}

		reap_proc();

		/*
		 * flush sysfs cache since kernel objs may
		 * have changed as a result of handling op
		 */
		sysfs_cleanup();
	}

	if (shutdown_qtask)
		mgmt_ipc_write_rsp(shutdown_qtask, ISCSI_SUCCESS);

	close(sig_fd);
	sigprocmask(SIG_UNBLOCK, &sigset, NULL);
}
