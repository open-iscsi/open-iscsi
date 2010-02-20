/*
 * iSCSI Initiator discovery daemon
 *
 * Copyright (C) 2010 Mike Christie
 * Copyright (C) 2010 Red Hat, Inc. All rights reserved.

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
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "discovery.h"
#include "idbm.h"
#include "list.h"
#include "iscsi_proto.h"
#include "sysdeps.h"
#include "log.h"
#include "session_mgmt.h"
#include "iscsi_util.h"
#include "event_poll.h"
#include "iface.h"

#define DISC_ST_ADDR_CFG_STR "discovery.daemon.sendtargets.addresses"
#define DISC_ST_POLL_INVL "discovery.daemon.sendtargets.poll_interval"

#define DISC_DEF_POLL_INVL 30

typedef void (do_disc_and_login_fn)(char *addr, int port);

static int do_disc_to_addrs(char *disc_addrs,
			    do_disc_and_login_fn *do_disc_and_login)
{
	pid_t pid;
	int nr_procs = 0, portn;
	char *saveptr1, *saveptr2;
	char *ip_str, *addr, *port_str;

        addr = strtok_r(disc_addrs, " ", &saveptr1);
	if (!addr)
		return 0;

	do {
		ip_str = strtok_r(addr, ",", &saveptr2);
		if (!ip_str) {
			log_error("Invalid disc addr %s", addr);
			continue;
		}

		port_str = strtok_r(NULL, " ", &saveptr2);
		if (!port_str)
			portn = ISCSI_LISTEN_PORT;
		else
			portn = atoi(port_str);

		pid = fork();
		if (pid == 0) {
			do_disc_and_login(ip_str, portn);
			exit(0);
		} else if (pid < 0)
			log_error("Fork failed (err %d - %s). Will not be able "
				   "to perform discovery to %s.\n",
				   errno, strerror(errno), ip_str);
		else {
			log_debug(1, "iSCSI disc and login helper pid=%d", pid);
			nr_procs++;
		}


	} while ((addr = strtok_r(NULL, " ", &saveptr1)));

	return nr_procs;
}

static void discoveryd_start(char *addr_cfg_str, char *poll_cfg_str,
				   do_disc_and_login_fn *do_disc_and_login)
{
	char *disc_addrs, *disc_poll_param;
	int disc_poll_invl = DISC_DEF_POLL_INVL;
	pid_t pid;

	disc_addrs = cfg_get_string_param(CONFIG_FILE, addr_cfg_str);
	if (!disc_addrs)
		return;
	free(disc_addrs);

	pid = fork();
	if (pid == 0) {
		do {
			/* check for updates */
			disc_addrs = cfg_get_string_param(CONFIG_FILE,
							  addr_cfg_str);
			if (!disc_addrs)
				continue;

			disc_poll_param = cfg_get_string_param(CONFIG_FILE,
							       poll_cfg_str);
			if (disc_poll_param) {
				disc_poll_invl = atoi(disc_poll_param);
				free(disc_poll_param);
			}

			log_debug(1, "%s=%s poll interval %d", addr_cfg_str,
				  disc_addrs, disc_poll_invl);

			do_disc_to_addrs(disc_addrs, do_disc_and_login);
			free(disc_addrs);

			/*
			 * wait for the procs to complete, or we could
			 * end up flooding the targets with pdus.
			 */
			while ((pid = waitpid(0, NULL, 0)) > 0)
				log_debug(7, "disc cleaned up pid %d", pid);

		if (!disc_poll_invl)
				break;
		} while (!sleep(disc_poll_invl));

		log_debug(1, "disc process done");
		exit(0);
	} else if (pid < 0)
		log_error("Fork failed (err %d - %s). Will not be able "
			   "to perform discovery.\n",
			   errno, strerror(errno));
	else
		need_reap();

	log_debug(1, "iSCSI discovery daemon for %s pid=%d",
		  addr_cfg_str, pid);
}

/* SendTargets */
static void do_st_disc_and_login(char *disc_addr, int port)
{
	discovery_rec_t drec;
	struct list_head rec_list, setup_ifaces;
	int rc, nr_found;
	struct node_rec *rec, *tmp_rec;

	INIT_LIST_HEAD(&rec_list);
	INIT_LIST_HEAD(&setup_ifaces);

	idbm_sendtargets_defaults(&drec.u.sendtargets);
	strlcpy(drec.address, disc_addr, sizeof(drec.address));
	drec.port = port;

	/*
	 * The disc daemon will try agin in poll_interval secs
	 * so no need to retry here
	 */
	drec.u.sendtargets.reopen_max = 0;

	iface_link_ifaces(&setup_ifaces);
	/*
	 * disc code assumes this is not set and wants to use
	 * the userspace IO code.
	 */
	ipc = NULL;

	rc = idbm_bind_ifaces_to_nodes(discovery_sendtargets, &drec,
					&setup_ifaces, &rec_list);
	if (rc) {
		log_error("Could not perform SendTargets to %s.",
			   disc_addr);
		return;
	}

	list_for_each_entry_safe(rec, tmp_rec, &rec_list, list) {
		if (iscsi_check_for_running_session(rec)) {
			list_del(&rec->list);
			free(rec);
		}

		/* no need to retry since the disc daemon will retry */
		rec->session.initial_login_retry_max = 0;
	}

	iscsi_login_portals(NULL, &nr_found, &rec_list, iscsi_login_portal);
}

void discoveryd_start_st(void)
{
	discoveryd_start(DISC_ST_ADDR_CFG_STR, DISC_ST_POLL_INVL,
			       do_st_disc_and_login);
}
