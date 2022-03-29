/*
 * iscsid communication helpers
 *
 * Copyright (C) 2004 Dmitry Yusupov, Alex Aizman
 * Copyright (C) 2006 - 2010 Mike Christie
 * Copyright (C) 2006 - 2010 Red Hat, Inc. All rights reserved.
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
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/un.h>
#include <poll.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "initiator.h"
#include "log.h"
#include "mgmt_ipc.h"
#include "iscsi_util.h"
#include "config.h"
#include "iscsi_err.h"
#include "iscsid_req.h"
#include "uip_mgmt_ipc.h"

static void iscsid_startup(void)
{
	char *startup_cmd;

	startup_cmd = cfg_get_string_param(CONFIG_FILE, "iscsid.startup");
	if (!startup_cmd) {
		log_error("iscsid is not running. Could not start it up "
			  "automatically using the startup command in the "
			  "iscsid.conf iscsid.startup setting. "
			  "Please check that the file exists or that your "
			  "init scripts have started iscsid.");
		return;
	}

	if (system(startup_cmd) < 0)
		log_error("Could not execute '%s' (err %d)",
			  startup_cmd, errno);

	free(startup_cmd);
}

#define MAXSLEEP 128

static int ipc_connect(int *fd, char *unix_sock_name, int start_iscsid)
{
	int nsec, addr_len;
	struct sockaddr_un addr;

	*fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (*fd < 0) {
		log_error("can not create IPC socket (%d)!", errno);
		return ISCSI_ERR_ISCSID_NOTCONN;
	}

	addr_len = setup_abstract_addr(&addr, unix_sock_name);

	/*
	 * Trying to connect with exponential backoff
	 */
	for (nsec = 1; nsec <= MAXSLEEP; nsec <<= 1) {
		if (connect(*fd, (struct sockaddr *) &addr, addr_len) == 0)
			/* Connection established */
			return ISCSI_SUCCESS;

		/* If iscsid isn't there, there's no sense
		 * in retrying. */
		if (errno == ECONNREFUSED) {
			if (start_iscsid && nsec == 1)
				iscsid_startup();
			else
				break;
		}

		/*
		 * Delay before trying again
		 */
		if (nsec <= MAXSLEEP/2)
			sleep(nsec);
	}
	close(*fd);
	*fd = -1;
	log_error("can not connect to iSCSI daemon (%d)!", errno);
	return ISCSI_ERR_ISCSID_NOTCONN;
}

char iscsid_namespace[64] = ISCSIADM_NAMESPACE;

void iscsid_set_namespace(pid_t pid) {
	if (pid) {
		snprintf(iscsid_namespace, 64, ISCSIADM_NAMESPACE "-%d", pid);
	} else {
		snprintf(iscsid_namespace, 64, ISCSIADM_NAMESPACE);
	}
}

static int iscsid_connect(int *fd, int start_iscsid)
{
	return ipc_connect(fd, iscsid_namespace, start_iscsid);
}

int iscsid_request(int *fd, iscsiadm_req_t *req, int start_iscsid)
{
	int err;

	err = iscsid_connect(fd, start_iscsid);
	if (err)
		return err;

	if ((err = write(*fd, req, sizeof(*req))) != sizeof(*req)) {
		log_error("got write error (%d/%d) on cmd %d, daemon died?",
			err, errno, req->command);
		close(*fd);
		return ISCSI_ERR_ISCSID_COMM_ERR;
	}
	return ISCSI_SUCCESS;
}

int iscsid_response(int fd, iscsiadm_cmd_e cmd, iscsiadm_rsp_t *rsp,
		    int timeout)
{
	size_t len = sizeof(*rsp);
	int iscsi_err = ISCSI_ERR_ISCSID_COMM_ERR;
	int err;

	while (len) {
		struct pollfd pfd;

		pfd.fd = fd;
		pfd.events = POLLIN;
		err = poll(&pfd, 1, timeout);
		if (!err) {
			return ISCSI_ERR_REQ_TIMEDOUT;
		} else if (err < 0) {
			if (errno == EINTR)
				continue;
			log_error("got poll error (%d/%d), daemon died?",
				  err, errno);
			return ISCSI_ERR_ISCSID_COMM_ERR;
		} else if (pfd.revents & POLLIN) {
			err = recv(fd, rsp, sizeof(*rsp), MSG_WAITALL);
			if (err <= 0) {
				log_error("read error (%d/%d), daemon died?",
					  err, errno);
				break;
			}
			len -= err;
			iscsi_err = rsp->err;
		}
	}
	close(fd);

	if (!iscsi_err && cmd != rsp->command)
		iscsi_err = ISCSI_ERR_ISCSID_COMM_ERR;
	return iscsi_err;
}

int iscsid_exec_req(iscsiadm_req_t *req, iscsiadm_rsp_t *rsp,
		    int start_iscsid, int tmo)
{
	int fd;
	int err;

	err = iscsid_request(&fd, req, start_iscsid);
	if (err)
		return err;

	return iscsid_response(fd, req->command, rsp, tmo);
}

int iscsid_req_wait(iscsiadm_cmd_e cmd, int fd)
{
	iscsiadm_rsp_t rsp;

	memset(&rsp, 0, sizeof(iscsiadm_rsp_t));
	return iscsid_response(fd, cmd, &rsp, -1);
}

int iscsid_req_by_rec_async(iscsiadm_cmd_e cmd, node_rec_t *rec, int *fd)
{
	iscsiadm_req_t req;

	memset(&req, 0, sizeof(iscsiadm_req_t));
	req.command = cmd;
	memcpy(&req.u.session.rec, rec, sizeof(node_rec_t));

	return iscsid_request(fd, &req, 1);
}

int iscsid_req_by_rec(iscsiadm_cmd_e cmd, node_rec_t *rec)
{
	int err, fd;

	err = iscsid_req_by_rec_async(cmd, rec, &fd);
	if (err)
		return err;
	return iscsid_req_wait(cmd, fd);
}

int iscsid_req_by_sid_async(iscsiadm_cmd_e cmd, int sid, int *fd)
{
	iscsiadm_req_t req;

	memset(&req, 0, sizeof(iscsiadm_req_t));
	req.command = cmd;
	req.u.session.sid = sid;

	return iscsid_request(fd, &req, 1);
}

int iscsid_req_by_sid(iscsiadm_cmd_e cmd, int sid)
{
	int err, fd;

	err = iscsid_req_by_sid_async(cmd, sid, &fd);
	if (err)
		return err;
	return iscsid_req_wait(cmd, fd);
}

static int uip_connect(int *fd)
{
	return ipc_connect(fd, ISCSID_UIP_NAMESPACE, 0);
}

int uip_broadcast(void *buf, size_t buf_len, int fd_flags, uint32_t *status)
{
	int err;
	int fd;
	iscsid_uip_rsp_t rsp;
	int flags;
	int count;
	size_t write_res;
	
	err = uip_connect(&fd);
	if (err) {
		log_warning("uIP daemon is not up");
		return err;
	}

	log_debug(3, "connected to uIP daemon");

	/*  Send the data to uIP */
	write_res = write(fd, buf, buf_len);
	if (write_res != buf_len) {
		log_error("got write error (%d/%d), daemon died?",
			  (int)write_res, errno);
		close(fd);
		return ISCSI_ERR_ISCSID_COMM_ERR;
	}

	log_debug(3, "send iface config to uIP daemon");

	/*  Set the socket to a non-blocking read, this way if there are
	 *  problems waiting for uIP, iscsid can bailout early */
	flags = fcntl(fd, F_GETFL, 0);
	if (flags == -1)
		flags = 0;

	if (fd_flags)
		flags |= fd_flags;

	err = fcntl(fd, F_SETFL, flags);
	if (err) {
		log_error("could not set uip broadcast to non-blocking: %d",
			  errno);
		close(fd);
		return ISCSI_ERR;
	}

#define MAX_UIP_BROADCAST_READ_TRIES 5
	for (count = 0; count < MAX_UIP_BROADCAST_READ_TRIES; count++) {
		/*  Wait for the response */
		err = read(fd, &rsp, sizeof(rsp));
		if (err == sizeof(rsp)) {
			log_debug(3, "Broadcasted to uIP with length: %zu cmd: 0x%x rsp: 0x%x",
				  buf_len, rsp.command, rsp.err);
			err = 0;
			break;
		} else if ((err == -1) && (errno == EAGAIN)) {
			usleep(1000000);
			continue;
		} else {
			log_error("Could not read response (%d/%d), daemon "
				  "died?", err, errno);
			err = ISCSI_ERR;
			break;
		}
	}

	if (count == MAX_UIP_BROADCAST_READ_TRIES) {
		log_error("Could not broadcast to uIP after %d tries",
			  count);
		err = ISCSI_ERR_AGAIN;
	}

	if (err)
		goto done;

	switch (rsp.command) {
	case ISCSID_UIP_IPC_GET_IFACE:
		if (rsp.err != ISCSID_UIP_MGMT_IPC_DEVICE_UP) {
			log_debug(3, "Device is not ready\n");
			err = ISCSI_ERR_AGAIN;
		}

		break;
	case ISCSID_UIP_IPC_PING:
		*status = rsp.ping_sc;
		if (rsp.err == ISCSID_UIP_MGMT_IPC_DEVICE_INITIALIZING) {
			log_debug(3, "Device is not ready\n");
			err = ISCSI_ERR_AGAIN;
		} else if (*status) {
			err = ISCSI_ERR;
		}

		break;
	default:
		err = ISCSI_ERR;
	}

done:
	close(fd);
	return err;
}
