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
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "initiator.h"
#include "log.h"
#include "mgmt_ipc.h"
#include "iscsi_util.h"
#include "config.h"
#include "iscsi_err.h"

static void iscsid_startup(void)
{
	char *startup_cmd;

	startup_cmd = cfg_get_string_param(CONFIG_FILE, "iscsid.startup");
	if (!startup_cmd) {
		log_error("iscsid is not running. Could not start it up "
			  "automatically using the startup command in the "
			  "/etc/iscsi/iscsid.conf iscsid.startup setting. "
			  "Please check that the file exists or that your "
			  "init scripts have started iscsid.");
		return;
	}

	if (system(startup_cmd) < 0)
		log_error("Could not execute '%s' (err %d)",
			  startup_cmd, errno);
}

#define MAXSLEEP 128

static int iscsid_connect(int *fd, int start_iscsid)
{
	int nsec;
	struct sockaddr_un addr;

	*fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (*fd < 0) {
		log_error("can not create IPC socket (%d)!", errno);
		return ISCSI_ERR_ISCSID_NOTCONN;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	memcpy((char *) &addr.sun_path + 1, ISCSIADM_NAMESPACE,
		strlen(ISCSIADM_NAMESPACE));
	/*
	 * Trying to connect with exponential backoff
	 */
	for (nsec = 1; nsec <= MAXSLEEP; nsec <<= 1) {
		if (connect(*fd, (struct sockaddr *) &addr, sizeof(addr)) == 0)
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
	log_error("can not connect to iSCSI daemon (%d)!", errno);
	return ISCSI_ERR_ISCSID_NOTCONN;
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

int iscsid_response(int fd, iscsiadm_cmd_e cmd, iscsiadm_rsp_t *rsp)
{
	int iscsi_err;
	int err;

	if ((err = recv(fd, rsp, sizeof(*rsp), MSG_WAITALL)) != sizeof(*rsp)) {
		log_error("got read error (%d/%d), daemon died?", err, errno);
		iscsi_err = ISCSI_ERR_ISCSID_COMM_ERR;
	} else
		iscsi_err = rsp->err;
	close(fd);

	if (!iscsi_err && cmd != rsp->command)
		iscsi_err = ISCSI_ERR_ISCSID_COMM_ERR;
	return iscsi_err;
}

int iscsid_exec_req(iscsiadm_req_t *req, iscsiadm_rsp_t *rsp,
				int start_iscsid)
{
	int fd;
	int err;

	err = iscsid_request(&fd, req, start_iscsid);
	if (err)
		return err;

	return iscsid_response(fd, req->command, rsp);
}

int iscsid_req_wait(iscsiadm_cmd_e cmd, int fd)
{
	iscsiadm_rsp_t rsp;

	memset(&rsp, 0, sizeof(iscsiadm_rsp_t));
	return iscsid_response(fd, cmd, &rsp);
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
