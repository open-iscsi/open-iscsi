/*
 * iSCSI Administrator Utility Socket Interface
 *
 * Copyright (C) 2004 Dmitry Yusupov, Alex Aizman
 * maintained by open-iscsi@@googlegroups.com
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
#include <errno.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include "iscsid.h"
#include "ipc.h"
#include "log.h"

int
ipc_listen(void)
{
	int fd, err;
	struct sockaddr_un addr;

	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0) {
		log_error("can not create IPC socket");
		return fd;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	memcpy((char *) &addr.sun_path + 1, ISCSIADM_NAMESPACE,
		strlen(ISCSIADM_NAMESPACE));

	if ((err = bind(fd, (struct sockaddr *) &addr, sizeof(addr))) < 0) {
		log_error("can not bind IPC socket");
		close(fd);
		return err;
	}

	if ((err = listen(fd, 32)) < 0) {
		log_error("can not listen IPC socket");
		close(fd);
		return err;
	}

	log_debug(1, "IPC socket is listening...");

	return fd;
}

void
ipc_close(int fd)
{
}

static void
__ipc_handle(iscsiadm_req_t *req, iscsiadm_rsp_t *rsp)
{
	log_debug(1, "got request, command %d", req->command);

	switch(req->command) {
	case IPC_SESSION_LOGIN:
		rsp->err = ipc_session_login(req->u.session.rid);
		break;
	case IPC_SESSION_LOGOUT:
		rsp->err = ipc_session_logout(req->u.session.rid);
		break;
	case IPC_CONN_ADD:
		rsp->err = ipc_conn_add(req->u.conn.rid, req->u.conn.cid);
		break;
	case IPC_CONN_REMOVE:
		rsp->err = ipc_conn_remove(req->u.conn.rid, req->u.conn.cid);
		break;
	default:
		log_error("unknown request: %s(%d) %u",
			  __FUNCTION__, __LINE__, req->command);
		break;
	}
}

int
ipc_handle(int accept_fd)
{
	struct sockaddr addr;
	struct ucred cred;
	int fd, err, len;
	iscsiadm_req_t req;
	iscsiadm_rsp_t rsp;

	memset(&rsp, 0, sizeof(rsp));
	len = sizeof(addr);
	if ((fd = accept(accept_fd, (struct sockaddr *) &addr, &len)) < 0) {
		if (errno == EINTR)
			err = -EINTR;
		else
			err = -EIO;

		goto out;
	}

	len = sizeof(cred);
	if ((err = getsockopt(fd, SOL_SOCKET, SO_PEERCRED,
					(void *)&cred, &len)) < 0) {
		rsp.err = -EPERM;
		goto send;
	}

	if (cred.uid || cred.gid) {
		rsp.err = -EPERM;
		goto send;
	}

	err = read(fd, &req, sizeof(req));
	if (err != sizeof(req)) {
		if (err >= 0)
			err = -EIO;
		goto out;
	}

	__ipc_handle(&req, &rsp);

send:
	err = write(fd, &rsp, sizeof(rsp));
	if (err != sizeof(rsp))
		if (err >= 0)
			err = -EIO;
out:
	if (fd > 0)
		close(fd);
	return err;
}
