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
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include "iscsid.h"
#include "idbm.h"
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
__connect_timedout(void *data)
{
	queue_task_t *qtask = data;
	iscsi_conn_t *conn = qtask->conn;
	iscsi_session_t *session = conn->session;

	if (conn->state == STATE_WAIT_CONNECT) {
		queue_produce(session->queue, EV_CNX_TIMER, qtask, 0, 0);
		sched_schedule(&session->mainloop);
	}
}

static ipc_err_e
ipc_session_login(queue_task_t *qtask, int rid)
{
	idbm_t *db;
	node_rec_t rec;
	iscsi_session_t *session;
	iscsi_conn_t *conn;
	int rc;

	db = idbm_init(CONFIG_FILE);
	if (!db) {
		return IPC_ERR_IDBM_FAILURE;
	}

	if (idbm_node_read(db, rid, &rec)) {
		log_error("node record [%06x] not found!", rid);
		return IPC_ERR_NOT_FOUND;
	}

	idbm_terminate(db);

	session = session_create(&rec);
	if (session == NULL) {
		return IPC_ERR_LOGIN_FAILURE;
	}

	if (!rec.active_cnx) {
		session_destroy(session);
		return IPC_ERR_INVAL;
	}

	/* create leading connection */
	if (session_cnx_create(session, 0)) {
		session_destroy(session);
		return IPC_ERR_LOGIN_FAILURE;
	}
	conn = &session->cnx[0];
	qtask->conn = conn;

	rc = iscsi_tcp_connect(conn, 1);
	if (rc < 0 && errno != EINPROGRESS) {
		log_error("cannot make a connection to %s:%d (%d)",
			 inet_ntoa(conn->addr.sin_addr), conn->port, errno);
		session_cnx_destroy(session, 0);
		session_destroy(session);
		return IPC_ERR_TCP_FAILURE;
	}

	conn->state = STATE_WAIT_CONNECT;
	queue_produce(session->queue, EV_CNX_POLL, qtask, 0, 0);
	sched_schedule(&session->mainloop);
	sched_timer(&conn->connect_timer, conn->login_timeout*100,
		    __connect_timedout, qtask);
	return IPC_OK;
}

static ipc_err_e
ipc_session_logout(queue_task_t *qtask, int rid)
{
	return IPC_ERR;
}

static ipc_err_e
ipc_conn_add(queue_task_t *qtask, int rid, int cid)
{
	return IPC_ERR;
}

static ipc_err_e
ipc_conn_remove(queue_task_t *qtask, int rid, int cid)
{
	return IPC_ERR;
}

int
ipc_handle(int accept_fd)
{
	struct sockaddr addr;
	struct ucred cred;
	int fd, rc, len;
	iscsiadm_req_t req;
	iscsiadm_rsp_t rsp;
	queue_task_t *qtask;

	memset(&rsp, 0, sizeof(rsp));
	len = sizeof(addr);
	if ((fd = accept(accept_fd, (struct sockaddr *) &addr, &len)) < 0) {
		if (errno == EINTR)
			rc = -EINTR;
		else
			rc = -EIO;
		return rc;
	}

	len = sizeof(cred);
	if ((rc = getsockopt(fd, SOL_SOCKET, SO_PEERCRED,
					(void *)&cred, &len)) < 0) {
		rsp.err = IPC_ERR_TCP_FAILURE;
		goto err;
	}

	if (cred.uid || cred.gid) {
		rsp.err = IPC_ERR_TCP_FAILURE;
		rc = -EPERM;
		goto err;
	}

	rc = read(fd, &req, sizeof(req));
	if (rc != sizeof(req)) {
		if (rc >= 0)
			rc = -EIO;
		close(fd);
		return rc;
	}

	qtask = calloc(1, sizeof(queue_task_t));
	if (!qtask) {
		rsp.err = IPC_ERR_NOMEM;
		rc = -ENOMEM;
		goto err;
	}
	memcpy(&qtask->u.login.req, &req, sizeof(iscsiadm_req_t));
	qtask->u.login.ipc_fd = fd;

	switch(req.command) {
	case IPC_SESSION_LOGIN:
		rsp.err = ipc_session_login(qtask, req.u.session.rid);
		break;
	case IPC_SESSION_LOGOUT:
		rsp.err = ipc_session_logout(qtask, req.u.session.rid);
		break;
	case IPC_CONN_ADD:
		rsp.err = ipc_conn_add(qtask, req.u.conn.rid, req.u.conn.cid);
		break;
	case IPC_CONN_REMOVE:
		rsp.err = ipc_conn_remove(qtask,req.u.conn.rid,req.u.conn.cid);
		break;
	default:
		log_error("unknown request: %s(%d) %u",
			  __FUNCTION__, __LINE__, req.command);
		break;
	}

	if (rsp.err == IPC_OK)
		return 0;

err:
	rc = write(fd, &rsp, sizeof(rsp));
	if (rc != sizeof(rsp))
		if (rc >= 0)
			rc = -EIO;
	close(fd);
	return rc;
}
