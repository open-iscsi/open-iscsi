/*
 * iSCSI Administrator Utility Socket Interface
 *
 * Copyright (C) 2004 Dmitry Yusupov, Alex Aizman
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
#include <errno.h>
#include <unistd.h>

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <pwd.h>

#include "iscsid.h"
#include "idbm.h"
#include "mgmt_ipc.h"
#include "iscsi_ipc.h"
#include "log.h"

#define PEERUSER_MAX	64

int
mgmt_ipc_listen(void)
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
mgmt_ipc_close(int fd)
{
}

static mgmt_ipc_err_e
mgmt_ipc_node_read(int rid, node_rec_t *rec)
{
	idbm_t *db;

	db = idbm_init(CONFIG_FILE);
	if (!db) {
		return MGMT_IPC_ERR_IDBM_FAILURE;
	}

	if (idbm_node_read(db, rid, rec)) {
		log_error("node record [%06x] not found!", rid);
		return MGMT_IPC_ERR_NOT_FOUND;
	}

	idbm_terminate(db);
	return 0;
}

static mgmt_ipc_err_e
mgmt_ipc_session_login(queue_task_t *qtask, int rid)
{
	mgmt_ipc_err_e rc;
	node_rec_t rec;

	if ((rc = mgmt_ipc_node_read(rid, &rec)))
		return rc;
	return session_login_task(&rec, qtask);
}

static mgmt_ipc_err_e
mgmt_ipc_session_activelist(queue_task_t *qtask, iscsiadm_rsp_t *rsp)
{
	iscsi_session_t *session;
	struct qelem *item;

	rsp->u.activelist.cnt = 0;
	item = provider[0].sessions.q_forw;
	while (item != &provider[0].sessions) {
		session = (iscsi_session_t *)item;
		rsp->u.activelist.rids[rsp->u.activelist.cnt]= session->nrec.id;
		rsp->u.activelist.sids[rsp->u.activelist.cnt]= session->id;
		rsp->u.activelist.cnt++;
		item = item->q_forw;
	}

	return MGMT_IPC_OK;
}

static mgmt_ipc_err_e
mgmt_ipc_session_getstats(queue_task_t *qtask, int rid, int sid,
		iscsiadm_rsp_t *rsp)
{
	iscsi_session_t *session;
	struct qelem *item;

	item = provider[0].sessions.q_forw;
	while (item != &provider[0].sessions) {
		session = (iscsi_session_t *)item;
		if (session->id == sid) {
			int rc;

			rc = ipc->get_stats(session->transport_handle,
				session->conn[0].handle, (void*)&rsp->u.getstats,
				MGMT_IPC_GETSTATS_BUF_MAX);
			if (rc) {
				log_error("get_stats(): IPC error %d "
					"session [%02d:%06x]", rc, sid, rid);
				return MGMT_IPC_ERR_INTERNAL;
			}	
			return MGMT_IPC_OK;
		}
		item = item->q_forw;
	}

	return MGMT_IPC_ERR_NOT_FOUND;
}

static mgmt_ipc_err_e
mgmt_ipc_session_logout(queue_task_t *qtask, int rid)
{
	mgmt_ipc_err_e rc;
	node_rec_t rec;
	iscsi_session_t *session;

	if ((rc = mgmt_ipc_node_read(rid, &rec)))
		return rc;

	if (!(session = session_find_by_rec(&rec))) {
		log_error("session with corresponding record [%06x] "
			  "not found!", rid);
		return MGMT_IPC_ERR_NOT_FOUND;
	}

	return session_logout_task(session, qtask);
}

static mgmt_ipc_err_e
mgmt_ipc_cfg_initiatorname(queue_task_t *qtask, iscsiadm_rsp_t *rsp)
{
	strcpy(rsp->u.config.var, dconfig->initiator_name);

	return MGMT_IPC_OK;
}

static mgmt_ipc_err_e
mgmt_ipc_cfg_initiatoralias(queue_task_t *qtask, iscsiadm_rsp_t *rsp)
{
	strcpy(rsp->u.config.var, dconfig->initiator_alias);

	return MGMT_IPC_OK;
}

static mgmt_ipc_err_e
mgmt_ipc_cfg_filename(queue_task_t *qtask, iscsiadm_rsp_t *rsp)
{
	strcpy(rsp->u.config.var, dconfig->config_file);

	return MGMT_IPC_OK;
}

static mgmt_ipc_err_e
mgmt_ipc_conn_add(queue_task_t *qtask, int rid, int cid)
{
	return MGMT_IPC_ERR;
}

static mgmt_ipc_err_e
mgmt_ipc_conn_remove(queue_task_t *qtask, int rid, int cid)
{
	return MGMT_IPC_ERR;
}

static int
mgmt_peeruser(int sock, char *user)
{
#if defined(SO_PEERCRED)
	/* Linux style: use getsockopt(SO_PEERCRED) */
	struct ucred peercred;
	socklen_t so_len = sizeof(peercred);
	struct passwd *pass;

	errno = 0;
	if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &peercred,
		&so_len) != 0 || so_len != sizeof(peercred)) {
		/* We didn't get a valid credentials struct. */
		log_error("peeruser_unux: error receiving credentials: %m");
		return 0;
	}

	pass = getpwuid(peercred.uid);
	if (pass == NULL) {
		log_error("peeruser_unix: unknown local user with uid %d",
				(int) peercred.uid);
		return 0;
	}

	strncpy(user, pass->pw_name, PEERUSER_MAX);
	return 1;

#elif defined(SCM_CREDS)
	struct msghdr msg;
	typedef struct cmsgcred Cred;
#define cruid cmcred_uid
	Cred *cred;

	/* Compute size without padding */
	/* for NetBSD */
	char cmsgmem[_ALIGN(sizeof(struct cmsghdr)) + _ALIGN(sizeof(Cred))];

	/* Point to start of first structure */
	struct cmsghdr *cmsg = (struct cmsghdr *) cmsgmem;

	struct iovec iov;
	char buf;
	struct passwd *pw;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = (char *) cmsg;
	msg.msg_controllen = sizeof(cmsgmem);
	memset(cmsg, 0, sizeof(cmsgmem));

	/*
	 * The one character which is received here is not meaningful; its
	 * purposes is only to make sure that recvmsg() blocks long enough for
	 * the other side to send its credentials.
	 */
	iov.iov_base = &buf;
	iov.iov_len = 1;

	if (recvmsg(sock, &msg, 0) < 0 || cmsg->cmsg_len < sizeof(cmsgmem) ||
			cmsg->cmsg_type != SCM_CREDS) {
		log_error("ident_unix: error receiving credentials: %m");
		return 0;
	}

	cred = (Cred *) CMSG_DATA(cmsg);

	pw = getpwuid(cred->cruid);
	if (pw == NULL) {
		log_error("ident_unix: unknown local user with uid %d",
				(int) cred->cruid);
		return 0;
	}

	strncpy(user, pw->pw_name, PEERUSER_MAX);
	return 1;

#else
	log_error("'mgmg_ipc' auth is not supported on local connections "
		"on this platform");
	return 0;
#endif
}

int
mgmt_ipc_handle(int accept_fd)
{
	struct sockaddr addr;
	int fd, rc, immrsp = 0;
	iscsiadm_req_t req;
	iscsiadm_rsp_t rsp;
	queue_task_t *qtask = NULL;
	char user[PEERUSER_MAX];
	socklen_t len;

	memset(&rsp, 0, sizeof(rsp));
	len = sizeof(addr);
	if ((fd = accept(accept_fd, (struct sockaddr *) &addr, &len)) < 0) {
		if (errno == EINTR)
			rc = -EINTR;
		else
			rc = -EIO;
		return rc;
	}

	if (!mgmt_peeruser(accept_fd, user) ||
	    strncmp(user, "root", PEERUSER_MAX)) {
		rsp.err = MGMT_IPC_ERR_ACCESS;
		goto err;
	}

	rc = read(fd, &req, sizeof(req));
	if (rc != sizeof(req)) {
		if (rc >= 0)
			rc = -EIO;
		close(fd);
		return rc;
	}
	rsp.command = req.command;

	qtask = calloc(1, sizeof(queue_task_t));
	if (!qtask) {
		rsp.err = MGMT_IPC_ERR_NOMEM;
		rc = -ENOMEM;
		goto err;
	}
	memcpy(&qtask->u.login.req, &req, sizeof(iscsiadm_req_t));
	qtask->u.login.mgmt_ipc_fd = fd;

	switch(req.command) {
	case MGMT_IPC_SESSION_LOGIN:
		rsp.err = mgmt_ipc_session_login(qtask, req.u.session.rid);
		break;
	case MGMT_IPC_SESSION_LOGOUT:
		rsp.err = mgmt_ipc_session_logout(qtask, req.u.session.rid);
		break;
	case MGMT_IPC_SESSION_ACTIVELIST:
		rsp.err = mgmt_ipc_session_activelist(qtask, &rsp);
		immrsp = 1;
		break;
	case MGMT_IPC_SESSION_STATS:
		rsp.err = mgmt_ipc_session_getstats(qtask, req.u.session.rid,
				req.u.session.sid, &rsp);
		immrsp = 1;
		break;
	case MGMT_IPC_CONN_ADD:
		rsp.err = mgmt_ipc_conn_add(qtask, req.u.conn.rid,
					    req.u.conn.cid);
		break;
	case MGMT_IPC_CONN_REMOVE:
		rsp.err = mgmt_ipc_conn_remove(qtask, req.u.conn.rid,
					       req.u.conn.cid);
		break;
	case MGMT_IPC_CONFIG_INAME:
		rsp.err = mgmt_ipc_cfg_initiatorname(qtask, &rsp);
		immrsp = 1;
		break;
	case MGMT_IPC_CONFIG_IALIAS:
		rsp.err = mgmt_ipc_cfg_initiatoralias(qtask, &rsp);
		immrsp = 1;
		break;
	case MGMT_IPC_CONFIG_FILE:
		rsp.err = mgmt_ipc_cfg_filename(qtask, &rsp);
		immrsp = 1;
		break;
	default:
		log_error("unknown request: %s(%d) %u",
			  __FUNCTION__, __LINE__, req.command);
		break;
	}

	if (rsp.err == MGMT_IPC_OK && !immrsp)
		return 0;

err:
	rc = write(fd, &rsp, sizeof(rsp));
	if (rc != sizeof(rsp))
		if (rc >= 0)
			rc = -EIO;
	close(fd);
	if (qtask)
		free(qtask);
	return rc;
}
