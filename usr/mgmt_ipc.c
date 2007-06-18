/*
 * iSCSI Administrator Utility Socket Interface
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
#include <errno.h>
#include <unistd.h>

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <pwd.h>

#include "iscsid.h"
#include "idbm.h"
#include "mgmt_ipc.h"
#include "iscsi_ipc.h"
#include "log.h"
#include "transport.h"
#include "iscsi_sysfs.h"

static int	leave_event_loop = 0;

#define PEERUSER_MAX	64

int
mgmt_ipc_listen(void)
{
	int fd, err;
	struct sockaddr_un addr;

	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0) {
		log_error("Can not create IPC socket");
		return fd;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	memcpy((char *) &addr.sun_path + 1, ISCSIADM_NAMESPACE,
		strlen(ISCSIADM_NAMESPACE));

	if ((err = bind(fd, (struct sockaddr *) &addr, sizeof(addr))) < 0) {
		log_error("Can not bind IPC socket");
		close(fd);
		return err;
	}

	if ((err = listen(fd, 32)) < 0) {
		log_error("Can not listen IPC socket");
		close(fd);
		return err;
	}

	return fd;
}

void
mgmt_ipc_close(int fd)
{
}

static mgmt_ipc_err_e
mgmt_ipc_session_login(queue_task_t *qtask, node_rec_t *rec)
{
	if (session_is_running(rec)) {
		log_error("session [%s,%s,%d] already running.", rec->name,
			  rec->conn[0].address, rec->conn[0].port);
		return MGMT_IPC_ERR_EXISTS;
	}

	return session_login_task(rec, qtask);
}

static mgmt_ipc_err_e
mgmt_ipc_session_getstats(queue_task_t *qtask, int sid,
			  iscsiadm_rsp_t *rsp)
{
	struct iscsi_transport *t;
	iscsi_session_t *session;

	list_for_each_entry(t, &transports, list) {
		list_for_each_entry(session, &t->sessions, list) {
			if (session->id == sid) {
				int rc;

				rc = ipc->get_stats(session->t->handle,
					session->id, session->conn[0].id,
					(void*)&rsp->u.getstats,
					MGMT_IPC_GETSTATS_BUF_MAX);
				if (rc) {
					log_error("get_stats(): IPC error %d "
						"session [%02d]", rc, sid);
					return MGMT_IPC_ERR_INTERNAL;
				}
				return MGMT_IPC_OK;
			}
		}
	}

	return MGMT_IPC_ERR_NOT_FOUND;
}

static mgmt_ipc_err_e
mgmt_ipc_session_logout(queue_task_t *qtask, node_rec_t *rec)
{
	iscsi_session_t *session;

	if (!(session = session_find_by_rec(rec))) {
		log_error("session [%s,%s,%d] not found!", rec->name,
			  rec->conn[0].address, rec->conn[0].port);
		return MGMT_IPC_ERR_NOT_FOUND;
	}

	return session_logout_task(session, qtask);
}

static mgmt_ipc_err_e
mgmt_ipc_session_sync(queue_task_t *qtask, node_rec_t *rec, int sid)
{
	return iscsi_sync_session(rec, qtask, sid);
}

static mgmt_ipc_err_e
mgmt_ipc_cfg_initiatorname(queue_task_t *qtask, iscsiadm_rsp_t *rsp)
{
	strcpy(rsp->u.config.var, dconfig->initiator_name);

	return MGMT_IPC_OK;
}

static mgmt_ipc_err_e
mgmt_ipc_session_info(queue_task_t *qtask, int sid, iscsiadm_rsp_t *rsp)
{
	iscsi_session_t *session;
	struct ipc_msg_session_state *info;

	if (!(session = session_find_by_sid(sid))) {
		log_error("session with sid %d not found!", sid);
		return MGMT_IPC_ERR_NOT_FOUND;
	}

	info = &rsp->u.session_state;
	info->conn_state = session->conn[0].state;
	info->session_state = session->r_stage;
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
mgmt_ipc_conn_add(queue_task_t *qtask, int cid)
{
	return MGMT_IPC_ERR;
}

static mgmt_ipc_err_e
mgmt_ipc_conn_remove(queue_task_t *qtask, int cid)
{
	return MGMT_IPC_ERR;
}

static mgmt_ipc_err_e
mgmt_ipc_isns_dev_attr_query(queue_task_t *qtask)
{
	return isns_dev_attr_query_task(qtask);
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

/*
 * Send the IPC response and destroy the queue_task.
 * The recovery code uses a qtask which is allocated as
 * part of a larger structure, and we don't want it to
 * get freed when we come here. This is what qtask->allocated
 * is for.
 */
void
mgmt_ipc_write_rsp(queue_task_t *qtask, mgmt_ipc_err_e err)
{
	if (!qtask)
		return;
	log_debug(4, "%s: rsp to fd %d", __FUNCTION__,
		 qtask->mgmt_ipc_fd);

	if (qtask->mgmt_ipc_fd < 0) {
		if (qtask->allocated)
			free(qtask);
		return;
	}

	qtask->rsp.err = err;
	write(qtask->mgmt_ipc_fd, &qtask->rsp, sizeof(qtask->rsp));
	close(qtask->mgmt_ipc_fd);
	if (qtask->allocated)
		free(qtask);
}

static void
mgmt_ipc_handle(int accept_fd)
{
	struct sockaddr addr;
	int fd, immrsp = 0, err;
	iscsiadm_req_t *req;
	queue_task_t *qtask = NULL;
	char user[PEERUSER_MAX];
	socklen_t len;

	qtask = calloc(1, sizeof(queue_task_t));
	if (!qtask)
		return;

	len = sizeof(addr);
	if ((fd = accept(accept_fd, (struct sockaddr *) &addr, &len)) < 0) {
		free(qtask);
		return;
	}

	qtask->allocated = 1;
	qtask->mgmt_ipc_fd = fd;

	if (!mgmt_peeruser(fd, user) || strncmp(user, "root", PEERUSER_MAX)) {
		err = MGMT_IPC_ERR_ACCESS;
		goto err;
	}

	req = &qtask->req;
	if (read(fd, req, sizeof(*req)) != sizeof(*req)) {
		close(fd);
		free(qtask);
		return;
	}

	qtask->rsp.command = req->command;

	switch(req->command) {
	case MGMT_IPC_SESSION_LOGIN:
		err = mgmt_ipc_session_login(qtask, &req->u.session.rec);
		break;
	case MGMT_IPC_SESSION_LOGOUT:
		err = mgmt_ipc_session_logout(qtask, &req->u.session.rec);
		break;
	case MGMT_IPC_SESSION_SYNC:
		err = mgmt_ipc_session_sync(qtask, &req->u.session.rec,
						req->u.session.sid);
		break;
	case MGMT_IPC_SESSION_STATS:
		err = mgmt_ipc_session_getstats(qtask, req->u.session.sid,
						    &qtask->rsp);
		immrsp = 1;
		break;
	case MGMT_IPC_SEND_TARGETS:
		err = iscsi_host_send_targets(qtask, req->u.st.host_no,
						  req->u.st.do_login,
						  &req->u.st.ss);
		immrsp = 1;
		break;
	case MGMT_IPC_SESSION_INFO:
		err = mgmt_ipc_session_info(qtask, req->u.session.sid,
						&qtask->rsp);
		immrsp = 1;
		break;
	case MGMT_IPC_CONN_ADD:
		err = mgmt_ipc_conn_add(qtask, req->u.conn.cid);
		break;
	case MGMT_IPC_CONN_REMOVE:
		err = mgmt_ipc_conn_remove(qtask, req->u.conn.cid);
		break;
	case MGMT_IPC_CONFIG_INAME:
		err = mgmt_ipc_cfg_initiatorname(qtask, &qtask->rsp);
		immrsp = 1;
		break;
	case MGMT_IPC_CONFIG_IALIAS:
		err = mgmt_ipc_cfg_initiatoralias(qtask, &qtask->rsp);
		immrsp = 1;
		break;
	case MGMT_IPC_CONFIG_FILE:
		err = mgmt_ipc_cfg_filename(qtask, &qtask->rsp);
		immrsp = 1;
		break;
	case MGMT_IPC_IMMEDIATE_STOP:
		err = MGMT_IPC_OK;
		immrsp = 1;
		leave_event_loop = 1;
		break;
	case MGMT_IPC_ISNS_DEV_ATTR_QUERY:
		err = mgmt_ipc_isns_dev_attr_query(qtask);
		break;
	case MGMT_IPC_SET_HOST_PARAM:
		err = iscsi_host_set_param(qtask->req.u.set_host_param.host_no,
						qtask->req.u.set_host_param.param,
						qtask->req.u.set_host_param.value);
		immrsp = 1;
		break;
	default:
		log_error("unknown request: %s(%d) %u",
			  __FUNCTION__, __LINE__, req->command);
		err = MGMT_IPC_ERR_INVALID_REQ;
		immrsp = 1;
		break;
	}

	if (err == MGMT_IPC_OK && !immrsp)
		return;

err:
	/* This will send the response, close the
	 * connection and free the qtask */
	mgmt_ipc_write_rsp(qtask, err);
}

static int reap_count;

void
need_reap(void)
{
	reap_count++;
}

static void
reaper(void)
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

/* TODO: this should go somewhere else */
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

	leave_event_loop = 0;
	while (!leave_event_loop) {
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
	}
}
