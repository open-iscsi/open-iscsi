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
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/un.h>
#include <string.h>
#include <stdbool.h>

#include "iscsid.h"
#include "idbm.h"
#include "mgmt_ipc.h"
#include "event_poll.h"
#include "log.h"
#include "transport.h"
#include "sysdeps.h"
#include "iscsi_ipc.h"
#include "iscsi_err.h"
#include "iscsi_util.h"
#include "iscsid_req.h"

#define PEERUSER_MAX	64
#define EXTMSG_MAX	(64 * 1024)
#define SD_SOCKET_FDS_START 3

int
mgmt_ipc_listen(void)
{
	int fd, err, addr_len;
	struct sockaddr_un addr;

	/* first check if we have fd handled by systemd */
	fd = mgmt_ipc_systemd();
	if (fd >= 0)
		return fd;

	/* manually establish a socket */
	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0) {
		log_error("Can not create IPC socket");
		return fd;
	}

	addr_len = setup_abstract_addr(&addr, iscsid_namespace);

	if ((err = bind(fd, (struct sockaddr *) &addr, addr_len)) < 0 ) {
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

int mgmt_ipc_systemd(void)
{
	const char *env;

	env = getenv("LISTEN_PID");

	if (!env || ((pid_t)strtoul(env, NULL, 10) != getpid()))
		return -EINVAL;

	env = getenv("LISTEN_FDS");

	if (!env)
		return -EINVAL;

	if (strtoul(env, NULL, 10) != 1) {
		log_error("Did not receive exactly one IPC socket from systemd");
		return -EINVAL;
	}

	return SD_SOCKET_FDS_START;
}

void
mgmt_ipc_close(int fd)
{
	event_loop_exit(NULL);
	if (fd >= 0)
		close(fd);
}

static int 
mgmt_ipc_session_login(queue_task_t *qtask)
{
	return session_login_task(&qtask->req.u.session.rec, qtask);
}

static int
mgmt_ipc_session_getstats(queue_task_t *qtask)
{
	int sid = qtask->req.u.session.sid;
	iscsi_session_t *session;
	int rc;

	if (!(session = session_find_by_sid(sid)))
		return ISCSI_ERR_SESS_NOT_FOUND;

	rc = ipc->get_stats(session->t->handle,
		session->id, session->conn[0].id,
		(void *)&qtask->rsp.u.getstats,
		MGMT_IPC_GETSTATS_BUF_MAX);
	if (rc) {
		log_error("get_stats(): IPC error %d "
			"session [%02d]", rc, sid);
		return ISCSI_ERR_INTERNAL;
	}

	mgmt_ipc_write_rsp(qtask, ISCSI_SUCCESS);
	return ISCSI_SUCCESS;
}

static int
mgmt_ipc_send_targets(queue_task_t *qtask)
{
	iscsiadm_req_t *req = &qtask->req;
	int err;

	err = iscsi_host_send_targets(qtask, req->u.st.host_no,
					  req->u.st.do_login,
					  &req->u.st.ss);
	mgmt_ipc_write_rsp(qtask, err);
	return ISCSI_SUCCESS;
}

static int
mgmt_ipc_session_logout(queue_task_t *qtask)
{
	return session_logout_task(qtask->req.u.session.sid, qtask);
}

static int
mgmt_ipc_session_sync(queue_task_t *qtask)
{
	struct ipc_msg_session *session= &qtask->req.u.session;

	return iscsi_sync_session(&session->rec, qtask, session->sid);
}

static int
mgmt_ipc_cfg_initiatorname(queue_task_t *qtask)
{
	if (dconfig->initiator_name)
		strcpy(qtask->rsp.u.config.var, dconfig->initiator_name);
	mgmt_ipc_write_rsp(qtask, ISCSI_SUCCESS);
	return ISCSI_SUCCESS;
}

static int
mgmt_ipc_session_info(queue_task_t *qtask)
{
	int sid = qtask->req.u.session.sid;
	iscsi_session_t *session;
	struct ipc_msg_session_state *info;

	if (!(session = session_find_by_sid(sid))) {
		log_debug(1, "session with sid %d not found!", sid);
		return ISCSI_ERR_SESS_NOT_FOUND;
	}

	info = &qtask->rsp.u.session_state;
	info->conn_state = session->conn[0].state;
	info->session_state = session->r_stage;

	mgmt_ipc_write_rsp(qtask, ISCSI_SUCCESS);
	return ISCSI_SUCCESS;
}

static int
mgmt_ipc_cfg_initiatoralias(queue_task_t *qtask)
{
	strcpy(qtask->rsp.u.config.var, dconfig->initiator_alias);
	mgmt_ipc_write_rsp(qtask, ISCSI_SUCCESS);
	return ISCSI_SUCCESS;
}

static int
mgmt_ipc_cfg_filename(queue_task_t *qtask)
{
	strcpy(qtask->rsp.u.config.var, dconfig->config_file);
	mgmt_ipc_write_rsp(qtask, ISCSI_SUCCESS);
	return ISCSI_SUCCESS;
}

static int
mgmt_ipc_conn_add(__attribute__((unused))queue_task_t *qtask)
{
	return ISCSI_ERR;
}

static int
mgmt_ipc_immediate_stop(queue_task_t *qtask)
{
	event_loop_exit(qtask);
	return ISCSI_SUCCESS;
}

static int
mgmt_ipc_conn_remove(__attribute__((unused))queue_task_t *qtask)
{
	return ISCSI_ERR;
}

/*
 * Parse a list of strings, encoded as a 32bit
 * length followed by the string itself (not necessarily
 * NUL-terminated).
 */
static int
mgmt_ipc_parse_strings(queue_task_t *qtask, char ***result)
{
	char		*data, *endp, **argv = NULL;
	unsigned int	left, argc;

again:
	data = qtask->payload;
	left = qtask->req.payload_len;
	endp = NULL;
	argc = 0;

	while (left) {
		uint32_t len;

		if (left < 4)
			return -1;
		memcpy(&len, data, 4);
		data += 4;

		if (endp)
			*endp = '\0';

		if (len > left)
			return -1;

		if (argv) {
			argv[argc] = (char *) data;
			endp = data + len;
		}
		data += len;
		argc++;
	}

	if (endp)
		*endp = '\0';

	if (argv == NULL) {
		argv = malloc((argc + 1) * sizeof(char *));
		*result = argv;
		goto again;
	}

	argv[argc] = NULL;
	return argc;
}

static int
mgmt_ipc_notify_common(queue_task_t *qtask, int (*handler)(int, char **))
{
	char	**argv = NULL;
	int	argc, err = ISCSI_ERR;

	argc = mgmt_ipc_parse_strings(qtask, &argv);
	if (argc > 0)
		err = handler(argc, argv);

	if (argv)
		free(argv);
	mgmt_ipc_write_rsp(qtask, err);
	return ISCSI_SUCCESS;
}

/* Replace these dummies as you implement them
   elsewhere */
static int
iscsi_discovery_add_node(__attribute__((unused))int argc,
			 __attribute__((unused))char **argv)
{
	return ISCSI_SUCCESS;
}

static int
iscsi_discovery_del_node(__attribute__((unused))int argc,
			 __attribute__((unused))char **argv)
{
	return ISCSI_SUCCESS;
}

static int
iscsi_discovery_add_portal(__attribute__((unused))int argc,
			   __attribute__((unused))char **argv)
{
	return ISCSI_SUCCESS;
}

static int
iscsi_discovery_del_portal(__attribute__((unused))int argc,
			   __attribute__((unused))char **argv)
{
	return ISCSI_SUCCESS;
}

static int
mgmt_ipc_notify_add_node(queue_task_t *qtask)
{
	return mgmt_ipc_notify_common(qtask, iscsi_discovery_add_node);
}

static int
mgmt_ipc_notify_del_node(queue_task_t *qtask)
{
	return mgmt_ipc_notify_common(qtask, iscsi_discovery_del_node);
}

static int
mgmt_ipc_notify_add_portal(queue_task_t *qtask)
{
	return mgmt_ipc_notify_common(qtask, iscsi_discovery_add_portal);
}

static int
mgmt_ipc_notify_del_portal(queue_task_t *qtask)
{
	return mgmt_ipc_notify_common(qtask, iscsi_discovery_del_portal);
}

static int
mgmt_peeruser(int sock, char *user)
{
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

	strlcpy(user, pass->pw_name, PEERUSER_MAX);
	return 1;
}

static bool
mgmt_authorized_uid(int sock)
{
	int authorized = false;
	struct ucred peercred = {0};
	socklen_t so_len = sizeof(peercred);

	errno = 0;
	if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &peercred,
		&so_len) != 0 || so_len != sizeof(peercred)) {
		/* We didn't get a valid credentials struct. */
		log_error("Error receiving credentials: %m");
		goto ret_auth;
	}

	/* Only UID==0 is authorized */
	authorized = peercred.uid ? false: true;

	if (!authorized) {
		log_error("Unauthorized user with UID=%u", peercred.uid);
	}

ret_auth:
	return authorized;
}

static void
mgmt_ipc_destroy_queue_task(queue_task_t *qtask)
{
	if (qtask->mgmt_ipc_fd >= 0)
		close(qtask->mgmt_ipc_fd);
	if (qtask->payload)
		free(qtask->payload);
	if (qtask->allocated)
		free(qtask);
}

/*
 * Send the IPC response and destroy the queue_task.
 * The recovery code uses a qtask which is allocated as
 * part of a larger structure, and we don't want it to
 * get freed when we come here. This is what qtask->allocated
 * is for.
 */
void
mgmt_ipc_write_rsp(queue_task_t *qtask, int err)
{
	if (!qtask)
		return;
	log_debug(4, "%s: rsp to fd %d", __FUNCTION__,
		 qtask->mgmt_ipc_fd);

	if (qtask->mgmt_ipc_fd < 0) {
		mgmt_ipc_destroy_queue_task(qtask);
		return;
	}

	qtask->rsp.err = err;
	if (write(qtask->mgmt_ipc_fd, &qtask->rsp, sizeof(qtask->rsp)) < 0) {
		if (qtask->conn && qtask->conn->session)
			conn_error(qtask->conn, "IPC qtask write failed: %s", strerror(errno));
		else
			log_error("IPC qtask write failed: %s", strerror(errno));
	}
	mgmt_ipc_destroy_queue_task(qtask);
}

static int
mgmt_ipc_read_data(int fd, void *ptr, size_t len)
{
	int	n;

	while (len) {
		n = read(fd, ptr, len);
		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -EIO;
		}
		if (n == 0) {
			/* Client closed connection */
			return -EIO;
		}
		ptr += n;
		len -= n;
	}
	return 0;
}

static int
mgmt_ipc_read_req(queue_task_t *qtask)
{
	iscsiadm_req_t *req = &qtask->req;
	int	rc;

	rc = mgmt_ipc_read_data(qtask->mgmt_ipc_fd, req, sizeof(*req));
	if (rc >= 0 && req->payload_len > 0) {
		/* Limit what we accept */
		if (req->payload_len > EXTMSG_MAX)
			return -EIO;

		/* Remember the allocated pointer in the
		 * qtask - it will be freed by write_rsp.
		 * Note: we allocate one byte in excess
		 * so we can append a NULL byte. */
		qtask->payload = malloc(req->payload_len + 1);
		if (!qtask->payload)
			return -ENOMEM;

		rc = mgmt_ipc_read_data(qtask->mgmt_ipc_fd,
				qtask->payload,
				req->payload_len);
	}
	return rc;
}

static mgmt_ipc_fn_t *	mgmt_ipc_functions[__MGMT_IPC_MAX_COMMAND] = {
[MGMT_IPC_SESSION_LOGIN]	= mgmt_ipc_session_login,
[MGMT_IPC_SESSION_LOGOUT]	= mgmt_ipc_session_logout,
[MGMT_IPC_SESSION_SYNC]		= mgmt_ipc_session_sync,
[MGMT_IPC_SESSION_STATS]	= mgmt_ipc_session_getstats,
[MGMT_IPC_SEND_TARGETS]		= mgmt_ipc_send_targets,
[MGMT_IPC_SESSION_INFO]		= mgmt_ipc_session_info,
[MGMT_IPC_CONN_ADD]		= mgmt_ipc_conn_add,
[MGMT_IPC_CONN_REMOVE]		= mgmt_ipc_conn_remove,
[MGMT_IPC_CONFIG_INAME]		= mgmt_ipc_cfg_initiatorname,
[MGMT_IPC_CONFIG_IALIAS]	= mgmt_ipc_cfg_initiatoralias,
[MGMT_IPC_CONFIG_FILE]		= mgmt_ipc_cfg_filename,
[MGMT_IPC_IMMEDIATE_STOP]	= mgmt_ipc_immediate_stop,
[MGMT_IPC_NOTIFY_ADD_NODE]	= mgmt_ipc_notify_add_node,
[MGMT_IPC_NOTIFY_DEL_NODE]	= mgmt_ipc_notify_del_node,
[MGMT_IPC_NOTIFY_ADD_PORTAL]	= mgmt_ipc_notify_add_portal,
[MGMT_IPC_NOTIFY_DEL_PORTAL]	= mgmt_ipc_notify_del_portal,
};

static void mgmt_ipc_handle_check_auth(int accept_fd, bool auth_legacy)
{
	unsigned int command;
	int fd, err;
	queue_task_t *qtask = NULL;
	mgmt_ipc_fn_t *handler = NULL;
	char user[PEERUSER_MAX];

	qtask = calloc(1, sizeof(queue_task_t));
	if (!qtask)
		return;

	if ((fd = accept(accept_fd, NULL, NULL)) < 0) {
		free(qtask);
		return;
	}

	qtask->allocated = 1;
	qtask->mgmt_ipc_fd = fd;

	if (auth_legacy) {
		if (!mgmt_peeruser(fd, user) || strncmp(user, "root", PEERUSER_MAX)) {
			err = ISCSI_ERR_ACCESS;
			goto err;
		}
	} else {
		if (!mgmt_authorized_uid(fd)) {
			err = ISCSI_ERR_ACCESS;
			goto err;
		}
	}

	if (mgmt_ipc_read_req(qtask) < 0) {
		mgmt_ipc_destroy_queue_task(qtask);
		return;
	}

	command = qtask->req.command;
	qtask->rsp.command = command;

	if (command > 0 &&
	    command < __MGMT_IPC_MAX_COMMAND)
		handler = mgmt_ipc_functions[command];

	if (handler != NULL) {
		/* If the handler returns OK, this means it
		 * already sent the reply. */
		err = handler(qtask);
		if (err == ISCSI_SUCCESS)
			return;
	} else {
		log_error("unknown request: %s(%d) %u",
			  __FUNCTION__, __LINE__, command);
		err = ISCSI_ERR_INVALID_MGMT_REQ;
	}

err:
	/* This will send the response, close the
	 * connection and free the qtask */
	mgmt_ipc_write_rsp(qtask, err);
}

void mgmt_ipc_handle(int accept_fd)
{
	/* Default behavior. Check originating UID. */
	mgmt_ipc_handle_check_auth(accept_fd, false);
}

void mgmt_ipc_handle_legacy(int accept_fd)
{
	/* Legacy behavior. Check UID and username. */
	mgmt_ipc_handle_check_auth(accept_fd, true);
}
