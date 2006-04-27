/*
 * iSCSI Session Management and Slow-path Control
 *
 * Copyright (C) 2004 Dmitry Yusupov, Alex Aizman
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
#include <search.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "initiator.h"
#include "transport.h"
#include "iscsid.h"
#include "iscsi_if.h"
#include "mgmt_ipc.h"
#include "iscsi_ipc.h"
#include "idbm.h"
#include "log.h"
#include "util.h"

static void __session_mainloop(void *data);
static void __conn_error_handle(iscsi_session_t*, iscsi_conn_t*);

char sysfs_file[PATH_MAX];

/*
 * calculate parameter's padding
 */
static unsigned int
__padding(unsigned int param)
{
	int pad;

	pad = param & 3;
	if (pad) {
		pad = 4 - pad;
		log_debug(1, "parameter's value %d padded to %d bytes\n",
			   param, param + pad);
	}
	return param + pad;
}

static int
__recvpool_alloc(iscsi_conn_t *conn)
{
	int i;

	for (i = 0; i < RECVPOOL_MAX; i++) {
		conn->recvpool[i] = calloc(1, ipc->ctldev_bufmax);
		if (!conn->recvpool[i]) {
			int j;
			for (j = 0; j < i; j++)
				free(conn->recvpool[j]);
			return -ENOMEM;
		}
	}

	return 0;
}

static void
__recvpool_free(iscsi_conn_t *conn)
{
	int i;

	for (i = 0; i < RECVPOOL_MAX; i++) {
		if (!conn->recvpool[i]) {
			log_error("recvpool leak: %d bytes",
				  ipc->ctldev_bufmax);
		} else
			free(conn->recvpool[i]);
	}
}

void* recvpool_get(iscsi_conn_t *conn, int ev_size)
{
	int i;

	if (ev_size > ipc->ctldev_bufmax)
		return NULL;

	for (i = 0; i < RECVPOOL_MAX; i++) {
		if (conn->recvpool[i]) {
			void *handle = conn->recvpool[i];
			conn->recvpool[i] = NULL;
			return handle;
		}
	}
	return NULL;
}

void recvpool_put(iscsi_conn_t *conn, void *handle)
{
	int i;

	for (i = 0; i < RECVPOOL_MAX; i++) {
		if (!conn->recvpool[i]) {
			conn->recvpool[i] = handle;
			break;
		}
	}
}

/*
 * To sync caches before actual scsi_remove_host() we
 * need manually walk through the sysfs scsi host and delete
 * all related LUNs.
 */
static void
__session_delete_devs(iscsi_session_t *session)
{
	int lu = 0;
	int hostno = session->hostno;

	do {
		pid_t pid;
		int fd;

		sprintf(sysfs_file, "/sys/bus/scsi/devices/%d:0:0:%d/delete",
			hostno, lu);
		fd = open(sysfs_file, O_WRONLY);
		if (fd < 0)
			continue;
		if (!(pid = fork())) {
			/* child */
			log_debug(4, "deleting device using %s", sysfs_file);
			write(fd, "1", 1);
			close(fd);
			exit(0);
		}
		if (pid > 0) {
			int attempts = 3, status, rc;
			while (!(rc = waitpid(pid, &status, WNOHANG)) &&
			       attempts--)
				sleep(1);
			if (!rc)
				log_debug(4, "could not delete device %s "
					  "after delay\n", sysfs_file);
		}
		close(fd);
	} while (++lu < 256); /* FIXME: hardcoded */
}

static void
__session_online_devs(iscsi_session_t *session)
{
	int lun = 0;
	int hostno = session->hostno;

	do {
		int fd;

		sprintf(sysfs_file, "/sys/bus/scsi/devices/%d:0:0:%d/state",
			hostno, lun);
		fd = open(sysfs_file, O_WRONLY);
		if (fd < 0)
			continue;
		log_debug(4, "online device using %s", sysfs_file);
		if (write(fd, "running\n", 8) == -1 && errno != EINVAL) {
			/* we should read the state */
			log_error("Could not online LUN %d err %d\n",
				  lun, errno);
		}
		close(fd);

	} while (++lun < 256); /* FIXME: hardcoded */
}

static void
write_mgmt_login_rsp(queue_task_t *qtask, mgmt_ipc_err_e err)
{
	if (qtask->u.login.mgmt_ipc_fd == 0)
		return;

	qtask->u.login.rsp.err = err;
	write(qtask->u.login.mgmt_ipc_fd, &qtask->u.login.rsp,
	      sizeof(qtask->u.login.rsp));
	close(qtask->u.login.mgmt_ipc_fd);
	free(qtask);
}

/*
 * Scan a session from usersapce using sysfs
 */
static void
__session_scan_host(iscsi_session_t *session, queue_task_t *qtask)
{
	int hostno = session->hostno;
	pid_t pid;
	int fd;

	sprintf(sysfs_file, "/sys/class/scsi_host/host%d/scan",
		session->hostno);
	fd = open(sysfs_file, O_WRONLY);
	if (fd < 0) {
		log_error("could not scan scsi host%d\n", hostno);
		return;
	}

	pid = fork();
	if (pid == 0) {
		/* child */
		log_debug(4, "scanning host%d using %s",hostno,
			  sysfs_file);
		write(fd, "- - -", 5);
		close(fd);

		write_mgmt_login_rsp(qtask, MGMT_IPC_OK);
		log_debug(4, "scanning host%d completed\n", hostno);
		exit(0);
	} else if (pid > 0) {
		log_debug(4, "scanning host%d from pid %d", hostno, pid);
		need_reap();
		free(qtask);
	} else {
		/*
		 * Session is fine, so log the error and let the user
		 * scan by hand
		  */
		log_error("Could not start scanning process for host %d "
			  "err %d. Try scanning through sysfs\n", hostno,
			  errno);
		write_mgmt_login_rsp(qtask, MGMT_IPC_ERR_INTERNAL);
	}

	close(fd);
}

static conn_login_status_e
__login_response_status(iscsi_conn_t *conn,
		      enum iscsi_login_status login_status)
{
	switch (login_status) {
	case LOGIN_OK:
		/* check the status class and detail */
		return CONN_LOGIN_SUCCESS;
	case LOGIN_IO_ERROR:
	case LOGIN_WRONG_PORTAL_GROUP:
	case LOGIN_REDIRECTION_FAILED:
		conn->session->provider->utransport->ep_disconnect(conn);
		return CONN_LOGIN_RETRY;
	default:
		conn->session->provider->utransport->ep_disconnect(conn);
		log_error("conn %d giving up on login attempts", conn->id);
		break;
	}

	return CONN_LOGIN_FAILED;
}

static conn_login_status_e
__check_iscsi_status_class(iscsi_session_t *session, int cid,
			uint8_t status_class, uint8_t status_detail)
{
	iscsi_conn_t *conn = &session->conn[cid];

	switch (status_class) {
	case ISCSI_STATUS_CLS_SUCCESS:
		return CONN_LOGIN_SUCCESS;
	case ISCSI_STATUS_CLS_REDIRECT:
		switch (status_detail) {
		case ISCSI_LOGIN_STATUS_TGT_MOVED_TEMP:
			return CONN_LOGIN_IMM_RETRY;
		case ISCSI_LOGIN_STATUS_TGT_MOVED_PERM:
			/*
			 * for a permanent redirect, we need to update the
			 * failback address
			 */
			memset(&conn->failback_saddr, 0,
				sizeof(struct sockaddr_storage));
			conn->failback_saddr = conn->saddr;
                        return CONN_LOGIN_IMM_REDIRECT_RETRY;
		default:
			log_error("conn %d login rejected: redirection "
			        "type 0x%x not supported",
				conn->id, status_detail);
			conn->session->provider->utransport->ep_disconnect(conn);
			return CONN_LOGIN_RETRY;
		}
	case ISCSI_STATUS_CLS_INITIATOR_ERR:
		conn->session->provider->utransport->ep_disconnect(conn);

		switch (status_detail) {
		case ISCSI_LOGIN_STATUS_AUTH_FAILED:
			log_error("conn %d login rejected: Initiator "
			       "failed authentication with target", conn->id);
			if ((session->num_auth_buffers < 5) &&
			    (session->username || session->password_length ||
			    session->bidirectional_auth))
				/*
				 * retry, and hope we can allocate the auth
				 * structures next time.
				 */
				return CONN_LOGIN_RETRY;
			else
				return CONN_LOGIN_FAILED;
		case ISCSI_LOGIN_STATUS_TGT_FORBIDDEN:
			log_error("conn %d login rejected: initiator "
			       "failed authorization with target", conn->id);
			return CONN_LOGIN_FAILED;
		case ISCSI_LOGIN_STATUS_TGT_NOT_FOUND:
			log_error("conn %d login rejected: initiator "
			       "error - target not found (%02x/%02x)",
			       conn->id, status_class, status_detail);
			return CONN_LOGIN_FAILED;
		case ISCSI_LOGIN_STATUS_NO_VERSION:
			/*
			 * FIXME: if we handle multiple protocol versions,
			 * before we log an error, try the other supported
			 * versions.
			 */
			log_error("conn %d login rejected: incompatible "
			       "version (%02x/%02x), non-retryable, "
			       "giving up", conn->id, status_class,
			       status_detail);
			return CONN_LOGIN_FAILED;
		default:
			log_error("conn %d login rejected: initiator "
			       "error (%02x/%02x), non-retryable, "
			       "giving up", conn->id, status_class,
			       status_detail);
			return CONN_LOGIN_FAILED;
		}
	case ISCSI_STATUS_CLS_TARGET_ERR:
		log_error("conn %d login rejected: target error "
		       "(%02x/%02x)\n", conn->id, status_class, status_detail);
		conn->session->provider->utransport->ep_disconnect(conn);
		/*
		 * We have no idea what the problem is. But spec says initiator
		 * may retry later.
		 */
		 return CONN_LOGIN_RETRY;
	default:
		log_error("conn %d login response with unknown status "
		       "class 0x%x, detail 0x%x\n", conn->id, status_class,
		       status_detail);
		conn->session->provider->utransport->ep_disconnect(conn);
		break;
	}

	return CONN_LOGIN_FAILED;
}

static void
__setup_authentication(iscsi_session_t *session,
			struct iscsi_auth_config *auth_cfg)
{
	/* if we have any incoming credentials, we insist on authenticating
	 * the target or not logging in at all
	 */
	if (auth_cfg->username_in[0]
	    || auth_cfg->password_in_length) {
		/* sanity check the config */
		if ((auth_cfg->username[0] == '\0')
		    || (auth_cfg->password_length == 0)) {
			log_debug(1,
			       "node record has incoming "
			       "authentication credentials but has no outgoing "
			       "credentials configured, exiting");
			return;
		}
		session->bidirectional_auth = 1;
	} else {
		/* no or 1-way authentication */
		session->bidirectional_auth = 0;
	}

	/* copy in whatever credentials we have */
	strncpy(session->username, auth_cfg->username,
		sizeof (session->username));
	session->username[sizeof (session->username) - 1] = '\0';
	if ((session->password_length = auth_cfg->password_length))
		memcpy(session->password, auth_cfg->password,
		       session->password_length);

	strncpy(session->username_in, auth_cfg->username_in,
		sizeof (session->username_in));
	session->username_in[sizeof (session->username_in) - 1] = '\0';
	if ((session->password_in_length =
	     auth_cfg->password_in_length))
		memcpy(session->password_in, auth_cfg->password_in,
		       session->password_in_length);

	if (session->password_length || session->password_in_length) {
		/* setup the auth buffers */
		session->auth_buffers[0].address = &session->auth_client_block;
		session->auth_buffers[0].length =
		    sizeof (session->auth_client_block);
		session->auth_buffers[1].address =
		    &session->auth_recv_string_block;
		session->auth_buffers[1].length =
		    sizeof (session->auth_recv_string_block);

		session->auth_buffers[2].address =
		    &session->auth_send_string_block;
		session->auth_buffers[2].length =
		    sizeof (session->auth_send_string_block);

		session->auth_buffers[3].address =
		    &session->auth_recv_binary_block;
		session->auth_buffers[3].length =
		    sizeof (session->auth_recv_binary_block);

		session->auth_buffers[4].address =
		    &session->auth_send_binary_block;
		session->auth_buffers[4].length =
		    sizeof (session->auth_send_binary_block);

		session->num_auth_buffers = 5;
		log_debug(6, "authentication setup complete...");
	} else {
		session->num_auth_buffers = 0;
		log_debug(6, "no authentication configured...");
	}
}

static int
setup_portal(iscsi_conn_t *conn, conn_rec_t *conn_rec)
{
	char port[NI_MAXSERV];

	sprintf(port, "%d", conn_rec->port);
	if (resolve_address(conn_rec->address, port, &conn->saddr)) {
		log_error("cannot resolve host name %s",
			  conn_rec->address);
		return -EINVAL;
	}
	conn->failback_saddr = conn->saddr;

	getnameinfo((struct sockaddr *)&conn->saddr, sizeof(conn->saddr),
		    conn->host, sizeof(conn->host), NULL, 0, NI_NUMERICHOST);
	log_debug(4, "resolved %s to %s", conn_rec->address, conn->host);
	return 0;
}

static int
__session_conn_create(iscsi_session_t *session, int cid)
{
	iscsi_conn_t *conn = &session->conn[cid];
	conn_rec_t *conn_rec = &session->nrec.conn[cid];
	int err;

	if (__recvpool_alloc(conn)) {
		log_error("cannot allocate recvpool for conn cid %d", cid);
		return -ENOMEM;
	}

	conn->socket_fd = -1;
	/* connection's timeouts */
	conn->id = cid;
	conn->login_timeout = conn_rec->timeo.login_timeout;
	conn->auth_timeout = conn_rec->timeo.auth_timeout;
	conn->active_timeout = conn_rec->timeo.active_timeout;
	conn->idle_timeout = conn_rec->timeo.idle_timeout;
	conn->ping_timeout = conn_rec->timeo.ping_timeout;

	/* noop-out setting */
	conn->noop_out_interval = conn_rec->timeo.noop_out_interval;
	conn->noop_out_timeout = conn_rec->timeo.noop_out_timeout;

	/* operational parameters */
	conn->max_recv_dlength =
			__padding(conn_rec->iscsi.MaxRecvDataSegmentLength);
	/*
	 * iSCSI default, unless declared otherwise by the
	 * target during login
	 */
	conn->max_xmit_dlength = DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH;
	conn->hdrdgst_en = conn_rec->iscsi.HeaderDigest;
	conn->datadgst_en = conn_rec->iscsi.DataDigest;

	/* TCP options */
	conn->tcp_window_size = conn_rec->tcp.window_size;
	/* FIXME: type_of_service */

	/* resolve the string address to an IP address */
	err = setup_portal(conn, conn_rec);
	if (err)
		return err;

	conn->state = STATE_FREE;
	conn->session = session;

	return 0;
}

static void
__send_pdu_timedout(void *data)
{
	queue_task_t *qtask = data;
	iscsi_conn_t *conn = qtask->conn;
	iscsi_session_t *session = conn->session;

	if (conn->send_pdu_in_progress) {
		/*
		 * redirect timeout processing to __session_conn_timer()
		 */
		queue_produce(session->queue, EV_CONN_TIMER, qtask, 0, NULL);
		actor_schedule(&session->mainloop);
		log_debug(7, "send_pdu timer timedout!");
	}
}

static void
__send_pdu_timer_add(struct iscsi_conn *conn, int timeout)
{
	if (conn->state == STATE_IN_LOGIN) {
		iscsi_login_context_t *c = &conn->login_context;
		conn->send_pdu_in_progress = 1;
		actor_timer(&conn->send_pdu_timer, timeout*1000,
			    __send_pdu_timedout, c->qtask);
		log_debug(7, "send_pdu timer added %d secs", timeout);
	}
}

static void
__send_pdu_timer_remove(struct iscsi_conn *conn)
{
	if (conn->send_pdu_in_progress) {
		actor_delete(&conn->send_pdu_timer);
		conn->send_pdu_in_progress = 0;
		log_debug(7, "send_pdu timer removed");
	}
}


static void
session_conn_destroy(iscsi_session_t *session, int cid)
{
	iscsi_conn_t *conn = &session->conn[cid];

	__send_pdu_timer_remove(conn);
	actor_delete(&conn->connect_timer);
	__recvpool_free(conn);
}

static void
session_put(iscsi_session_t *session)
{
	session->refcount--;
	if (session->refcount == 0) {
		actor_delete(&session->mainloop);
		queue_destroy(session->queue);
		queue_destroy(session->splice_queue);
		free(session);
	}
}

static void
session_get(iscsi_session_t *session)
{
	session->refcount++;
}

static iscsi_session_t*
__session_create(node_rec_t *rec, iscsi_provider_t *provider)
{
	iscsi_session_t *session;

	session = calloc(1, sizeof (*session));
	if (session == NULL) {
		log_debug(1, "can not allocate memory for session");
		return NULL;
	}

	session_get(session);
	/* opened at daemon load time (iscsid.c) */
	session->ctrl_fd = control_fd;
	session->transport_handle = provider->handle;
	session->provider = provider;

	/* save node record. we might need it for redirection */
	memcpy(&session->nrec, rec, sizeof(node_rec_t));

	/* initalize per-session queue */
	session->queue = queue_create(4, 4, NULL, session);
	if (session->queue == NULL) {
		log_error("can not create session's queue");
		free(session);
		return NULL;
	}

	/* initalize per-session tmp queue */
	session->splice_queue = queue_create(4, 4, NULL, session);
	if (session->splice_queue == NULL) {
		log_error("can not create session's splice queue");
		queue_destroy(session->queue);
		free(session);
		return NULL;
	}

	/* initalize per-session event processor */
	actor_new(&session->mainloop, __session_mainloop, session);
	actor_schedule(&session->mainloop);

	/* session's operational parameters */
	session->initial_r2t_en = rec->session.iscsi.InitialR2T;
	session->imm_data_en = rec->session.iscsi.ImmediateData;
	session->first_burst = __padding(rec->session.iscsi.FirstBurstLength);
	session->max_burst = __padding(rec->session.iscsi.MaxBurstLength);
	session->def_time2wait = rec->session.iscsi.DefaultTime2Wait;
	session->def_time2retain = rec->session.iscsi.DefaultTime2Retain;
	session->erl = rec->session.iscsi.ERL;
	session->portal_group_tag = rec->tpgt;
	session->type = ISCSI_SESSION_TYPE_NORMAL;
	session->r_stage = R_STAGE_NO_CHANGE;
	session->initiator_name = dconfig->initiator_name;
	session->initiator_alias = dconfig->initiator_alias;
	strncpy(session->target_name, rec->name, TARGET_NAME_MAXLEN);


	/* session's eh parameters */
	session->replacement_timeout = rec->session.timeo.replacement_timeout;
	if (session->replacement_timeout == 0) {
		log_error("Cannot set replacement_timeout to zero. Setting "
			  "120 seconds\n");
		session->replacement_timeout = 120;
	}

	/* OUI and uniqifying number */
	session->isid[0] = DRIVER_ISID_0;
	session->isid[1] = DRIVER_ISID_1;
	session->isid[2] = DRIVER_ISID_2;
	session->isid[3] = 0;
	session->isid[4] = 0;
	session->isid[5] = 0;

	/* setup authentication variables for the session*/
	__setup_authentication(session, &rec->session.auth);

	session->param_mask = 0xFFFFFFFF;
	if (!(provider->caps & CAP_MULTI_R2T))
		session->param_mask &= ~(1 << ISCSI_PARAM_MAX_R2T);
	if (!(provider->caps & CAP_HDRDGST))
		session->param_mask &= ~(1 << ISCSI_PARAM_HDRDGST_EN);
	if (!(provider->caps & CAP_DATADGST))
		session->param_mask &= ~(1 << ISCSI_PARAM_DATADGST_EN);
	if (!(provider->caps & CAP_MARKERS)) {
		session->param_mask &= ~(1 << ISCSI_PARAM_IFMARKER_EN);
		session->param_mask &= ~(1 << ISCSI_PARAM_OFMARKER_EN);
	}

	insque(&session->item, &provider->sessions);

	return session;
}

static void
__session_destroy(iscsi_session_t *session)
{
	remque(&session->item);
	queue_flush(session->queue);
	queue_flush(session->splice_queue);
	session_put(session);
}

static void
__conn_noop_out_delete(iscsi_conn_t *conn)
{
	if (conn->noop_out_interval) {
		actor_delete(&conn->noop_out_timer);
		actor_delete(&conn->noop_out_timeout_timer);
		log_debug(3, "conn noop out timer %p stopped\n",
				&conn->noop_out_timer);
	}
}

static void
__session_conn_queue_flush(iscsi_conn_t *conn)
{
	iscsi_session_t *session = conn->session;
	int count = session->queue->count, i;
	unsigned char item_buf[sizeof(queue_item_t) + EVENT_PAYLOAD_MAX];
	queue_item_t *item = (queue_item_t *)(void *)item_buf;

	log_debug(3, "flushing per-connection events");

	for (i = 0; i < count; i++) {
		if (queue_consume(session->queue, EVENT_PAYLOAD_MAX,
					item) == QUEUE_IS_EMPTY) {
			log_error("queue damage detected...");
			break;
		}
		if (conn != item->context) {
			queue_produce(session->queue, item->event_type,
				 item->context, item->data_size,
				 queue_item_data(item));
		}
		/* do nothing */
		log_debug(7, "item %p(%d) flushed", item, item->event_type);
	}
}

static int
__session_conn_cleanup(iscsi_conn_t *conn)
{
	iscsi_session_t *session = conn->session;

	iscsi_io_disconnect(conn);
	__conn_noop_out_delete(conn);
	actor_delete(&conn->connect_timer);
	__session_conn_queue_flush(conn);

	if (ipc->destroy_conn(session->transport_handle, session->id,
		conn->id)) {
		log_error("can not safely destroy connection %d", conn->id);
		return MGMT_IPC_ERR_INTERNAL;
	}
	session_conn_destroy(session, conn->id);

	if (ipc->destroy_session(session->transport_handle, session->id)) {
		log_error("can not safely destroy session %d", session->id);
		return MGMT_IPC_ERR_INTERNAL;
	}

	if (conn->id == 0)
		__session_destroy(session);
	return 0;
}

static int
session_conn_cleanup(iscsi_conn_t *conn, int do_stop)
{
	iscsi_session_t *session = conn->session;

	if (do_stop) {
		if (ipc->stop_conn(session->transport_handle, session->id,
				   conn->id, STOP_CONN_TERM)) {
			log_error("can't stop connection %d:%d (%d)",
				  session->id, conn->id, errno);
			return MGMT_IPC_ERR_INTERNAL;
		}
	}

	return __session_conn_cleanup(conn);
}

static void
__session_mgmt_ipc_login_cleanup(queue_task_t *qtask, mgmt_ipc_err_e err,
				 int conn_cleanup)
{
	iscsi_conn_t *conn = qtask->conn;
	iscsi_session_t *session = conn->session;
	iscsi_session_r_stage_e r_stage = session->r_stage;

	if (conn_cleanup)
		__session_conn_cleanup(conn);
	else {
		session_conn_destroy(session, conn->id);
		if (conn->id == 0)
			__session_destroy(session);
	}

	if (r_stage != R_STAGE_SESSION_REOPEN)
		write_mgmt_login_rsp(qtask, err);
}


static int
__send_nopin_rsp(iscsi_conn_t *conn, struct iscsi_nopin *rhdr, char *data)
{
	struct iscsi_nopout hdr;

	memset(&hdr, 0, sizeof(struct iscsi_nopout));
	hdr.opcode = ISCSI_OP_NOOP_OUT | ISCSI_OP_IMMEDIATE;
	hdr.flags = ISCSI_FLAG_CMD_FINAL;
	hdr.dlength[0] = rhdr->dlength[0];
	hdr.dlength[1] = rhdr->dlength[1];
	hdr.dlength[2] = rhdr->dlength[2];
	memcpy(hdr.lun, rhdr->lun, 8);
	hdr.ttt = rhdr->ttt;
	hdr.itt = ISCSI_RESERVED_TAG;

	return iscsi_io_send_pdu(conn, (struct iscsi_hdr*)&hdr,
	       ISCSI_DIGEST_NONE, data, ISCSI_DIGEST_NONE, 0);
}

static int
__send_nopout(iscsi_conn_t *conn)
{
	struct iscsi_nopout hdr;

	memset(&hdr, 0, sizeof(struct iscsi_nopout));
	hdr.opcode = ISCSI_OP_NOOP_OUT | ISCSI_OP_IMMEDIATE;
	hdr.flags = ISCSI_FLAG_CMD_FINAL;
	hdr.itt = 0;  /* XXX: let kernel send_pdu set for us*/
	hdr.ttt = ISCSI_RESERVED_TAG;
	/* we have hdr.lun reserved, and no data */
	return iscsi_io_send_pdu(conn, (struct iscsi_hdr*)&hdr,
		ISCSI_DIGEST_NONE, NULL, ISCSI_DIGEST_NONE, 0);
}

void 
__conn_noop_out_timeout(void *data)
{
	iscsi_conn_t *conn = (iscsi_conn_t*)data;
	iscsi_session_t *session = conn->session;

	log_debug(3, "noop out rsp timeout, closing conn...\n");
	/* XXX: error handle */
	__conn_error_handle(session, conn);
}

void
__conn_noop_out(void *data)
{
	iscsi_conn_t *conn = (iscsi_conn_t*)data;
	__send_nopout(conn);
	if (conn->noop_out_timeout_timer.state == ACTOR_NOTSCHEDULED) {
		actor_timer(&conn->noop_out_timeout_timer,
				conn->noop_out_timeout*1000,
				__conn_noop_out_timeout, conn);
		log_debug(3, "noop out timeout timer %p start\n",
				&conn->noop_out_timeout_timer);
	}
	actor_timer(&conn->noop_out_timer, conn->noop_out_interval*1000,
			__conn_noop_out, data);
}

static void
__connect_timedout(void *data)
{
	queue_task_t *qtask = data;
	iscsi_conn_t *conn = qtask->conn;
	iscsi_session_t *session = conn->session;

	if (conn->state == STATE_XPT_WAIT) {
		log_debug(3, "__connect_timedout queue EV_CONN_TIMER\n");
		queue_produce(session->queue, EV_CONN_TIMER, qtask, 0, NULL);
		actor_schedule(&session->mainloop);
	}
}

static int
__session_conn_reopen(iscsi_conn_t *conn, queue_task_t *qtask, int do_stop)
{
	int rc;
	iscsi_session_t *session = conn->session;

	log_debug(1, "re-opening session %d (reopen_cnt %d)", session->id,
			session->reopen_cnt);

	qtask->conn = conn;

	actor_delete(&conn->connect_timer);
	__conn_noop_out_delete(conn);

	__send_pdu_timer_remove(conn);
	conn->state = STATE_XPT_WAIT;

	if (do_stop) {
		/* state: STATE_CLEANUP_WAIT */
		if (ipc->stop_conn(session->transport_handle, session->id,
				   conn->id, do_stop)) {
			log_error("can't stop connection %d:%d (%d)",
				  session->id, conn->id, errno);
			return -1;
		}
		log_debug(3, "connection %d:%d is stopped for recovery",
			  session->id, conn->id);
		conn->session->provider->utransport->ep_disconnect(conn);
	}

	rc = iscsi_io_tcp_connect(conn, 1);
	if (rc < 0 && errno != EINPROGRESS) {
		char serv[NI_MAXSERV];

		getnameinfo((struct sockaddr *) &conn->saddr,
			    sizeof(conn->saddr),
			    conn->host, sizeof(conn->host), serv, sizeof(serv),
			    NI_NUMERICHOST|NI_NUMERICSERV);

		log_error("cannot make a connection to %s:%s (%d)",
			  conn->host, serv, errno);
		return MGMT_IPC_ERR_TCP_FAILURE;
	}

	queue_produce(session->queue, EV_CONN_POLL, qtask, 0, NULL);
	actor_schedule(&session->mainloop);

	actor_timer(&conn->connect_timer, conn->login_timeout*1000,
		    __connect_timedout, qtask);

	return MGMT_IPC_OK;
}

static int
session_conn_reopen(iscsi_conn_t *conn, queue_task_t *qtask, int do_stop)
{
	iscsi_session_t *session = conn->session;
	int rc;

	session->reopen_cnt++;
	/*
	 * If we were temporarily redirected, we need to fall back to
	 * the original address to see where the target will send us
	 * for the retry
	 */
	memset(&conn->saddr, 0, sizeof(struct sockaddr_storage));
	conn->saddr = conn->failback_saddr;

	rc = __session_conn_reopen(conn, qtask, do_stop);
	if (rc) {
		log_debug(4, "Requeue reopen attempt in %d secs\n", 5);
		actor_delete(&conn->connect_timer);
		actor_timer(&conn->connect_timer, 5*1000, __connect_timedout,
			    qtask);
	}

	return rc;
}

static int
iscsi_login_redirect(iscsi_conn_t *conn)
{
	iscsi_session_t *session = conn->session;
	iscsi_login_context_t *c = &conn->login_context;

	log_debug(3, "login redirect ...\n");

	__session_conn_queue_flush(conn);

	if (session->r_stage == R_STAGE_NO_CHANGE)
		session->r_stage = R_STAGE_SESSION_REDIRECT;

	if (__session_conn_reopen(conn, c->qtask, STOP_CONN_RECOVER)) {
		log_error("redirct __session_conn_reopen failed\n");
		__session_conn_cleanup(conn);
		return 1;
	}

	return 0;
}

static void
print_param_value(enum iscsi_param param, void *value)
{
	log_debug(3, "set operational parameter %d to:", param);

	switch (param) {
	case ISCSI_PARAM_TARGET_NAME:
	case ISCSI_PARAM_PERSISTENT_ADDRESS:
		log_debug(3, "%s", (char *)value);
		break;
	default:
		log_debug(3, "%u", *(uint32_t *)value);
		break;
	}
}

static void
setup_full_feature_phase(iscsi_conn_t *conn)
{
	iscsi_session_t *session = conn->session;
	iscsi_login_context_t *c = &conn->login_context;
	int i, rc;
	uint32_t one = 1, zero = 0;
	struct connparam {
		int param;
		int len;
		void *value;
		int conn_only; } conntbl[ISCSI_PARAM_SESS_RECOVERY_TMO + 1] = {

		{
		.param = ISCSI_PARAM_MAX_RECV_DLENGTH,
		.value = &conn->max_recv_dlength,
		.len = sizeof(conn->max_recv_dlength),
		.conn_only = 1,
		}, {
		.param = ISCSI_PARAM_MAX_XMIT_DLENGTH,
		.value = &conn->max_xmit_dlength,
		.len = sizeof(conn->max_xmit_dlength),
		.conn_only = 1,
		}, {
		.param = ISCSI_PARAM_HDRDGST_EN,
		.value = &conn->hdrdgst_en,
		.len = sizeof(conn->hdrdgst_en),
		.conn_only = 1,
		}, {
		.param = ISCSI_PARAM_DATADGST_EN,
		.value = &conn->datadgst_en,
		.len = sizeof(conn->datadgst_en),
		.conn_only = 1,
		}, {
		.param = ISCSI_PARAM_INITIAL_R2T_EN,
		.value = &session->initial_r2t_en,
		.len = sizeof(session->initial_r2t_en),
		.conn_only = 0,
		}, {
		.param = ISCSI_PARAM_MAX_R2T,
		.value = &one, /* FIXME: session->max_r2t */
		.len = sizeof(uint32_t),
		.conn_only = 0,
		}, {
		.param = ISCSI_PARAM_IMM_DATA_EN,
		.value = &session->imm_data_en,
		.len = sizeof(session->imm_data_en),
		.conn_only = 0,
		}, {
		.param = ISCSI_PARAM_FIRST_BURST,
		.value = &session->first_burst,
		.len = sizeof(session->first_burst),
		.conn_only = 0,
		}, {
		.param = ISCSI_PARAM_MAX_BURST,
		.value = &session->max_burst,
		.len = sizeof(session->max_burst),
		.conn_only = 0,
		}, {
		.param = ISCSI_PARAM_PDU_INORDER_EN,
		.value = &session->pdu_inorder_en,
		.len = sizeof(session->pdu_inorder_en),
		.conn_only = 0,
		}, {
		.param =ISCSI_PARAM_DATASEQ_INORDER_EN,
		.value = &session->dataseq_inorder_en,
		.len = sizeof(session->dataseq_inorder_en),
		.conn_only = 0,
		}, {
		.param = ISCSI_PARAM_ERL,
		.value = &zero, /* FIXME: session->erl */
		.len = sizeof(uint32_t),
		.conn_only = 0,
		}, {
		.param = ISCSI_PARAM_IFMARKER_EN,
		.value = &zero,/* FIXME: session->ifmarker_en */
		.len = sizeof(uint32_t),
		.conn_only = 0,
		}, {
		.param = ISCSI_PARAM_OFMARKER_EN,
		.value = &zero,/* FIXME: session->ofmarker_en */
		.len = sizeof(uint32_t),
		.conn_only = 0,
		}, {
		.param = ISCSI_PARAM_TARGET_NAME,
		.conn_only = 0,
		.len = strlen(session->target_name) + 1,
		.value = session->target_name,
		}, {
		.param = ISCSI_PARAM_TPGT,
		.value = &session->portal_group_tag,
		.len = sizeof(session->portal_group_tag),
		.conn_only = 0,
		}, {
		.param = ISCSI_PARAM_PERSISTENT_ADDRESS,
		.value = session->nrec.conn[conn->id].address,
		.len = NI_MAXHOST,
		.conn_only = 1,
		}, {
		.param = ISCSI_PARAM_PERSISTENT_PORT,
		.value = &session->nrec.conn[conn->id].port,
		.len = sizeof(session->nrec.conn[conn->id].port),
		.conn_only = 1,
		}, {
		.param = ISCSI_PARAM_SESS_RECOVERY_TMO,
		.value = &session->replacement_timeout,
		.len = sizeof(uint32_t),
		.conn_only = 0,
		}

		/*
		 * FIXME: set these timeouts via set_param() API
		 *
		 * rec->session.timeo
		 * rec->session.err_timeo
		 */
	};

	/* almost! entered full-feature phase */
	if (__login_response_status(conn, c->ret) != CONN_LOGIN_SUCCESS) {
		__session_mgmt_ipc_login_cleanup(c->qtask,
						 MGMT_IPC_ERR_LOGIN_FAILURE, 1);
		return;
	}

	/* check the login status */
	if (__check_iscsi_status_class(session, conn->id, c->status_class,
				      c->status_detail) != CONN_LOGIN_SUCCESS) {
		__session_mgmt_ipc_login_cleanup(c->qtask,
						 MGMT_IPC_ERR_LOGIN_FAILURE, 1);
		return;
	}

	/* Entered full-feature phase! */
	for (i = 0; i < ISCSI_PARAM_SESS_RECOVERY_TMO + 1; i++) {
		if (conn->id != 0 && !conntbl[i].conn_only)
			continue;
		if (!(session->param_mask & (1 << conntbl[i].param)))
			continue;

		if (ipc->set_param(session->transport_handle, session->id,
				   conn->id, conntbl[i].param, conntbl[i].value,
				   conntbl[i].len, &rc) || rc) {
			log_error("can't set operational parameter %d for "
				  "connection %d:%d, retcode %d (%d)",
				  conntbl[i].param, session->id, conn->id,
				  rc, errno);

			__session_mgmt_ipc_login_cleanup(c->qtask,
						MGMT_IPC_ERR_LOGIN_FAILURE, 1);
			return;
		}

		print_param_value(conntbl[i].param, conntbl[i].value);
	}

	if (ipc->start_conn(session->transport_handle, session->id, conn->id,
			    &rc) || rc) {
		__session_mgmt_ipc_login_cleanup(c->qtask,
						MGMT_IPC_ERR_INTERNAL, 1);
		log_error("can't start connection %d:%d retcode %d (%d)",
			  session->id, conn->id, rc, errno);
		return;
	}

	conn->state = STATE_LOGGED_IN;
	if (session->r_stage == R_STAGE_NO_CHANGE ||
	    session->r_stage == R_STAGE_SESSION_REDIRECT) {
		/*
		 * scan host is one-time deal. We
		 * don't want to re-scan it on recovery.
		 */
		if (conn->id == 0)
			__session_scan_host(session, c->qtask);

		log_warning("connection%d:%d is operational now",
			    session->id, conn->id);
	} else {
		__session_online_devs(session);
		log_warning("connection%d:%d is operational after recovery "
			    "(%d attempts)", session->id, conn->id,
			     session->reopen_cnt);
	}

	/*
	 * reset ERL=0 reopen counter
	 */
	session->reopen_cnt = 0;
	session->r_stage = R_STAGE_NO_CHANGE;

	/* noop_out */
	if (conn->noop_out_interval) {
		actor_timer(&conn->noop_out_timer, conn->noop_out_interval*1000,
			   __conn_noop_out, conn);
		actor_new(&conn->noop_out_timeout_timer,
			  __conn_noop_out_timeout, conn);
		log_debug(3, "noop out timer %p start\n",
			  &conn->noop_out_timer);
	}
}

static void
__session_conn_recv_pdu(queue_item_t *item)
{
	iscsi_conn_t *conn = item->context;
	iscsi_session_t *session = conn->session;

	conn->recv_handle = *(uintptr_t*)queue_item_data(item);

	if (conn->state == STATE_IN_LOGIN) {
		iscsi_login_context_t *c = &conn->login_context;

		if (iscsi_login_rsp(session, c)) {
			log_debug(1, "login_rsp ret (%d)", c->ret);
			if (c->ret != LOGIN_REDIRECT ||
			    iscsi_login_redirect(conn))				
				__session_mgmt_ipc_login_cleanup(c->qtask,
					MGMT_IPC_ERR_LOGIN_FAILURE, 1);
			return;
		}

		if (conn->current_stage != ISCSI_FULL_FEATURE_PHASE) {
			/* more nego. needed! */
			conn->state = STATE_IN_LOGIN;
			if (iscsi_login_req(session, c)) {
				__session_mgmt_ipc_login_cleanup(c->qtask,
						MGMT_IPC_ERR_LOGIN_FAILURE, 1);
				return;
			}
		} else
			setup_full_feature_phase(conn);

	} else if (conn->state == STATE_LOGGED_IN) {
		struct iscsi_hdr hdr;

		/* read incomming PDU */
		if (!iscsi_io_recv_pdu(conn, &hdr, ISCSI_DIGEST_NONE,conn->data,
			    DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH,
			    ISCSI_DIGEST_NONE, 0)) {
			return;
		}

		if (hdr.opcode == ISCSI_OP_NOOP_IN) {
			if (hdr.ttt == ISCSI_RESERVED_TAG) {
				/* noop out rsp */
				actor_delete(&conn->noop_out_timeout_timer);
			} else /*  noop in req */
				if (!__send_nopin_rsp(conn, 
						(struct iscsi_nopin*)&hdr, 
					      conn->data)) {
				log_error("can not send nopin response");
			}
		} else {
			log_error("unsupported opcode 0x%x", hdr.opcode);
		}
	} else if (conn->state == STATE_XPT_WAIT) {
		log_debug(1, "ignoring incomming PDU in XPT_WAIT. "
			  "let connection re-establish or fail");
		return;
	} else if (conn->state == STATE_CLEANUP_WAIT) {
		log_debug(1, "ignoring incomming PDU in XPT_WAIT. "
			  "let connection cleanup");
		return;
	}
}

static int
__session_node_established(char *node_name)
{
	struct qelem *item;
	int i;

	for (i = 0; i < num_providers; i++) {
		item = provider[i].sessions.q_forw;
		while (item != &provider[i].sessions) {
			iscsi_session_t *session = (iscsi_session_t *)item;
			if (session->conn[0].state == STATE_LOGGED_IN &&
			    !strncmp(session->nrec.name, node_name, TARGET_NAME_MAXLEN))
				return 1;
			item = item->q_forw;
		}
	}
	return 0;
}

static void
setup_kernel_io_callouts(iscsi_conn_t *conn)
{
	conn->kernel_io = 1;
	conn->send_pdu_begin = ipc->send_pdu_begin;
	conn->send_pdu_end = ipc->send_pdu_end;
	conn->recv_pdu_begin = ipc->recv_pdu_begin;
	conn->recv_pdu_end = ipc->recv_pdu_end;
	conn->send_pdu_timer_add = __send_pdu_timer_add;
	conn->send_pdu_timer_remove = __send_pdu_timer_remove;
}

static void
__session_conn_poll(queue_item_t *item)
{
	mgmt_ipc_err_e err = MGMT_IPC_OK;
	queue_task_t *qtask = item->context;
	iscsi_conn_t *conn = qtask->conn;
	iscsi_login_context_t *c = &conn->login_context;
	iscsi_session_t *session = conn->session;
	int rc;

	if (conn->state == STATE_XPT_WAIT) {
		rc = conn->session->provider->utransport->ep_poll(conn, 1);
		if (rc == 0) {
			/* timedout: poll again */
			queue_produce(session->queue, EV_CONN_POLL,
					qtask, 0, NULL);
			actor_schedule(&session->mainloop);
		} else if (rc > 0) {

			/* connected! */

			memset(c, 0, sizeof(iscsi_login_context_t));

			actor_delete(&conn->connect_timer);

			/* do not allocate new connection in case of reopen */
			if (session->r_stage == R_STAGE_NO_CHANGE) {
				if (conn->id == 0 &&
				    ipc->create_session(
					session->transport_handle,
					session->nrec.session.initial_cmdsn,
					&session->id, &session->hostno)) {
					log_error("can't create session (%d)",
						errno);
					err = MGMT_IPC_ERR_INTERNAL;
					goto cleanup;
				}
				log_debug(3, "created new iSCSI session %d",
					  session->id);

				/* unique identifier for OUI */
				if (__session_node_established(
					       session->nrec.name)) {
					log_warning("picking unique OUI for "
					    "the same target node name %s",
					    session->nrec.name);
					session->isid[3] = session->id;
				}

				if (ipc->create_conn(session->transport_handle,
					session->id, conn->id, &conn->id)) {
					log_error("can't create connection (%d)",
						  errno);
					err = MGMT_IPC_ERR_INTERNAL;
					goto s_cleanup;
				}
				log_debug(3, "created new iSCSI connection "
					  "%d:%d", session->id, conn->id);
			}

			if (ipc->bind_conn(session->transport_handle,
				session->id, conn->id, conn->transport_ep_handle,
				(conn->id == 0), &rc) || rc) {
				log_error("can't bind conn %d:%d to "
					  "session %d, retcode %d (%d)",
					  session->id, conn->id, 
					  session->id, rc, errno);
				err = MGMT_IPC_ERR_INTERNAL;
				goto c_cleanup;
			}
			log_debug(3, "bound iSCSI connection %d:%d to "
				  "session %d", 
				  session->id, conn->id, session->id);

			setup_kernel_io_callouts(conn);

			c->qtask = qtask;
			c->cid = conn->id;
			c->buffer = conn->data;
			c->bufsize = sizeof(conn->data);

			if (iscsi_login_begin(session, c)) {
				err = MGMT_IPC_ERR_LOGIN_FAILURE;
				goto c_cleanup;
			}

			conn->state = STATE_IN_LOGIN;
			if (iscsi_login_req(session, c)) {
				err = MGMT_IPC_ERR_LOGIN_FAILURE;
				goto c_cleanup;
			}
		} else {
			actor_delete(&conn->connect_timer);
			/* error during connect */
			err = MGMT_IPC_ERR_TCP_FAILURE;
			goto cleanup;
		}
	}

	return;

c_cleanup:
	if (ipc->destroy_conn(session->transport_handle, session->id,
                conn->id)) {
		log_error("can not safely destroy connection %d:%d",
			  session->id, conn->id);
	}
s_cleanup:
	if (ipc->destroy_session(session->transport_handle, session->id)) {
		log_error("can not safely destroy session %d", session->id);
	}
cleanup:
	__session_mgmt_ipc_login_cleanup(qtask, err, 0);
}

static void
__session_conn_timer(queue_item_t *item)
{
	queue_task_t *qtask = item->context;
	iscsi_conn_t *conn = qtask->conn;
	iscsi_session_t *session = conn->session;

	switch (conn->state) {
	case STATE_XPT_WAIT:
		switch (session->r_stage) {
		case R_STAGE_NO_CHANGE:
		case R_STAGE_SESSION_REDIRECT:
			log_debug(6, "conn_timer popped at XPT_WAIT: login");
			/* timeout during initial connect.
			 * clean connection. write ipc rsp */
			__session_mgmt_ipc_login_cleanup(qtask,
					    MGMT_IPC_ERR_TCP_TIMEOUT, 0);
			break;
		case R_STAGE_SESSION_REOPEN:
			log_debug(6, "conn_timer popped at XPT_WAIT: reopen");
			/* timeout during reopen connect. try again */
			session_conn_reopen(conn, qtask, 0);
			break;
		case R_STAGE_SESSION_CLEANUP:
			session_conn_cleanup(conn, 0);
			break;
		default:
			break;
		}

		break;
	case STATE_IN_LOGIN:
		conn->session->provider->utransport->ep_disconnect(conn);

		switch (session->r_stage) {
		case R_STAGE_NO_CHANGE:
		case R_STAGE_SESSION_REDIRECT:
			log_debug(6, "conn_timer popped at IN_LOGIN: cleanup");
			/*
			 * send pdu timeout. during initial connect clean
			 * connection. write rsp
			 */
			write_mgmt_login_rsp(qtask, MGMT_IPC_ERR_PDU_TIMEOUT);
			__session_conn_cleanup(conn);
			break;
		case R_STAGE_SESSION_REOPEN:
			log_debug(6, "conn_timer popped at IN_LOGIN: reopen");
			session_conn_reopen(conn, qtask, STOP_CONN_RECOVER);
			break;
		case R_STAGE_SESSION_CLEANUP:
			session_conn_cleanup(conn, 1);
			break;
		default:
			break;
		}

		break;
	default:
		log_debug(8, "ignoring timeout in conn state %d\n",
			  conn->state);
		break;
	}
}

static void
__conn_error_handle(iscsi_session_t *session, iscsi_conn_t *conn)
{
	int i;

	switch (conn->state) {
	case STATE_LOGGED_IN:
		/* mark failed connection */
		conn->state = STATE_CLEANUP_WAIT;

		if (session->erl > 0) {
			/* check if we still have some logged in connections */
			for (i=0; i<ISCSI_CONN_MAX; i++) {
				if (session->conn[i].state == STATE_LOGGED_IN) {
					break;
				}
			}
			if (i != ISCSI_CONN_MAX) {
				/* FIXME: re-assign leading connection
				 *        for ERL>0 */
			}

			break;
		} 

		/* mark all connections as failed */
		for (i=0; i<ISCSI_CONN_MAX; i++) {
			if (session->conn[i].state == STATE_LOGGED_IN)
				session->conn[i].state = STATE_CLEANUP_WAIT;
		}
		session->r_stage = R_STAGE_SESSION_REOPEN;
		break;
	case STATE_IN_LOGIN:
		if (session->r_stage == R_STAGE_SESSION_REOPEN) {
			conn->send_pdu_timer_remove(conn);
			session_conn_reopen(conn, &session->reopen_qtask,
					    STOP_CONN_RECOVER);
			return;
		}

		log_debug(1, "ignoring conn error in login. "
			  "let it timeout");
		return;
	case STATE_XPT_WAIT:
		log_debug(1, "ignoring conn error in XPT_WAIT. "
			  "let connection fail on its own");
		return;
	case STATE_CLEANUP_WAIT:
		log_debug(1, "ignoring conn error in CLEANUP_WAIT. "
			  "let connection stop");
		return;
	default:
		log_debug(8, "invalid state %d\n", conn->state);
		return;
	}

	if (session->r_stage == R_STAGE_SESSION_REOPEN) {
		session_conn_reopen(conn, &session->reopen_qtask,
				    STOP_CONN_RECOVER);
		return;
	} else {
		if (ipc->stop_conn(session->transport_handle, session->id,
				   conn->id, STOP_CONN_TERM)) {
			log_error("can't stop connection %d:%d (%d)",
				  session->id, conn->id, errno);
			return;
		}
		log_debug(3, "connection %d:%d is stopped for termination",
			  session->id, conn->id);
		conn->session->provider->utransport->ep_disconnect(conn);
		__session_conn_queue_flush(conn);
	}

	__session_conn_cleanup(conn);
}

static void
__session_conn_error(queue_item_t *item)
{
	enum iscsi_err error = *(enum iscsi_err *)queue_item_data(item);
	iscsi_conn_t *conn = item->context;
	iscsi_session_t *session = conn->session;

	log_warning("detected iSCSI connection %d:%d error (%d) "
		    "state (%d)", session->id, conn->id, error, 
		    conn->state);
	__conn_error_handle(session, conn);

}

static void
__session_mainloop(void *data)
{
	iscsi_session_t *session = data;
	unsigned char item_buf[sizeof(queue_item_t) + EVENT_PAYLOAD_MAX];
	queue_item_t *item = (queue_item_t *)(void *)item_buf;


	/* splice the queue incase one of the events reueues */
	while (queue_consume(session->queue, EVENT_PAYLOAD_MAX,
			     item) != QUEUE_IS_EMPTY)
		queue_produce(session->splice_queue, item->event_type,
			      item->context, item->data_size,
			      queue_item_data(item));

	/*
	 * grab a reference in case one of these events destroys
	 * the session
	 */
	session_get(session);
	while (queue_consume(session->splice_queue, EVENT_PAYLOAD_MAX,
			     item) != QUEUE_IS_EMPTY) {
		switch (item->event_type) {
		case EV_CONN_RECV_PDU:
			__session_conn_recv_pdu(item);
			break;
		case EV_CONN_POLL:
			__session_conn_poll(item);
			break;
		case EV_CONN_TIMER:
			__session_conn_timer(item);
			break;
		case EV_CONN_ERROR:
			__session_conn_error(item);
			break;
		default:
			break;
		}
	}
	session_put(session);
}

iscsi_session_t*
session_find_by_rec(node_rec_t *rec)
{
	iscsi_session_t *session;
	struct qelem *item;
	int i;

	for (i = 0; i < num_providers; i++) {
		item = provider[i].sessions.q_forw;
		while (item != &provider[i].sessions) {
			session = (iscsi_session_t *)item;
			log_debug(6, "looking for session with rec_id [%06x]...",
				  session->nrec.id);
			if (rec->id == session->nrec.id) {
				return session;
			}
			item = item->q_forw;
		}
	}
	return NULL;
}

static iscsi_provider_t*
__get_transport_by_name(char *transport_name)
{
	int i;

	if (ipc->trans_list()) {
		log_error("can't retreive transport list (%d)", errno);
		return NULL;
	}

	for (i = 0; i < num_providers; i++) {
		if (provider[i].handle &&
		   !strncmp(provider[i].name, transport_name,
			     ISCSI_TRANSPORT_NAME_MAXLEN))
			return &provider[i];
	}
	return NULL;
}

int
session_login_task(node_rec_t *rec, queue_task_t *qtask)
{
	int rc;
	iscsi_session_t *session;
	iscsi_conn_t *conn;
	iscsi_provider_t *provider;

	if (!rec->active_conn)
		return MGMT_IPC_ERR_INVAL;

	provider = __get_transport_by_name(rec->transport_name);
	if (!provider)
		return MGMT_IPC_ERR_TRANS_NOT_FOUND;

	if ((!(provider->caps & CAP_RECOVERY_L0) &&
	     rec->session.iscsi.ERL != 0) ||
	    (!(provider->caps & CAP_RECOVERY_L1) &&
	     rec->session.iscsi.ERL > 1)) {
		log_error("transport '%s' does not support ERL %d",
			  provider->name, rec->session.iscsi.ERL);
		return MGMT_IPC_ERR_TRANS_CAPS;
	}

	if (!(provider->caps & CAP_MULTI_R2T) &&
	    rec->session.iscsi.MaxOutstandingR2T) {
		log_error("transport '%s' does not support "
			  "MaxOutstandingR2T %d", provider->name,
			  rec->session.iscsi.MaxOutstandingR2T);
		return MGMT_IPC_ERR_TRANS_CAPS;
	}

	if (!(provider->caps & CAP_HDRDGST) &&
	    rec->conn[0].iscsi.HeaderDigest) {
		log_error("transport '%s' does not support "
			  "HeaderDigest != None", provider->name);
		return MGMT_IPC_ERR_TRANS_CAPS;
	}

	if (!(provider->caps & CAP_DATADGST) &&
	    rec->conn[0].iscsi.DataDigest) {
		log_error("transport '%s' does not support "
			  "DataDigest != None", provider->name);
		return MGMT_IPC_ERR_TRANS_CAPS;
	}

	if (!(provider->caps & CAP_MARKERS) &&
	    rec->conn[0].iscsi.IFMarker) {
		log_error("transport '%s' does not support IFMarker",
			  provider->name);
		return MGMT_IPC_ERR_TRANS_CAPS;
	}

	if (!(provider->caps & CAP_MARKERS) &&
	    rec->conn[0].iscsi.OFMarker) {
		log_error("transport '%s' does not support OFMarker",
			  provider->name);
		return MGMT_IPC_ERR_TRANS_CAPS;
	}

	session = __session_create(rec, provider);
	if (!session)
		return MGMT_IPC_ERR_LOGIN_FAILURE;

	/* FIXME: login all connections! marked as "automatic" */

	/* create leading connection */
	if (__session_conn_create(session, 0)) {
		__session_destroy(session);
		return MGMT_IPC_ERR_LOGIN_FAILURE;
	}
	conn = &session->conn[0];
	qtask->conn = conn;

	rc = session->provider->utransport->ep_connect(conn, 1);
	if (rc < 0 && errno != EINPROGRESS) {
		char serv[NI_MAXSERV];

		getnameinfo((struct sockaddr *) &conn->saddr,
			    sizeof(conn->saddr),
			    conn->host, sizeof(conn->host), serv, sizeof(serv),
			    NI_NUMERICHOST|NI_NUMERICSERV);

		log_error("cannot make a connection to %s:%s (%d)",
			 conn->host, serv, errno);
		session_conn_destroy(session, 0);
		__session_destroy(session);
		return MGMT_IPC_ERR_TCP_FAILURE;
	}

	conn->state = STATE_XPT_WAIT;
	queue_produce(session->queue, EV_CONN_POLL, qtask, 0, NULL);
	actor_schedule(&session->mainloop);

	actor_timer(&conn->connect_timer, conn->login_timeout*1000,
		    __connect_timedout, qtask);

	qtask->u.login.rsp.command = MGMT_IPC_SESSION_LOGIN;
	qtask->u.login.rsp.err = MGMT_IPC_OK;

	return MGMT_IPC_OK;
}

static int
session_find_hostno(uint32_t sid)
{
	DIR *dirfd;
	struct dirent *dent;
	int host_no = -1;

	sprintf(sysfs_file, "/sys/class/iscsi_session/session%d/device", sid);
	dirfd = opendir(sysfs_file);
	if (!dirfd) {
		log_error("Could not open %s err %d\n", sysfs_file, errno);
		return -1;
	}

	while ((dent = readdir(dirfd))) {
		if (strncmp(dent->d_name, "target", 6))
			continue;
		sscanf(dent->d_name, "target%d:0:0", &host_no);
		log_debug(7," Found host_no %d\n", host_no);
		break;
	}
	closedir(dirfd);

	return host_no;
}

#define UPDATE_CONN_PARAM(filename, param)	\
	if (!strcmp(dent->d_name, filename))	\
		read_sysfs_int_attr(sysfs_file, &conn->param)

static int 
sync_conn_params(iscsi_conn_t *conn)
{
	DIR *dirfd;
	struct dirent *dent;
	char *ptr;

	sprintf(sysfs_file, "/sys/class/iscsi_connection/connection%d:%d",
	conn->session->id, conn->id);
	dirfd = opendir(sysfs_file);
	if (!dirfd) {
		log_error("Could not open %s err %d\n", sysfs_file, errno);
		return errno;
	}

	while ((dent = readdir(dirfd))) {
		if (!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, ".."))
			continue;

		strncat(sysfs_file, "/", PATH_MAX);
		strncat(sysfs_file, dent->d_name, PATH_MAX);
		UPDATE_CONN_PARAM("data_digest", datadgst_en);
		UPDATE_CONN_PARAM("header_digest", hdrdgst_en);
		UPDATE_CONN_PARAM("max_recv_dlength", max_recv_dlength);
		UPDATE_CONN_PARAM("max_xmit_dlength", max_xmit_dlength);
		ptr = strrchr(sysfs_file, '/');
		*ptr = '\0';
	}
	closedir(dirfd);
	return 0;
}


static int
sync_conn(iscsi_session_t *session, uint32_t cid)
{
	iscsi_conn_t *conn;

	if (__session_conn_create(session, cid))
		return -ENOMEM;
	conn = &session->conn[cid];

	setup_kernel_io_callouts(conn);
	/* TODO: must export via sysfs so we can pick this up */
	conn->state = STATE_CLEANUP_WAIT;

	if (sync_conn_params(conn))
		goto destroy_conn;

	return 0;

destroy_conn:
	session_conn_destroy(session, cid);
	return -ENODEV;
}

#define UPDATE_SESSION_PARAM(filename, param)	\
	if (!strcmp(dent->d_name, filename))	\
		read_sysfs_int_attr(sysfs_file, (uint32_t *)&session->param)

static int
sync_session_params(iscsi_session_t *session)
{
	DIR *dirfd;
	struct dirent *dent;
	char *ptr;

	sprintf(sysfs_file, "/sys/class/iscsi_session/session%d",
		session->id);
	dirfd = opendir(sysfs_file);
	if (!dirfd) {
		log_error("Could not open %s err %d\n", sysfs_file, errno);
		return errno;
	}

	while ((dent = readdir(dirfd))) {
		if (!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, ".."))
			continue;

		strncat(sysfs_file, "/", PATH_MAX);
		strncat(sysfs_file, dent->d_name, PATH_MAX);
		UPDATE_SESSION_PARAM("data_pdu_in_order", pdu_inorder_en);
		UPDATE_SESSION_PARAM("data_seq_in_order", dataseq_inorder_en);
		UPDATE_SESSION_PARAM("erl", erl);
		UPDATE_SESSION_PARAM("first_burst_len", first_burst);
		UPDATE_SESSION_PARAM("immediate_data", imm_data_en);
		UPDATE_SESSION_PARAM("initial_r2t", initial_r2t_en);
		UPDATE_SESSION_PARAM("max_burst_len", max_burst);
		ptr = strrchr(sysfs_file, '/');
		*ptr = '\0';
	}
	closedir(dirfd);
	return 0;
}

int
iscsi_sync_session(node_rec_t *rec, uint32_t sid)
{
	iscsi_session_t *session;
	iscsi_provider_t *provider;
	int err;

	provider = __get_transport_by_name(rec->transport_name);
	if (!provider)
		return -EINVAL;

	session = __session_create(rec, provider);
	if (!session)
		return -ENOMEM;

	session->id = sid;
	session->hostno = session_find_hostno(sid);
	if (session->hostno < 0) {
		log_error("Could not get hostno for session %d\n", sid);
		err = -ENODEV;
		goto destroy_session;
	}

	session->r_stage = R_STAGE_SESSION_REOPEN;

	err = sync_session_params(session);
	if (err)
		goto destroy_session;

	err = sync_conn(session, 0);
	if (err)
		goto destroy_session;

	/*
	 * we must force a relogin to sync us up with the kernel,
	 * just in case it is starting recovery now or is in recovery
	 * already.
	 *
	 * TODO: export session state and only reopen when not logged in
	 */
	session_conn_reopen(&session->conn[0], &session->reopen_qtask,
			    STOP_CONN_RECOVER);
	log_debug(3, "synced iSCSI session %d", session->id);
	return 0;

destroy_session:
	__session_destroy(session);
	log_error("Could not sync session%d err %d\n", sid, err);
	return err;
}

int
session_logout_task(iscsi_session_t *session, queue_task_t *qtask)
{
	iscsi_conn_t *conn;
	int rc = MGMT_IPC_OK;
	int stop = 0;

	conn = &session->conn[0];
	if (conn->state == STATE_XPT_WAIT &&
	    (session->r_stage == R_STAGE_NO_CHANGE ||
	     session->r_stage == R_STAGE_SESSION_REDIRECT)) {
		log_error("session in invalid state for logout. "
			   "Try again later\n");
		rc = MGMT_IPC_ERR_INTERNAL;
		goto done;
	}

	/* FIXME: logout all active connections */
	conn = &session->conn[0];
	/* FIXME: implement Logout Request */

	__session_delete_devs(session);

	if (conn->state == STATE_LOGGED_IN ||
	    conn->state == STATE_IN_LOGIN)
		stop = 1;

	rc = session_conn_cleanup(conn, stop);
	if (rc) {
		log_error("session cleanup failed during logout\n");
		goto done;
	}

	qtask->u.login.rsp.err = rc;
	qtask->u.login.rsp.command = MGMT_IPC_SESSION_LOGOUT;
	write(qtask->u.login.mgmt_ipc_fd, &qtask->u.login.rsp,
		sizeof(qtask->u.login.rsp));
	close(qtask->u.login.mgmt_ipc_fd);
	free(qtask);
done:
	return rc;
}
