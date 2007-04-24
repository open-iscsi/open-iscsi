/*
 * iSCSI Session Management and Slow-path Control
 *
 * Copyright (C) 2004 Dmitry Yusupov, Alex Aizman
 * Copyright (C) 2006 Mike Christie
 * Copyright (C) 2006 Red Hat, Inc. All rights reserved.
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
#include "iscsi_sysfs.h"
#include "iscsi_settings.h"

static void __session_mainloop(void *data);
static void __conn_error_handle(iscsi_session_t*, iscsi_conn_t*);

#define DEFAULT_TIME2WAIT 2

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

static void
__session_online_devs(iscsi_session_t *session)
{
	sysfs_for_each_device(session->hostno, session->id,
			      set_device_online);
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
		return CONN_LOGIN_RETRY;
	default:
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
			return CONN_LOGIN_RETRY;
		}
	case ISCSI_STATUS_CLS_INITIATOR_ERR:
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
		/*
		 * We have no idea what the problem is. But spec says initiator
		 * may retry later.
		 */
		 return CONN_LOGIN_RETRY;
	default:
		log_error("conn %d login response with unknown status "
		       "class 0x%x, detail 0x%x\n", conn->id, status_class,
		       status_detail);
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
	conn->logout_timeout = conn_rec->timeo.logout_timeout;
	if (!conn->logout_timeout) {
		log_error("Invalid timeo.logout_timeout. Must be greater "
			  "than zero. Using default %d.\n",
			  DEF_LOGOUT_TIMEO);
		conn->logout_timeout = DEF_LOGOUT_TIMEO;
	}

	conn->login_timeout = conn_rec->timeo.login_timeout;
	if (!conn->login_timeout) {
		log_error("Invalid timeo.login_timeout. Must be greater "
			  "than zero. Using default %d.\n",
			  DEF_LOGIN_TIMEO);
		conn->login_timeout = DEF_LOGIN_TIMEO;
	}

	/* noop-out setting */
	conn->noop_out_interval = conn_rec->timeo.noop_out_interval;
	conn->noop_out_timeout = conn_rec->timeo.noop_out_timeout;
	if (conn->noop_out_interval && !conn->noop_out_timeout) {
		log_error("Invalid timeo.noop_out_timeout. Must be greater "
			  "than zero. Using default %d.\n",
			  DEF_NOOP_OUT_TIMEO);
		conn->noop_out_timeout = DEF_NOOP_OUT_TIMEO;
	}

	if (conn->noop_out_timeout && !conn->noop_out_interval) {
		log_error("Invalid timeo.noop_out_interval. Must be greater "
			  "than zero. Using default %d.\n",
			  DEF_NOOP_OUT_INTERVAL);
		conn->noop_out_timeout = DEF_NOOP_OUT_INTERVAL;
	}

	/*
	 * currently not used (leftover from linux-iscsi which we
	 * may do one day)
	 */
	conn->auth_timeout = conn_rec->timeo.auth_timeout;
	conn->active_timeout = conn_rec->timeo.active_timeout;
	conn->idle_timeout = conn_rec->timeo.idle_timeout;
	conn->ping_timeout = conn_rec->timeo.ping_timeout;

	/* operational parameters */
	conn->max_recv_dlength =
			__padding(conn_rec->iscsi.MaxRecvDataSegmentLength);
	if (conn->max_recv_dlength < ISCSI_MIN_MAX_RECV_SEG_LEN ||
	    conn->max_recv_dlength > ISCSI_MAX_MAX_RECV_SEG_LEN) {
		log_error("Invalid iscsi.MaxRecvDataSegmentLength. Must be "
			 "within %u and %u. Setting to %u\n",
			  ISCSI_MIN_MAX_RECV_SEG_LEN,
			  ISCSI_MAX_MAX_RECV_SEG_LEN,
			  DEF_INI_MAX_RECV_SEG_LEN);
		conn->max_recv_dlength = DEF_INI_MAX_RECV_SEG_LEN;
	}

	/*
	 * iSCSI default, unless declared otherwise by the
	 * target during login
	 */
	conn->max_xmit_dlength = ISCSI_DEF_MAX_RECV_SEG_LEN;
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
	session->reopen_qtask.mgmt_ipc_fd = -1;

	/* save node record. we might need it for redirection */
	memcpy(&session->nrec, rec, sizeof(node_rec_t));

	/* initalize per-session queue */
	session->queue = queue_create(4, 4, NULL, session);
	if (session->queue == NULL) {
		log_error("can not create session's queue");
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
	if (session->first_burst < ISCSI_MIN_FIRST_BURST_LEN ||
	    session->first_burst > ISCSI_MAX_FIRST_BURST_LEN) {
		log_error("Invalid iscsi.FirstBurstLength of %u. Must be "
			 "within %u and %u. Setting to %u\n",
			  session->first_burst,
			  ISCSI_MIN_FIRST_BURST_LEN,
			  ISCSI_MAX_FIRST_BURST_LEN,
			  DEF_INI_FIRST_BURST_LEN);
		session->first_burst = DEF_INI_FIRST_BURST_LEN;
	}

	session->max_burst = __padding(rec->session.iscsi.MaxBurstLength);
	if (session->max_burst < ISCSI_MIN_MAX_BURST_LEN ||
	    session->max_burst > ISCSI_MAX_MAX_BURST_LEN) {
		log_error("Invalid iscsi.MaxBurstLength of %u. Must be "
			  "within %u and %u. Setting to %u\n",
			   session->max_burst, ISCSI_MIN_MAX_BURST_LEN,
			   ISCSI_MAX_MAX_BURST_LEN, DEF_INI_MAX_BURST_LEN);
		session->max_burst = DEF_INI_MAX_BURST_LEN;
	}

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
		session->replacement_timeout = DEF_REPLACEMENT_TIMEO;
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
	log_debug(1, "destroying session\n");
	remque(&session->item);
	queue_flush(session->queue);
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
session_conn_cleanup(queue_task_t *qtask, mgmt_ipc_err_e err)
{
	iscsi_conn_t *conn = qtask->conn;
	iscsi_session_t *session = conn->session;

	mgmt_ipc_write_rsp(qtask, err);
	session_conn_destroy(session, conn->id);
	if (conn->id == 0)
		__session_destroy(session);
}

static mgmt_ipc_err_e
__session_conn_shutdown(iscsi_conn_t *conn, queue_task_t *qtask,
			mgmt_ipc_err_e err)
{
	iscsi_session_t *session = conn->session;

	__conn_noop_out_delete(conn);
	actor_delete(&conn->connect_timer);
	queue_flush(session->queue);

	if (ipc->destroy_conn(session->transport_handle, session->id,
		conn->id)) {
		log_error("can not safely destroy connection %d", conn->id);
		return MGMT_IPC_ERR_INTERNAL;
	}
	conn->session->provider->utransport->ep_disconnect(conn);

	if (ipc->destroy_session(session->transport_handle, session->id)) {
		log_error("can not safely destroy session %d", session->id);
		return MGMT_IPC_ERR_INTERNAL;
	}

	session_conn_cleanup(qtask, err);
	return MGMT_IPC_OK;
}

static mgmt_ipc_err_e
session_conn_shutdown(iscsi_conn_t *conn, queue_task_t *qtask,
		      mgmt_ipc_err_e err)
{
	iscsi_session_t *session = conn->session;

	if (ipc->stop_conn(session->transport_handle, session->id,
			   conn->id, STOP_CONN_TERM)) {
		log_error("can't stop connection %d:%d (%d)",
			  session->id, conn->id, errno);
		return MGMT_IPC_ERR_INTERNAL;
	}

	return __session_conn_shutdown(conn, qtask, err);
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

	log_warning("Nop-out timedout after %d seconds on connection %d:%d "
		    "state (%d). Dropping session.", conn->noop_out_timeout,
		    session->id, conn->id, conn->state);
	/* XXX: error handle */
	__conn_error_handle(session, conn);
}

void
__conn_noop_out(void *data)
{
	iscsi_conn_t *conn = (iscsi_conn_t*)data;

	if (conn->noop_out_timeout_timer.state == ACTOR_NOTSCHEDULED) {
		__send_nopout(conn);

		actor_timer(&conn->noop_out_timeout_timer,
				conn->noop_out_timeout*1000,
				__conn_noop_out_timeout, conn);
		log_debug(3, "noop out timeout timer %p start, timeout %d\n",
			 &conn->noop_out_timeout_timer, conn->noop_out_timeout);
	}
}

static void
__connect_timedout(void *data)
{
	queue_task_t *qtask = data;
	iscsi_conn_t *conn = qtask->conn;
	iscsi_session_t *session = conn->session;

	if (conn->state == STATE_XPT_WAIT) {
		/* flush any polls or other events queued */
		queue_flush(session->queue);
		log_debug(3, "__connect_timedout queue EV_CONN_TIMER\n");
		queue_produce(session->queue, EV_CONN_TIMER, qtask, 0, NULL);
		actor_schedule(&session->mainloop);
	}
}

static void
queue_delayed_reopen(queue_task_t *qtask, int delay)
{
	iscsi_conn_t *conn = qtask->conn;

	log_debug(4, "Requeue reopen attempt in %d secs\n", delay);
	actor_delete(&conn->connect_timer);
	actor_timer(&conn->connect_timer, delay * 1000,
		    __connect_timedout, qtask);
}

static void
reset_iscsi_params(iscsi_conn_t *conn)
{
	iscsi_session_t *session = conn->session;
	conn_rec_t *conn_rec = &session->nrec.conn[conn->id];
	node_rec_t *rec = &session->nrec;

	/* operational parameters */
	conn->max_recv_dlength =
			__padding(conn_rec->iscsi.MaxRecvDataSegmentLength);
	/*
	 * iSCSI default, unless declared otherwise by the
	 * target during login
	 */
	conn->max_xmit_dlength = ISCSI_DEF_MAX_RECV_SEG_LEN;
	conn->hdrdgst_en = conn_rec->iscsi.HeaderDigest;
	conn->datadgst_en = conn_rec->iscsi.DataDigest;

	/* session's operational parameters */
	session->initial_r2t_en = rec->session.iscsi.InitialR2T;
	session->imm_data_en = rec->session.iscsi.ImmediateData;
	session->first_burst = __padding(rec->session.iscsi.FirstBurstLength);
	session->max_burst = __padding(rec->session.iscsi.MaxBurstLength);
	session->def_time2wait = rec->session.iscsi.DefaultTime2Wait;
	session->def_time2retain = rec->session.iscsi.DefaultTime2Retain;
	session->erl = rec->session.iscsi.ERL;
}

static int
__session_conn_reopen(iscsi_conn_t *conn, queue_task_t *qtask, int do_stop)
{
	int rc, delay;
	iscsi_session_t *session = conn->session;

	log_debug(1, "re-opening session %d (reopen_cnt %d)", session->id,
			session->reopen_cnt);

	reset_iscsi_params(conn);
	qtask->conn = conn;

	/* flush stale polls or errors queued */
	queue_flush(session->queue);
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
			goto queue_reopen;
		}
		log_debug(3, "connection %d:%d is stopped for recovery",
			  session->id, conn->id);
	}
	conn->session->provider->utransport->ep_disconnect(conn);

	if (session->time2wait)
		goto queue_reopen;

	rc = conn->session->provider->utransport->ep_connect(conn, 1);
	if (rc < 0 && errno != EINPROGRESS) {
		char serv[NI_MAXSERV];

		getnameinfo((struct sockaddr *) &conn->saddr,
			    sizeof(conn->saddr),
			    conn->host, sizeof(conn->host), serv, sizeof(serv),
			    NI_NUMERICHOST|NI_NUMERICSERV);

		log_error("cannot make a connection to %s:%s (%d)",
			  conn->host, serv, errno);
		goto queue_reopen;
	}

	queue_produce(session->queue, EV_CONN_POLL, qtask, 0, NULL);
	actor_schedule(&session->mainloop);

	actor_timer(&conn->connect_timer, conn->login_timeout*1000,
		    __connect_timedout, qtask);

	return 0;

queue_reopen:
	if (session->time2wait) {
		rc = 0;
		delay = session->time2wait;
	} else {
		rc = -1;
		delay = DEFAULT_TIME2WAIT;
	}
	session->time2wait = 0;
	queue_delayed_reopen(qtask, delay);
	return rc;
}

static int
session_conn_reopen(iscsi_conn_t *conn, queue_task_t *qtask, int do_stop)
{
	iscsi_session_t *session = conn->session;

	session->reopen_cnt++;
	/*
	 * If we were temporarily redirected, we need to fall back to
	 * the original address to see where the target will send us
	 * for the retry
	 */
	memset(&conn->saddr, 0, sizeof(struct sockaddr_storage));
	conn->saddr = conn->failback_saddr;

	return __session_conn_reopen(conn, qtask, do_stop);
}

static int
iscsi_login_redirect(iscsi_conn_t *conn)
{
	iscsi_session_t *session = conn->session;
	iscsi_login_context_t *c = &conn->login_context;

	log_debug(3, "login redirect ...\n");

	queue_flush(session->queue);

	if (session->r_stage == R_STAGE_NO_CHANGE)
		session->r_stage = R_STAGE_SESSION_REDIRECT;

	if (__session_conn_reopen(conn, c->qtask, STOP_CONN_RECOVER)) {
		log_error("redirct __session_conn_reopen failed\n");
		return 1;
	}

	return 0;
}

static void
print_param_value(enum iscsi_param param, void *value, int type)
{
	log_debug(3, "set operational parameter %d to:", param);

	if (type == ISCSI_STRING)
		log_debug(3, "%s", value ? (char *)value : "NULL");
	else
		log_debug(3, "%u", *(uint32_t *)value);
}

static void
__session_scan_host(iscsi_session_t *session, queue_task_t *qtask)
{
	pid_t pid;

	pid = scan_host(session);
	if (pid == 0) {
		mgmt_ipc_write_rsp(qtask, MGMT_IPC_OK);
		exit(0);
	} else if (pid > 0) {
		close(qtask->mgmt_ipc_fd);
		need_reap();
		free(qtask);
	} else
		mgmt_ipc_write_rsp(qtask, MGMT_IPC_ERR_INTERNAL);
}

#define MAX_SESSION_PARAMS 24
#define MAX_HOST_PARAMS 2

static void
setup_full_feature_phase(iscsi_conn_t *conn)
{
	iscsi_session_t *session = conn->session;
	iscsi_login_context_t *c = &conn->login_context;
	int i, rc;
	uint32_t one = 1, zero = 0;
	struct hostparam {
		int param;
		int type;
		void *value;
	} hosttbl[MAX_HOST_PARAMS] = {
		{
			.param = ISCSI_HOST_PARAM_HWADDRESS,
			.value = session->nrec.iface.name,
			.type = ISCSI_STRING,
		}, {
			.param = ISCSI_HOST_PARAM_INITIATOR_NAME,
			.value = session->initiator_name,
			.type = ISCSI_STRING,
		},
	};
	struct connparam {
		int param;
		int type;
		void *value;
		int conn_only;
	} conntbl[MAX_SESSION_PARAMS] = {
		{
			.param = ISCSI_PARAM_MAX_RECV_DLENGTH,
			.value = &conn->max_recv_dlength,
			.type = ISCSI_INT,
			.conn_only = 0,
		}, {
			.param = ISCSI_PARAM_MAX_XMIT_DLENGTH,
			.value = &conn->max_xmit_dlength,
			.type = ISCSI_INT,
			.conn_only = 0,
		}, {
			.param = ISCSI_PARAM_HDRDGST_EN,
			.value = &conn->hdrdgst_en,
			.type = ISCSI_INT,
			.conn_only = 0,
		}, {
			.param = ISCSI_PARAM_DATADGST_EN,
			.value = &conn->datadgst_en,
			.type = ISCSI_INT,
			.conn_only = 1,
		}, {
			.param = ISCSI_PARAM_INITIAL_R2T_EN,
			.value = &session->initial_r2t_en,
			.type = ISCSI_INT,
			.conn_only = 0,
		}, {
			.param = ISCSI_PARAM_MAX_R2T,
			.value = &one, /* FIXME: session->max_r2t */
			.type = ISCSI_INT,
			.conn_only = 0,
		}, {
			.param = ISCSI_PARAM_IMM_DATA_EN,
			.value = &session->imm_data_en,
			.type = ISCSI_INT,
			.conn_only = 0,
		}, {
			.param = ISCSI_PARAM_FIRST_BURST,
			.value = &session->first_burst,
			.type = ISCSI_INT,
			.conn_only = 0,
		}, {
			.param = ISCSI_PARAM_MAX_BURST,
			.value = &session->max_burst,
			.type = ISCSI_INT,
			.conn_only = 0,
		}, {
			.param = ISCSI_PARAM_PDU_INORDER_EN,
			.value = &session->pdu_inorder_en,
			.type = ISCSI_INT,
			.conn_only = 0,
		}, {
			.param =ISCSI_PARAM_DATASEQ_INORDER_EN,
			.value = &session->dataseq_inorder_en,
			.type = ISCSI_INT,
			.conn_only = 0,
		}, {
			.param = ISCSI_PARAM_ERL,
			.value = &zero, /* FIXME: session->erl */
			.type = ISCSI_INT,
			.conn_only = 0,
		}, {
			.param = ISCSI_PARAM_IFMARKER_EN,
			.value = &zero,/* FIXME: session->ifmarker_en */
			.type = ISCSI_INT,
			.conn_only = 0,
		}, {
			.param = ISCSI_PARAM_OFMARKER_EN,
			.value = &zero,/* FIXME: session->ofmarker_en */
			.type = ISCSI_INT,
			.conn_only = 0,
		}, {
			.param = ISCSI_PARAM_EXP_STATSN,
			.value = &conn->exp_statsn,
			.type = ISCSI_INT,
			.conn_only = 1,
		}, {
			.param = ISCSI_PARAM_TARGET_NAME,
			.conn_only = 0,
			.type = ISCSI_STRING,
			.value = session->target_name,
		}, {
			.param = ISCSI_PARAM_TPGT,
			.value = &session->portal_group_tag,
			.type = ISCSI_INT,
			.conn_only = 0,
		}, {
			.param = ISCSI_PARAM_PERSISTENT_ADDRESS,
			.value = session->nrec.conn[conn->id].address,
			.type = ISCSI_STRING,
			.conn_only = 1,
		}, {
			.param = ISCSI_PARAM_PERSISTENT_PORT,
			.value = &session->nrec.conn[conn->id].port,
			.type = ISCSI_INT,
			.conn_only = 1,
		}, {
			.param = ISCSI_PARAM_SESS_RECOVERY_TMO,
			.value = &session->replacement_timeout,
			.type = ISCSI_INT,
			.conn_only = 0,
		}, {
			.param = ISCSI_PARAM_USERNAME,
			.value = session->username,
			.type = ISCSI_STRING,
			.conn_only = 0,
		}, {
			.param = ISCSI_PARAM_USERNAME_IN,
			.value = session->username_in,
			.type = ISCSI_STRING,
			.conn_only = 0,
		}, {
			.param = ISCSI_PARAM_PASSWORD,
			.value = session->password,
			.type = ISCSI_STRING,
			.conn_only = 0,
		}, {
			.param = ISCSI_PARAM_PASSWORD_IN,
			.value = session->password_in,
			.type = ISCSI_STRING,
			.conn_only = 0,
		},
		/*
		 * FIXME: set these timeouts via set_param() API
		 *
		 * rec->session.timeo
		 * rec->session.err_timeo
		 */
	};

	/* almost! entered full-feature phase */
	if (__login_response_status(conn, c->ret) != CONN_LOGIN_SUCCESS) {
		__session_conn_shutdown(conn, c->qtask,
				        MGMT_IPC_ERR_LOGIN_FAILURE);
		return;
	}

	/* check the login status */
	if (__check_iscsi_status_class(session, conn->id, c->status_class,
				      c->status_detail) != CONN_LOGIN_SUCCESS) {
		__session_conn_shutdown(conn, c->qtask,
				        MGMT_IPC_ERR_LOGIN_FAILURE);
		return;
	}

	/* Entered full-feature phase! */
	for (i = 0; i < MAX_SESSION_PARAMS; i++) {
		if (conn->id != 0 && !conntbl[i].conn_only)
			continue;
		if (!(session->param_mask & (1 << conntbl[i].param)))
			continue;

		rc = ipc->set_param(session->transport_handle, session->id,
				   conn->id, conntbl[i].param, conntbl[i].value,
				   conntbl[i].type);
		if (rc && rc != -ENOSYS) {
			log_error("can't set operational parameter %d for "
				  "connection %d:%d, retcode %d (%d)",
				  conntbl[i].param, session->id, conn->id,
				  rc, errno);

			__session_conn_shutdown(conn, c->qtask,
					       MGMT_IPC_ERR_LOGIN_FAILURE);
			return;
		}

		print_param_value(conntbl[i].param, conntbl[i].value,
				  conntbl[i].type);
	}

	for (i = 0; i < MAX_HOST_PARAMS; i++) {
		rc = ipc->set_host_param(session->transport_handle,
					 session->hostno, hosttbl[i].param,
					 hosttbl[i].value, hosttbl[i].type);
		/* 2.6.20 and below returns EINVAL */
		if (rc && rc != -ENOSYS && rc != -EINVAL) {
			log_error("can't set operational parameter %d for "
				  "host %d, retcode %d (%d)",
				  conntbl[i].param, session->hostno,
				  rc, errno);

			__session_conn_shutdown(conn, c->qtask,
					       MGMT_IPC_ERR_LOGIN_FAILURE);
			return;
		}

		print_param_value(conntbl[i].param, conntbl[i].value,
				  conntbl[i].type);
	}

	if (ipc->start_conn(session->transport_handle, session->id, conn->id,
			    &rc) || rc) {
		__session_conn_shutdown(conn, c->qtask,
				       MGMT_IPC_ERR_INTERNAL);
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
		session->sync_qtask = NULL;

		__session_online_devs(session);
		mgmt_ipc_write_rsp(c->qtask, MGMT_IPC_OK);
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

static void iscsi_logout_timeout(void *data)
{
	iscsi_conn_t *conn = data;

	/*
	 * assume we were in STATE_IN_LOGOUT or there
	 * was some nasty error
	 */
	log_debug(3, "logout timeout, dropping conn...\n");
	__conn_error_handle(conn->session, conn);
}

static int iscsi_send_logout(iscsi_conn_t *conn)
{
	struct iscsi_logout hdr;

	if (conn->state == STATE_IN_LOGOUT ||
	    conn->state != STATE_LOGGED_IN)
		return -EINVAL;

	memset(&hdr, 0, sizeof(struct iscsi_logout));
	hdr.opcode = ISCSI_OP_LOGOUT | ISCSI_OP_IMMEDIATE;
	hdr.flags = ISCSI_FLAG_CMD_FINAL |
	   (ISCSI_LOGOUT_REASON_CLOSE_SESSION & ISCSI_FLAG_LOGOUT_REASON_MASK);
	/* kernel will set the rest */

	if (!iscsi_io_send_pdu(conn, (struct iscsi_hdr*)&hdr,
			       ISCSI_DIGEST_NONE, NULL, ISCSI_DIGEST_NONE, 0))
		return -EIO;
	conn->state = STATE_IN_LOGOUT;

	actor_timer(&conn->logout_timer, conn->logout_timeout * 1000,
		    iscsi_logout_timeout, conn);
	log_debug(3, "logout timeout timer %p start\n", &conn->logout_timer);
	return 0;
}

static void iscsi_recv_nop_in(iscsi_conn_t *conn, struct iscsi_hdr *hdr)
{
	if (hdr->ttt == ISCSI_RESERVED_TAG) {
		/* noop out rsp */
		actor_delete(&conn->noop_out_timeout_timer);
		/* schedule a new ping */
		actor_timer(&conn->noop_out_timer, conn->noop_out_interval*1000,
			    __conn_noop_out, conn);
	} else /*  noop in req */
		if (!__send_nopin_rsp(conn, (struct iscsi_nopin*)hdr,
				      conn->data)) {
			log_error("can not send nopin response");
		}
}

static void iscsi_recv_logout_rsp(iscsi_conn_t *conn, struct iscsi_hdr *hdr)
{
	log_debug(3, "Recv: logout response\n");
	/* TODO process the hdr */
	__conn_error_handle(conn->session, conn);
}

static void iscsi_recv_async_msg(iscsi_conn_t *conn, struct iscsi_hdr *hdr)
{
	iscsi_session_t *session = conn->session;
	struct iscsi_async *async_hdr = (struct iscsi_async *)hdr;
	char *buf = conn->data;
	unsigned int senselen;

	log_debug(3, "Read AEN %d\n", async_hdr->async_event);

	switch (async_hdr->async_event) {
	case ISCSI_ASYNC_MSG_SCSI_EVENT:
		senselen = (buf[0] << 8) | buf[1];
		buf += 2;

		/* TODO: do something with it */
		break;
	case ISCSI_ASYNC_MSG_REQUEST_LOGOUT:
		log_warning("Target requests logout within %u seconds for "
			   "connection\n", ntohs(async_hdr->param3));
		if (iscsi_send_logout(conn))
			log_error("Could not send logout in response to"
				 "logout request aen\n");
		break;
	case ISCSI_ASYNC_MSG_DROPPING_CONNECTION:
		log_warning("Target dropping connection %u, reconnect min %u "
			    "max %u\n", ntohs(async_hdr->param1),
			    ntohs(async_hdr->param2), ntohs(async_hdr->param3));
		session->time2wait =
			(uint32_t)ntohs(async_hdr->param2) & 0x0000FFFFFL;
		break;
	case ISCSI_ASYNC_MSG_DROPPING_ALL_CONNECTIONS:
		log_warning("Target dropping all connections, reconnect min %u "
			    "max %u\n", ntohs(async_hdr->param2),
			     ntohs(async_hdr->param3));
		session->time2wait =
			(uint32_t)ntohs(async_hdr->param2) & 0x0000FFFFFL;
		break;
	case ISCSI_ASYNC_MSG_PARAM_NEGOTIATION:
		log_warning("Received async event param negotiation, "
			    "dropping session\n");
		__conn_error_handle(session, conn);
		break;
	case ISCSI_ASYNC_MSG_VENDOR_SPECIFIC:
	default:
		log_warning("AEN not supported\n");
	}
}

static void
__session_conn_recv_pdu(queue_item_t *item)
{
	iscsi_conn_t *conn = item->context;
	iscsi_session_t *session = conn->session;
	iscsi_login_context_t *c;
	struct iscsi_hdr hdr;

	conn->recv_handle = *(uintptr_t*)queue_item_data(item);

	switch (conn->state) {
	case STATE_IN_LOGIN:
		c = &conn->login_context;

		if (iscsi_login_rsp(session, c)) {
			log_debug(1, "login_rsp ret (%d)", c->ret);
			if (c->ret != LOGIN_REDIRECT ||
			    iscsi_login_redirect(conn))
				__session_conn_shutdown(conn, c->qtask,
					MGMT_IPC_ERR_LOGIN_FAILURE);
			return;
		}

		if (conn->current_stage != ISCSI_FULL_FEATURE_PHASE) {
			/* more nego. needed! */
			conn->state = STATE_IN_LOGIN;
			if (iscsi_login_req(session, c)) {
				__session_conn_shutdown(conn, c->qtask,
						MGMT_IPC_ERR_LOGIN_FAILURE);
				return;
			}
		} else
			setup_full_feature_phase(conn);
		break;
	case STATE_LOGGED_IN:
	case STATE_IN_LOGOUT:
	case STATE_LOGOUT_REQUESTED:
		/* read incomming PDU */
		if (!iscsi_io_recv_pdu(conn, &hdr, ISCSI_DIGEST_NONE,
			    conn->data, ISCSI_DEF_MAX_RECV_SEG_LEN,
			    ISCSI_DIGEST_NONE, 0)) {
			return;
		}

		switch (hdr.opcode & ISCSI_OPCODE_MASK) {
		case ISCSI_OP_NOOP_IN:
			iscsi_recv_nop_in(conn, &hdr);
			break;
		case ISCSI_OP_LOGOUT_RSP:
			iscsi_recv_logout_rsp(conn, &hdr);
			break;
		case ISCSI_OP_ASYNC_EVENT:
			iscsi_recv_async_msg(conn, &hdr);
			break;
		default:
			log_error("unsupported opcode 0x%x", hdr.opcode);
			break;
		}
		break;
	case STATE_XPT_WAIT:
		recvpool_put(conn, (void *)conn->recv_handle);
		log_debug(1, "ignoring incomming PDU in XPT_WAIT. "
			  "let connection re-establish or fail");
		break;
	case STATE_CLEANUP_WAIT:
		recvpool_put(conn, (void *)conn->recv_handle);
		log_debug(1, "ignoring incomming PDU in XPT_WAIT. "
			  "let connection cleanup");
		break;
	default:
		recvpool_put(conn, (void *)conn->recv_handle);
		log_error("Invalid state. Dropping PDU.\n");
	}
}

static int
__session_node_established(char *node_name)
{
	iscsi_provider_t *p;
	struct qelem *sitem, *pitem;

	pitem = providers.q_forw;
	while (pitem != &providers) {
		p = (iscsi_provider_t *)pitem;

		sitem = p->sessions.q_forw;
		while (sitem != &p->sessions) {
			iscsi_session_t *session = (iscsi_session_t *)sitem;
			if (session->conn[0].state == STATE_LOGGED_IN &&
			    !strncmp(session->nrec.name, node_name, TARGET_NAME_MAXLEN))
				return 1;
			sitem = sitem->q_forw;
		}

		pitem = pitem->q_forw;
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

	if (conn->state != STATE_XPT_WAIT)
		return;

	rc = session->provider->utransport->ep_poll(conn, 1);
	if (rc == 0) {
		/* timedout: Poll again. */
		queue_produce(session->queue, EV_CONN_POLL, qtask, 0, NULL);
		actor_schedule(&session->mainloop);
	} else if (rc > 0) {
		/* connected! */
		memset(c, 0, sizeof(iscsi_login_context_t));

		actor_delete(&conn->connect_timer);

		/* do not allocate new connection in case of reopen */
		if (session->r_stage == R_STAGE_NO_CHANGE) {
			if (conn->id == 0 &&
			    ipc->create_session(session->transport_handle,
					session->nrec.session.initial_cmdsn,
					session->nrec.session.cmds_max,
					session->nrec.session.queue_depth,
					&session->id, &session->hostno)) {
				log_error("can't create session (%d)", errno);
				err = MGMT_IPC_ERR_INTERNAL;
				goto cleanup;
			}
			log_debug(3, "created new iSCSI session %d",
				  session->id);

			/* unique identifier for OUI */
			if (__session_node_established(session->nrec.name)) {
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

		if (ipc->bind_conn(session->transport_handle, session->id,
				   conn->id, conn->transport_ep_handle,
				   (conn->id == 0), &rc) || rc) {
			log_error("can't bind conn %d:%d to session %d, "
				  "retcode %d (%d)", session->id, conn->id,
				   session->id, rc, errno);
			err = MGMT_IPC_ERR_INTERNAL;
			goto c_cleanup;
		}
		log_debug(3, "bound iSCSI connection %d:%d to session %d",
			  session->id, conn->id, session->id);

		setup_kernel_io_callouts(conn);

		c->qtask = qtask;
		c->cid = conn->id;
		c->buffer = conn->data;
		c->bufsize = sizeof(conn->data);

		set_exp_statsn(conn);

		if (iscsi_login_begin(session, c)) {
			err = MGMT_IPC_ERR_LOGIN_FAILURE;
			goto c_cleanup;
		}

		conn->state = STATE_IN_LOGIN;
		if (iscsi_login_req(session, c)) {
			err = MGMT_IPC_ERR_LOGIN_FAILURE;
			goto c_cleanup;
		}
	} else if (session->r_stage == R_STAGE_NO_CHANGE) {
		/*
		 * poll failed during the initial connect. Give up
		 */
		/* error during connect */
		err = MGMT_IPC_ERR_TRANS_FAILURE;
		goto cleanup;
	} else
		/*
		 * poll failed on reopen
		 */
		queue_delayed_reopen(qtask, DEFAULT_TIME2WAIT);
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
	session->provider->utransport->ep_disconnect(conn);
	session_conn_cleanup(qtask, err);
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
			session->provider->utransport->ep_disconnect(conn);
			log_debug(6, "conn_timer popped at XPT_WAIT: login");
			/* timeout during initial connect.
			 * clean connection. write ipc rsp */
			session_conn_cleanup(qtask,
					     MGMT_IPC_ERR_TRANS_TIMEOUT);
			break;
		case R_STAGE_SESSION_REDIRECT:
			log_debug(6, "conn_timer popped at XPT_WAIT: "
				  "login redirect");
			/* timeout during initial redirect connect
			 * clean connection. write ipc rsp */
			__session_conn_shutdown(conn, qtask,
						MGMT_IPC_ERR_TRANS_TIMEOUT);
			break;
		case R_STAGE_SESSION_REOPEN:
			log_debug(6, "conn_timer popped at XPT_WAIT: reopen");
			/* timeout during reopen connect. try again */
			session_conn_reopen(conn, qtask, 0);
			break;
		case R_STAGE_SESSION_CLEANUP:
			__session_conn_shutdown(conn, qtask,
					        MGMT_IPC_ERR_TRANS_TIMEOUT);
			break;
		default:
			break;
		}

		break;
	case STATE_IN_LOGIN:
		switch (session->r_stage) {
		case R_STAGE_NO_CHANGE:
		case R_STAGE_SESSION_REDIRECT:
			log_debug(6, "conn_timer popped at IN_LOGIN: cleanup");
			/*
			 * send pdu timeout during initial connect or
			 * initial redirected connect. Clean connection
			 * and write rsp.
			 */
			session_conn_shutdown(conn, qtask,
					      MGMT_IPC_ERR_PDU_TIMEOUT);
			break;
		case R_STAGE_SESSION_REOPEN:
			log_debug(6, "conn_timer popped at IN_LOGIN: reopen");
			session_conn_reopen(conn, qtask, STOP_CONN_RECOVER);
			break;
		case R_STAGE_SESSION_CLEANUP:
			session_conn_shutdown(conn, qtask,
					      MGMT_IPC_ERR_PDU_TIMEOUT);
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
	case STATE_IN_LOGOUT:
		actor_delete(&conn->logout_timer);
		/* logout was requested by user */
		if (conn->logout_qtask) {
			session_conn_shutdown(conn, conn->logout_qtask,
					      MGMT_IPC_OK);
			return;
		}
		/* logout was from eh - fall down to cleanup */
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
			queue_task_t *qtask;

			if (session->sync_qtask)
				qtask = session->sync_qtask;
			else
				qtask = &session->reopen_qtask;

			session_conn_reopen(conn, qtask, STOP_CONN_RECOVER);
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
	}
}

static void
__session_conn_error(queue_item_t *item)
{
	enum iscsi_err error = *(enum iscsi_err *)queue_item_data(item);
	iscsi_conn_t *conn = item->context;
	iscsi_session_t *session = conn->session;

	log_warning("Kernel reported iSCSI connection %d:%d error (%d) "
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
	int count = session->queue->count, i;

	/*
	 * grab a reference in case one of these events destroys
	 * the session
	 */
	session_get(session);
	for (i = 0; i < count; i++) {
		if (queue_consume(session->queue, EVENT_PAYLOAD_MAX,
				  item) == QUEUE_IS_EMPTY) {
			log_debug(4, "%d items flushed while mainloop "
				  "was processing", count - i);
			break;
		}

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
session_find_by_sid(int sid)
{
	iscsi_provider_t *p;
	iscsi_session_t *session;
	struct qelem *pitem, *sitem;

	pitem = providers.q_forw;
	while (pitem != &providers) {
		p = (iscsi_provider_t *)pitem;

		sitem = p->sessions.q_forw;
		while (sitem != &p->sessions) {
			session = (iscsi_session_t *)sitem;

			if (session->id == sid)
				return session;
			sitem = sitem->q_forw;
		}
		pitem = pitem->q_forw;
	}

	return NULL;
}

iscsi_session_t*
session_find_by_rec(node_rec_t *rec)
{
	iscsi_provider_t *p;
	iscsi_session_t *session;
	struct qelem *pitem, *sitem;

	pitem = providers.q_forw;
	while (pitem != &providers) {
		p = (iscsi_provider_t *)pitem;

		sitem = p->sessions.q_forw;
		while (sitem != &p->sessions) {
			session = (iscsi_session_t *)sitem;

			if (iscsi_match_session(rec, session->nrec.name,
					 -1, session->nrec.conn[0].address,
					 session->nrec.conn[0].port,
					 session->id, session->nrec.iface.name))
				return session;

			sitem = sitem->q_forw;
		}
		pitem = pitem->q_forw;
	}

	return NULL;
}

/*
 * a session could be running in the kernel but not in iscsid
 * due to a resync or becuase some other app started the session
 */
int session_is_running(node_rec_t *rec)
{
	int nr_found = 0;

	if (session_find_by_rec(rec))
		return 1;

	if (sysfs_for_each_session(rec, &nr_found, iscsi_match_session))
		return 1;

	return 0;
}

int
session_login_task(node_rec_t *rec, queue_task_t *qtask)
{
	int rc;
	iscsi_session_t *session;
	iscsi_conn_t *conn;
	iscsi_provider_t *provider;

	provider = get_transport_by_name(rec->iface.transport_name);
	if (!provider)
		return MGMT_IPC_ERR_TRANS_NOT_FOUND;
	if (set_uspace_transport(provider))
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
		return MGMT_IPC_ERR_TRANS_FAILURE;
	}

	conn->state = STATE_XPT_WAIT;
	queue_produce(session->queue, EV_CONN_POLL, qtask, 0, NULL);
	actor_schedule(&session->mainloop);

	actor_timer(&conn->connect_timer, conn->login_timeout*1000,
		    __connect_timedout, qtask);

	qtask->rsp.command = MGMT_IPC_SESSION_LOGIN;
	qtask->rsp.err = MGMT_IPC_OK;

	return MGMT_IPC_OK;
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
	return 0;
}

mgmt_ipc_err_e
iscsi_sync_session(node_rec_t *rec, queue_task_t *qtask, uint32_t sid)
{
	iscsi_session_t *session;
	iscsi_provider_t *provider;
	int err;

	provider = get_transport_by_name(rec->iface.transport_name);
	if (!provider)
		return MGMT_IPC_ERR_TRANS_NOT_FOUND;
	if (set_uspace_transport(provider))
		return MGMT_IPC_ERR_TRANS_NOT_FOUND;

	session = __session_create(rec, provider);
	if (!session)
		return MGMT_IPC_ERR_NOMEM;

	session->id = sid;
	session->hostno = get_host_no_from_sid(sid, &err);
	if (err) {
		log_error("Could not get hostno for session %d\n", sid);
		err = MGMT_IPC_ERR_NOT_FOUND;
		goto destroy_session;
	}

	session->r_stage = R_STAGE_SESSION_REOPEN;

	err = sync_conn(session, 0);
	if (err) {
		if (err == -ENOMEM)
			err = MGMT_IPC_ERR_NOMEM;
		else if (err == -ENODEV)
			err = MGMT_IPC_ERR_NOT_FOUND;
		else
			err = MGMT_IPC_ERR_INVAL;
		goto destroy_session;
	}

	session->sync_qtask = qtask;
	qtask->rsp.command = MGMT_IPC_SESSION_SYNC;

	session_conn_reopen(&session->conn[0], qtask, STOP_CONN_RECOVER);
	log_debug(3, "Started sync iSCSI session %d", session->id);
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
	mgmt_ipc_err_e rc = MGMT_IPC_OK;

	conn = &session->conn[0];
	if (session->sync_qtask ||
	    (conn->state == STATE_XPT_WAIT &&
	    (session->r_stage == R_STAGE_NO_CHANGE ||
	     session->r_stage == R_STAGE_SESSION_REDIRECT))) {
		log_error("session in invalid state for logout. "
			   "Try again later\n");
		return MGMT_IPC_ERR_INTERNAL;
	}

	/* FIXME: logout all active connections */
	conn = &session->conn[0];
	/* FIXME: implement Logout Request */

	qtask->conn = conn;
	qtask->rsp.command = MGMT_IPC_SESSION_LOGOUT;
	conn->logout_qtask = qtask;

	switch (conn->state) {
	case STATE_LOGGED_IN:
		if (!iscsi_send_logout(conn))
			return MGMT_IPC_OK;
		log_error("Could not send logout pdu. Dropping session\n");
		/* fallthrough */
	case STATE_IN_LOGIN:
		rc = session_conn_shutdown(conn, qtask, MGMT_IPC_OK);
		break;
	case STATE_IN_LOGOUT:
		rc = MGMT_IPC_ERR_LOGOUT_FAILURE;
		break;
	default:
		rc = __session_conn_shutdown(conn, qtask, MGMT_IPC_OK);
		break;
	}

	return rc;
}
