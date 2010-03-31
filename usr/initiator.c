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

#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>

#include "initiator.h"
#include "transport.h"
#include "iscsid.h"
#include "iscsi_if.h"
#include "mgmt_ipc.h"
#include "event_poll.h"
#include "iscsi_ipc.h"
#include "idbm.h"
#include "log.h"
#include "iscsi_util.h"
#include "scsi.h"
#include "iscsi_sysfs.h"
#include "iscsi_settings.h"
#include "iface.h"
#include "sysdeps.h"

#define ISCSI_CONN_ERR_REOPEN_DELAY	3
#define ISCSI_INTERNAL_ERR_REOPEN_DELAY	5

#define PROC_DIR "/proc"

static void iscsi_login_timedout(void *data);

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

static int iscsi_conn_context_alloc(iscsi_conn_t *conn)
{
	int i;

	for (i = 0; i < CONTEXT_POOL_MAX; i++) {
		conn->context_pool[i] = calloc(1,
					   sizeof(struct iscsi_conn_context) +
					   ipc->ctldev_bufmax);
		if (!conn->context_pool[i]) {
			int j;
			for (j = 0; j < i; j++)
				free(conn->context_pool[j]);
			return ENOMEM;
		}
		conn->context_pool[i]->conn = conn;
	}

	return 0;
}

static void iscsi_conn_context_free(iscsi_conn_t *conn)
{
	int i;

	for (i = 0; i < CONTEXT_POOL_MAX; i++) {
		if (!conn->context_pool[i])
			continue;

		if (conn->context_pool[i]->allocated)
			/* missing flush on shutdown */
			log_error("BUG: context_pool leak %p",
				  conn->context_pool[i]);
		free(conn->context_pool[i]);
	}
}

struct iscsi_conn_context *iscsi_conn_context_get(iscsi_conn_t *conn,
						  int ev_size)
{
	struct iscsi_conn_context *conn_context;
	int i;

	if (ev_size > ipc->ctldev_bufmax)
		return NULL;

	for (i = 0; i < CONTEXT_POOL_MAX; i++) {
		if (!conn->context_pool[i])
			continue;

		if (!conn->context_pool[i]->allocated) {
			conn_context = conn->context_pool[i];

			memset(&conn_context->actor, 0,
				sizeof(struct actor));
			conn_context->allocated = 1;
			/* some callers abuse this pointer */
			conn_context->data = (void *)conn_context +
					sizeof(struct iscsi_conn_context);
			log_debug(7, "get conn context %p",
				  &conn_context->actor);
			return conn_context;
		}
	}
	return NULL;
}

void iscsi_conn_context_put(struct iscsi_conn_context *conn_context)
{
	log_debug(7, "put conn context %p", &conn_context->actor);
	conn_context->allocated = 0;
}

static void session_online_devs(int host_no, int sid)
{
	iscsi_sysfs_for_each_device(NULL, host_no, sid,
				    iscsi_sysfs_set_device_online);
}

static conn_login_status_e
__login_response_status(iscsi_conn_t *conn,
		      enum iscsi_login_status login_status)
{
	switch (login_status) {
	case LOGIN_OK:
		/* check the status class and detail */
		return CONN_LOGIN_SUCCESS;
	case LOGIN_REDIRECT:
		return CONN_LOGIN_IMM_REDIRECT_RETRY;
	case LOGIN_IO_ERROR:
	case LOGIN_REDIRECTION_FAILED:
		return CONN_LOGIN_RETRY;
	default:
		log_error("Login error (Login status %d) on conn %d", conn->id,
			  login_status);
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
			log_error("session %d login rejected: Initiator "
			       "failed authentication with target",
				session->id);
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
			       "error (%02x/%02x)", conn->id, status_class,
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
		if (auth_cfg->password_length == 0) {
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
	strlcpy(session->username, auth_cfg->username,
		sizeof (session->username));
	session->username[sizeof (session->username) - 1] = '\0';
	if ((session->password_length = auth_cfg->password_length))
		memcpy(session->password, auth_cfg->password,
		       session->password_length);

	strlcpy(session->username_in, auth_cfg->username_in,
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
		return EINVAL;
	}
	conn->failback_saddr = conn->saddr;

	getnameinfo((struct sockaddr *)&conn->saddr, sizeof(conn->saddr),
		    conn->host, sizeof(conn->host), NULL, 0, NI_NUMERICHOST);
	log_debug(4, "resolved %s to %s", conn_rec->address, conn->host);
	return 0;
}

static void
iscsi_copy_operational_params(iscsi_conn_t *conn)
{
	iscsi_session_t *session = conn->session;
	conn_rec_t *conn_rec = &session->nrec.conn[conn->id];
	node_rec_t *rec = &session->nrec;

	conn->hdrdgst_en = conn_rec->iscsi.HeaderDigest;
	conn->datadgst_en = conn_rec->iscsi.DataDigest;

	conn->max_recv_dlength =
			__padding(conn_rec->iscsi.MaxRecvDataSegmentLength);
	if (conn->max_recv_dlength < ISCSI_MIN_MAX_RECV_SEG_LEN ||
	    conn->max_recv_dlength > ISCSI_MAX_MAX_RECV_SEG_LEN) {
		log_error("Invalid iscsi.MaxRecvDataSegmentLength. Must be "
			 "within %u and %u. Setting to %u\n",
			  ISCSI_MIN_MAX_RECV_SEG_LEN,
			  ISCSI_MAX_MAX_RECV_SEG_LEN,
			  DEF_INI_MAX_RECV_SEG_LEN);
		conn_rec->iscsi.MaxRecvDataSegmentLength =
						DEF_INI_MAX_RECV_SEG_LEN;
		conn->max_recv_dlength = DEF_INI_MAX_RECV_SEG_LEN;
	}

	/* zero indicates to use the target's value */
	conn->max_xmit_dlength =
			__padding(conn_rec->iscsi.MaxXmitDataSegmentLength);
	if (conn->max_xmit_dlength == 0)
		conn->max_xmit_dlength = ISCSI_DEF_MAX_RECV_SEG_LEN;
	if (conn->max_xmit_dlength < ISCSI_MIN_MAX_RECV_SEG_LEN ||
	    conn->max_xmit_dlength > ISCSI_MAX_MAX_RECV_SEG_LEN) {
		log_error("Invalid iscsi.MaxXmitDataSegmentLength. Must be "
			 "within %u and %u. Setting to %u\n",
			  ISCSI_MIN_MAX_RECV_SEG_LEN,
			  ISCSI_MAX_MAX_RECV_SEG_LEN,
			  DEF_INI_MAX_RECV_SEG_LEN);
		conn_rec->iscsi.MaxXmitDataSegmentLength =
						DEF_INI_MAX_RECV_SEG_LEN;
		conn->max_xmit_dlength = DEF_INI_MAX_RECV_SEG_LEN;
	}

	/* session's operational parameters */
	session->initial_r2t_en = rec->session.iscsi.InitialR2T;
	session->imm_data_en = rec->session.iscsi.ImmediateData;
	session->first_burst = __padding(rec->session.iscsi.FirstBurstLength);
	/*
	 * some targets like netapp fail the login if sent bad first_burst
	 * and max_burst lens, even when immediate data=no and
	 * initial r2t = Yes, so we always check the user values.
	 */
	if (session->first_burst < ISCSI_MIN_FIRST_BURST_LEN ||
	    session->first_burst > ISCSI_MAX_FIRST_BURST_LEN) {
		log_error("Invalid iscsi.FirstBurstLength of %u. Must be "
			 "within %u and %u. Setting to %u\n",
			  session->first_burst,
			  ISCSI_MIN_FIRST_BURST_LEN,
			  ISCSI_MAX_FIRST_BURST_LEN,
			  DEF_INI_FIRST_BURST_LEN);
		rec->session.iscsi.FirstBurstLength = DEF_INI_FIRST_BURST_LEN;
		session->first_burst = DEF_INI_FIRST_BURST_LEN;
	}

	session->max_burst = __padding(rec->session.iscsi.MaxBurstLength);
	if (session->max_burst < ISCSI_MIN_MAX_BURST_LEN ||
	    session->max_burst > ISCSI_MAX_MAX_BURST_LEN) {
		log_error("Invalid iscsi.MaxBurstLength of %u. Must be "
			  "within %u and %u. Setting to %u\n",
			   session->max_burst, ISCSI_MIN_MAX_BURST_LEN,
			   ISCSI_MAX_MAX_BURST_LEN, DEF_INI_MAX_BURST_LEN);
		rec->session.iscsi.MaxBurstLength = DEF_INI_MAX_BURST_LEN;
		session->max_burst = DEF_INI_MAX_BURST_LEN;
	}

	if (session->first_burst > session->max_burst) {
		log_error("Invalid iscsi.FirstBurstLength of %u. Must be "
			  "less than iscsi.MaxBurstLength. Setting to %u\n",
			   session->first_burst, session->max_burst);
		rec->session.iscsi.FirstBurstLength = session->max_burst;
		session->first_burst = session->max_burst;
	}

	session->def_time2wait = rec->session.iscsi.DefaultTime2Wait;
	session->def_time2retain = rec->session.iscsi.DefaultTime2Retain;
	session->erl = rec->session.iscsi.ERL;
}

static int
__session_conn_create(iscsi_session_t *session, int cid)
{
	iscsi_conn_t *conn = &session->conn[cid];
	conn_rec_t *conn_rec = &session->nrec.conn[cid];
	int err;

	if (iscsi_conn_context_alloc(conn)) {
		log_error("cannot allocate context_pool for conn cid %d", cid);
		return ENOMEM;
	}

	conn->state = STATE_FREE;
	conn->session = session;
	/*
	 * TODO: we must export the socket_fd/transport_eph from sysfs
	 * so if iscsid is resyncing up we can pick that up and cleanup up
	 * the old connection. Right now we leak a connection.
	 * We can also probably merge these two fields.
	 */
	conn->socket_fd = -1;
	conn->transport_ep_handle = -1;
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

	conn->auth_timeout = conn_rec->timeo.auth_timeout;

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
		conn->noop_out_interval = DEF_NOOP_OUT_INTERVAL;
	}

	iscsi_copy_operational_params(conn);

	/* TCP options */
	conn->tcp_window_size = conn_rec->tcp.window_size;
	/* FIXME: type_of_service */

	/* resolve the string address to an IP address */
	err = setup_portal(conn, conn_rec);
	if (err)
		return err;
	return 0;
}

static void
session_release(iscsi_session_t *session)
{
	log_debug(2, "Releasing session %p", session);

	if (session->target_alias)
		free(session->target_alias);
	iscsi_conn_context_free(&session->conn[0]);
	free(session);
}

static iscsi_session_t*
__session_create(node_rec_t *rec, struct iscsi_transport *t)
{
	iscsi_session_t *session;
	int hostno, rc = 0;

	session = calloc(1, sizeof (*session));
	if (session == NULL) {
		log_debug(1, "can not allocate memory for session");
		return NULL;
	}
	log_debug(2, "Allocted session %p", session);

	INIT_LIST_HEAD(&session->list);
	/* opened at daemon load time (iscsid.c) */
	session->ctrl_fd = control_fd;
	session->t = t;
	session->reopen_qtask.mgmt_ipc_fd = -1;
	session->id = -1;

	/* save node record. we might need it for redirection */
	memcpy(&session->nrec, rec, sizeof(node_rec_t));

	session->portal_group_tag = rec->tpgt;
	session->type = ISCSI_SESSION_TYPE_NORMAL;
	session->r_stage = R_STAGE_NO_CHANGE;
	strlcpy(session->target_name, rec->name, TARGET_NAME_MAXLEN);

	if (strlen(session->nrec.iface.iname))
		session->initiator_name = session->nrec.iface.iname;
	else if (dconfig->initiator_name)
		session->initiator_name = dconfig->initiator_name;
	else {
		log_error("No initiator name set. Cannot create session.");
		free(session);
		return NULL;
	}

	if (strlen(session->nrec.iface.alias))
		session->initiator_alias = session->nrec.iface.alias;
	else
		session->initiator_alias = dconfig->initiator_alias;

	/* session's eh parameters */
	session->replacement_timeout = rec->session.timeo.replacement_timeout;
	session->fast_abort = rec->session.iscsi.FastAbort;
	session->abort_timeout = rec->session.err_timeo.abort_timeout;
	session->lu_reset_timeout = rec->session.err_timeo.lu_reset_timeout;
	session->tgt_reset_timeout = rec->session.err_timeo.tgt_reset_timeout;
	session->host_reset_timeout = rec->session.err_timeo.host_reset_timeout;

	/* OUI and uniqifying number */
	session->isid[0] = DRIVER_ISID_0;
	session->isid[1] = DRIVER_ISID_1;
	session->isid[2] = DRIVER_ISID_2;
	session->isid[3] = 0;
	session->isid[4] = 0;
	session->isid[5] = 0;

	/* setup authentication variables for the session*/
	__setup_authentication(session, &rec->session.auth);

	session->param_mask = ~0ULL;
	if (!(t->caps & CAP_MULTI_R2T))
		session->param_mask &= ~ISCSI_MAX_R2T;
	if (!(t->caps & CAP_HDRDGST))
		session->param_mask &= ~ISCSI_HDRDGST_EN;
	if (!(t->caps & CAP_DATADGST))
		session->param_mask &= ~ISCSI_DATADGST_EN;
	if (!(t->caps & CAP_MARKERS)) {
		session->param_mask &= ~ISCSI_IFMARKER_EN;
		session->param_mask &= ~ISCSI_OFMARKER_EN;
	}

	hostno = iscsi_sysfs_get_host_no_from_hwinfo(&rec->iface, &rc);
	if (!rc) {
		/*
		 * if the netdev or mac was set, then we are going to want
		 * to want to bind the all the conns/eps to a specific host
		 * if offload is used.
		 */
		session->conn[0].bind_ep = 1;
		session->hostno = hostno;
	}

	list_add_tail(&session->list, &t->sessions);
	return session;
}

static void iscsi_flush_context_pool(struct iscsi_session *session)
{
	struct iscsi_conn_context *conn_context;
	struct iscsi_conn *conn = &session->conn[0];
	int i;

	for (i = 0; i < CONTEXT_POOL_MAX; i++) {
		conn_context = conn->context_pool[i];
		if (!conn_context)
			continue;

		if (conn_context->allocated) {
			actor_delete(&(conn->context_pool[i]->actor));
			iscsi_conn_context_put(conn_context);
		}
	}
}

static void
__session_destroy(iscsi_session_t *session)
{
	log_debug(1, "destroying session\n");
	list_del(&session->list);
	iscsi_flush_context_pool(session);
	session_release(session);
}

static void
conn_delete_timers(iscsi_conn_t *conn)
{
	actor_delete(&conn->login_timer);
	actor_delete(&conn->nop_out_timer);
}

static mgmt_ipc_err_e
session_conn_shutdown(iscsi_conn_t *conn, queue_task_t *qtask,
		      mgmt_ipc_err_e err)
{
	iscsi_session_t *session = conn->session;

	log_debug(2, "disconnect conn");
	/* this will check for a valid interconnect connection */
	conn->session->t->template->ep_disconnect(conn);

	if (session->id == -1)
		goto cleanup;

	if (!iscsi_sysfs_session_has_leadconn(session->id))
		goto cleanup;

	if (conn->state == STATE_IN_LOGIN ||
	    conn->state == STATE_IN_LOGOUT ||
	    conn->state == STATE_LOGGED_IN) {
		log_debug(2, "stop conn (conn state %d)", conn->state);
		if (ipc->stop_conn(session->t->handle, session->id,
				   conn->id, STOP_CONN_TERM)) {
			log_error("can't stop connection %d:%d (%d)",
				  session->id, conn->id, errno);
			return MGMT_IPC_ERR_INTERNAL;
		}
	}

	log_debug(2, "kdestroy conn");
	if (ipc->destroy_conn(session->t->handle, session->id,
		conn->id)) {
		log_error("can not safely destroy connection %d", conn->id);
		return MGMT_IPC_ERR_INTERNAL;
	}

cleanup:
	if (session->id != -1) {
		log_debug(2, "kdestroy session %u", session->id);
		if (ipc->destroy_session(session->t->handle, session->id)) {
			log_error("can not safely destroy session %d",
				  session->id);
			return MGMT_IPC_ERR_INTERNAL;
		}
	}

	log_warning("Connection%d:%d to [target: %s, portal: %s,%d] "
		    "through [iface: %s] is shutdown.",
		    session->id, conn->id, session->nrec.name,
		    session->nrec.conn[conn->id].address,
		    session->nrec.conn[conn->id].port,
		    session->nrec.iface.name);

	mgmt_ipc_write_rsp(qtask, err);
	conn_delete_timers(conn);
	__session_destroy(session);
	return MGMT_IPC_OK;
}

static void
queue_delayed_reopen(queue_task_t *qtask, int delay)
{
	iscsi_conn_t *conn = qtask->conn;

	log_debug(4, "Requeue reopen attempt in %d secs\n", delay);

	/*
 	 * iscsi_login_eh can handle the login resched as
 	 * if it were login time out
 	 */
	actor_delete(&conn->login_timer);
	actor_timer(&conn->login_timer, delay * 1000,
		    iscsi_login_timedout, qtask);
}

static int iscsi_conn_connect(struct iscsi_conn *conn, queue_task_t *qtask)
{
	struct iscsi_conn_context *conn_context;
	int rc;

	conn_context = iscsi_conn_context_get(conn, 0);
	if (!conn_context) {
		/* while reopening the recv pool should be full */
		log_error("BUG: __session_conn_reopen could not get conn "
			  "context for recv.");
		return ENOMEM;
	}
	conn_context->data = qtask;

	rc = conn->session->t->template->ep_connect(conn, 1);
	if (rc < 0 && errno != EINPROGRESS) {
		char serv[NI_MAXSERV];

		getnameinfo((struct sockaddr *) &conn->saddr,
			    sizeof(conn->saddr),
			    conn->host, sizeof(conn->host), serv, sizeof(serv),
			    NI_NUMERICHOST|NI_NUMERICSERV);

		log_error("cannot make a connection to %s:%s (%d,%d)",
			  conn->host, serv, rc, errno);
		iscsi_conn_context_put(conn_context);
		return ENOTCONN;
	}

	iscsi_sched_conn_context(conn_context, conn, 0, EV_CONN_POLL);
	log_debug(3, "Setting login timer %p timeout %d", &conn->login_timer,
		  conn->login_timeout);
	actor_timer(&conn->login_timer, conn->login_timeout * 1000,
		    iscsi_login_timedout, qtask);
	return 0;
}

static void
__session_conn_reopen(iscsi_conn_t *conn, queue_task_t *qtask, int do_stop,
		      int redirected)
{
	iscsi_session_t *session = conn->session;
	uint32_t delay;

	log_debug(1, "re-opening session %d (reopen_cnt %d)", session->id,
			session->reopen_cnt);

	qtask->conn = conn;

	/* flush stale polls or errors queued */
	iscsi_flush_context_pool(session);
	conn_delete_timers(conn);
	conn->state = STATE_XPT_WAIT;

	conn->session->t->template->ep_disconnect(conn);
	if (do_stop) {
		/* state: STATE_CLEANUP_WAIT */
		if (ipc->stop_conn(session->t->handle, session->id,
				   conn->id, do_stop)) {
			log_error("can't stop connection %d:%d (%d)",
				  session->id, conn->id, errno);
			delay = ISCSI_INTERNAL_ERR_REOPEN_DELAY;
			goto queue_reopen;
		}
		log_debug(3, "connection %d:%d is stopped for recovery",
			  session->id, conn->id);
	}

	if (!redirected) {
		delay = session->def_time2wait;
		session->def_time2wait = 0;
		if (delay)
			goto queue_reopen;
	}

	if (!redirected)
		session->reopen_cnt++;

	if (iscsi_conn_connect(conn, qtask)) {
		delay = ISCSI_CONN_ERR_REOPEN_DELAY;
		goto queue_reopen;
	}
	return;

queue_reopen:
	log_debug(4, "Waiting %u seconds before trying to reconnect.\n", delay);
	queue_delayed_reopen(qtask, delay);
}

static void
session_conn_reopen(iscsi_conn_t *conn, queue_task_t *qtask, int do_stop)
{
	/*
	 * If we were temporarily redirected, we need to fall back to
	 * the original address to see where the target will send us
	 * for the retry
	 */
	memset(&conn->saddr, 0, sizeof(struct sockaddr_storage));
	conn->saddr = conn->failback_saddr;

	__session_conn_reopen(conn, qtask, do_stop, 0);
}

static int iscsi_retry_initial_login(struct iscsi_conn *conn)
{
	int initial_login_retry_max;
	struct timeval now, timeout, fail_time;

	initial_login_retry_max =
			conn->session->nrec.session.initial_login_retry_max;

	memset(&now, 0, sizeof(now));
	memset(&timeout, 0, sizeof(timeout));
	memset(&fail_time, 0, sizeof(fail_time));

	timeout.tv_sec = initial_login_retry_max * conn->login_timeout;
	if (gettimeofday(&now, NULL)) {
		log_error("Could not get time of day. Dropping down to "
			  "max retry check.\n");
		return initial_login_retry_max > conn->session->reopen_cnt;
	}
	timeradd(&conn->initial_connect_time, &timeout, &fail_time);

	/*
	 * if we have been trying for login_retry_max * login_timeout
	 * then it is time to give up
	 */
	if (timercmp(&now, &fail_time, >)) {
		log_debug(1, "Giving up on initial login attempt after "
			  "%u seconds.\n",
			  initial_login_retry_max * conn->login_timeout);
		return 0;
	}

	return 1;
}

static void iscsi_login_eh(struct iscsi_conn *conn, struct queue_task *qtask,
			   mgmt_ipc_err_e err)
{
	struct iscsi_session *session = conn->session;

	log_debug(3, "iscsi_login_eh");
	/*
	 * Flush polls and other events
	 */
	iscsi_flush_context_pool(conn->session);

	switch (conn->state) {
	case STATE_XPT_WAIT:
		switch (session->r_stage) {
		case R_STAGE_NO_CHANGE:
			log_debug(6, "login failed STATE_XPT_WAIT/"
				  "R_STAGE_NO_CHANGE");
			/* timeout during initial connect.
			 * clean connection. write ipc rsp or retry */
			if (err == MGMT_IPC_ERR_FATAL_LOGIN_FAILURE ||
			    !iscsi_retry_initial_login(conn))
				session_conn_shutdown(conn, qtask, err);
			else {
				session->reopen_cnt++;
				session->t->template->ep_disconnect(conn);
				if (iscsi_conn_connect(conn, qtask))
					queue_delayed_reopen(qtask,
						ISCSI_CONN_ERR_REOPEN_DELAY);
			}
			break;
		case R_STAGE_SESSION_REDIRECT:
			log_debug(6, "login failed STATE_XPT_WAIT/"
				  "R_STAGE_SESSION_REDIRECT");
			/* timeout during initial redirect connect
			 * clean connection. write ipc rsp or retry */
			if (err == MGMT_IPC_ERR_FATAL_LOGIN_FAILURE ||
			    !iscsi_retry_initial_login(conn))
				session_conn_shutdown(conn, qtask, err);
			else
				session_conn_reopen(conn, qtask, 0);
			break;
		case R_STAGE_SESSION_REOPEN:
			log_debug(6, "login failed STATE_XPT_WAIT/"
				  "R_STAGE_SESSION_REOPEN %d",
				  session->reopen_cnt);
			/* timeout during reopen connect. try again */
			session_conn_reopen(conn, qtask, 0);
			break;
		case R_STAGE_SESSION_CLEANUP:
			session_conn_shutdown(conn, qtask, err);
			break;
		default:
			break;
		}

		break;
	case STATE_IN_LOGIN:
		switch (session->r_stage) {
		case R_STAGE_NO_CHANGE:
		case R_STAGE_SESSION_REDIRECT:
			log_debug(6, "login failed STATE_IN_LOGIN/"
				  "R_STAGE_NO_CHANGE %d",
				  session->reopen_cnt);
			/*
			 * send pdu timeout during initial connect or
			 * initial redirected connect. Clean connection
			 * and write rsp or retry.
			 */
			if (err == MGMT_IPC_ERR_FATAL_LOGIN_FAILURE ||
			    !iscsi_retry_initial_login(conn))
				session_conn_shutdown(conn, qtask, err);
			else
				session_conn_reopen(conn, qtask,
						    STOP_CONN_RECOVER);
			break;
		case R_STAGE_SESSION_REOPEN:
			log_debug(6, "login failed STATE_IN_LOGIN/"
				  "R_STAGE_SESSION_REOPEN %d",
				  session->reopen_cnt);
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
		log_error("Ignoring login error %d in conn state %d.\n",
			  err, conn->state);
		break;
	}
}

static void
__conn_error_handle(iscsi_session_t *session, iscsi_conn_t *conn)
{
	int i;

	/*
	 * if we got an error while trying to logout for the user then
	 * just cleanup and return to the user.
	 */
	if (conn->logout_qtask) {
		session_conn_shutdown(conn, conn->logout_qtask, MGMT_IPC_OK);
		return;
	}

	switch (conn->state) {
	case STATE_IN_LOGOUT:
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
			iscsi_login_eh(conn, qtask, MGMT_IPC_ERR_TRANS_FAILURE);
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

static void session_conn_error(void *data)
{
	struct iscsi_conn_context *conn_context = data;
	enum iscsi_err error = *(enum iscsi_err *)conn_context->data;
	iscsi_conn_t *conn = conn_context->conn;
	iscsi_session_t *session = conn->session;

	log_warning("Kernel reported iSCSI connection %d:%d error (%d) "
		    "state (%d)", session->id, conn->id, error,
		    conn->state);
	iscsi_conn_context_put(conn_context);

	switch (error) {
	case ISCSI_ERR_INVALID_HOST:
		if (session_conn_shutdown(conn, NULL, MGMT_IPC_OK))
			log_error("BUG: Could not shutdown session.");
		break;
	default:
		__conn_error_handle(session, conn);
	}
}

static void iscsi_login_timedout(void *data)
{
	struct queue_task *qtask = data;
	struct iscsi_conn *conn = qtask->conn;

	switch (conn->state) {
	case STATE_XPT_WAIT:
		iscsi_login_eh(conn, qtask, MGMT_IPC_ERR_TRANS_TIMEOUT);
		break;
	case STATE_IN_LOGIN:
		iscsi_login_eh(conn, qtask, MGMT_IPC_ERR_PDU_TIMEOUT);
		break;
	default:
		iscsi_login_eh(conn, qtask, MGMT_IPC_ERR_INTERNAL);
		break;
	}
}

static void iscsi_login_redirect(iscsi_conn_t *conn)
{
	iscsi_session_t *session = conn->session;
	iscsi_login_context_t *c = &conn->login_context;

	log_debug(3, "login redirect ...\n");

	if (session->r_stage == R_STAGE_NO_CHANGE)
		session->r_stage = R_STAGE_SESSION_REDIRECT;

	__session_conn_reopen(conn, c->qtask, STOP_CONN_RECOVER, 1);
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

static void conn_nop_out_timeout(void *data)
{
	iscsi_conn_t *conn = (iscsi_conn_t*)data;
	iscsi_session_t *session = conn->session;

	log_warning("Nop-out timedout after %d seconds on connection %d:%d "
		    "state (%d). Dropping session.", conn->noop_out_timeout,
		    session->id, conn->id, conn->state);
	/* XXX: error handle */
	__conn_error_handle(session, conn);
}

static void conn_send_nop_out(void *data)
{
	iscsi_conn_t *conn = data;

	/*
	 * we cannot start new request during logout and the logout timer
	 * will figure things out.
	 */
	if (conn->state == STATE_IN_LOGOUT)
		return;

	__send_nopout(conn);

	actor_timer(&conn->nop_out_timer, conn->noop_out_timeout*1000,
		    conn_nop_out_timeout, conn);
	log_debug(3, "noop out timeout timer %p start, timeout %d\n",
		 &conn->nop_out_timer, conn->noop_out_timeout);
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

void free_initiator(void)
{
	struct iscsi_transport *t;
	iscsi_session_t *session, *tmp;

	list_for_each_entry(t, &transports, list) {
		list_for_each_entry_safe(session, tmp, &t->sessions, list) {
			list_del(&session->list);
			iscsi_flush_context_pool(session);
			session_release(session);
		}
	}

	free_transports();
}

static void session_scan_host(struct iscsi_session *session, int hostno,
			      queue_task_t *qtask)
{
	pid_t pid;

	pid = iscsi_sysfs_scan_host(hostno, 1);
	if (pid == 0) {
		mgmt_ipc_write_rsp(qtask, MGMT_IPC_OK);

		if (session)
			iscsi_sysfs_for_each_device(
					&session->nrec.session.queue_depth,
					hostno, session->id,
					iscsi_sysfs_set_queue_depth);
		exit(0);
	} else if (pid > 0) {
		reap_inc();
		if (qtask) {
			close(qtask->mgmt_ipc_fd);
			free(qtask);
		}
	} else
		mgmt_ipc_write_rsp(qtask, MGMT_IPC_ERR_INTERNAL);
}

static int __iscsi_host_set_param(struct iscsi_transport *t,
				  int host_no, int param, char *value,
				  int type)
{
	int rc;

	rc = ipc->set_host_param(t->handle, host_no, param, value, type);
	/* 2.6.20 and below returns EINVAL */
	if (rc && rc != -ENOSYS && rc != -EINVAL) {
		log_error("can't set operational parameter %d for "
			  "host %d, retcode %d (%d)", param, host_no,
			  rc, errno);
		return rc;
	}
	return 0;
}

mgmt_ipc_err_e iscsi_host_set_param(int host_no, int param, char *value)
{
	struct iscsi_transport *t;

	t = iscsi_sysfs_get_transport_by_hba(host_no);
	if (!t)
		return MGMT_IPC_ERR_TRANS_FAILURE;
	if (__iscsi_host_set_param(t, host_no, param, value, ISCSI_STRING))
		return MGMT_IPC_ERR;
        return MGMT_IPC_OK;
}

#define MAX_SESSION_PARAMS 32
#define MAX_HOST_PARAMS 3

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
		int set;
	} hosttbl[MAX_HOST_PARAMS] = {
		{
			.param = ISCSI_HOST_PARAM_NETDEV_NAME,
			.value = session->nrec.iface.netdev,
			.type = ISCSI_STRING,
			.set = 1,
		}, {
			.param = ISCSI_HOST_PARAM_HWADDRESS,
			.value = session->nrec.iface.hwaddress,
			.type = ISCSI_STRING,
			.set = 1,
		}, {
			.param = ISCSI_HOST_PARAM_INITIATOR_NAME,
			.value = session->initiator_name,
			.type = ISCSI_STRING,
			.set = 0,
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
		}, {
			.param = ISCSI_PARAM_FAST_ABORT,
			.value = &session->fast_abort,
			.type = ISCSI_INT,
			.conn_only = 0,
		}, {
			.param = ISCSI_PARAM_ABORT_TMO,
			.value = &session->abort_timeout,
			.type = ISCSI_INT,
			.conn_only = 0,
		}, {
			.param = ISCSI_PARAM_LU_RESET_TMO,
			.value = &session->lu_reset_timeout,
			.type = ISCSI_INT,
			.conn_only = 0,
		}, {
			.param = ISCSI_PARAM_TGT_RESET_TMO,
			.value = &session->tgt_reset_timeout,
			.type = ISCSI_INT,
			.conn_only = 0,
		}, {
			.param = ISCSI_PARAM_PING_TMO,
			.value = &conn->noop_out_timeout,
			.type = ISCSI_INT,
			.conn_only = 1,
		}, {
			.param = ISCSI_PARAM_RECV_TMO,
			.value = &conn->noop_out_interval,
			.type = ISCSI_INT,
			.conn_only = 1,
		}, {
			.param = ISCSI_PARAM_IFACE_NAME,
			.value = session->nrec.iface.name,
			.type = ISCSI_STRING,
		}, {
			.param = ISCSI_PARAM_INITIATOR_NAME,
			.value = session->initiator_name,
			.type = ISCSI_STRING,
		},
	};

	actor_delete(&conn->login_timer);
	/* Entered full-feature phase! */
	for (i = 0; i < MAX_SESSION_PARAMS; i++) {
		if (conn->id != 0 && !conntbl[i].conn_only)
			continue;
		
		if (!(session->param_mask & (1ULL << conntbl[i].param)))
			continue;

		rc = ipc->set_param(session->t->handle, session->id,
				   conn->id, conntbl[i].param, conntbl[i].value,
				   conntbl[i].type);
		if (rc && rc != -ENOSYS) {
			log_error("can't set operational parameter %d for "
				  "connection %d:%d, retcode %d (%d)",
				  conntbl[i].param, session->id, conn->id,
				  rc, errno);

			iscsi_login_eh(conn, c->qtask,
				       MGMT_IPC_ERR_LOGIN_FAILURE);
			return;
		}

		if (rc == -ENOSYS) {
			switch (conntbl[i].param) {
			case ISCSI_PARAM_PING_TMO:
				/*
				 * older kernels may not support nops
				 * in kernel
				 */
				conn->userspace_nop = 1;
				break;
			case ISCSI_PARAM_INITIATOR_NAME:
				/* use host level one instead */
				hosttbl[ISCSI_HOST_PARAM_INITIATOR_NAME].set = 1;
				break;
			}
		}

		print_param_value(conntbl[i].param, conntbl[i].value,
				  conntbl[i].type);
	}

	for (i = 0; i < MAX_HOST_PARAMS; i++) {
		if (!hosttbl[i].set)
			continue;

		if (__iscsi_host_set_param(session->t, session->hostno,
					   hosttbl[i].param, hosttbl[i].value,
					   hosttbl[i].type)) {
			iscsi_login_eh(conn, c->qtask,
				       MGMT_IPC_ERR_LOGIN_FAILURE);
			return;
		}

		print_param_value(hosttbl[i].param, hosttbl[i].value,
				  hosttbl[i].type);
	}

	if (ipc->start_conn(session->t->handle, session->id, conn->id,
			    &rc) || rc) {
		log_error("can't start connection %d:%d retcode %d (%d)",
			  session->id, conn->id, rc, errno);
		iscsi_login_eh(conn, c->qtask, MGMT_IPC_ERR_INTERNAL);
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
			session_scan_host(session, session->hostno, c->qtask);

		log_warning("Connection%d:%d to [target: %s, portal: %s,%d] "
			    "through [iface: %s] is operational now",
			    session->id, conn->id, session->nrec.name,
			    session->nrec.conn[conn->id].address,
			    session->nrec.conn[conn->id].port,
			    session->nrec.iface.name);
	} else {
		session->sync_qtask = NULL;

		session_online_devs(session->hostno, session->id);
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
	if (conn->userspace_nop && conn->noop_out_interval) {
		actor_timer(&conn->nop_out_timer, conn->noop_out_interval*1000,
			   conn_send_nop_out, conn);
		log_debug(3, "noop out timer %p start\n",
			  &conn->nop_out_timer);
	}
}

static void iscsi_logout_timedout(void *data)
{
	struct iscsi_conn_context *conn_context = data;
	struct iscsi_conn *conn = conn_context->conn;

	iscsi_conn_context_put(conn_context); 
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
	struct iscsi_conn_context *conn_context;

	if (conn->state != STATE_LOGGED_IN)
		return EINVAL;

	memset(&hdr, 0, sizeof(struct iscsi_logout));
	hdr.opcode = ISCSI_OP_LOGOUT | ISCSI_OP_IMMEDIATE;
	hdr.flags = ISCSI_FLAG_CMD_FINAL |
	   (ISCSI_LOGOUT_REASON_CLOSE_SESSION & ISCSI_FLAG_LOGOUT_REASON_MASK);
	/* kernel will set the rest */

	if (!iscsi_io_send_pdu(conn, (struct iscsi_hdr*)&hdr,
			       ISCSI_DIGEST_NONE, NULL, ISCSI_DIGEST_NONE, 0))
		return EIO;
	conn->state = STATE_IN_LOGOUT;

	conn_context = iscsi_conn_context_get(conn, 0);
	if (!conn_context)
		/* unbounded logout */
		log_warning("Could not allocate conn context for logout.");
	else {
		iscsi_sched_conn_context(conn_context, conn,
					 conn->logout_timeout,
					 EV_CONN_LOGOUT_TIMER);
		log_debug(3, "logout timeout timer %u\n",
			  conn->logout_timeout * 1000);
	}

	return 0;
}

static void iscsi_stop(void *data)
{
	struct iscsi_conn_context *conn_context = data;
	struct iscsi_conn *conn = conn_context->conn;
	int rc = 0;

	iscsi_conn_context_put(conn_context);

	if (!iscsi_send_logout(conn))
		return;

	rc = session_conn_shutdown(conn, conn->logout_qtask, MGMT_IPC_OK);
	if (rc)
		log_error("BUG: Could not shutdown session.");
}

static void iscsi_recv_nop_in(iscsi_conn_t *conn, struct iscsi_hdr *hdr)
{
	if (!conn->userspace_nop) {
		log_error("Got nop in, but kernel supports nop handling.");
		return;
	}

	if (hdr->ttt == ISCSI_RESERVED_TAG) {
		/* noop out rsp */
		actor_delete(&conn->nop_out_timer);
		/* schedule a new ping */
		actor_timer(&conn->nop_out_timer, conn->noop_out_interval*1000,
			    conn_send_nop_out, conn);
	} else /*  noop in req */
		if (!__send_nopin_rsp(conn, (struct iscsi_nopin*)hdr,
				      conn->data)) {
			log_error("can not send nopin response");
		}
}

static void iscsi_recv_logout_rsp(iscsi_conn_t *conn, struct iscsi_hdr *hdr)
{
	struct iscsi_logout_rsp *logout_rsp = (struct iscsi_logout_rsp *)hdr;

	log_debug(3, "Recv: logout response %d\n", logout_rsp->response);
	if (logout_rsp->response == 2 || logout_rsp->response == 3) {
		conn->session->def_time2wait = ntohs(logout_rsp->t2wait);
		log_debug(4, "logout rsp returned time2wait %u",
			  conn->session->def_time2wait);
	}
	/* TODO process the hdr */
	__conn_error_handle(conn->session, conn);
}

static void iscsi_recv_async_msg(iscsi_conn_t *conn, struct iscsi_hdr *hdr)
{
	iscsi_session_t *session = conn->session;
	struct iscsi_async *async_hdr = (struct iscsi_async *)hdr;
	char *buf = conn->data;
	unsigned int senselen;
	struct scsi_sense_hdr sshdr;

	log_debug(3, "Read AEN %d\n", async_hdr->async_event);

	switch (async_hdr->async_event) {
	case ISCSI_ASYNC_MSG_SCSI_EVENT:
		senselen = (buf[0] << 8) | buf[1];
		buf += 2;

		if (!scsi_normalize_sense((uint8_t *)buf, senselen, &sshdr)) {
			log_error("Could not handle AEN %d. Invalid sense.",
				  async_hdr->async_event);
			break;
		}

		if (sshdr.asc == 0x3f && sshdr.ascq == 0x0e)
			session_scan_host(session, session->hostno, NULL);
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
		session->def_time2wait =
			(uint32_t)ntohs(async_hdr->param2) & 0x0000FFFFFL;
		break;
	case ISCSI_ASYNC_MSG_DROPPING_ALL_CONNECTIONS:
		log_warning("Target dropping all connections, reconnect min %u "
			    "max %u\n", ntohs(async_hdr->param2),
			     ntohs(async_hdr->param3));
		session->def_time2wait =
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

static void iscsi_recv_login_rsp(struct iscsi_conn *conn)
{ 
	struct iscsi_session *session = conn->session;
	iscsi_login_context_t *c = &conn->login_context;

	if (iscsi_login_rsp(session, c)) {
		log_debug(1, "login_rsp ret (%d)", c->ret);

		switch (__login_response_status(conn, c->ret)) {
		case CONN_LOGIN_FAILED:
			goto failed;
		case CONN_LOGIN_RETRY:
			goto retry;
		case CONN_LOGIN_IMM_REDIRECT_RETRY:
			iscsi_login_redirect(conn);
			return;
		default:
			; /* success - fall through */
		}

		/* check the login status */
		switch (__check_iscsi_status_class(session, conn->id,
						   c->status_class,
						   c->status_detail)) {
		case CONN_LOGIN_FAILED:
			goto failed;
		case CONN_LOGIN_IMM_REDIRECT_RETRY:
			iscsi_login_redirect(conn);
			return;
		case CONN_LOGIN_IMM_RETRY:
		case CONN_LOGIN_RETRY:
			goto retry;
		default:
			; /* success - fall through */
		}
	}

	if (conn->current_stage != ISCSI_FULL_FEATURE_PHASE) {
		/* more nego. needed! */
		conn->state = STATE_IN_LOGIN;
		if (iscsi_login_req(session, c)) {
			iscsi_login_eh(conn, c->qtask,
				       MGMT_IPC_ERR_LOGIN_FAILURE);
			return;
		}
	} else
		setup_full_feature_phase(conn);

	return;
retry:
	/* retry if not initial login or initial login has not timed out */
	iscsi_login_eh(conn, c->qtask, MGMT_IPC_ERR_LOGIN_FAILURE);
	return;
failed:
	/* force failure if initial login */
	session->reopen_cnt = session->nrec.session.initial_login_retry_max;
	iscsi_login_eh(conn, c->qtask, MGMT_IPC_ERR_FATAL_LOGIN_FAILURE);
	return;
}

static void session_conn_recv_pdu(void *data)
{
	struct iscsi_conn_context *conn_context = data;
	iscsi_conn_t *conn = conn_context->conn;
	struct iscsi_hdr hdr;

	conn->recv_context = conn_context;

	switch (conn->state) {
	case STATE_IN_LOGIN:
		iscsi_recv_login_rsp(conn);
		break;
	case STATE_LOGGED_IN:
	case STATE_IN_LOGOUT:
	case STATE_LOGOUT_REQUESTED:
		/* read incoming PDU */
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
		iscsi_conn_context_put(conn_context);
		log_debug(1, "ignoring incoming PDU in XPT_WAIT. "
			  "let connection re-establish or fail");
		break;
	case STATE_CLEANUP_WAIT:
		iscsi_conn_context_put(conn_context);
		log_debug(1, "ignoring incoming PDU in XPT_WAIT. "
			  "let connection cleanup");
		break;
	default:
		iscsi_conn_context_put(conn_context);
		log_error("Invalid state. Dropping PDU.\n");
	}
}

static void session_increase_wq_priority(struct iscsi_session *session)
{
	DIR *proc_dir;
	struct dirent *proc_dent;
	struct stat statb;
	char stat_file[PATH_SIZE];
	char sbuf[1024];	/* got this from ps */
	int pid, stat_fd, num_read;
	char *proc_name, *proc_name_end;
	uint32_t host_no;

	/* drivers like bnx2i and qla4xxx do not have a write wq */
	if (session->t->caps & CAP_DATA_PATH_OFFLOAD)
		return;

	proc_dir = opendir(PROC_DIR);
	if (!proc_dir)
		goto fail;

	while ((proc_dent = readdir(proc_dir))) {
		if (!strcmp(proc_dent->d_name, ".") ||
		    !strcmp(proc_dent->d_name, ".."))
			continue;
		if (sscanf(proc_dent->d_name, "%d", &pid) != 1)
			continue;

		memset(stat_file, 0, sizeof(stat_file));
		sprintf(stat_file, PROC_DIR"/%d/stat", pid);
		if (stat(stat_file, &statb))
			continue;

		if (!S_ISREG( statb.st_mode))
			continue;

		stat_fd = open(stat_file, O_RDONLY);
		if (stat_fd == -1)
			continue;

		memset(sbuf, 0, sizeof(sbuf));
		num_read = read(stat_fd, sbuf, sizeof(sbuf));
		close(stat_fd);
		if (num_read == -1)
			continue;
		if (num_read == sizeof(sbuf))
			sbuf[num_read - 1] = '\0';
		else
			sbuf[num_read] = '\0';

		/*
		 * Finally match proc name to iscsi thread name.
		 * In newer kernels the name is iscsi_wq_%HOST_NO.
		 * In older kernels before 2.6.30, it was scsi_wq_%HOST_NO.
		 *
		 * We only support newer kernels.
		 */
		proc_name = strchr(sbuf, '(') + 1;
		if (!proc_name)
			continue;

		proc_name_end = strchr(proc_name, ')');
		if (!proc_name_end)
			continue;

		*proc_name_end = '\0';

		if (sscanf(proc_name, "iscsi_q_%u\n", &host_no) == 1) {
			if (host_no == session->hostno) {
				if (!setpriority(PRIO_PROCESS, pid,
					session->nrec.session.xmit_thread_priority)) {
					closedir(proc_dir);
					return;
				} else
					break;
			}
		}
	}
	closedir(proc_dir);
fail:
	log_error("Could not set session%d priority. "
		  "READ/WRITE throughout and latency could be "
		  "affected.\n", session->id);
}

static int session_ipc_create(struct iscsi_session *session)
{
	struct iscsi_conn *conn = &session->conn[0];
	int err = 0, pass_ep = 1;
	uint32_t host_no = -1;

	if (session->t->template->ep_connect != ktransport_ep_connect)
		pass_ep = 0;
retry_create:
	err = ipc->create_session(session->t->handle,
				  pass_ep ? conn->transport_ep_handle : 0,
				  session->nrec.session.initial_cmdsn,
				  session->nrec.session.cmds_max,
				  session->nrec.session.queue_depth,
				  &session->id, &host_no);
	/*
	 * Older kernels were not passed the sessions's leading conn ep,
	 * so we will get -EINVAL || -ENOSYS for iser.
	 *
	 * 2.6.22 and earlier would send -EINVAL instead of -ENOSYS.
	 */
	if (pass_ep && (err == -ENOSYS || err == -EINVAL)) {
		pass_ep = 0;
		goto retry_create;
	}

	if (!err) {
		session->hostno = host_no;
		session_increase_wq_priority(session);
	}
	return err;
}

static void session_conn_poll(void *data)
{
	struct iscsi_conn_context *conn_context = data;
	iscsi_conn_t *conn = conn_context->conn;
	struct iscsi_session *session = conn->session;
	mgmt_ipc_err_e err = MGMT_IPC_OK;
	queue_task_t *qtask = conn_context->data;
	iscsi_login_context_t *c = &conn->login_context;
	int rc;

	iscsi_conn_context_put(conn_context);

	if (conn->state != STATE_XPT_WAIT)
		return;

	rc = session->t->template->ep_poll(conn, 1);
	if (rc == 0) {
		log_debug(4, "poll not connected %d", rc);
		/* timedout: Poll again. */
		conn_context = iscsi_conn_context_get(conn, 0);
		if (!conn_context) {
			/* while polling the recv pool should be full */
			log_error("BUG: session_conn_poll could not get conn "
				  "context.");
			iscsi_login_eh(conn, qtask, MGMT_IPC_ERR_INTERNAL);
			return;
		}
		conn_context->data = qtask;
		iscsi_sched_conn_context(conn_context, conn, 0, EV_CONN_POLL);
	} else if (rc > 0) {
		/* connected! */
		memset(c, 0, sizeof(iscsi_login_context_t));

		/* do not allocate new connection in case of reopen */
		if (session->id == -1) {
			if (conn->id == 0 && session_ipc_create(session)) {
				log_error("Can't create session.");
				err = MGMT_IPC_ERR_INTERNAL;
				goto cleanup;
			}
			log_debug(3, "created new iSCSI session sid %d host "
				  "no %u", session->id, session->hostno);

			if (ipc->create_conn(session->t->handle,
					session->id, conn->id, &conn->id)) {
				log_error("Can't create connection.");
				err = MGMT_IPC_ERR_INTERNAL;
				goto cleanup;
			}
			log_debug(3, "created new iSCSI connection "
				  "%d:%d", session->id, conn->id);
		}

		iscsi_copy_operational_params(conn);

		if (session->t->template->create_conn)
			session->t->template->create_conn(conn);
		/*
		 * TODO: use the iface number or some other value
		 * so this will be persistent
		 */
		session->isid[3] = session->id;

		if (ipc->bind_conn(session->t->handle, session->id,
				   conn->id, conn->transport_ep_handle,
				   (conn->id == 0), &rc) || rc) {
			log_error("can't bind conn %d:%d to session %d, "
				  "retcode %d (%d)", session->id, conn->id,
				   session->id, rc, errno);
			iscsi_login_eh(conn, qtask, MGMT_IPC_ERR_LOGIN_FAILURE);
			return;
		}
		log_debug(3, "bound iSCSI connection %d:%d to session %d",
			  session->id, conn->id, session->id);

		c->qtask = qtask;
		c->cid = conn->id;
		c->buffer = conn->data;
		c->bufsize = sizeof(conn->data);

		conn->exp_statsn = iscsi_sysfs_get_exp_statsn(session->id);

		if (iscsi_login_begin(session, c)) {
			iscsi_login_eh(conn, qtask, MGMT_IPC_ERR_LOGIN_FAILURE);
			return;
		}

		conn->state = STATE_IN_LOGIN;
		if (iscsi_login_req(session, c)) {
			iscsi_login_eh(conn, qtask, MGMT_IPC_ERR_LOGIN_FAILURE);
			return;
		}
	} else {
		log_debug(4, "poll error %d", rc);
		queue_delayed_reopen(qtask, ISCSI_CONN_ERR_REOPEN_DELAY);
	}

	return;

cleanup:
	session_conn_shutdown(conn, qtask, err);
}

void iscsi_sched_conn_context(struct iscsi_conn_context *conn_context,
			      struct iscsi_conn *conn, unsigned long tmo,
			      int event)
{
	enum iscsi_err error;

	log_debug(7, "sched conn context %p event %d, tmo %lu",
		  &conn_context->actor, event, tmo);

	conn_context->conn = conn;
	switch (event) {
	case EV_CONN_RECV_PDU:
		actor_new(&conn_context->actor, session_conn_recv_pdu,
			  conn_context);
		actor_schedule(&conn_context->actor);
		break;
	case EV_CONN_ERROR:
		error = *(enum iscsi_err *)conn_context->data;

		actor_new(&conn_context->actor, session_conn_error,
			  conn_context);
		/*
		 * We handle invalid host, by killing the session.
		 * It must go at the head of the queue, so we do not
		 * initiate error handling or logout or some other op.
		 */
		if (error == ISCSI_ERR_INVALID_HOST)
			actor_schedule_head(&conn_context->actor);
		else
			actor_schedule(&conn_context->actor);
		break;
	case EV_CONN_POLL:
		actor_new(&conn_context->actor, session_conn_poll,
			  conn_context);
		actor_schedule(&conn_context->actor);
		break;
	case EV_CONN_LOGOUT_TIMER:
		actor_timer(&conn_context->actor, tmo * 1000,
			    iscsi_logout_timedout, conn_context);
		break;
	case EV_CONN_STOP:
		actor_new(&conn_context->actor, iscsi_stop,
			  conn_context);
		actor_schedule(&conn_context->actor);
		break;
	default:
		log_error("Invalid event type %d.", event);
		return;
	}
}

iscsi_session_t*
session_find_by_sid(int sid)
{
	struct iscsi_transport *t;
	iscsi_session_t *session;

	list_for_each_entry(t, &transports, list) {
		list_for_each_entry(session, &t->sessions, list) {
			if (session->id == sid)
				return session;
		}
	}
	return NULL;
}

static iscsi_session_t* session_find_by_rec(node_rec_t *rec)
{
	struct iscsi_transport *t;
	iscsi_session_t *session;

	list_for_each_entry(t, &transports, list) {
		list_for_each_entry(session, &t->sessions, list) {
			if (__iscsi_match_session(rec, session->nrec.name,
					 session->nrec.conn[0].address,
					 session->nrec.conn[0].port,
					 &session->nrec.iface))
				return session;
		}
	}
	return NULL;
}

/*
 * a session could be running in the kernel but not in iscsid
 * due to a resync or becuase some other app started the session
 */
static int session_is_running(node_rec_t *rec)
{
	int nr_found = 0;

	if (session_find_by_rec(rec))
		return 1;

	if (iscsi_sysfs_for_each_session(rec, &nr_found, iscsi_match_session))
		return 1;

	return 0;
}

static int iface_set_param(struct iscsi_transport *t, struct iface_rec *iface,
			   struct iscsi_session *session)
{
	int rc = 0;

	log_debug(3, "setting iface %s, dev %s, set ip %s, hw %s, "
		  "transport %s.\n",
		  iface->name, iface->netdev, iface->ipaddress,
		  iface->hwaddress, iface->transport_name);

	if (!t->template->set_host_ip)
		return 0;

	/* if we need to set the ip addr then set all the iface net settings */
	if (!iface_is_bound_by_ipaddr(iface)) {
		log_warning("Please set the iface.ipaddress for iface %s, "
			    "then retry the login command.\n", iface->name);
		return EINVAL;
	}

	rc = __iscsi_host_set_param(t, session->hostno,
				    ISCSI_HOST_PARAM_IPADDRESS,
				    iface->ipaddress, ISCSI_STRING);
	if (rc)
		return rc;

	if (iface_is_bound_by_netdev(iface)) {
		rc = __iscsi_host_set_param(t, session->hostno,
					    ISCSI_HOST_PARAM_NETDEV_NAME,
					    iface->netdev, ISCSI_STRING);
		if (rc)
			return rc;
	}

	if (iface_is_bound_by_hwaddr(iface)) {
		rc = __iscsi_host_set_param(t, session->hostno,
					    ISCSI_HOST_PARAM_HWADDRESS,
					    iface->hwaddress, ISCSI_STRING);
		if (rc)
			return rc;
	}
	return 0;
}

int
session_login_task(node_rec_t *rec, queue_task_t *qtask)
{
	iscsi_session_t *session;
	iscsi_conn_t *conn;
	struct iscsi_transport *t;

	if (session_is_running(rec))
		return MGMT_IPC_ERR_EXISTS;

	t = iscsi_sysfs_get_transport_by_name(rec->iface.transport_name);
	if (!t)
		return MGMT_IPC_ERR_TRANS_NOT_FOUND;
	if (set_transport_template(t))
		return MGMT_IPC_ERR_TRANS_NOT_FOUND;

	if ((!(t->caps & CAP_RECOVERY_L0) &&
	     rec->session.iscsi.ERL != 0) ||
	    (!(t->caps & CAP_RECOVERY_L1) &&
	     rec->session.iscsi.ERL > 1)) {
		log_error("Transport '%s' does not support ERL %d."
			  "Setting ERL to ERL0.\n",
			  t->name, rec->session.iscsi.ERL);
		rec->session.iscsi.ERL = 0;
	}

	if (!(t->caps & CAP_MULTI_R2T) &&
	    rec->session.iscsi.MaxOutstandingR2T) {
		log_error("Transport '%s' does not support "
			  "MaxOutstandingR2T %d. Setting "
			  "MaxOutstandingR2T to 1.", t->name,
			  rec->session.iscsi.MaxOutstandingR2T);
		rec->session.iscsi.MaxOutstandingR2T = 1;		
	}

	if (!(t->caps & CAP_HDRDGST) &&
	    rec->conn[0].iscsi.HeaderDigest) {
		log_error("Transport '%s' does not support "
			  "HeaderDigest != None. Setting HeaderDigest "
			  "to None.", t->name);
		rec->conn[0].iscsi.HeaderDigest = CONFIG_DIGEST_NEVER;
	}

	if (!(t->caps & CAP_DATADGST) &&
	    rec->conn[0].iscsi.DataDigest) {
		log_error("Transport '%s' does not support "
			  "DataDigest != None. Setting DataDigest "
			  "to None", t->name);
		rec->conn[0].iscsi.DataDigest = CONFIG_DIGEST_NEVER;
	}

	if (!(t->caps & CAP_MARKERS) &&
	    rec->conn[0].iscsi.IFMarker) {
		log_error("Transport '%s' does not support IFMarker. "
			  "Disabling IFMarkers.\n", t->name);
		rec->conn[0].iscsi.IFMarker = 0;
	}

	if (!(t->caps & CAP_MARKERS) &&
	    rec->conn[0].iscsi.OFMarker) {
		log_error("Transport '%s' does not support OFMarker."
			  "Disabling OFMarkers.\n", t->name);
		rec->conn[0].iscsi.OFMarker = 0;
	}

	session = __session_create(rec, t);
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

	if (iface_set_param(t, &rec->iface, session)) {
		__session_destroy(session);
		return MGMT_IPC_ERR_LOGIN_FAILURE;
	}

	conn->state = STATE_XPT_WAIT;
	if (iscsi_conn_connect(conn, qtask)) {
		__session_destroy(session);
		return MGMT_IPC_ERR_TRANS_FAILURE;
	}

	if (gettimeofday(&conn->initial_connect_time, NULL))
		log_error("Could not get initial connect time. If "
			  "login errors iscsid may give up the initial "
			  "login early. You should manually login.");

	qtask->rsp.command = MGMT_IPC_SESSION_LOGIN;
	qtask->rsp.err = MGMT_IPC_OK;
	return MGMT_IPC_OK;
}

static int
sync_conn(iscsi_session_t *session, uint32_t cid)
{
	iscsi_conn_t *conn;

	if (__session_conn_create(session, cid))
		return ENOMEM;
	conn = &session->conn[cid];

	/* TODO: must export via sysfs so we can pick this up */
	conn->state = STATE_CLEANUP_WAIT;
	return 0;
}

mgmt_ipc_err_e
iscsi_sync_session(node_rec_t *rec, queue_task_t *qtask, uint32_t sid)
{
	iscsi_session_t *session;
	struct iscsi_transport *t;
	int err;

	t = iscsi_sysfs_get_transport_by_name(rec->iface.transport_name);
	if (!t)
		return MGMT_IPC_ERR_TRANS_NOT_FOUND;
	if (set_transport_template(t))
		return MGMT_IPC_ERR_TRANS_NOT_FOUND;

	session = __session_create(rec, t);
	if (!session)
		return MGMT_IPC_ERR_LOGIN_FAILURE;

	session->id = sid;
	session->hostno = iscsi_sysfs_get_host_no_from_sid(sid, &err);
	if (err) {
		log_error("Could not get hostno for session %d\n", sid);
		err = MGMT_IPC_ERR_NOT_FOUND;
		goto destroy_session;
	}

	session->r_stage = R_STAGE_SESSION_REOPEN;

	err = sync_conn(session, 0);
	if (err) {
		if (err == ENOMEM)
			err = MGMT_IPC_ERR_NOMEM;
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

static int session_unbind(struct iscsi_session *session)
{
	int err;

	err = ipc->unbind_session(session->t->handle, session->id);
	if (err)
		/* older kernels did not support unbind */
		log_debug(2, "Could not unbind session %d.\n", err);
	return err;
}

int
session_logout_task(int sid, queue_task_t *qtask)
{
	iscsi_session_t *session;
	iscsi_conn_t *conn;
	mgmt_ipc_err_e rc = MGMT_IPC_OK;

	session = session_find_by_sid(sid);
	if (!session) {
                log_debug(1, "session sid %d not found.\n", sid);
		return MGMT_IPC_ERR_NOT_FOUND;
	}
	conn = &session->conn[0];
	/*
	 * If syncing up or if this is the initial login and mgmt_ipc
	 * has not been notified of that result fail the logout request
	 */
	if (session->sync_qtask ||
	    ((conn->state == STATE_XPT_WAIT ||
	      conn->state == STATE_IN_LOGIN) &&
	    (session->r_stage == R_STAGE_NO_CHANGE ||
	     session->r_stage == R_STAGE_SESSION_REDIRECT))) {
invalid_state:
		log_error("session in invalid state for logout. "
			   "Try again later\n");
		return MGMT_IPC_ERR_INTERNAL;
	}

	/* FIXME: logout all active connections */
	conn = &session->conn[0];
	/* FIXME: implement Logout Request */
	if (conn->logout_qtask)
		goto invalid_state;

	qtask->conn = conn;
	qtask->rsp.command = MGMT_IPC_SESSION_LOGOUT;
	conn->logout_qtask = qtask;

	switch (conn->state) {
	case STATE_LOGGED_IN:
		if (!session_unbind(session))
			return MGMT_IPC_OK;

		/* unbind is not supported so just do old logout */
		if (!iscsi_send_logout(conn))
			return MGMT_IPC_OK;
		log_error("Could not send logout pdu. Dropping session\n");
		/* fallthrough */
	default:
		rc = session_conn_shutdown(conn, qtask, MGMT_IPC_OK);
		break;
	}

	return rc;
}

mgmt_ipc_err_e
iscsi_host_send_targets(queue_task_t *qtask, int host_no, int do_login,
			struct sockaddr_storage *ss)
{
	struct iscsi_transport *t;

	t = iscsi_sysfs_get_transport_by_hba(host_no);
	if (!t || set_transport_template(t)) {
		log_error("Invalid host no %d for sendtargets\n", host_no);
		return MGMT_IPC_ERR_TRANS_FAILURE;
	}
	if (!(t->caps & CAP_SENDTARGETS_OFFLOAD))
		return MGMT_IPC_ERR_TRANS_CAPS;

	if (ipc->sendtargets(t->handle, host_no, (struct sockaddr *)ss))
		return MGMT_IPC_ERR;

	return MGMT_IPC_OK;
}

/*
 * HW drivers like qla4xxx present a interface that hides most of the iscsi
 * details. Userspace sends down a discovery event then it gets notified
 * if the sessions that were logged in as a result asynchronously, or
 * the card will have sessions preset in the FLASH and will log into them
 * automaotically then send us notification that a session is setup.
 */
void iscsi_async_session_creation(uint32_t host_no, uint32_t sid)
{
	struct iscsi_transport *transport;

	transport = iscsi_sysfs_get_transport_by_hba(host_no);
	if (!transport)
		return;

	if (!(transport->caps & CAP_FW_DB))
		return;

	log_debug(3, "session created sid %u host no %d", sid, host_no);
	session_online_devs(host_no, sid);
	session_scan_host(NULL, host_no, NULL);
}

void iscsi_async_session_destruction(uint32_t host_no, uint32_t sid)
{
	log_debug(3, "session destroyed sid %u host no %d", sid, host_no);
}
