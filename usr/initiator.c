/*
 * iSCSI Session Management and Slow-path Control
 *
 * Copyright (C) 2004 Dmitry Yusupov, Alex Aizman
 * maintained by open-iscsi@@googlegroups.com
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

#include <search.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <errno.h>
#include <sys/param.h>
#include <sys/ioctl.h>

#include "initiator.h"
#include "iscsid.h"
#include "iscsi_u.h"
#include "ipc.h"
#include "idbm.h"
#include "log.h"

static void __session_mainloop(void *data);

static cnx_login_status_e
login_response_status(iscsi_conn_t *conn,
		      enum iscsi_login_status login_status)
{
	switch (login_status) {
	case LOGIN_OK:
		/* check the status class and detail */
		return CNX_LOGIN_SUCCESS;
	case LOGIN_IO_ERROR:
	case LOGIN_WRONG_PORTAL_GROUP:
	case LOGIN_REDIRECTION_FAILED:
		iscsi_disconnect(conn);
		return CNX_LOGIN_RETRY;
	default:
		iscsi_disconnect(conn);
		log_error("cnx %d giving up on login attempts", conn->id);
		break;
	}

	return CNX_LOGIN_FAILED;
}

static cnx_login_status_e
check_iscsi_status_class(iscsi_session_t *session, int cid,
			uint8_t status_class, uint8_t status_detail)
{
	iscsi_conn_t *conn = &session->cnx[cid];

	switch (status_class) {
	case ISCSI_STATUS_CLS_SUCCESS:
		return CNX_LOGIN_SUCCESS;
	case ISCSI_STATUS_CLS_REDIRECT:
		switch (status_detail) {
		case ISCSI_LOGIN_STATUS_TGT_MOVED_TEMP:
			return CNX_LOGIN_IMM_RETRY;
		case ISCSI_LOGIN_STATUS_TGT_MOVED_PERM:
			/*
			 * for a permanent redirect, we need to update the
			 * portal address within a record,  and then try again.
			 */
                        return CNX_LOGIN_IMM_REDIRECT_RETRY;
		default:
			log_error("cnx %d login rejected: redirection "
			        "type 0x%x not supported",
				conn->id, status_detail);
			iscsi_disconnect(conn);
			return CNX_LOGIN_RETRY;
		}
	case ISCSI_STATUS_CLS_INITIATOR_ERR:
		iscsi_disconnect(conn);

		switch (status_detail) {
		case ISCSI_LOGIN_STATUS_AUTH_FAILED:
			log_error("cnx %d login rejected: Initiator "
			       "failed authentication with target", conn->id);
			if ((session->num_auth_buffers < 5) &&
			    (session->username || session->password_length ||
			    session->bidirectional_auth))
				/*
				 * retry, and hope we can allocate the auth
				 * structures next time.
				 */
				return CNX_LOGIN_RETRY;
			else
				return CNX_LOGIN_FAILED;
		case ISCSI_LOGIN_STATUS_TGT_FORBIDDEN:
			log_error("cnx %d login rejected: initiator "
			       "failed authorization with target", conn->id);
			return CNX_LOGIN_FAILED;
		case ISCSI_LOGIN_STATUS_TGT_NOT_FOUND:
			log_error("cnx %d login rejected: initiator "
			       "error - target not found (%02x/%02x)",
			       conn->id, status_class, status_detail);
			return CNX_LOGIN_FAILED;
		case ISCSI_LOGIN_STATUS_NO_VERSION:
			/*
			 * FIXME: if we handle multiple protocol versions,
			 * before we log an error, try the other supported
			 * versions.
			 */
			log_error("cnx %d login rejected: incompatible "
			       "version (%02x/%02x), non-retryable, "
			       "giving up", conn->id, status_class,
			       status_detail);
			return CNX_LOGIN_FAILED;
		default:
			log_error("cnx %d login rejected: initiator "
			       "error (%02x/%02x), non-retryable, "
			       "giving up", conn->id, status_class,
			       status_detail);
			return CNX_LOGIN_FAILED;
		}
	case ISCSI_STATUS_CLS_TARGET_ERR:
		log_error("cnx %d login rejected: target error "
		       "(%02x/%02x)\n", conn->id, status_class, status_detail);
		iscsi_disconnect(conn);
		/*
		 * We have no idea what the problem is. But spec says initiator
		 * may retry later.
		 */
		 return CNX_LOGIN_RETRY;
	default:
		log_error("cnx %d login response with unknown status "
		       "class 0x%x, detail 0x%x\n", conn->id, status_class,
		       status_detail);
		iscsi_disconnect(conn);
		break;
	}

	return CNX_LOGIN_FAILED;
}

static void
setup_authentication(iscsi_session_t *session,
			struct iscsi_auth_config *auth_cfg)
{
	/* if we have any incoming credentials, we insist on authenticating
	 * the target or not logging in at all
	 */
	if (auth_cfg->username_in[0]
	    || auth_cfg->password_length_in) {
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
	if ((session->password_length_in =
	     auth_cfg->password_length_in))
		memcpy(session->password_in, auth_cfg->password_in,
		       session->password_length_in);

	if (session->password_length || session->password_length_in) {
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
	} else {
		session->num_auth_buffers = 0;
	}
}

int
session_cnx_create(iscsi_session_t *session, int cid)
{
	struct hostent *hostn = NULL;
	iscsi_conn_t *conn = &session->cnx[cid];
	cnx_rec_t *cnx = &session->nrec.cnx[cid];

	/* connection's timeouts */
	conn->id = cid;
	conn->login_timeout = cnx->timeo.login_timeout;
	conn->auth_timeout = cnx->timeo.auth_timeout;
	conn->active_timeout = cnx->timeo.active_timeout;
	conn->idle_timeout = cnx->timeo.idle_timeout;
	conn->ping_timeout = cnx->timeo.ping_timeout;

	/* operational parameters */
	conn->max_recv_dlength =
			cnx->iscsi.MaxRecvDataSegmentLength;
	/*
	 * iSCSI default, unless declared otherwise by the
	 * target during login
	 */
	conn->max_xmit_dlength = DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH;
	conn->hdrdgst_en = cnx->iscsi.HeaderDigest;
	conn->datadgst_en = cnx->iscsi.DataDigest;

	/* TCP options */
	conn->tcp_window_size = cnx->tcp.window_size;
	/* FIXME: type_of_service */

	/* resolve the string address to an IP address */
	while (!hostn) {
		hostn = gethostbyname(cnx->address);
		if (hostn) {
			/* save the resolved address */
			conn->ip_length = hostn->h_length;
			conn->port = cnx->port;
			memcpy(&conn->ip_address, hostn->h_addr,
			       MIN(sizeof(cnx->address), hostn->h_length));
			/* FIXME: IPv6 */
			log_debug(4, "resolved %s to %u.%u.%u.%u",
				 cnx->address, conn->ip_address[0],
				 conn->ip_address[1], conn->ip_address[2],
				 conn->ip_address[3]);
		} else {
			log_error("cannot resolve host name %s", cnx->address);
			return 1;
		}
	}

	conn->rx_buffer = malloc(DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH);
	if (conn->rx_buffer == NULL) {
		log_error("failed to allocate connection's rx buffer");
		return 1;
	}

	conn->state = STATE_IDLE;
	conn->session = session;

	return 0;
}

void
session_cnx_destroy(iscsi_session_t *session, int cid)
{
	iscsi_conn_t *conn = &session->cnx[cid];
	free(conn->rx_buffer);
}

#if 0
cnx_login_status_e
establish_cnx(iscsi_session_t *session, iscsi_conn_t *conn, cnx_rec_t *cnx) {
	uint8_t status_class;
	uint8_t status_detail;
	enum iscsi_login_status login_status;
	cnx_login_status_e rc;


	login_status = iscsi_login(session, conn->id, rx_buffer,
			   DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH, &status_class,
			   &status_detail);
	rc = login_response_status(conn, login_status);
	if (rc != CNX_LOGIN_SUCCESS) {
		free(rx_buffer);
		return rc;
	}

	/* check the login status */
	rc = check_iscsi_status_class(session, conn->id, status_class,
				status_detail);
	if (rc != CNX_LOGIN_SUCCESS) {
		free(rx_buffer);
		return rc;
	}

	free(rx_buffer);
	return CNX_LOGIN_SUCCESS;
}
#endif

iscsi_session_t*
session_create(node_rec_t *rec)
{
	iscsi_session_t *session;

	session = calloc(1, sizeof (*session));
	if (session == NULL) {
		log_debug(1, "can not allocate memory for session");
		return NULL;
	}

	/* save node record. we might need it for redirection */
	memcpy(&session->nrec, rec, sizeof(node_rec_t));

	/* initalize per-session queue */
	session->queue = queue_create(4096, 256*1024, NULL, session);
	if (session->queue == NULL) {
		log_debug(1, "can not create session's queue");
		free(session);
		return NULL;
	}

	/* initalize per-session event processor */
	actor_new(&session->mainloop, __session_mainloop, session);
	actor_schedule(&session->mainloop);

	/* session's operational parameters */
	session->initial_r2t_en = rec->session.iscsi.InitialR2T;
	session->imm_data_en = rec->session.iscsi.ImmediateData;
	session->first_burst = rec->session.iscsi.FirstBurstLength;
	session->max_burst = rec->session.iscsi.MaxBurstLength;
	session->def_time2wait = rec->session.iscsi.DefaultTime2Wait;
	session->def_time2retain = rec->session.iscsi.DefaultTime2Retain;
	session->portal_group_tag = rec->tpgt;
	session->type = ISCSI_SESSION_TYPE_NORMAL;
	session->initiator_name = dconfig->initiator_name;
	session->initiator_alias = dconfig->initiator_alias;
	strncpy(session->target_name, rec->name, TARGET_NAME_MAXLEN);
	session->vendor_specific_keys = 1;

	/* OUI and uniqifying number */
	session->isid[0] = DRIVER_ISID_0;
	session->isid[1] = DRIVER_ISID_1;
	session->isid[2] = DRIVER_ISID_2;
	session->isid[3] = 0;
	session->isid[4] = 0;
	session->isid[5] = 0;

	/* setup authentication variables for the session*/
	setup_authentication(session, &rec->session.auth);

	insque(&session->item, &provider[0].sessions);

	return session;
}

void
session_destroy(iscsi_session_t *session)
{
	remque(&session->item);
	queue_flush(session->queue);
	queue_destroy(session->queue);
	actor_delete(&session->mainloop);
	free(session);
}

static int
__ksession_create(iscsi_session_t *session)
{
	int rc;
	iscsi_uevent_t ev;

	memset(&ev, 0, sizeof(iscsi_uevent_t));

	ev.type = ISCSI_UEVENT_CREATE_SESSION;
	ev.provider_id = 0; /* FIXME: hardcoded */
	ev.u.c_session.session_handle = (ulong_t)session;
	ev.u.c_session.sid = session->id;
	ev.u.c_session.initial_cmdsn = session->nrec.session.initial_cmdsn;

	if ((rc = ioctl(ctrl_fd, ISCSI_UEVENT_CREATE_SESSION, &ev)) < 0) {
		log_error("can't create a session with id = %d (%d)",
			  session->id, errno);
		return rc;
	}

	session->handle = ev.r.handle;
	log_debug(3, "created new iSCSI session, handle 0x%llx",
		  (uint64_t)session->handle);

	return 0;
}

static int
__ksession_cnx_create(iscsi_session_t *session, iscsi_conn_t *conn)
{
	int rc;
	iscsi_uevent_t ev;

	memset(&ev, 0, sizeof(iscsi_uevent_t));

	ev.type = ISCSI_UEVENT_CREATE_CNX;
	ev.provider_id = 0; /* FIXME: hardcoded */
	ev.u.c_cnx.session_handle = session->handle;
	ev.u.c_cnx.cnx_handle = (ulong_t)conn;
	ev.u.c_cnx.socket_fd = conn->socket_fd;
	ev.u.c_cnx.cid = conn->id;

	if ((rc = ioctl(ctrl_fd, ISCSI_UEVENT_CREATE_CNX, &ev)) < 0) {
		log_error("can't create a cnx with id = %d (%d)",
			  conn->id, errno);
		return rc;
	}

	conn->handle = ev.r.handle;
	log_debug(3, "created new iSCSI connection, handle 0x%llx",
		  (uint64_t)conn->handle);

	return 0;
}

static int
__ksession_cnx_bind(iscsi_session_t *session, iscsi_conn_t *conn)
{
	int rc;
	iscsi_uevent_t ev;

	memset(&ev, 0, sizeof(iscsi_uevent_t));

	ev.type = ISCSI_UEVENT_BIND_CNX;
	ev.provider_id = 0; /* FIXME: hardcoded */
	ev.u.b_cnx.session_handle = session->handle;
	ev.u.b_cnx.handle = conn->handle;
	ev.u.b_cnx.is_leading = (conn->id == 0);

	if ((rc = ioctl(ctrl_fd, ISCSI_UEVENT_BIND_CNX, &ev)) < 0) {
		log_error("can't bind a cnx with id = %d (%d), retcode %d",
			  conn->id, errno,  ev.r.retcode);
		return rc;
	}

	log_debug(3, "binded iSCSI connection (handle 0x%llx) to "
		  "session (handle 0x%llx)", (uint64_t)conn->handle,
		  (uint64_t)session->handle);

	return 0;
}

static int
__ksession_send_pdu_begin(iscsi_session_t *session, iscsi_conn_t *conn,
			int hdr_size, int data_size)
{
	int rc;
	iscsi_uevent_t ev;

	memset(&ev, 0, sizeof(iscsi_uevent_t));

	ev.type = ISCSI_UEVENT_SEND_PDU_BEGIN;
	ev.provider_id = 0; /* FIXME: hardcoded */
	ev.u.sp_begin.cnx_handle = conn->handle;
	ev.u.sp_begin.hdr_size = hdr_size;
	ev.u.sp_begin.data_size = data_size;

	if ((rc = ioctl(ctrl_fd, ISCSI_UEVENT_SEND_PDU_BEGIN, &ev)) < 0) {
		log_error("can't initiate send PDU operation for cnx with "
			  "id = %d (%d), retcode %d",
			  conn->id, errno, ev.r.retcode);
		return rc;
	}

	log_debug(3, "send PDU began for hdr %d bytes and data %d bytes",
		hdr_size, data_size);

	return 0;
}

static int
__ksession_send_pdu_end(iscsi_session_t *session, iscsi_conn_t *conn)
{
	int rc;
	iscsi_uevent_t ev;

	memset(&ev, 0, sizeof(iscsi_uevent_t));

	ev.type = ISCSI_UEVENT_SEND_PDU_END;
	ev.provider_id = 0; /* FIXME: hardcoded */
	ev.u.sp_end.cnx_handle = conn->handle;

	if ((rc = ioctl(ctrl_fd, ISCSI_UEVENT_SEND_PDU_END, &ev)) < 0) {
		log_error("can't finish send PDU operation for cnx with "
			  "id = %d (%d), retcode %d",
			  conn->id, errno, ev.r.retcode);
		return rc;
	}

	log_debug(3, "send PDU finished for cnx (handle %llx)",
		(uint64_t)conn->handle);

	return 0;
}

#if 0
	/* the only leading connection */
	if (cid == 0) {
		session->leadcnx = cnx;
		/* setup session's parameters once */
		if (provider->ops.set_param(cnx->handle,
			ISCSI_PARAM_INITIAL_R2T_EN,
			initiator.sp.initial_r2t_en))
			goto setparam_fail;
		if (provider->ops.set_param(cnx->handle,
			ISCSI_PARAM_MAX_R2T, initiator.sp.max_r2t))
			goto setparam_fail;
		if (provider->ops.set_param(cnx->handle,
			ISCSI_PARAM_IMM_DATA_EN, initiator.sp.imm_data_en))
			goto setparam_fail;
		if (provider->ops.set_param(cnx->handle,
			ISCSI_PARAM_FIRST_BURST, initiator.sp.first_burst))
			goto setparam_fail;
		if (provider->ops.set_param(cnx->handle,
			ISCSI_PARAM_MAX_BURST, initiator.sp.max_burst))
			goto setparam_fail;
		if (provider->ops.set_param(cnx->handle,
			ISCSI_PARAM_PDU_INORDER_EN,
			initiator.sp.pdu_inorder_en))
			goto setparam_fail;
		if (provider->ops.set_param(cnx->handle,
			ISCSI_PARAM_DATASEQ_INORDER_EN,
			initiator.sp.dataseq_inorder_en))
			goto setparam_fail;
		if (provider->ops.set_param(cnx->handle,
			ISCSI_PARAM_ERL, initiator.sp.erl))
			goto setparam_fail;
		if (provider->ops.set_param(cnx->handle,
			ISCSI_PARAM_IFMARKER_EN, initiator.sp.ifmarker_en))
			goto setparam_fail;
		if (provider->ops.set_param(cnx->handle,
			ISCSI_PARAM_OFMARKER_EN, initiator.sp.ofmarker_en))
			goto setparam_fail;
	}
	if (provider->ops.set_param(cnx->handle,
		ISCSI_PARAM_MAX_RECV_DLENGH, initiator.cp.max_recv_dlength))
		goto setparam_fail;
	if (provider->ops.set_param(cnx->handle,
		ISCSI_PARAM_MAX_XMIT_DLENGH, initiator.cp.max_xmit_dlength))
		goto setparam_fail;
	if (provider->ops.set_param(cnx->handle,
		ISCSI_PARAM_HDRDGST_EN, initiator.cp.hdrdgst_en))
		goto setparam_fail;
	if (provider->ops.set_param(cnx->handle,
		ISCSI_PARAM_DATADGST_EN, initiator.cp.datadgst_en))
		goto setparam_fail;
#endif

static void
__session_ipc_login_cleanup(queue_task_t *qtask, ipc_err_e err)
{
	iscsi_conn_t *conn = qtask->conn;
	iscsi_session_t *session = conn->session;

	qtask->u.login.rsp.err = err;
	write(qtask->u.login.ipc_fd, &qtask->u.login.rsp,
		sizeof(qtask->u.login.rsp));
	close(qtask->u.login.ipc_fd);
	free(qtask);
	if (conn->login_context.buffer)
		free(conn->login_context.buffer);
	session_cnx_destroy(session, conn->id);
	if (conn->id == 0)
		session_destroy(session);
}

static int
__ksession_set_param(iscsi_conn_t *conn, iscsi_param_e param, uint32_t value)
{
	int rc;
	iscsi_uevent_t ev;

	memset(&ev, 0, sizeof(iscsi_uevent_t));

	ev.type = ISCSI_UEVENT_SET_PARAM;
	ev.provider_id = 0; /* FIXME: hardcoded */
	ev.u.set_param.cnx_handle = (ulong_t)conn->handle;
	ev.u.set_param.param = param;
	ev.u.set_param.value = value;

	if ((rc = ioctl(ctrl_fd, ISCSI_UEVENT_SET_PARAM, &ev)) < 0) {
		log_error("can't set operational parameter %d for cnx with "
			  "id = %d (%d)", param, conn->id, errno);
		return rc;
	}

	log_debug(3, "set operational parameter %d to %u",
			param, value);

	return 0;
}

static int
__ksession_start_cnx(iscsi_conn_t *conn)
{
	int rc;
	iscsi_uevent_t ev;

	memset(&ev, 0, sizeof(iscsi_uevent_t));

	ev.type = ISCSI_UEVENT_SET_PARAM;
	ev.provider_id = 0; /* FIXME: hardcoded */
	ev.u.start_cnx.cnx_handle = (ulong_t)conn->handle;

	if ((rc = ioctl(ctrl_fd, ISCSI_UEVENT_START_CNX, &ev)) < 0) {
		log_error("can't start connection 0x%llx with "
			  "id = %d (%d)", (uint64_t)conn->handle,
			  conn->id, errno);
		return rc;
	}

	log_debug(3, "connection 0x%llx operational now",
			(uint64_t)conn->handle);

	return 0;
}

static int
__ksession_recv_pdu_begin(iscsi_conn_t *conn, ulong_t recv_handle,
				ulong_t *pdu_handle, int *pdu_size)
{
	int rc;
	iscsi_uevent_t ev;

	memset(&ev, 0, sizeof(iscsi_uevent_t));

	ev.type = ISCSI_UEVENT_RECV_PDU_BEGIN;
	ev.provider_id = 0; /* FIXME: hardcoded */
	ev.u.rp_begin.cpcnx_handle = (ulong_t)conn;
	ev.u.rp_begin.recv_handle = recv_handle;

	if ((rc = ioctl(ctrl_fd, ISCSI_UEVENT_RECV_PDU_BEGIN, &ev)) < 0) {
		log_error("can't initiate recv PDU operation for cnx with "
			  "id = %d (%d)", conn->id, errno);
		return rc;
	}

	*pdu_handle = ev.r.rp_begin.pdu_handle;
	*pdu_size = ev.r.rp_begin.pdu_size;

	log_debug(3, "recv PDU began, pdu handle 0x%llx size %d",
		  (uint64_t)*pdu_handle, *pdu_size);

	return 0;
}

static int
__ksession_recv_pdu_end(iscsi_conn_t *conn, ulong_t pdu_handle)
{
	int rc;
	iscsi_uevent_t ev;

	memset(&ev, 0, sizeof(iscsi_uevent_t));

	ev.type = ISCSI_UEVENT_RECV_PDU_END;
	ev.provider_id = 0; /* FIXME: hardcoded */
	ev.u.rp_end.cpcnx_handle = (ulong_t)conn;
	ev.u.rp_end.pdu_handle = pdu_handle;

	if ((rc = ioctl(ctrl_fd, ISCSI_UEVENT_RECV_PDU_END, &ev)) < 0) {
		log_error("can't finish recv PDU operation for cnx with "
			  "id = %d (%d)", conn->id, errno);
		return rc;
	}

	log_debug(3, "recv PDU finished for pdu handle 0x%llx",
		  (uint64_t)pdu_handle);

	return 0;
}

static void
__session_cnx_recv_pdu(queue_item_t *item)
{
	ulong_t recv_handle = *(ulong_t*)queue_item_data(item);
	iscsi_conn_t *conn = item->context;
	iscsi_session_t *session = conn->session;

	if (conn->state == STATE_WAIT_LOGIN_RSP) {
		iscsi_login_context_t *c = &conn->login_context;

		conn->recv_handle = recv_handle;

		if (iscsi_login_rsp(session, c)) {
			__session_ipc_login_cleanup(c->qtask,
					IPC_ERR_LOGIN_FAILURE);
			return;
		}

		if (conn->current_stage != ISCSI_FULL_FEATURE_PHASE) {
			/* more nego. needed! */
			conn->state = STATE_WAIT_LOGIN_RSP;
			if (iscsi_login_req(session, c)) {
				__session_ipc_login_cleanup(c->qtask,
						IPC_ERR_LOGIN_FAILURE);
				return;
			}
		} else {
			/* almost! entered full-feature phase */

			if (login_response_status(conn, c->ret) !=
						CNX_LOGIN_SUCCESS) {
				__session_ipc_login_cleanup(c->qtask,
						IPC_ERR_LOGIN_FAILURE);
				return;
			}

			/* check the login status */
			if (check_iscsi_status_class(session, conn->id,
				c->status_class, c->status_detail) !=
							CNX_LOGIN_SUCCESS) {
				__session_ipc_login_cleanup(c->qtask,
						IPC_ERR_LOGIN_FAILURE);
				return;
			}

			/* Entered full-feature phase! */

			if (__ksession_set_param(conn,
				ISCSI_PARAM_MAX_RECV_DLENGTH,
				conn->max_recv_dlength)) {
				__session_ipc_login_cleanup(c->qtask,
						IPC_ERR_LOGIN_FAILURE);
				return;
			}
			if (__ksession_set_param(conn,
				ISCSI_PARAM_MAX_XMIT_DLENGTH,
				conn->max_xmit_dlength)) {
				__session_ipc_login_cleanup(c->qtask,
						IPC_ERR_LOGIN_FAILURE);
				return;
			}
			if (__ksession_set_param(conn,
				ISCSI_PARAM_HDRDGST_EN, conn->hdrdgst_en)) {
				__session_ipc_login_cleanup(c->qtask,
						IPC_ERR_LOGIN_FAILURE);
				return;
			}
			if (__ksession_set_param(conn,
				ISCSI_PARAM_DATADGST_EN, conn->datadgst_en)) {
				__session_ipc_login_cleanup(c->qtask,
						IPC_ERR_LOGIN_FAILURE);
				return;
			}
			if (conn->id == 0) {
				/* setup session's op. parameters just once */
				if (__ksession_set_param(conn,
					ISCSI_PARAM_INITIAL_R2T_EN,
					session->initial_r2t_en)) {
					__session_ipc_login_cleanup(c->qtask,
							IPC_ERR_LOGIN_FAILURE);
					return;
				}
				if (__ksession_set_param(conn,
					ISCSI_PARAM_MAX_R2T,
					1 /* FIXME: session->max_r2t */)) {
					__session_ipc_login_cleanup(c->qtask,
							IPC_ERR_LOGIN_FAILURE);
					return;
				}
				if (__ksession_set_param(conn,
					ISCSI_PARAM_IMM_DATA_EN,
					session->imm_data_en)) {
					__session_ipc_login_cleanup(c->qtask,
							IPC_ERR_LOGIN_FAILURE);
					return;
				}
				if (__ksession_set_param(conn,
					ISCSI_PARAM_FIRST_BURST,
					session->first_burst)) {
					__session_ipc_login_cleanup(c->qtask,
							IPC_ERR_LOGIN_FAILURE);
					return;
				}
				if (__ksession_set_param(conn,
					ISCSI_PARAM_MAX_BURST,
					session->max_burst)) {
					__session_ipc_login_cleanup(c->qtask,
							IPC_ERR_LOGIN_FAILURE);
					return;
				}
				if (__ksession_set_param(conn,
					ISCSI_PARAM_PDU_INORDER_EN,
					session->pdu_inorder_en)) {
					__session_ipc_login_cleanup(c->qtask,
							IPC_ERR_LOGIN_FAILURE);
					return;
				}
				if (__ksession_set_param(conn,
					ISCSI_PARAM_DATASEQ_INORDER_EN,
					session->dataseq_inorder_en)) {
				}
				if (__ksession_set_param(conn,
					ISCSI_PARAM_ERL,
					0 /* FIXME: session->erl */)) {
					__session_ipc_login_cleanup(c->qtask,
							IPC_ERR_LOGIN_FAILURE);
					return;
				}
				if (__ksession_set_param(conn,
					ISCSI_PARAM_IFMARKER_EN,
					0 /* FIXME: session->ifmarker_en */)) {
					__session_ipc_login_cleanup(c->qtask,
							IPC_ERR_LOGIN_FAILURE);
					return;
				}
				if (__ksession_set_param(conn,
					ISCSI_PARAM_OFMARKER_EN,
					0 /* FIXME: session->ofmarker_en */)) {
					__session_ipc_login_cleanup(c->qtask,
							IPC_ERR_LOGIN_FAILURE);
					return;
				}

			}

			if (__ksession_start_cnx(conn)) {
				__session_ipc_login_cleanup(c->qtask,
						IPC_ERR_INTERNAL);
				return;
			}
		}
	}
}

static void
__session_cnx_poll(queue_item_t *item)
{
	queue_task_t *qtask = item->context;
	iscsi_conn_t *conn = qtask->conn;
	iscsi_session_t *session = conn->session;
	int rc;

	if (conn->state == STATE_WAIT_CONNECT) {
		rc = iscsi_tcp_poll(conn);
		if (rc == 0) {
			/* timedout: poll again */
			queue_produce(session->queue, EV_CNX_POLL, qtask, 0, 0);
			actor_schedule(&session->mainloop);
		} else if (rc > 0) {
			iscsi_login_context_t *c = &conn->login_context;

			/* connected! */

			memset(c, 0, sizeof(iscsi_login_context_t));

			actor_delete(&conn->connect_timer);

			if (conn->id == 0 && __ksession_create(session)) {
				__session_ipc_login_cleanup(qtask,
						IPC_ERR_INTERNAL);
				return;
			}

			if (__ksession_cnx_create(session, conn)) {
				__session_ipc_login_cleanup(qtask,
						IPC_ERR_INTERNAL);
				return;
			}

			if (__ksession_cnx_bind(session, conn)) {
				__session_ipc_login_cleanup(qtask,
						IPC_ERR_INTERNAL);
				return;
			}

			conn->kernel_io = 1;
			conn->ctrl_fd = ctrl_fd;
			conn->send_pdu_begin = __ksession_send_pdu_begin;
			conn->send_pdu_end = __ksession_send_pdu_end;
			conn->recv_pdu_begin = __ksession_recv_pdu_begin;
			conn->recv_pdu_end = __ksession_recv_pdu_end;

			c->qtask = qtask;
			c->cid = conn->id;
			c->buffer = calloc(1,
					DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH);
			if (!c->buffer) {
				log_error("failed to allocate recv "
					  "data buffer");
				__session_ipc_login_cleanup(qtask,
						IPC_ERR_NOMEM);
				return;
			}
			c->bufsize = DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH;

			if (iscsi_login_begin(session, c)) {
				__session_ipc_login_cleanup(qtask,
						IPC_ERR_LOGIN_FAILURE);
				return;
			}

			conn->state = STATE_WAIT_LOGIN_RSP;
			if (iscsi_login_req(session, c)) {
				__session_ipc_login_cleanup(qtask,
						IPC_ERR_LOGIN_FAILURE);
				return;
			}
		} else {
			actor_delete(&conn->connect_timer);
			/* error during connect */
			__session_ipc_login_cleanup(qtask,
						IPC_ERR_TCP_FAILURE);
		}
	}
}

static void
__session_cnx_timer(queue_item_t *item)
{
	queue_task_t *qtask = item->context;
	iscsi_conn_t *conn = qtask->conn;

	if (conn->state == STATE_WAIT_CONNECT) {
		/* timeout during connect. clean connection. write rsp */
		__session_ipc_login_cleanup(qtask, IPC_ERR_TCP_TIMEOUT);
		return;
	}
}

#if 0
static void
__session_cnx_logged_in(queue_item_t *item)
{

	/*
	 * FIXME: set these timeouts via set_param() API
	 *
	 * rec->session.timeo
	 * rec->session.timeo
	 * rec->session.err_timeo
	 */
}
#endif

static void
__session_mainloop(void *data)
{
	iscsi_session_t *session = data;
	unsigned char item_buf[sizeof(queue_item_t) + EVENT_PAYLOAD_MAX];
	queue_item_t *item = (queue_item_t *)(void *)item_buf;

	if (queue_consume(session->queue, EVENT_PAYLOAD_MAX,
				item) != QUEUE_IS_EMPTY) {
		switch (item->event_type) {
		case EV_CNX_RECV_PDU: __session_cnx_recv_pdu(item); break;
		case EV_CNX_POLL: __session_cnx_poll(item); break;
		case EV_CNX_TIMER: __session_cnx_timer(item); break;
		default:
			break;
		}
	}
}
