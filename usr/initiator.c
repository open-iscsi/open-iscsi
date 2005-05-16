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
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "initiator.h"
#include "iscsid.h"
#include "iscsi_if.h"
#include "iscsi_ifev.h"
#include "mgmt_ipc.h"
#include "iscsi_ipc.h"
#include "idbm.h"
#include "log.h"

static void __session_mainloop(void *data);

static char sysfs_file[PATH_MAX];

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
__session_delete_luns(iscsi_session_t *session)
{
	int lu = 0;

	do {
		pid_t pid;
		int fd;

		sprintf(sysfs_file, "/sys/class/scsi_host/host%d/"
			"device/target%d:0:0/%d:0:0:%d/delete",
			session->id, session->id, session->id, lu);
		fd = open(sysfs_file, O_WRONLY);
		if (fd < 0)
			continue;
		if (!(pid = fork())) {
			/* child */
			log_debug(4, "deleting device using %s", sysfs_file);
			write(fd, "1\n", 3);
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

/*
 * Scan a session from usersapce using sysfs
 */
static void
__session_scan_host(iscsi_session_t *session)
{
	pid_t pid;
	int fd;

	sprintf(sysfs_file, "/sys/class/scsi_host/host%d/scan", session->id);
	fd = open(sysfs_file, O_WRONLY);
	if (fd < 0) {
		log_error("could not scan scsi host%d\n", session->id);
		return;
	}
	if (!(pid = fork())) {
		/* child */
		log_debug(4, "scanning host%d using %s",session->id,
			  sysfs_file);
		write(fd, "- - -", 5);
		close(fd);
		exit(0);
	}
	if (pid > 0) {
		int attempts = 3, status, rc;
		while (!(rc = waitpid(pid, &status, WNOHANG)) && attempts--)
			sleep(1);
		if (!rc)
			log_debug(4, "could not finish scan scsi host%d "
				  "after delay\n", session->id);
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
		iscsi_io_disconnect(conn);
		return CONN_LOGIN_RETRY;
	default:
		iscsi_io_disconnect(conn);
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
			 * portal address within a record,  and then try again.
			 */
                        return CONN_LOGIN_IMM_REDIRECT_RETRY;
		default:
			log_error("conn %d login rejected: redirection "
			        "type 0x%x not supported",
				conn->id, status_detail);
			iscsi_io_disconnect(conn);
			return CONN_LOGIN_RETRY;
		}
	case ISCSI_STATUS_CLS_INITIATOR_ERR:
		iscsi_io_disconnect(conn);

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
		iscsi_io_disconnect(conn);
		/*
		 * We have no idea what the problem is. But spec says initiator
		 * may retry later.
		 */
		 return CONN_LOGIN_RETRY;
	default:
		log_error("conn %d login response with unknown status "
		       "class 0x%x, detail 0x%x\n", conn->id, status_class,
		       status_detail);
		iscsi_io_disconnect(conn);
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
		log_debug(6, "authentication setup complete...");
	} else {
		session->num_auth_buffers = 0;
		log_debug(6, "no authentication configured...");
	}
}

static int
__session_conn_create(iscsi_session_t *session, int cid)
{
	struct hostent *hostn = NULL;
	iscsi_conn_t *conn = &session->conn[cid];
	conn_rec_t *conn_rec = &session->nrec.conn[cid];

	if (__recvpool_alloc(conn)) {
		log_error("cannot allocate recvpool for conn cid %d", cid);
		return -ENOMEM;
	}

	/* connection's timeouts */
	conn->id = cid;
	conn->login_timeout = conn_rec->timeo.login_timeout;
	conn->auth_timeout = conn_rec->timeo.auth_timeout;
	conn->active_timeout = conn_rec->timeo.active_timeout;
	conn->idle_timeout = conn_rec->timeo.idle_timeout;
	conn->ping_timeout = conn_rec->timeo.ping_timeout;

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
	while (!hostn) {
		hostn = gethostbyname(conn_rec->address);
		if (hostn) {
			/* save the resolved address */
			conn->ip_length = hostn->h_length;
			conn->port = conn_rec->port;
			memcpy(&conn->ip_address, hostn->h_addr,
			       MIN(sizeof(conn_rec->address), hostn->h_length));
			/* FIXME: IPv6 */
			log_debug(4, "resolved %s to %u.%u.%u.%u",
				 conn_rec->address, conn->ip_address[0],
				 conn->ip_address[1], conn->ip_address[2],
				 conn->ip_address[3]);
		} else {
			log_error("cannot resolve host name %s",
				  conn_rec->address);
			return 1;
		}
	}

	conn->state = STATE_FREE;
	conn->session = session;

	return 0;
}

void
session_conn_destroy(iscsi_session_t *session, int cid)
{
	iscsi_conn_t *conn = &session->conn[cid];

	__recvpool_free(conn);
}

static iscsi_session_t*
__session_create(node_rec_t *rec, uint64_t transport_handle)
{
	iscsi_session_t *session;

	session = calloc(1, sizeof (*session));
	if (session == NULL) {
		log_debug(1, "can not allocate memory for session");
		return NULL;
	}

	/* opened at daemon load time (iscsid.c) */
	session->ctrl_fd = control_fd;
	session->transport_handle = transport_handle;

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
	session->vendor_specific_keys = 1;

	/* session's misc parameters */
	session->reopen_cnt = rec->session.reopen_max;

	/* OUI and uniqifying number */
	session->isid[0] = DRIVER_ISID_0;
	session->isid[1] = DRIVER_ISID_1;
	session->isid[2] = DRIVER_ISID_2;
	session->isid[3] = 0;
	session->isid[4] = 0;
	session->isid[5] = 0;

	/* setup authentication variables for the session*/
	__setup_authentication(session, &rec->session.auth);

	insque(&session->item, &provider[0].sessions);

	return session;
}

static void
__session_destroy(iscsi_session_t *session)
{
	remque(&session->item);
	queue_flush(session->queue);
	queue_destroy(session->queue);
	actor_delete(&session->mainloop);
	free(session);
}

static void
__session_conn_cleanup(iscsi_conn_t *conn)
{
	iscsi_session_t *session = conn->session;

	if (ipc->destroy_conn(session->transport_handle, conn->handle,
		conn->id)) {
		log_error("can not safely destroy connection %d", conn->id);
		return;
	}
	session_conn_destroy(session, conn->id);

	if (ipc->destroy_session(session->transport_handle, session->handle,
			session->id)) {
		log_error("can not safely destroy session %d", session->id);
		return;
	}
	if (conn->id == 0)
		__session_destroy(session);
}

static void
__session_mgmt_ipc_login_cleanup(queue_task_t *qtask, mgmt_ipc_err_e err,
				 int conn_cleanup)
{
	iscsi_conn_t *conn = qtask->conn;
	iscsi_session_t *session = conn->session;

	if (conn_cleanup) {
		iscsi_io_disconnect(conn);
		__session_conn_cleanup(conn);
	} else {
		session_conn_destroy(session, conn->id);
		if (conn->id == 0)
			__session_destroy(session);
	}

	if (session->r_stage != R_STAGE_SESSION_REOPEN) {
		qtask->u.login.rsp.err = err;
		write(qtask->u.login.mgmt_ipc_fd, &qtask->u.login.rsp,
			sizeof(qtask->u.login.rsp));
		close(qtask->u.login.mgmt_ipc_fd);
		free(qtask);
	}
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
__session_conn_recv_pdu(queue_item_t *item)
{
	iscsi_conn_t *conn = item->context;
	iscsi_session_t *session = conn->session;

	conn->recv_handle = *(uintptr_t*)queue_item_data(item);

	if (conn->state == STATE_IN_LOGIN) {
		iscsi_login_context_t *c = &conn->login_context;

		if (iscsi_login_rsp(session, c)) {
			log_debug(1, "login_rsp ret (%d)", c->ret);
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
		} else {
			int i, rc;
			uint32_t one = 1, zero = 0;
			struct connparam {
				int param;
				uint32_t *value;
				int conn_only; } conntbl[ISCSI_PARAM_MAX] = {

				{
				.param = ISCSI_PARAM_MAX_RECV_DLENGTH,
				.value = &conn->max_recv_dlength,
				.conn_only = 1,
				}, {
				.param = ISCSI_PARAM_MAX_XMIT_DLENGTH,
				.value = &conn->max_xmit_dlength,
				.conn_only = 1,
				}, {
				.param = ISCSI_PARAM_HDRDGST_EN,
				.value = &conn->hdrdgst_en,
				.conn_only = 1,
				}, {
				.param = ISCSI_PARAM_DATADGST_EN,
				.value = &conn->datadgst_en,
				.conn_only = 1,
				}, {
				.param = ISCSI_PARAM_INITIAL_R2T_EN,
				.value = &session->initial_r2t_en,
				.conn_only = 0,
				}, {
				.param = ISCSI_PARAM_MAX_R2T,
				.value = &one, /* FIXME: session->max_r2t */
				.conn_only = 0,
				}, {
				.param = ISCSI_PARAM_IMM_DATA_EN,
				.value = &session->imm_data_en,
				.conn_only = 0,
				}, {
				.param = ISCSI_PARAM_FIRST_BURST,
				.value = &session->first_burst,
				.conn_only = 0,
				}, {
				.param = ISCSI_PARAM_MAX_BURST,
				.value = &session->max_burst,
				.conn_only = 0,
				}, {
				.param = ISCSI_PARAM_PDU_INORDER_EN,
				.value = &session->pdu_inorder_en,
				.conn_only = 0,
				}, {
				.param =ISCSI_PARAM_DATASEQ_INORDER_EN,
				.value = &session->dataseq_inorder_en,
				.conn_only = 0,
				}, {
				.param = ISCSI_PARAM_ERL,
				.value = &zero, /* FIXME: session->erl */
				.conn_only = 0,
				}, {
				.param = ISCSI_PARAM_IFMARKER_EN,
				.value = &zero,/* FIXME: session->ifmarker_en */
				.conn_only = 0,
				}, {
				.param = ISCSI_PARAM_OFMARKER_EN,
				.value = &zero,/* FIXME: session->ofmarker_en */
				.conn_only = 0,
				}

				/*
				 * FIXME: set these timeouts via set_param() API
				 *
				 * rec->session.timeo
				 * rec->session.timeo
				 * rec->session.err_timeo
				 */
			};

			/* almost! entered full-feature phase */

			if (__login_response_status(conn, c->ret) !=
						CONN_LOGIN_SUCCESS) {
				__session_mgmt_ipc_login_cleanup(c->qtask,
						MGMT_IPC_ERR_LOGIN_FAILURE, 1);
				return;
			}

			/* check the login status */
			if (__check_iscsi_status_class(session, conn->id,
				c->status_class, c->status_detail) !=
							CONN_LOGIN_SUCCESS) {
				__session_mgmt_ipc_login_cleanup(c->qtask,
						MGMT_IPC_ERR_LOGIN_FAILURE, 1);
				return;
			}

			/* Entered full-feature phase! */

			for (i = 0; i < ISCSI_PARAM_MAX; i++) {
				if (conn->id != 0 && !conntbl[i].conn_only)
					continue;
				if (ipc->set_param(
					session->transport_handle,
					conn->handle, conntbl[i].param,
					*conntbl[i].value, &rc) || rc) {
					log_error("can't set operational "
						"parameter %d for conn with "
						"id = %d, retcode %d (%d)",
						conntbl[i].param, conn->id,
						rc, errno);
					__session_mgmt_ipc_login_cleanup(
						c->qtask,
						MGMT_IPC_ERR_LOGIN_FAILURE, 1);
					return;
				}
				log_debug(3, "set operational parameter %d "
					"to %u", conntbl[i].param,
					*conntbl[i].value);
			}

			if (ipc->start_conn(session->transport_handle,
				conn->handle, &rc) || rc) {
				__session_mgmt_ipc_login_cleanup(c->qtask,
						MGMT_IPC_ERR_INTERNAL, 1);
				log_error("can't start connection 0x%p with "
					"id = %d, retcode %d (%d)",
					iscsi_ptr(conn->handle), conn->id, rc,
					errno);
				return;
			}

			conn->state = STATE_LOGGED_IN;
			if (session->r_stage == R_STAGE_NO_CHANGE) {
				/*
				 * scan host is one-time deal. We
				 * don't want to re-scan it on recovery.
				 */
				if (conn->id == 0)
					__session_scan_host(session);
				c->qtask->u.login.rsp.err = MGMT_IPC_OK;
				write(c->qtask->u.login.mgmt_ipc_fd,
					&c->qtask->u.login.rsp,
					sizeof(c->qtask->u.login.rsp));
				close(c->qtask->u.login.mgmt_ipc_fd);
				free(c->qtask);
				log_warning("connection%d:%d is operational "
					"now", session->id, conn->id);
			} else {
				log_warning("connection%d:%d is operational "
					"after recovery (%d attempts)",
					session->id, conn->id,
					session->nrec.session.reopen_max -
							session->reopen_cnt);

				/*
				 * reset ERL=0 reopen counter
				 */
				session->reopen_cnt =
					session->nrec.session.reopen_max;

				session->r_stage = R_STAGE_NO_CHANGE;
			}
		}
	} else if (conn->state == STATE_LOGGED_IN) {
		struct iscsi_hdr hdr;

		/* read incomming PDU */
		if (!iscsi_io_recv_pdu(conn, &hdr, ISCSI_DIGEST_NONE,conn->data,
			    DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH,
			    ISCSI_DIGEST_NONE, 0)) {
			return;
		}

		if (hdr.opcode == ISCSI_OP_NOOP_IN) {
			if (!__send_nopin_rsp(conn,
				     (struct iscsi_nopin*)&hdr, conn->data)) {
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

	item = provider[0].sessions.q_forw;
	while (item != &provider[0].sessions) {
		iscsi_session_t *session = (iscsi_session_t *)item;
		if (session->conn[0].state == STATE_LOGGED_IN &&
		    !strncmp(session->nrec.name, node_name, TARGET_NAME_MAXLEN))
			return 1;
		item = item->q_forw;
	}
	return 0;
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
		rc = iscsi_io_tcp_poll(conn);
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
					&session->handle, &session->id)) {
					log_error("can't create session (%d)",
						errno);
					err = MGMT_IPC_ERR_INTERNAL;
					goto cleanup;
				}
				log_debug(3, "created new iSCSI session, "
					"handle 0x%p",
					iscsi_ptr(session->handle));

				/* unique identifier for OUI */
				if (__session_node_established(
					       session->nrec.name)) {
					log_warning("picking unique OUI for "
					    "the same target node name %s",
					    session->nrec.name);
					session->isid[3] = session->id;
				}

				if (ipc->create_conn(session->transport_handle,
					session->handle, session->id, conn->id,
					&conn->handle)) {
					err = MGMT_IPC_ERR_INTERNAL;
					goto s_cleanup;
				}
				log_debug(3, "created new iSCSI connection, "
					"handle 0x%p", iscsi_ptr(conn->handle));
			}

			if (ipc->bind_conn(session->transport_handle,
				session->handle, conn->handle, conn->socket_fd,
				(conn->id == 0), &rc) || rc) {
				log_error("can't bind a conn with id = %d, "
					  "retcode %d (%d)", conn->id, rc,
					  errno);
				err = MGMT_IPC_ERR_INTERNAL;
				goto c_cleanup;
			}
			log_debug(3, "bound iSCSI connection (handle 0x%p) to "
				  "session (handle 0x%p)",
				  iscsi_ptr(conn->handle),
				  iscsi_ptr(session->handle));

			conn->kernel_io = 1;
			conn->send_pdu_begin = ipc->send_pdu_begin;
			conn->send_pdu_end = ipc->send_pdu_end;
			conn->recv_pdu_begin = ipc->recv_pdu_begin;
			conn->recv_pdu_end = ipc->recv_pdu_end;
			conn->send_pdu_timer_add = __send_pdu_timer_add;
			conn->send_pdu_timer_remove = __send_pdu_timer_remove;

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

	actor_schedule(&session->mainloop);
	return;

c_cleanup:
	if (ipc->destroy_conn(session->transport_handle, conn->handle,
                conn->id)) {
		log_error("can not safely destroy connection %d", conn->id);
	}
s_cleanup:
	if (ipc->destroy_session(session->transport_handle, session->handle,
                        session->id)) {
		log_error("can not safely destroy session %d", session->id);
	}
cleanup:
	__session_mgmt_ipc_login_cleanup(qtask, err, 0);
}

static void
__connect_timedout(void *data)
{
	queue_task_t *qtask = data;
	iscsi_conn_t *conn = qtask->conn;
	iscsi_session_t *session = conn->session;

	if (conn->state == STATE_XPT_WAIT) {
		queue_produce(session->queue, EV_CONN_TIMER, qtask, 0, NULL);
		actor_schedule(&session->mainloop);
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
__session_conn_reopen(iscsi_conn_t *conn, int do_stop)
{
	int rc;
	iscsi_session_t *session = conn->session;

	log_debug(1, "re-opening session %d (reopen_cnt %d)", session->id,
			session->reopen_cnt);

	session->reopen_qtask.conn = conn;

	if (do_stop) {
		/* state: STATE_CLEANUP_WAIT */
		if (ipc->stop_conn(session->transport_handle, conn->handle,
				      STOP_CONN_RECOVER)) {
			log_error("can't stop connection 0x%p with "
				  "id = %d (%d)", iscsi_ptr(conn->handle),
				  conn->id, errno);
			return -1;
		}
		log_debug(3, "connection 0x%p is stopped for recovery",
			iscsi_ptr(conn->handle));
		iscsi_io_disconnect(conn);
		__session_conn_queue_flush(conn);
	}

	rc = iscsi_io_tcp_connect(conn, 1);
	if (rc < 0 && errno != EINPROGRESS) {
		log_error("cannot make a connection to %s:%d (%d)",
			 inet_ntoa(conn->addr.sin_addr), conn->port, errno);
		return MGMT_IPC_ERR_TCP_FAILURE;
	}

	conn->send_pdu_in_progress = 0;
	conn->state = STATE_XPT_WAIT;
	queue_produce(session->queue, EV_CONN_POLL,
		      &session->reopen_qtask, 0, NULL);
	actor_schedule(&session->mainloop);
	actor_timer(&conn->connect_timer, conn->login_timeout*1000,
		    __connect_timedout, &session->reopen_qtask);

	return MGMT_IPC_OK;
}

static void
__session_conn_timer(queue_item_t *item)
{
	queue_task_t *qtask = item->context;
	iscsi_conn_t *conn = qtask->conn;
	iscsi_session_t *session = conn->session;

	if (conn->state == STATE_XPT_WAIT) {
		if (session->r_stage == R_STAGE_NO_CHANGE) {
			log_debug(6, "conn_timer popped at XPT_WAIT: login");
			/* timeout during initial connect.
			 * clean connection. write ipc rsp */
			__session_mgmt_ipc_login_cleanup(qtask,
					    MGMT_IPC_ERR_TCP_TIMEOUT, 0);
		} else if (session->r_stage == R_STAGE_SESSION_REOPEN) {
			log_debug(6, "conn_timer popped at XPT_WAIT: reopen");
			/* timeout during reopen connect.
			 * try again or cleanup connection. */
			if (--session->reopen_cnt > 0) {
				if (__session_conn_reopen(conn, 0))
					__session_conn_cleanup(conn);
			} else {
				__session_conn_cleanup(conn);
			}
		}
	} else if (conn->state == STATE_IN_LOGIN) {
		iscsi_io_disconnect(conn);
		if (session->r_stage == R_STAGE_NO_CHANGE) {
			log_debug(6, "conn_timer popped at IN_LOGIN");
			/* send pdu timeout. clean connection. write rsp */
			if (ipc->destroy_conn(session->transport_handle,
				conn->handle, conn->id)) {
				log_error("can not safely destroy "
					  "connection %d", conn->id);
			}
			if (ipc->destroy_session(session->transport_handle,
					session->handle, session->id)) {
				log_error("can not safely destroy session %d",
					  session->id);
			}
			__session_mgmt_ipc_login_cleanup(qtask,
					    MGMT_IPC_ERR_PDU_TIMEOUT, 0);
		} else if (session->r_stage == R_STAGE_SESSION_REOPEN) {
			if (--session->reopen_cnt > 0) {
				if (__session_conn_reopen(conn, 1))
					__session_conn_cleanup(conn);
			} else
				__session_conn_cleanup(conn);
		}
	}
}

static void
__session_conn_error(queue_item_t *item)
{
	enum iscsi_err error = *(enum iscsi_err *)queue_item_data(item);
	iscsi_conn_t *conn = item->context;
	iscsi_session_t *session = conn->session;

	log_warning("detected iSCSI connection (handle %p) error (%d) "
		"state (%d)", iscsi_ptr(conn->handle), error, conn->state);

	if (conn->state == STATE_LOGGED_IN) {
		int i;

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
		} else {
			/* mark all connections as failed */
			for (i=0; i<ISCSI_CONN_MAX; i++) {
				if (session->conn[i].state == STATE_LOGGED_IN) {
					session->conn[i].state =
						STATE_CLEANUP_WAIT;
				}
			}
			if (--session->reopen_cnt > 0)
				session->r_stage = R_STAGE_SESSION_REOPEN;
			else
				session->r_stage = R_STAGE_SESSION_CLEANUP;
		}
	} else if (conn->state == STATE_IN_LOGIN) {
		if (session->r_stage == R_STAGE_SESSION_REOPEN) {
			conn->send_pdu_timer_remove(conn);
			if (--session->reopen_cnt > 0) {
				if (__session_conn_reopen(conn, 1))
					__session_conn_cleanup(conn);
			} else
				__session_conn_cleanup(conn);
			return;
		} else {
			log_debug(1, "ignoring conn error in login. "
				"let it timeout");
			return;
		}
	} else if (conn->state == STATE_XPT_WAIT) {
		log_debug(1, "ignoring conn error in XPT_WAIT. "
			  "let connection fail on its own");
		return;
	} else if (conn->state == STATE_CLEANUP_WAIT) {
		log_debug(1, "ignoring conn error in CLEANUP_WAIT. "
			  "let connection stop");
		return;
	}

	if (session->r_stage == R_STAGE_SESSION_REOPEN) {
		if (__session_conn_reopen(conn, 1))
			__session_conn_cleanup(conn);
		return;
	} else {
		if (ipc->stop_conn(session->transport_handle, conn->handle,
				      STOP_CONN_TERM)) {
			log_error("can't stop connection 0x%p with "
				  "id = %d (%d)", iscsi_ptr(conn->handle),
				  conn->id, errno);
			return;
		}
		log_debug(3, "connection 0x%p is stopped for termination",
			iscsi_ptr(conn->handle));
		iscsi_io_disconnect(conn);
		__session_conn_queue_flush(conn);
	}

	__session_conn_cleanup(conn);
}

static void
__session_mainloop(void *data)
{
	iscsi_session_t *session = data;
	unsigned char item_buf[sizeof(queue_item_t) + EVENT_PAYLOAD_MAX];
	queue_item_t *item = (queue_item_t *)(void *)item_buf;

	if (queue_consume(session->queue, EVENT_PAYLOAD_MAX,
				item) != QUEUE_IS_EMPTY) {
		switch (item->event_type) {
		case EV_CONN_RECV_PDU: __session_conn_recv_pdu(item); break;
		case EV_CONN_POLL: __session_conn_poll(item); break;
		case EV_CONN_TIMER: __session_conn_timer(item); break;
		case EV_CONN_ERROR: __session_conn_error(item); break;
		default:
			break;
		}
	}
}

iscsi_session_t*
session_find_by_rec(node_rec_t *rec)
{
	iscsi_session_t *session;
	struct qelem *item;

	item = provider[0].sessions.q_forw;
	while (item != &provider[0].sessions) {
		session = (iscsi_session_t *)item;
		log_debug(6, "looking for session with rec_id [%06x]...",
			  session->nrec.id);
		if (rec->id == session->nrec.id) {
			return session;
		}
		item = item->q_forw;
	}

	return NULL;
}

static uint64_t
__get_transport_by_name(char *transport_name)
{
	struct iscsi_uevent ev;
	int i;

	if (ipc->trans_list(&ev)) {
		log_error("can't retreive transport list (%d)", errno);
		return 0;
	}

	for (i = 0; i < ISCSI_TRANSPORT_MAX; i++) {
		if (ev.r.t_list.elements[i].trans_handle) {
			strncmp(ev.r.t_list.elements[i].name, transport_name,
				ISCSI_TRANSPORT_NAME_MAXLEN);
			return ev.r.t_list.elements[i].trans_handle;
		}
	}
	return 0;
}

int
session_login_task(node_rec_t *rec, queue_task_t *qtask)
{
	int rc;
	iscsi_session_t *session;
	iscsi_conn_t *conn;
	uint64_t transport_handle;

	if (!rec->active_conn)
		return MGMT_IPC_ERR_INVAL;

	transport_handle = __get_transport_by_name(rec->transport_name);
	if (!transport_handle)
		return MGMT_IPC_ERR_TRANS_NOT_FOUND;

	session = __session_create(rec, transport_handle);
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

	rc = iscsi_io_tcp_connect(conn, 1);
	if (rc < 0 && errno != EINPROGRESS) {
		log_error("cannot make a connection to %s:%d (%d)",
			 inet_ntoa(conn->addr.sin_addr), conn->port, errno);
		session_conn_destroy(session, 0);
		__session_destroy(session);
		return MGMT_IPC_ERR_TCP_FAILURE;
	}

	conn->state = STATE_XPT_WAIT;
	queue_produce(session->queue, EV_CONN_POLL, qtask, 0, NULL);
	actor_schedule(&session->mainloop);
	actor_timer(&conn->connect_timer, conn->login_timeout*1000,
		    __connect_timedout, qtask);

	return MGMT_IPC_OK;
}

int
session_logout_task(iscsi_session_t *session, queue_task_t *qtask)
{
	iscsi_conn_t *conn;

	/* FIXME: logout all active connections */
	conn = &session->conn[0];
	if (conn->state != STATE_LOGGED_IN &&
	    conn->state != STATE_CLEANUP_WAIT) {
		return MGMT_IPC_ERR_INTERNAL;
	}

	/* FIXME: implement Logout Request */

	__session_delete_luns(session);

	/* stop if connection is logged in */
	if (conn->state == STATE_LOGGED_IN) {
		if (ipc->stop_conn(session->transport_handle, conn->handle,
				      STOP_CONN_TERM)) {
			log_error("can't stop connection 0x%p with "
				  "id = %d (%d)", iscsi_ptr(conn->handle),
				  conn->id, errno);
			return MGMT_IPC_ERR_INTERNAL;
		}
		log_debug(3, "connection 0x%p is stopped for termination",
			iscsi_ptr(conn->handle));
	}

	iscsi_io_disconnect(conn);
	__session_conn_queue_flush(conn);

	if (ipc->destroy_conn(session->transport_handle, conn->handle,
                conn->id)) {
		return MGMT_IPC_ERR_INTERNAL;
	}
	session_conn_destroy(session, conn->id);

	if (ipc->destroy_session(session->transport_handle, session->handle,
                        session->id)) {
		return MGMT_IPC_ERR_INTERNAL;
	}
	__session_destroy(session);

	qtask->u.login.rsp.err = MGMT_IPC_OK;
	write(qtask->u.login.mgmt_ipc_fd, &qtask->u.login.rsp,
		sizeof(qtask->u.login.rsp));
	close(qtask->u.login.mgmt_ipc_fd);
	free(qtask);

	return MGMT_IPC_OK;
}
