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

#include <unistd.h>
#include <search.h>
#include <string.h>
#include <stdlib.h>
#include <netdb.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/param.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "initiator.h"
#include "iscsid.h"
#include "iscsi_if.h"
#include "iscsi_ifev.h"
#include "ipc.h"
#include "idbm.h"
#include "log.h"

static void __session_mainloop(void *data);

static cnx_login_status_e
__login_response_status(iscsi_conn_t *conn,
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
__check_iscsi_status_class(iscsi_session_t *session, int cid,
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
	} else {
		session->num_auth_buffers = 0;
	}
}

static int
__session_cnx_create(iscsi_session_t *session, int cid)
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

	conn->state = STATE_FREE;
	conn->session = session;

	return 0;
}

void
session_cnx_destroy(iscsi_session_t *session, int cid)
{
	iscsi_conn_t *conn = &session->cnx[cid];
	free(conn->rx_buffer);
}

static iscsi_session_t*
__session_create(node_rec_t *rec)
{
	iscsi_session_t *session;

	session = calloc(1, sizeof (*session));
	if (session == NULL) {
		log_debug(1, "can not allocate memory for session");
		return NULL;
	}

	/* opened at daemon load time (iscsid.c) */
	session->ctrl_fd = control_fd;

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
	session->erl = rec->session.iscsi.ERL;
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
		__session_destroy(session);
}

static int
__send_nopin_rsp(iscsi_conn_t *conn, iscsi_nopin_t *rhdr, char *data)
{
	iscsi_nopout_t hdr;

	memset(&hdr, 0, sizeof(iscsi_nopout_t));
	hdr.opcode = ISCSI_OP_NOOP_OUT | ISCSI_OP_IMMEDIATE;
	hdr.flags = ISCSI_FLAG_CMD_FINAL;
	hdr.dlength[0] = rhdr->dlength[0];
	hdr.dlength[1] = rhdr->dlength[1];
	hdr.dlength[2] = rhdr->dlength[2];
	memcpy(hdr.lun, rhdr->lun, 8);
	hdr.ttt = rhdr->ttt;
	hdr.itt = ISCSI_RESERVED_TAG;

	return iscsi_send_pdu(conn, (iscsi_hdr_t*)&hdr,
	       ISCSI_DIGEST_NONE, data, ISCSI_DIGEST_NONE, 0);
}

static void
__send_pdu_timedout(void *data)
{
	queue_task_t *qtask = data;
	iscsi_conn_t *conn = qtask->conn;
	iscsi_session_t *session = conn->session;

	if (conn->send_pdu_in_progress) {
		queue_produce(session->queue, EV_CNX_TIMER, qtask, 0, 0);
		actor_schedule(&session->mainloop);
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
	}
}

static void
__send_pdu_timer_remove(struct iscsi_conn *conn)
{
	if (conn->send_pdu_in_progress) {
		actor_delete(&conn->send_pdu_timer);
		conn->send_pdu_in_progress = 0;
	}
}

static void
__session_cnx_recv_pdu(queue_item_t *item)
{
	iscsi_conn_t *conn = item->context;
	iscsi_session_t *session = conn->session;

	conn->recv_handle = *(ulong_t*)queue_item_data(item);

	if (conn->state == STATE_IN_LOGIN) {
		iscsi_login_context_t *c = &conn->login_context;

		if (iscsi_login_rsp(session, c)) {
			__session_ipc_login_cleanup(c->qtask,
					IPC_ERR_LOGIN_FAILURE);
			return;
		}

		if (conn->current_stage != ISCSI_FULL_FEATURE_PHASE) {
			/* more nego. needed! */
			conn->state = STATE_IN_LOGIN;
			if (iscsi_login_req(session, c)) {
				__session_ipc_login_cleanup(c->qtask,
						IPC_ERR_LOGIN_FAILURE);
				return;
			}
		} else {
			/* almost! entered full-feature phase */

			if (__login_response_status(conn, c->ret) !=
						CNX_LOGIN_SUCCESS) {
				__session_ipc_login_cleanup(c->qtask,
						IPC_ERR_LOGIN_FAILURE);
				return;
			}

			/* check the login status */
			if (__check_iscsi_status_class(session, conn->id,
				c->status_class, c->status_detail) !=
							CNX_LOGIN_SUCCESS) {
				__session_ipc_login_cleanup(c->qtask,
						IPC_ERR_LOGIN_FAILURE);
				return;
			}

			/* Entered full-feature phase! */

			if (ksession_set_param(session->ctrl_fd, conn,
				ISCSI_PARAM_MAX_RECV_DLENGTH,
				conn->max_recv_dlength)) {
				__session_ipc_login_cleanup(c->qtask,
						IPC_ERR_LOGIN_FAILURE);
				return;
			}
			if (ksession_set_param(session->ctrl_fd, conn,
				ISCSI_PARAM_MAX_XMIT_DLENGTH,
				conn->max_xmit_dlength)) {
				__session_ipc_login_cleanup(c->qtask,
						IPC_ERR_LOGIN_FAILURE);
				return;
			}
			if (ksession_set_param(session->ctrl_fd, conn,
				ISCSI_PARAM_HDRDGST_EN, conn->hdrdgst_en)) {
				__session_ipc_login_cleanup(c->qtask,
						IPC_ERR_LOGIN_FAILURE);
				return;
			}
			if (ksession_set_param(session->ctrl_fd, conn,
				ISCSI_PARAM_DATADGST_EN, conn->datadgst_en)) {
				__session_ipc_login_cleanup(c->qtask,
						IPC_ERR_LOGIN_FAILURE);
				return;
			}
			if (conn->id == 0) {
				/* setup session's op. parameters just once */
				if (ksession_set_param(session->ctrl_fd, conn,
					ISCSI_PARAM_INITIAL_R2T_EN,
					session->initial_r2t_en)) {
					__session_ipc_login_cleanup(c->qtask,
							IPC_ERR_LOGIN_FAILURE);
					return;
				}
				if (ksession_set_param(session->ctrl_fd, conn,
					ISCSI_PARAM_MAX_R2T,
					1 /* FIXME: session->max_r2t */)) {
					__session_ipc_login_cleanup(c->qtask,
							IPC_ERR_LOGIN_FAILURE);
					return;
				}
				if (ksession_set_param(session->ctrl_fd, conn,
					ISCSI_PARAM_IMM_DATA_EN,
					session->imm_data_en)) {
					__session_ipc_login_cleanup(c->qtask,
							IPC_ERR_LOGIN_FAILURE);
					return;
				}
				if (ksession_set_param(session->ctrl_fd, conn,
					ISCSI_PARAM_FIRST_BURST,
					session->first_burst)) {
					__session_ipc_login_cleanup(c->qtask,
							IPC_ERR_LOGIN_FAILURE);
					return;
				}
				if (ksession_set_param(session->ctrl_fd, conn,
					ISCSI_PARAM_MAX_BURST,
					session->max_burst)) {
					__session_ipc_login_cleanup(c->qtask,
							IPC_ERR_LOGIN_FAILURE);
					return;
				}
				if (ksession_set_param(session->ctrl_fd, conn,
					ISCSI_PARAM_PDU_INORDER_EN,
					session->pdu_inorder_en)) {
					__session_ipc_login_cleanup(c->qtask,
							IPC_ERR_LOGIN_FAILURE);
					return;
				}
				if (ksession_set_param(session->ctrl_fd, conn,
					ISCSI_PARAM_DATASEQ_INORDER_EN,
					session->dataseq_inorder_en)) {
				}
				if (ksession_set_param(session->ctrl_fd, conn,
					ISCSI_PARAM_ERL,
					0 /* FIXME: session->erl */)) {
					__session_ipc_login_cleanup(c->qtask,
							IPC_ERR_LOGIN_FAILURE);
					return;
				}
				if (ksession_set_param(session->ctrl_fd, conn,
					ISCSI_PARAM_IFMARKER_EN,
					0 /* FIXME: session->ifmarker_en */)) {
					__session_ipc_login_cleanup(c->qtask,
							IPC_ERR_LOGIN_FAILURE);
					return;
				}
				if (ksession_set_param(session->ctrl_fd, conn,
					ISCSI_PARAM_OFMARKER_EN,
					0 /* FIXME: session->ofmarker_en */)) {
					__session_ipc_login_cleanup(c->qtask,
							IPC_ERR_LOGIN_FAILURE);
					return;
				}

				/*
				 * FIXME: set these timeouts via set_param() API
				 *
				 * rec->session.timeo
				 * rec->session.timeo
				 * rec->session.err_timeo
				 */
			}

			if (ksession_start_cnx(session->ctrl_fd, conn)) {
				__session_ipc_login_cleanup(c->qtask,
						IPC_ERR_INTERNAL);
				return;
			}

			conn->state = STATE_LOGGED_IN;
			c->qtask->u.login.rsp.err = IPC_OK;
			write(c->qtask->u.login.ipc_fd, &c->qtask->u.login.rsp,
				sizeof(c->qtask->u.login.rsp));
			close(c->qtask->u.login.ipc_fd);
			free(c->qtask);
		}
	} else if (conn->state == STATE_LOGGED_IN) {
		iscsi_hdr_t hdr;
		char *data;

		/* FIXME: better to read PDU Header first, than allocate needed
		 *        space for PDU Data, than read data. */

		data = calloc(1, conn->max_recv_dlength);
		if (data == NULL) {
			log_error("can not allocate memory for incomming PDU");
			return;
		}

		/* read incomming PDU */
		if (!iscsi_recv_pdu(conn, &hdr, ISCSI_DIGEST_NONE, data,
			    conn->max_recv_dlength, ISCSI_DIGEST_NONE, 0)) {
			free(data);
			return;
		}

		if (hdr.opcode == ISCSI_OP_NOOP_IN) {
			if (__send_nopin_rsp(conn,
				     (iscsi_nopin_t*)&hdr, data)) {
				free(data);
			}
		} else {
			log_error("unsupported opcode 0x%x", hdr.opcode);
			free(data);
		}
	}
}

static void
__session_cnx_poll(queue_item_t *item)
{
	ipc_err_e err = IPC_OK;
	queue_task_t *qtask = item->context;
	iscsi_conn_t *conn = qtask->conn;
	iscsi_login_context_t *c = &conn->login_context;
	iscsi_session_t *session = conn->session;
	int rc;

	if (conn->state == STATE_XPT_WAIT) {
		rc = iscsi_tcp_poll(conn);
		if (rc == 0) {
			/* timedout: poll again */
			queue_produce(session->queue, EV_CNX_POLL, qtask, 0, 0);
			actor_schedule(&session->mainloop);
		} else if (rc > 0) {

			/* connected! */

			memset(c, 0, sizeof(iscsi_login_context_t));

			actor_delete(&conn->connect_timer);

			if (conn->id == 0 && ksession_create(session->ctrl_fd,
							session)) {
				err = IPC_ERR_INTERNAL;
				goto cleanup;
			}

			if (ksession_cnx_create(session->ctrl_fd, session,
							conn)) {
				err = IPC_ERR_INTERNAL;
				goto s_cleanup;
			}

			if (ksession_cnx_bind(session->ctrl_fd, session,
							conn)) {
				err = IPC_ERR_INTERNAL;
				goto c_cleanup;
			}

			conn->kernel_io = 1;
			conn->send_pdu_begin = ksession_send_pdu_begin;
			conn->send_pdu_end = ksession_send_pdu_end;
			conn->recv_pdu_begin = ksession_recv_pdu_begin;
			conn->recv_pdu_end = ksession_recv_pdu_end;
			conn->send_pdu_timer_add = __send_pdu_timer_add;
			conn->send_pdu_timer_remove = __send_pdu_timer_remove;

			c->qtask = qtask;
			c->cid = conn->id;
			c->buffer = calloc(1,
					DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH);
			if (!c->buffer) {
				log_error("failed to aallocate recv "
					  "data buffer");
				err = IPC_ERR_NOMEM;
				goto c_cleanup;
			}
			c->bufsize = DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH;

			if (iscsi_login_begin(session, c)) {
				err = IPC_ERR_LOGIN_FAILURE;
				goto mem_cleanup;
			}

			conn->state = STATE_IN_LOGIN;
			if (iscsi_login_req(session, c)) {
				err = IPC_ERR_LOGIN_FAILURE;
				goto mem_cleanup;
			}
		} else {
			actor_delete(&conn->connect_timer);
			/* error during connect */
			err = IPC_ERR_TCP_FAILURE;
			goto cleanup;
		}
	}

	return;

mem_cleanup:
	free(c->buffer);
	c->buffer = NULL;
c_cleanup:
	if (ksession_cnx_destroy(session->ctrl_fd, conn)) {
		log_error("can not safely destroy connection %d", conn->id);
	}
s_cleanup:
	if (ksession_destroy(session->ctrl_fd, session)) {
		log_error("can not safely destroy session %d", session->id);
	}
cleanup:
	__session_ipc_login_cleanup(qtask, err);
}

static void
__session_cnx_timer(queue_item_t *item)
{
	queue_task_t *qtask = item->context;
	iscsi_conn_t *conn = qtask->conn;
	iscsi_session_t *session = conn->session;

	if (conn->state == STATE_XPT_WAIT) {
		/* timeout during connect. clean connection. write rsp */
		__session_ipc_login_cleanup(qtask, IPC_ERR_TCP_TIMEOUT);
	} else if (conn->state == STATE_IN_LOGIN) {
		/* send pdu timeout. clean connection. write rsp */
		if (ksession_cnx_destroy(session->ctrl_fd, conn)) {
			log_error("can not safely destroy connection %d",
				  conn->id);
		}
		if (ksession_destroy(session->ctrl_fd, session)) {
			log_error("can not safely destroy session %d",
				  session->id);
		}
		__session_ipc_login_cleanup(qtask, IPC_ERR_PDU_TIMEOUT);
	}
}

#define R_STAGE_NO_CHANGE	0
#define R_STAGE_SESSION_CLEANUP	1
#define R_STAGE_SESSION_REOPEN	2

static void
__session_cnx_error(queue_item_t *item)
{
	iscsi_err_e error = *(iscsi_err_e *)queue_item_data(item);
	iscsi_conn_t *conn = item->context;
	iscsi_session_t *session = conn->session;
	int r_stage = R_STAGE_NO_CHANGE;

	log_warning("detected iSCSI connection (handle %p) error %d",
			(void*)conn->handle, error);

	if (conn->state == STATE_LOGGED_IN) {
		int i;

		/* mark failed connection */
		conn->state = STATE_CLEANUP_WAIT;

		if (session->erl > 0) {
			/* check if we still have some logged in connections */
			for (i=0; i<ISCSI_CNX_MAX; i++) {
				if (session->cnx[i].state == STATE_LOGGED_IN) {
					break;
				}
			}
			if (i != ISCSI_CNX_MAX) {
				/* FIXME: re-assign leading connection
				 *        for ERL>0 */
			}
		} else {
			/* mark all connections as failed */
			for (i=0; i<ISCSI_CNX_MAX; i++) {
				if (session->cnx[i].state == STATE_LOGGED_IN) {
					session->cnx[i].state =
						STATE_CLEANUP_WAIT;
				}
			}
			r_stage = R_STAGE_SESSION_CLEANUP;
		}
	}

	if (r_stage == R_STAGE_SESSION_REOPEN) {
		log_debug(1, "re-opening session %d", session->id);
		/* FIXME: implement session re-open logic */
		return;
	}

	if (ksession_stop_cnx(session->ctrl_fd, conn)) {
		log_error("can not safely stop connection %d", conn->id);
		return;
	}

	iscsi_disconnect(conn);

	if (ksession_cnx_destroy(session->ctrl_fd, conn)) {
		log_error("can not safely destroy connection %d", conn->id);
		return;
	}
	session_cnx_destroy(session, conn->id);

	if (ksession_destroy(session->ctrl_fd, session)) {
		log_error("can not safely destroy session %d", session->id);
		return;
	}
	__session_destroy(session);
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
		case EV_CNX_RECV_PDU: __session_cnx_recv_pdu(item); break;
		case EV_CNX_POLL: __session_cnx_poll(item); break;
		case EV_CNX_TIMER: __session_cnx_timer(item); break;
		case EV_CNX_ERROR: __session_cnx_error(item); break;
		default:
			break;
		}
	}
}

static void
__connect_timedout(void *data)
{
	queue_task_t *qtask = data;
	iscsi_conn_t *conn = qtask->conn;
	iscsi_session_t *session = conn->session;

	if (conn->state == STATE_XPT_WAIT) {
		queue_produce(session->queue, EV_CNX_TIMER, qtask, 0, 0);
		actor_schedule(&session->mainloop);
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

int
session_login_task(node_rec_t *rec, queue_task_t *qtask)
{
	int rc;
	iscsi_session_t *session;
	iscsi_conn_t *conn;

	if (!rec->active_cnx)
		return IPC_ERR_INVAL;

	session = __session_create(rec);
	if (session == NULL) {
		return IPC_ERR_LOGIN_FAILURE;
	}

	/* FIXME: login all connections! marked as "automatic" */

	/* create leading connection */
	if (__session_cnx_create(session, 0)) {
		__session_destroy(session);
		return IPC_ERR_LOGIN_FAILURE;
	}
	conn = &session->cnx[0];
	qtask->conn = conn;

	rc = iscsi_tcp_connect(conn, 1);
	if (rc < 0 && errno != EINPROGRESS) {
		log_error("cannot make a connection to %s:%d (%d)",
			 inet_ntoa(conn->addr.sin_addr), conn->port, errno);
		session_cnx_destroy(session, 0);
		__session_destroy(session);
		return IPC_ERR_TCP_FAILURE;
	}

	conn->state = STATE_XPT_WAIT;
	queue_produce(session->queue, EV_CNX_POLL, qtask, 0, 0);
	actor_schedule(&session->mainloop);
	actor_timer(&conn->connect_timer, conn->login_timeout*1000,
		    __connect_timedout, qtask);

	return IPC_OK;
}

int
session_logout_task(iscsi_session_t *session, queue_task_t *qtask)
{
	iscsi_conn_t *conn;

	/* FIXME: logout all active connections */
	conn = &session->cnx[0];
	if (conn->state != STATE_LOGGED_IN &&
	    conn->state != STATE_CLEANUP_WAIT) {
		return IPC_ERR_INTERNAL;
	}

	/* FIXME: implement Logout Request */

	/* stop if connection is logged in */
	if (conn->state == STATE_LOGGED_IN &&
	    ksession_stop_cnx(session->ctrl_fd, conn)) {
		return IPC_ERR_INTERNAL;
	}

	iscsi_disconnect(conn);

	if (ksession_cnx_destroy(session->ctrl_fd, conn)) {
		return IPC_ERR_INTERNAL;
	}
	session_cnx_destroy(session, conn->id);

	if (ksession_destroy(session->ctrl_fd, session)) {
		return IPC_ERR_INTERNAL;
	}
	__session_destroy(session);

	qtask->u.login.rsp.err = IPC_OK;
	write(qtask->u.login.ipc_fd, &qtask->u.login.rsp,
		sizeof(qtask->u.login.rsp));
	close(qtask->u.login.ipc_fd);
	free(qtask);

	return IPC_OK;
}
