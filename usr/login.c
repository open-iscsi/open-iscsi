/*
 * iSCSI Login Library
 *
 * Copyright (C) 2004 Dmitry Yusupov, Alex Aizman
 * maintained by open-iscsi@googlegroups.com
 *
 * heavily based on code from iscsi-login.c:
 * Copyright (C) 2001 Cisco Systems, Inc.
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
 *
 * Formation of iSCSI login pdu, processing the login response and other
 * functions are defined here
 */

#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <poll.h>
#include <errno.h>
#include <sys/param.h>

#include "initiator.h"
#include "transport.h"
#include "log.h"
#include "iscsi_timer.h"

/* caller is assumed to be well-behaved and passing NUL terminated strings */
int
iscsi_add_text(struct iscsi_hdr *pdu, char *data, int max_data_length,
		char *param, char *value)
{
	int param_len = strlen(param);
	int value_len = strlen(value);
	int length = param_len + 1 + value_len + 1;	/* param, separator,
							 * value, and trailing
							 * NULL
							 */
	int pdu_length = ntoh24(pdu->dlength);
	char *text = data;
	char *end = data + max_data_length;
	char *pdu_text;

	/* find the end of the current text */
	text += pdu_length;
	pdu_text = text;
	pdu_length += length;

	if (text + length >= end) {
		log_warning("Failed to add login text "
			    "'%s=%s'\n", param, value);
		return 0;
	}

	/* param */
	strncpy(text, param, param_len);
	text += param_len;

	/* separator */
	*text++ = ISCSI_TEXT_SEPARATOR;

	/* value */
	strncpy(text, value, value_len);
	text += value_len;

	/* NUL */
	*text++ = '\0';

	/* update the length in the PDU header */
	hton24(pdu->dlength, pdu_length);

	return 1;
}

static int
iscsi_find_key_value(char *param, char *pdu, char *pdu_end, char **value_start,
		     char **value_end)
{
	char *str = param;
	char *text = pdu;
	char *value;

	if (value_start)
		*value_start = NULL;
	if (value_end)
		*value_end = NULL;

	/* make sure they contain the same bytes */
	while (*str) {
		if (text >= pdu_end)
			return 0;
		if (*text == '\0')
			return 0;
		if (*str != *text)
			return 0;
		str++;
		text++;
	}

	if ((text >= pdu_end) || (*text == '\0')
	    || (*text != ISCSI_TEXT_SEPARATOR)) {
		return 0;
	}

	/* find the value */
	value = text + 1;

	/* find the end of the value */
	while ((text < pdu_end) && (*text))
		text++;

	if (value_start)
		*value_start = value;
	if (value_end)
		*value_end = text;

	return 1;
}

static enum iscsi_login_status
get_auth_key_type(struct iscsi_acl *auth_client, char **data, char *end)
{
	char *key;
	char *value = NULL;
        char *value_end = NULL;
	char *text = *data;

	int keytype = AUTH_KEY_TYPE_NONE;

	while (acl_get_next_key_type(&keytype) == AUTH_STATUS_NO_ERROR) {
		key = (char *)acl_get_key_name(keytype);
		if (key && iscsi_find_key_value(key, text, end, &value,
						&value_end)) {
			if (acl_recv_key_value(auth_client, keytype, value) !=
					       AUTH_STATUS_NO_ERROR) {
				log_error("login negotiation failed, can't "
					  "accept %s in security stage", text);
				return LOGIN_NEGOTIATION_FAILED;
			}
			text = value_end;
			*data = text;
			return LOGIN_OK;
		}
	}
	log_error("Login negotiation failed, can't accept %s in security "
		  "stage", text);
	return LOGIN_NEGOTIATION_FAILED;
}

int
resolve_address(char *host, char *port, struct sockaddr_storage *ss)
{
	struct addrinfo hints, *res;
	int rc;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rc = getaddrinfo(host, port, &hints, &res))) {
		log_error("Cannot resolve host %s. getaddrinfo error: "
			  "[%s]\n", host, gai_strerror(rc));
		return rc;
	}

	memcpy(ss, res->ai_addr, res->ai_addrlen);

	freeaddrinfo(res);

	return rc;
}

/*
 * try to reset the session's IP address and port, based on the TargetAddress
 * provided
 */
int
iscsi_update_address(iscsi_conn_t *conn, char *address)
{
	char *port, *tag;
	char default_port[NI_MAXSERV];
	iscsi_session_t *session = conn->session;
	struct sockaddr_storage addr;

	if ((tag = strrchr(address, ','))) {
		*tag = '\0';
		tag++;
	}
	if ((port = strrchr(address, ':'))) {
		*port = '\0';
		port++;
	}

	if (!port) {
		sprintf(default_port, "%d", ISCSI_LISTEN_PORT);
		port = default_port;
	}

	if (*address == '[') {
		char *end_bracket;

		if (!(end_bracket = strchr(address, ']'))) {
			log_error("Invalid IPv6 address with opening bracket, "
				  "but no closing bracket.");
			return 0;
		}
		*end_bracket = '\0';
		address++;
        }

	if (resolve_address(address, port, &addr)) {
		log_error("cannot resolve host name %s", address);
		return 0;
	}

	conn->saddr = addr;
	if (tag)
		session->portal_group_tag = atoi(tag);
	return 1;
}

static enum iscsi_login_status
get_security_text_keys(iscsi_session_t *session, int cid, char **data,
		       struct iscsi_acl *auth_client, char *end)
{
	char *text = *data;
	char *value = NULL;
	char *value_end = NULL;
	size_t size;
	int tag;
	enum iscsi_login_status ret;

	/*
	 * a few keys are possible in Security stage
	 * which the auth code doesn't care about, but
	 * which we might want to see, or at least not
	 * choke on.
	 */
	if (iscsi_find_key_value("TargetAlias", text, end, &value,
		&value_end)) {
		size = value_end - value;
		session->target_alias = malloc(size + 1);
		if (!session->target_alias) {
			/* Alias not critical. So just print an error */
			log_error("Login failed to allocate alias");
			*data = value_end;
			return LOGIN_OK;
		}
		memcpy(session->target_alias, value, size);
		session->target_alias[size] = '\0';
		text = value_end;
	} else if (iscsi_find_key_value("TargetAddress", text, end, &value,
					 &value_end)) {
		/*
		 * if possible, change the session's
		 * ip_address and port to the new TargetAddress for
		 * leading connection
		 */
		if (iscsi_update_address(&session->conn[cid], value)) {
			text = value_end;
		} else {
			log_error("Login redirection failed, "
				  "can't handle redirection to %s", value);
			return LOGIN_REDIRECTION_FAILED;
		}
	} else if (iscsi_find_key_value("TargetPortalGroupTag", text, end,
					 &value, &value_end)) {
		/*
		 * We should have already obtained this
		 * via discovery, but the value could be stale.
		 * If the target was reconfigured it will send us
		 * the updated tpgt.
		 */
		tag = strtoul(value, NULL, 0);
		if (session->portal_group_tag >= 0) {
			if (tag != session->portal_group_tag)
				log_debug(2, "Portal group tag "
					  "mismatch, expected %u, "
					  "received %u. Updating",
					  session->portal_group_tag, tag);
		}
		/* we now know the tag */
		session->portal_group_tag = tag;
		text = value_end;
	} else {
		/*
		 * any key we don't recognize either
		 * goes to the auth code, or we choke
		 * on it
		 */
		ret = get_auth_key_type(auth_client, &text, end);
		if (ret != LOGIN_OK)
			return ret;
	}
	*data = text;
	return LOGIN_OK;
}

static enum iscsi_login_status
get_op_params_text_keys(iscsi_session_t *session, int cid,
			char **data, char *end)
{
	char *text = *data;
	char *value = NULL;
	char *value_end = NULL;
	size_t size;
	iscsi_conn_t *conn = &session->conn[cid];

	if (iscsi_find_key_value("TargetAlias", text, end, &value,
				 &value_end)) {
		size = value_end - value;
		if (session->target_alias &&
		    strlen(session->target_alias) == size &&
		    memcmp(session->target_alias, value, size) == 0) {
			*data = value_end;
			return LOGIN_OK;
		}
		free(session->target_alias);
		session->target_alias = malloc(size + 1);
		if (!session->target_alias) {
			/* Alias not critical. So just print an error */
			log_error("Login failed to allocate alias");
			*data = value_end;
			return LOGIN_OK;
		}
		memcpy(session->target_alias, value, size);
		session->target_alias[size] = '\0';
		text = value_end;
	} else if (iscsi_find_key_value("TargetAddress", text, end, &value,
					 &value_end)) {
		if (iscsi_update_address(conn, value))
			text = value_end;
		else {
			log_error("Login redirection failed, "
				  "can't handle redirection to %s",
				  value);
			return LOGIN_REDIRECTION_FAILED;
		}
	} else if (iscsi_find_key_value("TargetPortalGroupTag", text, end,
					 &value, &value_end)) {
		int tag = strtoul(value, NULL, 0);
		/*
		 * We should have already obtained this
		 * via discovery, but the value could be stale.
		 * If the target was reconfigured it will send us
		 * the updated tpgt.
		 */
		if (session->portal_group_tag >= 0) {
			if (tag != session->portal_group_tag)
				log_debug(2, "Portal group tag "
					  "mismatch, expected %u, "
					  "received %u. Updating",
					  session->portal_group_tag, tag);
		}
		/* we now know the tag */
		session->portal_group_tag = tag;
		text = value_end;
	} else if (iscsi_find_key_value("InitialR2T", text, end, &value,
					 &value_end)) {
		if (session->type == ISCSI_SESSION_TYPE_NORMAL) {
			if (value && (strcmp(value, "Yes") == 0))
				session->initial_r2t_en = 1;
			else
				session->initial_r2t_en = 0;
		} else
			session->irrelevant_keys_bitmap |=
						IRRELEVANT_INITIALR2T;
		text = value_end;
	} else if (iscsi_find_key_value("ImmediateData", text, end, &value,
					 &value_end)) {
		if (session->type == ISCSI_SESSION_TYPE_NORMAL) {
			if (value && (strcmp(value, "Yes") == 0))
				session->imm_data_en = 1;
			else
				session->imm_data_en = 0;
		} else
			session->irrelevant_keys_bitmap |=
						IRRELEVANT_IMMEDIATEDATA;
		text = value_end;
	} else if (iscsi_find_key_value("MaxRecvDataSegmentLength", text, end,
				     &value, &value_end)) {
		if (session->type == ISCSI_SESSION_TYPE_DISCOVERY ||
		    !session->t->template->rdma) {
			int tgt_max_xmit;
			conn_rec_t *conn_rec = &session->nrec.conn[cid];

			tgt_max_xmit = strtoul(value, NULL, 0);
			/*
			 * if the rec value is zero it means to use
			 * what the target gave us.
			 */
			if (!conn_rec->iscsi.MaxXmitDataSegmentLength ||
			    tgt_max_xmit < conn->max_xmit_dlength)
				conn->max_xmit_dlength = tgt_max_xmit;
		}
		text = value_end;
	} else if (iscsi_find_key_value("FirstBurstLength", text, end, &value,
					 &value_end)) {
		if (session->type == ISCSI_SESSION_TYPE_NORMAL)
			session->first_burst = strtoul(value, NULL, 0);
		else
			session->irrelevant_keys_bitmap |=
						IRRELEVANT_FIRSTBURSTLENGTH;
		text = value_end;
	} else if (iscsi_find_key_value("MaxBurstLength", text, end, &value,
					 &value_end)) {
		/*
		 * we don't really care, since it's a  limit on the target's
		 * R2Ts, but record it anwyay
		 */
		if (session->type == ISCSI_SESSION_TYPE_NORMAL)
			session->max_burst = strtoul(value, NULL, 0);
		else
			session->irrelevant_keys_bitmap |=
						IRRELEVANT_MAXBURSTLENGTH;
		text = value_end;
	} else if (iscsi_find_key_value("HeaderDigest", text, end, &value,
					 &value_end)) {
		if (strcmp(value, "None") == 0) {
			if (conn->hdrdgst_en != ISCSI_DIGEST_CRC32C)
				conn->hdrdgst_en = ISCSI_DIGEST_NONE;
			else {
				log_error("Login negotiation "
					       "failed, HeaderDigest=CRC32C "
					       "is required, can't accept "
					       "%s", text);
				return LOGIN_NEGOTIATION_FAILED;
			}
		} else if (strcmp(value, "CRC32C") == 0) {
			if (conn->hdrdgst_en != ISCSI_DIGEST_NONE)
				conn->hdrdgst_en = ISCSI_DIGEST_CRC32C;
			else {
				log_error("Login negotiation "
				       "failed, HeaderDigest=None is "
				       "required, can't accept %s", text);
				return LOGIN_NEGOTIATION_FAILED;
			}
		} else {
			log_error("Login negotiation failed, "
				       "can't accept %s", text);
			return LOGIN_NEGOTIATION_FAILED;
		}
		text = value_end;
	} else if (iscsi_find_key_value("DataDigest", text, end, &value,
					 &value_end)) {
		if (strcmp(value, "None") == 0) {
			if (conn->datadgst_en != ISCSI_DIGEST_CRC32C)
				conn->datadgst_en = ISCSI_DIGEST_NONE;
			else {
				log_error("Login negotiation "
				       "failed, DataDigest=CRC32C "
				       "is required, can't accept %s", text);
				return LOGIN_NEGOTIATION_FAILED;
			}
		} else if (strcmp(value, "CRC32C") == 0) {
			if (conn->datadgst_en != ISCSI_DIGEST_NONE)
				conn->datadgst_en = ISCSI_DIGEST_CRC32C;
			else {
				log_error("Login negotiation "
				       "failed, DataDigest=None is "
				       "required, can't accept %s", text);
				return LOGIN_NEGOTIATION_FAILED;
			}
		} else {
			log_error("Login negotiation failed, "
				       "can't accept %s", text);
			return LOGIN_NEGOTIATION_FAILED;
		}
		text = value_end;
	} else if (iscsi_find_key_value("DefaultTime2Wait", text, end, &value,
					 &value_end)) {
		session->def_time2wait = strtoul(value, NULL, 0);
		text = value_end;
	} else if (iscsi_find_key_value("DefaultTime2Retain", text, end,
					 &value, &value_end)) {
		session->def_time2retain = strtoul(value, NULL, 0);
		text = value_end;
	} else if (iscsi_find_key_value("OFMarker", text, end, &value,
					 &value_end))
		/* result function is AND, target must honor our No */
		text = value_end;
	else if (iscsi_find_key_value("OFMarkInt", text, end, &value,
					 &value_end))
		/* we don't do markers, so we don't care */
		text = value_end;
	else if (iscsi_find_key_value("IFMarker", text, end, &value,
					 &value_end))
		/* result function is AND, target must honor our No */
		text = value_end;
	else if (iscsi_find_key_value("IFMarkInt", text, end, &value,
					 &value_end))
		/* we don't do markers, so we don't care */
		text = value_end;
	else if (iscsi_find_key_value("DataPDUInOrder", text, end, &value,
					 &value_end)) {
		if (session->type == ISCSI_SESSION_TYPE_NORMAL) {
			if (value && strcmp(value, "Yes") == 0)
				session->pdu_inorder_en = 1;
			else
				session->pdu_inorder_en = 0;
		} else
			session->irrelevant_keys_bitmap |=
						IRRELEVANT_DATAPDUINORDER;
		text = value_end;
	} else if (iscsi_find_key_value ("DataSequenceInOrder", text, end,
					 &value, &value_end)) {
		if (session->type == ISCSI_SESSION_TYPE_NORMAL)
			if (value && strcmp(value, "Yes") == 0)
				session->dataseq_inorder_en = 1;
			else
				session->dataseq_inorder_en = 0;
		else
			session->irrelevant_keys_bitmap |=
						IRRELEVANT_DATASEQUENCEINORDER;
		text = value_end;
	} else if (iscsi_find_key_value("MaxOutstandingR2T", text, end, &value,
					 &value_end)) {
		if (session->type == ISCSI_SESSION_TYPE_NORMAL) {
			if (strcmp(value, "1")) {
				log_error("Login negotiation "
					       "failed, can't accept Max"
					       "OutstandingR2T %s", value);
				return LOGIN_NEGOTIATION_FAILED;
			}
		} else
			session->irrelevant_keys_bitmap |=
						IRRELEVANT_MAXOUTSTANDINGR2T;
		text = value_end;
	} else if (iscsi_find_key_value("MaxConnections", text, end, &value,
					 &value_end)) {
		if (session->type == ISCSI_SESSION_TYPE_NORMAL) {
			if (strcmp(value, "1")) {
				log_error("Login negotiation "
					       "failed, can't accept Max"
					       "Connections %s", value);
				return LOGIN_NEGOTIATION_FAILED;
			}
		} else
			session->irrelevant_keys_bitmap |=
						IRRELEVANT_MAXCONNECTIONS;
		text = value_end;
	} else if (iscsi_find_key_value("ErrorRecoveryLevel", text, end,
					 &value, &value_end)) {
		if (strcmp(value, "0")) {
			log_error("Login negotiation failed, "
			       "can't accept ErrorRecovery %s", value);
			return LOGIN_NEGOTIATION_FAILED;
		}
		text = value_end;
	} else if (iscsi_find_key_value("RDMAExtensions", text, end,
					&value, &value_end)) {
		if (session->t->template->rdma &&
		    strcmp(value, "Yes") != 0) {
			log_error("Login negotiation failed, "
				  "Target must support RDMAExtensions");
			return LOGIN_NEGOTIATION_FAILED;
		}
		text = value_end;
	} else if (iscsi_find_key_value("InitiatorRecvDataSegmentLength", text,
					end, &value, &value_end)) {
		if (session->t->template->rdma) {
			conn->max_recv_dlength = MIN(conn->max_recv_dlength,
						     strtoul(value, NULL, 0));
		}
		text = value_end;
	} else if (iscsi_find_key_value("TargetRecvDataSegmentLength", text,
					end, &value, &value_end)) {
		if (session->t->template->rdma) {
			conn->max_xmit_dlength = MIN(conn->max_xmit_dlength,
						     strtoul(value, NULL, 0));
		}
		text = value_end;
	} else if (iscsi_find_key_value ("X-com.cisco.protocol", text, end,
					 &value, &value_end)) {
		if (strcmp(value, "NotUnderstood") &&
		    strcmp(value, "Reject") &&
		    strcmp(value, "Irrelevant") &&
		    strcmp(value, "draft20")) {
			/* if we didn't get a compatible protocol, fail */
			log_error("Login version mismatch, "
				       "can't accept protocol %s", value);
			return LOGIN_VERSION_MISMATCH;
		}
		text = value_end;
	} else if (iscsi_find_key_value("X-com.cisco.PingTimeout", text, end,
					 &value, &value_end))
		/* we don't really care what the target ends up using */
		text = value_end;
	else if (iscsi_find_key_value("X-com.cisco.sendAsyncText", text, end,
					 &value, &value_end))
		/* we don't bother for the target response */
		text = value_end;
	else {
		log_error("Login negotiation failed, couldn't "
			       "recognize text %s", text);
		return LOGIN_NEGOTIATION_FAILED;
	}
	*data = text;
	return LOGIN_OK;
}

static enum iscsi_login_status
check_security_stage_status(iscsi_session_t *session,
			    struct iscsi_acl *auth_client)
{
	int debug_status = 0;

	switch (acl_recv_end(auth_client, session)) {
	case AUTH_STATUS_CONTINUE:
		/* continue sending PDUs */
		break;

	case AUTH_STATUS_PASS:
		break;

	case AUTH_STATUS_NO_ERROR:	/* treat this as an error,
					 * since we should get a
					 * different code
					 */
	case AUTH_STATUS_ERROR:
	case AUTH_STATUS_FAIL:
	default:
		if (acl_get_dbg_status(auth_client, &debug_status) !=
		    AUTH_STATUS_NO_ERROR)
			log_error("Login authentication failed "
				       "with target %s, %s",
				       session->target_name,
				       acl_dbg_status_to_text(debug_status));
		else
			log_error("Login authentication failed "
				       "with target %s",
				       session->target_name);
		return LOGIN_AUTHENTICATION_FAILED;
	}
	return LOGIN_OK;
}

/*
 * this assumes the text data is always NULL terminated.  The caller can
 * always arrange for that by using a slightly larger buffer than the max PDU
 * size, and then appending a NULL to the PDU.
 */
static enum iscsi_login_status
iscsi_process_login_response(iscsi_session_t *session, int cid,
			     struct iscsi_login_rsp *login_rsp,
			     char *data, int max_data_length)
{
	int transit = login_rsp->flags & ISCSI_FLAG_LOGIN_TRANSIT;
	char *text = data;
	char *end;
	int pdu_current_stage, pdu_next_stage;
	enum iscsi_login_status ret;
	struct iscsi_acl *auth_client;
	iscsi_conn_t *conn = &session->conn[cid];

	auth_client = (session->auth_buffers && session->num_auth_buffers) ?
		(struct iscsi_acl *)session->auth_buffers[0].address : NULL;

	end = text + ntoh24(login_rsp->dlength) + 1;
	if (end >= (data + max_data_length)) {
		log_error("Login failed, process_login_response "
			       "buffer too small to guarantee NULL "
			       "termination");
		return LOGIN_FAILED;
	}

	/* guarantee a trailing NUL */
	*end = '\0';

	/* if the response status was success, sanity check the response */
	if (login_rsp->status_class == ISCSI_STATUS_CLS_SUCCESS) {
		/* check the active version */
		if (login_rsp->active_version != ISCSI_DRAFT20_VERSION) {
			log_error("Login version mismatch, "
				       "received incompatible active iSCSI "
				       "version 0x%02x, expected version "
				       "0x%02x",
				       login_rsp->active_version,
				       ISCSI_DRAFT20_VERSION);
			return LOGIN_VERSION_MISMATCH;
		}

		/* make sure the current stage matches */
		pdu_current_stage = (login_rsp->flags &
				    ISCSI_FLAG_LOGIN_CURRENT_STAGE_MASK) >> 2;
		if (pdu_current_stage != conn->current_stage) {
			log_error("Received invalid login PDU, "
				       "current stage mismatch, session %d, "
				       "response %d", conn->current_stage,
				       pdu_current_stage);
			return LOGIN_INVALID_PDU;
		}

		/*
		 * make sure that we're actually advancing if the T-bit is set
		 */
		pdu_next_stage = login_rsp->flags &
				 ISCSI_FLAG_LOGIN_NEXT_STAGE_MASK;
		if (transit && (pdu_next_stage <= conn->current_stage))
			return LOGIN_INVALID_PDU;
	}

	if (conn->current_stage == ISCSI_SECURITY_NEGOTIATION_STAGE) {
		if (acl_recv_begin(auth_client) != AUTH_STATUS_NO_ERROR) {
			log_error("Login failed because "
				       "acl_recv_begin failed");
			return LOGIN_FAILED;
		}

		if (acl_recv_transit_bit(auth_client, transit) !=
		    AUTH_STATUS_NO_ERROR) {
			log_error("Login failed because "
				  "acl_recv_transit_bit failed");
			return LOGIN_FAILED;
		}
	}

	/* scan the text data */
	while (text && (text < end)) {
		/* skip any NULs separating each text key=value pair */
		while ((text < end) && (*text == '\0'))
			text++;
		if (text >= end)
			break;

		/* handle keys appropriate for each stage */
		switch (conn->current_stage) {
		case ISCSI_SECURITY_NEGOTIATION_STAGE:{
				ret = get_security_text_keys(session, cid,
						&text, auth_client, end);
				if (ret != LOGIN_OK)
					return ret;
				break;
			}
		case ISCSI_OP_PARMS_NEGOTIATION_STAGE:{
				ret = get_op_params_text_keys(session, cid,
						&text, end);
				if (ret != LOGIN_OK)
					return ret;
				break;
			}
		default:
			return LOGIN_FAILED;
		}
	}

	if (conn->current_stage == ISCSI_SECURITY_NEGOTIATION_STAGE) {
		ret = check_security_stage_status(session, auth_client);
		if (ret != LOGIN_OK)
			return ret;
	}
	/* record some of the PDU fields for later use */
	session->tsih = ntohs(login_rsp->tsih);
	session->exp_cmdsn = ntohl(login_rsp->exp_cmdsn);
	session->max_cmdsn = ntohl(login_rsp->max_cmdsn);
	if (login_rsp->status_class == ISCSI_STATUS_CLS_SUCCESS)
		conn->exp_statsn = ntohl(login_rsp->statsn) + 1;

	if (transit) {
		/* advance to the next stage */
		conn->partial_response = 0;
		conn->current_stage = login_rsp->flags &
					 ISCSI_FLAG_LOGIN_NEXT_STAGE_MASK;
		session->irrelevant_keys_bitmap = 0;
	} else
		/*
		 * we got a partial response, don't advance,
		 * more negotiation to do
		 */
		conn->partial_response = 1;

	return LOGIN_OK;	/* this PDU is ok, though the login process
				 * may not be done yet
				 */
}

static int
add_params_normal_session(iscsi_session_t *session, struct iscsi_hdr *pdu,
                    char *data, int max_data_length)
{
	char value[AUTH_STR_MAX_LEN];

	/* these are only relevant for normal sessions */
	if (!iscsi_add_text(pdu, data, max_data_length, "InitialR2T",
			    session->initial_r2t_en ? "Yes" : "No"))
		return 0;

	if (!iscsi_add_text(pdu, data, max_data_length,
			    "ImmediateData",
			    session->imm_data_en ? "Yes" : "No"))
		return 0;

	sprintf(value, "%d", session->max_burst);
	if (!iscsi_add_text(pdu, data, max_data_length,
			    "MaxBurstLength", value))
		return 0;

	sprintf(value, "%d",session->first_burst);
	if (!iscsi_add_text(pdu, data, max_data_length,
			    "FirstBurstLength", value))
		return 0;

	/* these we must have */
	if (!iscsi_add_text(pdu, data, max_data_length,
			    "MaxOutstandingR2T", "1"))
		return 0;
	if (!iscsi_add_text(pdu, data, max_data_length,
			    "MaxConnections", "1"))
		return 0;
	if (!iscsi_add_text(pdu, data, max_data_length,
			    "DataPDUInOrder", "Yes"))
		return 0;
	if (!iscsi_add_text(pdu, data, max_data_length,
			    "DataSequenceInOrder", "Yes"))
		return 0;
	return 1;
}

static int
add_params_transport_specific(iscsi_session_t *session, int cid,
			     struct iscsi_hdr *pdu, char *data,
			     int max_data_length)
{
	char value[AUTH_STR_MAX_LEN];
	iscsi_conn_t *conn = &session->conn[cid];

	if (session->type == ISCSI_SESSION_TYPE_DISCOVERY ||
   	    !session->t->template->rdma) {
		sprintf(value, "%d", conn->max_recv_dlength);
		if (!iscsi_add_text(pdu, data, max_data_length,
				    "MaxRecvDataSegmentLength", value))
			return 0;
	} else {
		sprintf(value, "%d", conn->max_recv_dlength);
		if (!iscsi_add_text(pdu, data, max_data_length,
				   "InitiatorRecvDataSegmentLength",
				    value))
			return 0;

		sprintf(value, "%d", conn->max_xmit_dlength);
		if (!iscsi_add_text(pdu, data, max_data_length,
				   "TargetRecvDataSegmentLength",
				    value))
			return 0;

		if (!iscsi_add_text(pdu, data, max_data_length,
				   "RDMAExtensions", "Yes"))
			return 0;
	}
	return 1;
}

static int
check_irrelevant_keys(iscsi_session_t *session, struct iscsi_hdr *pdu,
                    char *data, int max_data_length)
{
	/* If you receive irrelevant keys, just check them from the irrelevant
	 * keys bitmap and respond with the key=Irrelevant text
	 */

	if (session->irrelevant_keys_bitmap & IRRELEVANT_MAXCONNECTIONS)
		if (!iscsi_add_text(pdu, data, max_data_length,
				    "MaxConnections", "Irrelevant"))
			return 0;

	if (session->irrelevant_keys_bitmap & IRRELEVANT_INITIALR2T)
		if (!iscsi_add_text(pdu, data, max_data_length,
				    "InitialR2T", "Irrelevant"))
			return 0;

	if (session->irrelevant_keys_bitmap & IRRELEVANT_IMMEDIATEDATA)
		if (!iscsi_add_text(pdu, data, max_data_length,
				    "ImmediateData", "Irrelevant"))
			return 0;

	if (session->irrelevant_keys_bitmap & IRRELEVANT_MAXBURSTLENGTH)
		if (!iscsi_add_text(pdu, data, max_data_length,
				    "MaxBurstLength", "Irrelevant"))
			return 0;

	if (session->irrelevant_keys_bitmap & IRRELEVANT_FIRSTBURSTLENGTH)
		if (!iscsi_add_text(pdu, data, max_data_length,
				    "FirstBurstLength", "Irrelevant"))
			return 0;

	if (session->irrelevant_keys_bitmap & IRRELEVANT_MAXOUTSTANDINGR2T)
		if (!iscsi_add_text(pdu, data, max_data_length,
				    "MaxOutstandingR2T", "Irrelevant"))
			return 0;

	if (session->irrelevant_keys_bitmap & IRRELEVANT_DATAPDUINORDER)
		if (!iscsi_add_text(pdu, data, max_data_length,
				    "DataPDUInOrder", "Irrelevant"))
			return 0;

	if (session->irrelevant_keys_bitmap & IRRELEVANT_DATASEQUENCEINORDER )
		if (!iscsi_add_text(pdu, data, max_data_length,
				    "DataSequenceInOrder", "Irrelevant"))
			return 0;

	return 1;
}

static int
fill_crc_digest_text(iscsi_conn_t *conn, struct iscsi_hdr *pdu,
		     char *data, int max_data_length)
{
	switch (conn->hdrdgst_en) {
	case ISCSI_DIGEST_NONE:
		if (!iscsi_add_text(pdu, data, max_data_length,
		    "HeaderDigest", "None"))
			return 0;
		break;
	case ISCSI_DIGEST_CRC32C:
		if (!iscsi_add_text(pdu, data, max_data_length,
		    "HeaderDigest", "CRC32C"))
			return 0;
		break;
	case ISCSI_DIGEST_CRC32C_NONE:
		if (!iscsi_add_text(pdu, data, max_data_length,
		    "HeaderDigest", "CRC32C,None"))
			return 0;
		break;
	default:
	case ISCSI_DIGEST_NONE_CRC32C:
		if (!iscsi_add_text(pdu, data, max_data_length,
		    "HeaderDigest", "None,CRC32C"))
			return 0;
		break;
	}

	switch (conn->datadgst_en) {
	case ISCSI_DIGEST_NONE:
		if (!iscsi_add_text(pdu, data, max_data_length,
		    "DataDigest", "None"))
			return 0;
		break;
	case ISCSI_DIGEST_CRC32C:
		if (!iscsi_add_text(pdu, data, max_data_length,
		    "DataDigest", "CRC32C"))
			return 0;
		break;
	case ISCSI_DIGEST_CRC32C_NONE:
		if (!iscsi_add_text(pdu, data, max_data_length,
		    "DataDigest", "CRC32C,None"))
			return 0;
		break;
	default:
	case ISCSI_DIGEST_NONE_CRC32C:
		if (!iscsi_add_text(pdu, data, max_data_length,
		    "DataDigest", "None,CRC32C"))
			return 0;
		break;
	}
	return 1;
}

static int
fill_op_params_text(iscsi_session_t *session, int cid, struct iscsi_hdr *pdu,
		    char *data, int max_data_length, int *transit)
{
	char value[AUTH_STR_MAX_LEN];
	iscsi_conn_t *conn = &session->conn[cid];
	int rdma;

	/* we always try to go from op params to full feature stage */
	conn->current_stage = ISCSI_OP_PARMS_NEGOTIATION_STAGE;
	conn->next_stage = ISCSI_FULL_FEATURE_PHASE;
	*transit = 1;

	rdma = (session->type == ISCSI_SESSION_TYPE_NORMAL) &&
			session->t->template->rdma;

	/*
	 * If we haven't gotten a partial response, then either we shouldn't be
	 * here, or we just switched to this stage, and need to start offering
	 * keys.
	 */
	if (!conn->partial_response) {
		/*
		 * request the desired settings the first time
		 * we are in this stage
		 */
		if (!rdma &&
		    !fill_crc_digest_text(conn, pdu, data, max_data_length))
			return 0;

		sprintf(value, "%d", session->def_time2wait);
		if (!iscsi_add_text(pdu, data, max_data_length,
				    "DefaultTime2Wait", value))
			return 0;

		sprintf(value, "%d", session->def_time2retain);
		if (!iscsi_add_text(pdu, data, max_data_length,
				    "DefaultTime2Retain", value))
			return 0;

		if (!iscsi_add_text(pdu, data, max_data_length,
				    "IFMarker", "No"))
			return 0;

		if (!iscsi_add_text(pdu, data, max_data_length,
				    "OFMarker", "No"))
			return 0;

		if (!iscsi_add_text(pdu, data, max_data_length,
				    "ErrorRecoveryLevel", "0"))
			return 0;

		if (session->type == ISCSI_SESSION_TYPE_NORMAL) {
			if (!add_params_normal_session(session, pdu, data,
						  max_data_length))
				return 0;

			if (!add_params_transport_specific(session, cid,
							  pdu, data,
 max_data_length))
				return 0;
		} else {
			sprintf(value, "%d", conn->max_recv_dlength);
			if (!iscsi_add_text(pdu, data, max_data_length,
					    "MaxRecvDataSegmentLength", value))
				return 0;
		}
	} else {
		if (!check_irrelevant_keys(session, pdu, data, max_data_length))
			return 0;

		if (rdma &&
		    !fill_crc_digest_text(conn, pdu, data, max_data_length))
			return 0;
	}

	return 1;
}

static void
enum_auth_keys(struct iscsi_acl *auth_client, struct iscsi_hdr *pdu,
	       char *data, int max_data_length, int keytype)
{
	int present = 0, rc;
	char *key = (char *)acl_get_key_name(keytype);
	int key_length = key ? strlen(key) : 0;
	int pdu_length = ntoh24(pdu->dlength);
	char *auth_value = data + pdu_length + key_length + 1;
	unsigned int max_length = max_data_length - (pdu_length
					  + key_length + 1);

	/*
	 * add the key/value pairs the auth code wants to send
	 * directly to the PDU, since they could in theory be large.
	 */
	rc = acl_send_key_val(auth_client, keytype, &present, auth_value,
			      max_length);
	if ((rc == AUTH_STATUS_NO_ERROR) && present) {
		/* actually fill in the key */
		strncpy(&data[pdu_length], key, key_length);
		pdu_length += key_length;
		data[pdu_length] = '=';
		pdu_length++;
		/*
		 * adjust the PDU's data segment length
		 * to include the value and trailing NUL
		 */
		pdu_length += strlen(auth_value) + 1;
		hton24(pdu->dlength, pdu_length);
	}
}

static int
fill_security_params_text(iscsi_session_t *session, int cid, struct iscsi_hdr *pdu,
			  struct iscsi_acl *auth_client, char *data,
			  int max_data_length, int *transit)
{
	int keytype = AUTH_KEY_TYPE_NONE;
	int rc = acl_send_transit_bit(auth_client, transit);
	iscsi_conn_t *conn = &session->conn[cid];

	/* see if we're ready for a stage change */
	if (rc != AUTH_STATUS_NO_ERROR)
		return 0;

	if (*transit) {
		/*
		 * discovery sessions can go right to full-feature phase,
		 * unless they want to non-standard values for the few relevant
		 * keys, or want to offer vendor-specific keys
		 */
		if (session->type == ISCSI_SESSION_TYPE_DISCOVERY)
			if ((conn->hdrdgst_en != ISCSI_DIGEST_NONE) ||
			    (conn->datadgst_en != ISCSI_DIGEST_NONE) ||
			    (conn->max_recv_dlength !=
			    ISCSI_DEF_MAX_RECV_SEG_LEN))
				conn->next_stage =
					    ISCSI_OP_PARMS_NEGOTIATION_STAGE;
			else
				conn->next_stage = ISCSI_FULL_FEATURE_PHASE;
		else
			conn->next_stage = ISCSI_OP_PARMS_NEGOTIATION_STAGE;
	} else
		conn->next_stage = ISCSI_SECURITY_NEGOTIATION_STAGE;

	/* enumerate all the keys the auth code might want to send */
	while (acl_get_next_key_type(&keytype) == AUTH_STATUS_NO_ERROR)
		enum_auth_keys(auth_client, pdu, data, max_data_length,
			       keytype);

	return 1;
}

/**
 * iscsi_make_login_pdu - Prepare the login pdu to be sent to iSCSI target.
 * @session: session for which login is initiated.
 * @pdu: login header
 * @data: contains text keys to be negotiated during login
 * @max_data_length: data size
 *
 * Description:
 *     Based on whether authentication is enabled or not, corresponding text
 *     keys are filled up in login pdu.
 *
 **/
static int
iscsi_make_login_pdu(iscsi_session_t *session, int cid, struct iscsi_hdr *hdr,
		     char *data, int max_data_length)
{
	int transit = 0;
	int ret;
	struct iscsi_login *login_hdr = (struct iscsi_login *)hdr;
	struct iscsi_acl *auth_client;
	iscsi_conn_t *conn = &session->conn[cid];

	auth_client = (session->auth_buffers && session->num_auth_buffers) ?
		(struct iscsi_acl *)session->auth_buffers[0].address : NULL;

	/* initialize the PDU header */
	memset(login_hdr, 0, sizeof(*login_hdr));
	login_hdr->opcode = ISCSI_OP_LOGIN | ISCSI_OP_IMMEDIATE;
	login_hdr->cid = 0;
	memcpy(login_hdr->isid, session->isid, sizeof(session->isid));
	login_hdr->tsih = 0;
	login_hdr->cmdsn = htonl(session->cmdsn);
	/* don't increment on immediate */
	login_hdr->min_version = ISCSI_DRAFT20_VERSION;
	login_hdr->max_version = ISCSI_DRAFT20_VERSION;
	login_hdr->exp_statsn = htonl(conn->exp_statsn);

	/*
	 * the very first Login PDU has some additional requirements,
	 * and we need to decide what stage to start in.
	 */
	if (conn->current_stage == ISCSI_INITIAL_LOGIN_STAGE) {
		if (session->initiator_name && session->initiator_name[0]) {
			if (!iscsi_add_text(hdr, data, max_data_length,
			     "InitiatorName", session->initiator_name))
				return 0;
		} else {
			log_error("InitiatorName is required "
				       "on the first Login PDU");
			return 0;
		}
		if (session->initiator_alias && session->initiator_alias[0]) {
			if (!iscsi_add_text(hdr, data, max_data_length,
			     "InitiatorAlias", session->initiator_alias))
				return 0;
		}

		if ((session->target_name && session->target_name[0]) &&
		    (session->type == ISCSI_SESSION_TYPE_NORMAL)) {
			if (!iscsi_add_text(hdr, data, max_data_length,
			    "TargetName", session->target_name))
				return 0;
		}

		if (!iscsi_add_text(hdr, data, max_data_length,
		    "SessionType", (session->type ==
		      ISCSI_SESSION_TYPE_DISCOVERY) ? "Discovery" : "Normal"))
			return 0;

		if (auth_client)
			/* we're prepared to do authentication */
			conn->current_stage = conn->next_stage =
			    ISCSI_SECURITY_NEGOTIATION_STAGE;
		else
			/* can't do any authentication, skip that stage */
			conn->current_stage = conn->next_stage =
			    ISCSI_OP_PARMS_NEGOTIATION_STAGE;
	}

	/* fill in text based on the stage */
	switch (conn->current_stage) {
	case ISCSI_OP_PARMS_NEGOTIATION_STAGE:{
			ret = fill_op_params_text(session, cid, hdr, data,
						  max_data_length, &transit);
			if (!ret)
				return ret;
			break;
		}
	case ISCSI_SECURITY_NEGOTIATION_STAGE:{
			ret = fill_security_params_text(session, cid, hdr,
					auth_client, data, max_data_length,
					&transit);
			if (!ret)
				return ret;
			break;
		}
	case ISCSI_FULL_FEATURE_PHASE:
		log_error("Can't send login PDUs in full "
			       "feature phase");
		return 0;
	default:
		log_error("Can't send login PDUs in unknown "
			       "stage %d", conn->current_stage);
		return 0;
	}

	/* fill in the flags */
	login_hdr->flags = 0;
	login_hdr->flags |= conn->current_stage << 2;
	if (transit) {
		/* transit to the next stage */
		login_hdr->flags |= conn->next_stage;
		login_hdr->flags |= ISCSI_FLAG_LOGIN_TRANSIT;
	} else
		/* next == current */
		login_hdr->flags |= conn->current_stage;

	return 1;
}

static enum iscsi_login_status
check_for_authentication(iscsi_session_t *session,
			 struct iscsi_acl *auth_client)
{
	enum iscsi_login_status ret = LOGIN_FAILED;

	auth_client = (struct iscsi_acl *)session->auth_buffers[0].address;

	/* prepare for authentication */
	if (acl_init(TYPE_INITIATOR, session->num_auth_buffers,
		     session->auth_buffers) != AUTH_STATUS_NO_ERROR) {
		log_error("Couldn't initialize authentication");
		return LOGIN_FAILED;
	}

	if (session->username &&
	    (acl_set_user_name(auth_client, session->username) !=
	    AUTH_STATUS_NO_ERROR)) {
		log_error("Couldn't set username");
		goto end;
	}

	if (session->password && (acl_set_passwd(auth_client,
	    session->password, session->password_length) !=
		 AUTH_STATUS_NO_ERROR)) {
		log_error("Couldn't set password");
		goto end;
	}

	if (acl_set_ip_sec(auth_client, 1) != AUTH_STATUS_NO_ERROR) {
		log_error("Couldn't set IPSec");
		goto end;
	}

	if (acl_set_auth_rmt(auth_client, session->bidirectional_auth) !=
			     AUTH_STATUS_NO_ERROR) {
		log_error("Couldn't set remote authentication");
		goto end;
	}
	return LOGIN_OK;

 end:
	if (auth_client && acl_finish(auth_client) != AUTH_STATUS_NO_ERROR) {
		log_error("Login failed, error finishing auth_client");
		if (ret == LOGIN_OK)
			ret = LOGIN_FAILED;
	}
	return ret;
}

static enum iscsi_login_status
check_status_login_response(iscsi_session_t *session, int cid,
			    struct iscsi_login_rsp *login_rsp,
			    char *data, int max_data_length, int *final)
{
	enum iscsi_login_status ret;

	switch (login_rsp->status_class) {
	case ISCSI_STATUS_CLS_SUCCESS:
		/* process this response and possibly continue sending PDUs */
		ret = iscsi_process_login_response(session, cid, login_rsp,
						   data, max_data_length);
		if (ret != LOGIN_OK)	/* pass back whatever
					 * error we discovered
					 */
			*final = 1;
		break;
	case ISCSI_STATUS_CLS_REDIRECT:
		/*
		 * we need to process this response to get the
		 * TargetAddress of the redirect, but we don't care
		 * about the return code.
		 */
		iscsi_process_login_response(session, cid, login_rsp,
					     data, max_data_length);
		ret = LOGIN_REDIRECT;
		*final = 1;
		break;
	case ISCSI_STATUS_CLS_INITIATOR_ERR:
		if (login_rsp->status_detail ==
		    ISCSI_LOGIN_STATUS_AUTH_FAILED) {
			log_error("Login failed to authenticate "
				       "with target %s", session->target_name);
		}
		ret = LOGIN_OK;
		*final = 1;
		break;
	default:
		/*
		 * some sort of error, login terminated unsuccessfully,
		 * though this function did it's job.
		 * the caller must check the status_class and
		 * status_detail and decide what to do next.
		 */
		ret = LOGIN_OK;
		*final = 1;
	}
	return ret;
}

int
iscsi_login_begin(iscsi_session_t *session, iscsi_login_context_t *c)
{
	iscsi_conn_t *conn = &session->conn[c->cid];

	c->auth_client = NULL;
	c->login_rsp = (struct iscsi_login_rsp *)&c->pdu;
	c->received_pdu = 0;
	c->timeout = 0;
	c->final = 0;
	c->ret = LOGIN_FAILED;

	/* prepare the session of the connection is leading */
	if (c->cid ==0) {
		session->cmdsn = 1;
		session->exp_cmdsn = 1;
		session->max_cmdsn = 1;
	}

	conn->current_stage = ISCSI_INITIAL_LOGIN_STAGE;
	conn->partial_response = 0;

	if (session->auth_buffers && session->num_auth_buffers) {
		c->ret = check_for_authentication(session, c->auth_client);
		if (c->ret != LOGIN_OK)
			return 1;
	}

	return 0;
}

int
iscsi_login_req(iscsi_session_t *session, iscsi_login_context_t *c)
{
	iscsi_conn_t *conn = &session->conn[c->cid];

	c->final = 0;
	c->timeout = 0;
	c->login_rsp = (struct iscsi_login_rsp *)&c->pdu;
	c->ret = LOGIN_FAILED;

	memset(c->buffer, 0, c->bufsize);
	c->data = c->buffer;
	c->max_data_length = c->bufsize;

	/*
	 * pick the appropriate timeout. If we know the target has
	 * responded before, and we're in the security stage, we use a
	 * longer timeout, since the authentication alogorithms can
	 * take a while, especially if the target has to go talk to a
	 * tacacs or RADIUS server (which may or may not be
	 * responding).
	 */
	if (c->received_pdu && (conn->current_stage ==
		ISCSI_SECURITY_NEGOTIATION_STAGE))
		c->timeout = conn->auth_timeout;
	else
		c->timeout = conn->login_timeout;

	/*
	 * fill in the PDU header and text data based on the login
	 * stage that we're in
	 */
	if (!iscsi_make_login_pdu(session, c->cid, &c->pdu, c->data,
				  c->max_data_length)) {
		log_error("login failed, couldn't make a login PDU");
		c->ret = LOGIN_FAILED;
		goto done;
	}

	/* send a PDU to the target */
	if (!iscsi_io_send_pdu(conn, &c->pdu, ISCSI_DIGEST_NONE,
			    c->data, ISCSI_DIGEST_NONE, c->timeout)) {
		/*
		 * FIXME: caller might want us to distinguish I/O
		 * error and timeout. Might want to switch portals on
		 * timeouts, but not I/O errors.
		 */
		log_error("Login I/O error, failed to send a PDU");
		c->ret = LOGIN_IO_ERROR;
		goto done;
	}
	return 0;

 done:
	if (c->auth_client && acl_finish(c->auth_client) !=
	    AUTH_STATUS_NO_ERROR) {
		log_error("Login failed, error finishing c->auth_client");
		if (c->ret == LOGIN_OK)
			c->ret = LOGIN_FAILED;
	}
	return 1;
}

int
iscsi_login_rsp(iscsi_session_t *session, iscsi_login_context_t *c)
{
	iscsi_conn_t *conn = &session->conn[c->cid];
	int err;

	/* read the target's response into the same buffer */
	err = iscsi_io_recv_pdu(conn, &c->pdu, ISCSI_DIGEST_NONE, c->data,
			        c->max_data_length, ISCSI_DIGEST_NONE,
			        c->timeout);
	if (err == -EAGAIN) {
		goto done;
	} else if (err < 0) {
		/*
		 * FIXME: caller might want us to distinguish I/O
		 * error and timeout. Might want to switch portals on
		 * timeouts, but not I/O errors.
		 */
		log_error("Login I/O error, failed to receive a PDU");
		c->ret = LOGIN_IO_ERROR;
		goto done;
	}

	err = -EIO;
	c->received_pdu = 1;

	/* check the PDU response type */
	if (c->pdu.opcode == (ISCSI_OP_LOGIN_RSP | 0xC0)) {
		/*
		 * it's probably a draft 8 login response,
		 * which we can't deal with
		 */
		log_error("Received iSCSI draft 8 login "
			  "response opcode 0x%x, expected draft "
			  "20 login response 0x%2x",
			  c->pdu.opcode, ISCSI_OP_LOGIN_RSP);
		c->ret = LOGIN_VERSION_MISMATCH;
		goto done;
	} else if (c->pdu.opcode != ISCSI_OP_LOGIN_RSP) {
		c->ret = LOGIN_INVALID_PDU;
		goto done;
	}

	/*
	 * give the caller the status class and detail from the last
	 * login response PDU received
	 */
	c->status_class = c->login_rsp->status_class;
	c->status_detail = c->login_rsp->status_detail;
	log_debug(1, "login response status %02d%02d",
			c->status_class, c->status_detail);
	c->ret = check_status_login_response(session, c->cid,
		     c->login_rsp, c->data, c->max_data_length,
		     &c->final);
	if (c->final)
		goto done;
	return 0;

 done:
	if (c->auth_client && acl_finish(c->auth_client) !=
	    AUTH_STATUS_NO_ERROR) {
		log_error("Login failed, error finishing c->auth_client");
		if (c->ret == LOGIN_OK)
			c->ret = LOGIN_FAILED;
	}
	return err;
}

/**
 * iscsi_login - attempt to login to the target.
 * @session: login is initiated over this session
 * @buffer: holds login pdu
 * @bufsize: size of login pdu
 * @status_class: holds either success or failure as status of login
 * @status_detail: contains details based on the login status
 *
 * Description:
 *     The caller must check the status class to determine if the login
 *     succeeded. A return of 1 does not mean the login succeeded, it just
 *     means this function worked, and the status class is valid info.
 *     This allows the caller to decide whether or not to retry logins, so
 *     that we don't have any policy logic here.
 **/
enum iscsi_login_status
iscsi_login(iscsi_session_t *session, int cid, char *buffer, size_t bufsize,
	    uint8_t *status_class, uint8_t *status_detail)
{
	iscsi_conn_t *conn = &session->conn[cid];
	iscsi_login_context_t *c = &conn->login_context;
	struct timeval connection_timer;
	struct pollfd pfd;
	int ret, timeout;

	/*
	 * assume iscsi_login is only called from discovery, so it is
	 * safe to always set to zero
	 */
	conn->exp_statsn = 0;

	c->cid = cid;
	c->buffer = buffer;
	c->bufsize = bufsize;

	if (iscsi_login_begin(session, c))
		return c->ret;

	do {
		if (iscsi_login_req(session, c))
			return c->ret;

		/*
		 * TODO: merge the poll and req/rsp code with the discovery
		 * poll and text req/rsp.
		 */
		iscsi_timer_set(&connection_timer,
				session->conn[0].active_timeout);
		timeout = iscsi_timer_msecs_until(&connection_timer);

		memset(&pfd, 0, sizeof (pfd));
		pfd.fd = conn->socket_fd;
		pfd.events = POLLIN | POLLPRI;

repoll:
		pfd.revents = 0;
		ret = poll(&pfd, 1, timeout);
		log_debug(7, "%s: Poll return %d\n", __FUNCTION__, ret);
		if (iscsi_timer_expired(&connection_timer)) {
			log_warning("Login response timeout. Waited %d "
				    "seconds and did not get reponse PDU.\n",
				    session->conn[0].active_timeout);
			c->ret = LOGIN_FAILED;
			return c->ret;
		}

		if (ret > 0) {
			if (pfd.revents & (POLLIN | POLLPRI)) {
				ret = iscsi_login_rsp(session, c);
				if (ret ==  -EAGAIN)
					goto repoll;

				if (status_class)
					*status_class = c->status_class;
				if (status_detail)
					*status_detail = c->status_detail;

				if (ret)
					return c->ret;
			} else if (pfd.revents & POLLHUP) {
				log_warning("Login POLLHUP");
				c->ret = LOGIN_FAILED;
				return c->ret;
			} else if (pfd.revents & POLLNVAL) {
				log_warning("Login POLLNVAL");
				c->ret = LOGIN_IO_ERROR;
				return c->ret;
			} else if (pfd.revents & POLLERR) {
				log_warning("Login POLLERR");
				c->ret = LOGIN_IO_ERROR;
				return c->ret;
			}

		} else if (ret < 0) {
			log_error("Login poll error.\n");
			c->ret = LOGIN_FAILED;
			return c->ret;
		}
	} while (conn->current_stage != ISCSI_FULL_FEATURE_PHASE);

	c->ret = LOGIN_OK;
	if (c->auth_client && acl_finish(c->auth_client) !=
	    AUTH_STATUS_NO_ERROR) {
		log_error("Login failed, error finishing c->auth_client");
		if (c->ret == LOGIN_OK)
			c->ret = LOGIN_FAILED;
	}

	return c->ret;
}
