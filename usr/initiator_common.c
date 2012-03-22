/*
 * Common code for setting up discovery and normal sessions.
 *
 * Copyright (C) 2004 Dmitry Yusupov, Alex Aizman
 * Copyright (C) 2006 - 2009 Mike Christie
 * Copyright (C) 2006 - 2009 Red Hat, Inc. All rights reserved.
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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "initiator.h"
#include "transport.h"
#include "iscsid.h"
#include "iscsi_ipc.h"
#include "log.h"
#include "iscsi_sysfs.h"
#include "iscsi_settings.h"
#include "iface.h"
#include "host.h"
#include "sysdeps.h"
#include "iscsi_err.h"
#include "iscsi_net_util.h"

struct iscsi_session *session_find_by_sid(uint32_t sid)
{
	struct iscsi_transport *t;
	struct iscsi_session *session;

	list_for_each_entry(t, &transports, list) {
		list_for_each_entry(session, &t->sessions, list) {
			if (session->id == sid)
				return session;
		}
	}
	return NULL;
}

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

int iscsi_setup_authentication(struct iscsi_session *session,
			       struct iscsi_auth_config *auth_cfg)
{
	/* if we have any incoming credentials, we insist on authenticating
	 * the target or not logging in at all
	 */
	if (auth_cfg->username_in[0] || auth_cfg->password_in_length) {
		/* sanity check the config */
		if (auth_cfg->password_length == 0) {
			log_warning("CHAP configuratoin has incoming "
				    "authentication credentials but has no "
				    "outgoing credentials configured.");
			return EINVAL;
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

	return 0;
}

void
iscsi_copy_operational_params(struct iscsi_conn *conn,
			struct iscsi_session_operational_config *session_conf,
			struct iscsi_conn_operational_config *conn_conf)
{
	struct iscsi_session *session = conn->session;
	struct iscsi_transport *t = session->t;

	conn->hdrdgst_en = conn_conf->HeaderDigest;
	conn->datadgst_en = conn_conf->DataDigest;

	conn->max_recv_dlength =
			__padding(conn_conf->MaxRecvDataSegmentLength);
	if (conn->max_recv_dlength < ISCSI_MIN_MAX_RECV_SEG_LEN ||
	    conn->max_recv_dlength > ISCSI_MAX_MAX_RECV_SEG_LEN) {
		log_error("Invalid iscsi.MaxRecvDataSegmentLength. Must be "
			 "within %u and %u. Setting to %u\n",
			  ISCSI_MIN_MAX_RECV_SEG_LEN,
			  ISCSI_MAX_MAX_RECV_SEG_LEN,
			  DEF_INI_MAX_RECV_SEG_LEN);
		conn_conf->MaxRecvDataSegmentLength =
						DEF_INI_MAX_RECV_SEG_LEN;
		conn->max_recv_dlength = DEF_INI_MAX_RECV_SEG_LEN;
	}

	/* zero indicates to use the target's value */
	conn->max_xmit_dlength =
			__padding(conn_conf->MaxXmitDataSegmentLength);
	if (conn->max_xmit_dlength == 0)
		conn->max_xmit_dlength = ISCSI_DEF_MAX_RECV_SEG_LEN;
	if (conn->max_xmit_dlength < ISCSI_MIN_MAX_RECV_SEG_LEN ||
	    conn->max_xmit_dlength > ISCSI_MAX_MAX_RECV_SEG_LEN) {
		log_error("Invalid iscsi.MaxXmitDataSegmentLength. Must be "
			 "within %u and %u. Setting to %u\n",
			  ISCSI_MIN_MAX_RECV_SEG_LEN,
			  ISCSI_MAX_MAX_RECV_SEG_LEN,
			  DEF_INI_MAX_RECV_SEG_LEN);
		conn_conf->MaxXmitDataSegmentLength =
						DEF_INI_MAX_RECV_SEG_LEN;
		conn->max_xmit_dlength = DEF_INI_MAX_RECV_SEG_LEN;
	}

	/* session's operational parameters */
	session->initial_r2t_en = session_conf->InitialR2T;
	session->imm_data_en = session_conf->ImmediateData;
	session->first_burst = __padding(session_conf->FirstBurstLength);
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
		session_conf->FirstBurstLength = DEF_INI_FIRST_BURST_LEN;
		session->first_burst = DEF_INI_FIRST_BURST_LEN;
	}

	session->max_burst = __padding(session_conf->MaxBurstLength);
	if (session->max_burst < ISCSI_MIN_MAX_BURST_LEN ||
	    session->max_burst > ISCSI_MAX_MAX_BURST_LEN) {
		log_error("Invalid iscsi.MaxBurstLength of %u. Must be "
			  "within %u and %u. Setting to %u\n",
			   session->max_burst, ISCSI_MIN_MAX_BURST_LEN,
			   ISCSI_MAX_MAX_BURST_LEN, DEF_INI_MAX_BURST_LEN);
		session_conf->MaxBurstLength = DEF_INI_MAX_BURST_LEN;
		session->max_burst = DEF_INI_MAX_BURST_LEN;
	}

	if (session->first_burst > session->max_burst) {
		log_error("Invalid iscsi.FirstBurstLength of %u. Must be "
			  "less than iscsi.MaxBurstLength. Setting to %u\n",
			   session->first_burst, session->max_burst);
		session_conf->FirstBurstLength = session->max_burst;
		session->first_burst = session->max_burst;
	}

	session->def_time2wait = session_conf->DefaultTime2Wait;
	session->def_time2retain = session_conf->DefaultTime2Retain;
	session->erl = session_conf->ERL;

	if (session->type == ISCSI_SESSION_TYPE_DISCOVERY) {
		/*
		 * Right now, we only support 8K max for kernel based
		 * sendtargets discovery, because the recv pdu buffers are
		 * limited to this size.
		 */
		if ((t->caps & CAP_TEXT_NEGO) &&
		     conn->max_recv_dlength > ISCSI_DEF_MAX_RECV_SEG_LEN)
			conn->max_recv_dlength = ISCSI_DEF_MAX_RECV_SEG_LEN;

		/* We do not support discovery sessions with digests */
		conn->hdrdgst_en = ISCSI_DIGEST_NONE;
		conn->datadgst_en = ISCSI_DIGEST_NONE;
	}

	if (t->template->create_conn)
		t->template->create_conn(conn);
}

int iscsi_setup_portal(struct iscsi_conn *conn, char *address, int port)
{
	char serv[NI_MAXSERV];

	sprintf(serv, "%d", port);
	if (resolve_address(address, serv, &conn->saddr)) {
		log_error("cannot resolve host name %s", address);
		return ISCSI_ERR_TRANS;
	}
	conn->failback_saddr = conn->saddr;

	getnameinfo((struct sockaddr *)&conn->saddr, sizeof(conn->saddr),
		    conn->host, sizeof(conn->host), NULL, 0, NI_NUMERICHOST);
	log_debug(4, "resolved %s to %s", address, conn->host);
	return 0;
}

int host_set_param(struct iscsi_transport *t,
		   uint32_t host_no, int param, char *value,
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

static void print_param_value(enum iscsi_param param, void *value, int type)
{
	log_debug(3, "set operational parameter %d to:", param);

	if (type == ISCSI_STRING)
		log_debug(3, "%s", value ? (char *)value : "NULL");
	else
		log_debug(3, "%u", *(uint32_t *)value);
}

#define MAX_HOST_PARAMS 2

int iscsi_host_set_params(struct iscsi_session *session)
{
	struct iscsi_transport *t = session->t;
	int i;
	struct hostparam {
		int param;
		int type;
		void *value;
	} hosttbl[MAX_HOST_PARAMS] = {
		{
			.param = ISCSI_HOST_PARAM_NETDEV_NAME,
			.value = session->nrec.iface.netdev,
			.type = ISCSI_STRING,
		}, {
			.param = ISCSI_HOST_PARAM_HWADDRESS,
			.value = session->nrec.iface.hwaddress,
			.type = ISCSI_STRING,
		},
	};

	for (i = 0; i < MAX_HOST_PARAMS; i++) {
		if (host_set_param(t, session->hostno,
				   hosttbl[i].param, hosttbl[i].value,
				   hosttbl[i].type)) {
			return EPERM;
		}

		print_param_value(hosttbl[i].param, hosttbl[i].value,
				  hosttbl[i].type);
	}

	return 0;
}

#define MAX_SESSION_PARAMS 32

int iscsi_session_set_params(struct iscsi_conn *conn)
{
	struct iscsi_session *session = conn->session;
	struct iscsi_transport *t = session->t;
	int i, rc;
	uint32_t one = 1, zero = 0;
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

	/* some llds will send nops internally */
	if (!iscsi_sysfs_session_supports_nop(session->id)) {
		session->param_mask &= ~ISCSI_PING_TMO;
		session->param_mask &= ~ISCSI_RECV_TMO;
	}

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
			return EPERM;
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
#if 0
TODO handle this
			case ISCSI_PARAM_INITIATOR_NAME:
				/* use host level one instead */
				hosttbl[ISCSI_HOST_PARAM_INITIATOR_NAME].set = 1;
				break;
#endif
			}
		}

		print_param_value(conntbl[i].param, conntbl[i].value,
				  conntbl[i].type);
	}

	return 0;
}

int iscsi_host_set_net_params(struct iface_rec *iface,
			      struct iscsi_session *session)
{
	struct iscsi_transport *t = session->t;
	int rc = 0;
	char *netdev;
	struct host_info hinfo;

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

	/* these type of drivers need the netdev upd */
	if (strlen(iface->netdev))
		netdev = iface->netdev;
	else {
		memset(&hinfo, 0, sizeof(hinfo));
		hinfo.host_no = session->hostno;
		iscsi_sysfs_get_hostinfo_by_host_no(&hinfo);

		netdev = hinfo.iface.netdev;
	}

	if (net_ifup_netdev(netdev))
		log_warning("Could not brining up netdev %s. Try running "
			    "'ifup %s' first if login fails.", netdev, netdev);

	rc = host_set_param(t, session->hostno,
			    ISCSI_HOST_PARAM_IPADDRESS,
			    iface->ipaddress, ISCSI_STRING);
	if (rc)
		return rc;

	if (iface_is_bound_by_netdev(iface)) {
		rc = host_set_param(t, session->hostno,
				    ISCSI_HOST_PARAM_NETDEV_NAME,
				    iface->netdev, ISCSI_STRING);
		if (rc)
			return rc;
	}

	if (iface_is_bound_by_hwaddr(iface)) {
		rc = host_set_param(t, session->hostno,
				    ISCSI_HOST_PARAM_HWADDRESS,
				    iface->hwaddress, ISCSI_STRING);
		if (rc)
			return rc;
	}
	return 0;
}
