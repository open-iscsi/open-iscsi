/*
 * Copyright (C) 2017-2018 Red Hat, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Author: Gris Ge <fge@redhat.com>
 */

#include <string.h>

#include "libopeniscsiusr/libopeniscsiusr.h"
#include "default.h"
#include "iface.h"
#include "node.h"

#define CONFIG_DIGEST_NEVER	0

static void default_session_op_cfg(struct iscsi_session_op_cfg *op_cfg)
{
	op_cfg->InitialR2T = 0;
	op_cfg->ImmediateData = 1;
	op_cfg->FirstBurstLength = DEF_INI_FIRST_BURST_LEN;
	op_cfg->MaxBurstLength = DEF_INI_MAX_BURST_LEN;
	op_cfg->DefaultTime2Wait = ISCSI_DEF_TIME2WAIT;
	op_cfg->DefaultTime2Retain = 0;
	op_cfg->MaxConnections = 1;
	op_cfg->MaxOutstandingR2T = 1;
	op_cfg->ERL = 0;
	op_cfg->FastAbort = 1;
}

static void default_conn_op_cfg(struct iscsi_conn_op_cfg *op_cfg)
{
	op_cfg->MaxXmitDataSegmentLength = 0;
	op_cfg->MaxRecvDataSegmentLength = DEF_INI_MAX_RECV_SEG_LEN;
	op_cfg->HeaderDigest = DIGEST_NEVER;
	op_cfg->DataDigest = DIGEST_NEVER;
	op_cfg->IFMarker = 0;
	op_cfg->OFMarker = 0;
}

/*
 * default is to use tcp through whatever the network layer
 * selects for us with the /etc/iscsi/initiatorname.iscsi iname.
 */
static void default_iface(struct iscsi_iface *iface)
{
	snprintf(iface->transport_name,
		 sizeof(iface->transport_name)/sizeof(char),
		 DEFAULT_TRANSPORT);

	if (!strlen(iface->name))
		snprintf(iface->name, sizeof(iface->name)/sizeof(char),
			 DEFAULT_IFACENAME);
}

void _default_node(struct iscsi_node *node)
{
	node->tpgt = PORTAL_GROUP_TAG_UNKNOWN;
	node->disc_type = DISCOVERY_TYPE_STATIC;
	node->leading_login = 0;
	node->session.cmds_max = CMDS_MAX;
	node->session.xmit_thread_priority = XMIT_THREAD_PRIORITY;
	node->session.initial_cmdsn = 0;
	node->session.queue_depth = QUEUE_DEPTH;
	node->session.nr_sessions = 1;
	node->session.initial_login_retry_max = DEF_INITIAL_LOGIN_RETRIES_MAX;
	node->session.reopen_max = DEF_SESSION_REOPEN_MAX;
	node->session.auth.authmethod = 0;
	/* TYPE_INT_LIST fields should be initialized to ~0 to indicate unset values */
	memset(node->session.auth.chap_algs, ~0, sizeof(node->session.auth.chap_algs));
	node->session.auth.chap_algs[0] = ISCSI_AUTH_CHAP_ALG_MD5;
	node->session.auth.password_length = 0;
	node->session.auth.password_in_length = 0;
	node->session.err_tmo.abort_timeout = DEF_ABORT_TIMEO;
	node->session.err_tmo.lu_reset_timeout = DEF_LU_RESET_TIMEO;
	node->session.err_tmo.tgt_reset_timeout = DEF_TGT_RESET_TIMEO;
	node->session.err_tmo.host_reset_timeout = DEF_HOST_RESET_TIMEO;
	node->session.tmo.replacement_timeout = DEF_REPLACEMENT_TIMEO;
	node->session.se = NULL;
	node->session.sid = 0;
	node->session.multiple = 0;
	node->session.scan = DEF_INITIAL_SCAN;

	default_session_op_cfg(&node->session.op_cfg);

	node->conn.startup = ISCSI_STARTUP_MANUAL;
	node->conn.port = ISCSI_DEFAULT_PORT;
	node->conn.tcp.window_size = TCP_WINDOW_SIZE;
	node->conn.tcp.type_of_service = 0;
	node->conn.tmo.login_timeout= DEF_LOGIN_TIMEO;
	node->conn.tmo.logout_timeout= DEF_LOGOUT_TIMEO;
	node->conn.tmo.auth_timeout = 45;
	node->conn.tmo.noop_out_interval = DEF_NOOP_OUT_INTERVAL;
	node->conn.tmo.noop_out_timeout = DEF_NOOP_OUT_TIMEO;

	default_conn_op_cfg(&node->conn.op_cfg);

	default_iface(&node->iface);
}
