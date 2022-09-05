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

/* The code below is modified from usr/idbm.c which licensed like below:
 *
 * iSCSI Discovery Database Library
 *
 * Copyright (C) 2004 Dmitry Yusupov, Alex Aizman
 * Copyright (C) 2006 Mike Christie
 * Copyright (C) 2006 Red Hat, Inc. All rights reserved.
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
 *
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE			/* For strerror_r() */
#endif

#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <inttypes.h>
#include <limits.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdbool.h>

#include "libopeniscsiusr/libopeniscsiusr_common.h"

#include "context.h"
#include "idbm.h"
#include "misc.h"
#include "idbm_fields.h"
#include "iface.h"
#include "node.h"
#include "default.h"

#define TYPE_INT_O	1
#define TYPE_STR	2
#define TYPE_UINT8	3
#define TYPE_UINT16	4
#define TYPE_UINT32	5
#define TYPE_INT32	6
#define TYPE_INT64	7
#define TYPE_BOOL	8
#define TYPE_INT_LIST	9
#define MAX_KEYS	256   /* number of keys total(including CNX_MAX) */
#define NAME_MAXVAL	128   /* the maximum length of key name */
#define VALUE_MAXVAL	256   /* the maximum length of 223 bytes in the RFC. */
/* ^ MAX_KEYS, NAME_MAXVAL and VALUE_MAXVAL are copied from usr/idbm.h
 * The RFC 3720 only said:
 *	If not otherwise specified, the maximum length of a simple-value (not
 *	its encoded representation) is 255 bytes, not including the delimiter
 *	(comma or zero byte).
 */

#define OPTS_MAXVAL	8

#define IDBM_HIDE	0    /* Hide parameter when print. */
#define IDBM_SHOW	1    /* Show parameter when print. */
#define IDBM_MASKED	2    /* Show "stars" instead of real value when print */

#define ISCSI_BEGIN_REC	"# BEGIN RECORD "ISCSI_VERSION_STR
#define ISCSI_END_REC	"# END RECORD"

#ifndef LOCK_DIR
#define LOCK_DIR		"/run/lock/iscsi"
#endif
#define LOCK_FILE		LOCK_DIR"/lock"
#define LOCK_WRITE_FILE		LOCK_DIR"/lock.write"

#define _rec_str(_key, _recs, _org, _name, _show, _n, _mod) \
do { \
	_recs[_n].type = TYPE_STR; \
	_strncpy(_recs[_n].name, _key, NAME_MAXVAL); \
	if (strlen((char*)_org->_name)) \
		_strncpy((char*)_recs[_n].value, (char*)_org->_name, \
			 VALUE_MAXVAL); \
	_recs[_n].data = &_org->_name; \
	_recs[_n].data_len = sizeof(_org->_name); \
	_recs[_n].visible = _show; \
	_recs[_n].can_modify = _mod; \
	_n++; \
} while(0)

#define _rec_uint8(_key, _recs, _org, _name, _show, _n, _mod) \
do { \
	_recs[_n].type = TYPE_UINT8; \
	_strncpy(_recs[_n].name, _key, NAME_MAXVAL); \
	snprintf(_recs[_n].value, VALUE_MAXVAL, "%" PRIu8, _org->_name); \
	_recs[_n].data = &_org->_name; \
	_recs[_n].data_len = sizeof(_org->_name); \
	_recs[_n].visible = _show; \
	_recs[_n].can_modify = _mod; \
	_n++; \
} while (0)

#define _rec_uint16(_key, _recs, _org, _name, _show, _n, _mod) \
do { \
	_recs[_n].type = TYPE_UINT16; \
	_strncpy(_recs[_n].name, _key, NAME_MAXVAL); \
	snprintf(_recs[_n].value, VALUE_MAXVAL, "%" PRIu16, _org->_name); \
	_recs[_n].data = &_org->_name; \
	_recs[_n].data_len = sizeof(_org->_name); \
	_recs[_n].visible = _show; \
	_recs[_n].can_modify = _mod; \
	_n++; \
} while (0)

#define _rec_uint32(_key, _recs, _org, _name, _show, _n, _mod) \
do { \
	_recs[_n].type = TYPE_UINT32; \
	_strncpy(_recs[_n].name, _key, NAME_MAXVAL); \
	snprintf(_recs[_n].value, VALUE_MAXVAL, "%" PRIu32, _org->_name); \
	_recs[_n].data = &_org->_name; \
	_recs[_n].data_len = sizeof(_org->_name); \
	_recs[_n].visible = _show; \
	_recs[_n].can_modify = _mod; \
	_n++; \
} while (0)

#define _rec_int32(_key, _recs, _org, _name, _show, _n, _mod) \
do { \
	_recs[_n].type = TYPE_INT32; \
	_strncpy(_recs[_n].name, _key, NAME_MAXVAL); \
	snprintf(_recs[_n].value, VALUE_MAXVAL, "%" PRIi32, _org->_name); \
	_recs[_n].data = &_org->_name; \
	_recs[_n].data_len = sizeof(_org->_name); \
	_recs[_n].visible = _show; \
	_recs[_n].can_modify = _mod; \
	_n++; \
} while (0)

#define _rec_int64(_key, _recs, _org, _name, _show, _n, _mod) \
do { \
	_recs[_n].type = TYPE_INT64; \
	_strncpy(_recs[_n].name, _key, NAME_MAXVAL); \
	snprintf(_recs[_n].value, VALUE_MAXVAL, "%" PRIi64, _org->_name); \
	_recs[_n].data = &_org->_name; \
	_recs[_n].data_len = sizeof(_org->_name); \
	_recs[_n].visible = _show; \
	_recs[_n].can_modify = _mod; \
	_n++; \
} while (0)

#define _rec_bool(_key, _recs, _org, _name, _show, _n, _mod) \
do { \
	_recs[_n].type = TYPE_BOOL; \
	_strncpy(_recs[_n].name, _key, NAME_MAXVAL); \
	snprintf(_recs[_n].value, VALUE_MAXVAL, "%s", \
		 _org->_name ? "Yes" : "No"); \
	_recs[_n].data = &_org->_name; \
	_recs[_n].data_len = sizeof(_org->_name); \
	_recs[_n].visible = _show; \
	_recs[_n].can_modify = _mod; \
	_n++; \
} while(0)

#define _rec_int_o2(_key, _recs, _org, _name, _show, _op0, _op1, _n, _mod) \
do { \
	_recs[_n].type = TYPE_INT_O; \
	_strncpy(_recs[_n].name, _key, NAME_MAXVAL); \
	if (_org->_name == 0) _strncpy(_recs[_n].value, _op0, VALUE_MAXVAL); \
	if (_org->_name == 1) _strncpy(_recs[_n].value, _op1, VALUE_MAXVAL); \
	_recs[_n].data = &_org->_name; \
	_recs[_n].data_len = sizeof(_org->_name); \
	_recs[_n].visible = _show; \
	_recs[_n].opts[0] = _op0; \
	_recs[_n].opts[1] = _op1; \
	_recs[_n].numopts = 2; \
	_recs[_n].can_modify = _mod; \
	_n++; \
} while(0)

#define _rec_int_o3(_key, _recs, _org, _name, _show, _op0, _op1, _op2, _n, \
		    _mod) \
do { \
	_rec_int_o2(_key, _recs, _org, _name, _show, _op0, _op1, _n, _mod); \
	_n--; \
	if (_org->_name == 2) _strncpy(_recs[_n].value, _op2, VALUE_MAXVAL);\
	_recs[_n].opts[2] = _op2; \
	_recs[_n].numopts = 3; \
	_n++; \
} while(0)

#define _rec_int_o4(_key, _recs, _org, _name, _show, _op0, _op1, _op2, _op3, \
		    _n, _mod) \
do { \
	_rec_int_o3(_key, _recs, _org, _name, _show, _op0, _op1, _op2, _n, \
		    _mod); \
	_n--; \
	if (_org->_name == 3) _strncpy(_recs[_n].value, _op3, VALUE_MAXVAL);\
	_recs[_n].opts[3] = _op3; \
	_recs[_n].numopts = 4; \
	_n++; \
} while(0)

#define _rec_int_o5(_key, _recs, _org, _name, _show, _op0, _op1, _op2, _op3, \
		    _op4, _n, _mod) \
do { \
	_rec_int_o4(_key, _recs, _org, _name, _show, _op0, _op1, _op2, _op3, \
		    _n, _mod); \
	_n--; \
	if (_org->_name == 4) _strncpy(_recs[_n].value, _op4, VALUE_MAXVAL);\
	_recs[_n].opts[4] = _op4; \
	_recs[_n].numopts = 5; \
	_n++; \
} while(0)

#define _rec_int_o6(_key, _recs, _org, _name, _show, _op0, _op1, _op2, _op3, \
		    _op4, _op5, _n, _mod) \
do { \
	_rec_int_o5(_key, _recs, _org, _name, _show, _op0, _op1, _op2, _op3, \
		    _op4, _n, _mod); \
	_n--; \
	if (_org->_name == 5) _strncpy(_recs[_n].value, _op5, VALUE_MAXVAL);\
	_recs[_n].opts[5] = _op5; \
	_recs[_n].numopts = 6; \
	_n++; \
} while(0)

#define ARRAY_LEN(x) ( sizeof(x) / sizeof((x)[0]) )

/* Options list type, rather than matching a single value this populates an
 * array with a list of values in user specified order.
 * Requires a table matching config strings to values.
 **/
#define _rec_int_list(_key, _recs, _org, _name, _show, _tbl, _n, _mod) \
do {\
	_recs[_n].type = TYPE_INT_LIST; \
	_strncpy(_recs[_n].name, _key, NAME_MAXVAL); \
	for (unsigned int _i = 0; _i < ARRAY_LEN(_org->_name); _i++) { \
		if (_org->_name[_i] != UINT_MAX) { \
			for (unsigned int _j = 0; _j < ARRAY_LEN(_tbl); _j++) { \
				if (_tbl[_j].value == _org->_name[_i]) { \
					strcat(_recs[_n].value, _tbl[_j].name); \
					strcat(_recs[_n].value, ","); \
					break; \
				} \
			} \
		} \
	} \
	/* delete traling ',' */ \
	if (strrchr(_recs[_n].value, ',')) \
		*strrchr(_recs[_n].value, ',') = '\0'; \
	_recs[_n].data = &_org->_name; \
	_recs[_n].data_len = sizeof(_org->_name); \
	_recs[_n].visible = _show; \
	_recs[_n].opts[0] = (void *)&_tbl; \
	_recs[_n].numopts = ARRAY_LEN(_tbl); \
	_recs[_n].can_modify = _mod; \
	_n++; \
} while(0)

enum modify_mode {
	_CANNOT_MODIFY,
	_CAN_MODIFY,
};

struct idbm_rec {
	int			type;
	char			name[NAME_MAXVAL];
	char			value[VALUE_MAXVAL];
	void			*data;
	int			data_len;
	int			visible;
	char*			opts[OPTS_MAXVAL];
	int			numopts;
	/*
	 * TODO: make it a enum that can indicate whether it also requires
	 * a relogin to pick up if a session is running.
	 */
	enum modify_mode	can_modify;
};

static void _idbm_node_rec_link(struct iscsi_node *node, struct idbm_rec *recs, const char *iface_name);

int _idbm_lock(struct iscsi_context *ctx)
{
	int fd, i, ret;
	struct idbm *db = NULL;
	char strerr_buff[_STRERR_BUFF_LEN];
	int errno_save = 0;

	assert(ctx != NULL);

	db = ctx->db;

	if (db->refs > 0) {
		db->refs++;
		return 0;
	}

	if (access(LOCK_DIR, F_OK) != 0) {
		if (mkdir(LOCK_DIR, 0770) != 0) {
			_error(ctx, "Could not open %s: %d %s", LOCK_DIR, errno,
				_strerror(errno, strerr_buff));
			return LIBISCSI_ERR_IDBM;
		}
	}

	fd = open(LOCK_FILE, O_RDWR | O_CREAT, 0666);
	if (fd >= 0)
		close(fd);

	for (i = 0; i < 3000; i++) {
		ret = link(LOCK_FILE, LOCK_WRITE_FILE);
		if (ret == 0)
			break;
		errno_save = errno;

		if (errno != EEXIST) {
			_error(ctx, "Maybe you are not root? "
			       "Could not lock discovery DB: %s: %d %s",
			       LOCK_WRITE_FILE, errno_save,
			       _strerror(errno_save, strerr_buff));
			return LIBISCSI_ERR_IDBM;
		} else if (i == 0)
			_debug(ctx, "Waiting for discovery DB lock on %s",
			       LOCK_WRITE_FILE);

		usleep(10000);
	}

	if (ret != 0) {
		_error(ctx, "Timeout on acquiring lock on DB: %s, errno: %d %s",
		       LOCK_WRITE_FILE, errno_save,
		       _strerror(errno_save, strerr_buff));
		return LIBISCSI_ERR_IDBM;
	}

	db->refs = 1;
	return 0;
}

void _idbm_unlock(struct iscsi_context *ctx)
{
	struct idbm *db = NULL;

	assert(ctx != NULL);

	db = ctx->db;

	if (db->refs > 1) {
		db->refs--;
		return;
	}

	db->refs = 0;
	unlink(LOCK_WRITE_FILE);
}

static struct idbm_rec* _idbm_recs_alloc(void)
{
	return calloc(MAX_KEYS, sizeof(struct idbm_rec));
}

static void _idbm_recs_free(struct idbm_rec* recs)
{
	free(recs);
}

static int _idbm_iface_rec_link(struct iscsi_iface *iface,
				 struct idbm_rec *recs, int num)
{
	int init_num = num;

	if (strstr(iface->name, "ipv6"))
		iface->is_ipv6 = true;

	if (init_num == 0)
		_rec_str(IFACE_ISCSINAME, recs, iface, name, IDBM_SHOW, num,
			 _CANNOT_MODIFY);
	else
		_rec_str(IFACE_ISCSINAME, recs, iface, name, IDBM_SHOW, num,
			 _CAN_MODIFY);
	_rec_str(IFACE_NETNAME, recs, iface, netdev, IDBM_SHOW, num,
		 _CAN_MODIFY);
	_rec_str(IFACE_IPADDR, recs, iface, ipaddress, IDBM_SHOW, num,
		 _CAN_MODIFY);
	_rec_uint8(IFACE_PREFIX_LEN, recs, iface, prefix_len, IDBM_SHOW, num,
		_CAN_MODIFY);
	_rec_str(IFACE_HWADDR, recs, iface, hwaddress, IDBM_SHOW, num,
		 _CAN_MODIFY);
	_rec_str(IFACE_TRANSPORTNAME, recs, iface, transport_name, IDBM_SHOW,
		 num, _CAN_MODIFY);
	_rec_str(IFACE_INAME, recs, iface, iname, IDBM_SHOW, num, _CAN_MODIFY);
	_rec_str(IFACE_STATE, recs, iface, state, IDBM_SHOW, num, _CAN_MODIFY);
	_rec_uint16(IFACE_VLAN_ID, recs, iface, vlan_id, IDBM_SHOW, num,
		    _CAN_MODIFY);
	_rec_uint8(IFACE_VLAN_PRIORITY, recs, iface, vlan_priority, IDBM_SHOW,
		   num, _CAN_MODIFY);
	_rec_str(IFACE_VLAN_STATE, recs, iface, vlan_state, IDBM_SHOW, num,
		 _CAN_MODIFY);
	_rec_uint32(IFACE_NUM, recs, iface, iface_num, IDBM_SHOW, num,
		    _CAN_MODIFY);
	_rec_uint16(IFACE_MTU, recs, iface, mtu, IDBM_SHOW, num, _CAN_MODIFY);
	_rec_uint16(IFACE_PORT, recs, iface, port, IDBM_SHOW, num, _CAN_MODIFY);

	if (! iface->is_ipv6) {
		_rec_str(IFACE_BOOT_PROTO, recs, iface, bootproto, IDBM_SHOW,
			 num, _CAN_MODIFY);
		_rec_str(IFACE_SUBNET_MASK, recs, iface, subnet_mask, IDBM_SHOW,
			 num, _CAN_MODIFY);
		_rec_str(IFACE_GATEWAY, recs, iface, gateway, IDBM_SHOW, num,
			 _CAN_MODIFY);
		_rec_str(IFACE_DHCP_ALT_CID, recs, iface,
			 dhcp_alt_client_id_state, IDBM_SHOW, num, _CAN_MODIFY);
		_rec_str(IFACE_DHCP_ALT_CID_STR, recs, iface,
			 dhcp_alt_client_id, IDBM_SHOW, num, _CAN_MODIFY);
		_rec_str(IFACE_DHCP_DNS, recs, iface, dhcp_dns, IDBM_SHOW, num,
			 _CAN_MODIFY);
		_rec_str(IFACE_DHCP_LEARN_IQN, recs, iface, dhcp_learn_iqn,
			 IDBM_SHOW, num, _CAN_MODIFY);
		_rec_str(IFACE_DHCP_REQ_VID, recs, iface,
			 dhcp_req_vendor_id_state, IDBM_SHOW, num, _CAN_MODIFY);
		_rec_str(IFACE_DHCP_VID, recs, iface, dhcp_vendor_id_state,
			 IDBM_SHOW, num, _CAN_MODIFY);
		_rec_str(IFACE_DHCP_VID_STR, recs, iface, dhcp_vendor_id,
			 IDBM_SHOW, num, _CAN_MODIFY);
		_rec_str(IFACE_DHCP_SLP_DA, recs, iface, dhcp_slp_da, IDBM_SHOW,
			 num, _CAN_MODIFY);
		_rec_str(IFACE_FRAGMENTATION, recs, iface, fragmentation,
			 IDBM_SHOW, num, _CAN_MODIFY);
		_rec_str(IFACE_GRAT_ARP, recs, iface, gratuitous_arp, IDBM_SHOW,
			 num, _CAN_MODIFY);
		_rec_str(IFACE_IN_FORWARD, recs, iface, incoming_forwarding,
			 IDBM_SHOW, num, _CAN_MODIFY);
		_rec_str(IFACE_TOS_STATE, recs, iface, tos_state, IDBM_SHOW,
			 num, _CAN_MODIFY);
		_rec_uint8(IFACE_TOS, recs, iface, tos, IDBM_SHOW, num,
			   _CAN_MODIFY);
		_rec_uint8(IFACE_TTL, recs, iface, ttl, IDBM_SHOW, num,
			   _CAN_MODIFY);
	} else {
		_rec_str(IFACE_IPV6_AUTOCFG, recs, iface, ipv6_autocfg,
			 IDBM_SHOW, num, _CAN_MODIFY);
		_rec_str(IFACE_LINKLOCAL_AUTOCFG, recs, iface,
			 linklocal_autocfg, IDBM_SHOW, num, _CAN_MODIFY);
		_rec_str(IFACE_ROUTER_AUTOCFG, recs, iface, router_autocfg,
			 IDBM_SHOW, num, _CAN_MODIFY);
		_rec_str(IFACE_LINKLOCAL, recs, iface, ipv6_linklocal,
			 IDBM_SHOW, num, _CAN_MODIFY);
		_rec_str(IFACE_ROUTER, recs, iface, ipv6_router, IDBM_SHOW, num,
			 _CAN_MODIFY);
		_rec_uint8(IFACE_DUP_ADDR_DETECT_CNT, recs, iface,
			   dup_addr_detect_cnt, IDBM_SHOW, num, _CAN_MODIFY);
		_rec_uint32(IFACE_FLOW_LABEL, recs, iface, flow_label,
			    IDBM_SHOW, num, _CAN_MODIFY);
		_rec_str(IFACE_GRAT_NEIGHBOR_ADV, recs, iface,
			 gratuitous_neighbor_adv, IDBM_SHOW, num, _CAN_MODIFY);
		_rec_uint8(IFACE_HOP_LIMIT, recs, iface, hop_limit, IDBM_SHOW,
			   num, _CAN_MODIFY);
		_rec_str(IFACE_MLD, recs, iface, mld, IDBM_SHOW, num,
			 _CAN_MODIFY);
		_rec_uint32(IFACE_ND_REACHABLE_TMO, recs, iface,
			    nd_reachable_tmo, IDBM_SHOW, num, _CAN_MODIFY);
		_rec_uint32(IFACE_ND_REXMIT_TIME, recs, iface, nd_rexmit_time,
			    IDBM_SHOW, num, _CAN_MODIFY);
		_rec_uint32(IFACE_ND_STALE_TMO, recs, iface, nd_stale_tmo,
			    IDBM_SHOW, num, _CAN_MODIFY);
		_rec_uint32(IFACE_RTR_ADV_LINK_MTU, recs, iface,
			    router_adv_link_mtu, IDBM_SHOW, num, _CAN_MODIFY);
		_rec_uint8(IFACE_TRAFFIC_CLASS, recs, iface, traffic_class,
			   IDBM_SHOW, num, _CAN_MODIFY);
	}

	_rec_str(IFACE_DELAYED_ACK, recs, iface, delayed_ack, IDBM_SHOW, num,
		 _CAN_MODIFY);
	_rec_str(IFACE_TCP_NAGLE, recs, iface, nagle, IDBM_SHOW, num,
		 _CAN_MODIFY);
	_rec_str(IFACE_TCP_WSF_STATE, recs, iface, tcp_wsf_state, IDBM_SHOW,
		 num, _CAN_MODIFY);
	_rec_uint8(IFACE_TCP_WSF, recs, iface, tcp_wsf, IDBM_SHOW, num,
		   _CAN_MODIFY);
	_rec_uint8(IFACE_TCP_TIMER_SCALE, recs, iface, tcp_timer_scale,
		   IDBM_SHOW, num, _CAN_MODIFY);
	_rec_str(IFACE_TCP_TIMESTAMP, recs, iface, tcp_timestamp, IDBM_SHOW,
		 num, _CAN_MODIFY);
	_rec_str(IFACE_REDIRECT, recs, iface, redirect, IDBM_SHOW, num,
		 _CAN_MODIFY);
	_rec_uint16(IFACE_DEF_TMF_TMO, recs, iface, def_task_mgmt_tmo,
		    IDBM_SHOW, num, _CAN_MODIFY);
	_rec_str(IFACE_HDRDGST, recs, iface, header_digest, IDBM_SHOW, num,
		 _CAN_MODIFY);
	_rec_str(IFACE_DATADGST, recs, iface, data_digest, IDBM_SHOW, num,
		 _CAN_MODIFY);
	_rec_str(IFACE_IMM_DATA, recs, iface, immediate_data, IDBM_SHOW, num,
		 _CAN_MODIFY);
	_rec_str(IFACE_INITIAL_R2T, recs, iface, initial_r2t, IDBM_SHOW, num,
		 _CAN_MODIFY);
	_rec_str(IFACE_DSEQ_INORDER, recs, iface, data_seq_inorder, IDBM_SHOW,
		 num, _CAN_MODIFY);
	_rec_str(IFACE_DPDU_INORDER, recs, iface, data_pdu_inorder, IDBM_SHOW,
		 num, _CAN_MODIFY);
	_rec_uint8(IFACE_ERL, recs, iface, erl, IDBM_SHOW, num, _CAN_MODIFY);
	_rec_uint32(IFACE_MAX_RECV_DLEN, recs, iface, max_recv_dlength,
		    IDBM_SHOW, num, _CAN_MODIFY);
	_rec_uint32(IFACE_FIRST_BURST, recs, iface, first_burst_len, IDBM_SHOW,
		    num, _CAN_MODIFY);
	_rec_uint16(IFACE_MAX_R2T, recs, iface, max_out_r2t, IDBM_SHOW, num,
		    _CAN_MODIFY);
	_rec_uint32(IFACE_MAX_BURST, recs, iface, max_burst_len, IDBM_SHOW, num,
		    _CAN_MODIFY);
	_rec_str(IFACE_CHAP_AUTH, recs, iface, chap_auth, IDBM_SHOW, num,
		 _CAN_MODIFY);
	_rec_str(IFACE_BIDI_CHAP, recs, iface, bidi_chap, IDBM_SHOW, num,
		 _CAN_MODIFY);
	_rec_str(IFACE_STRICT_LOGIN_COMP, recs, iface, strict_login_comp,
		 IDBM_SHOW, num, _CAN_MODIFY);
	_rec_str(IFACE_DISCOVERY_AUTH, recs, iface, discovery_auth, IDBM_SHOW,
		 num, _CAN_MODIFY);
	_rec_str(IFACE_DISCOVERY_LOGOUT, recs, iface, discovery_logout,
		 IDBM_SHOW, num, _CAN_MODIFY);
	return num;
}

static void _idbm_recs_print(struct idbm_rec *recs, FILE *f, int show)
{
	int i;
	fprintf(f, "%s\n", ISCSI_BEGIN_REC);
	for (i = 0; i < MAX_KEYS; i++) {
		if (recs[i].visible == IDBM_HIDE)
			continue;
		if (show == IDBM_MASKED && recs[i].visible == IDBM_MASKED) {
			if (*(char*)recs[i].data) {
				fprintf(f, "%s = ********\n", recs[i].name);
				continue;
			}
			/* fall through */
		}

		if (strlen(recs[i].value))
			fprintf(f, "%s = %s\n", recs[i].name, recs[i].value);
		else if (f == stdout)
			fprintf(f, "%s = <empty>\n", recs[i].name);
	}
	fprintf(f, "%s\n", ISCSI_END_REC);
}

void _idbm_iface_print(struct iscsi_iface *iface, FILE *f)
{
	struct idbm_rec *recs = NULL;

	recs = _idbm_recs_alloc();
	if (recs == NULL)
		return;

	_idbm_iface_rec_link(iface, recs, 0);

	_idbm_recs_print(recs, f, IDBM_SHOW);

	_idbm_recs_free(recs);
}

void _idbm_node_print(struct iscsi_node *node, FILE *f, bool show_secret)
{
	struct idbm_rec *recs = NULL;

	recs = _idbm_recs_alloc();
	if (recs == NULL)
		return;

	_idbm_node_rec_link(node, recs, NULL);
	_idbm_recs_print(recs, f, show_secret ? IDBM_SHOW : IDBM_MASKED);
	_idbm_recs_free(recs);
}

struct int_list_tbl {
	const char *name;
	unsigned int value;
};

static int _idbm_rec_update_param(struct iscsi_context *ctx,
				  struct idbm_rec *recs, char *name,
				  char *value, int line_number)
{
	int rc = LIBISCSI_OK;
	int i = 0;
	int j = 0;
	int k = 0;
	int passwd_done = 0;
	char passwd_len[8];
	struct int_list_tbl *tbl = NULL;
	char *tmp_value, *orig_tmp_value;
	int *tmp_data;
	bool *found;
	char *token;

	assert(ctx != NULL);
	assert(recs != NULL);
	assert(name != NULL);
	assert(value != NULL);

setup_passwd_len:
	for (i = 0; i < MAX_KEYS; ++i) {
		if (!strcmp(name, recs[i].name)) {
			_debug(ctx, "updated '%s', '%s' => '%s'", name,
			       recs[i].value, value);
			/* parse recinfo by type */
			switch (recs[i].type) {
			case TYPE_UINT8:
				if (!recs[i].data)
					continue;

				*(uint8_t *)recs[i].data =
					strtoul(value, NULL, 10);
				goto updated;
			case TYPE_UINT16:
				if (!recs[i].data)
					continue;

				*(uint16_t *)recs[i].data =
					strtoul(value, NULL, 10);
				goto updated;
			case TYPE_UINT32:
				if (!recs[i].data)
					continue;

				*(uint32_t *)recs[i].data =
					strtoul(value, NULL, 10);
				goto updated;
			case TYPE_STR:
				if (!recs[i].data)
					continue;

				_strncpy((char*)recs[i].data,
					 value, recs[i].data_len);
				goto updated;
			case TYPE_INT32:
				if (!recs[i].data)
					continue;

				*(int32_t *)recs[i].data =
					strtoul(value, NULL, 10);
				goto updated;
			case TYPE_INT64:
				if (!recs[i].data)
					continue;

				*(int64_t *)recs[i].data =
					strtoull(value, NULL, 10);
				goto updated;
			case TYPE_INT_O:
				for (j = 0; j < recs[i].numopts; ++j) {
					if (!strcmp(value, recs[i].opts[j])) {
						if (!recs[i].data)
							continue;

						*(int*)recs[i].data = j;
						goto updated;
					}
				}
				goto unknown_value;
			case TYPE_BOOL:
				if (!recs[i].data)
					continue;
				if (strcmp(value, "Yes") == 0)
					*(bool *)recs[i].data = true;
				else if (strcmp(value, "No") == 0)
					*(bool *)recs[i].data = false;
				else
					goto unknown_value;
				goto updated;
			case TYPE_INT_LIST:
				if (!recs[i].data)
					continue;
				tbl = (void *)recs[i].opts[0];
				/* strsep is destructive, make a copy to work with */
				orig_tmp_value = tmp_value = strdup(value);
				k = 0;
				tmp_data = malloc(recs[i].data_len);
				memset(tmp_data, ~0, recs[i].data_len);
				found = calloc(recs[i].numopts, sizeof(bool));
next_token:			while ((token = strsep(&tmp_value, ", \n"))) {
					if (!strlen(token))
						continue;
					if ((k * (int)sizeof(int)) >= (recs[i].data_len)) {
						_warn(ctx, "Too many values set for '%s'"
						      ", continuing without processing them all",
						      recs[i].name);
						break;
					}
					for (j = 0; j < recs[i].numopts; j++) {
						if (!strcmp(token, tbl[j].name)) {
							if ((found[j])) {
								_warn(ctx, "Ignoring repeated value '%s'"
								      " for '%s'", token, recs[i].name);
								goto next_token;
							}
							((unsigned *)tmp_data)[k++] = tbl[j].value;
							found[j] = true;
							goto next_token;
						}
					}
					_warn(ctx, "Ignoring unknown value '%s'"
					      " for '%s'", token, recs[i].name);
				}
				free(found);
				found = NULL;
				free(orig_tmp_value);
				orig_tmp_value = NULL;
				memcpy(recs[i].data, tmp_data, recs[i].data_len);
				free(tmp_data);
				tmp_data = NULL;
				token = NULL;
				goto updated;
			default:
unknown_value:
				_error(ctx, "Got unknown data type %d "
				       "for name '%s', value '%s'",
				       recs[i].data, recs[i].name,
				       recs[i].value);
				rc = LIBISCSI_ERR_BUG;
				goto out;
			}
			if (line_number) {
				_warn(ctx, "config file line %d contains "
					   "unknown value format '%s' for "
					   "parameter name '%s'",
					   line_number, value, name);
			} else {
				_error(ctx, "unknown value format '%s' for "
				       "parameter name '%s'", value, name);
				rc = LIBISCSI_ERR_INVAL;
			}
			goto out;
		}
	}
	_error(ctx, "Unknown parameter name %s", name);
	rc = LIBISCSI_ERR_INVAL;
	goto out;

updated:
	_strncpy((char*)recs[i].value, value, VALUE_MAXVAL);

#define check_password_param(_param) \
	if (!passwd_done && !strcmp(#_param, name)) { \
		passwd_done = 1; \
		name = #_param "_length"; \
		snprintf(passwd_len, 8, "%.7d", (int)strlen(value) & 0xffff); \
		value = passwd_len; \
		goto setup_passwd_len; \
	}

	check_password_param(node.session.auth.password);
	check_password_param(node.session.auth.password_in);
	check_password_param(discovery.sendtargets.auth.password);
	check_password_param(discovery.sendtargets.auth.password_in);
	check_password_param(discovery.slp.auth.password);
	check_password_param(discovery.slp.auth.password_in);
	check_password_param(host.auth.password);
	check_password_param(host.auth.password_in);

out:
	return rc;
}

/*
 * from linux kernel
 */
static char *strstrip(char *s)
{
	size_t size;
	char *end;

	size = strlen(s);
	if (!size)
		return s;

	end = s + size - 1;
	while (end >= s && isspace(*end))
		end--;
	*(end + 1) = '\0';

	while (*s && isspace(*s))
		s++;

	return s;
}

static int _idbm_recs_read(struct iscsi_context *ctx, struct idbm_rec *recs,
			   const char *conf_path)
{
	int rc = LIBISCSI_OK;
	char name[NAME_MAXVAL];
	char value[VALUE_MAXVAL];
	char *line = NULL;
	char *nl = NULL;
	char buffer[2048];
	int line_number = 0;
	int c = 0;
	int i = 0;
	FILE *f = NULL;
	int errno_save = 0;
	char strerr_buff[_STRERR_BUFF_LEN];

	assert(ctx != NULL);
	assert(recs != NULL);
	assert(conf_path != NULL);

	f = fopen(conf_path, "r");
	errno_save = errno;
	if (!f) {
		_error(ctx, "Failed to open %s using read mode: %d %s",
		       conf_path, errno_save,
		       _strerror(errno_save, strerr_buff));
		rc = LIBISCSI_ERR_IDBM;
		goto out;
	}

	_info(ctx, "Parsing iSCSI interface configuration %s", conf_path);
	/* process the config file */
	do {
		line = fgets(buffer, sizeof (buffer), f);
		line_number++;
		if (!line)
			continue;
		if (strlen(line) == 0)
			continue;

		nl = line + strlen(line) - 1;
		if (*nl != '\n') {
			_warn(ctx, "Config file %s line %d too long.",
			      conf_path, line_number);
			continue;
		}

		line = strstrip(line);
		/* process any non-empty, non-comment lines */
		if (!*line || *line == '\0' || *line ==  '\n' || *line == '#')
			continue;

		/* parse name */
		i=0; nl = line; *name = 0;
		while (*nl && !isspace(c = *nl) && *nl != '=') {
			*(name+i) = *nl; i++; nl++;
		}
		if (!*nl) {
			_warn(ctx, "config file %s line %d do not has value",
			      conf_path, line_number);
			continue;
		}
		*(name+i)=0; nl++;
		/* skip after-name traling spaces */
		while (*nl && isspace(c = *nl)) nl++;
		if (*nl && *nl != '=') {
			_warn(ctx, "config file %s line %d has not '=' "
			      "separator", conf_path, line_number);
			continue;
		}
		/* skip '=' sepa */
		nl++;
		/* skip after-sepa traling spaces */
		while (*nl && isspace(c = *nl)) nl++;
		if (!*nl) {
			_warn(ctx, "config file %s line %d do not has value",
			      conf_path, line_number);
			continue;
		}
		/* parse value */
		i=0; *value = 0;
		while (*nl) {
			*(value+i) = *nl; i++; nl++;
		}
		*(value+i) = 0;

		rc = _idbm_rec_update_param(ctx, recs, name, value,
					    line_number);
		if (rc == LIBISCSI_ERR_INVAL) {
			_error(ctx, "config file %s invalid.", conf_path);
			goto out;
		} else if (rc != LIBISCSI_OK)
		      goto out;
	} while (line);

out:
	if (f != NULL)
		fclose(f);
	return rc;
}

int _idbm_iface_get(struct iscsi_context *ctx, const char *iface_name, struct
		    iscsi_iface **iface)
{
	int rc = LIBISCSI_OK;
	char *conf_path = NULL;
	struct idbm_rec *recs = NULL;

	assert(iface != NULL);
	assert(ctx != NULL);

	*iface = NULL;

	if (iface_name == NULL)
		goto out;

	if (strcmp(iface_name, "iface.example") == 0)
		goto out;

	_good(_asprintf(&conf_path, "%s/%s", IFACE_CONFIG_DIR, iface_name),
	      rc, out);

	*iface = calloc(1, sizeof(struct iscsi_iface));
	_alloc_null_check(ctx, *iface, rc, out);

	snprintf((*iface)->name, sizeof((*iface)->name)/sizeof(char),
		 "%s", iface_name);

	if (strstr(iface_name, "ipv6"))
		(*iface)->is_ipv6 = true;

	recs = _idbm_recs_alloc();
	_alloc_null_check(ctx, recs, rc, out);

	_idbm_iface_rec_link(*iface, recs, 0);

	_good(_idbm_recs_read(ctx, recs, conf_path), rc, out);

	if (! _iface_is_valid(*iface)) {
		_warn(ctx, "'%s' is not a valid iSCSI interface configuration "
		      "file", conf_path);
		iscsi_iface_free(*iface);
		*iface = NULL;
		/* We still treat this as pass(no error) */
	}

out:
	if (rc != LIBISCSI_OK) {
		iscsi_iface_free(*iface);
		*iface = NULL;
	}
	free(conf_path);
	_idbm_recs_free(recs);
	return rc;
}
struct idbm *_idbm_new(void)
{
	return calloc(1, sizeof(struct idbm));
}

void _idbm_free(struct idbm *db)
{
	free(db);
}

static struct int_list_tbl chap_algs[] = {
	{ "MD5", ISCSI_AUTH_CHAP_ALG_MD5 },
	{ "SHA1", ISCSI_AUTH_CHAP_ALG_SHA1 },
	{ "SHA256", ISCSI_AUTH_CHAP_ALG_SHA256 },
	{ "SHA3-256", ISCSI_AUTH_CHAP_ALG_SHA3_256 },
};

static void _idbm_node_rec_link(struct iscsi_node *node, struct idbm_rec *recs, const char *iface_name)
{
	int num = 0;

	_rec_str(NODE_NAME, recs, node, target_name, IDBM_SHOW, num,
		 _CANNOT_MODIFY);
	_rec_int32(NODE_TPGT, recs, node, tpgt, IDBM_SHOW, num,
		   _CANNOT_MODIFY);
	_rec_int_o3(NODE_STARTUP, recs, node, startup, IDBM_SHOW, "manual",
		    "automatic", "onboot", num, _CAN_MODIFY);
	_rec_bool(NODE_LEADING_LOGIN, recs, node, leading_login, IDBM_SHOW,
		  num, _CAN_MODIFY);

	/* use the interface name passed in, if any */
	if (iface_name)
		strncpy((*node).iface.name, iface_name, ISCSI_MAX_IFACE_LEN-1);

	/*
	 * Note: because we do not add the iface.iscsi_ifacename to
	 * sysfs iscsiadm does some weird matching. We can change the iface
	 * values if a session is not running, but node record ifaces values
	 * have to be changed and so do the iface record ones.
	 *
	 * Users should normally not want to change the iface ones
	 * in the node record directly and instead do it through
	 * the iface mode which will do the right thing (although that
	 * needs some locking).
	 */
	num = _idbm_iface_rec_link(&((*node).iface), recs, num);

	_rec_str(NODE_DISC_ADDR, recs, node, disc_address, IDBM_SHOW, num,
		 _CANNOT_MODIFY);
	_rec_int32(NODE_DISC_PORT, recs, node, disc_port, IDBM_SHOW, num,
		   _CANNOT_MODIFY);
	_rec_int_o6(NODE_DISC_TYPE, recs, node, disc_type, IDBM_SHOW,
		    "send_targets", "isns", "offload_send_targets", "slp",
		    "static", "fw", num, _CANNOT_MODIFY);

	_rec_uint32(SESSION_INIT_CMDSN, recs, node, session.initial_cmdsn,
		    IDBM_SHOW, num,_CAN_MODIFY);
	_rec_int64(SESSION_INIT_LOGIN_RETRY, recs, node,
		   session.initial_login_retry_max, IDBM_SHOW, num,
		   _CAN_MODIFY);
	_rec_int64(SESSION_XMIT_THREAD_PRIORITY, recs, node,
		   session.xmit_thread_priority, IDBM_SHOW, num, _CAN_MODIFY);
	_rec_uint16(SESSION_CMDS_MAX, recs, node, session.cmds_max, IDBM_SHOW,
		    num, _CAN_MODIFY);
	_rec_uint16(SESSION_QDEPTH, recs, node, session.queue_depth, IDBM_SHOW,
		    num, _CAN_MODIFY);
	_rec_int64(SESSION_NR_SESSIONS, recs, node, session.nr_sessions,
		   IDBM_SHOW, num, _CAN_MODIFY);
	_rec_int_o2(SESSION_AUTH_METHOD, recs, node, session.auth.authmethod,
		    IDBM_SHOW, "None", "CHAP", num, _CAN_MODIFY);
	_rec_str(SESSION_USERNAME, recs, node, session.auth.username, IDBM_SHOW,
		 num, _CAN_MODIFY);
	_rec_str(SESSION_PASSWORD, recs, node, session.auth.password,
		 IDBM_MASKED, num, _CAN_MODIFY);
	_rec_uint32(SESSION_PASSWORD_LEN, recs, node,
		    session.auth.password_length, IDBM_HIDE, num, _CAN_MODIFY);
	_rec_str(SESSION_USERNAME_IN, recs, node, session.auth.username_in,
		 IDBM_SHOW, num, _CAN_MODIFY);
	_rec_str(SESSION_PASSWORD_IN, recs, node, session.auth.password_in,
		 IDBM_MASKED, num, _CAN_MODIFY);
	_rec_uint32(SESSION_PASSWORD_IN_LEN, recs, node,
		    session.auth.password_in_length, IDBM_HIDE, num,
		    _CAN_MODIFY);
	_rec_int_list(SESSION_CHAP_ALGS, recs, node, session.auth.chap_algs,
		IDBM_SHOW, chap_algs, num, _CAN_MODIFY);
	_rec_int64(SESSION_REPLACEMENT_TMO, recs, node,
		   session.tmo.replacement_timeout, IDBM_SHOW, num,
		   _CAN_MODIFY);
	_rec_int64(SESSION_ABORT_TMO, recs, node, session.err_tmo.abort_timeout,
		   IDBM_SHOW, num, _CAN_MODIFY);
	_rec_int64(SESSION_LU_RESET_TMO, recs, node,
		   session.err_tmo.lu_reset_timeout, IDBM_SHOW, num,
		   _CAN_MODIFY);
	_rec_int64(SESSION_TGT_RESET_TMO, recs, node,
		   session.err_tmo.tgt_reset_timeout, IDBM_SHOW, num,
		   _CAN_MODIFY);
	_rec_int64(SESSION_HOST_RESET_TMO, recs, node,
		   session.err_tmo.host_reset_timeout, IDBM_SHOW, num,
		   _CAN_MODIFY);
	_rec_bool(SESSION_FAST_ABORT, recs, node, session.op_cfg.FastAbort,
		  IDBM_SHOW, num, _CAN_MODIFY);
	_rec_bool(SESSION_INITIAL_R2T, recs, node, session.op_cfg.InitialR2T,
		  IDBM_SHOW, num, _CAN_MODIFY);
	_rec_bool(SESSION_IMM_DATA, recs, node, session.op_cfg.ImmediateData,
		  IDBM_SHOW, num, _CAN_MODIFY);
	_rec_int64(SESSION_FIRST_BURST, recs, node,
		   session.op_cfg.FirstBurstLength, IDBM_SHOW, num,
		   _CAN_MODIFY);
	_rec_int64(SESSION_MAX_BURST, recs, node, session.op_cfg.MaxBurstLength,
		   IDBM_SHOW, num, _CAN_MODIFY);
	_rec_int64(SESSION_DEF_TIME2RETAIN, recs, node,
		   session.op_cfg.DefaultTime2Retain, IDBM_SHOW, num,
		   _CAN_MODIFY);
	_rec_int64(SESSION_DEF_TIME2WAIT, recs, node,
		   session.op_cfg.DefaultTime2Wait, IDBM_SHOW, num,
		   _CAN_MODIFY);
	_rec_int64(SESSION_MAX_CONNS, recs, node, session.op_cfg.MaxConnections,
		   IDBM_SHOW, num, _CAN_MODIFY);
	_rec_int64(SESSION_MAX_R2T, recs, node,
		   session.op_cfg.MaxOutstandingR2T, IDBM_SHOW, num,
		   _CAN_MODIFY);
	_rec_int64(SESSION_ERL, recs, node, session.op_cfg.ERL, IDBM_SHOW, num,
		   _CAN_MODIFY);
	_rec_int_o2(SESSION_SCAN, recs, node, session.scan, IDBM_SHOW, "manual",
		    "auto", num, _CAN_MODIFY);
	_rec_int64(SESSION_REOPEN_MAX, recs, node, session.reopen_max, IDBM_SHOW, num,
		   _CAN_MODIFY);

	_rec_str(CONN_ADDR, recs, node, conn.address, IDBM_SHOW, num,
		 _CANNOT_MODIFY);
	_rec_int32(CONN_PORT, recs, node, conn.port, IDBM_SHOW, num,
		   _CANNOT_MODIFY);
	_rec_int_o3(CONN_STARTUP, recs, node, conn.startup, IDBM_SHOW,
		    "manual", "automatic", "onboot", num, _CAN_MODIFY);
	_rec_int64(CONN_WINDOW_SIZE, recs, node, conn.tcp.window_size,
		   IDBM_SHOW, num, _CAN_MODIFY);
	_rec_int64(CONN_SERVICE_TYPE, recs, node, conn.tcp.type_of_service,
		   IDBM_SHOW, num, _CAN_MODIFY);
	_rec_int64(CONN_LOGOUT_TMO, recs, node, conn.tmo.logout_timeout,
		   IDBM_SHOW, num, _CAN_MODIFY);
	_rec_int64(CONN_LOGIN_TMO, recs, node, conn.tmo.login_timeout,
		   IDBM_SHOW, num, _CAN_MODIFY);
	_rec_int64(CONN_AUTH_TMO, recs, node, conn.tmo.auth_timeout,
		   IDBM_SHOW, num, _CAN_MODIFY);
	_rec_int64(CONN_NOP_INT, recs, node, conn.tmo.noop_out_interval,
		   IDBM_SHOW, num, _CAN_MODIFY);
	_rec_int64(CONN_NOP_TMO, recs, node, conn.tmo.noop_out_timeout,
		   IDBM_SHOW, num, _CAN_MODIFY);
	_rec_int64(CONN_MAX_XMIT_DLEN, recs, node,
		   conn.op_cfg.MaxXmitDataSegmentLength, IDBM_SHOW,
		   num, _CAN_MODIFY);
	_rec_int64(CONN_MAX_RECV_DLEN, recs, node,
		   conn.op_cfg.MaxRecvDataSegmentLength, IDBM_SHOW,
		   num, _CAN_MODIFY);
	_rec_int_o4(CONN_HDR_DIGEST, recs, node, conn.op_cfg.HeaderDigest,
		    IDBM_SHOW, "None", "CRC32C", "CRC32C,None",
		    "None,CRC32C", num, _CAN_MODIFY);
	_rec_int_o4(CONN_DATA_DIGEST, recs, node, conn.op_cfg.DataDigest,
		    IDBM_SHOW, "None", "CRC32C", "CRC32C,None",
		    "None,CRC32C", num, _CAN_MODIFY);
	_rec_bool(CONN_IFMARKER, recs, node, conn.op_cfg.IFMarker, IDBM_SHOW,
		  num, _CAN_MODIFY);
	_rec_bool(CONN_OFMARKER, recs, node, conn.op_cfg.OFMarker, IDBM_SHOW,
		  num, _CAN_MODIFY);
}

int _idbm_node_get(struct iscsi_context *ctx, const char *target_name,
		   const char *portal, const char *iface_name,
		   struct iscsi_node **node)
{
	int rc = LIBISCSI_OK;
	char *conf_path = NULL;
	struct idbm_rec *recs = NULL;

	assert(node != NULL);
	assert(ctx != NULL);

	*node = NULL;

	if ((target_name == NULL) || (portal == NULL))
		goto out;

	if (iface_name == NULL)			// old style of config
		_good(_asprintf(&conf_path, "%s/%s/%s", NODE_CONFIG_DIR,
			 target_name, portal), rc, out);
	else
		_good(_asprintf(&conf_path, "%s/%s/%s/%s", NODE_CONFIG_DIR,
			 target_name, portal, iface_name), rc, out);

	*node = calloc(1, sizeof(struct iscsi_node));
	_alloc_null_check(ctx, *node, rc, out);

	_default_node(*node);

	recs = _idbm_recs_alloc();
	_alloc_null_check(ctx, recs, rc, out);

	_idbm_node_rec_link(*node, recs, iface_name);

	_good(_idbm_recs_read(ctx, recs, conf_path), rc, out);

	if (! _iface_is_valid(&((*node)->iface))) {
		_warn(ctx, "'%s' has invalid iSCSI interface configuration",
		      conf_path);
		iscsi_node_free(*node);
		*node = NULL;
		/* We still treat this as pass(no error) */
		goto out;
	}

	// Add extra properties
	if (strchr((*node)->conn.address, '.')) {
		(*node)->conn.is_ipv6 = false;
		snprintf((*node)->portal, sizeof((*node)->portal)/sizeof(char),
			 "%s:%" PRIi32, (*node)->conn.address,
			 (*node)->conn.port);

	} else {
		(*node)->conn.is_ipv6 = true;
		snprintf((*node)->portal, sizeof((*node)->portal)/sizeof(char),
			 "[%s]:%" PRIi32, (*node)->conn.address,
			 (*node)->conn.port);
	}

out:
	if (rc != LIBISCSI_OK) {
		iscsi_node_free(*node);
		*node = NULL;
	}
	free(conf_path);
	_idbm_recs_free(recs);
	return rc;
}
