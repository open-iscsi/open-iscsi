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

#include "libopeniscsiusr/libopeniscsiusr_common.h"

#include "context.h"
#include "idbm.h"
#include "misc.h"
#include "idbm_fields.h"
#include "iface.h"
#include "version.h"

#define TYPE_STR	2
#define TYPE_UINT8	3
#define TYPE_UINT16	4
#define TYPE_UINT32	5
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
#define LOCK_DIR		"/var/lock/iscsi"
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
	/*
	 * TODO: make it a enum that can indicate whether it also requires
	 * a relogin to pick up if a session is running.
	 */
	enum modify_mode	can_modify;
};

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
		if (mkdir(LOCK_DIR, 0660) != 0) {
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

static void _idbm_iface_rec_link(struct iscsi_iface *iface,
				 struct idbm_rec *recs)
{
	int num = 0;

	_rec_str(IFACE_ISCSINAME, recs, iface, name, IDBM_SHOW, num,
		 _CANNOT_MODIFY);
	_rec_str(IFACE_NETNAME, recs, iface, netdev, IDBM_SHOW, num,
		 _CAN_MODIFY);
	_rec_str(IFACE_IPADDR, recs, iface, ipaddress, IDBM_SHOW, num,
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
}

static void _idbm_recs_print(struct idbm_rec *recs, FILE *f, int show)
{
	int i;
	fprintf(f, "%s\n", ISCSI_BEGIN_REC);
	for (i = 0; i < MAX_KEYS; i++) {
		if (recs[i].visible == IDBM_HIDE)
			continue;
		if (!show && recs[i].visible == IDBM_MASKED) {
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

	_idbm_iface_rec_link(iface, recs);

	_idbm_recs_print(recs, f, IDBM_SHOW);

	_idbm_recs_free(recs);
}

static int _idbm_rec_update_param(struct iscsi_context *ctx,
				  struct idbm_rec *recs, char *name,
				  char *value, int line_number)
{
	int rc = LIBISCSI_OK;
	int i = 0;
	int passwd_done = 0;
	char passwd_len[8];

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
			default:
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
		snprintf(passwd_len, 8, "%d", (int)strlen(value)); \
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
	char conf_path[PATH_MAX];
	struct idbm_rec *recs = NULL;

	assert(iface != NULL);
	assert(ctx != NULL);

	*iface = NULL;

	if (iface_name == NULL)
		goto out;

	snprintf(conf_path, PATH_MAX, "%s/%s", IFACE_CONFIG_DIR, iface_name);

	*iface = calloc(1, sizeof(struct iscsi_iface));
	_alloc_null_check(ctx, *iface, rc, out);

	snprintf((*iface)->name, sizeof((*iface)->name)/sizeof(char),
		 "%s", iface_name);

	recs = _idbm_recs_alloc();
	_alloc_null_check(ctx, recs, rc, out);

	_idbm_iface_rec_link(*iface, recs);

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
