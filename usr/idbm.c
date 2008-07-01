/*
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
 */

#include <stdio.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/file.h>

#include "idbm.h"
#include "log.h"
#include "util.h"
#include "iscsi_settings.h"
#include "transport.h"
#include "iscsi_sysfs.h"
#include "iface.h"

#define IDBM_HIDE	0    /* Hide parameter when print. */
#define IDBM_SHOW	1    /* Show parameter when print. */
#define IDBM_MASKED	2    /* Show "stars" instead of real value when print */

static struct idbm *db;

#define __recinfo_str(_key, _info, _rec, _name, _show, _n, _mod) do { \
	_info[_n].type = TYPE_STR; \
	strncpy(_info[_n].name, _key, NAME_MAXVAL); \
	if (strlen((char*)_rec->_name)) \
		strncpy((char*)_info[_n].value, (char*)_rec->_name, \
			VALUE_MAXVAL); \
	_info[_n].data = &_rec->_name; \
	_info[_n].data_len = sizeof(_rec->_name); \
	_info[_n].visible = _show; \
	_info[_n].can_modify = _mod; \
	_n++; \
} while(0)

#define __recinfo_int(_key, _info, _rec, _name, _show, _n, _mod) do { \
	_info[_n].type = TYPE_INT; \
	strncpy(_info[_n].name, _key, NAME_MAXVAL); \
	snprintf(_info[_n].value, VALUE_MAXVAL, "%d", _rec->_name); \
	_info[_n].data = &_rec->_name; \
	_info[_n].data_len = sizeof(_rec->_name); \
	_info[_n].visible = _show; \
	_info[_n].can_modify = _mod; \
	_n++; \
} while(0)

#define __recinfo_int_o2(_key,_info,_rec,_name,_show,_op0,_op1,_n, _mod) do { \
	_info[_n].type = TYPE_INT_O; \
	strncpy(_info[_n].name, _key, NAME_MAXVAL); \
	if (_rec->_name == 0) strncpy(_info[_n].value, _op0, VALUE_MAXVAL); \
	if (_rec->_name == 1) strncpy(_info[_n].value, _op1, VALUE_MAXVAL); \
	_info[_n].data = &_rec->_name; \
	_info[_n].data_len = sizeof(_rec->_name); \
	_info[_n].visible = _show; \
	_info[_n].opts[0] = _op0; \
	_info[_n].opts[1] = _op1; \
	_info[_n].numopts = 2; \
	_info[_n].can_modify = _mod; \
	_n++; \
} while(0)

#define __recinfo_int_o3(_key,_info,_rec,_name,_show,_op0,_op1,_op2,_n,	\
			 _mod) do { \
	__recinfo_int_o2(_key,_info,_rec,_name,_show,_op0,_op1,_n, _mod); \
	_n--; \
	if (_rec->_name == 2) strncpy(_info[_n].value, _op2, VALUE_MAXVAL);\
	_info[_n].opts[2] = _op2; \
	_info[_n].numopts = 3; \
	_n++; \
} while(0)

#define __recinfo_int_o4(_key,_info,_rec,_name,_show,_op0,_op1,_op2,_op3,_n, \
			 _mod) do { \
	__recinfo_int_o3(_key,_info,_rec,_name,_show,_op0,_op1,_op2,_n, _mod); \
	_n--; \
	if (_rec->_name == 3) strncpy(_info[_n].value, _op3, VALUE_MAXVAL); \
	_info[_n].opts[3] = _op3; \
	_info[_n].numopts = 4; \
	_n++; \
} while(0)

#define __recinfo_int_o5(_key,_info,_rec,_name,_show,_op0,_op1,_op2,_op3, \
			 _op4,_n, _mod) do { \
	__recinfo_int_o4(_key,_info,_rec,_name,_show,_op0,_op1,_op2,_op3, \
			  _n,_mod); \
	_n--; \
	if (_rec->_name == 4) strncpy(_info[_n].value, _op4, VALUE_MAXVAL); \
	_info[_n].opts[4] = _op4; \
	_info[_n].numopts = 5; \
	_n++; \
} while(0)

#define __recinfo_int_o6(_key,_info,_rec,_name,_show,_op0,_op1,_op2, \
			 _op3,_op4,_op5,_n,_mod) do { \
	__recinfo_int_o5(_key,_info,_rec,_name,_show,_op0,_op1,_op2,_op3, \
			 _op4,_n,_mod); \
	_n--; \
	if (_rec->_name == 5) strncpy(_info[_n].value, _op5, VALUE_MAXVAL); \
	_info[_n].opts[5] = _op5; \
	_info[_n].numopts = 6; \
	_n++; \
} while(0)

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

static char *get_global_string_param(char *pathname, const char *key)
{
	FILE *f = NULL;
	int len;
	char *line, buffer[1024];
	char *name = NULL;

	if (!pathname) {
		log_error("No pathname to load %s from", key);
		return NULL;
	}

	len = strlen(key);
	if ((f = fopen(pathname, "r"))) {
		while ((line = fgets(buffer, sizeof (buffer), f))) {

			line = strstrip(line);

			if (strncmp(line, key, len) == 0) {
				char *end = line + len;

				/*
				 * make sure ther is something after the
				 * key.
				 */
				if (strlen(end))
					name = strdup(line + len);
			}
		}
		fclose(f);
		if (name)
			log_debug(5, "%s=%s", key, name);
	} else
		log_error("can't open %s configuration file %s", key, pathname);

	return name;
}

char *get_iscsi_initiatorname(char *pathname)
{
	char *name;

	name = get_global_string_param(pathname, "InitiatorName=");
	if (!name)
		log_error("An InitiatorName= is required, but was not "
			  "found in %s", pathname);
	return name;
}

char *get_iscsi_initiatoralias(char *pathname)
{
	return get_global_string_param(pathname, "InitiatorAlias=");
}

static void
idbm_recinfo_discovery(discovery_rec_t *r, recinfo_t *ri)
{
	int num = 0;

	__recinfo_int_o2("discovery.startup", ri, r, startup, IDBM_SHOW,
			"manual", "automatic", num, 1);
	__recinfo_int_o6("discovery.type", ri, r, type, IDBM_SHOW,
			"sendtargets", "offload_send_targets", "slp", "isns",
			"static", "fw", num, 0);
	if (r->type == DISCOVERY_TYPE_SENDTARGETS) {
		__recinfo_str("discovery.sendtargets.address", ri, r,
			address, IDBM_SHOW, num, 0);
		__recinfo_int("discovery.sendtargets.port", ri, r,
			port, IDBM_SHOW, num, 0);
		__recinfo_int_o2("discovery.sendtargets.auth.authmethod", ri, r,
			u.sendtargets.auth.authmethod,
			IDBM_SHOW, "None", "CHAP", num, 1);
		__recinfo_str("discovery.sendtargets.auth.username", ri, r,
			u.sendtargets.auth.username, IDBM_SHOW, num, 1);
		__recinfo_str("discovery.sendtargets.auth.password", ri, r,
			u.sendtargets.auth.password, IDBM_MASKED, num, 1);
		__recinfo_int("discovery.sendtargets.auth.password_length",
			ri, r, u.sendtargets.auth.password_length,
			IDBM_HIDE, num, 1);
		__recinfo_str("discovery.sendtargets.auth.username_in", ri, r,
			u.sendtargets.auth.username_in, IDBM_SHOW, num, 1);
		__recinfo_str("discovery.sendtargets.auth.password_in", ri, r,
			u.sendtargets.auth.password_in, IDBM_MASKED, num, 1);
		__recinfo_int("discovery.sendtargets.auth.password_in_length",
			ri, r, u.sendtargets.auth.password_in_length,
			IDBM_HIDE, num, 1);
		__recinfo_int("discovery.sendtargets.timeo.login_timeout",ri, r,
			u.sendtargets.conn_timeo.login_timeout,
			IDBM_SHOW, num, 1);
		__recinfo_int("discovery.sendtargets.reopen_max",ri, r,
			u.sendtargets.reopen_max,
			IDBM_SHOW, num, 1);
		__recinfo_int("discovery.sendtargets.timeo.auth_timeout", ri, r,
			u.sendtargets.conn_timeo.auth_timeout,
			IDBM_SHOW, num, 1);
		__recinfo_int("discovery.sendtargets.timeo.active_timeout",ri,r,
			      u.sendtargets.conn_timeo.active_timeout,
			      IDBM_SHOW, num, 1);
		__recinfo_int("discovery.sendtargets.iscsi.MaxRecvDataSegmentLength",
			ri, r, u.sendtargets.iscsi.MaxRecvDataSegmentLength,
			IDBM_SHOW, num, 1);
	}
}

static void
idbm_recinfo_node(node_rec_t *r, recinfo_t *ri)
{
	int num = 0, i;

	__recinfo_str("node.name", ri, r, name, IDBM_SHOW, num, 0);
	__recinfo_int("node.tpgt", ri, r, tpgt, IDBM_SHOW, num, 0);
	__recinfo_int_o3("node.startup", ri, r, startup,
			IDBM_SHOW, "manual", "automatic", "onboot", num, 1);
	/*
	 * Note: because we do not add the iface.iscsi_ifacename to
	 * sysfs iscsiadm does some weird matching. We can change the iface
	 * values if a session is not running, but node record ifaces values
	 * have to be changed and so do the iface record ones.
	 *
	 * Users should nornmally not want to change the iface ones
	 * in the node record directly and instead do it through
	 * the iface mode which will do the right thing (althought that
	 * needs some locking).
	 */
	__recinfo_str("iface.hwaddress", ri, r, iface.hwaddress, IDBM_SHOW,
		      num, 1);
//	__recinfo_str("iface.ipaddress", ri, r, iface.ipaddress,
//		     IDBM_SHOW, num);
	__recinfo_str("iface.iscsi_ifacename", ri, r, iface.name, IDBM_SHOW,
		      num, 1);
	__recinfo_str("iface.net_ifacename", ri, r, iface.netdev, IDBM_SHOW,
		      num, 1);
	/*
	 * svn 780 compat: older versions used node.transport_name and
	 * rec->transport_name
	 */
	__recinfo_str("iface.transport_name", ri, r, iface.transport_name,
		      IDBM_SHOW, num, 1);
	__recinfo_str("iface.initiatorname", ri, r, iface.iname,
		      IDBM_SHOW, num, 1);
	__recinfo_str("node.discovery_address", ri, r, disc_address, IDBM_SHOW,
		      num, 0);
	__recinfo_int("node.discovery_port", ri, r, disc_port, IDBM_SHOW,
		      num, 0);
	__recinfo_int_o6("node.discovery_type", ri, r, disc_type,
			 IDBM_SHOW, "send_targets", "offload_send_targets",
			 "slp", "isns", "static", "fw", num, 0);
	__recinfo_int("node.session.initial_cmdsn", ri, r,
		      session.initial_cmdsn, IDBM_SHOW, num, 1);
	__recinfo_int("node.session.initial_login_retry_max", ri, r,
		      session.initial_login_retry_max, IDBM_SHOW, num, 1);
	__recinfo_int("node.session.cmds_max", ri, r,
		      session.cmds_max, IDBM_SHOW, num, 1);
	__recinfo_int("node.session.queue_depth", ri, r,
		       session.queue_depth, IDBM_SHOW, num, 1);
	__recinfo_int_o2("node.session.auth.authmethod", ri, r,
		session.auth.authmethod, IDBM_SHOW, "None", "CHAP", num, 1);
	__recinfo_str("node.session.auth.username", ri, r,
		      session.auth.username, IDBM_SHOW, num, 1);
	__recinfo_str("node.session.auth.password", ri, r,
		      session.auth.password, IDBM_MASKED, num, 1);
	__recinfo_int("node.session.auth.password_length", ri, r,
		      session.auth.password_length, IDBM_HIDE, num, 1);
	__recinfo_str("node.session.auth.username_in", ri, r,
		      session.auth.username_in, IDBM_SHOW, num, 1);
	__recinfo_str("node.session.auth.password_in", ri, r,
		      session.auth.password_in, IDBM_MASKED, num, 1);
	__recinfo_int("node.session.auth.password_in_length", ri, r,
		      session.auth.password_in_length, IDBM_HIDE, num, 1);
	__recinfo_int("node.session.timeo.replacement_timeout", ri, r,
		      session.timeo.replacement_timeout,
		      IDBM_SHOW, num, 1);
	__recinfo_int("node.session.err_timeo.abort_timeout", ri, r,
		      session.err_timeo.abort_timeout,
		      IDBM_SHOW, num, 1);
	__recinfo_int("node.session.err_timeo.lu_reset_timeout", ri, r,
		      session.err_timeo.lu_reset_timeout,
		      IDBM_SHOW, num, 1);
	__recinfo_int("node.session.err_timeo.host_reset_timeout", ri, r,
		      session.err_timeo.host_reset_timeout,
		      IDBM_SHOW, num, 1);
	__recinfo_int_o2("node.session.iscsi.FastAbort", ri, r,
			 session.iscsi.FastAbort, IDBM_SHOW, "No", "Yes",
			 num, 1);
	__recinfo_int_o2("node.session.iscsi.InitialR2T", ri, r,
			 session.iscsi.InitialR2T, IDBM_SHOW,
			"No", "Yes", num, 1);
	__recinfo_int_o2("node.session.iscsi.ImmediateData",
			 ri, r, session.iscsi.ImmediateData, IDBM_SHOW,
			"No", "Yes", num, 1);
	__recinfo_int("node.session.iscsi.FirstBurstLength", ri, r,
		      session.iscsi.FirstBurstLength, IDBM_SHOW, num, 1);
	__recinfo_int("node.session.iscsi.MaxBurstLength", ri, r,
		      session.iscsi.MaxBurstLength, IDBM_SHOW, num, 1);
	__recinfo_int("node.session.iscsi.DefaultTime2Retain", ri, r,
		      session.iscsi.DefaultTime2Retain, IDBM_SHOW, num, 1);
	__recinfo_int("node.session.iscsi.DefaultTime2Wait", ri, r,
		      session.iscsi.DefaultTime2Wait, IDBM_SHOW, num, 1);
	__recinfo_int("node.session.iscsi.MaxConnections", ri, r,
		      session.iscsi.MaxConnections, IDBM_SHOW, num, 1);
	__recinfo_int("node.session.iscsi.MaxOutstandingR2T", ri, r,
		      session.iscsi.MaxOutstandingR2T, IDBM_SHOW, num, 1);
	__recinfo_int("node.session.iscsi.ERL", ri, r,
		      session.iscsi.ERL, IDBM_SHOW, num, 1);

	for (i = 0; i < ISCSI_CONN_MAX; i++) {
		char key[NAME_MAXVAL];

		sprintf(key, "node.conn[%d].address", i);
		__recinfo_str(key, ri, r, conn[i].address, IDBM_SHOW, num, 0);
		sprintf(key, "node.conn[%d].port", i);
		__recinfo_int(key, ri, r, conn[i].port, IDBM_SHOW, num, 0);
		sprintf(key, "node.conn[%d].startup", i);
		__recinfo_int_o3(key, ri, r, conn[i].startup, IDBM_SHOW,
				 "manual", "automatic", "onboot", num, 1);
		sprintf(key, "node.conn[%d].tcp.window_size", i);
		__recinfo_int(key, ri, r, conn[i].tcp.window_size,
			      IDBM_SHOW, num, 1);
		sprintf(key, "node.conn[%d].tcp.type_of_service", i);
		__recinfo_int(key, ri, r, conn[i].tcp.type_of_service,
				IDBM_SHOW, num, 1);
		sprintf(key, "node.conn[%d].timeo.logout_timeout", i);
		__recinfo_int(key, ri, r, conn[i].timeo.logout_timeout,
				IDBM_SHOW, num, 1);
		sprintf(key, "node.conn[%d].timeo.login_timeout", i);
		__recinfo_int(key, ri, r, conn[i].timeo.login_timeout,
				IDBM_SHOW, num, 1);
		sprintf(key, "node.conn[%d].timeo.auth_timeout", i);
		__recinfo_int(key, ri, r, conn[i].timeo.auth_timeout,
				IDBM_SHOW, num, 1);

		sprintf(key, "node.conn[%d].timeo.noop_out_interval", i);
		__recinfo_int(key, ri, r, conn[i].timeo.noop_out_interval,
				IDBM_SHOW, num, 1);
		sprintf(key, "node.conn[%d].timeo.noop_out_timeout", i);
		__recinfo_int(key, ri, r, conn[i].timeo.noop_out_timeout,
				IDBM_SHOW, num, 1);

		sprintf(key, "node.conn[%d].iscsi.MaxRecvDataSegmentLength", i);
		__recinfo_int(key, ri, r,
			conn[i].iscsi.MaxRecvDataSegmentLength, IDBM_SHOW,
			num, 1);
		sprintf(key, "node.conn[%d].iscsi.HeaderDigest", i);
		__recinfo_int_o4(key, ri, r, conn[i].iscsi.HeaderDigest,
				 IDBM_SHOW, "None", "CRC32C", "CRC32C,None",
				 "None,CRC32C", num, 1);
		sprintf(key, "node.conn[%d].iscsi.DataDigest", i);
		__recinfo_int_o4(key, ri, r, conn[i].iscsi.DataDigest, IDBM_SHOW,
				 "None", "CRC32C", "CRC32C,None",
				 "None,CRC32C", num, 1);
		sprintf(key, "node.conn[%d].iscsi.IFMarker", i);
		__recinfo_int_o2(key, ri, r, conn[i].iscsi.IFMarker, IDBM_SHOW,
				"No", "Yes", num, 1);
		sprintf(key, "node.conn[%d].iscsi.OFMarker", i);
		__recinfo_int_o2(key, ri, r, conn[i].iscsi.OFMarker, IDBM_SHOW,
				"No", "Yes", num, 1);
	}
}

void idbm_recinfo_iface(iface_rec_t *r, recinfo_t *ri)
{
	int num = 0;

	__recinfo_str("iface.iscsi_ifacename", ri, r, name, IDBM_SHOW, num, 0);
	__recinfo_str("iface.net_ifacename", ri, r, netdev, IDBM_SHOW, num, 1);
//	__recinfo_str("iface.ipaddress", ri, r, ipaddress, IDBM_SHOW, num, 1);
	__recinfo_str("iface.hwaddress", ri, r, hwaddress, IDBM_SHOW, num, 1);
	__recinfo_str("iface.transport_name", ri, r, transport_name,
		      IDBM_SHOW, num, 1);
	__recinfo_str("iface.initiatorname", ri, r, iname, IDBM_SHOW, num, 1);
}

recinfo_t *idbm_recinfo_alloc(int max_keys)
{
	recinfo_t *info;

	info = malloc(sizeof(recinfo_t)*max_keys);
	if (!info)
		return NULL;
	memset(info, 0, sizeof(recinfo_t)*max_keys);
	return info;
}

void idbm_print(int type, void *rec, int show, FILE *f)
{
	int i;
	recinfo_t *info;

	info = idbm_recinfo_alloc(MAX_KEYS);
	if (!info)
		return;

	switch (type) {
	case IDBM_PRINT_TYPE_DISCOVERY:
		idbm_recinfo_discovery((discovery_rec_t*)rec, info);
		break;
	case IDBM_PRINT_TYPE_NODE:
		idbm_recinfo_node((node_rec_t*)rec, info);
		break;
	case IDBM_PRINT_TYPE_IFACE:
		idbm_recinfo_iface((struct iface_rec *)rec, info);
		break;
	}

	for (i = 0; i < MAX_KEYS; i++) {
		if (!info[i].visible)
			continue;
		if (!show && info[i].visible == IDBM_MASKED) {
			if (*(char*)info[i].data) {
				fprintf(f, "%s = ********\n", info[i].name);
				continue;
			}
			/* fall through */
		}

		if (strlen(info[i].value))
			fprintf(f, "%s = %s\n", info[i].name, info[i].value);
		else if (f == stdout)
			fprintf(f, "%s = <empty>\n", info[i].name);
	}

	free(info);
}

static void
idbm_discovery_setup_defaults(discovery_rec_t *rec, discovery_type_e type)
{
	memset(rec, 0, sizeof(discovery_rec_t));

	rec->startup = ISCSI_STARTUP_MANUAL;
	rec->type = type;
	if (type == DISCOVERY_TYPE_SENDTARGETS) {
		rec->u.sendtargets.reopen_max = 5;
		rec->u.sendtargets.auth.authmethod = 0;
		rec->u.sendtargets.auth.password_length = 0;
		rec->u.sendtargets.auth.password_in_length = 0;
		rec->u.sendtargets.conn_timeo.login_timeout=15;
		rec->u.sendtargets.conn_timeo.auth_timeout = 45;
		rec->u.sendtargets.conn_timeo.active_timeout=30;
		rec->u.sendtargets.iscsi.MaxRecvDataSegmentLength =
						DEF_INI_DISC_MAX_RECV_SEG_LEN;
	} else if (type == DISCOVERY_TYPE_SLP) {
		rec->u.slp.interfaces = NULL;
		rec->u.slp.scopes = NULL;
		rec->u.slp.poll_interval = 5 * 60;	/* 5 minutes */
		rec->u.slp.auth.authmethod = 0;
		rec->u.slp.auth.password_length = 0;
		rec->u.slp.auth.password_in_length = 0;
		rec->u.slp.auth.password_in_length = 0;
	} else if (type == DISCOVERY_TYPE_ISNS) {
		/* to be implemented */
	}
}

int idbm_rec_update_param(recinfo_t *info, char *name, char *value,
			  int line_number)
{
	int i;
	int passwd_done = 0;
	char passwd_len[8];

setup_passwd_len:
	for (i=0; i<MAX_KEYS; i++) {
		if (!strcmp(name, info[i].name)) {
			int j;
			log_debug(7, "updated '%s', '%s' => '%s'", name,
				  info[i].value, value);
			/* parse recinfo by type */
			if (info[i].type == TYPE_INT) {
				if (!info[i].data)
					continue;

				*(int*)info[i].data =
					strtoul(value, NULL, 10);
				goto updated;
			} else if (info[i].type == TYPE_STR) {
				if (!info[i].data)
					continue;

				strncpy((char*)info[i].data,
					value, info[i].data_len);
				goto updated;
			}
			for (j=0; j<info[i].numopts; j++) {
				if (!strcmp(value, info[i].opts[j])) {
					if (!info[i].data)
						continue;

					*(int*)info[i].data = j;
					goto updated;
				}
			}
			if (line_number) {
				log_warning("config file line %d contains "
					    "unknown value format '%s' for "
					    "parameter name '%s'",
					    line_number, value, name);
			}
			break;
		}
	}

	return 1;

updated:
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

	return 0;
}

/*
 * TODO: we can also check for valid values here.
 */
int idbm_verify_param(recinfo_t *info, char *name)
{
	int i;

	for (i = 0; i < MAX_KEYS; i++) {
		if (strcmp(name, info[i].name))
			continue;

		log_debug(7, "verify %s %d\n", name, info[i].can_modify);
		if (info[i].can_modify)
			return 0;
		else {
			log_error("Cannot modify %s. It is used to look up "
				  "the record and cannot be changed.", name);
			return EINVAL;
		}
	}

	log_error("Cannot modify %s. Invalid param name.", name);
	return EINVAL;
}

void idbm_recinfo_config(recinfo_t *info, FILE *f)
{
	char name[NAME_MAXVAL];
	char value[VALUE_MAXVAL];
	char *line, *nl, buffer[2048];
	int line_number = 0;
	int c = 0, i;

	fseek(f, 0, SEEK_SET);

	/* process the config file */
	do {
		line = fgets(buffer, sizeof (buffer), f);
		line_number++;
		if (!line)
			continue;

		nl = line + strlen(line) - 1;
		if (*nl != '\n') {
			log_warning("Config file line %d too long.",
			       line_number);
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
			log_warning("config file line %d do not has value",
			       line_number);
			continue;
		}
		*(name+i)=0; nl++;
		/* skip after-name traling spaces */
		while (*nl && isspace(c = *nl)) nl++;
		if (*nl && *nl != '=') {
			log_warning("config file line %d has not '=' sepa",
			       line_number);
			continue;
		}
		/* skip '=' sepa */
		nl++;
		/* skip after-sepa traling spaces */
		while (*nl && isspace(c = *nl)) nl++;
		if (!*nl) {
			log_warning("config file line %d do not has value",
			       line_number);
			continue;
		}
		/* parse value */
		i=0; *value = 0;
		while (*nl) {
			*(value+i) = *nl; i++; nl++;
		}
		*(value+i) = 0;

		(void)idbm_rec_update_param(info, name, value, line_number);
	} while (line);
}

/*
 * TODO: remove db's copy of nrec and infos
 */
static void idbm_sync_config(void)
{
	char *config_file;
	FILE *f;

	/* in case of no configuration file found we just
	 * initialize default node and default discovery records
	 * from hard-coded default values */
	idbm_node_setup_defaults(&db->nrec);
	idbm_discovery_setup_defaults(&db->drec_st, DISCOVERY_TYPE_SENDTARGETS);
	idbm_discovery_setup_defaults(&db->drec_slp, DISCOVERY_TYPE_SLP);
	idbm_discovery_setup_defaults(&db->drec_isns, DISCOVERY_TYPE_ISNS);

	idbm_recinfo_discovery(&db->drec_st, db->dinfo_st);
	idbm_recinfo_discovery(&db->drec_slp, db->dinfo_slp);
	idbm_recinfo_discovery(&db->drec_isns, db->dinfo_isns);
	idbm_recinfo_node(&db->nrec, db->ninfo);

	if (!db->get_config_file) {
		log_debug(1, "Could not get config file. No config file fn\n");
		return;
	}

	config_file = db->get_config_file();
	if (!config_file) {
		log_debug(1, "Could not get config file for sync config\n");
		return;
	}

	f = fopen(config_file, "r");
	if (!f) {
		log_debug(1, "cannot open configuration file %s. "
			  "Default location is %s.\n",
			  config_file, CONFIG_FILE);
		return;
	}
	log_debug(5, "updating defaults from '%s'", config_file);

	idbm_recinfo_config(db->dinfo_st, f);
	idbm_recinfo_config(db->dinfo_slp, f);
	idbm_recinfo_config(db->dinfo_isns, f);
	idbm_recinfo_config(db->ninfo, f);
	fclose(f);

	/* update password lengths */
	if (*db->drec_st.u.sendtargets.auth.password)
		db->drec_st.u.sendtargets.auth.password_length =
			strlen((char*)db->drec_st.u.sendtargets.auth.password);
	if (*db->drec_st.u.sendtargets.auth.password_in)
		db->drec_st.u.sendtargets.auth.password_in_length =
		     strlen((char*)db->drec_st.u.sendtargets.auth.password_in);
	if (*db->drec_slp.u.slp.auth.password)
		db->drec_slp.u.slp.auth.password_length =
			strlen((char*)db->drec_slp.u.slp.auth.password);
	if (*db->drec_slp.u.slp.auth.password_in)
		db->drec_slp.u.slp.auth.password_in_length =
			strlen((char*)db->drec_slp.u.slp.auth.password_in);
	if (*db->nrec.session.auth.password)
		db->nrec.session.auth.password_length =
			strlen((char*)db->nrec.session.auth.password);
	if (*db->nrec.session.auth.password_in)
		db->nrec.session.auth.password_in_length =
			strlen((char*)db->nrec.session.auth.password_in);
}

void idbm_node_setup_from_conf(node_rec_t *rec)
{
	memset(rec, 0, sizeof(*rec));
	idbm_node_setup_defaults(rec);
	idbm_sync_config();
	memcpy(rec, &db->nrec, sizeof(*rec));
}

int idbm_print_discovery_info(discovery_rec_t *rec, int show)
{
	idbm_print(IDBM_PRINT_TYPE_DISCOVERY, rec, show, stdout);
	return 1;
}

int idbm_print_node_info(void *data, node_rec_t *rec)
{
	int show = *((int *)data);

	idbm_print(IDBM_PRINT_TYPE_NODE, rec, show, stdout);
	return 0;
}

int idbm_print_iface_info(void *data, struct iface_rec *iface)
{
	int show = *((int *)data);

	idbm_print(IDBM_PRINT_TYPE_IFACE, iface, show, stdout);
	return 0;
}

int idbm_print_node_flat(void *data, node_rec_t *rec)
{
	if (strchr(rec->conn[0].address, '.'))
		printf("%s:%d,%d %s\n", rec->conn[0].address, rec->conn[0].port,
			rec->tpgt, rec->name);
	else
		printf("[%s]:%d,%d %s\n", rec->conn[0].address,
		       rec->conn[0].port, rec->tpgt, rec->name);
	return 0;
}

int idbm_print_node_tree(void *data, node_rec_t *rec)
{
	node_rec_t *last_rec = data;

	if (!last_rec || strcmp(last_rec->name, rec->name)) {
		printf("Target: %s\n", rec->name);
		if (last_rec)
			memset(last_rec, 0, sizeof(node_rec_t));
	}

	if (!last_rec ||
	     ((strcmp(last_rec->conn[0].address, rec->conn[0].address) ||
	     last_rec->conn[0].port != rec->conn[0].port))) {
		if (strchr(rec->conn[0].address, '.'))
			printf("\tPortal: %s:%d,%d\n", rec->conn[0].address,
			       rec->conn[0].port, rec->tpgt);
		else
			printf("\tPortal: [%s]:%d,%d\n", rec->conn[0].address,
			       rec->conn[0].port, rec->tpgt);
	}

	printf("\t\tIface Name: %s\n", rec->iface.name);

	if (last_rec)
		memcpy(last_rec, rec, sizeof(node_rec_t));
	return 0;
}

static int
get_params_from_disc_link(char *link, char **target, char **tpgt,
			  char **address, char **port, char **ifaceid)
{
	(*target) = link;
	*address = strchr(*target, ',');
	if (!(*address))
		return EINVAL;
	*(*address)++ = '\0';
	*port = strchr(*address, ',');
	if (!(*port))
		return EINVAL;
	*(*port)++ = '\0';
	*tpgt = strchr(*port, ',');
	if (!(*tpgt))
		return EINVAL;
	*(*tpgt)++ = '\0';
	*ifaceid = strchr(*tpgt, ',');
	if (!(*ifaceid))
		return EINVAL;
	*(*ifaceid)++ = '\0';
	return 0;
}

int idbm_lock(void)
{
	int fd, i, ret;

	if (db->refs > 0) {
		db->refs++;
		return 0;
	}

	if (access(LOCK_DIR, F_OK) != 0) {
		if (mkdir(LOCK_DIR, 0660) != 0) {
			log_error("Could not open %s. Exiting\n", LOCK_DIR);
			exit(-1);
		}
	}

	fd = open(LOCK_FILE, O_RDWR | O_CREAT, 0666);
	if (fd >= 0)
		close(fd);

	for (i = 0; i < 3000; i++) {
		ret = link(LOCK_FILE, LOCK_WRITE_FILE);
		if (ret == 0)
			break;

		usleep(10000);
	}

	db->refs = 1;
	return 0;
}

void idbm_unlock(void)
{
	if (db->refs > 1) {
		db->refs--;
		return;
	}

	db->refs = 0;
	unlink(LOCK_WRITE_FILE);
}

/*
 * Backwards Compat:
 * If the portal is a file then we are doing the old style default
 * session behavior (svn pre 780).
 */
static FILE *idbm_open_rec_r(char *portal, char *config)
{
	struct stat statb;

	log_debug(5, "Looking for config file %s config %s.", portal, config);

	if (stat(portal, &statb)) {
		log_debug(5, "Could not stat %s err %d.", portal, errno);
		return NULL;
	}

	if (S_ISDIR(statb.st_mode)) {
		strncat(portal, "/", PATH_MAX);
		strncat(portal, config, PATH_MAX);
	}
	return fopen(portal, "r");
}

static int __idbm_rec_read(node_rec_t *out_rec, char *conf)
{
	recinfo_t *info;
	FILE *f;
	int rc = 0;

	info = idbm_recinfo_alloc(MAX_KEYS);
	if (!info)
		return ENOMEM;

	idbm_lock();
	f = fopen(conf, "r");
	if (!f) {
		log_debug(5, "Could not open %s err %d\n", conf, errno);
		rc = errno;
		goto unlock;
	}

	memset(out_rec, 0, sizeof(*out_rec));
	idbm_node_setup_defaults(out_rec);
	idbm_recinfo_node(out_rec, info);
	idbm_recinfo_config(info, f);
	fclose(f);

unlock:
	idbm_unlock();
	free(info);
	return rc;
}

int
idbm_rec_read(node_rec_t *out_rec, char *targetname, int tpgt,
	      char *ip, int port, struct iface_rec *iface)
{
	struct stat statb;
	char *portal;
	int rc;

	portal = calloc(1, PATH_MAX);
	if (!portal)
		return ENOMEM;

	/* try old style portal as config */
	snprintf(portal, PATH_MAX, "%s/%s/%s,%d", NODE_CONFIG_DIR,
		 targetname, ip, port);
	log_debug(5, "rec read looking for config file %s.", portal);
	if (!stat(portal, &statb))
		goto read;

	snprintf(portal, PATH_MAX, "%s/%s/%s,%d,%d/%s", NODE_CONFIG_DIR,
		 targetname, ip, port, tpgt, iface->name);
	log_debug(5, "rec read looking for config file %s.", portal);
	if (!strlen(iface->name)) {
		rc = EINVAL;
		goto free_portal;
	}

	if (stat(portal, &statb)) {
		log_debug(5, "Could not stat %s err %d.", portal, errno);
		free(portal);
		return errno;
	}

read:
	rc = __idbm_rec_read(out_rec, portal);
free_portal:
	free(portal);
	return rc;
}

static int st_disc_filter(const struct dirent *dir)
{
	return strcmp(dir->d_name, ".") && strcmp(dir->d_name, "..") &&
	       strcmp(dir->d_name, ST_CONFIG_NAME);
}

static int print_discovered(char *disc_path, int info_level)
{
	char *tmp_port = NULL, *last_address = NULL, *last_target = NULL;
	char *target = NULL, *address = NULL, *ifaceid = NULL, *tpgt = NULL;
	char *portal;
	int n, i, last_port = -1;
	struct dirent **namelist;
	node_rec_t *rec;

	n = scandir(disc_path, &namelist, st_disc_filter, direntcmp);
	if (n < 0)
		return 0;

	rec = malloc(sizeof(*rec));
	if (!rec)
		goto free_namelist;

	portal = malloc(PATH_MAX);
	if (!portal)
		goto free_rec;

	for (i = 0; i < n; i++) {
		if (get_params_from_disc_link(namelist[i]->d_name, &target,
					      &tpgt, &address, &tmp_port,
					      &ifaceid)) {
			log_error("Improperly formed disc to node link");
			continue;
		}

		memset(portal, 0, PATH_MAX);
		snprintf(portal, PATH_MAX, "%s/%s/%s,%s,%s/%s", NODE_CONFIG_DIR,
			 target, address, tmp_port, tpgt, ifaceid);
		if (__idbm_rec_read(rec, portal)) {
			log_error("Could not read node record for %s "
				  "%s %d %s", target, address, atoi(tmp_port),
				  ifaceid);
			continue;
		}

		if (info_level < 1) {
			if (strchr(address, '.'))
				printf("%s:%d,%d %s\n", address, atoi(tmp_port),
					rec->tpgt, target);
			else
				printf("[%s]:%d,%d %s\n", address,
					atoi(tmp_port), rec->tpgt, target);
			continue;
		}

		if (!last_target || strcmp(last_target, target)) {
			printf("    Target: %s\n", target);
			last_target = namelist[i]->d_name;
			last_port = -1;
			last_address = NULL;
		}

		if (!last_address || strcmp(last_address, address) ||
		    last_port == -1 || last_port != atoi(tmp_port)) {
			last_port = atoi(tmp_port);
			printf("        ");
			if (strchr(address, '.'))
				printf("Portal: %s:%d,%d\n", address,
					last_port, rec->tpgt);
			else
				printf("Portal: [%s]:%d,%d\n", address,
					last_port, rec->tpgt);
			last_address = address;
		}

		printf("           Iface Name: %s\n", rec->iface.name);
	}

	free(portal);
free_rec:
	free(rec);
free_namelist:
	for (i = 0; i < n; i++)
		free(namelist[i]);
	free(namelist);
	return n;
}

int idbm_print_discovered(discovery_rec_t *drec, int info_level)
{
	char *disc_path;
	int rc;

	disc_path = calloc(1, PATH_MAX);
	if (!disc_path)
		return 0;

	switch (drec->type) {
	case DISCOVERY_TYPE_SENDTARGETS:
		snprintf(disc_path, PATH_MAX, "%s/%s,%d", ST_CONFIG_DIR,
			 drec->address, drec->port);
		break;
	case DISCOVERY_TYPE_STATIC:
		snprintf(disc_path, PATH_MAX, "%s", STATIC_CONFIG_DIR);
		break;
	case DISCOVERY_TYPE_ISNS:
		snprintf(disc_path, PATH_MAX, "%s", ISNS_CONFIG_DIR);
		break;
	case DISCOVERY_TYPE_SLP:
	default:
		rc = 0;
		goto done;
	}

	rc = print_discovered(disc_path, info_level);
done:
	free(disc_path);
	return rc;
}

static int idbm_print_all_st(int info_level)
{
	DIR *entity_dirfd;
	struct dirent *entity_dent;
	int found = 0;
	char *disc_dir;

	disc_dir = malloc(PATH_MAX);
	if (!disc_dir)
		return 0;

	entity_dirfd = opendir(ST_CONFIG_DIR);
	if (!entity_dirfd)
		goto free_disc;

	while ((entity_dent = readdir(entity_dirfd))) {
		if (!strcmp(entity_dent->d_name, ".") ||
		    !strcmp(entity_dent->d_name, ".."))
			continue;

		log_debug(5, "found %s\n", entity_dent->d_name);
		if (info_level >= 1) {
			memset(disc_dir, 0, PATH_MAX);
			snprintf(disc_dir, PATH_MAX, "%s/%s", ST_CONFIG_DIR,
				 entity_dent->d_name);

			printf("DiscoveryAddress: %s\n", entity_dent->d_name);
			found += print_discovered(disc_dir, info_level);
		} else {
			char *tmp_port;

			tmp_port = strchr(entity_dent->d_name, ',');
			if (!tmp_port)
				continue;
			*tmp_port++ = '\0';

			printf("%s:%d via sendtargets\n", entity_dent->d_name,
			       atoi(tmp_port));
			found++;
		}
	}
	closedir(entity_dirfd);
free_disc:
	free(disc_dir);
	return found;
}

int idbm_print_all_discovery(int info_level)
{
	discovery_rec_t *drec;
	int found = 0, tmp;

	if (info_level < 1)
		return idbm_print_all_st(info_level);

	drec = calloc(1, sizeof(*drec));
	if (!drec)
		return ENOMEM;

	tmp = 0;
	printf("SENDTARGETS:\n");
	tmp = idbm_print_all_st(info_level);
	if (!tmp)
		printf("No targets found.\n");
	found += tmp;
	tmp = 0;

	printf("iSNS:\n");
	drec->type = DISCOVERY_TYPE_ISNS;
	tmp = idbm_print_discovered(drec, info_level);
	if (!tmp)
		printf("No targets found.\n");
	found += tmp;
	tmp = 0;

	printf("STATIC:\n");
	drec->type = DISCOVERY_TYPE_STATIC;
	tmp = idbm_print_discovered(drec, info_level);
	if (!tmp)
		printf("No targets found.\n");
	found += tmp;

	free(drec);
	return found;
}

/*
 * This iterates over the ifaces in use in the nodes dir.
 * It does not iterate over the ifaces setup in /etc/iscsi/ifaces.
 */
static int idbm_for_each_iface(int *found, void *data,
				idbm_iface_op_fn *fn,
				char *targetname, int tpgt, char *ip, int port)
{
	DIR *iface_dirfd;
	struct dirent *iface_dent;
	struct stat statb;
	node_rec_t rec;
	int rc = 0;
	char *portal;

	portal = calloc(1, PATH_MAX);
	if (!portal)
		return ENOMEM;

	if (tpgt >= 0)
		goto read_iface;

	/* old style portal as a config */
	snprintf(portal, PATH_MAX, "%s/%s/%s,%d", NODE_CONFIG_DIR, targetname,
		 ip, port);
	if (stat(portal, &statb)) {
		log_error("iface iter could not stat %s.", portal);
		rc = ENODEV;
		goto free_portal;
	}

	rc = __idbm_rec_read(&rec, portal);
	if (rc)
		goto free_portal;

	rc = fn(data, &rec);
	if (!rc)
		(*found)++;
	else if (rc == -1)
		rc = 0;
	goto free_portal;

read_iface:
	snprintf(portal, PATH_MAX, "%s/%s/%s,%d,%d", NODE_CONFIG_DIR,
		 targetname, ip, port, tpgt);

	iface_dirfd = opendir(portal);
	if (!iface_dirfd) {
		rc = errno;
		goto free_portal;
	}

	while ((iface_dent = readdir(iface_dirfd))) {
		if (!strcmp(iface_dent->d_name, ".") ||
		    !strcmp(iface_dent->d_name, ".."))
			continue;

		log_debug(5, "iface iter found %s.", iface_dent->d_name);
		memset(portal, 0, PATH_MAX);
		snprintf(portal, PATH_MAX, "%s/%s/%s,%d,%d/%s", NODE_CONFIG_DIR,
			 targetname, ip, port, tpgt, iface_dent->d_name);
		if (__idbm_rec_read(&rec, portal))
			continue;

		/* less than zero means it was not a match */
		rc = fn(data, &rec);
		if (rc > 0)
			break;
		else if (rc == 0)
			(*found)++;
		else 
			rc = 0;
	}

	closedir(iface_dirfd);
free_portal:
	free(portal);
	return rc;
}

/*
 * backwards compat
 * The portal could be a file or dir with interfaces
 */
int idbm_for_each_portal(int *found, void *data, idbm_portal_op_fn *fn,
			 char *targetname)
{
	DIR *portal_dirfd;
	struct dirent *portal_dent;
	int rc = 0;
	char *portal;

	portal = calloc(1, PATH_MAX);
	if (!portal)
		return ENOMEM;

	snprintf(portal, PATH_MAX, "%s/%s", NODE_CONFIG_DIR, targetname);
	portal_dirfd = opendir(portal);
	if (!portal_dirfd) {
		rc = errno;
		goto done;
	}

	while ((portal_dent = readdir(portal_dirfd))) {
		char *tmp_port, *tmp_tpgt;

		if (!strcmp(portal_dent->d_name, ".") ||
		    !strcmp(portal_dent->d_name, ".."))
			continue;

		log_debug(5, "found %s\n", portal_dent->d_name);
		tmp_port = strchr(portal_dent->d_name, ',');
		if (!tmp_port)
			continue;
		*tmp_port++ = '\0';
		tmp_tpgt = strchr(tmp_port, ',');
		if (tmp_tpgt)
			*tmp_tpgt++ = '\0';

		rc = fn(found, data, targetname,
			tmp_tpgt ? atoi(tmp_tpgt) : -1,
			portal_dent->d_name, atoi(tmp_port));
		if (rc)
			break;
	}
	closedir(portal_dirfd);
done:
	free(portal);
	return rc;
}

int idbm_for_each_node(int *found, void *data, idbm_node_op_fn *fn)
{
	DIR *node_dirfd;
	struct dirent *node_dent;
	int rc = 0;

	*found = 0;

	node_dirfd = opendir(NODE_CONFIG_DIR);
	if (!node_dirfd)
		/* on start up node dir may not be created */
		return 0;

	while ((node_dent = readdir(node_dirfd))) {
		if (!strcmp(node_dent->d_name, ".") ||
		    !strcmp(node_dent->d_name, ".."))
			continue;

		log_debug(5, "searching %s\n", node_dent->d_name);
		rc = fn(found, data, node_dent->d_name);
		if (rc)
			break;
	}

	closedir(node_dirfd);
	return rc;
}

static int iface_fn(void *data, node_rec_t *rec)
{
	struct rec_op_data *op_data = data;

	return op_data->fn(op_data->data, rec);
}

static int portal_fn(int *found, void *data, char *targetname,
		     int tpgt, char *ip, int port)
{
	return idbm_for_each_iface(found, data, iface_fn, targetname,
				   tpgt, ip, port);
}

static int node_fn(int *found, void *data, char *targetname)
{
	return idbm_for_each_portal(found, data, portal_fn, targetname);
}

int idbm_for_each_rec(int *found, void *data, idbm_iface_op_fn *fn)
{
	struct rec_op_data op_data;

	memset(&op_data, 0, sizeof(struct rec_op_data));
	op_data.data = data;
	op_data.fn = fn;

	return idbm_for_each_node(found, &op_data, node_fn);
}

int
idbm_discovery_read(discovery_rec_t *out_rec, char *addr, int port)
{
	recinfo_t *info;
	char *portal;
	int rc = 0;
	FILE *f;

	memset(out_rec, 0, sizeof(discovery_rec_t));

	info = idbm_recinfo_alloc(MAX_KEYS);
	if (!info)
		return ENOMEM;

	portal = malloc(PATH_MAX);
	if (!portal)
		goto free_info;

	snprintf(portal, PATH_MAX, "%s/%s,%d", ST_CONFIG_DIR,
		 addr, port);
	log_debug(5, "Looking for config file %s\n", portal);

	idbm_lock();

	f = idbm_open_rec_r(portal, ST_CONFIG_NAME);
	if (!f) {
		log_debug(1, "Could not open %s err %d\n", portal, errno);
		rc = errno;
		goto unlock;
	}

	idbm_discovery_setup_defaults(out_rec, DISCOVERY_TYPE_SENDTARGETS);
	idbm_recinfo_discovery(out_rec, info);
	idbm_recinfo_config(info, f);
	fclose(f);

unlock:	
	idbm_unlock();
free_info:
	free(portal);
	free(info);
	return rc;
}

/*
 * Backwards Compat:
 * If the portal is a file then we are doing the old style default
 * session behavior (svn pre 780).
 */
static FILE *idbm_open_rec_w(char *portal, char *config)
{
	struct stat statb;
	FILE *f;
	int err;

	log_debug(5, "Looking for config file %s\n", portal);

	err = stat(portal, &statb);
	if (err)
		goto mkdir_portal;

	if (!S_ISDIR(statb.st_mode)) {
		/*
		 * Old style portal as a file. Let's update it.
		 */
		if (unlink(portal)) {
			log_error("Could not convert %s to %s/%s. "
				 "err %d\n", portal, portal,
				  config, errno);
			return NULL;
		}

mkdir_portal:
		if (mkdir(portal, 0660) != 0) {
			log_error("Could not make dir %s err %d\n",
				  portal, errno);
			return NULL;
		}
	}

	strncat(portal, "/", PATH_MAX);
	strncat(portal, config, PATH_MAX);
	f = fopen(portal, "w");
	if (!f)
		log_error("Could not open %s err %d\n", portal, errno);
	return f;
}

static int idbm_rec_write(node_rec_t *rec)
{
	struct stat statb;
	FILE *f;
	char *portal;
	int rc = 0;

	portal = malloc(PATH_MAX);
	if (!portal) {
		log_error("Could not alloc portal\n");
		return ENOMEM;
	}

	snprintf(portal, PATH_MAX, "%s", NODE_CONFIG_DIR);
	if (access(portal, F_OK) != 0) {
		if (mkdir(portal, 0660) != 0) {
			log_error("Could not make %s\n", portal);
			rc = errno;
			goto free_portal;
		}
	}

	snprintf(portal, PATH_MAX, "%s/%s", NODE_CONFIG_DIR, rec->name);
	if (access(portal, F_OK) != 0) {
		if (mkdir(portal, 0660) != 0) {
			log_error("Could not make %s\n", portal);
			rc = errno;
			goto free_portal;
		}
	}

	snprintf(portal, PATH_MAX, "%s/%s/%s,%d", NODE_CONFIG_DIR,
		 rec->name, rec->conn[0].address, rec->conn[0].port);
	log_debug(5, "Looking for config file %s", portal);

	idbm_lock();

	rc = stat(portal, &statb);
	if (rc) {
		rc = 0;
		/*
		 * older iscsiadm versions had you create the config then set
		 * set the tgpt. In new versions you must pass all the info in
		 * from the start
		 */
		if (rec->tpgt == PORTAL_GROUP_TAG_UNKNOWN)
			/* drop down to old style portal as config */
			goto open_conf;
		else
			goto mkdir_portal;
	}

	if (!S_ISDIR(statb.st_mode)) {
		/*
		 * older iscsiadm versions had you create the config then set
		 * set the tgpt. In new versions you must pass all the info in
		 * from the start
		 */
		if (rec->tpgt == PORTAL_GROUP_TAG_UNKNOWN)
			/* drop down to old style portal as config */
			goto open_conf;
		/*
		 * Old style portal as a file, but with tpgt. Let's update it.
		 */
		if (unlink(portal)) {
			log_error("Could not convert %s. err %d\n", portal,
				  errno);
			rc = errno;
			goto unlock;
		}
	} else {
		rc = EINVAL;
		goto unlock;
	}	

mkdir_portal:
	snprintf(portal, PATH_MAX, "%s/%s/%s,%d,%d", NODE_CONFIG_DIR,
		 rec->name, rec->conn[0].address, rec->conn[0].port, rec->tpgt);
	if (stat(portal, &statb)) {
		if (mkdir(portal, 0660) != 0) {
			log_error("Could not make dir %s err %d\n",
				  portal, errno);
			rc = errno;
			goto unlock;
		}
	}

	snprintf(portal, PATH_MAX, "%s/%s/%s,%d,%d/%s", NODE_CONFIG_DIR,
		 rec->name, rec->conn[0].address, rec->conn[0].port, rec->tpgt,
		 rec->iface.name);
open_conf:
	f = fopen(portal, "w");
	if (!f) {
		log_error("Could not open %s err %d\n", portal, errno);
		rc = errno;
		goto unlock;
	}

	idbm_print(IDBM_PRINT_TYPE_NODE, rec, 1, f);
	fclose(f);
unlock:
	idbm_unlock();
free_portal:
	free(portal);
	return rc;
}

static int
idbm_discovery_write(discovery_rec_t *rec)
{
	FILE *f;
	char *portal;
	int rc = 0;

	portal = malloc(PATH_MAX);
	if (!portal) {
		log_error("Could not alloc portal\n");
		return ENOMEM;
	}

	idbm_lock();
	snprintf(portal, PATH_MAX, "%s", ST_CONFIG_DIR);
	if (access(portal, F_OK) != 0) {
		if (mkdir(portal, 0660) != 0) {
			log_error("Could not make %s\n", portal);
			rc = errno;
			goto free_portal;
		}
	}

	snprintf(portal, PATH_MAX, "%s/%s,%d", ST_CONFIG_DIR,
		 rec->address, rec->port);

	f = idbm_open_rec_w(portal, ST_CONFIG_NAME);
	if (!f) {
		log_error("Could not open %s err %d\n", portal, errno);
		rc = errno;
		goto free_portal;
	}

	idbm_print(IDBM_PRINT_TYPE_DISCOVERY, rec, 1, f);
	fclose(f);
free_portal:
	idbm_unlock();
	free(portal);
	return rc;
}

int
idbm_add_discovery(discovery_rec_t *newrec, int overwrite)
{
	discovery_rec_t rec;
	int rc;

	if (!idbm_discovery_read(&rec, newrec->address,
				newrec->port)) {
		if (!overwrite)
			return 0;
		log_debug(7, "overwriting existing record");
	} else
		log_debug(7, "adding new DB record");

	rc = idbm_discovery_write(newrec);
	return rc;
}

static int setup_disc_to_node_link(char *disc_portal, node_rec_t *rec)
{
	int rc = 0;

	switch (rec->disc_type) {
	case DISCOVERY_TYPE_SENDTARGETS:
		/* st dir setup when we create its discovery node */
		snprintf(disc_portal, PATH_MAX, "%s/%s,%d/%s,%s,%d,%d,%s",
			 ST_CONFIG_DIR,
			 rec->disc_address, rec->disc_port, rec->name,
			 rec->conn[0].address, rec->conn[0].port, rec->tpgt,
			 rec->iface.name);
		break;
	case DISCOVERY_TYPE_STATIC:
		if (access(STATIC_CONFIG_DIR, F_OK) != 0) {
			if (mkdir(STATIC_CONFIG_DIR, 0660) != 0) {
				log_error("Could not make %s\n",
					  STATIC_CONFIG_DIR);
				rc = errno;
			}
		}

		snprintf(disc_portal, PATH_MAX, "%s/%s,%s,%d,%d,%s",
			 STATIC_CONFIG_DIR, rec->name,
			 rec->conn[0].address, rec->conn[0].port, rec->tpgt,
			 rec->iface.name);
		break;
	case DISCOVERY_TYPE_ISNS:
		if (access(ISNS_CONFIG_DIR, F_OK) != 0) {
			if (mkdir(ISNS_CONFIG_DIR, 0660) != 0) {
				log_error("Could not make %s\n",
					  ISNS_CONFIG_DIR);
				rc = errno;
			}
		}

		snprintf(disc_portal, PATH_MAX, "%s/%s,%s,%d,%d,%s",
			 ISNS_CONFIG_DIR,
			 rec->name, rec->conn[0].address,
			 rec->conn[0].port, rec->tpgt, rec->iface.name);
		break;
	case DISCOVERY_TYPE_SLP:
	default:
		rc = EINVAL;
	}

	return rc;
}

int idbm_add_node(node_rec_t *newrec, discovery_rec_t *drec, int overwrite)
{
	node_rec_t rec;
	char *node_portal, *disc_portal;
	int rc;

	if (!idbm_rec_read(&rec, newrec->name, newrec->tpgt,
			   newrec->conn[0].address, newrec->conn[0].port,
			   &newrec->iface)) {
		if (!overwrite)
			return 0;

		rc = idbm_delete_node(&rec);
		if (rc)
			return rc;
		log_debug(7, "overwriting existing record");
	} else
		log_debug(7, "adding new DB record");

	if (drec) {
		newrec->disc_type = drec->type;
		newrec->disc_port = drec->port;
		strcpy(newrec->disc_address, drec->address);
	}

	rc = idbm_rec_write(newrec);
	/*
	 * if a old app passed in a bogus tpgt then we do not create links
	 * since it will set a different tpgt in another iscsiadm call
	 */
	if (rc || !drec || newrec->tpgt == PORTAL_GROUP_TAG_UNKNOWN)
		return rc;

	node_portal = calloc(2, PATH_MAX);
	if (!node_portal)
		return ENOMEM;

	disc_portal = node_portal + PATH_MAX;
	snprintf(node_portal, PATH_MAX, "%s/%s/%s,%d,%d", NODE_CONFIG_DIR,
		 newrec->name, newrec->conn[0].address, newrec->conn[0].port,
		 newrec->tpgt);
	rc = setup_disc_to_node_link(disc_portal, newrec);
	if (rc)
		goto free_portal;

	log_debug(7, "node addition making link from %s to %s", node_portal,
		 disc_portal);

	idbm_lock();
	if (symlink(node_portal, disc_portal)) {
		if (errno == EEXIST)
			log_debug(7, "link from %s to %s exists", node_portal,
				  disc_portal);
		else {
			rc = errno;
			log_error("Could not make link from disc source %s to "
				 "node %s", disc_portal, node_portal);
		}
	}
	idbm_unlock();
free_portal:
	free(node_portal);
	return rc;
}

static int idbm_bind_iface_to_node(struct node_rec *new_rec,
				   struct iface_rec *iface,
				   struct list_head *bound_recs)
{
	struct node_rec *clone_rec;

	clone_rec = calloc(1, sizeof(*clone_rec));
	if (!clone_rec)
		return ENOMEM;

	memcpy(clone_rec, new_rec, sizeof(*clone_rec));
	INIT_LIST_HEAD(&clone_rec->list);
	iface_copy(&clone_rec->iface, iface);
	list_add_tail(&clone_rec->list, bound_recs);
	return 0;
}

int idbm_bind_ifaces_to_node(struct node_rec *new_rec, struct list_head *ifaces,
			     struct list_head *bound_recs)
{
	struct iface_rec *iface, *tmp;
	struct iscsi_transport *t;
	int rc = 0, found = 0;

	if (!ifaces || list_empty(ifaces)) {
		struct list_head def_ifaces;

		INIT_LIST_HEAD(&def_ifaces);
		iface_link_ifaces(&def_ifaces);

		list_for_each_entry_safe(iface, tmp, &def_ifaces, list) {
			list_del(&iface->list);
			t = iscsi_sysfs_get_transport_by_name(iface->transport_name);
			/*
			 * only auto bind to software iscsi if it is
			 * not the default iface (that is handled below)
			 */
			if (!t || strcmp(t->name, DEFAULT_TRANSPORT) ||
			    !strcmp(iface->name, DEFAULT_IFACENAME)) {
				free(iface);
				continue;
			}

			rc = idbm_bind_iface_to_node(new_rec, iface,
						     bound_recs);
			free(iface);
			if (rc)
				return rc;
			found = 1;
		}

		/* create default iface with old/default behavior */
		if (!found) {
			struct iface_rec def_iface;

			iface_setup_defaults(&def_iface);
			return idbm_bind_iface_to_node(new_rec, &def_iface,
						       bound_recs);
		}
	} else {
		list_for_each_entry(iface, ifaces, list) {
			if (strcmp(iface->name, DEFAULT_IFACENAME) &&
			    !iface_is_valid(iface)) {
				log_error("iface %s is not valid. Will not "
					  "bind node to it. Iface settings "
					  iface_fmt, iface->name,
					  iface_str(iface));
				continue;
			}

			rc = idbm_bind_iface_to_node(new_rec, iface,
						     bound_recs);
			if (rc)
				return rc;
		}
	}
	return 0;
}

/*
 * remove this when isns is converted
 */
int idbm_add_nodes(node_rec_t *newrec, discovery_rec_t *drec,
		   struct list_head *ifaces, int update)
{
	struct iface_rec *iface, *tmp;
	struct iscsi_transport *t;
	int rc = 0, found = 0;

	if (!ifaces || list_empty(ifaces)) {
		struct list_head def_ifaces;

		INIT_LIST_HEAD(&def_ifaces);
		iface_link_ifaces(&def_ifaces);

		list_for_each_entry_safe(iface, tmp, &def_ifaces, list) {
			list_del(&iface->list);
			t = iscsi_sysfs_get_transport_by_name(iface->transport_name);
			/* only auto bind to software iscsi */
			if (!t || strcmp(t->name, DEFAULT_TRANSPORT) ||
			     !strcmp(iface->name, DEFAULT_IFACENAME)) {
				free(iface);
				continue;
			}

			iface_copy(&newrec->iface, iface);
			rc = idbm_add_node(newrec, drec, update);
			free(iface);
			if (rc)
				return rc;
			found = 1;
		}

		/* create default iface with old/default behavior */
		if (!found) {
			iface_setup_defaults(&newrec->iface);
			return idbm_add_node(newrec, drec, update);
		}
	} else {
		list_for_each_entry(iface, ifaces, list) {
			if (strcmp(iface->name, DEFAULT_IFACENAME) &&
			    !iface_is_valid(iface)) {
				log_error("iface %s is not valid. Will not "
					  "bind node to it. Iface settings "
					  iface_fmt, iface->name,
					  iface_str(iface));
				continue;
			}

			iface_copy(&newrec->iface, iface);
			rc = idbm_add_node(newrec, drec, update);
			if (rc)
				return rc;
		}
	}
	return 0;
}

static void idbm_rm_disc_node_links(char *disc_dir)
{
	char *target = NULL, *tpgt = NULL, *port = NULL;
	char *address = NULL, *iface_id = NULL;
	DIR *disc_dirfd;
	struct dirent *disc_dent;
	node_rec_t *rec;

	rec = calloc(1, sizeof(*rec));
	if (!rec)
		return;

	disc_dirfd = opendir(disc_dir);
	if (!disc_dirfd)
		goto free_rec;

	/* rm links to nodes */
	while ((disc_dent = readdir(disc_dirfd))) {
		if (!strcmp(disc_dent->d_name, ".") ||
		    !strcmp(disc_dent->d_name, ".."))
			continue;


		if (get_params_from_disc_link(disc_dent->d_name, &target, &tpgt,
					      &address, &port, &iface_id)) {
			log_error("Improperly formed disc to node link");
			continue;
		}

		log_debug(5, "disc removal removing link %s %s %s %s",
			  target, address, port, iface_id);

		memset(rec, 0, sizeof(*rec));	
		strncpy(rec->name, target, TARGET_NAME_MAXLEN);
		rec->tpgt = atoi(tpgt);
		rec->conn[0].port = atoi(port);
		strncpy(rec->conn[0].address, address, NI_MAXHOST);
		strncpy(rec->iface.name, iface_id, ISCSI_MAX_IFACE_LEN);

		if (idbm_delete_node(rec))
			log_error("Could not delete node %s/%s/%s,%s/%s",
				  NODE_CONFIG_DIR, target, address, port,
				  iface_id);
 	}

	closedir(disc_dirfd);
free_rec:
	free(rec);
}

int idbm_delete_discovery(discovery_rec_t *drec)
{
	char *portal;
	struct stat statb;
	int rc = 0;

	portal = calloc(1, PATH_MAX);
	if (!portal)
		return ENOMEM;

	snprintf(portal, PATH_MAX, "%s/%s,%d", ST_CONFIG_DIR,
		 drec->address, drec->port);
	log_debug(5, "Removing config file %s\n", portal);

	if (stat(portal, &statb)) {
		log_debug(5, "Could not stat %s to delete disc err %d\n",
			  portal, errno);
		goto free_portal;
	}

	if (S_ISDIR(statb.st_mode)) {
		strncat(portal, "/", PATH_MAX);
		strncat(portal, ST_CONFIG_NAME, PATH_MAX);
	}

	if (unlink(portal))
		log_debug(5, "Could not remove %s err %d\n", portal, errno);

	memset(portal, 0, PATH_MAX);
	snprintf(portal, PATH_MAX, "%s/%s,%d", ST_CONFIG_DIR,
		 drec->address, drec->port);
	idbm_rm_disc_node_links(portal);

	/* rm portal dir */
	if (S_ISDIR(statb.st_mode)) {
		memset(portal, 0, PATH_MAX);
		snprintf(portal, PATH_MAX, "%s/%s,%d", ST_CONFIG_DIR,
			 drec->address, drec->port);
		rmdir(portal);
	}

free_portal:
	free(portal);
	return rc;
}

/*
 * Backwards Compat or SLP:
 * if there is no link then this is pre svn 780 version where
 * we did not link the disc source and node
 */
static int idbm_remove_disc_to_node_link(node_rec_t *rec,
					 char *portal)
{
	int rc = 0;
	struct stat statb;
	node_rec_t *tmprec;

	tmprec = malloc(sizeof(*tmprec));
	if (!tmprec)
		return ENOMEM;

	memset(portal, 0, PATH_MAX);
	snprintf(portal, PATH_MAX, "%s/%s/%s,%d,%d/%s", NODE_CONFIG_DIR,
		 rec->name, rec->conn[0].address, rec->conn[0].port, rec->tpgt,
		 rec->iface.name);

	rc = __idbm_rec_read(tmprec, portal);
	if (rc) {
		/* old style recs will not have tpgt or a link so skip */
		rc = 0;
		goto done;
	}

	log_debug(7, "found drec %s %d\n", tmprec->disc_address,
		 tmprec->disc_port); 
	/* rm link from discovery source to node */
	memset(portal, 0, PATH_MAX);
	rc = setup_disc_to_node_link(portal, tmprec);
	if (rc)
		goto done;

	idbm_lock();
	if (!stat(portal, &statb)) {
		if (unlink(portal)) {
			log_error("Could not remove link %s err %d\n",
				  portal, errno);
			rc = errno;
		} else
			log_debug(7, "rmd %s", portal);
	} else
		log_debug(7, "Could not stat %s", portal);
	idbm_unlock();

done:
	free(tmprec);
	return rc;
}

int idbm_delete_node(node_rec_t *rec)
{
	struct stat statb;
	char *portal;
	int rc = 0, dir_rm_rc = 0;

	portal = calloc(1, PATH_MAX);
	if (!portal)
		return ENOMEM;

	rc = idbm_remove_disc_to_node_link(rec, portal);
	if (rc)
		goto free_portal;

	memset(portal, 0, PATH_MAX);
	snprintf(portal, PATH_MAX, "%s/%s/%s,%d", NODE_CONFIG_DIR,
		 rec->name, rec->conn[0].address, rec->conn[0].port);
	log_debug(5, "Removing config file %s iface id %s\n",
		  portal, rec->iface.name);

	idbm_lock();
	if (!stat(portal, &statb))
		goto rm_conf;

	snprintf(portal, PATH_MAX, "%s/%s/%s,%d,%d/%s", NODE_CONFIG_DIR,
		 rec->name, rec->conn[0].address, rec->conn[0].port,
		 rec->tpgt, rec->iface.name);
	log_debug(5, "Removing config file %s", portal);

	if (!stat(portal, &statb))
		goto rm_conf;

	log_error("Could not stat %s to delete node err %d\n",
		  portal, errno);
	rc = errno;
	goto unlock;

rm_conf:
	if (unlink(portal)) {
		log_error("Could not remove %s err %d\n", portal, errno);
		rc = errno;
		goto unlock;
	}

	memset(portal, 0, PATH_MAX);
	snprintf(portal, PATH_MAX, "%s/%s/%s,%d,%d", NODE_CONFIG_DIR,
		 rec->name, rec->conn[0].address, rec->conn[0].port,
		 rec->tpgt);
	if (!stat(portal, &statb)) {
		struct dirent **namelist;
		int n, i;

		memset(portal, 0, PATH_MAX);
		snprintf(portal, PATH_MAX, "%s/%s/%s,%d,%d", NODE_CONFIG_DIR,
			 rec->name, rec->conn[0].address, rec->conn[0].port,
			 rec->tpgt);
		n = scandir(portal, &namelist, st_disc_filter, direntcmp);
		if (n < 0)
			goto free_portal;
		if (n == 0)
			dir_rm_rc = rmdir(portal);

		for (i = 0; i < n; i++)
			free(namelist[i]);
		free(namelist);
	}
	/* rm target dir */
	if (!dir_rm_rc) {
		memset(portal, 0, PATH_MAX);
		snprintf(portal, PATH_MAX, "%s/%s", NODE_CONFIG_DIR, rec->name);
		rmdir(portal);
	}
unlock:
	idbm_unlock();
free_portal:
	free(portal);
	return rc;
}

void
idbm_sendtargets_defaults(struct iscsi_sendtargets_config *cfg)
{
	idbm_sync_config();
	memcpy(cfg, &db->drec_st.u.sendtargets,
	       sizeof(struct iscsi_sendtargets_config));
}

void
idbm_slp_defaults(struct iscsi_slp_config *cfg)
{
	memcpy(cfg, &db->drec_slp.u.slp,
	       sizeof(struct iscsi_slp_config));
}

int idbm_node_set_param(void *data, node_rec_t *rec)
{
	struct db_set_param *param = data;
	recinfo_t *info;
	int rc = 0;

	info = idbm_recinfo_alloc(MAX_KEYS);
	if (!info)
		return ENOMEM;

	idbm_recinfo_node(rec, info);

	rc = idbm_verify_param(info, param->name);
	if (rc)
		goto free_info;

	rc = idbm_rec_update_param(info, param->name, param->value, 0);
	if (rc)
		goto free_info;

	rc = idbm_rec_write(rec);
	if (rc)
		goto free_info;

free_info:
	free(info);
	return rc;
}

int idbm_init(idbm_get_config_file_fn *fn)
{
	/* make sure root db dir is there */
	if (access(ISCSI_CONFIG_ROOT, F_OK) != 0) {
		if (mkdir(ISCSI_CONFIG_ROOT, 0660) != 0) {
			log_error("Could not make %s %d\n", ISCSI_CONFIG_ROOT,
				   errno);
			return errno;
		}
	}

	db = malloc(sizeof(idbm_t));
	if (!db) {
		log_error("out of memory on idbm allocation");
		return ENOMEM;
	}
	memset(db, 0, sizeof(idbm_t));
	db->get_config_file = fn;
	return 0;
}

void idbm_terminate(void)
{
	if (db)
		free(db);
}
