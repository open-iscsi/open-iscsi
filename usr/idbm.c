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
#include <fcntl.h>
#include <errno.h>
#include <stdarg.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/types.h>

#include "idbm.h"
#include "log.h"
#include "util.h"
#include "iscsi_settings.h"

#define IDBM_HIDE	0    /* Hide parameter when print. */
#define IDBM_SHOW	1    /* Show parameter when print. */
#define IDBM_MASKED	2    /* Show "stars" instead of real value when print */

#define __recinfo_str(_key, _info, _rec, _name, _show, _n) do { \
	_info[_n].type = TYPE_STR; \
	strncpy(_info[_n].name, _key, NAME_MAXVAL); \
	if (strlen((char*)_rec->_name)) \
		strncpy((char*)_info[_n].value, (char*)_rec->_name, \
			VALUE_MAXVAL); \
	_info[_n].data = &_rec->_name; \
	_info[_n].data_len = sizeof(_rec->_name); \
	_info[_n].visible = _show; \
	_n++; \
} while(0)

#define __recinfo_int(_key, _info, _rec, _name, _show, _n) do { \
	_info[_n].type = TYPE_INT; \
	strncpy(_info[_n].name, _key, NAME_MAXVAL); \
	snprintf(_info[_n].value, VALUE_MAXVAL, "%d", _rec->_name); \
	_info[_n].data = &_rec->_name; \
	_info[_n].data_len = sizeof(_rec->_name); \
	_info[_n].visible = _show; \
	_n++; \
} while(0)

#define __recinfo_int_o2(_key,_info,_rec,_name,_show,_op0,_op1,_n) do { \
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
	_n++; \
} while(0)

#define __recinfo_int_o3(_key,_info,_rec,_name,_show,_op0,_op1,_op2,_n)do{ \
	__recinfo_int_o2(_key,_info,_rec,_name,_show,_op0,_op1,_n); _n--; \
	if (_rec->_name == 2) strncpy(_info[_n].value, _op2, VALUE_MAXVAL); \
	_info[_n].opts[2] = _op2; \
	_info[_n].numopts = 3; \
	_n++; \
} while(0)

#define __recinfo_int_o4(_key,_info,_rec,_name,_show,_op0,_op1,_op2,_op3,_n)do{\
	__recinfo_int_o3(_key,_info,_rec,_name,_show,_op0,_op1,_op2,_n); _n--; \
	if (_rec->_name == 3) strncpy(_info[_n].value, _op3, VALUE_MAXVAL); \
	_info[_n].opts[3] = _op3; \
	_info[_n].numopts = 4; \
	_n++; \
} while(0)

static char *get_global_string_param(char *pathname, const char *key)
{
	FILE *f = NULL;
	int c, len;
	char *line, buffer[1024];
	char *name = NULL;

	if (!pathname) {
		log_error("No pathname to load %s from", key);
		return NULL;
	}

	len = strlen(key);
	if ((f = fopen(pathname, "r"))) {
		while ((line = fgets(buffer, sizeof (buffer), f))) {

			while (line && isspace(c = *line))
				line++;

			if (strncmp(line, key, len) == 0) {
				char *end = line + len;

				/* the name is everything up to the first
				 * bit of whitespace
				 */
				while (*end && (!isspace(c = *end)))
					end++;

				if (isspace(c = *end))
					*end = '\0';

				if (end > line + len)
					name = strdup(line + len);
			}
		}
		fclose(f);
		if (!name)
			log_error("an %s is required, but was not found in %s",
				  key, pathname);
		else
			log_debug(5, "%s=%s", key, name);
	} else
		log_error("can't open %s configuration file %s", key, pathname);

	return name;
}

char *get_iscsi_initiatorname(char *pathname)
{
	return get_global_string_param(pathname, "InitiatorName=");
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
			"manual", "automatic", num);
	__recinfo_int_o3("discovery.type", ri, r, type, IDBM_SHOW,
			"sendtargets", "slp", "isns", num);
	if (r->type == DISCOVERY_TYPE_SENDTARGETS) {
		__recinfo_str("discovery.sendtargets.address", ri, r,
			address, IDBM_SHOW, num);
		__recinfo_int("discovery.sendtargets.port", ri, r,
			port, IDBM_SHOW, num);
		__recinfo_int_o2("discovery.sendtargets.auth.authmethod", ri, r,
			u.sendtargets.auth.authmethod,
			IDBM_SHOW, "None", "CHAP", num);
		__recinfo_str("discovery.sendtargets.auth.username", ri, r,
			u.sendtargets.auth.username, IDBM_SHOW, num);
		__recinfo_str("discovery.sendtargets.auth.password", ri, r,
			u.sendtargets.auth.password, IDBM_MASKED, num);
		__recinfo_int("discovery.sendtargets.auth.password_length",
			ri, r, u.sendtargets.auth.password_length,
			IDBM_HIDE, num);
		__recinfo_str("discovery.sendtargets.auth.username_in", ri, r,
			u.sendtargets.auth.username_in, IDBM_SHOW, num);
		__recinfo_str("discovery.sendtargets.auth.password_in", ri, r,
			u.sendtargets.auth.password_in, IDBM_MASKED, num);
		__recinfo_int("discovery.sendtargets.auth.password_in_length",
			ri, r, u.sendtargets.auth.password_in_length,
			IDBM_HIDE, num);
		__recinfo_int("discovery.sendtargets.timeo.login_timeout",ri, r,
			u.sendtargets.conn_timeo.login_timeout,
			IDBM_SHOW, num);
		__recinfo_int("discovery.sendtargets.reopen_max",ri, r,
			u.sendtargets.reopen_max,
			IDBM_SHOW, num);
		__recinfo_int("discovery.sendtargets.timeo.auth_timeout", ri, r,
			u.sendtargets.conn_timeo.auth_timeout,
			IDBM_SHOW, num);
		__recinfo_int("discovery.sendtargets.timeo.active_timeout",ri,r,
			u.sendtargets.conn_timeo.active_timeout,
			IDBM_SHOW, num);
		__recinfo_int("discovery.sendtargets.timeo.idle_timeout", ri, r,
			u.sendtargets.conn_timeo.idle_timeout,
			IDBM_SHOW, num);
		__recinfo_int("discovery.sendtargets.iscsi.MaxRecvDataSegmentLength",
			ri, r, u.sendtargets.iscsi.MaxRecvDataSegmentLength,
			IDBM_SHOW, num);
	}
}

static void
idbm_recinfo_node(node_rec_t *r, recinfo_t *ri)
{
	int num = 0, i;

	__recinfo_str("node.name", ri, r, name, IDBM_SHOW, num);
	__recinfo_str("node.transport_name", ri, r, transport_name,
		      IDBM_SHOW, num);
	__recinfo_int("node.tpgt", ri, r, tpgt, IDBM_SHOW, num);
	__recinfo_int_o3("node.startup", ri, r, startup,
			IDBM_SHOW, "manual", "automatic", "onboot", num);
	__recinfo_str("iface.name", ri, r, iface.name, IDBM_SHOW, num);
	__recinfo_str("node.discovery_address", ri, r, disc_address, IDBM_SHOW,
		      num);
	__recinfo_int("node.discovery_port", ri, r, disc_port, IDBM_SHOW, num);
	__recinfo_int_o4("node.discovery_type", ri, r, disc_type,
			 IDBM_SHOW, "send_targets", "slp", "isns", "static",
			 num);
	__recinfo_int("node.session.initial_cmdsn", ri, r,
		      session.initial_cmdsn, IDBM_SHOW, num);
	__recinfo_int("node.session.cmds_max", ri, r,
		      session.cmds_max, IDBM_SHOW, num);
	__recinfo_int("node.session.queue_depth", ri, r,
		       session.queue_depth, IDBM_SHOW, num);
	__recinfo_int_o2("node.session.auth.authmethod", ri, r,
		session.auth.authmethod, IDBM_SHOW, "None", "CHAP", num);
	__recinfo_str("node.session.auth.username", ri, r,
		      session.auth.username, IDBM_SHOW, num);
	__recinfo_str("node.session.auth.password", ri, r,
		      session.auth.password, IDBM_MASKED, num);
	__recinfo_int("node.session.auth.password_length", ri, r,
		      session.auth.password_length, IDBM_HIDE, num);
	__recinfo_str("node.session.auth.username_in", ri, r,
		      session.auth.username_in, IDBM_SHOW, num);
	__recinfo_str("node.session.auth.password_in", ri, r,
		      session.auth.password_in, IDBM_MASKED, num);
	__recinfo_int("node.session.auth.password_in_length", ri, r,
		      session.auth.password_in_length, IDBM_HIDE, num);
	__recinfo_int("node.session.timeo.replacement_timeout", ri, r,
		      session.timeo.replacement_timeout,
		      IDBM_SHOW, num);
	__recinfo_int("node.session.err_timeo.abort_timeout", ri, r,
		      session.err_timeo.abort_timeout,
		      IDBM_SHOW, num);
	__recinfo_int("node.session.err_timeo.reset_timeout", ri, r,
		      session.err_timeo.reset_timeout,
		      IDBM_SHOW, num);
	__recinfo_int_o2("node.session.iscsi.InitialR2T", ri, r,
			 session.iscsi.InitialR2T, IDBM_SHOW,
			"No", "Yes", num);
	__recinfo_int_o2("node.session.iscsi.ImmediateData",
			 ri, r, session.iscsi.ImmediateData, IDBM_SHOW,
			"No", "Yes", num);
	__recinfo_int("node.session.iscsi.FirstBurstLength", ri, r,
		      session.iscsi.FirstBurstLength, IDBM_SHOW, num);
	__recinfo_int("node.session.iscsi.MaxBurstLength", ri, r,
		      session.iscsi.MaxBurstLength, IDBM_SHOW, num);
	__recinfo_int("node.session.iscsi.DefaultTime2Retain", ri, r,
		      session.iscsi.DefaultTime2Retain, IDBM_SHOW, num);
	__recinfo_int("node.session.iscsi.DefaultTime2Wait", ri, r,
		      session.iscsi.DefaultTime2Wait, IDBM_SHOW, num);
	__recinfo_int("node.session.iscsi.MaxConnections", ri, r,
		      session.iscsi.MaxConnections, IDBM_SHOW, num);
	__recinfo_int("node.session.iscsi.MaxOutstandingR2T", ri, r,
		      session.iscsi.MaxOutstandingR2T, IDBM_SHOW, num);
	__recinfo_int("node.session.iscsi.ERL", ri, r,
		      session.iscsi.ERL, IDBM_SHOW, num);

	for (i = 0; i < ISCSI_CONN_MAX; i++) {
		char key[NAME_MAXVAL];

		sprintf(key, "node.conn[%d].address", i);
		__recinfo_str(key, ri, r, conn[i].address, IDBM_SHOW, num);
		sprintf(key, "node.conn[%d].port", i);
		__recinfo_int(key, ri, r, conn[i].port, IDBM_SHOW, num);
		sprintf(key, "node.conn[%d].startup", i);
		__recinfo_int_o3(key, ri, r, conn[i].startup, IDBM_SHOW,
				 "manual", "automatic", "onboot", num);
		sprintf(key, "node.conn[%d].tcp.window_size", i);
		__recinfo_int(key, ri, r, conn[i].tcp.window_size,
			      IDBM_SHOW, num);
		sprintf(key, "node.conn[%d].tcp.type_of_service", i);
		__recinfo_int(key, ri, r, conn[i].tcp.type_of_service,
				IDBM_SHOW, num);
		sprintf(key, "node.conn[%d].timeo.logout_timeout", i);
		__recinfo_int(key, ri, r, conn[i].timeo.logout_timeout,
				IDBM_SHOW, num);
		sprintf(key, "node.conn[%d].timeo.login_timeout", i);
		__recinfo_int(key, ri, r, conn[i].timeo.login_timeout,
				IDBM_SHOW, num);
		sprintf(key, "node.conn[%d].timeo.auth_timeout", i);
		__recinfo_int(key, ri, r, conn[i].timeo.auth_timeout,
				IDBM_SHOW, num);
		sprintf(key, "node.conn[%d].timeo.active_timeout", i);
		__recinfo_int(key, ri, r, conn[i].timeo.active_timeout,
				IDBM_SHOW, num);
		sprintf(key, "node.conn[%d].timeo.idle_timeout", i);
		__recinfo_int(key, ri, r, conn[i].timeo.idle_timeout,
				IDBM_SHOW, num);
		sprintf(key, "node.conn[%d].timeo.ping_timeout", i);
		__recinfo_int(key, ri, r, conn[i].timeo.ping_timeout,
				IDBM_SHOW, num);

		sprintf(key, "node.conn[%d].timeo.noop_out_interval", i);
		__recinfo_int(key, ri, r, conn[i].timeo.noop_out_interval,
				IDBM_SHOW, num);
		sprintf(key, "node.conn[%d].timeo.noop_out_timeout", i);
		__recinfo_int(key, ri, r, conn[i].timeo.noop_out_timeout,
				IDBM_SHOW, num);

		sprintf(key, "node.conn[%d].iscsi.MaxRecvDataSegmentLength", i);
		__recinfo_int(key, ri, r,
			conn[i].iscsi.MaxRecvDataSegmentLength, IDBM_SHOW, num);
		sprintf(key, "node.conn[%d].iscsi.HeaderDigest", i);
		__recinfo_int_o4(key, ri, r, conn[i].iscsi.HeaderDigest,
				 IDBM_SHOW, "None", "CRC32C", "CRC32C,None",
				 "None,CRC32C", num);
		sprintf(key, "node.conn[%d].iscsi.DataDigest", i);
		__recinfo_int_o4(key, ri, r, conn[i].iscsi.DataDigest, IDBM_SHOW,
				 "None", "CRC32C", "CRC32C,None",
				 "None,CRC32C", num);
		sprintf(key, "node.conn[%d].iscsi.IFMarker", i);
		__recinfo_int_o2(key, ri, r, conn[i].iscsi.IFMarker, IDBM_SHOW,
				"No", "Yes", num);
		sprintf(key, "node.conn[%d].iscsi.OFMarker", i);
		__recinfo_int_o2(key, ri, r, conn[i].iscsi.OFMarker, IDBM_SHOW,
				"No", "Yes", num);
	}
}

static void
idbm_recinfo_iface(iface_rec_t *r, recinfo_t *ri)
{
	int num = 0, i;
	char key[NAME_MAXVAL];

	for (i = 0; i < ISCSI_IFACE_MAX; i++) {
		sprintf(key, "iface[%d].name", i);
		__recinfo_str(key, ri, (&r[i]), name, IDBM_SHOW, num);
	}
}

static recinfo_t*
idbm_recinfo_alloc(int max_keys)
{
	recinfo_t *info;

	info = malloc(sizeof(recinfo_t)*max_keys);
	if (!info)
		return NULL;
	memset(info, 0, sizeof(recinfo_t)*max_keys);
	return info;
}

#define PRINT_TYPE_DISCOVERY	0
#define PRINT_TYPE_NODE		1
static void
idbm_print(int type, void *rec, int show, FILE *f)
{
	int i;
	recinfo_t *info;

	info = idbm_recinfo_alloc(MAX_KEYS);
	if (!info)
		return;

	if (type == PRINT_TYPE_DISCOVERY) {
		idbm_recinfo_discovery((discovery_rec_t*)rec, info);
	} else {
		idbm_recinfo_node((node_rec_t*)rec, info);
	}

	for (i=0; i<MAX_KEYS; i++) {
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
idbm_interface_setup_defaults(iface_rec_t *rec)
{
	sprintf(rec[0].name, "default");
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
		rec->u.sendtargets.conn_timeo.idle_timeout = 60;	
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

static int
idbm_node_update_param(recinfo_t *info, char *name, char *value,
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

static void
idbm_recinfo_config(recinfo_t *info, FILE *f)
{
	char name[NAME_MAXVAL];
	char value[VALUE_MAXVAL];
	char *line, *nl, buffer[2048];
	int line_number = 0;
	int c, i;

	fseek(f, 0, SEEK_SET);

	/* process the config file */
	do {
		line = fgets(buffer, sizeof (buffer), f);
		line_number++;
		if (!line)
			continue;

		/* skip leading whitespace */
		while (isspace(c = *line))
			line++;

		/* strip trailing whitespace, including the newline.
		 * anything that needs the whitespace must be quoted.
		 */
		nl = line + strlen(line) - 1;
		if (*nl == '\n') {
			do {
				*nl = '\0';
				nl--;
			} while (isspace(c = *nl));
		} else {
			log_warning("config file line %d too long",
			       line_number);
			continue;
		}

		/* process any non-empty, non-comment lines */
		if (!*line || *line == '#')
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

		(void)idbm_node_update_param(info, name, value, line_number);
	} while (line);
}

/*
 * TODO: remove db's copy of nrec and infos
 */
static void
idbm_sync_config(idbm_t *db)
{
	FILE *f;

	/* in case of no configuration file found we just
	 * initialize default node and default discovery records
	 * from hard-coded default values */
	idbm_node_setup_defaults(&db->nrec);
	idbm_interface_setup_defaults(db->irec_iface);
	idbm_discovery_setup_defaults(&db->drec_st, DISCOVERY_TYPE_SENDTARGETS);
	idbm_discovery_setup_defaults(&db->drec_slp, DISCOVERY_TYPE_SLP);
	idbm_discovery_setup_defaults(&db->drec_isns, DISCOVERY_TYPE_ISNS);

	idbm_recinfo_discovery(&db->drec_st, db->dinfo_st);
	idbm_recinfo_discovery(&db->drec_slp, db->dinfo_slp);
	idbm_recinfo_discovery(&db->drec_isns, db->dinfo_isns);
	idbm_recinfo_node(&db->nrec, db->ninfo);
	idbm_recinfo_iface(db->irec_iface, db->iinfo);

	f = fopen(db->configfile, "r");
	if (!f) {
		log_debug(1, "cannot open configuration file %s. "
			  "Default location is %s.\n",
			  db->configfile, CONFIG_FILE);
		return;
	}

	log_debug(5, "updating defaults from '%s'", db->configfile);

	idbm_recinfo_config(db->dinfo_st, f);
	idbm_recinfo_config(db->dinfo_slp, f);
	idbm_recinfo_config(db->dinfo_isns, f);
	idbm_recinfo_config(db->ninfo, f);
	idbm_recinfo_config(db->iinfo, f);
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

void idbm_node_setup_from_conf(idbm_t *db, node_rec_t *rec)
{
	memset(rec, 0, sizeof(*rec));
	idbm_node_setup_defaults(rec);
	idbm_sync_config(db);
	memcpy(rec, &db->nrec, sizeof(*rec));
}

int idbm_print_discovery_info(idbm_t *db, discovery_rec_t *rec, int show)
{
	idbm_print(PRINT_TYPE_DISCOVERY, rec, show, stdout);
	return 1;
}

int idbm_print_node_info(idbm_t *db, void *data, node_rec_t *rec)
{
	int show = *((int *)data);

	idbm_print(PRINT_TYPE_NODE, rec, show, stdout);
	return 0;
}

int idbm_print_node_flat(idbm_t *db, void *data, node_rec_t *rec)
{
	if (strchr(rec->conn[0].address, '.'))
		printf("%s:%d,%d %s\n", rec->conn[0].address, rec->conn[0].port,
			rec->tpgt, rec->name);
	else
		printf("[%s]:%d,%d %s\n", rec->conn[0].address,
		       rec->conn[0].port, rec->tpgt, rec->name);
	return 0;
}

int idbm_print_node_tree(idbm_t *db, void *data, node_rec_t *rec)
{
	node_rec_t *last_rec = data;

	if (strcmp(last_rec->name, rec->name)) {
		printf("Target: %s\n", rec->name);
		memset(last_rec, 0, sizeof(node_rec_t));
	}

	if ((strcmp(last_rec->conn[0].address, rec->conn[0].address) ||
	     last_rec->conn[0].port != rec->conn[0].port)) {
		if (strchr(rec->conn[0].address, '.'))
			printf("\tPortal: %s:%d,%d\n", rec->conn[0].address,
			       rec->conn[0].port, rec->tpgt);
		else
			printf("\tPortal: [%s]:%d,%d\n", rec->conn[0].address,
			       rec->conn[0].port, rec->tpgt);
	}

	printf("\t\tDriver: %s\n", rec->transport_name);
	printf("\t\tHWaddress: %s\n", rec->iface.name);

	memcpy(last_rec, rec, sizeof(node_rec_t));
	return 0;
}

static int
get_params_from_disc_link(char *link, char **target, char **tpgt,
			  char **address, char **port, char **iface,
			  char **driver)
{
	(*target) = link;
	*tpgt = strchr((*target), ',');
	if (!tpgt)
		return EINVAL;
	*(*tpgt)++ = '\0';
	*address = strchr(*tpgt, ',');
	if (!(*address))
		return EINVAL;
	*(*address)++ = '\0';
	*port = strchr(*address, ',');
	if (!(*port))
		return EINVAL;
	*(*port)++ = '\0';
	*iface = strchr(*port, ',');
	if (!(*iface))
		return EINVAL;
	*(*iface)++ = '\0';
	*driver = strchr(*iface, ',');
	if (!(*driver))
		return EINVAL;
	*(*driver)++ = '\0';
	return 0;
}

static int st_disc_filter(const struct dirent *dir)
{
	return strcmp(dir->d_name, ".") && strcmp(dir->d_name, "..") &&
	       strcmp(dir->d_name, ST_CONFIG_NAME);
}

static int print_discovered(char *disc_path, int info_level)
{
	char *tmp_port = NULL, *last_address = NULL, *last_target = NULL;
	char *target = NULL, *tpgt = NULL, *address = NULL, *iface = NULL;
	char *driver = NULL;
	int n, i, last_port = -1;
	struct dirent **namelist;

	n = scandir(disc_path, &namelist, st_disc_filter, versionsort);
	if (n < 0)
		return 0;

	for (i = 0; i < n; i++) {
		if (get_params_from_disc_link(namelist[i]->d_name, &target,
					      &tpgt, &address, &tmp_port,
					      &iface, &driver)) {
			log_error("Improperly formed disc to node link");
			continue;
		}

		if (info_level < 1) {
			if (strchr(address, '.'))
				printf("%s:%d,%d %s\n", address, atoi(tmp_port),
					atoi(tpgt), target);
			else
				printf("[%s]:%d,%d %s\n", address,
					atoi(tmp_port), atoi(tpgt), target);
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
					last_port, atoi(tpgt));
			else
				printf("Portal: [%s]:%d,%d\n", address,
					last_port, atoi(tpgt));
			last_address = namelist[i]->d_name +
					strlen(namelist[i]->d_name) + 1;
		}

		printf("           Driver: %s\n", driver);
		printf("           HWaddress: %s\n", iface);
	}

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

static int idbm_print_all_st(idbm_t *db, int info_level)
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

int idbm_print_all_discovery(idbm_t *db, int info_level)
{
	discovery_rec_t *drec;
	int found = 0, tmp;

	if (info_level < 1)
		return idbm_print_all_st(db, info_level);

	drec = calloc(1, sizeof(*drec));
	if (!drec)
		return ENOMEM;

	tmp = 0;
	printf("SENDTARGETS:\n");
	tmp = idbm_print_all_st(db, info_level);
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

int idbm_for_each_iface(idbm_t *db, void *data, idbm_iface_op_fn *fn,
			char *targetname, char *ip, int port)
{
	DIR *iface_dirfd;
	struct dirent *iface_dent;
	struct stat statb;
	node_rec_t rec;
	int found = 0;
	char *config;

	config = calloc(1, PATH_MAX);
	if (!config)
		return 0;

	sprintf(config, "%s/%s/%s,%d", NODE_CONFIG_DIR, targetname, ip, port);
	if (stat(config, &statb)) {
		log_error("iface iter could not stat %s\n", config);
		goto done;
	}

	if (!S_ISDIR(statb.st_mode)) {
		if (idbm_node_read(db, &rec, targetname, ip, port, "default"))
			goto done;

		fn(db, data, &rec);
		found = 1;
		goto done;
	}

	iface_dirfd = opendir(config);
	if (!iface_dirfd)
		goto done;

	while ((iface_dent = readdir(iface_dirfd))) {
		if (!strcmp(iface_dent->d_name, ".") ||
		    !strcmp(iface_dent->d_name, ".."))
			continue;

		log_debug(5, "found %s\n", iface_dent->d_name);
		if (idbm_node_read(db, &rec, targetname, ip, port,
				   iface_dent->d_name))
			continue;

		fn(db, data, &rec);
		found++;
	}

	closedir(iface_dirfd);
done:
	free(config);
	return found;
}

/*
 * backwards compat
 * The portal could be a file or dir with interfaces
 */
int idbm_for_each_portal(idbm_t *db, void *data, idbm_portal_op_fn *fn,
			 char *targetname)
{
	DIR *portal_dirfd;
	struct dirent *portal_dent;
	int found = 0;
	char *portal;

	portal = calloc(1, PATH_MAX);
	if (!portal)
		return 0;

	sprintf(portal, "%s/%s", NODE_CONFIG_DIR, targetname);
	portal_dirfd = opendir(portal);
	if (!portal_dirfd)
		goto done;

	while ((portal_dent = readdir(portal_dirfd))) {
		char *tmp_port;

		if (!strcmp(portal_dent->d_name, ".") ||
		    !strcmp(portal_dent->d_name, ".."))
			continue;

		log_debug(5, "found %s\n", portal_dent->d_name);
		tmp_port = strchr(portal_dent->d_name, ',');
		if (!tmp_port)
			continue;
		*tmp_port++ = '\0';

		found += fn(db, data, targetname, portal_dent->d_name,
			    atoi(tmp_port));
	}
	closedir(portal_dirfd);
done:
	free(portal);
	return found;
}

int idbm_for_each_node(idbm_t *db, void *data, idbm_node_op_fn *fn)
{
	DIR *node_dirfd;
	struct dirent *node_dent;
	int found = 0;

	node_dirfd = opendir(NODE_CONFIG_DIR);
	if (!node_dirfd)
		return 0;

	while ((node_dent = readdir(node_dirfd))) {
		if (!strcmp(node_dent->d_name, ".") ||
		    !strcmp(node_dent->d_name, ".."))
			continue;

		log_debug(5, "searching %s\n", node_dent->d_name);
		found += fn(db, data, node_dent->d_name);
	}

	closedir(node_dirfd);
	return found;
}

static int iface_fn(idbm_t *db, void *data, node_rec_t *rec)
{
	struct rec_op_data *op_data = data;

	return op_data->fn(db, op_data->data, rec);
}

static int portal_fn(idbm_t *db, void *data, char *targetname,
		     char *ip, int port)
{
	return idbm_for_each_iface(db, data, iface_fn, targetname, ip, port);
}

static int node_fn(idbm_t *db, void *data, char *targetname)
{
	return idbm_for_each_portal(db, data, portal_fn, targetname);
}

int idbm_for_each_rec(idbm_t *db, void *data, idbm_iface_op_fn *fn)
{
	struct rec_op_data op_data;

	memset(&op_data, 0, sizeof(struct rec_op_data));
	op_data.data = data;
	op_data.fn = fn;

	return idbm_for_each_node(db, &op_data, node_fn);
}

static int idbm_lock(idbm_t *db)
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

static void idbm_unlock(idbm_t *db)
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
static FILE *idbm_open_node_rec_r(char *portal, char *config)
{
	struct stat statb;

	log_debug(5, "Looking for config file %s config %s\n", portal, config);

	if (stat(portal, &statb)) {
		log_debug(5, "Could not stat %s err %d\n", portal, errno);
		return NULL;
	}

	if (S_ISDIR(statb.st_mode)) {
		strncat(portal, "/", PATH_MAX);
		strncat(portal, config, PATH_MAX);
	}
	return fopen(portal, "r");
}

int
idbm_discovery_read(idbm_t *db, discovery_rec_t *out_rec, char *addr, int port)
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

	idbm_lock(db);

	f = idbm_open_node_rec_r(portal, ST_CONFIG_NAME);
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
	idbm_unlock(db);
free_info:
	free(portal);
	free(info);
	return rc;
}

int
idbm_node_read(idbm_t *db, node_rec_t *out_rec, char *target_name,
	       char *addr, int port, char *iface)
{
	recinfo_t *info;
	char *portal;
	int rc = 0;
	FILE *f;

	memset(out_rec, 0, sizeof(node_rec_t));

	info = idbm_recinfo_alloc(MAX_KEYS);
	if (!info)
		return ENOMEM;

	portal = malloc(PATH_MAX);
	if (!portal)
		goto free_info;
	snprintf(portal, PATH_MAX, "%s/%s/%s,%d", NODE_CONFIG_DIR,
		 target_name, addr, port);

	idbm_lock(db);
	f = idbm_open_node_rec_r(portal, iface);
	if (!f) {
		log_debug(5, "Could not open %s err %d\n", portal, errno);
		rc = errno;
		goto unlock;
	}

	idbm_node_setup_defaults(out_rec);
	idbm_recinfo_node(out_rec, info);
	idbm_recinfo_config(info, f);
	fclose(f);

unlock:
	idbm_unlock(db);
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
static FILE *idbm_open_node_rec_w(char *portal, char *config)
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

static int idbm_node_write(idbm_t *db, node_rec_t *rec)
{
	FILE *f;
	char *portal;
	int rc = 0;

	portal = malloc(PATH_MAX);
	if (!portal) {
		log_error("Could not alloc portal\n");
		return ENOMEM;
	}

	idbm_lock(db);

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
	log_debug(5, "Looking for config file %s iface %s\n", portal,
		  rec->iface.name);

	f = idbm_open_node_rec_w(portal, rec->iface.name);
	if (!f) {
		rc = errno;
		goto free_portal;
	}

	idbm_print(PRINT_TYPE_NODE, rec, 1, f);
	fclose(f);
free_portal:
	idbm_unlock(db);
	free(portal);
	return rc;
}

static int
idbm_discovery_write(idbm_t *db, discovery_rec_t *rec)
{
	FILE *f;
	char *portal;
	int rc = 0;

	portal = malloc(PATH_MAX);
	if (!portal) {
		log_error("Could not alloc portal\n");
		return -ENOMEM;
	}

	idbm_lock(db);
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

	f = idbm_open_node_rec_w(portal, ST_CONFIG_NAME);
	if (!f) {
		log_error("Could not open %s err %d\n", portal, errno);
		rc = errno;
		goto free_portal;
	}

	idbm_print(PRINT_TYPE_DISCOVERY, rec, 1, f);
	fclose(f);
free_portal:
	idbm_unlock(db);
	free(portal);
	return rc;
}

static int
idbm_add_discovery(idbm_t *db, discovery_rec_t *newrec)
{
	discovery_rec_t rec;
	int rc;

	idbm_lock(db);
	if (!idbm_discovery_read(db, &rec, newrec->address,
				newrec->port)) {
		log_debug(7, "overwriting existing record");
	} else
		log_debug(7, "adding new DB record");

	rc = idbm_discovery_write(db, newrec);
	idbm_unlock(db);
	return rc;
}

static int setup_disc_to_node_link(char *disc_portal, node_rec_t *rec)
{
	int rc = 0;

	switch (rec->disc_type) {
	case DISCOVERY_TYPE_SENDTARGETS:
		/* st dir setup when we create its discovery node */
		snprintf(disc_portal, PATH_MAX, "%s/%s,%d/%s,%d,%s,%d,%s,%s",
			 ST_CONFIG_DIR,
			 rec->disc_address, rec->disc_port, rec->name,
			 rec->tpgt, rec->conn[0].address, rec->conn[0].port,
			 rec->iface.name, rec->transport_name);
		break;
	case DISCOVERY_TYPE_STATIC:
		if (access(STATIC_CONFIG_DIR, F_OK) != 0) {
			if (mkdir(STATIC_CONFIG_DIR, 0660) != 0) {
				log_error("Could not make %s\n",
					  STATIC_CONFIG_DIR);
				rc = errno;
			}
		}

		snprintf(disc_portal, PATH_MAX, "%s/%s,%s,%d,%s,%s",
			 STATIC_CONFIG_DIR, rec->name,
			 rec->conn[0].address, rec->conn[0].port,
			 rec->iface.name, rec->transport_name);
		break;
	case DISCOVERY_TYPE_ISNS:
		if (access(ISNS_CONFIG_DIR, F_OK) != 0) {
			if (mkdir(ISNS_CONFIG_DIR, 0660) != 0) {
				log_error("Could not make %s\n",
					  ISNS_CONFIG_DIR);
				rc = errno;
			}
		}

		snprintf(disc_portal, PATH_MAX, "%s/%s,%d/%s,%d,%s,%d,%s,%s",
			 ISNS_CONFIG_DIR, rec->disc_address, rec->disc_port,
			 rec->name, rec->tpgt, rec->conn[0].address,
			 rec->conn[0].port, rec->iface.name,
			 rec->transport_name);
		break;
	case DISCOVERY_TYPE_SLP:
	default:
		rc = EINVAL;
	}

	return rc;
}

int idbm_add_node(idbm_t *db, node_rec_t *newrec, discovery_rec_t *drec)
{
	node_rec_t rec;
	char *node_portal, *disc_portal;
	int rc;

	idbm_lock(db);
	if (!idbm_node_read(db, &rec, newrec->name, newrec->conn[0].address,
			    newrec->conn[0].port, newrec->iface.name)) {
		rc = idbm_delete_node(db, NULL, &rec);
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

	rc = idbm_node_write(db, newrec);
	if (rc || !drec)
		goto unlock;

	node_portal = calloc(2, PATH_MAX);
	if (!node_portal) {
		rc = ENOMEM;
		goto unlock;
	}

	disc_portal = node_portal + PATH_MAX;
	snprintf(node_portal, PATH_MAX, "%s/%s/%s,%d", NODE_CONFIG_DIR,
		 newrec->name, newrec->conn[0].address, newrec->conn[0].port);
	rc = setup_disc_to_node_link(disc_portal, newrec);
	if (rc)
		goto done;

	log_debug(7, "node addition making link from %s to %s", node_portal,
		 disc_portal);
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

done:
	free(node_portal);
unlock:
	idbm_unlock(db);
	return rc;
}

int idbm_add_nodes(idbm_t *db, node_rec_t *newrec, discovery_rec_t *drec)
{
	int i, rc = 0;

	for (i = 0; i < ISCSI_IFACE_MAX; i++) {
		if (!strlen(db->irec_iface[i].name))
			continue;

		strcpy(newrec->iface.name, db->irec_iface[i].name);
		rc = idbm_add_node(db, newrec, drec);
		if (rc)
			return rc;
	}
	return 0;
}

void idbm_new_discovery(idbm_t *db, discovery_rec_t *drec)
{
	idbm_delete_discovery(db, drec);
	if (idbm_add_discovery(db, drec))
		log_error("can not update discovery record.");
}

static void idbm_rm_disc_node_links(idbm_t *db, char *disc_dir)
{
	char *driver = NULL, *target = NULL, *tpgt = NULL, *port = NULL;
	char *address = NULL, *iface = NULL;
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
					      &address, &port, &iface,
					      &driver)) {
			log_error("Improperly formed disc to node link");
			continue;
		}

		log_debug(5, "disc removal removing link %s %s %s %s %s\n",
			  target, address, port, iface, driver);

		memset(rec, 0, sizeof(*rec));	
		strncpy(rec->name, target, TARGET_NAME_MAXLEN);
		rec->conn[0].port = atoi(port);
		strncpy(rec->conn[0].address, address, NI_MAXHOST);
		strncpy(rec->iface.name, iface, ISCSI_MAX_IFACE_LEN);
		strncpy(rec->transport_name, driver,
			ISCSI_TRANSPORT_NAME_MAXLEN);

		if (idbm_delete_node(db, NULL, rec))
			log_error("Could not delete node %s/%s/%s,%s/%s",
				  NODE_CONFIG_DIR, target, address, port,
				  iface);
 	}

	closedir(disc_dirfd);
free_rec:
	free(rec);
}

int idbm_delete_discovery(idbm_t *db, discovery_rec_t *drec)
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
	idbm_rm_disc_node_links(db, portal);

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
static int idbm_remove_disc_to_node_link(idbm_t *db, node_rec_t *rec,
					 char *portal)
{
	int rc = 0;
	struct stat statb;
	node_rec_t *newrec;

	newrec = malloc(sizeof(*newrec));
	if (!newrec)
		return ENOMEM;

	rc = idbm_node_read(db, newrec, rec->name, rec->conn[0].address,
			    rec->conn[0].port, rec->iface.name);
	if (rc)
		goto done;

	log_debug(7, "found drec %s %d\n", newrec->disc_address,
		 newrec->disc_port); 
	/* rm link from discovery source to node */
	memset(portal, 0, PATH_MAX);
	rc = setup_disc_to_node_link(portal, newrec);
	if (rc)
		goto done;

	if (!stat(portal, &statb)) {
		if (unlink(portal)) {
			log_error("Could not remove link %s err %d\n",
				  portal, errno);
			rc = errno;
		} else
			log_debug(7, "rmd %s", portal);
	} else
		log_debug(7, "Could not stat %s", portal);

done:
	free(newrec);
	return rc;
}

int idbm_delete_node(idbm_t *db, void *data, node_rec_t *rec)
{
	struct stat statb;
	char *portal;
	int rc = 0, dir_rm_rc = 0;

	portal = calloc(1, PATH_MAX);
	if (!portal)
		return ENOMEM;

	rc = idbm_remove_disc_to_node_link(db, rec, portal);
	if (rc)
		goto free_portal;

	memset(portal, 0, PATH_MAX);
	snprintf(portal, PATH_MAX, "%s/%s/%s,%d", NODE_CONFIG_DIR,
		 rec->name, rec->conn[0].address, rec->conn[0].port);
	log_debug(5, "Removing config file %s iface %s\n",
		  portal, rec->iface.name);

	if (stat(portal, &statb)) {
		log_error("Could not stat %s to delete node err %d\n",
			  portal, errno);
		rc = errno;
		goto free_portal;
	}

	if (S_ISDIR(statb.st_mode)) {
		strncat(portal, "/", PATH_MAX);
		strncat(portal, rec->iface.name, PATH_MAX);
	}

	if (unlink(portal)) {
		log_error("Could not remove %s err %d\n", portal, errno);
		rc = errno;
		goto free_portal;
	}

	/* rm portal dir */
	if (S_ISDIR(statb.st_mode)) {
		struct dirent **namelist;
		int n, i;

		memset(portal, 0, PATH_MAX);
		snprintf(portal, PATH_MAX, "%s/%s/%s,%d", NODE_CONFIG_DIR,
			 rec->name, rec->conn[0].address, rec->conn[0].port);
		n = scandir(portal, &namelist, st_disc_filter, versionsort);
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

free_portal:
	free(portal);
	return rc;
}

void
idbm_sendtargets_defaults(idbm_t *db, struct iscsi_sendtargets_config *cfg)
{
	idbm_sync_config(db);
	memcpy(cfg, &db->drec_st.u.sendtargets,
	       sizeof(struct iscsi_sendtargets_config));
}

void
idbm_slp_defaults(idbm_t *db, struct iscsi_slp_config *cfg)
{
	memcpy(cfg, &db->drec_slp.u.slp,
	       sizeof(struct iscsi_slp_config));
}

int
idbm_node_set_param(idbm_t *db, void *data, node_rec_t *rec)
{
	struct db_set_param *param = data;
	recinfo_t *info;

	info = idbm_recinfo_alloc(MAX_KEYS);
	if (!info)
		return 1;

	idbm_recinfo_node(rec, info);

	if (idbm_node_update_param(info, param->name, param->value, 0)) {
		free(info);
		return 1;
	}

	if (idbm_node_write(param->db, rec)) {
		free(info);
		return 1;
	}

	free(info);
	return 0;
}

idbm_t*
idbm_init(char *configfile)
{
	idbm_t *db;

	db = malloc(sizeof(idbm_t));
	if (!db) {
		log_error("out of memory on idbm allocation");
		return NULL;
	}
	memset(db, 0, sizeof(idbm_t));
	db->configfile = strdup(configfile);
	return db;
}

void
idbm_terminate(idbm_t *db)
{
	free(db->configfile);
	free(db);
}
