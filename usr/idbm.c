/*
 * iSCSI Discovery Database Library
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

char *
get_iscsi_initiatorname(char *pathname)
{
	FILE *f = NULL;
	int c;
	char *line, buffer[1024];
	char *name = NULL;

	if (!pathname) {
		log_error("No pathname to load InitiatorName from");
		return NULL;
	}

	/* get the InitiatorName */
	if ((f = fopen(pathname, "r"))) {
		while ((line = fgets(buffer, sizeof (buffer), f))) {

			while (line && isspace(c = *line))
				line++;

			if (strncmp(line, "InitiatorName=", 14) == 0) {
				char *end = line + 14;

				/* the name is everything up to the first
				 * bit of whitespace
				 */
				while (*end && (!isspace(c = *end)))
					end++;

				if (isspace(c = *end))
					*end = '\0';

				if (end > line + 14)
					name = strdup(line + 14);
			}
		}
		fclose(f);
		if (!name) {
			log_error(
			       "an InitiatorName is required, but "
			       "was not found in %s", pathname);
			return NULL;
		} else {
			log_debug(5, "InitiatorName=%s", name);
		}
		return name;
	} else {
		log_error("cannot open InitiatorName configuration file %s",
			 pathname);
		return NULL;
	}
}

char *
get_iscsi_initiatoralias(char *pathname)
{
	FILE *f = NULL;
	int c;
	char *line, buffer[1024];
	char *name = NULL;

	if (!pathname) {
		log_error("No pathname to load InitiatorAlias from");
		return NULL;
	}

	/* get the InitiatorName */
	if ((f = fopen(pathname, "r"))) {
		while ((line = fgets(buffer, sizeof (buffer), f))) {

			while (line && isspace(c = *line))
				line++;

			if (strncmp(line, "InitiatorAlias=", 15) == 0) {
				char *end = line + 15;

				/* the name is everything up to the first
				 * bit of whitespace
				 */
				while (*end && (!isspace(c = *end)))
					end++;

				if (isspace(c = *end))
					*end = '\0';

				if (end > line + 15)
					name = strdup(line + 15);
			}
		}
		fclose(f);
		if (!name) {
			log_debug(5,"no InitiatorAlias found in %s", pathname);
			return NULL;
		} else {
			log_debug(5, "InitiatorAlias=%s", name);
		}
		return name;
	} else {
		log_error("cannot open InitiatorAlias configuration file %s",
			 pathname);
		return NULL;
	}
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
			u.sendtargets.address, IDBM_SHOW, num);
		__recinfo_int("discovery.sendtargets.port", ri, r,
			u.sendtargets.port, IDBM_SHOW, num);
		__recinfo_int("discovery.sendtargets.continuous", ri, r,
			u.sendtargets.continuous, IDBM_SHOW, num);
		__recinfo_int("discovery.sendtargets.send_async_text", ri, r,
			u.sendtargets.send_async_text, IDBM_SHOW, num);
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
		__recinfo_int("discovery.sendtargets.timeo.ping_timeout", ri, r,
			u.sendtargets.conn_timeo.ping_timeout,
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
	__recinfo_int("node.active_conn", ri, r, active_conn, IDBM_SHOW, num);
	__recinfo_int_o3("node.startup", ri, r, startup,
			IDBM_SHOW, "manual", "automatic", "onboot", num);
	__recinfo_int("node.session.initial_cmdsn", ri, r,
		      session.initial_cmdsn, IDBM_SHOW, num);
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

	for (i=0; i < r->active_conn; i++) {
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
idbm_discovery_setup_defaults(discovery_rec_t *rec, discovery_type_e type)
{
	memset(rec, 0, sizeof(discovery_rec_t));

	rec->dbversion = IDBM_VERSION;
	rec->startup = ISCSI_STARTUP_MANUAL;
	rec->type = type;
	if (type == DISCOVERY_TYPE_SENDTARGETS) {
		rec->u.sendtargets.continuous = 0;
		rec->u.sendtargets.send_async_text = 0;
		rec->u.sendtargets.reopen_max = 5;
		rec->u.sendtargets.auth.authmethod = 0;
		rec->u.sendtargets.auth.password_length = 0;
		rec->u.sendtargets.auth.password_in_length = 0;
		rec->u.sendtargets.conn_timeo.login_timeout=15;
		rec->u.sendtargets.conn_timeo.auth_timeout = 45;
		rec->u.sendtargets.conn_timeo.active_timeout=5;
		rec->u.sendtargets.conn_timeo.idle_timeout = 60;
		rec->u.sendtargets.conn_timeo.ping_timeout = 5;
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
				*(int*)info[i].data =
					strtoul(value, NULL, 10);
				goto updated;
			} else if (info[i].type == TYPE_STR) {
				strncpy((char*)info[i].data,
					value, info[i].data_len);
				goto updated;
			}
			for (j=0; j<info[i].numopts; j++) {
				if (!strcmp(value, info[i].opts[j])) {
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

static void
idbm_sync_config(idbm_t *db, int read_config)
{
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

	if (read_config) {
		FILE *f;

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

		fclose(f);
	}

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

int
idbm_print_discovery(idbm_t *db, discovery_rec_t *rec, int show)
{
	idbm_print(PRINT_TYPE_DISCOVERY, rec, show, stdout);
	return 1;
}

int
idbm_print_node(idbm_t *db, node_rec_t *rec, int show)
{
	idbm_print(PRINT_TYPE_NODE, rec, show, stdout);
	return 1;
}

int idbm_print_all_discovery(idbm_t *db)
{
	DIR *entity_dirfd;
	struct dirent *entity_dent;
	char *tmp_ip;
	int found = 0, tmp_port;

	entity_dirfd = opendir(ST_CONFIG_DIR);
	if (!entity_dirfd)
		return 0;

	while ((entity_dent = readdir(entity_dirfd))) {
		if (!strcmp(entity_dent->d_name, ".") ||
		    !strcmp(entity_dent->d_name, ".."))
			continue;

		log_debug(5, "found %s\n", entity_dent->d_name);

		tmp_ip = str_to_ipport(entity_dent->d_name, &tmp_port, ',');

		printf("%s:%d via sendtargets\n", tmp_ip, tmp_port);
		found++;
	}
	closedir(entity_dirfd);

	return found;
}

int idbm_print_nodes(idbm_t *db)
{
	DIR *node_dirfd, *portal_dirfd;
	struct dirent *node_dent, *portal_dent;
	char *portal;
	node_rec_t rec;
	int found = 0;

	portal = malloc(PATH_MAX);
	if (!portal)
		return 0;

	node_dirfd = opendir(NODE_CONFIG_DIR);
	if (!node_dirfd)
		goto free_portal;

	while ((node_dent = readdir(node_dirfd))) {
		if (!strcmp(node_dent->d_name, ".") ||
		    !strcmp(node_dent->d_name, ".."))
			continue;

		log_debug(5, "searching %s\n", node_dent->d_name);

		sprintf(portal, "%s/%s", NODE_CONFIG_DIR, node_dent->d_name);
		portal_dirfd = opendir(portal);
		if (!portal_dirfd)
			continue;
		while ((portal_dent = readdir(portal_dirfd))) {
			int tmp_port;
			char *tmp_ip;

			if (!strcmp(portal_dent->d_name, ".") ||
			    !strcmp(portal_dent->d_name, ".."))
				continue;

			log_debug(5, "found %s\n", portal_dent->d_name);
			tmp_ip = str_to_ipport(portal_dent->d_name, &tmp_port,
					       ',');

			if (idbm_node_read(db, &rec, node_dent->d_name,
					   tmp_ip, tmp_port))
				continue;

			printf("%s:%d,%d %s\n",
				rec.conn[0].address, rec.conn[0].port,
				rec.tpgt, rec.name);
			found++;
		}
		closedir(portal_dirfd);
	}

	closedir(node_dirfd);

free_portal:
	free(portal);
	return found;
}

static int idbm_lock(idbm_t *db)
{
	int fd, i, ret;

	if (db->refs > 0) {
		db->refs++;
		return 0;
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

int
idbm_discovery_read(idbm_t *db, discovery_rec_t *out_rec, char *addr, int port)
{
	char *portal;
	int rc = 0;
	FILE *f;

	memset(out_rec, 0, sizeof(discovery_rec_t));

	portal = malloc(PATH_MAX);
	if (!portal)
		return -ENOMEM;

	snprintf(portal, PATH_MAX, "%s/%s,%d", ST_CONFIG_DIR,
		 addr, port);
	log_debug(5, "Looking for config file %s\n", portal);

	idbm_lock(db);

	f = fopen(portal, "r");
	if (!f) {
		log_debug(1, "Could not open %s err %d\n", portal, errno);
		rc = errno;
		goto free_portal;
	}

	idbm_recinfo_config(db->dinfo_st, f);
	memcpy(out_rec, &db->drec_st, sizeof(discovery_rec_t));

free_portal:
	idbm_unlock(db);
	free(portal);
	return rc;
}

int
idbm_node_read(idbm_t *db, node_rec_t *out_rec, char *target_name,
	       char *addr, int port)
{
	char *portal;
	int rc = 0;
	FILE *f;

	memset(out_rec, 0, sizeof(node_rec_t));

	portal = malloc(PATH_MAX);
	if (!portal)
		return -ENOMEM;

	snprintf(portal, PATH_MAX, "%s/%s/%s,%d", NODE_CONFIG_DIR,
		 target_name, addr, port);
	log_debug(5, "Looking for config file %s\n", portal);

	idbm_lock(db);
	f = fopen(portal, "r");
	if (!f) {
		log_debug(5, "Could not open %s err %d\n", portal, errno);
		rc = errno;
		goto free_portal;
	}

	idbm_recinfo_config(db->ninfo, f);
	memcpy(out_rec, &db->nrec, sizeof(node_rec_t));

free_portal:
	idbm_unlock(db);
	free(portal);
	return rc;
}

static int
idbm_node_write(idbm_t *db, node_rec_t *rec)
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

	snprintf(portal, PATH_MAX, "%s", NODE_CONFIG_DIR);
	if (access(portal, F_OK) != 0) {
		if (mkdir(portal, 0755) != 0) {
			log_error("Could not make %s\n", portal);
			rc = errno;
			goto free_portal;
		}
	}	

	snprintf(portal, PATH_MAX, "%s/%s", NODE_CONFIG_DIR, rec->name);
	if (access(portal, F_OK) != 0) {
		if (mkdir(portal, 0755) != 0) {
			log_error("Could not make %s\n", portal);
			rc = errno;
			goto free_portal;
		}
	}	

	snprintf(portal, PATH_MAX, "%s/%s/%s,%d", NODE_CONFIG_DIR,
		 rec->name, rec->conn[0].address, rec->conn[0].port);
	log_debug(5, "Looking for config file %s\n", portal);

	f = fopen(portal, "w");
	if (!f) {
		log_error("Could not open %s err %d\n", portal, errno);
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
		if (mkdir(portal, 0755) != 0) {
			log_error("Could not make %s\n", portal);
			rc = errno;
			goto free_portal;
		}
	}	

	snprintf(portal, PATH_MAX, "%s/%s,%d", ST_CONFIG_DIR,
		 rec->u.sendtargets.address, rec->u.sendtargets.port);
	log_debug(5, "Looking for disc config file %s\n", portal);

	f = fopen(portal, "w");
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

int
idbm_add_discovery(idbm_t *db, discovery_rec_t *newrec)
{
	discovery_rec_t rec;
	int rc;

	idbm_lock(db);
	if (!idbm_discovery_read(db, &rec, newrec->u.sendtargets.address,
				newrec->u.sendtargets.port) == 0) {
		log_debug(7, "overwriting existing record");
	} else
		log_debug(7, "adding new DB record");

	rc = idbm_discovery_write(db, newrec);
	idbm_unlock(db);
	return rc;
}
	
static int
idbm_add_node(idbm_t *db, discovery_rec_t *drec, node_rec_t *newrec)
{
	node_rec_t rec;
	int rc;

	idbm_lock(db);
	if (!idbm_node_read(db, &rec, newrec->name, newrec->conn[0].address,
			newrec->conn[0].port) == 0) {
		log_debug(7, "overwriting existing record");
	} else
		log_debug(7, "adding new DB record");

	rc = idbm_node_write(db, newrec);
	idbm_unlock(db);
	return rc;
}

int
idbm_new_node(idbm_t *db, node_rec_t *newrec)
{
	return idbm_node_write(db, newrec);
}

discovery_rec_t*
idbm_new_discovery(idbm_t *db, char *ip, int port,
			discovery_type_e type, char *info)
{
	char *ptr, *newinfo;
	discovery_rec_t *drec;
	node_rec_t *nrec;

	/* sync default configuration */
	idbm_sync_config(db, 1);

	/* allocate new discovery record and initialize with defaults */
	drec = malloc(sizeof(discovery_rec_t));
	if (!drec) {
		log_error("out of memory on discovery record allocation");
		return NULL;
	}
	if (drec->type == DISCOVERY_TYPE_SENDTARGETS) {
		memcpy(drec, &db->drec_st, sizeof(discovery_rec_t));
	} else if (drec->type == DISCOVERY_TYPE_SLP) {
		memcpy(drec, &db->drec_slp, sizeof(discovery_rec_t));
	} else if (drec->type == DISCOVERY_TYPE_ISNS) {
		memcpy(drec, &db->drec_isns, sizeof(discovery_rec_t));
	}

	/* allocate new node record and initialize with defaults */
	nrec = malloc(sizeof(node_rec_t));
	if (!nrec) {
		log_error("out of memory on node record allocation");
		free(drec);
		return NULL;
	}
	memcpy(nrec, &db->nrec, sizeof(node_rec_t));

	/* update discovery record */
	drec->type = type;
	if (drec->type == DISCOVERY_TYPE_SENDTARGETS) {
		strncpy(drec->u.sendtargets.address, ip, NI_MAXHOST);
		drec->u.sendtargets.port = port;
	} else if (drec->type == DISCOVERY_TYPE_SLP) {
		log_error("not implemented discovery type");
	} else if (drec->type == DISCOVERY_TYPE_ISNS) {
		log_error("not implemented discovery type");
	}

	/*
	 * Discovery info example:
	 *
	 * DTN=iqn.2001-04.com.example:storage.disk2.sys1.xyz
	 * TT=1
	 * TP=3260
	 * TA=10.16.16.227
	 * ;
	 * DTN=iqn.2001-04.com.example:storage.disk2.sys2.xyz
	 * TT=1
	 * TP=3260
	 * TA=10.16.16.228
	 * ;
	 * !
	 */
	ptr = newinfo = strdup(info);
	log_debug(6, "parsing discovery info:\n---\n%s\n---", ptr);

	/* Maybe there are no targets */
	if (!strcmp(ptr, "!\n")) {
		log_debug(3, "No targets were found\n");
		free(drec);
		drec = NULL;
		goto out;
	}

	while (*ptr) {
		char *dp;

		/* convert line to zero-string */
		if ((dp = strchr(ptr, '\n'))) {
			*dp = '\0';
		}

		/* separate name and value */
		if ((dp = strchr(ptr, '='))) {
			*dp = '\0'; dp++;
			if (!strcmp(ptr, "DTN") || !strcmp(ptr, "TN")) {
				strncpy(nrec->name, dp, TARGET_NAME_MAXLEN);
			} else if (!strcmp(ptr, "TT")) {
				nrec->tpgt = strtoul(dp, NULL, 10);
			} else if (!strcmp(ptr, "TP")) {
				nrec->conn[0].port = strtoul(dp, NULL, 10);
			} else if (!strcmp(ptr, "TA")) {
				strncpy(nrec->conn[0].address, dp, NI_MAXHOST);
				if (idbm_add_discovery(db, drec)) {
					log_error("can not update discovery "
						  "record.");
					free(drec);
					drec = NULL;
					goto out;
				}
				if (idbm_add_node(db, drec, nrec)) {
					log_error("can not update node "
						  "record.");
					free(drec);
					drec = NULL;
					goto out;
				}
			} else {
				log_error("can not parse discovery info value. "
					  "Bug?");
				free(drec);
				drec = NULL;
				goto out;
			}
			log_debug(7, "discovery info key %s value %s", ptr, dp);
			ptr = dp + strlen(dp) + 1;
		} else if (*ptr == ';' && *(ptr+1) == '\0' && *(ptr+2) == '!') {
			/* end of discovery info */
			ptr += 3;
		} else if (*ptr == ';' && *(ptr+1) == '\0') {
			/* end of entry */
			ptr += 2;
		} else if (*ptr == '\0') {
			ptr++;
		} else {
			log_error("can not parse discovery info key '..%s' "
				  "Bug?", ptr);
			free(drec);
			drec = NULL;
			goto out;
		}
	}

out:
	free(nrec);
	free(newinfo);
	return drec;
}

int
idbm_delete_discovery(idbm_t *db, discovery_rec_t *rec)
{
	char *portal;
	int rc = 0;

	portal = malloc(PATH_MAX);
	if (!portal)
		return -ENOMEM;

	snprintf(portal, PATH_MAX, "%s/%s,%d", ST_CONFIG_DIR,
		 rec->u.sendtargets.address, rec->u.sendtargets.port);
	log_debug(5, "Removing config file %s\n", portal);

	if (unlink(portal)) {
		log_error("Could not remove %s err %d\n", portal, errno);
		rc = errno;
	}
	free(portal);

	return rc;
}

int
idbm_delete_node(idbm_t *db, node_rec_t *rec)
{
	char *portal;
	int rc = 0;

	portal = malloc(PATH_MAX);
	if (!portal)
		return -ENOMEM;

	snprintf(portal, PATH_MAX, "%s/%s/%s,%d", NODE_CONFIG_DIR,
		 rec->name, rec->conn[0].address, rec->conn[0].port);
	log_debug(5, "Removing config file %s\n", portal);

	if (unlink(portal)) {
		log_error("Could not remove %s err %d\n", portal, errno);
		rc = errno;
	}
	free(portal);

	return rc;
}

void
idbm_sendtargets_defaults(idbm_t *db, struct iscsi_sendtargets_config *cfg)
{
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
idbm_node_set_param(idbm_t *db, node_rec_t *rec, char *name, char *value)
{
	recinfo_t *info;

	info = idbm_recinfo_alloc(MAX_KEYS);
	if (!info)
		return 1;

	idbm_recinfo_node(rec, info);

	if (idbm_node_update_param(info, name, value, 0)) {
		free(info);
		return 1;
	}

	if (idbm_node_write(db, rec)) {
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
	idbm_sync_config(db, 0);	

	return db;
}

void
idbm_terminate(idbm_t *db)
{
	free(db->configfile);
	free(db);
}
