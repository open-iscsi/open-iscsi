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

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/file.h>

#include "idbm.h"
#include "log.h"

#define LOCK_EX 2    /* Exclusive lock.  */
#define LOCK_UN 8    /* Unlock.  */

static int
idbm_lock(DBM *dbm)
{
#ifndef DB_DBM_HSEARCH
	if (flock(dbm->dbm_dirf, LOCK_EX) == -1 ||
	    flock(dbm->dbm_pagf, LOCK_EX) == -1)
		return 1;
#else
	if (flock(dbm_dirfno(dbm), LOCK_EX) == -1)
		return 1;
#endif
	return 0;
}

static void
idbm_unlock(DBM *dbm)
{
#ifndef DB_DBM_HSEARCH
	flock(dbm->dbm_dirf, LOCK_UN);
	flock(dbm->dbm_pagf, LOCK_UN);
#else
	flock(dbm_dirfno(dbm), LOCK_UN);
#endif
}

static void
idbm_update_rec(discovery_rec_t *rec, discovery_rec_t *newrec)
{
	int i;

#define __update_rec_int(r, n, fld) \
	if (n->fld) r->fld = n->fld
#define __update_rec_str(r, n, fld, len) \
	if (strlen(n->fld)) strncpy(r->fld, n->fld, len)

	/* update rec */
	__update_rec_str(rec, newrec, nodename, TARGET_NAME_MAXLEN);
	__update_rec_str(rec, newrec, address, 16);
	__update_rec_int(rec, newrec, port);
	__update_rec_int(rec, newrec, tpgt);
	__update_rec_int(rec, newrec, startup);
	__update_rec_int(rec, newrec, type);

	/* update rec->session */
	__update_rec_str(rec, newrec, session.auth.username,
			 AUTH_STR_MAX_LEN);
	__update_rec_str(rec, newrec, session.auth.password,
			 AUTH_STR_MAX_LEN);
	__update_rec_int(rec, newrec, session.auth.password_length);
	__update_rec_str(rec, newrec, session.auth.username_in,
			 AUTH_STR_MAX_LEN);
	__update_rec_str(rec, newrec, session.auth.password_in,
			 AUTH_STR_MAX_LEN);
	__update_rec_int(rec, newrec, session.auth.password_length_in);
	__update_rec_int(rec, newrec, session.timeo.replacement_timeout);
	__update_rec_int(rec, newrec, session.err_timeo.abort_timeout);
	__update_rec_int(rec, newrec, session.err_timeo.reset_timeout);
	__update_rec_int(rec, newrec, session.iscsi.protocol);
	__update_rec_int(rec, newrec, session.iscsi.InitialR2T);
	__update_rec_int(rec, newrec, session.iscsi.ImmediateData);
	__update_rec_int(rec, newrec, session.iscsi.FirstBurstLength);
	__update_rec_int(rec, newrec, session.iscsi.MaxBurstLength);
	__update_rec_int(rec, newrec, session.iscsi.DefaultTime2Wait);
	__update_rec_int(rec, newrec, session.iscsi.DefaultTime2Retain);

	for (i=0; i < ISCSI_CNX_MAX; i++) {
		/* update rec->cnx[i] */
		__update_rec_int(rec, newrec, cnx[i].startup);
		__update_rec_int(rec, newrec, cnx[i].tcp.window_size);
		__update_rec_int(rec, newrec, cnx[i].tcp.type_of_service);
		__update_rec_int(rec, newrec, cnx[i].timeo.login_timeout);
		__update_rec_int(rec, newrec, cnx[i].timeo.auth_timeout);
		__update_rec_int(rec, newrec, cnx[i].timeo.active_timeout);
		__update_rec_int(rec, newrec, cnx[i].timeo.idle_timeout);
		__update_rec_int(rec, newrec, cnx[i].timeo.ping_timeout);
		__update_rec_int(rec, newrec,
				 cnx[i].iscsi.MaxRecvDataSegmentLength);
		__update_rec_int(rec, newrec, cnx[i].iscsi.HeaderDigest);
		__update_rec_int(rec, newrec, cnx[i].iscsi.DataDigest);
	}

	/* update rec->u.sendtargets */
	__update_rec_str(rec, newrec, u.sendtargets.address, 16);
	__update_rec_int(rec, newrec, u.sendtargets.port);
	__update_rec_int(rec, newrec, u.sendtargets.continuous);
	__update_rec_int(rec, newrec, u.sendtargets.send_async_text);
	__update_rec_int(rec, newrec, u.sendtargets.auth_options.authmethod);
	__update_rec_str(rec, newrec,u.sendtargets.auth_options.username,
			 AUTH_STR_MAX_LEN);
	__update_rec_str(rec, newrec, u.sendtargets.auth_options.password,
			 AUTH_STR_MAX_LEN);
	__update_rec_int(rec, newrec,
			 u.sendtargets.auth_options.password_length);
	__update_rec_str(rec, newrec,u.sendtargets.auth_options.username_in,
			 AUTH_STR_MAX_LEN);
	__update_rec_str(rec, newrec, u.sendtargets.auth_options.password_in,
			 AUTH_STR_MAX_LEN);
	__update_rec_int(rec, newrec,
			 u.sendtargets.auth_options.password_length_in);
	__update_rec_int(rec, newrec,
		 u.sendtargets.connection_timeout_options.login_timeout);
	__update_rec_int(rec, newrec,
		 u.sendtargets.connection_timeout_options.auth_timeout);
	__update_rec_int(rec, newrec,
		 u.sendtargets.connection_timeout_options.active_timeout);
	__update_rec_int(rec, newrec,
		 u.sendtargets.connection_timeout_options.idle_timeout);
	__update_rec_int(rec, newrec,
		 u.sendtargets.connection_timeout_options.ping_timeout);
}

static char*
idbm_hash(discovery_rec_t *rec)
{
	char *hash = malloc(HASH_MAXLEN);

	if (!hash) {
		log_error("out of memory on hash allocation");
		return NULL;
	}

	if (rec->type == DISCOVERY_TYPE_SENDTARGETS) {
		snprintf(hash, HASH_MAXLEN, "%s:%d#%s:%d,%d",
			rec->u.sendtargets.address,
			rec->u.sendtargets.port,
			rec->address,
			rec->port,
			rec->tpgt);
		return hash;
	} else {
		log_error("unsupported discovery type");
		return NULL;
	}
}

static discovery_rec_t*
idbm_read(DBM *dbm, char *hash)
{
	datum key, data;

	key.dptr = hash;
	key.dsize = HASH_MAXLEN;

	data = dbm_fetch(dbm, key);
	if (data.dsize > 0) {
		return (discovery_rec_t*)data.dptr;
	}

	log_debug(7, "key '%s' not found", hash);
	return NULL;
}

static int
idbm_write(DBM *dbm, discovery_rec_t *rec)
{
	char *hash;
	datum key, data;

	if (!(hash = idbm_hash(rec))) {
		return 1;
	}

	key.dptr = hash;
	key.dsize = HASH_MAXLEN;

	data.dptr = (void*)rec;
	data.dsize = sizeof(discovery_rec_t);

	if (dbm_store(dbm, key, data, DBM_REPLACE)) {
		log_error("can not write record with hash-key '%s'", hash);
		free(hash);
		return 1;
	}

	free(hash);
	return 0;
}

static void
idbm_print_rec(int rec_id, discovery_rec_t *rec)
{
	if (rec->type == DISCOVERY_TYPE_SENDTARGETS) {
		printf("#%d %s:%d,%d %s\n",
			rec_id,
			rec->address,
			rec->port,
			rec->tpgt,
			rec->nodename);
	} else {
		log_error("unsupported discovery type");
		return;
	}
}

static void
idbm_recinfo_init(discovery_rec_t *rec, discovery_recinfo_t *info, int *out_num)
{
	int num = 0, i;

#define __recinfo_str(_key, _show) \
	info[num].type = TYPE_STR; \
	strncpy(info[num].key, #_key, KEY_MAXVAL); \
	if (strlen(rec->_key)) \
		strncpy(info[num].value, rec->_key, VALUE_MAXVAL); \
	else \
		strcpy(info[num].value, "<empty>"); \
	info[num].data = &rec->_key; \
	info[num].visible = _show; \
	num++;

#define __recinfo_int(_key, _show) \
	info[num].type = TYPE_INT; \
	strncpy(info[num].key, #_key, KEY_MAXVAL); \
	snprintf(info[num].value, VALUE_MAXVAL, "%d", rec->_key); \
	info[num].data = &rec->_key; \
	info[num].visible = _show; \
	num++;

#define __recinfo_int_o2(_key, _show, _op0, _op1) \
	info[num].type = TYPE_INT_O; \
	strncpy(info[num].key, #_key, KEY_MAXVAL); \
	if (rec->_key == 0) strncpy(info[num].value, _op0, VALUE_MAXVAL); \
	if (rec->_key == 1) strncpy(info[num].value, _op1, VALUE_MAXVAL); \
	info[num].data = &rec->_key; \
	info[num].visible = _show; \
	info[num].opts[0] = _op0; \
	info[num].opts[1] = _op1; \
	info[num].numopts = 2; \
	num++;

#define __recinfo_int_o3(_key, _show, _op0, _op1, _op2) \
	__recinfo_int_o2(_key, _show, _op0, _op1); num--; \
	if (rec->_key == 2) strncpy(info[num].value, _op2, VALUE_MAXVAL); \
	info[num].opts[2] = _op2; \
	info[num].numopts = 3;

	memset(info, 0, sizeof(discovery_recinfo_t)*MAX_KEYS);

	__recinfo_str(nodename, 0);
	__recinfo_str(address, 0);
	__recinfo_int(port, 0);
	__recinfo_int(tpgt, 0);
	__recinfo_int(active_cnx, 1);
	__recinfo_int_o2(startup, 1, "manual", "automatic");
	__recinfo_int_o3(type, 1, "sendtargets", "slp", "isns");
	__recinfo_str(session.auth.username, 1);
	__recinfo_str(session.auth.password, 1);
	__recinfo_str(session.auth.username_in, 1);
	__recinfo_str(session.auth.password_in, 1);
	__recinfo_int(session.timeo.replacement_timeout, 1);
	__recinfo_int(session.err_timeo.abort_timeout, 1);
	__recinfo_int(session.err_timeo.reset_timeout, 1);
	__recinfo_int_o2(session.iscsi.InitialR2T, 1, "No", "Yes");
	__recinfo_int_o2(session.iscsi.ImmediateData, 1, "No", "Yes");
	__recinfo_int(session.iscsi.FirstBurstLength, 1);
	__recinfo_int(session.iscsi.MaxBurstLength, 1);
	__recinfo_int(session.iscsi.DefaultTime2Wait, 1);
	__recinfo_int(session.iscsi.DefaultTime2Retain, 1);
	__recinfo_int(session.iscsi.MaxConnections, 1);

	for (i=0; i < rec->active_cnx; i++) {
		__recinfo_int_o2(cnx[i].startup, 1, "manual", "automatic");
		__recinfo_int(cnx[i].tcp.window_size, 1);
		__recinfo_int(cnx[i].tcp.type_of_service, 1);
		__recinfo_int(cnx[i].timeo.login_timeout, 1);
		__recinfo_int(cnx[i].timeo.auth_timeout, 1);
		__recinfo_int(cnx[i].timeo.active_timeout, 1);
		__recinfo_int(cnx[i].timeo.idle_timeout, 1);
		__recinfo_int(cnx[i].timeo.ping_timeout, 1);
		__recinfo_int(cnx[i].iscsi.MaxRecvDataSegmentLength, 1);
		__recinfo_int_o2(cnx[i].iscsi.HeaderDigest, 1, "No", "Yes");
		__recinfo_int_o2(cnx[i].iscsi.DataDigest, 1, "No", "Yes");
	}

	*out_num = num;
}

static discovery_recinfo_t*
idbm_recinfo_alloc(int max_keys)
{
	discovery_recinfo_t *info;

	info = malloc(sizeof(discovery_recinfo_t)*max_keys);
	if (!info)
		return NULL;
	memset(info, 0, sizeof(discovery_recinfo_t)*max_keys);
	return info;
}

static void
idbm_print_details(int rec_id, discovery_rec_t *rec)
{
	int num, i;
	discovery_recinfo_t *info;

	info = idbm_recinfo_alloc(MAX_KEYS);
	if (!info)
		return;

	idbm_recinfo_init(rec, info, &num);

	for (i=0; i<num; i++) {
		if (!info[i].visible)
			continue;
		printf("\t%s = %s\n", info[i].key, info[i].value);
	}

	free(info);
}

static DBM*
idbm_open(char *filename, int flags)
{
	DBM *dbm;

	if (flags & O_CREAT) {
		char *dirname, *ptr;

		dirname = strdup(filename);
		if (dirname && (ptr = strrchr(dirname, '/'))) {
			*ptr = '\0';
		} else if (!dirname)
			return NULL;

		if (access(dirname, F_OK) != 0) {
			if (mkdir(dirname, 0755) != 0) {
				free(dirname);
				log_error("mkdir '%s' error", dirname);
				return NULL;
			}
		}
		free(dirname);
	}

	/* Now open the database */
	dbm = dbm_open(filename, flags, 0666);
	if (!dbm) {
		log_error("discovery DB '%s' open failed", filename);
		return NULL;
	}

	return dbm;
}

static void
idbm_close(DBM *dbm)
{
	dbm_close(dbm);
}

int
idbm_load_config(idbm_t *db)
{
	int num;
	FILE *f = NULL;

	f = fopen(db->configfile, "r");
	if (!f) {
		log_error("cannot open configuration file %s", db->configfile);
		return 1;
	}

	log_debug(5, "updating defaults from '%s'", db->configfile);

	memset(&db->drec, 0, sizeof(discovery_rec_t));
	idbm_discovery_recinfo_init(&drec, db->dinfo);

	memset(&db->nrec, 0, sizeof(node_rec_t));
	idbm_node_recinfo_init(&nrec, db->ninfo);

	fclose(f);
	return 0;
}

void
idbm_print(DBM *dbm, int rec_id)
{
	int rid = 0;
	datum key, data;

	(void)idbm_lock(dbm);

	for (key=dbm_firstkey(dbm); key.dptr != NULL; key=dbm_nextkey(dbm)) {
		data = dbm_fetch(dbm, key);
		if (rec_id < 0 || rec_id == rid) {
			idbm_print_rec(rid, (discovery_rec_t*)data.dptr);
		}
		if (rec_id == rid) {
			idbm_print_details(rid, (discovery_rec_t*)data.dptr);
			break;
		}
		rid++;
	}

	idbm_unlock(dbm);
}

int
idbm_update_discovery(idbm_t *db, discovery_rec_t *newrec)
{
	char *hash;
	discovery_rec_t *rec;

	if (!(hash = idbm_hash(newrec))) {
		return 1;
	}

	if (idbm_lock(db->discdb)) {
		free(hash);
		return 1;
	}

	if ((rec = idbm_read(db->discdb, hash))) {
		log_debug(7, "updating existing DB record");
		idbm_update_rec(rec, newrec);
	} else {
		log_debug(7, "adding new DB record");
	}

	if (idbm_write(db->discdb, newrec)) {
		idbm_unlock(db->discdb);
		free(hash);
		return 1;
	}

	idbm_unlock(db->discdb);
	free(hash);
	return 0;
}

int
idbm_new_discovery(idbm_t *db, char *ip, int port,
			discovery_type_e type, char *info)
{
	char *ptr, *newinfo;
	discovery_rec_t *drec;
	node_rec_t *nrec;

	/* sync default configuration */
	if (idbm_load_config(db)) {
		return 1;
	}

	/* allocate new discovery record and initialize with defaults */
	drec = malloc(sizeof(discovery_rec_t));
	if (!drec) {
		log_error("out of memory on discovery record allocation");
		return 1;
	}
	memcpy(drec, db->drec, sizeof(discovery_rec_t));

	/* allocate new node record and initialize with defaults */
	nrec = malloc(sizeof(node_rec_t));
	if (!nrec) {
		log_error("out of memory on node record allocation");
		free(drec);
		return 1;
	}
	memcpy(nrec, db->nrec, sizeof(node_rec_t));

	/* update discovery record */
	drec->type = type;
	if (drec->type == DISCOVERY_TYPE_SENDTARGETS) {
		strncpy(drec->u.sendtargets.address, ip, 16);
		drec->u.sendtargets.port = port;
	} else {
		log_error("unsupported discovery type");
		return 1;
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
	while (*ptr) {
		char *dp;

		/* convert line to zero-string */
		if ((dp = strchr(ptr, '\n'))) {
			*dp = '\0';
		}

		/* separate name and value */
		if ((dp = strchr(ptr, '='))) {
			*dp = '\0'; dp++;
			if (!strcmp(ptr, "DTN")) {
				strncpy(rec->nodename, dp, TARGET_NAME_MAXLEN);
			} else if (!strcmp(ptr, "TT")) {
				rec->tpgt = strtoul(dp, NULL, 10);
			} else if (!strcmp(ptr, "TP")) {
				rec->port = strtoul(dp, NULL, 10);
			} else if (!strcmp(ptr, "TA")) {
				strncpy(rec->address, dp, 16);
			} else {
				log_error("can not parse discovery info value."
					  "Bug?");
				rc = 1;
				goto out;
			}
			log_debug(7, "discovery info key %s value %s", ptr, dp);
			ptr = dp + strlen(dp) + 1;
		} else if (*ptr == ';') {
			/* end of entry */
			ptr += 2;
			if (idbm_update_discovery(db, rec)) {
				log_error("can not update discovery record.");
				rc = 1;
				goto out;
			}
		} else if (*ptr == '!') {
			/* end of discovery info */
			ptr += 2;
		} else {
			log_error("can not parse discovery info key. Bug?");
			rc = 1;
			goto out;
		}
	}

out:
	free(drec);
	free(nrec);
	free(newinfo);
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

	if (idbm_load_config(db)) {
		free(db->configfile);
		free(db);
		return NULL;
	}

	if ((db->discdb = idbm_open(DISCOVERY_FILE,
				access(DISCOVERY_FILE, F_OK) != 0 ?
					O_CREAT|O_RDWR : O_RDWR)) == NULL) {
		free(db->configfile);
		free(db);
		return NULL;
	}

	if ((db->nodedb = idbm_open(NODE_FILE, access(NODE_FILE, F_OK) != 0 ?
				O_CREAT|O_RDWR : O_RDWR)) == NULL) {
		idbm_close(db->discdb);
		free(db->configfile);
		free(db);
		return -1;
	}

	return db;
}

void
idbm_terminate(idbm_t *db)
{
	idbm_close(db->discdb);
	idbm_close(db->nodedb);
	free(db->configfile);
	free(db);
}
