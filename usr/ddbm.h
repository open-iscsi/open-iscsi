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

#ifndef DDB_H
#define DDB_H

#include <sys/types.h>
#define DB_DBM_HSEARCH 1
#include <db.h>
#include "initiator.h"
#include "config.h"
#include "strings.h"

#define HASH_MAXLEN		48

typedef enum iscsi_startup {
	ISCSI_STARTUP_AUTOMATIC,
	ISCSI_STARTUP_MANUAL,
} iscsi_startup_e;

typedef enum discovery_type {
	DISCOVERY_TYPE_SENDTARGETS,
	DISCOVERY_TYPE_SLP,
	DISCOVERY_TYPE_ISNS,
} discovery_type_e;

typedef struct cnx_rec {
	struct iscsi_tcp_config			cfg_tcp;
	struct iscsi_connection_timeout_config	cfg_timeo;
	struct iscsi_cnx_operational_config	cfg_iscsi;
} cnx_rec_t;

typedef struct session_rec {
	struct iscsi_auth_config		cfg_auth;
	struct iscsi_session_timeout_config	cfg_timeo;
	struct iscsi_error_timeout_config	cfg_err_timeo;
	struct iscsi_session_operational_config	cfg_iscsi;
} session_rec_t;

typedef struct discovery_rec {
	char					nodename[TARGET_NAME_MAXLEN];
	char					address[16];
	int					port;
	int					tpgt;
	iscsi_startup_e				startup;
	session_rec_t				session;
	cnx_rec_t				cnx[ISCSI_CNX_MAX];
	discovery_type_e			type;
	union {
		struct iscsi_sendtargets_config	sendtargets;
		struct iscsi_slp_config		slp;
	} u;
} discovery_rec_t;

extern char* ddbm_hash(discovery_rec_t *rec);
extern DBM* ddbm_open(char *filename, int flags);
extern discovery_rec_t* ddbm_read(DBM *dbm, char *hash);
extern int ddbm_write(DBM *dbm, discovery_rec_t *rec);
extern void ddbm_close(DBM *dbm);
extern void ddbm_delete(DBM *dbm, char *portal);
extern int ddbm_update_info(DBM *dbm, struct string_buffer *info);

#endif /* DDB_H */
