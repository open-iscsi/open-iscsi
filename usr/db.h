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

#ifndef DISCOVERYDB_H
#define DISCOVERYDB_H

#include <sys/types.h>
#include <db.h>
#include "initiator.h"
#include "config.h"

#define PORTAL_KEY_MAXLEN 32	/* ip, port, tag */

typedef enum iscsi_startup {
	ISCSI_STARTUP_AUTOMATIC,
	ISCSI_STARTUP_MANUAL,
} iscsi_startup_e;

typedef enum discovery_type {
	ISCSI_DISCOVERY_SENDTARGETS,
	ISCSI_DISCOVERY_SLP,
	ISCSI_DISCOVERY_ISNS,
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
	char					key[PORTAL_KEY_MAXLEN];
	char					nodename[TARGET_NAME_MAXLEN];
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

extern DB* discoverydb_open(char *filename, uint32_t openflags);
extern discovery_rec_t* discoverydb_read(DB *dbp);
extern int discoverydb_write(DB *dbp, discovery_rec_t *rec);
extern void discoverydb_close(DB *dbp);

#endif /* DISCOVERYDB_H */
