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

#ifndef IDBM_H
#define IDBM_H

#include <sys/types.h>
#define DB_DBM_HSEARCH 1
#include <db.h>
#include "initiator.h"
#include "config.h"

#define HASH_MAXLEN	48

typedef enum iscsi_startup {
	ISCSI_STARTUP_MANUAL,
	ISCSI_STARTUP_AUTOMATIC,
} iscsi_startup_e;

typedef enum discovery_type {
	DISCOVERY_TYPE_SENDTARGETS,
	DISCOVERY_TYPE_SLP,
	DISCOVERY_TYPE_ISNS,
} discovery_type_e;

typedef struct cnx_rec {
	iscsi_startup_e				startup;
	char					address[16];
	int					port;
	struct iscsi_tcp_config			tcp;
	struct iscsi_connection_timeout_config	timeo;
	struct iscsi_cnx_operational_config	iscsi;
} cnx_rec_t;

typedef struct session_rec {
	struct iscsi_auth_config		auth;
	struct iscsi_session_timeout_config	timeo;
	struct iscsi_error_timeout_config	err_timeo;
	struct iscsi_session_operational_config	iscsi;
} session_rec_t;

typedef struct node_rec {
	int					id;
	char					name[TARGET_NAME_MAXLEN];
	int					tpgt;
	int					active_cnx;
	iscsi_startup_e				startup;
	session_rec_t				session;
	cnx_rec_t				cnx[ISCSI_CNX_MAX];
} node_rec_t;

typedef struct discovery_rec {
	int					id;
	iscsi_startup_e				startup;
	discovery_type_e			type;
	union {
		struct iscsi_sendtargets_config	sendtargets;
		struct iscsi_slp_config		slp;
	} u;
} discovery_rec_t;

#define TYPE_INT	0
#define TYPE_INT_O	1
#define TYPE_STR	2
#define MAX_KEYS	256
#define NAME_MAXVAL	128
#define VALUE_MAXVAL	256
#define OPTS_MAXVAL	32
typedef struct recinfo {
	int		type;
	char		name[NAME_MAXVAL];
	char		value[VALUE_MAXVAL];
	void		*data;
	int		visible;
	char*		opts[OPTS_MAXVAL];
	int		numopts;
} recinfo_t;

typedef struct idbm {
	DBM		*discdb;
	DBM		*nodedb;
	char		*configfile;
	node_rec_t	nrec;
	recinfo_t	ninfo[MAX_KEYS];
	discovery_rec_t	drec_st;
	recinfo_t	dinfo_st[MAX_KEYS];
	discovery_rec_t	drec_slp;
	recinfo_t	dinfo_slp[MAX_KEYS];
	discovery_rec_t	drec_isns;
	recinfo_t	dinfo_isns[MAX_KEYS];
} idbm_t;

extern idbm_t* idbm_init(char *configfile);
extern void idbm_terminate(idbm_t *db);
extern int idbm_print_node(idbm_t *db, int rec_id);
extern int idbm_print_nodes(idbm_t *db, discovery_rec_t *rec);
extern int idbm_print_discovery(idbm_t *db, int rec_id);
extern int idbm_add_node(idbm_t *db, discovery_rec_t *drec, node_rec_t *newrec);
extern int idbm_add_discovery(idbm_t *db, discovery_rec_t *newrec);
extern discovery_rec_t* idbm_new_discovery(idbm_t *db, char *ip, int port,
			    discovery_type_e type, char *info);
extern void idbm_sendtargets_defaults(idbm_t *db,
		      struct iscsi_sendtargets_config *cfg);
extern void idbm_slp_defaults(idbm_t *db, struct iscsi_slp_config *cfg);
extern int idbm_discovery_read(idbm_t *db, int rec_id, discovery_rec_t *rec);
extern int idbm_node_read(idbm_t *db, int rec_id, node_rec_t *rec);

#endif /* IDBM_H */
