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

#ifndef IDBM_H
#define IDBM_H

#include <sys/types.h>
#include "initiator.h"
#include "config.h"

#define NODE_CONFIG_DIR		ISCSI_CONFIG_ROOT"nodes"
#define IFACE_CONFIG_DIR	ISCSI_CONFIG_ROOT"ifaces"
#define SLP_CONFIG_DIR		ISCSI_CONFIG_ROOT"slp"
#define ISNS_CONFIG_DIR		ISCSI_CONFIG_ROOT"isns"
#define STATIC_CONFIG_DIR	ISCSI_CONFIG_ROOT"static"
#define ST_CONFIG_DIR		ISCSI_CONFIG_ROOT"send_targets"
#define ST_CONFIG_NAME		"st_config"

#define TYPE_INT	0
#define TYPE_INT_O	1
#define TYPE_STR	2
#define MAX_KEYS	256   /* number of keys total(including CNX_MAX) */
#define NAME_MAXVAL	128   /* the maximum length of key name */
#define VALUE_MAXVAL	256   /* the maximum length of 223 bytes in the RFC. */
#define OPTS_MAXVAL	8
typedef struct recinfo {
	int		type;
	char		name[NAME_MAXVAL];
	char		value[VALUE_MAXVAL];
	void		*data;
	int		data_len;
	int		visible;
	char*		opts[OPTS_MAXVAL];
	int		numopts;
} recinfo_t;

typedef struct idbm {
	void		*discdb;
	void		*nodedb;
	char		*configfile;
	int             refs;
	node_rec_t	nrec;
	recinfo_t	ninfo[MAX_KEYS];
	discovery_rec_t	drec_st;
	recinfo_t	dinfo_st[MAX_KEYS];
	discovery_rec_t	drec_slp;
	recinfo_t	dinfo_slp[MAX_KEYS];
	discovery_rec_t	drec_isns;
	recinfo_t	dinfo_isns[MAX_KEYS];
} idbm_t;

struct db_set_param {
	char *name;
	char *value;
	struct idbm  *db;
};

typedef int (idbm_iface_op_fn)(idbm_t *db, void *data, node_rec_t *rec);
typedef int (idbm_portal_op_fn)(idbm_t *db, void *data, char *targetname,
				int tpgt, char *ip, int port);
typedef int (idbm_node_op_fn)(idbm_t *db, void *data, char *targetname);

struct rec_op_data {
	void *data;
	node_rec_t *match_rec;
	idbm_iface_op_fn *fn;
};
extern int idbm_for_each_iface(idbm_t *db, void *data, idbm_iface_op_fn *fn,
				char *targetname, int tpgt, char *ip, int port);
extern int idbm_for_each_portal(idbm_t *db, void *data, idbm_portal_op_fn *fn,
				char *targetname);
extern int idbm_for_each_node(idbm_t *db, void *data, idbm_node_op_fn *fn);
extern int idbm_for_each_rec(idbm_t *db, void *data, idbm_iface_op_fn *fn);

extern char* get_iscsi_initiatorname(char *pathname);
extern char* get_iscsi_initiatoralias(char *pathname);
extern idbm_t* idbm_init(char *configfile);
extern void idbm_node_setup_from_conf(idbm_t *db, node_rec_t *rec);
extern void idbm_terminate(idbm_t *db);
extern int idbm_print_node_info(idbm_t *db, void *data, node_rec_t *rec);
extern int idbm_print_node_flat(idbm_t *db, void *data, node_rec_t *rec);
extern int idbm_print_node_tree(idbm_t *db, void *data, node_rec_t *rec);
extern int idbm_print_discovery_info(idbm_t *db, discovery_rec_t *rec,
				     int show);
extern int idbm_print_all_discovery(idbm_t *db, int info_level);
extern int idbm_print_discovered(idbm_t *db, discovery_rec_t *drec,
				 int info_level);
extern int idbm_delete_discovery(idbm_t *db, discovery_rec_t *rec);
extern void idbm_node_setup_defaults(node_rec_t *rec);
extern int idbm_delete_node(idbm_t *db, void *data, node_rec_t *rec);
extern int idbm_add_node(idbm_t *db, node_rec_t *newrec, discovery_rec_t *drec);

struct list_head;
extern int idbm_add_nodes(idbm_t *db, node_rec_t *newrec,
			  discovery_rec_t *drec, struct list_head *ifaces);
extern void idbm_new_discovery(idbm_t *db, discovery_rec_t *drec);
extern void idbm_sendtargets_defaults(idbm_t *db,
		      struct iscsi_sendtargets_config *cfg);
extern void idbm_slp_defaults(idbm_t *db, struct iscsi_slp_config *cfg);
extern int idbm_discovery_read(idbm_t *db, discovery_rec_t *rec, char *addr,
				int port);
extern int idbm_rec_read(idbm_t *db, node_rec_t *out_rec, char *target_name,
			 int tpgt, char *addr, int port,
			 struct iface_rec *iface);
extern int idbm_node_set_param(idbm_t *db, void *data, node_rec_t *rec);

/* TODO: seperate iface, node and core idbm code */
extern int iface_id_is_mac(char *iface_id);
extern void iface_copy(struct iface_rec *dst, struct iface_rec *src);
extern int iface_is_bound(struct iface_rec *iface);
extern int iface_match_bind_info(struct iface_rec *pattern,
				  struct iface_rec *iface);
extern struct iface_rec *iface_alloc(char *ifname, int *err);
extern int iface_conf_read(struct iface_rec *iface);
extern void iface_init(struct iface_rec *iface);
extern int iface_is_bound_by_hwaddr(struct iface_rec *iface);
extern int iface_is_bound_by_netdev(struct iface_rec *iface);
extern int iface_is_bound_by_ipaddr(struct iface_rec *iface);
typedef int (iface_op_fn)(void *data, struct iface_rec *iface);
extern int iface_for_each_iface(idbm_t *db, void *data, int *nr_found,
				 iface_op_fn *fn);
extern int iface_print_flat(void *data, struct iface_rec *iface);
extern void iface_setup_host_bindings(idbm_t *db);
extern int iface_get_by_bind_info(idbm_t *db, struct iface_rec *pattern,
				 struct iface_rec *out_rec);

#define iface_fmt "[hw=%s,ip=%s,net_if=%s,iscsi_if=%s]"
#define iface_str(_iface) \
	(_iface)->hwaddress, (_iface)->ipaddress, (_iface)->netdev, \
	(_iface)->name

#endif /* IDBM_H */
