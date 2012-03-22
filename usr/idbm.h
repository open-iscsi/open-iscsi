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

#include <stdio.h>
#include <sys/types.h>
#include "initiator.h"
#include "config.h"
#include "list.h"

#define NODE_CONFIG_DIR		ISCSI_CONFIG_ROOT"nodes"
#define SLP_CONFIG_DIR		ISCSI_CONFIG_ROOT"slp"
#define ISNS_CONFIG_DIR		ISCSI_CONFIG_ROOT"isns"
#define STATIC_CONFIG_DIR	ISCSI_CONFIG_ROOT"static"
#define FW_CONFIG_DIR		ISCSI_CONFIG_ROOT"fw"
#define ST_CONFIG_DIR		ISCSI_CONFIG_ROOT"send_targets"
#define ST_CONFIG_NAME		"st_config"
#define ISNS_CONFIG_NAME	"isns_config"

#define TYPE_INT	0
#define TYPE_INT_O	1
#define TYPE_STR	2
#define TYPE_UINT8	3
#define TYPE_UINT16	4
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
	/*
	 * bool indicating if we can change it or not.
	 * TODO: make it a enum that can indicate wheter it also requires
	 * a relogin to pick up if a session is running.
	 */
	int		can_modify;
} recinfo_t;

typedef char *(idbm_get_config_file_fn)(void);

typedef struct idbm {
	void		*discdb;
	void		*nodedb;
	char		*configfile;
	int             refs;
	idbm_get_config_file_fn *get_config_file;
	node_rec_t	nrec;
	recinfo_t	ninfo[MAX_KEYS];
	discovery_rec_t	drec_st;
	recinfo_t	dinfo_st[MAX_KEYS];
	discovery_rec_t	drec_slp;
	recinfo_t	dinfo_slp[MAX_KEYS];
	discovery_rec_t	drec_isns;
	recinfo_t	dinfo_isns[MAX_KEYS];
} idbm_t;

struct user_param {
	struct list_head list;
	char *name;
	char *value;
};

typedef int (idbm_iface_op_fn)(void *data, node_rec_t *rec);
typedef int (idbm_portal_op_fn)(int *found,  void *data,
				char *targetname, int tpgt, char *ip, int port);
typedef int (idbm_node_op_fn)(int *found, void *data,
			      char *targetname);

struct rec_op_data {
	void *data;
	node_rec_t *match_rec;
	idbm_iface_op_fn *fn;
};
extern int idbm_for_each_portal(int *found, void *data,
				idbm_portal_op_fn *fn, char *targetname);
extern int idbm_for_each_node(int *found, void *data,
			      idbm_node_op_fn *fn);
extern int idbm_for_each_rec(int *found, void *data,
			     idbm_iface_op_fn *fn);


typedef int (idbm_drec_op_fn)(void *data, discovery_rec_t *drec);
extern int idbm_for_each_st_drec(void *data, idbm_drec_op_fn *fn);
extern int idbm_for_each_isns_drec(void *data, idbm_drec_op_fn *fn);

extern int idbm_init(idbm_get_config_file_fn *fn);

extern void idbm_node_setup_from_conf(node_rec_t *rec);
extern void idbm_terminate(void);
extern int idbm_print_iface_info(void *data, struct iface_rec *iface);
extern int idbm_print_node_info(void *data, node_rec_t *rec);
extern int idbm_print_node_flat(void *data, node_rec_t *rec);
extern int idbm_print_node_tree(struct node_rec *last_rec, struct node_rec *rec,
				char *prefix);
extern int idbm_print_node_and_iface_tree(void *data, node_rec_t *rec);
extern int idbm_print_discovery_info(discovery_rec_t *rec, int show);
extern int idbm_print_all_discovery(int info_level);
extern int idbm_delete_discovery(discovery_rec_t *rec);
extern void idbm_node_setup_defaults(node_rec_t *rec);
extern int idbm_delete_node(node_rec_t *rec);
extern int idbm_add_node(node_rec_t *newrec, discovery_rec_t *drec,
			 int overwrite);
struct list_head;
typedef int (idbm_disc_nodes_fn)(void *data, struct iface_rec *iface,
				 struct list_head *recs);
extern int idbm_bind_ifaces_to_nodes(idbm_disc_nodes_fn *disc_node_fn,
				     void *data, struct list_head *ifaces,
				     struct list_head *bound_recs);
extern int idbm_add_discovery(discovery_rec_t *newrec);
extern void idbm_sendtargets_defaults(struct iscsi_sendtargets_config *cfg);
extern void idbm_isns_defaults(struct iscsi_isns_config *cfg);
extern void idbm_slp_defaults(struct iscsi_slp_config *cfg);
extern int idbm_discovery_read(discovery_rec_t *rec, int type, char *addr,
				int port);
extern int idbm_rec_read(node_rec_t *out_rec, char *target_name,
			 int tpgt, char *addr, int port,
			 struct iface_rec *iface);
extern int idbm_node_set_rec_from_param(struct list_head *params,
					node_rec_t *rec, int verify);
extern int idbm_node_set_param(void *data, node_rec_t *rec);
extern int idbm_discovery_set_param(void *data, discovery_rec_t *rec);
struct user_param *idbm_alloc_user_param(char *name, char *value);
extern void idbm_node_setup_defaults(node_rec_t *rec);
extern struct node_rec *idbm_find_rec_in_list(struct list_head *rec_list,
					      char *targetname, char *addr,
					      int port, struct iface_rec *iface);

/* lower level idbm functions for use by iface.c */
extern void idbm_recinfo_config(recinfo_t *info, FILE *f);
extern void idbm_recinfo_iface(struct iface_rec *r, recinfo_t *ri);
extern int idbm_lock(void);
extern void idbm_unlock(void);
extern recinfo_t *idbm_recinfo_alloc(int max_keys);
extern int idbm_verify_param(recinfo_t *info, char *name);
extern int idbm_rec_update_param(recinfo_t *info, char *name, char *value,
				 int line_number);
extern void idbm_recinfo_node(node_rec_t *r, recinfo_t *ri);

enum {
	IDBM_PRINT_TYPE_DISCOVERY,
	IDBM_PRINT_TYPE_NODE,
	IDBM_PRINT_TYPE_IFACE,
	IDBM_PRINT_TYPE_HOST_CHAP,
};

extern void idbm_print(int type, void *rec, int show, FILE *f);

struct boot_context;
extern struct node_rec *idbm_create_rec(char *targetname, int tpgt,
					char *ip, int port,
					struct iface_rec *iface,
					int verbose);
extern struct node_rec *
idbm_create_rec_from_boot_context(struct boot_context *context);

extern int idbm_print_host_chap_info(struct iscsi_chap_rec *chap);

#endif /* IDBM_H */
