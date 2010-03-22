/*
 * iSCSI discovery 
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
#ifndef DISCOVERY_H
#define DISCOVERY_H


/* discovery.c */
struct discovery_rec;
struct list_head;
struct iface_rec;
struct node_rec;
struct boot_context;

extern int discovery_isns_query(struct discovery_rec *drec, const char *iname,
				const char *targetname,
				struct list_head *rec_list);
extern void discovery_isns_free_servername(void);
extern int discovery_isns_set_servername(char *address, int port);
extern int discovery_isns(void *data, struct iface_rec *iface,
			  struct list_head *rec_list);
extern int discovery_fw(void *data, struct iface_rec *iface,
			struct list_head *rec_list);
extern int discovery_sendtargets(void *data, struct iface_rec *iface,
				 struct list_head *rec_list);
extern int discovery_offload_sendtargets(int host_no, int do_login,
					 struct discovery_rec *drec);
#endif /* DISCOVERY_H */
