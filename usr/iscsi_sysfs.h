/*
 * iSCSI sysfs
 *
 * Copyright (C) 2006 Mike Christie
 * Copyright (C) 2006 Red Hat, Inc. All rights reserved.
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
 */
#ifndef ISCSI_SYSFS_H
#define ISCSI_SYSFS_H

#include <search.h>
#include <sys/types.h>

struct iscsi_session;
struct iscsi_conn;
struct iscsi_session_operational_config;
struct iscsi_conn_operational_config;

extern int get_iscsi_kernel_version(char *buf);
extern void check_class_version(void);
extern int get_sessioninfo_by_sysfs_id(int *sid, char *targetname,
				      char *addr, int *port, int *tpgt,
				      char *sys_session);
extern int read_sysfs_file(char *filename, void *value, char *format);
extern int sysfs_for_each_session(void *data, int *nr_found,
			int (* fn)(void *, char *, int, char *, int, int));
extern uint32_t get_host_no_from_sid(uint32_t sid, int *err);
extern int set_exp_statsn(struct iscsi_conn *conn);
extern void get_negotiated_session_conf(int sid,
				struct iscsi_session_operational_config *conf);
extern void get_negotiated_conn_conf(int sid,
				struct iscsi_conn_operational_config *conf);
extern pid_t scan_host(struct iscsi_session *session);
extern pid_t __scan_host(int hostno, int async);
extern void set_device_online(int hostno, int lun);
extern void delete_device(int hostno, int lun);
extern int sysfs_for_each_device(int host_no, uint32_t sid,
				 void (* fn)(int host_no, int lun));
extern struct iscsi_provider_t *get_transport_by_hba(long host_no);
extern struct iscsi_provider_t *get_transport_by_session(char *sys_session);
extern struct iscsi_provider_t *get_transport_by_sid(uint32_t sid);
extern struct iscsi_provider_t *get_transport_by_name(char *transport_name);
extern void init_providers(void);

extern struct qelem providers;
extern int num_providers;

#endif
