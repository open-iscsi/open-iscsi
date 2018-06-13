/*
 * iscsid communication helpers
 *
 * Copyright (C) 2010 Mike Christie
 * Copyright (C) 2010 Red Hat, Inc. All rights reserved.
 * maintained by open-iscsi@googlegroups.com
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

#ifndef ISCSID_REQ_H_
#define ISCSID_REQ_H

#define ISCSID_REQ_TIMEOUT 1000

struct iscsiadm_req;
struct iscsiadm_rsp;
struct node_rec;

extern char iscsid_namespace[64];
extern void iscsid_set_namespace(pid_t);

extern int iscsid_exec_req(struct iscsiadm_req *req, struct iscsiadm_rsp *rsp,
			   int iscsid_start, int tmo);
extern int iscsid_req_wait(iscsiadm_cmd_e cmd, int fd);
extern int iscsid_req_by_rec_async(iscsiadm_cmd_e cmd, struct node_rec *rec,
				   int *fd);
extern int iscsid_req_by_rec(iscsiadm_cmd_e cmd, struct node_rec *rec);
extern int iscsid_req_by_sid_async(iscsiadm_cmd_e cmd, int sid, int *fd);
extern int iscsid_req_by_sid(iscsiadm_cmd_e cmd, int sid);

extern int uip_broadcast(void *buf, size_t buf_len, int fd_flags,
			 uint32_t *status);

#endif
