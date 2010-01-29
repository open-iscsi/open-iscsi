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

struct iscsiadm_req;
struct iscsiadm_rsp;
struct node_rec;

extern int iscsid_exec_req(struct iscsiadm_req *req, struct iscsiadm_rsp *rsp,
			   int iscsid_start);
extern void iscsid_handle_error(int err);
extern int iscsid_req_wait(int cmd, int fd);
extern int iscsid_req_by_rec_async(int cmd, struct node_rec *rec, int *fd);
extern int iscsid_req_by_rec(int cmd, struct node_rec *rec);
extern int iscsid_req_by_sid_async(int cmd, int sid, int *fd);
extern int iscsid_req_by_sid(int cmd, int sid);

#endif
