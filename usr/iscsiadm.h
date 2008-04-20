/*
 * iSCSI Administration Utility
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
#ifndef ISCSIADM_H
#define ISCSIADM_H

#include "types.h"
#include "strings.h"
#include "config.h"

/* discovery.c */
struct discovery_rec;
struct list_head;

extern int discovery_sendtargets(struct discovery_rec *drec,
				 struct list_head *rec_list);
extern int discovery_offload_sendtargets(int host_no, int do_login,
					 discovery_rec_t *drec);
#endif /* ISCSIADM_H */
