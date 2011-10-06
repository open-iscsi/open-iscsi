/*
 * iSCSI Netlink attr helpers
 *
 * Copyright (C) 2011 Red Hat, Inc. All rights reserved.
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

#ifndef ISCSI_NLA_H
#define ISCSI_NLA_H

#include <linux/netlink.h>

struct iovec;

#define ISCSI_NLA_HDRLEN	((int) NLA_ALIGN(sizeof(struct nlattr)))
#define ISCSI_NLA_DATA(nla)	((void *)((char*)(nla) + ISCSI_NLA_HDRLEN))
#define ISCSI_NLA_LEN(len) 	((len) + NLA_ALIGN(ISCSI_NLA_HDRLEN))
#define ISCSI_NLA_TOTAL_LEN(len) (NLA_ALIGN(ISCSI_NLA_LEN(len)))

extern struct nlattr *iscsi_nla_alloc(uint16_t type, uint16_t len);

#endif
