/*
 * iSCSI kernel/user interface
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

#ifndef ISCSI_U_H
#define ISCSI_U_H

typedef enum iscsi_uevent_type {
	ISCSI_UEVENT_UNKNOWN	= 0,
	ISCSI_UEVENT_CONN_FAIL	= 1,
} iscsi_uevent_type_e;

typedef struct iscsi_uevent {
	unsigned int sid;
	unsigned int cid;
	iscsi_uevent_type_e state;
} iscsi_uevent_t;

#endif /* ISCSI_U_H */
