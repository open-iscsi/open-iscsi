/*
 * iSCSI Kernel/User Interface
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

#define UEVENT_IN_BASE		10
#define UEVENT_OUT_BASE		100

typedef enum iscsi_uevent_e {
	ISCSI_UEVENT_UNKNOWN			= 0,
	ISCSI_UEVENT_OUT_CNX_ERROR		= UEVENT_OUT_BASE + 1,
	ISCSI_UEVENT_OUT_RECV_PDU		= UEVENT_OUT_BASE + 2,
	ISCSI_UEVENT_IN_CREATE_SESSION		= UEVENT_IN_BASE + 1,
	ISCSI_UEVENT_IN_DESTROY_SESSION		= UEVENT_IN_BASE + 2,
	ISCSI_UEVENT_IN_CREATE_CNX		= UEVENT_IN_BASE + 3,
	ISCSI_UEVENT_IN_DESTROY_CNX		= UEVENT_IN_BASE + 4,
} iscsi_uevent_e;

typedef struct iscsi_uevent {
	iscsi_uevent_e type;

	union {
		/* messages */
		struct msg_recv_pdu {
			unsigned int	cid;
			unsigned int	pdulen;
		} recvpdu;
		struct msg_cnx_error {
			unsigned int	cid;
		} cnxerror;
		struct msg_create_session {
			unsigned int	sid;
			unsigned int	initial_cmdsn;
		} c_session;
		struct msg_destroy_session {
			unsigned int	sid;
		} d_session;
		struct msg_create_cnx {
			unsigned int	sid;
			unsigned int	cid;
		} c_cnx;
		struct msg_destroy_cnx {
			unsigned int	cid;
		} d_cnx;
	} u;
} iscsi_uevent_t;

#endif /* ISCSI_U_H */
