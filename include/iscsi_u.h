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

#define UEVENT_BASE		10
#define KEVENT_BASE		100

/* up events */
typedef enum iscsi_uevent_e {
	ISCSI_UEVENT_UNKNOWN		= 0,
	ISCSI_UEVENT_CREATE_SESSION	= UEVENT_BASE + 1,
	ISCSI_UEVENT_DESTROY_SESSION	= UEVENT_BASE + 2,
	ISCSI_UEVENT_CREATE_CNX		= UEVENT_BASE + 3,
	ISCSI_UEVENT_DESTROY_CNX	= UEVENT_BASE + 4,
	ISCSI_UEVENT_SEND_PDU		= UEVENT_BASE + 4,
} iscsi_uevent_e;

/* down events */
typedef enum iscsi_kevent_e {
	ISCSI_KEVENT_UNKNOWN		= 0,
	ISCSI_KEVENT_CNX_ERROR		= KEVENT_BASE + 1,
	ISCSI_KEVENT_RECV_PDU		= KEVENT_BASE + 2,
} iscsi_kevent_e;

typedef struct iscsi_uevent {
	int type; /* k/u events type */

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
