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

#ifndef ulong_t
#define ulong_t unsigned long
#endif

#define ISCSI_PROVIDER_NAME_MAXLEN	64
#define ISCSI_PROVIDER_MAX		16
#define UEVENT_BASE			10
#define KEVENT_BASE			100

/* up events */
typedef enum iscsi_uevent_e {
	ISCSI_UEVENT_UNKNOWN		= 0,
	ISCSI_UEVENT_CREATE_SESSION	= UEVENT_BASE + 1,
	ISCSI_UEVENT_DESTROY_SESSION	= UEVENT_BASE + 2,
	ISCSI_UEVENT_CREATE_CNX		= UEVENT_BASE + 3,
	ISCSI_UEVENT_DESTROY_CNX	= UEVENT_BASE + 4,
	ISCSI_UEVENT_BIND_CNX		= UEVENT_BASE + 5,
	ISCSI_UEVENT_SEND_PDU_BEGIN	= UEVENT_BASE + 6,
	ISCSI_UEVENT_SEND_PDU_END	= UEVENT_BASE + 7,
} iscsi_uevent_e;

/* down events */
typedef enum iscsi_kevent_e {
	ISCSI_KEVENT_UNKNOWN		= 0,
	ISCSI_KEVENT_CNX_ERROR		= KEVENT_BASE + 1,
	ISCSI_KEVENT_RECV_PDU		= KEVENT_BASE + 2,
} iscsi_kevent_e;

typedef struct iscsi_uevent {
	int type; /* k/u events type */
	int provider_id;

	union {
		/* messages u -> k */
		struct msg_create_session {
			ulong_t		handle;
			unsigned int	sid;
			unsigned int	initial_cmdsn;
		} c_session;
		struct msg_destroy_session {
			unsigned int	sid;
		} d_session;
		struct msg_create_cnx {
			ulong_t		session_handle;
			ulong_t		handle;
			int		socket_fd;
			unsigned int	cid;
		} c_cnx;
		struct msg_bind_cnx {
			ulong_t		session_handle;
			ulong_t		handle;
			int		is_leading;
		} b_cnx;
		struct msg_destroy_cnx {
			unsigned int	cid;
		} d_cnx;
		struct msg_sp_begin {
			int		hdr_size;
			int		data_size;
			ulong_t		cnx_handle;
		} sp_begin;
		struct msg_sp_end {
			ulong_t		cnx_handle;
		} sp_end;
	} u;
	union {
		/* results */
		ulong_t			handle;
		int			retcode;
	} r;
} iscsi_uevent_t;

typedef struct iscsi_kevent {
	int type; /* k/u events type */

	union {
		/* messages k -> u */
		struct msg_cnx_error {
			unsigned int	cid;
		} cnxerror;
		struct msg_recv_pdu {
			unsigned int	cid;
			unsigned int	pdulen;
		} recvpdu;
	} u;
	union {
		/* results */
		ulong_t			handle;
		int			retcode;
	} r;
} iscsi_kevent_t;

#endif /* ISCSI_U_H */
