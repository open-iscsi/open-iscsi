/*
 * iSCSI Initiator for Linux Kernel (iSCSI Control Path)
 * Copyright (C) 2004 Dmitry Yusupov
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

#ifndef ISCSI_IF_H
#define ISCSI_IF_H

#include <net/tcp.h>
#include <iscsi_proto.h>
#include <iscsi_u.h>

typedef void* iscsi_snx_h;		/* iSCSI Data-Path session handle */
typedef void* iscsi_cnx_h;		/* iSCSI Data-Path connection handle */

typedef enum {
	ISCSI_STATE_FREE	= 1,
	ISCSI_STATE_LOGGED_IN	= 2,
	ISCSI_STATE_FAILED	= 3,
} iscsi_session_state_e;

/*
 * These flags presents iSCSI Data-Path capabilities.
 */
#define CAP_RECOVERY_L0		0x1
#define CAP_RECOVERY_L1		0x2
#define CAP_RECOVERY_L2		0x4
#define CAP_MULTI_R2T		0x8
#define CAP_HDRDGST		0x10
#define CAP_DATADGST		0x20
#define CAP_MULTI_CNX		0x40
#define CAP_TEXT_NEGO		0x80

typedef struct iscsi_caps {
	int	flags;
	int	max_cnx;
} iscsi_caps_t;

/**
 * struct iscsi_ops
 *
 * @caps: iSCSI Data-Path capabilities
 * @create_snx: create new iSCSI session object
 * @destroy_snx: destroy existing iSCSI session object
 * @create_cnx: create new iSCSI connection using specified transport
 * @bind_cnx: associate this connection with existing iSCSI session
 * @destroy_cnx: destroy inactive iSCSI connection
 * @set_param: set iSCSI Data-Path operational parameter
 * @start_cnx: set connection to be operational
 * @stop_cnx: suspend connection
 * @send_pdu: send iSCSI PDU, Login, Logout, NOP-Out, Reject, Text.
 *
 * API provided by generic iSCSI Data Path module
 */
typedef struct iscsi_ops {

	iscsi_snx_h	(*create_session) (iscsi_snx_h cp_snx,
					   int host_on,
					   int initial_cmdsn);

	void		(*destroy_session)(iscsi_snx_h dp_snx);

	iscsi_cnx_h	(*create_cnx)	  (iscsi_snx_h dp_snx,
					   iscsi_cnx_h cp_cnx,
					   struct socket *sock,
					   int cid);

	int		(*bind_cnx)	  (iscsi_snx_h dp_snx,
					   iscsi_cnx_h dp_cnx,
					   int is_leading);

	void		(*destroy_cnx)	  (iscsi_cnx_h dp_cnx);

	int		(*set_param)	  (iscsi_cnx_h dp_cnx,
					   iscsi_param_e param,
					   int value);

	int		(*start_cnx)	  (iscsi_cnx_h dp_cnx);

	void		(*stop_cnx)	  (iscsi_cnx_h dp_cnx);

	int		(*send_immpdu)	  (iscsi_cnx_h dp_cnx,
					   iscsi_hdr_t *hdr,
					   char *data,
					   int data_size);
} iscsi_ops_t;

int iscsi_control_recv_pdu(iscsi_cnx_h cp_cnx, iscsi_hdr_t *hdr,
				char *data, int data_size);
void iscsi_control_cnx_error(iscsi_cnx_h cp_cnx, iscsi_err_e error);

/* FIXME: generic register/unregister interface needed */
extern int iscsi_tcp_register(iscsi_ops_t *ops, iscsi_caps_t *caps);
extern void iscsi_tcp_unregister(void);

#endif
