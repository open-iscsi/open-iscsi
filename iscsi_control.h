/*
 * iSCSI Initiator Control Path
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

#ifndef ISCSI_CONTROL_H
#define ISCSI_CONTROL_H

#include <asm/io.h>
#include <net/tcp.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/inet.h>
#include <linux/blkdev.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_eh.h>
#include <scsi/scsi_request.h>
#include <scsi/scsi_tcq.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi.h>

#include <iscsi_if.h>

#define ISCSI_PORTAL_MAX	32
#define ISCSI_STRING_MAX	255
#define ISCSI_NODE_NAME_MAX	255
#define ISCSI_ALIAS_NAME_MAX	255
#define ISCSI_PROVIDER_MAX	1
#define ISCSI_SESSION_ATTRS_MAX	20

#define ISCSI_PROVIDER_TCP	0
#define ISCSI_PROVIDER_ISER	1

typedef struct iscsi_provider {
	char		name[16];
	iscsi_ops_t	ops;
	iscsi_caps_t	caps;
} iscsi_provider_t;

typedef enum {
	ISCSI_EVENT_CMD		= 1,
	ISCSI_EVENT_PDU		= 2,
	ISCSI_EVENT_REOPEN	= 3,
} iscsi_event_e;

struct iscsi_session_ctrl;
struct iscsi_cnx_ctrl;

typedef struct iscsi_event {
	/* Event's control info */
	struct list_head		item;
	iscsi_event_e			type;
	struct iscsi_session_ctrl	*session;
	struct iscsi_cnx_ctrl		*cnx;

	/* PDU event type */
	iscsi_hdr_t			rhdr;	/* outgoing PDU Header(if any)*/
	iscsi_hdr_t			hdr;	/* original PDU Header */
	char				*data;	/* original PDU Data */
} iscsi_event_t;

/* Initial iSCSI Connection-wide Parameters (See RFC 3720) */
typedef struct iscsi_cnx_params {
	uint32_t		max_recv_dlength;
	uint32_t		max_xmit_dlength;
	int			hdrdgst_en;
	int			datadgst_en;
} iscsi_cnx_params_t;

typedef struct iscsi_cnx_ctrl {
	iscsi_cnx_h		handle;		/* Data-Path conn. handle */
	struct list_head	item;		/* item in connection list */
	struct iscsi_session_ctrl *session;	/* associated session */
	iscsi_cnx_params_t	p;

	/* RFC 3720 Network Portal's parameters */
	unsigned char		ipaddr[16];
	int			port;
	int			tag;
	int			cid;
} iscsi_cnx_ctrl_t;

/* Initial iSCSI Session-wide Parameters (See RFC 3720) */
typedef struct iscsi_session_params {
	char			initiator_name[ISCSI_NODE_NAME_MAX];
	char			initiator_alias[ISCSI_ALIAS_NAME_MAX];
	uint8_t			isid[7];
	char			target_name[ISCSI_NODE_NAME_MAX];
	char			target_alias[ISCSI_ALIAS_NAME_MAX];
	char			target_portal[ISCSI_PORTAL_MAX];
	char			target_address[ISCSI_PORTAL_MAX];
	uint32_t		tpgt;
	uint32_t		tsih;
	uint32_t		first_burst;
	uint32_t		max_burst;
	uint32_t		max_r2t;
	uint32_t		max_cnx;
	int			erl;
	int			initial_r2t_en;
	int			imm_data_en;
	int			ifmarker_en;
	int			ofmarker_en;
	int			pdu_inorder_en;
	int			dataseq_inorder_en;
	uint32_t		time2wait;
	uint32_t		time2retain;
	int			auth_en;
	uint32_t		cmdsn;
	uint32_t		exp_cmdsn;
	uint32_t		max_cmdsn;
} iscsi_session_params_t;

typedef struct iscsi_session_ctrl {
	iscsi_snx_h		handle;		/* Data-Path session handle */
	int			host_no;	/* SCSI Host number */
	struct list_head	item;		/* item in session list */
	struct class		transport_class;
	iscsi_provider_t	*provider;
	iscsi_cnx_ctrl_t	*leadcnx;
	iscsi_session_params_t	p;
	iscsi_session_state_e	state;

	/* RFC 3720 FF and iSCSI Node parameters */
	int			time2wait;
	int			time2retain;
	char			target_name[ISCSI_NODE_NAME_MAX];
	char			target_alias[ISCSI_ALIAS_NAME_MAX];
	char			target_portal[ISCSI_PORTAL_MAX];
	char			target_address[ISCSI_PORTAL_MAX];
	uint16_t		tpgt;
	uint16_t		tsih;
	uint8_t			isid[6];
	uint16_t		max_cnx;

	struct list_head	connections;	/* connections list */
	spinlock_t		connections_lock;/* Protects connections */
	struct work_struct	eventwork;
	spinlock_t		eventlock;
	struct list_head	eventqueue;	/* the events queue */
	spinlock_t		freelock;
	struct list_head	freequeue;	/* pending to free queue */

	/* presetns iSCSI session as a transport /sys/class/iscsi_session
	 * associated with SCSI Host */
	struct scsi_transport_template	transportt;
	struct class_device_attribute *class_attrs[ISCSI_SESSION_ATTRS_MAX + 1];
} iscsi_session_ctrl_t;

typedef struct iscsi_initiator {
	iscsi_session_params_t	sp;		/* initial session params */
	iscsi_cnx_params_t	cp;		/* initial connection params */
	struct list_head	sessions;	/* sessions list */
	spinlock_t		sessions_lock;	/* Protects sessions */
} iscsi_initiator_t;

/*
 * Helper for parsing Initiator's initial parameters
 */
typedef struct iscsi_param {
	int		type;		/* 0 - int, 1 - string */
	char		key[32];
	void		*value;
	uint32_t	min, max;	/* range for int */
	int		show;
} iscsi_param_t;

#endif /* ISCSI_CONTROL_H */
