/*
 * iSCSI Initiator TCP Data-Path
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

#ifndef ISCSI_IDP_TCP_H
#define ISCSI_IDP_TCP_H

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

/* Connection states */
#define ISCSI_CNX_INITIAL_STAGE		0
#define ISCSI_CNX_STARTED		1
#define ISCSI_CNX_STOPPED		2

/* Socket's Receive state machine */
#define IN_PROGRESS_WAIT_HEADER		0x0
#define IN_PROGRESS_HEADER_GATHER	0x1
#define IN_PROGRESS_DATA_RECV		0x2

/* Socket's Xmit state machine */
#define IN_PROGRESS_XMIT_IMM		0x0
#define IN_PROGRESS_XMIT_SCSI		0x1

/* iSCSI Task Command's state machine */
#define IN_PROGRESS_OP_MASK		0x3	/* READ | WRITE */
#define IN_PROGRESS_IDLE		0x0
#define IN_PROGRESS_READ		0x1
#define IN_PROGRESS_WRITE		0x2
#define IN_PROGRESS_HEAD		0x4
#define IN_PROGRESS_UNSOLICIT_HEAD	0x10
#define IN_PROGRESS_SOLICIT_HEAD	0x20
#define IN_PROGRESS_UNSOLICIT_WRITE	0x40
#define IN_PROGRESS_SOLICIT_WRITE	0x80
#define IN_PROGRESS_R2T_WAIT		0x100
#define IN_PROGRESS_BEGIN_WRITE		0x200
#define IN_PROGRESS_IMM_HEAD		0x400
#define IN_PROGRESS_IMM_DATA		0x800
#define IN_PROGRESS_BEGIN_WRITE_IMM	0x1000

#define ISCSI_DRV_VERSION	"0.1"
#define ISCSI_DEFAULT_PORT	3260
#define ISCSI_STRING_MAX	255
#define ISCSI_NODE_NAME_MAX	255
#define ISCSI_NODE_PORTAL_MAX	32
#define ISCSI_ALIAS_NAME_MAX	255
#define ISCSI_CONN_MAX		1
#define ISCSI_PORTAL_MAX	1
#define ISCSI_CONN_RCVBUF_MIN	262144
#define ISCSI_CONN_SNDBUF_MIN	262144
#define ISCSI_TEXT_SEPARATOR	'='
#define ISCSI_PAD_LEN		4
#define ISCSI_DATA_MAX		65536
#define ISCSI_DRAFT20_VERSION	0x00
#define ISCSI_R2T_MAX		16
#define ISCSI_IMM_CMDS_MAX	32
#define ISCSI_IMM_ITT_OFFSET	0x1000
#define ISCSI_CMD_DATAPOOL_SIZE	32

typedef struct iscsi_portal {
	unsigned char		ipaddr[16];
	int			port;
	int			tag;
} iscsi_portal_t;

typedef struct iscsi_queue {
	void			**pool;		/* Queue pool */
	int			cons;		/* Queue consumer pointer */
	int			prod;		/* Queue producer pointer */
	int			max;		/* Max number of elements */
	spinlock_t		*lock;		/* Queue protection lock */
} iscsi_queue_t;

struct iscsi_session;
struct iscsi_cmd_task;
struct iscsi_mgmt_task;

/* Socket connection recieve helper */
typedef struct iscsi_tcp_recv {
	iscsi_hdr_t		*hdr;
	struct sk_buff		*skb;
	int			offset;
	int			len;
	int			hdr_offset;
	int			copy;
	int			copied;
	int			padding;
	struct iscsi_cmd_task	*ctask;		/* current cmd in progress */

	/* copied and flipped values */
	int			opcode;
	int			flags;
	int			cmd_status;
	int			ahslen;
	int			datalen;
	uint32_t		itt;
} iscsi_tcp_recv_t;

typedef struct iscsi_conn {
	iscsi_hdr_t		hdr;		/* Header placeholder */
	iscsi_hdr_t		prev_hdr;	/* Header placeholder */
	uint32_t		prev_itt;

	/* FIXME: do dynamic allocation by size max_recv_dlength */
	char			data[ISCSI_DATA_MAX]; /* Data placeholder */
	int			data_copied;

	/* iSCSI connection-wide sequencing */
	uint32_t		exp_statsn;
	int			hdr_size;	/* PDU Header size pre-calc. */

	/* control data */
	int			senselen;	/* is data has sense? */
	int			cpu;		/* binded CPU */
	int			busy;
	int			id;		/* iSCSI CID */
	iscsi_tcp_recv_t	in;		/* TCP receive context */
	int			in_progress;	/* Connection state machine */
	struct socket           *sock;          /* BSD socket layer */
	struct iscsi_session	*session;	/* Parent session */
	struct list_head	item;		/* item's list of connections */
	iscsi_queue_t		immqueue;	/* Immediate xmit queue */
	iscsi_queue_t		xmitqueue;	/* Data-path queue */
	struct work_struct	xmitwork;	/* per-conn. xmit workqueue */
	struct semaphore	xmitsema;
	int			c_stage;	/* Connection state */
	iscsi_cnx_h		handle;		/* CP connection handle */
	int			in_progress_xmit; /* xmit state machine */
	spinlock_t		lock;

	/* configuration */
	int			max_recv_dlength;
	int			max_xmit_dlength;
	int			hdrdgst_en;
	int			datadgst_en;

	/* old values for socket callbacks */
	void			(*old_data_ready)(struct sock *, int);
	void			(*old_state_change)(struct sock *);
	void			(*old_write_space)(struct sock *);
} iscsi_conn_t;

typedef struct iscsi_session {
	/* iSCSI session-wide sequencing */
	uint32_t			cmdsn;
	uint32_t			exp_cmdsn;
	uint32_t			max_cmdsn;

	/* configuration */
	int				initial_r2t_en;
	int				max_r2t;
	int				imm_data_en;
	int				first_burst;
	int				max_burst;
	int				time2wait;
	int				time2retain;
	int				pdu_inorder_en;
	int				dataseq_inorder_en;
	int				erl;
	int				ifmarker_en;
	int				ofmarker_en;

	/* control data */
	struct scsi_host_template	sht;
	struct Scsi_Host		*host;
	uint8_t				isid[6];
	int				id;
	iscsi_conn_t			*leadconn;	/* Leading Conn. */
	spinlock_t			conn_lock;
	volatile iscsi_session_state_e	state;
	struct list_head		item;
	void				*auth_client;
	iscsi_snx_h			handle;		/* CP session handle */
	int				conn_cnt;

	struct list_head		connections;	/* list of connects. */
	int				cmds_max;	/* size of cmds array */
	struct iscsi_cmd_task		**cmds;		/* Original Cmds arr */
	iscsi_queue_t			cmdpool;	/* PDU's pool */
	int				imm_max;	/* size of Imm array */
	struct iscsi_mgmt_task		**imm_cmds;	/* Original Imm arr */
	iscsi_queue_t			immpool;	/* Imm PDU's pool */
} iscsi_session_t;

typedef struct iscsi_buf {
	struct page		*page;
	int			offset;
	int			size;
	int			sent;
} iscsi_buf_t;

typedef struct iscsi_data_task {
	iscsi_data_t		hdr;			/* PDU */
	char			opt[sizeof(__u32)];	/* Header-Digest */
	struct list_head	item;			/* data queue item */
} iscsi_data_task_t;

typedef struct iscsi_mgmt_task {
	iscsi_hdr_t	hdr;			/* mgmt. PDU */
	char		opt[sizeof(__u32)];	/* Header-Digest */
	char		*data;			/* mgmt payload */
	int		in_progress;		/* mgmt xmit progress */
	int		data_count;		/* counts data to be sent */
	iscsi_buf_t	headbuf;		/* Header Buffer */
	iscsi_buf_t	sendbuf;		/* in progress buffer */
	int		sent;
	uint32_t	itt;			/* this ITT */
} iscsi_mgmt_task_t;

typedef union iscsi_union_task {
	iscsi_data_task_t	dtask;
	iscsi_mgmt_task_t	mtask;
} iscsi_union_task_t;

typedef struct iscsi_r2t_info {
	int			ttt;		/* copied from R2T */
	int			data_length;	/* copied from R2T */
	int			data_offset;	/* copied from R2T */
	iscsi_buf_t		headbuf;	/* Data-Out Header Buffer */
	iscsi_buf_t		sendbuf;	/* Data-Out in progress buffer*/
	int			sent;		/* R2T sequence progress */
	int			cont_bit;	/* Data-Out cont. faulure */
	int			data_count;	/* DATA-Out payload progress */
	struct scatterlist	*sg;		/* per-R2T SG list */
} iscsi_r2t_info_t;

typedef struct iscsi_cmd_task {
	iscsi_cmd_t		hdr;			/* orig. SCSI PDU */
	char			opt[4*sizeof(__u16) +	/* one AHS */
				    sizeof(__u32)];	/* Header-Digest */
	int			itt;			/* this ITT */
	int			datasn;			/* DataSN numbering */
	iscsi_buf_t		headbuf;		/* Header Buffer */
	iscsi_buf_t		sendbuf;		/* in progress buffer */
	int			sent;
	struct scatterlist	*sg;			/* per-cmd SG list */
	struct scatterlist	*bad_sg;		/* assert statement */
	int			sg_count;		/* SG's to process */
	iscsi_data_task_t	**solicit_data;		/* Solicited PDU's */
	int			solicit_count;
	iscsi_data_task_t	**unsolicit_data;	/* Unsolicited PDU's */
	int			unsolicit_count;
	int			in_progress;		/* State machine */
	int			imm_count;		/* Imm-Data bytes */
	int			imm_data_count;		/* Imm-Data-Out bytes */
	int			data_count;		/* Remaining Data-Out */
	struct scsi_cmnd	*sc;			/* Assoc. SCSI cmnd */
	int			total_length;
	int			data_offset;
	iscsi_conn_t		*conn;			/* used connection */

	iscsi_r2t_info_t	*r2t;			/* in progress R2T */
	iscsi_queue_t		r2tpool;
	iscsi_queue_t		r2tqueue;
	iscsi_r2t_info_t	*r2ts;
	struct list_head	dataqueue;		/* Data-Out dataqueue */
	mempool_t		*datapool;
} iscsi_cmd_task_t;

#endif /* ISCSI_H */
