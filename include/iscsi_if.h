/*
 * iSCSI User/Kernel Shares (Defines, Constants, Protocol definitions, etc)
 *
 * Copyright (C) 2005 Dmitry Yusupov, Alex Aizman
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

#ifndef ISCSI_IF_H
#define ISCSI_IF_H

#include <iscsi_proto.h>

#define ISCSI_TRANSPORT_NAME_MAXLEN	16
#define ISCSI_TRANSPORT_MAX		1
#define UEVENT_BASE			10
#define KEVENT_BASE			100
#define ISCSI_ERR_BASE			1000

/*
 * Common error codes
 */
enum iscsi_err {
	ISCSI_OK			= 0,

	ISCSI_ERR_DATASN		= ISCSI_ERR_BASE + 1,
	ISCSI_ERR_DATA_OFFSET		= ISCSI_ERR_BASE + 2,
	ISCSI_ERR_MAX_CMDSN		= ISCSI_ERR_BASE + 3,
	ISCSI_ERR_EXP_CMDSN		= ISCSI_ERR_BASE + 4,
	ISCSI_ERR_BAD_OPCODE		= ISCSI_ERR_BASE + 5,
	ISCSI_ERR_DATALEN		= ISCSI_ERR_BASE + 6,
	ISCSI_ERR_AHSLEN		= ISCSI_ERR_BASE + 7,
	ISCSI_ERR_PROTO			= ISCSI_ERR_BASE + 8,
	ISCSI_ERR_LUN			= ISCSI_ERR_BASE + 9,
	ISCSI_ERR_BAD_ITT		= ISCSI_ERR_BASE + 10,
	ISCSI_ERR_CNX_FAILED		= ISCSI_ERR_BASE + 11,
	ISCSI_ERR_R2TSN			= ISCSI_ERR_BASE + 12,
	ISCSI_ERR_SNX_FAILED		= ISCSI_ERR_BASE + 13,
	ISCSI_ERR_HDR_DGST		= ISCSI_ERR_BASE + 14,
	ISCSI_ERR_DATA_DGST		= ISCSI_ERR_BASE + 15,
	ISCSI_ERR_PDU_GATHER_FAILED	= ISCSI_ERR_BASE + 16,
	ISCSI_ERR_PARAM_NOT_FOUND	= ISCSI_ERR_BASE + 17
};

/*
 * iSCSI Parameters (RFC3720)
 */
enum iscsi_param {
	ISCSI_PARAM_MAX_RECV_DLENGTH	= 0,
	ISCSI_PARAM_MAX_XMIT_DLENGTH	= 1,
	ISCSI_PARAM_HDRDGST_EN		= 2,
	ISCSI_PARAM_DATADGST_EN		= 3,
	ISCSI_PARAM_INITIAL_R2T_EN	= 4,
	ISCSI_PARAM_MAX_R2T		= 5,
	ISCSI_PARAM_IMM_DATA_EN		= 6,
	ISCSI_PARAM_FIRST_BURST		= 7,
	ISCSI_PARAM_MAX_BURST		= 8,
	ISCSI_PARAM_PDU_INORDER_EN	= 9,
	ISCSI_PARAM_DATASEQ_INORDER_EN	= 10,
	ISCSI_PARAM_ERL			= 11,
	ISCSI_PARAM_IFMARKER_EN		= 12,
	ISCSI_PARAM_OFMARKER_EN		= 13,
};
#define ISCSI_PARAM_MAX			14

typedef uint64_t iscsi_snx_t;		/* iSCSI Data-Path session handle */
typedef uint64_t iscsi_cnx_t;		/* iSCSI Data-Path connection handle */

#define iscsi_ptr(_handle) ((void*)(unsigned long)_handle)
#define iscsi_handle(_ptr) ((uint64_t)(unsigned long)_ptr)
#define iscsi_hostdata(_hostdata) ((void*)_hostdata + sizeof(unsigned long))

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

/*
 * These flags describes reason of stop_cnx() call
 */
#define STOP_CNX_TERM		0x1
#define STOP_CNX_SUSPEND	0x2
#define STOP_CNX_RECOVER	0x3

#define ISCSI_STATS_CUSTOM_MAX		32
#define ISCSI_STATS_CUSTOM_DESC_MAX	64
struct iscsi_stats_custom {
	char desc[ISCSI_STATS_CUSTOM_DESC_MAX];
	uint64_t value;
};

/*
 * struct iscsi_stats - iSCSI Statistics (iSCSI MIB)
 *
 * Note: this structure contains counters collected on per-connection basis.
 */
struct iscsi_stats {
	/* octets */
	uint64_t txdata_octets;
	uint64_t rxdata_octets;

	/* xmit pdus */
	uint32_t noptx_pdus;
	uint32_t scsicmd_pdus;
	uint32_t tmfcmd_pdus;
	uint32_t login_pdus;
	uint32_t text_pdus;
	uint32_t dataout_pdus;
	uint32_t logout_pdus;
	uint32_t snack_pdus;

	/* recv pdus */
	uint32_t noprx_pdus;
	uint32_t scsirsp_pdus;
	uint32_t tmfrsp_pdus;
	uint32_t textrsp_pdus;
	uint32_t datain_pdus;
	uint32_t logoutrsp_pdus;
	uint32_t r2t_pdus;
	uint32_t async_pdus;
	uint32_t rjt_pdus;

	/* errors */
	uint32_t digest_err;
	uint32_t timeout_err;

	/*
	 * iSCSI Custom Statistics support, i.e. Transport could
	 * extend existing MIB statistics with its own specific statistics
	 * up to ISCSI_STATS_CUSTOM_MAX
	 */
	uint32_t custom_length;
	struct iscsi_stats_custom custom[0]
		__attribute__ ((aligned (sizeof(unsigned long))));
};

#endif
