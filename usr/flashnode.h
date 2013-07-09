/*
 * iSCSI flashnode helpers
 *
 * Copyright (C) 2013 QLogic Corporation.
 * Maintained by open-iscsi@googlegroups.com
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
#ifndef FLASHNODE_H
#define FLASHNODE_H
#include <sys/types.h>
#include <netdb.h>
#include <net/if.h>

#include "types.h"
#include "config.h"
#include "auth.h"

#define MAX_FLASHNODE_IDX UINT_MAX

typedef enum portal_type {
	IPV4,
	IPV6,
} portal_type_e;

typedef struct flashnode_sess_rec {
	char			targetname[TARGET_NAME_MAXLEN];
	char			targetalias[TARGET_NAME_MAXLEN];
	char			username[AUTH_STR_MAX_LEN];
	char			username_in[AUTH_STR_MAX_LEN];
	char			password[AUTH_STR_MAX_LEN];
	char			password_in[AUTH_STR_MAX_LEN];
	/* indicates if discovery was done through iSNS discovery service
	 * or through sendTarget */
	char			discovery_parent_type[ISCSI_MAX_STR_LEN];
	char			isid[16];
	char			portal_type[5]; /* ipv4 or ipv6 */
	unsigned		first_burst_len;
	unsigned		max_burst_len;
	uint16_t		def_time2wait;
	uint16_t		def_time2retain;
	uint16_t		max_outstanding_r2t;
	uint16_t		tsid;
	uint16_t		def_taskmgmt_tmo;
	uint16_t		tpgt;
	uint16_t		chap_out_idx;
	uint16_t		chap_in_idx;
	/* index of iSCSI discovery session if the entry is
	 * discovered by iSCSI discovery session
	 */
	uint16_t		discovery_parent_idx;
	/* Firmware auto sendtarget discovery disable */
	uint8_t			auto_snd_tgt_disable;
	uint8_t			discovery_session;
	/* indicates if this flashnode entry is enabled or disabled */
	uint8_t			entry_enable;
	uint8_t			immediate_data;
	uint8_t			initial_r2t;
	uint8_t			data_seq_in_order;
	uint8_t			data_pdu_in_order;
	uint8_t			chap_auth_en;
	/* enables firmware to auto logout the discovery session on discovery
	 * completion
	 */
	uint8_t			discovery_logout_en;
	uint8_t			bidi_chap_en;
	/* makes authentication for discovery session optional */
	uint8_t			discovery_auth_optional;
	uint8_t			erl;
	uint8_t			is_boot_target;
} flashnode_sess_rec_t;

typedef struct flashnode_conn_rec {
	char			ipaddress[NI_MAXHOST];
	char			redirect_ipaddr[NI_MAXHOST];
	char			link_local_ipv6[NI_MAXHOST];
	unsigned		max_recv_dlength;
	unsigned		max_xmit_dlength;
	unsigned		max_segment_size;
	unsigned		tcp_xmit_wsf;
	unsigned		tcp_recv_wsf;
	uint32_t		stat_sn;
	uint32_t		exp_stat_sn;
	uint16_t		keepalive_tmo;
	uint16_t		port;
	uint16_t		local_port;
	uint16_t		ipv6_flow_lbl;
	/* Link local IPv6 address is assigned by firmware or driver */
	uint8_t			is_fw_assigned_ipv6;
	uint8_t			header_digest_en;
	uint8_t			data_digest_en;
	uint8_t			snack_req_en;
	/* tcp timestamp negotiation status */
	uint8_t			tcp_timestamp_stat;
	uint8_t			tcp_nagle_disable;
	/* tcp window scale factor */
	uint8_t			tcp_wsf_disable;
	uint8_t			tcp_timer_scale;
	uint8_t			tcp_timestamp_en;
	uint8_t			fragment_disable;
	uint8_t			ipv4_tos;
	uint8_t			ipv6_traffic_class;
} flashnode_conn_rec_t;

struct flashnode_rec {
	struct list_head	list;
	char			transport_name[ISCSI_TRANSPORT_NAME_MAXLEN];
	flashnode_sess_rec_t	sess;
	flashnode_conn_rec_t	conn[ISCSI_CONN_MAX];
};

extern int flashnode_info_print_flat(void *data, struct flashnode_rec *tgt,
				     uint32_t host_no, uint32_t flashnode_idx);
extern int iscsi_logout_flashnode_sid(struct iscsi_transport *t,
				      uint32_t host_no, uint32_t sid);
extern int flashnode_build_config(struct list_head *params,
				  struct flashnode_rec *flashnode,
				  struct iovec *iovs);
#endif
