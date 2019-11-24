/*
 * iSCSI Configuration
 *
 * Copyright (C) 2002 Cisco Systems, Inc.
 * maintained by linux-iscsi-devel@lists.sourceforge.net
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

#ifndef CONFIG_H
#define CONFIG_H

#include <netdb.h>
#include <net/if.h>

#include "types.h"
#include "auth.h"	/* for the username and password sizes */
#include "list.h"
#include "iscsi_proto.h"
#include "iscsi_net_util.h"

/* ISIDs now have a typed naming authority in them.  We use an OUI */
#define DRIVER_ISID_0  0x00
#define DRIVER_ISID_1  0x02
#define DRIVER_ISID_2  0x3D

/* number of possible connections per session */
#define ISCSI_CONN_MAX		1
/* max len of interface */
#define ISCSI_MAX_IFACE_LEN	65

/* the following structures store the options set in the config file.
 * a structure is defined for each logically-related group of options.
 * if you are adding a new option, first check if it should belong
 * to one of the existing groups.  If it does, add it.  If not, define
 * a new structure.
 */

/* all authentication-related options should be added to this structure.
 * this structure is per-session, and can be configured
 * by TargetName but not Subnet.
 */
struct iscsi_auth_config {
	unsigned int authmethod;
	char username[AUTH_STR_MAX_LEN];
	unsigned char password[AUTH_STR_MAX_LEN];
	unsigned int password_length;
	char username_in[AUTH_STR_MAX_LEN];
	unsigned char password_in[AUTH_STR_MAX_LEN];
	unsigned int password_in_length;
	unsigned int chap_algs[AUTH_CHAP_ALG_MAX_COUNT];
};

/* all per-connection timeouts go in this structure.
 * this structure is per-portal, and can be configured
 * both by TargetName and Subnet.
 */
struct iscsi_connection_timeout_config {
	int login_timeout;
	int logout_timeout;
	int auth_timeout;
	int active_timeout;
	int noop_out_interval;
	int noop_out_timeout;
};

/* all per-session timeouts go in this structure.
 * this structure is per-session, and can be configured
 * by TargetName but not by Subnet.
 */
struct iscsi_session_timeout_config {
	int replacement_timeout;
};

/* all error handling timeouts go in this structure.
 * this structure is per-portal, and can be configured
 * both by TargetName and Subnet.
 */
struct iscsi_error_timeout_config {
	int abort_timeout;
	int host_reset_timeout;
	int lu_reset_timeout;
	int tgt_reset_timeout;
};

/* all TCP options go in this structure.
 * this structure is per-portal, and can be configured
 * both by TargetName and Subnet.
 */
struct iscsi_tcp_config {
	int window_size;
	int type_of_service;	/* try to set IP TOS bits */
};

struct iscsi_conn_operational_config {
	int MaxRecvDataSegmentLength;
	int MaxXmitDataSegmentLength;
	int HeaderDigest;
	int DataDigest;
	int IFMarker;
	int OFMarker;
};

/* all iSCSI operational params go in this structure.
 * this structure is per-portal, and can be configured
 * both by TargetName and Subnet.
 */
struct iscsi_session_operational_config {
	int DataPDUInOrder;
	int DataSequenceInOrder;
	int protocol;
	int InitialR2T;
	int ImmediateData;
	int FirstBurstLength;
	int MaxBurstLength;
	int DefaultTime2Wait;
	int DefaultTime2Retain;
	int MaxConnections;
	int MaxOutstandingR2T;
	int ERL;
	int FastAbort;
};

#define CONFIG_DIGEST_NEVER  0
#define CONFIG_DIGEST_ALWAYS 1
#define CONFIG_DIGEST_PREFER_ON 2
#define CONFIG_DIGEST_PREFER_OFF 3

struct iscsi_sendtargets_config {
	int reopen_max;
	int use_discoveryd;
	int discoveryd_poll_inval;
	struct iscsi_auth_config auth;
	struct iscsi_connection_timeout_config conn_timeo;
	struct iscsi_conn_operational_config conn_conf;
	struct iscsi_session_operational_config session_conf;
};

struct iscsi_isns_config {
	int use_discoveryd;
	int discoveryd_poll_inval;
};

struct iscsi_slp_config {
	char *scopes;
	char *interfaces;	/* for multicast, list of interfaces names,
				 * "all", or "none" */
	int poll_interval;
	struct iscsi_auth_config auth;
};

typedef enum iscsi_startup {
	ISCSI_STARTUP_MANUAL,
	ISCSI_STARTUP_AUTOMATIC,
	ISCSI_STARTUP_ONBOOT,
} iscsi_startup_e;

typedef enum discovery_type {
	DISCOVERY_TYPE_SENDTARGETS,
	DISCOVERY_TYPE_ISNS,
	DISCOVERY_TYPE_OFFLOAD_SENDTARGETS,
	DISCOVERY_TYPE_SLP,
	DISCOVERY_TYPE_STATIC,
	DISCOVERY_TYPE_FW,
} discovery_type_e;

typedef struct conn_rec {
	iscsi_startup_e				startup;
	char					address[NI_MAXHOST];
	int					port;
	struct iscsi_tcp_config			tcp;
	struct iscsi_connection_timeout_config	timeo;
	struct iscsi_conn_operational_config	iscsi;
} conn_rec_t;

typedef struct session_rec {
	int					initial_cmdsn;
	int					reopen_max;
	int					xmit_thread_priority;
	int					cmds_max;
	int					queue_depth;
	int					initial_login_retry_max;
	int					nr_sessions;
	int					scan;
	struct iscsi_auth_config		auth;
	struct iscsi_session_timeout_config	timeo;
	struct iscsi_error_timeout_config	err_timeo;
	struct iscsi_session_operational_config	iscsi;
	struct session_info			*info;
	unsigned                                sid;
	/*
	 * This is a flag passed to iscsid.  If set, multiple sessions are
	 * allowed to be initiated on this record
	 */
	unsigned char                           multiple;
	char					boot_root[BOOT_NAME_MAXLEN];
	char					boot_nic[BOOT_NAME_MAXLEN];
	char					boot_target[BOOT_NAME_MAXLEN];
} session_rec_t;

#define ISCSI_TRANSPORT_NAME_MAXLEN 16
#define ISCSI_MAX_STR_LEN 80

typedef struct iface_rec {
	struct list_head	list;
	/* iscsi iface record name */
	char			name[ISCSI_MAX_IFACE_LEN];
	uint32_t		iface_num;
	/* network layer iface name (eth0) */
	char			netdev[IFNAMSIZ];
	char			ipaddress[NI_MAXHOST];
	char			subnet_mask[NI_MAXHOST];
	char			gateway[NI_MAXHOST];
	char			bootproto[ISCSI_MAX_STR_LEN];
	char			ipv6_linklocal[NI_MAXHOST];
	char			ipv6_router[NI_MAXHOST];
	char			ipv6_autocfg[NI_MAXHOST];
	char			linklocal_autocfg[NI_MAXHOST];
	char			router_autocfg[NI_MAXHOST];
	uint8_t			prefix_len;
	uint16_t		vlan_id;
	uint8_t			vlan_priority;
	char			vlan_state[ISCSI_MAX_STR_LEN];
	char			state[ISCSI_MAX_STR_LEN]; /* 0 = disable,
							   * 1 = enable */
	uint16_t		mtu;
	uint16_t		port;
	char			delayed_ack[ISCSI_MAX_STR_LEN];
	char			nagle[ISCSI_MAX_STR_LEN];
	char			tcp_wsf_state[ISCSI_MAX_STR_LEN];
	uint8_t			tcp_wsf;
	uint8_t			tcp_timer_scale;
	char			tcp_timestamp[ISCSI_MAX_STR_LEN];
	char			dhcp_dns[ISCSI_MAX_STR_LEN];
	char			dhcp_slp_da[ISCSI_MAX_STR_LEN];
	char			tos_state[ISCSI_MAX_STR_LEN];
	uint8_t			tos;
	char			gratuitous_arp[ISCSI_MAX_STR_LEN];
	char			dhcp_alt_client_id_state[ISCSI_MAX_STR_LEN];
	char			dhcp_alt_client_id[ISCSI_MAX_STR_LEN];
	char			dhcp_req_vendor_id_state[ISCSI_MAX_STR_LEN];
	char			dhcp_vendor_id_state[ISCSI_MAX_STR_LEN];
	char			dhcp_vendor_id[ISCSI_MAX_STR_LEN];
	char			dhcp_learn_iqn[ISCSI_MAX_STR_LEN];
	char			fragmentation[ISCSI_MAX_STR_LEN];
	char			incoming_forwarding[ISCSI_MAX_STR_LEN];
	uint8_t			ttl;
	char			gratuitous_neighbor_adv[ISCSI_MAX_STR_LEN];
	char			redirect[ISCSI_MAX_STR_LEN];
	char			mld[ISCSI_MAX_STR_LEN];
	uint32_t		flow_label;
	uint32_t		traffic_class;
	uint8_t			hop_limit;
	uint32_t		nd_reachable_tmo;
	uint32_t		nd_rexmit_time;
	uint32_t		nd_stale_tmo;
	uint8_t			dup_addr_detect_cnt;
	uint32_t		router_adv_link_mtu;
	uint16_t		def_task_mgmt_tmo;
	char			header_digest[ISCSI_MAX_STR_LEN];
	char			data_digest[ISCSI_MAX_STR_LEN];
	char			immediate_data[ISCSI_MAX_STR_LEN];
	char			initial_r2t[ISCSI_MAX_STR_LEN];
	char			data_seq_inorder[ISCSI_MAX_STR_LEN];
	char			data_pdu_inorder[ISCSI_MAX_STR_LEN];
	uint8_t			erl;
	uint32_t		max_recv_dlength;
	uint32_t		first_burst_len;
	uint16_t		max_out_r2t;
	uint32_t		max_burst_len;
	char			chap_auth[ISCSI_MAX_STR_LEN];
	char			bidi_chap[ISCSI_MAX_STR_LEN];
	char			strict_login_comp[ISCSI_MAX_STR_LEN];
	char			discovery_auth[ISCSI_MAX_STR_LEN];
	char			discovery_logout[ISCSI_MAX_STR_LEN];
	char			port_state[ISCSI_MAX_STR_LEN];
	char			port_speed[ISCSI_MAX_STR_LEN];
	/*
	 * TODO: we may have to make this bigger and interconnect
	 * specific for infiniband
	 */
	char			hwaddress[ISCSI_HWADDRESS_BUF_SIZE];
	char			transport_name[ISCSI_TRANSPORT_NAME_MAXLEN];
	/*
	 * This is only used for boot now, but the iser guys
	 * can use this for their virtualization idea.
	 */
	char			alias[TARGET_NAME_MAXLEN + 1];
	char			iname[TARGET_NAME_MAXLEN + 1];
} iface_rec_t;

typedef struct node_rec {
	struct list_head	list;
	char			name[TARGET_NAME_MAXLEN];
	int			tpgt;
	iscsi_startup_e		startup;
	int			leading_login;
	session_rec_t		session;
	conn_rec_t		conn[ISCSI_CONN_MAX];
	iface_rec_t		iface;
	discovery_type_e	disc_type;
	char			disc_address[NI_MAXHOST];
	int			disc_port;
} node_rec_t;

typedef struct discovery_rec {
	iscsi_startup_e		startup;
	discovery_type_e	type;
	char			address[NI_MAXHOST];
	int			port;
	int			iscsid_req_tmo;
	union {
		struct iscsi_sendtargets_config	sendtargets;
		struct iscsi_slp_config		slp;
		struct iscsi_isns_config	isns;
	} u;
} discovery_rec_t;

#endif /* CONFIG_H */
