/*
 * Copyright (C) 2017-2018 Red Hat, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Author: Gris Ge <fge@redhat.com>
 */

#ifndef __ISCSI_USR_IFACE_H__
#define __ISCSI_USR_IFACE_H__

#include "libopeniscsiusr/libopeniscsiusr_common.h"
#include <stdint.h>
#include <netdb.h>
#include <net/if.h>

#define VALUE_MAXVAL	256   /* the maximum length of 223 bytes in the RFC. */
/* ^ VALUE_MAXVAL is copied from usr/idbm.h
 * The RFC 3720 only said:
 *	If not otherwise specified, the maximum length of a simple-value (not
 *	its encoded representation) is 255 bytes, not including the delimiter
 *	(comma or zero byte).
 */

#define ISCSI_MAX_IFACE_LEN			65
#define ISCSI_TRANSPORT_NAME_MAXLEN		16
#define ISCSI_MAX_STR_LEN			80
#define ISCSI_HWADDRESS_BUF_SIZE		18
#define TARGET_NAME_MAXLEN			VALUE_MAXVAL
/* ^ TODO(Gris Ge): Above 5 constants are copy from usr/config.h, need to
 *		    verify them in linux kernel code
 */

struct iscsi_iface {
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
	/* ^ prefix_len is removed, as linux kernel has no such sysfs property
	 * and there is no actual code in usr/ folder set this property
	 *
	 * Added back, we need to be backward compatible with iface records
	 * created by older tools. Look at fixing code to ignore in record
	 * files instead? - cleech
	 */
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
	bool			is_ipv6;
};

__DLL_LOCAL int _iscsi_iface_get_from_sysfs(struct iscsi_context *ctx,
					    uint32_t host_id, uint32_t sid,
					    char *iface_kern_id,
					    struct iscsi_iface **iface);

__DLL_LOCAL bool _iface_is_valid(struct iscsi_iface *iface);

#endif /* End of __ISCSI_USR_IFACE_H__ */
