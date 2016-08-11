/*
 * Copyright (c) 2011, Broadcom Corporation
 * Copyright (c) 2014, QLogic Corporation
 *
 * Written by:  Eddie Wai  (eddie.wai@broadcom.com)
 *              Based on Kevin Tran's iSCSI boot code
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Adam Dunkels.
 * 4. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * ipv6.h -  This file contains macro definitions pertaining to IPv6.
 *
 *     RFC 2460 : IPv6 Specification.
 *     RFC 2373 : IPv6 Addressing Architecture.
 *     RFC 2462 : IPv6 Stateless Address Autoconfiguration.
 *     RFC 2464 : Transmission of IPv6 Packets over Ethernet Networks.
 *
 */
#ifndef __IPV6_H__
#define __IPV6_H__

#include "ipv6_ndpc.h"

#define FALSE 0
#define TRUE  1

#define LINK_LOCAL_PREFIX_LENGTH	2
#define LAYER2_HEADER_LENGTH		14
#define LAYER2_VLAN_HEADER_LENGTH	16
#define LAYER2_TYPE_IPV6		0x86dd

struct ipv6_addr {
	union {
		u8_t addr8[16];
		u16_t addr16[8];
		u32_t addr[4];
	};
};

struct udp_hdr {
	u16_t src_port;
	u16_t dest_port;
	u16_t length;
	u16_t chksum;
};

struct mac_address {
	union {
		u8_t addr[6];
		struct {
			u16_t first_2_bytes;
			u32_t last_4_bytes;
		} __attribute__ ((packed));
	};
};

#define HOST_TO_NET16(a) htons(a)
#define HOST_TO_NET32(a) htonl(a)
#define NET_TO_HOST16(a) ntohs(a)
/*
 * Local definition for masks
 */
#define IPV6_MASK0   { { { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 } } }
#define IPV6_MASK32  { { { 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, \
			   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } }
#define IPV6_MASK64  { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, \
			   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } }
#define IPV6_MASK96  { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, \
			   0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 } } }
#define IPV6_MASK128 { { { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, \
			   0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff } } }

#ifdef BIG_ENDIAN
#define IPV6_ADDR_INT32_ONE     1
#define IPV6_ADDR_INT32_TWO     2
#define IPV6_ADDR_INT32_MNL     0xff010000
#define IPV6_ADDR_INT32_MLL     0xff020000
#define IPV6_ADDR_INT32_SMP     0x0000ffff
#define IPV6_ADDR_INT16_ULL     0xfe80
#define IPV6_ADDR_INT16_USL     0xfec0
#define IPV6_ADDR_INT16_MLL     0xff02
#else /* LITTE ENDIAN */
#define IPV6_ADDR_INT32_ONE     0x01000000
#define IPV6_ADDR_INT32_TWO     0x02000000
#define IPV6_ADDR_INT32_MNL     0x000001ff
#define IPV6_ADDR_INT32_MLL     0x000002ff
#define IPV6_ADDR_INT32_SMP     0xffff0000
#define IPV6_ADDR_INT16_ULL     0x80fe
#define IPV6_ADDR_INT16_USL     0xc0fe
#define IPV6_ADDR_INT16_MLL     0x02ff
#endif

/*
 * Definition of some useful macros to handle IP6 addresses
 */
#define IPV6_ADDR_ANY_INIT \
	{ { { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 } } }
#define IPV6_ADDR_LOOPBACK_INIT \
	{ { { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } } }
#define IPV6_ADDR_NODELOCAL_ALLNODES_INIT \
	{ { { 0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } } }
#define IPV6_ADDR_INTFACELOCAL_ALLNODES_INIT \
	{ { { 0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } } }
#define IPV6_ADDR_LINKLOCAL_ALLNODES_INIT \
	{ { { 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } } }
#define IPV6_ADDR_LINKLOCAL_ALLROUTERS_INIT \
	{ { { 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, \
	      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02 } } }

#define IPV6_ARE_ADDR_EQUAL(a, b) \
	(memcmp((char *)a, (char *)b, sizeof(struct ipv6_addr)) == 0)

/* Unspecified IPv6 address */
#define IPV6_IS_ADDR_UNSPECIFIED(a)	\
	((((a)->addr[0]) == 0) &&	\
	(((a)->addr[1]) == 0) &&	\
	(((a)->addr[2]) == 0) &&	\
	(((a)->addr[3]) == 0))

/* IPv6 Scope Values */
#define IPV6_ADDR_SCOPE_INTFACELOCAL    0x01	/* Node-local scope */
#define IPV6_ADDR_SCOPE_LINKLOCAL       0x02	/* Link-local scope */
#define IPV6_ADDR_SCOPE_SITELOCAL       0x05	/* Site-local scope */
#define IPV6_ADDR_SCOPE_ORGLOCAL        0x08	/* Organization-local scope */
#define IPV6_ADDR_SCOPE_GLOBAL          0x0e	/* Global scope */

/* Link-local Unicast : 10-bits much be 1111111010b --> 0xfe80. */
#define IPV6_IS_ADDR_LINKLOCAL(a)        \
	(((a)->addr8[0] == 0xfe) && (((a)->addr8[1] & 0xc0) == 0x80))

/* Site-local Unicast : 10-bits much be 1111111011b --> 0xfec0. */
#define IPV6_IS_ADDR_SITELOCAL(a)        \
	(((a)->addr8[0] == 0xfe) && (((a)->addr8[1] & 0xc0) == 0xc0))

/* Multicast : 10bits much be 11111111b. Next 4 bits is flags | 4-bit scope  */
#define IPV6_IS_ADDR_MULTICAST(a)	((a)->addr8[0] == 0xff)

#define IPV6_ADDR_MC_SCOPE(a)		((a)->addr8[1] & 0x0f)

/* Multicast Scope */

struct eth_hdr {
	struct mac_address dest_mac;
	struct mac_address src_mac;
	u16_t len_type;
};

struct ipv6_hdr {
	union {
		struct {
			u32_t ipv6_flow;	/* Version (4-bit) |
						   Traffic Class (8-bit) |
						   Flow ID (20-bit) */
			u16_t ipv6_plen;	/* Payload length */
			u8_t ipv6_nxt_hdr;	/* Next Header    */
			u8_t ipv6_hop_limit;	/* hop limit */
		} ipv6_dw1;

		u8_t ipv6_version_fc;	/* 4 bits version, top 4 bits class */
	} ipv6_ctrl;

	struct ipv6_addr ipv6_src;	/* Source address */
	struct ipv6_addr ipv6_dst;	/* Destination address */
};

#define ipv6_version_fc		ipv6_ctrl.ipv6_version_fc
#define ipv6_flow		ipv6_ctrl.ipv6_dw1.ipv6_flow
#define ipv6_plen		ipv6_ctrl.ipv6_dw1.ipv6_plen
#define ipv6_nxt_hdr		ipv6_ctrl.ipv6_dw1.ipv6_nxt_hdr
#define ipv6_hop_limit		ipv6_ctrl.ipv6_dw1.ipv6_hop_limit

#define IPV6_VERSION		0x60
#define IPV6_VERSION_MASK	0xf0
#define IPV6_HOP_LIMIT		64

/* Length of the IP header with no next header */
#define IPV6_HEADER_LEN		sizeof(struct ipv6_hdr)

#ifdef BIG_ENDIAN
#define IPV6_FLOWINFO_MASK	0x0fffffff	/* flow info (28 bits) */
#define IPV6_FLOWLABEL_MASK	0x000fffff	/* flow label (20 bits) */
#else /* LITTLE_ENDIAN */
#define IPV6_FLOWINFO_MASK	0xffffff0f	/* flow info (28 bits) */
#define IPV6_FLOWLABEL_MASK	0xffff0f00	/* flow label (20 bits) */
#endif

struct packet_ipv6 {
	struct mac_address dest_mac;
	struct mac_address src_mac;
	u16_t len_type;
	struct ipv6_hdr ipv6;
	union {
		struct udp_hdr udp;
	} layer4_prot;
};

struct packet_ipv6_vlan {
	struct mac_address dest_mac;
	struct mac_address src_mac;
	u16_t len_type;
	u16_t vlan_id;
	struct ipv6_hdr ipv6;
	union {
		struct udp_hdr udp;
	} layer4_prot;
};

struct ipv6_arp_entry {
	struct ipv6_addr ip_addr;
	struct mac_address mac_addr;
	u8_t time;
};

#define IPV6_NUM_OF_ADDRESS_ENTRY  4

struct ipv6_prefix_entry {
	struct ipv6_prefix_entry *next;
	struct ipv6_addr ip_addr;
	u8_t prefix_len;
};

struct ipv6_addr_entry {
	struct ipv6_addr ip_addr;
	u8_t prefix_len;
};

struct ipv6_context {
	u16_t flags;
#define IPV6_FLAGS_MANAGED_ADDR_CONFIG    (1 << 0)
#define IPV6_FLAGS_OTHER_STATEFUL_CONFIG  (1 << 1)
#define IPV6_FLAGS_ROUTER_ADV_RECEIVED    (1 << 2)
#define IPV6_FLAGS_DISABLE_DHCPV6         (1 << 3)

	struct mac_address mac_addr;
	struct ipv6_addr link_local_addr;
	struct ipv6_addr link_local_multi;
	struct ipv6_addr multi;	/* For Static IPv6 only */
	struct ipv6_addr multi_dest;	/* For Static IPv6 only */
	struct ipv6_addr default_router;
	struct ipv6_prefix_entry *addr_list;
	u8_t hop_limit;
#define UIP_ARPTAB_SIZE 16

	struct uip_stack *ustack;
#define MAX_MCADDR_TABLE 5
	struct mac_address mc_addr[MAX_MCADDR_TABLE];
	u8_t arptime;
	struct ipv6_arp_entry ipv6_arp_table[UIP_ARPTAB_SIZE];
	struct ipv6_prefix_entry ipv6_prefix_table[IPV6_NUM_OF_ADDRESS_ENTRY];

	/* VLAN support */

	void *dhcpv6_context;
};

#define ISCSI_FLAGS_DHCP_TCPIP_CONFIG (1<<0)
#define ISCSI_FLAGS_DHCP_ISCSI_CONFIG (1<<1)

#define IPV6_MAX_ROUTER_SOL_DELAY     4
#define IPV6_MAX_ROUTER_SOL_RETRY     3

#define DHCPV6_CLIENT_PORT    546
#define DHCPV6_SERVER_PORT    547

/* Function prototype */
void ipv6_init(struct ndpc_state *ndp, int cfg);
int ipv6_autoconfig(struct ipv6_context *context);
int ipv6_discover_address(struct ipv6_context *context);
struct ipv6_addr *ipv6_our_address(struct ipv6_context *context);
int ipv6_ip_in_arp_table(struct ipv6_context *context,
			 struct ipv6_addr *ipv6_addr,
			 struct mac_address *mac_addr);
void ipv6_arp_timer(struct ipv6_context *context);
void ipv6_arp_out(struct ipv6_context *context, int *uip_len);
int ipv6_add_prefix_entry(struct ipv6_context *context,
			  struct ipv6_addr *ip_addr, u8_t prefix_len);
void ipv6_set_ip_params(struct ipv6_context *context,
			struct ipv6_addr *src_ip, u8_t prefix_len,
			struct ipv6_addr *default_gateway,
			struct ipv6_addr *linklocal);
void ipv6_set_host_addr(struct ipv6_context *context, struct ipv6_addr *src_ip);
int ipv6_get_default_router_ip_addrs(struct ipv6_context *context,
				     struct ipv6_addr *ip_addr);
struct mac_address *ipv6_get_link_addr(struct ipv6_context *context);
u16_t ipv6_do_stateful_dhcpv6(struct ipv6_context *context, u32_t flags);
void ipv6_add_solit_node_address(struct ipv6_context *context,
				 struct ipv6_addr *ip_addr);
int ipv6_get_source_ip_addrs(struct ipv6_context *context,
			     struct ipv6_addr_entry *addr_list);
void ipv6_cfg_link_local_addr(struct ipv6_context *context,
			      struct ipv6_addr *ip_addr);
void ipv6_disable_dhcpv6(struct ipv6_context *context);
int ipv6_send_nd_solicited_packet(struct ipv6_context *context,
				  struct eth_hdr *eth, struct ipv6_hdr *ipv6);
int ipv6_is_it_our_link_local_address(struct ipv6_context *context,
				      struct ipv6_addr *ip_addr);
void ipv6_mc_init_dest_mac(struct eth_hdr *eth, struct ipv6_hdr *ipv6);
struct ipv6_addr *ipv6_find_longest_match(struct ipv6_context *context,
					  struct ipv6_addr *ip_addr);

#endif /* __IPV6_H__ */
