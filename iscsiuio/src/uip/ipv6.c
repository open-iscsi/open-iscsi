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
 * ipv6.c - This file contains simplifed IPv6 processing code.
 *
 */
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include "logger.h"
#include "uip.h"
#include "ipv6.h"
#include "ipv6_pkt.h"
#include "icmpv6.h"
#include "uipopt.h"
#include "dhcpv6.h"
#include "ping.h"

inline int best_match_bufcmp(u8_t *a, u8_t *b, int len)
{
	int i;

	for (i = 0; i < len; i++) {
		if (a[i] != b[i])
			break;
	}
	return i;
}

/* Local function prototypes */
static int ipv6_is_it_our_address(struct ipv6_context *context,
				  struct ipv6_addr *ip_addr);
static void ipv6_insert_protocol_chksum(struct ipv6_hdr *ipv6);
static void ipv6_update_arp_table(struct ipv6_context *context,
				  struct ipv6_addr *ip_addr,
				  struct mac_address *mac_addr);
static void ipv6_icmp_init_link_option(struct ipv6_context *context,
				       struct icmpv6_opt_link_addr *link_opt,
				       u8_t type);
static void ipv6_icmp_rx(struct ipv6_context *context);
static void ipv6_icmp_handle_nd_adv(struct ipv6_context *context);
static void ipv6_icmp_handle_nd_sol(struct ipv6_context *context);
static void ipv6_icmp_handle_echo_request(struct ipv6_context *context);
static void ipv6_icmp_handle_router_adv(struct ipv6_context *context);
static void ipv6_icmp_process_prefix(struct ipv6_context *context,
				     struct icmpv6_opt_prefix *icmp_prefix);
static void ipv6_udp_rx(struct ipv6_context *context);

int iscsiL2Send(struct ipv6_context *context, int pkt_len)
{
	LOG_DEBUG("IPv6: iscsiL2Send");
	uip_send(context->ustack,
		 (void *)context->ustack->data_link_layer, pkt_len);

	return pkt_len;
}

int iscsiL2AddMcAddr(struct ipv6_context *context,
		     struct mac_address *new_mc_addr)
{
	int i;
	struct mac_address *mc_addr;
	const struct mac_address all_zeroes_mc = { { { 0, 0, 0, 0, 0, 0 } } };

	mc_addr = context->mc_addr;
	for (i = 0; i < MAX_MCADDR_TABLE; i++, mc_addr++)
		if (!memcmp((char *)mc_addr,
			    (char *)new_mc_addr, sizeof(struct mac_address)))
			return TRUE;	/* Already in the mc table */

	mc_addr = context->mc_addr;
	for (i = 0; i < MAX_MCADDR_TABLE; i++, mc_addr++) {
		if (!memcmp((char *)mc_addr,
		    (char *)&all_zeroes_mc, sizeof(struct mac_address))) {
			memcpy((char *)mc_addr,
			       (char *)new_mc_addr, sizeof(struct mac_address));
			LOG_DEBUG("IPv6: mc_addr added "
				  "%02x:%02x:%02x:%02x:%02x:%02x",
				  *(u8_t *)new_mc_addr,
				  *((u8_t *)new_mc_addr + 1),
				  *((u8_t *)new_mc_addr + 2),
				  *((u8_t *)new_mc_addr + 3),
				  *((u8_t *)new_mc_addr + 4),
				  *((u8_t *)new_mc_addr + 5));
			return TRUE;
		}
	}
	return FALSE;
}

int iscsiL2IsOurMcAddr(struct ipv6_context *context,
		       struct mac_address *dest_mac)
{
	int i;
	struct mac_address *mc_addr;

	mc_addr = context->mc_addr;
	for (i = 0; i < MAX_MCADDR_TABLE; i++, mc_addr++)
		if (!memcmp((char *)mc_addr,
			    (char *)dest_mac->addr, sizeof(struct mac_address)))
			return TRUE;
	return FALSE;
}

void ipv6_init(struct ndpc_state *ndp, int cfg)
{
	int i;
	struct ipv6_context *context = (struct ipv6_context *)ndp->ipv6_context;
	struct mac_address *mac_addr = (struct mac_address *)ndp->mac_addr;
	struct ipv6_arp_entry *ipv6_arp_table;
	struct ipv6_prefix_entry *ipv6_prefix_table;
	struct mac_address mc_addr;

	if (context == NULL) {
		LOG_ERR("IPV6: INIT ipv6_context is NULL");
		return;
	}

	memset((char *)context, 0, sizeof(struct ipv6_context));

	/* Associate the nic_iface's ustack to this ipv6_context */
	context->ustack = ndp->ustack;

	ipv6_arp_table = &context->ipv6_arp_table[0];
	ipv6_prefix_table = &context->ipv6_prefix_table[0];

	memset((char *)ipv6_arp_table, 0, sizeof(*ipv6_arp_table));
	memset((char *)ipv6_prefix_table, 0, sizeof(*ipv6_prefix_table));
	memcpy((char *)&context->mac_addr,
	       (char *)mac_addr, sizeof(struct mac_address));
	/*
	 * Per RFC 2373.
	 * There are two types of local-use unicast addresses defined.  These
	 * are Link-Local and Site-Local.  The Link-Local is for use on a single
	 * link and the Site-Local is for use in a single site.  Link-Local
	 * addresses have the following format:
	 *
	 * |   10     |
	 * |  bits    |        54 bits          |          64 bits           |
	 * +----------+-------------------------+----------------------------+
	 * |1111111010|           0             |       interface ID         |
	 * +----------+-------------------------+----------------------------+
	 */
	if (context->ustack->linklocal_autocfg != IPV6_LL_AUTOCFG_OFF) {
		context->link_local_addr.addr8[0] = 0xfe;
		context->link_local_addr.addr8[1] = 0x80;
		/* Bit 1 is 1 to indicate universal scope. */
		context->link_local_addr.addr8[8] = mac_addr->addr[0] | 0x2;
		context->link_local_addr.addr8[9] = mac_addr->addr[1];
		context->link_local_addr.addr8[10] = mac_addr->addr[2];
		context->link_local_addr.addr8[11] = 0xff;
		context->link_local_addr.addr8[12] = 0xfe;
		context->link_local_addr.addr8[13] = mac_addr->addr[3];
		context->link_local_addr.addr8[14] = mac_addr->addr[4];
		context->link_local_addr.addr8[15] = mac_addr->addr[5];

		context->link_local_multi.addr8[0] = 0xff;
		context->link_local_multi.addr8[1] = 0x02;
		context->link_local_multi.addr8[11] = 0x01;
		context->link_local_multi.addr8[12] = 0xff;
		context->link_local_multi.addr8[13] |=
		    context->link_local_addr.addr8[13];
		context->link_local_multi.addr16[7] =
		    context->link_local_addr.addr16[7];

		/* Default Prefix length is 64 */
		/* Add Link local address to the head of the ipv6 address
		   list */
		ipv6_add_prefix_entry(context,
				      &context->link_local_addr, 64);
	}
	/*
	 * Convert Multicast IP address to Multicast MAC adress per
	 * RFC 2464: Transmission of IPv6 Packets over Ethernet Networks
	 *
	 * An IPv6 packet with a multicast destination address DST, consisting
	 * of the sixteen octets DST[1] through DST[16], is transmitted to the
	 * Ethernet multicast address whose first two octets are the value 3333
	 * hexadecimal and whose last four octets are the last four octets of
	 * DST.
	 *
	 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *          |0 0 1 1 0 0 1 1|0 0 1 1 0 0 1 1|
	 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *          |   DST[13]     |   DST[14]     |
	 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *          |   DST[15]     |   DST[16]     |
	 *          +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *
	 * IPv6 requires the following Multicast IP addresses setup per node.
	 */
	for (i = 0; i < 3; i++) {
		mc_addr.addr[0] = 0x33;
		mc_addr.addr[1] = 0x33;
		mc_addr.addr[2] = 0x0;
		mc_addr.addr[3] = 0x0;
		mc_addr.addr[4] = 0x0;

		switch (i) {
		case 0:
			/* All Nodes Multicast IPv6 address : ff02::1 */
			mc_addr.addr[5] = 0x1;
			break;

		case 1:
			/* All Host Multicast IPv6 address : ff02::3 */
			mc_addr.addr[5] = 0x3;
			break;

		case 2:
			/* Solicited Node Multicast Address: ff02::01:ffxx:yyzz
			 */
			mc_addr.addr[2] = 0xff;
			mc_addr.addr[3] = mac_addr->addr[3];
			mc_addr.addr[4] = mac_addr->addr[4];
			mc_addr.addr[5] = mac_addr->addr[5];
			break;

		default:
			break;
		}
		iscsiL2AddMcAddr(context, &mc_addr);
	}

	/* Default HOP number */
	context->hop_limit = IPV6_HOP_LIMIT;
}

int ipv6_add_prefix_entry(struct ipv6_context *context,
			  struct ipv6_addr *ip_addr, u8_t prefix_len)
{
	int i;
	struct ipv6_prefix_entry *prefix_entry;
	struct ipv6_prefix_entry *ipv6_prefix_table =
				  context->ipv6_prefix_table;
	char addr_str[INET6_ADDRSTRLEN];

	/* Check if there is an valid entry already. */
	for (i = 0; i < IPV6_NUM_OF_ADDRESS_ENTRY; i++) {
		prefix_entry = &ipv6_prefix_table[i];

		if (prefix_entry->prefix_len != 0) {
			if (memcmp((char *)&prefix_entry->ip_addr,
				   (char *)ip_addr,
				   sizeof(struct ipv6_addr)) == 0) {
				/* We already initialize on this interface.
				   There is nothing to do */
				return 0;
			}
		}
	}

	/* Find an unused entry */
	for (i = 0; i < IPV6_NUM_OF_ADDRESS_ENTRY; i++) {
		prefix_entry = &ipv6_prefix_table[i];

		if (prefix_entry->prefix_len == 0)
			break;
	}

	if (prefix_entry->prefix_len != 0)
		return -1;

	prefix_entry->prefix_len = prefix_len / 8;

	memcpy((char *)&prefix_entry->ip_addr,
	       (char *)ip_addr, sizeof(struct ipv6_addr));

	inet_ntop(AF_INET6, &prefix_entry->ip_addr.addr8, addr_str,
		  sizeof(addr_str));

	LOG_DEBUG("IPv6: add prefix IP addr %s", addr_str);

	/* Put it on the list on head of the list. */
	if (context->addr_list != NULL)
		prefix_entry->next = context->addr_list;
	else
		prefix_entry->next = NULL;

	context->addr_list = prefix_entry;

	return 0;
}

void ipv6_rx_packet(struct ipv6_context *context, u16_t len)
{
	struct ipv6_hdr *ipv6;
	u16_t protocol;

	if (!context->ustack) {
		LOG_WARN("ipv6 rx pkt ipv6_context = %p ustack = %p", context,
			 context->ustack);
		return;
	}
	ipv6 = (struct ipv6_hdr *)context->ustack->network_layer;
	/* Make sure it's an IPv6 packet */
	if ((ipv6->ipv6_version_fc & 0xf0) != IPV6_VERSION) {
		/* It's not an IPv6 packet. Drop it. */
		LOG_WARN("IPv6 version 0x%x not IPv6", ipv6->ipv6_version_fc);
		return;
	}
	protocol = ipv6_process_rx(ipv6);

	switch (protocol) {
	case IPPROTO_ICMPV6:
		ipv6_icmp_rx(context);
		break;

	case IPPROTO_UDP:
		/* Indicate to UDP processing code */
		ipv6_udp_rx(context);
		break;

	default:
		break;
	}
}

void ipv6_mc_init_dest_mac(struct eth_hdr *eth, struct ipv6_hdr *ipv6)
{
	int i;
	/*
	 * Initialize address mapping of IPV6 Multicast to multicast MAC
	 * address per RFC 2464.
	 *
	 * An IPv6 packet with a multicast destination address DST, consisting
	 * of the sixteen octets DST[1] through DST[16], is transmitted to the
	 * Ethernet multicast address whose first two octets are the value 3333
	 * hexadecimal and whose last four octets are the last four octets of
	 * DST.
	 *
	 *              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *              |0 0 1 1 0 0 1 1|0 0 1 1 0 0 1 1|
	 *              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *              |   DST[13]     |   DST[14]     |
	 *              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 *              |   DST[15]     |   DST[16]     |
	 *              +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
	eth->dest_mac.addr[0] = 0x33;
	eth->dest_mac.addr[1] = 0x33;
	for (i = 0; i < 4; i++)
		eth->dest_mac.addr[2 + i] = ipv6->ipv6_dst.addr8[12 + i];
}

int ipv6_autoconfig(struct ipv6_context *context)
{
	return ipv6_discover_address(context);
}

int ipv6_discover_address(struct ipv6_context *context)
{
	struct eth_hdr *eth =
			(struct eth_hdr *)context->ustack->data_link_layer;
	struct ipv6_hdr *ipv6 =
			(struct ipv6_hdr *)context->ustack->network_layer;
	struct icmpv6_hdr *icmp = (struct icmpv6_hdr *)((u8_t *)ipv6 +
						sizeof(struct ipv6_hdr));
	int rc = 0;

	/* Retrieve tx buffer */
	if (eth == NULL || ipv6 == NULL)
		return -EAGAIN;

	/* Setup IPv6 All Routers Multicast address : ff02::2 */
	memset((char *)&ipv6->ipv6_dst, 0, sizeof(struct ipv6_addr));
	ipv6->ipv6_dst.addr8[0] = 0xff;
	ipv6->ipv6_dst.addr8[1] = 0x02;
	ipv6->ipv6_dst.addr8[15] = 0x02;
	ipv6->ipv6_hop_limit = 255;

	/* Initialize MAC header based on destination MAC address */
	ipv6_mc_init_dest_mac(eth, ipv6);
	ipv6->ipv6_nxt_hdr = IPPROTO_ICMPV6;

	icmp->icmpv6_type = ICMPV6_RTR_SOL;
	icmp->icmpv6_code = 0;
	icmp->icmpv6_data = 0;
	icmp->icmpv6_cksum = 0;
	ipv6_icmp_init_link_option(context,
				   (struct icmpv6_opt_link_addr *)((u8_t *)icmp
					+ sizeof(struct icmpv6_hdr)),
					IPV6_ICMP_OPTION_SRC_ADDR);
	ipv6->ipv6_plen = HOST_TO_NET16((sizeof(struct icmpv6_hdr) +
					 sizeof(struct icmpv6_opt_link_addr)));
	memcpy((char *)&ipv6->ipv6_src,
	       (char *)&context->link_local_addr,
	       sizeof(struct ipv6_addr));

	icmp->icmpv6_cksum = 0;
	LOG_DEBUG("IPv6: Send rtr sol");
	ipv6_send(context, (u8_t *) icmp - (u8_t *) eth +
		  sizeof(struct icmpv6_hdr) +
		  sizeof(struct icmpv6_opt_link_addr));
	return rc;
}

u16_t ipv6_process_rx(struct ipv6_hdr *ipv6)
{
	return ipv6->ipv6_nxt_hdr;
}

int ipv6_send(struct ipv6_context *context, u16_t packet_len)
{
	struct eth_hdr *eth =
			(struct eth_hdr *)context->ustack->data_link_layer;
	struct ipv6_hdr *ipv6 =
			(struct ipv6_hdr *)context->ustack->network_layer;

	ipv6_setup_hdrs(context, eth, ipv6, packet_len);

	return iscsiL2Send(context, packet_len);
}

void ipv6_send_udp_packet(struct ipv6_context *context, u16_t packet_len)
{
	struct eth_hdr *eth =
			(struct eth_hdr *)context->ustack->data_link_layer;
	struct ipv6_hdr *ipv6 =
			(struct ipv6_hdr *)context->ustack->network_layer;
	struct udp_hdr *udp = (struct udp_hdr *)((u8_t *)ipv6 +
						 sizeof(struct ipv6_hdr));

	ipv6->ipv6_nxt_hdr = IPPROTO_UDP;
	ipv6->ipv6_plen =
	    HOST_TO_NET16(packet_len - ((u8_t *)udp - (u8_t *)eth));

	udp->chksum = 0;

	/*
	 * We only use UDP packet for DHCPv6.  The source address is always
	 * link-local address.
	 */
	ipv6->ipv6_src.addr[0] = 0;

	/* Hop limit is always 1 for DHCPv6 packet. */
	ipv6->ipv6_hop_limit = 1;

	ipv6_send(context, packet_len);
}

void ipv6_setup_hdrs(struct ipv6_context *context, struct eth_hdr *eth,
		     struct ipv6_hdr *ipv6, u16_t packet_len)
{
	struct ipv6_addr *our_address;

	/* VLAN will be taken cared of in the nic layer */
	eth->len_type = HOST_TO_NET16(LAYER2_TYPE_IPV6);
	memcpy((char *)&eth->src_mac,
	       (char *)&context->mac_addr, sizeof(struct mac_address));

	/* Put the traffic class into the packet. */
	memset(&ipv6->ipv6_version_fc, 0, sizeof(u32_t));
	ipv6->ipv6_version_fc = IPV6_VERSION;
	if (ipv6->ipv6_hop_limit == 0)
		ipv6->ipv6_hop_limit = context->hop_limit;

	if (ipv6->ipv6_src.addr[0] == 0) {
		/* Need to initialize source IP address. */
		our_address = ipv6_our_address(context);
		if (our_address != NULL) {
			/* Assume that caller has filled in the destination
			   IP address */
			memcpy((char *)&ipv6->ipv6_src,
			       (char *)our_address, sizeof(struct ipv6_addr));
		}
	}

	ipv6_insert_protocol_chksum(ipv6);
}

static void ipv6_insert_protocol_chksum(struct ipv6_hdr *ipv6)
{
	u32_t sum;
	u16_t *ptr;
	u16_t *protocol_data_ptr;
	int i;
	u16_t protocol_data_len;
	u16_t checksum;

	/*
	 * This routine assumes that there is no extension header. This driver
	 * doesn't user extension header to keep driver small and simple.
	 *
	 * Pseudo check consists of the following:
	 * SRC IP, DST IP, Protocol Data Length, and Next Header.
	 */
	sum = 0;
	ptr = (u16_t *)&ipv6->ipv6_src;

	for (i = 0; i < sizeof(struct ipv6_addr); i++) {
		sum += HOST_TO_NET16(*ptr);
		ptr++;
	}

	/* Keep track where the layer header is */
	protocol_data_ptr = ptr;

	protocol_data_len = HOST_TO_NET16(ipv6->ipv6_plen);
	sum += protocol_data_len;
	sum += ipv6->ipv6_nxt_hdr;
	/* Sum now contains sum of IPv6 pseudo header.  Let's add the data
	   streams. */
	if (protocol_data_len & 1) {
		/* Length of data is odd */
		*((u8_t *) ptr + protocol_data_len) = 0;
		protocol_data_len++;
	}

	for (i = 0; i < protocol_data_len / 2; i++) {
		sum += HOST_TO_NET16(*ptr);
		ptr++;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	sum &= 0xffff;
	checksum = (u16_t) (~sum);
	checksum = HOST_TO_NET16(checksum);

	switch (ipv6->ipv6_nxt_hdr) {
	case IPPROTO_ICMPV6:
		/* Insert correct ICMPv6 checksum */
		((struct icmpv6_hdr *)(protocol_data_ptr))->icmpv6_cksum =
			checksum;
		break;
	case IPPROTO_UDP:
		/* Insert correct UDP checksum */
		((struct udp_hdr *)protocol_data_ptr)->chksum = checksum;
		break;
	default:
		break;
	}
}

int ipv6_is_it_our_link_local_address(struct ipv6_context *context,
				      struct ipv6_addr *ip_addr)
{
	u8_t *test_addr = (u8_t *) ip_addr->addr8;
	u8_t test_remainder;

	if (test_addr[0] != context->link_local_addr.addr8[0])
		return FALSE;

	test_remainder = (test_addr[1] & 0xC0) >> 6;
	if (test_remainder != 2)
		return FALSE;

	return TRUE;
}

static int ipv6_is_it_our_address(struct ipv6_context *context,
				  struct ipv6_addr *ipv6_addr)
{
	struct ipv6_prefix_entry *ipv6_prefix;

	for (ipv6_prefix = context->addr_list; ipv6_prefix != NULL;
	     ipv6_prefix = ipv6_prefix->next) {
		if (IPV6_ARE_ADDR_EQUAL(&ipv6_prefix->ip_addr, ipv6_addr))
			return TRUE;
	}

	return FALSE;
}

struct ipv6_addr *ipv6_our_address(struct ipv6_context *context)
{
	return &context->link_local_addr;
}

int ipv6_ip_in_arp_table(struct ipv6_context *context,
			 struct ipv6_addr *ip_addr,
			 struct mac_address *mac_addr)
{
	struct ipv6_arp_entry *arp_entry;
	int i;

	for (i = 0; i < UIP_ARPTAB_SIZE; i++) {
		arp_entry = &context->ipv6_arp_table[i];

		if (IPV6_ARE_ADDR_EQUAL(&arp_entry->ip_addr, ip_addr)) {
			memcpy((char *)mac_addr, &arp_entry->mac_addr,
			       sizeof(struct mac_address));
			return 1;
		}
	}
	return 0;
}

struct ipv6_addr *ipv6_find_longest_match(struct ipv6_context *context,
				   struct ipv6_addr *ip_addr)
{
	struct ipv6_prefix_entry *ipv6_prefix;
	struct ipv6_prefix_entry *best_match = NULL;
	int longest_len = -1;
	int len;

	for (ipv6_prefix = context->addr_list; ipv6_prefix != NULL;
	     ipv6_prefix = ipv6_prefix->next) {
		if (!IPV6_IS_ADDR_LINKLOCAL(&ipv6_prefix->ip_addr)) {
			len = best_match_bufcmp((u8_t *)&ipv6_prefix->ip_addr,
						(u8_t *)ip_addr,
						sizeof(struct ipv6_addr));
			if (len > longest_len) {
				best_match = ipv6_prefix;
				longest_len = len;
			}
		}
	}

	if (best_match)
		return &best_match->ip_addr;

	return NULL;
}

void ipv6_arp_out(struct ipv6_context *context, int *uip_len)
{
	/* Empty routine */
}


static void ipv6_update_arp_table(struct ipv6_context *context,
				  struct ipv6_addr *ip_addr,
				  struct mac_address *mac_addr)
{
	struct ipv6_arp_entry *arp_entry;
	int i;
	struct ipv6_arp_entry *ipv6_arp_table = context->ipv6_arp_table;

	LOG_DEBUG("IPv6: Neighbor update");
	/*
	 * Walk through the ARP mapping table and try to find an entry to
	 * update. If none is found, the IP -> MAC address mapping is
	 * inserted in the ARP table.
	 */
	for (i = 0; i < UIP_ARPTAB_SIZE; i++) {
		arp_entry = &ipv6_arp_table[i];

		/* Only check those entries that are actually in use. */
		if (arp_entry->ip_addr.addr[0] != 0) {
			/*
			 * Check if the source IP address of the incoming
			 * packet matches the IP address in this ARP table
			 * entry.
			 */
			if (IPV6_ARE_ADDR_EQUAL(&arp_entry->ip_addr, ip_addr)) {
				/* An old entry found, update this and return */
				memcpy((char *)&arp_entry->mac_addr,
				       (char *)mac_addr,
				       sizeof(struct mac_address));
				arp_entry->time = context->arptime;
				return;
			}
		}
	}

	/*
	 * If we get here, no existing ARP table entry was found, so we
	 * create one.
	 *
	 * First, we try to find an unused entry in the ARP table.
	 */
	for (i = 0; i < UIP_ARPTAB_SIZE; i++) {
		arp_entry = &ipv6_arp_table[i];

		if (arp_entry->ip_addr.addr[0] == 0)
			break;
	}

	if (i == UIP_ARPTAB_SIZE)
		return;

	/* Index j is the entry that is least used */
	arp_entry = &ipv6_arp_table[i];
	memcpy((char *)&arp_entry->ip_addr, (char *)ip_addr,
	       sizeof(struct ipv6_addr));
	memcpy((char *)&arp_entry->mac_addr,
	       (char *)mac_addr, sizeof(struct mac_address));

	arp_entry->time = context->arptime;
}

/* DestIP is intact */
int ipv6_send_nd_solicited_packet(struct ipv6_context *context,
				  struct eth_hdr *eth, struct ipv6_hdr *ipv6)
{
	struct icmpv6_hdr *icmp;
	int pkt_len = 0;
	struct ipv6_addr *longest_match_addr;
	char addr_str[INET6_ADDRSTRLEN];

	ipv6->ipv6_nxt_hdr = IPPROTO_ICMPV6;

	/* Depending on the IPv6 address of the target, we'll need to determine
	   whether we use the assigned IPv6 address/RA or the link local address
	*/
	/* Use Link-local as source address */
	if (ipv6_is_it_our_link_local_address(context, &ipv6->ipv6_dst) ==
	    TRUE) {
		LOG_DEBUG("IPv6: NS using link local");
		memcpy((char *)&ipv6->ipv6_src,
		       (char *)&context->link_local_addr,
		       sizeof(struct ipv6_addr));
	} else {
		longest_match_addr =
		    ipv6_find_longest_match(context, &ipv6->ipv6_dst);
		if (longest_match_addr) {
			LOG_DEBUG("IPv6: NS using longest match addr");
			memcpy((char *)&ipv6->ipv6_src,
			       (char *)longest_match_addr,
			       sizeof(struct ipv6_addr));
		} else {
			LOG_DEBUG("IPv6: NS using link local instead");
			memcpy((char *)&ipv6->ipv6_src,
			       (char *)&context->link_local_addr,
			       sizeof(struct ipv6_addr));
		}
	}
	icmp = (struct icmpv6_hdr *)((u8_t *)ipv6 + sizeof(struct ipv6_hdr));

	inet_ntop(AF_INET6, &ipv6->ipv6_src.addr8, addr_str, sizeof(addr_str));
	LOG_DEBUG("IPv6: NS host IP addr: %s", addr_str);
	/*
	 * Destination IP address to be resolved is after the ICMPv6
	 * header.
	 */
	memcpy((char *)((u8_t *)icmp + sizeof(struct icmpv6_hdr)),
	       (char *)&ipv6->ipv6_dst, sizeof(struct ipv6_addr));

	/*
	 * Destination IP in the IPv6 header contains solicited-node multicast
	 * address corresponding to the target address.
	 *
	 * ff02::01:ffxx:yyzz. Where xyz are least
	 * significant of 24-bit MAC address.
	 */
	memset((char *)&ipv6->ipv6_dst, 0, sizeof(struct ipv6_addr) - 3);
	ipv6->ipv6_dst.addr8[0] = 0xff;
	ipv6->ipv6_dst.addr8[1] = 0x02;
	ipv6->ipv6_dst.addr8[11] = 0x01;
	ipv6->ipv6_dst.addr8[12] = 0xff;
	ipv6_mc_init_dest_mac(eth, ipv6);
	ipv6->ipv6_hop_limit = 255;

	icmp->icmpv6_type = ICMPV6_NEIGH_SOL;
	icmp->icmpv6_code = 0;
	icmp->icmpv6_data = 0;
	icmp->icmpv6_cksum = 0;
	ipv6_icmp_init_link_option(context,
				   (struct icmpv6_opt_link_addr *)((u8_t *)icmp
						+ sizeof(struct icmpv6_hdr)
						+ sizeof(struct ipv6_addr)),
						IPV6_ICMP_OPTION_SRC_ADDR);
	ipv6->ipv6_plen = HOST_TO_NET16((sizeof(struct icmpv6_hdr) +
			  sizeof(struct icmpv6_opt_link_addr) +
			  sizeof(struct ipv6_addr)));
	/* Total packet size */
	pkt_len = (u8_t *) icmp - (u8_t *) eth +
	    sizeof(struct icmpv6_hdr) +
	    sizeof(struct icmpv6_opt_link_addr) + sizeof(struct ipv6_addr);
	ipv6_setup_hdrs(context, eth, ipv6, pkt_len);
	return pkt_len;
}

static void ipv6_icmp_init_link_option(struct ipv6_context *context,
				       struct icmpv6_opt_link_addr *link_opt,
				       u8_t type)
{
	link_opt->hdr.type = type;
	link_opt->hdr.len = sizeof(struct icmpv6_opt_link_addr) / 8;
	memcpy((char *)&link_opt->link_addr,
	       (char *)&context->mac_addr, sizeof(struct mac_address));
}

static void ipv6_icmp_rx(struct ipv6_context *context)
{
	struct ipv6_hdr *ipv6 =
			(struct ipv6_hdr *)context->ustack->network_layer;
	struct icmpv6_hdr *icmp = (struct icmpv6_hdr *)((u8_t *)ipv6 +
						sizeof(struct ipv6_hdr));
	uip_icmp_echo_hdr_t *icmp_echo_hdr =
				(uip_icmp_echo_hdr_t *)((u8_t *)ipv6 +
						sizeof(struct ipv6_hdr));

	switch (icmp->icmpv6_type) {
	case ICMPV6_RTR_ADV:
		ipv6_icmp_handle_router_adv(context);
		break;

	case ICMPV6_NEIGH_SOL:
		ipv6_icmp_handle_nd_sol(context);
		break;

	case ICMPV6_NEIGH_ADV:
		ipv6_icmp_handle_nd_adv(context);
		break;

	case ICMPV6_ECHO_REQUEST:
		/* Response with ICMP reply */
		ipv6_icmp_handle_echo_request(context);
		break;

	case ICMPV6_ECHO_REPLY:
		/* Handle ICMP reply */
		process_icmp_packet(icmp_echo_hdr, context->ustack);
		break;

	default:
		break;
	}
}

static void ipv6_icmp_handle_router_adv(struct ipv6_context *context)
{
	struct ipv6_hdr *ipv6 =
			(struct ipv6_hdr *)context->ustack->network_layer;
	struct icmpv6_router_advert *icmp =
	(struct icmpv6_router_advert *)((u8_t *)ipv6 + sizeof(struct ipv6_hdr));
	struct icmpv6_opt_hdr *icmp_opt;
	u16_t opt_len;
	u16_t len;
	char addr_str[INET6_ADDRSTRLEN];

	if (context->flags & IPV6_FLAGS_ROUTER_ADV_RECEIVED)
		return;

	opt_len = HOST_TO_NET16(ipv6->ipv6_plen) -
		  sizeof(struct icmpv6_router_advert);

	icmp_opt = (struct icmpv6_opt_hdr *)((u8_t *)icmp +
				      sizeof(struct icmpv6_router_advert));
	len = 0;
	while (len < opt_len) {
		icmp_opt = (struct icmpv6_opt_hdr *)((u8_t *)icmp +
					sizeof(struct icmpv6_router_advert) +
					len);

		switch (icmp_opt->type) {
		case IPV6_ICMP_OPTION_PREFIX:
			ipv6_icmp_process_prefix(context,
					(struct icmpv6_opt_prefix *)icmp_opt);
			context->flags |= IPV6_FLAGS_ROUTER_ADV_RECEIVED;
			break;

		default:
			break;
		}

		len += icmp_opt->len * 8;
	}

	if (context->flags & IPV6_FLAGS_ROUTER_ADV_RECEIVED) {
		LOG_DEBUG("IPv6: RTR ADV nd_ra_flags = 0x%x",
			  icmp->nd_ra_flags_reserved);
		if (icmp->nd_ra_curhoplimit > 0)
			context->hop_limit = icmp->nd_ra_curhoplimit;

		if (icmp->nd_ra_flags_reserved & IPV6_RA_MANAGED_FLAG)
			context->flags |= IPV6_FLAGS_MANAGED_ADDR_CONFIG;

		if (icmp->nd_ra_flags_reserved & IPV6_RA_CONFIG_FLAG)
			context->flags |= IPV6_FLAGS_OTHER_STATEFUL_CONFIG;

		if (icmp->nd_ra_router_lifetime != 0) {
			/* There is a default router. */
			if (context->ustack->router_autocfg !=
			    IPV6_RTR_AUTOCFG_OFF)
				memcpy(
				   (char *)&context->default_router,
				       (char *)&ipv6->ipv6_src,
				       sizeof(struct ipv6_addr));
			inet_ntop(AF_INET6, &context->default_router,
				  addr_str, sizeof(addr_str));
			LOG_DEBUG("IPv6: Got default router IP addr: %s",
				  addr_str);
		}
	}
}

static void ipv6_icmp_process_prefix(struct ipv6_context *context,
				     struct icmpv6_opt_prefix *icmp_prefix)
{
	struct ipv6_addr addr;
	char addr_str[INET6_ADDRSTRLEN];

	/* we only process on-link address info */
	if (!(icmp_prefix->flags & ICMPV6_OPT_PREFIX_FLAG_ON_LINK))
		return;

	/*
	 * We only process prefix length of 64 since our Identifier is 64-bit
	 */
	if (icmp_prefix->prefix_len == 64) {
		/* Copy 64-bit from the local-link address to create
		   IPv6 address */
		memcpy((char *)&addr,
		       (char *)&icmp_prefix->prefix, 8);
		memcpy((char *)&addr.addr8[8],
		       &context->link_local_addr.addr8[8], 8);
		inet_ntop(AF_INET6, &addr, addr_str, sizeof(addr_str));
		LOG_DEBUG("IPv6: Got RA ICMP option IP addr: %s", addr_str);
		ipv6_add_prefix_entry(context, &addr, 64);
	}
}

static void ipv6_icmp_handle_nd_adv(struct ipv6_context *context)
{
	struct eth_hdr *eth =
			(struct eth_hdr *)context->ustack->data_link_layer;
	struct ipv6_hdr *ipv6 =
			(struct ipv6_hdr *)context->ustack->network_layer;
	struct icmpv6_hdr *icmp = (struct icmpv6_hdr *)((u8_t *)ipv6 +
						sizeof(struct ipv6_hdr));
	struct icmpv6_opt_link_addr *link_opt =
			(struct icmpv6_opt_link_addr *)((u8_t *)icmp +
			sizeof(struct icmpv6_hdr) + sizeof(struct ipv6_addr));
	struct ipv6_addr *tar_addr6;
	char addr_str[INET6_ADDRSTRLEN];

	/* Added the multicast check for ARP table update */
	/* Should we qualify for only our host's multicast and our
	   link_local_multicast?? */
	LOG_DEBUG("IPv6: Handle nd adv");
	if ((ipv6_is_it_our_address(context, &ipv6->ipv6_dst) == TRUE) ||
	    (memcmp((char *)&context->link_local_multi,
		    (char *)&ipv6->ipv6_dst, sizeof(struct ipv6_addr)) == 0) ||
	    (memcmp((char *)&context->multi,
		    (char *)&ipv6->ipv6_dst, sizeof(struct ipv6_addr)) == 0)) {
		/*
		 * This is an ARP reply for our addresses. Let's update the
		 * ARP table.
		 */
		ipv6_update_arp_table(context, &ipv6->ipv6_src,
				      &eth->src_mac);

		/* Now check for the target address option and update that as
		   well */
		if (link_opt->hdr.type == IPV6_ICMP_OPTION_TAR_ADDR) {
			tar_addr6 = (struct ipv6_addr *)((u8_t *)icmp +
				    sizeof(struct icmpv6_hdr));
			LOG_DEBUG("IPV6: Target MAC "
				  "%02x:%02x:%02x:%02x:%02x:%02x",
				link_opt->link_addr[0], link_opt->link_addr[1],
				link_opt->link_addr[2], link_opt->link_addr[3],
				link_opt->link_addr[4], link_opt->link_addr[5]);
			inet_ntop(AF_INET6, &tar_addr6->addr8, addr_str,
				  sizeof(addr_str));
			LOG_DEBUG("IPv6: Target IP addr %s", addr_str);
			ipv6_update_arp_table(context, tar_addr6,
			      (struct mac_address *)link_opt->link_addr);
		}

	}
}

static void ipv6_icmp_handle_nd_sol(struct ipv6_context *context)
{
	struct eth_hdr *eth =
			(struct eth_hdr *)context->ustack->data_link_layer;
	struct ipv6_hdr *ipv6 =
			(struct ipv6_hdr *)context->ustack->network_layer;
	struct icmpv6_hdr *icmp = (struct icmpv6_hdr *)((u8_t *)ipv6 +
						sizeof(struct ipv6_hdr));
	struct icmpv6_opt_link_addr *link_opt =
			(struct icmpv6_opt_link_addr *)((u8_t *)icmp +
			sizeof(struct icmpv6_hdr) + sizeof(struct ipv6_addr));
	int icmpv6_opt_len = 0;
	struct ipv6_addr tmp;
	struct ipv6_addr *longest_match_addr, *tar_addr6;

	LOG_DEBUG("IPv6: Handle nd sol");

	if ((memcmp((char *)&context->mac_addr,
		    (char *)&eth->dest_mac, sizeof(struct mac_address)) != 0) &&
	    (iscsiL2IsOurMcAddr(context, (struct mac_address *)&eth->dest_mac)
	     == FALSE)) {
		/* This packet is not for us to handle */
		LOG_DEBUG("IPv6: MAC not addressed to us "
			  "%02x:%02x:%02x:%02x:%02x:%02x",
			  eth->dest_mac.addr[0], eth->dest_mac.addr[1],
			  eth->dest_mac.addr[2], eth->dest_mac.addr[3],
			  eth->dest_mac.addr[4], eth->dest_mac.addr[5]);
		return;
	}

	/* Also check for the icmpv6_data before generating the reply */
	if (ipv6_is_it_our_address(context,
				   (struct ipv6_addr *) ((u8_t *) icmp +
						  sizeof(struct icmpv6_hdr)))
	    == FALSE) {
		/* This packet is not for us to handle */
		LOG_DEBUG("IPv6: IP not addressed to us");
		return;
	}

	/* Copy source MAC to Destination MAC */
	memcpy((char *)&eth->dest_mac,
	       (char *)&eth->src_mac, sizeof(struct mac_address));

	/* Dest IP contains source IP */
	memcpy((char *)&tmp,
	       (char *)&ipv6->ipv6_dst, sizeof(struct ipv6_addr));
	memcpy((char *)&ipv6->ipv6_dst,
	       (char *)&ipv6->ipv6_src, sizeof(struct ipv6_addr));

	/* Examine the Neighbor Solicitation ICMPv6 target address field.
	   If target address exist, use that to find best match src address
	   for the reply */
	if (link_opt->hdr.type == IPV6_ICMP_OPTION_SRC_ADDR) {
		tar_addr6 = (struct ipv6_addr *)((u8_t *)icmp +
						 sizeof(struct icmpv6_hdr));
		if (ipv6_is_it_our_link_local_address(context, tar_addr6)
		    == TRUE) {
			LOG_DEBUG("IPv6: NA using link local");
			memcpy((char *)&ipv6->ipv6_src,
			       (char *)&context->link_local_addr,
			       sizeof(struct ipv6_addr));
		} else {
			longest_match_addr =
			      ipv6_find_longest_match(context, tar_addr6);
			if (longest_match_addr) {
				LOG_DEBUG("IPv6: NA using longest match addr");
				memcpy((char *)&ipv6->ipv6_src,
				       (char *)longest_match_addr,
				       sizeof(struct ipv6_addr));
			} else {
				LOG_DEBUG("IPv6: NA using link local instead");
				memcpy((char *)&ipv6->ipv6_src,
				(char *)&context->link_local_addr,
				       sizeof(struct ipv6_addr));
			}
		}
	} else {
		/* No target link address, just use whatever it sent to us */
		LOG_DEBUG("IPv6: NA use dst addr");
		memcpy((char *)&ipv6->ipv6_src,
		       (char *)&tmp,
		       sizeof(struct ipv6_addr));
	}
	ipv6->ipv6_hop_limit = 255;
	icmp->icmpv6_type = ICMPV6_NEIGH_ADV;
	icmp->icmpv6_code = 0;
	icmp->icmpv6_data = 0;
	icmp->icmpv6_cksum = 0;
	icmp->data.icmpv6_un_data8[0] =
	    IPV6_NA_FLAG_SOLICITED | IPV6_NA_FLAG_OVERRIDE;
	memcpy((char *)((u8_t *)icmp + sizeof(struct icmpv6_hdr)),
	       (char *)&ipv6->ipv6_src,
	       sizeof(struct ipv6_addr));

	/* Add the target link address option only for all solicitation */
	ipv6_icmp_init_link_option(context,
			(struct icmpv6_opt_link_addr *)((u8_t *)icmp +
					sizeof(struct icmpv6_hdr) +
					sizeof(struct ipv6_addr)),
			IPV6_ICMP_OPTION_TAR_ADDR);
	icmpv6_opt_len = sizeof(struct icmpv6_opt_link_addr);
	ipv6->ipv6_plen = HOST_TO_NET16((sizeof(struct icmpv6_hdr) +
				 icmpv6_opt_len + sizeof(struct ipv6_addr)));
	LOG_DEBUG("IPv6: Send nd adv");
	ipv6_send(context,
		  (u8_t *) icmp - (u8_t *) eth +
		  sizeof(struct icmpv6_hdr) +
		  sizeof(struct icmpv6_opt_link_addr) +
		  sizeof(struct ipv6_addr));
	return;
}

static void ipv6_icmp_handle_echo_request(struct ipv6_context *context)
{
	struct eth_hdr *eth =
			(struct eth_hdr *)context->ustack->data_link_layer;
	struct ipv6_hdr *ipv6 =
			(struct ipv6_hdr *)context->ustack->network_layer;
	struct icmpv6_hdr *icmp = (struct icmpv6_hdr *)((u8_t *)ipv6 +
						sizeof(struct ipv6_hdr));
	struct ipv6_addr temp;

	/* Copy source MAC to Destination MAC */
	memcpy((char *)&eth->dest_mac,
	       (char *)&eth->src_mac, sizeof(struct mac_address));

	memcpy((char *)&temp,
	       (char *)&ipv6->ipv6_dst, sizeof(struct ipv6_addr));

	/* Dest IP contains source IP */
	memcpy((char *)&ipv6->ipv6_dst,
	       (char *)&ipv6->ipv6_src, sizeof(struct ipv6_addr));
	/* Use Link-local as source address */
	memcpy((char *)&ipv6->ipv6_src,
	       (char *)&temp, sizeof(struct ipv6_addr));

	ipv6->ipv6_hop_limit = context->hop_limit;
	icmp->icmpv6_type = ICMPV6_ECHO_REPLY;
	icmp->icmpv6_code = 0;
	icmp->icmpv6_cksum = 0;
	LOG_DEBUG("IPv6: Send echo reply");
	ipv6_send(context, (u8_t *) icmp - (u8_t *) eth +
		  sizeof(struct ipv6_hdr) + HOST_TO_NET16(ipv6->ipv6_plen));
	return;
}

void ipv6_set_ip_params(struct ipv6_context *context,
			struct ipv6_addr *src_ip, u8_t prefix_len,
			struct ipv6_addr *default_gateway,
			struct ipv6_addr *linklocal)
{
	if (!(IPV6_IS_ADDR_UNSPECIFIED(src_ip))) {
		ipv6_add_prefix_entry(context, src_ip, prefix_len);
		/* Create the multi_dest address */
		memset(&context->multi_dest, 0, sizeof(struct ipv6_addr));
		context->multi_dest.addr8[0] = 0xff;
		context->multi_dest.addr8[1] = 0x02;
		context->multi_dest.addr8[11] = 0x01;
		context->multi_dest.addr8[12] = 0xff;
		context->multi_dest.addr8[13] = src_ip->addr8[13];
		context->multi_dest.addr16[7] = src_ip->addr16[7];
		/* Create the multi address */
		memset(&context->multi, 0, sizeof(struct ipv6_addr));
		context->multi.addr8[0] = 0xfc;
		context->multi.addr8[2] = 0x02;
		context->multi.addr16[7] = src_ip->addr16[7];
	}

	if (!(IPV6_IS_ADDR_UNSPECIFIED(default_gateway))) {
		/* Override the default gateway addr */
		memcpy((char *)&context->default_router,
		       (char *)default_gateway, sizeof(struct ipv6_addr));
		ipv6_add_prefix_entry(context, default_gateway,
				      prefix_len);
	}
	if (!(IPV6_IS_ADDR_UNSPECIFIED(linklocal))) {
		/* Override the linklocal addr */
		memcpy((char *)&context->link_local_addr,
		       (char *)linklocal, sizeof(struct ipv6_addr));
		context->link_local_multi.addr8[0] = 0xff;
		context->link_local_multi.addr8[1] = 0x02;
		context->link_local_multi.addr8[11] = 0x01;
		context->link_local_multi.addr8[12] = 0xff;
		context->link_local_multi.addr8[13] |=
		    context->link_local_addr.addr8[13];
		context->link_local_multi.addr16[7] =
		    context->link_local_addr.addr16[7];

		/* Default Prefix length is 64 */
		/* Add Link local address to the head of the ipv6 address
		   list */
		ipv6_add_prefix_entry(context,
				      &context->link_local_addr, 64);
	}
}

int ipv6_get_source_ip_addrs(struct ipv6_context *context,
			     struct ipv6_addr_entry *addr_list)
{
	struct ipv6_prefix_entry *ipv6_prefix;
	int i;

	for (i = 0, ipv6_prefix = context->addr_list; ipv6_prefix != NULL;
	     ipv6_prefix = ipv6_prefix->next) {
		memcpy((char *)&addr_list->ip_addr,
		       (char *)&ipv6_prefix->ip_addr,
		       sizeof(struct ipv6_addr));
		addr_list->prefix_len = ipv6_prefix->prefix_len * 8;

		i++;
		addr_list++;
	}

	return i;
}

int ipv6_get_default_router_ip_addrs(struct ipv6_context *context,
				     struct ipv6_addr *ip_addr)
{
	/* This is a default router. */
	memcpy((char *)ip_addr,
	       (char *)&context->default_router,
	       sizeof(struct ipv6_addr));

	return 1;
}

static void ipv6_udp_rx(struct ipv6_context *context)
{
	struct eth_hdr *eth =
			(struct eth_hdr *)context->ustack->data_link_layer;
	struct ipv6_hdr *ipv6 =
			(struct ipv6_hdr *)context->ustack->network_layer;
	struct udp_hdr *udp = (struct udp_hdr *)((u8_t *)ipv6 +
						sizeof(struct ipv6_hdr));
	struct dhcpv6_context *dhcpv6c;

	/*
	 * We only care about DHCPv6 packets from the DHCPv6 server.  We drop
	 * all others.
	 */
	if (!(context->flags & IPV6_FLAGS_DISABLE_DHCPV6)) {
		if ((udp->src_port == HOST_TO_NET16(DHCPV6_SERVER_PORT)) &&
		    (udp->dest_port == HOST_TO_NET16(DHCPV6_CLIENT_PORT))) {
			dhcpv6c = context->dhcpv6_context;
			dhcpv6c->eth = eth;
			dhcpv6c->ipv6 = ipv6;
			dhcpv6c->udp = udp;
			ipv6_udp_handle_dhcp(dhcpv6c);
		}
	}
}

struct mac_address *ipv6_get_link_addr(struct ipv6_context *context)
{
	return &context->mac_addr;
}

u16_t ipv6_do_stateful_dhcpv6(struct ipv6_context *context, u32_t flags)
{
	u16_t task = 0;
	u16_t ra_flags;

	ra_flags = context->flags &
	    (IPV6_FLAGS_MANAGED_ADDR_CONFIG | IPV6_FLAGS_OTHER_STATEFUL_CONFIG);

	if (!(context->flags & IPV6_FLAGS_ROUTER_ADV_RECEIVED)) {
		LOG_DEBUG("IPv6: There is no IPv6 router on the network");
		ra_flags |=
		    (IPV6_FLAGS_MANAGED_ADDR_CONFIG |
		     IPV6_FLAGS_OTHER_STATEFUL_CONFIG);
	}

	if ((flags & ISCSI_FLAGS_DHCP_TCPIP_CONFIG) &&
	    (ra_flags & IPV6_FLAGS_MANAGED_ADDR_CONFIG))
		task |= DHCPV6_TASK_GET_IP_ADDRESS;

	if ((flags & ISCSI_FLAGS_DHCP_ISCSI_CONFIG) &&
	    (ra_flags & IPV6_FLAGS_OTHER_STATEFUL_CONFIG))
		task |= DHCPV6_TASK_GET_OTHER_PARAMS;

	LOG_DEBUG("IPv6: Stateful flags = 0x%x, ra_flags = 0x%x, task = 0x%x",
		  flags, ra_flags, task);

	return task;
}

void ipv6_add_solit_node_address(struct ipv6_context *context,
				 struct ipv6_addr *ip_addr)
{
	struct mac_address mac_addr;

	/*
	 * Add Solicited Node Multicast Address for statically configured IPv6
	 * address.
	 */
	mac_addr.addr[0] = 0x33;
	mac_addr.addr[1] = 0x33;
	mac_addr.addr[2] = 0xff;
	mac_addr.addr[3] = ip_addr->addr8[13];
	mac_addr.addr[4] = ip_addr->addr8[14];
	mac_addr.addr[5] = ip_addr->addr8[15];
	iscsiL2AddMcAddr(context, (struct mac_address *)&mac_addr);
}

void ipv6_cfg_link_local_addr(struct ipv6_context *context,
			      struct ipv6_addr *ip_addr)
{
	memcpy((char *)&context->link_local_addr,
	       (char *)ip_addr, sizeof(struct ipv6_addr));
}

void ipv6_disable_dhcpv6(struct ipv6_context *context)
{
	context->flags |= IPV6_FLAGS_DISABLE_DHCPV6;
}
