#include <errno.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "logger.h"
#include "packet.h"

/**
 * \addtogroup uip
 * @{
 */

/**
 * \defgroup uiparp uIP Address Resolution Protocol
 * @{
 *
 * The Address Resolution Protocol ARP is used for mapping between IP
 * addresses and link level addresses such as the Ethernet MAC
 * addresses. ARP uses broadcast queries to ask for the link level
 * address of a known IP address and the host which is configured with
 * the IP address for which the query was meant, will respond with its
 * link level address.
 *
 * \note This ARP implementation only supports Ethernet.
 */

/**
 * \file
 * Implementation of the ARP Address Resolution Protocol.
 * \author Adam Dunkels <adam@dunkels.com>
 *
 */

/*
 * Copyright (c) 2001-2003, Adam Dunkels.
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
 * 3. The name of the author may not be used to endorse or promote
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
 * This file is part of the uIP TCP/IP stack.
 *
 *
 */

#include "uip_arp.h"
#include "uip_eth.h"

#include <pthread.h>
#include <string.h>

static const struct uip_eth_addr broadcast_ethaddr = {
			{0xff, 0xff, 0xff, 0xff, 0xff, 0xff} };
static const u16_t broadcast_ipaddr[2] = { 0xffff, 0xffff };

pthread_mutex_t arp_table_mutex = PTHREAD_MUTEX_INITIALIZER;
static struct arp_entry arp_table[UIP_ARPTAB_SIZE];

static u8_t arptime;

/**
 * Initialize the ARP module.
 *
 */
/*----------------------------------------------------------------------------*/
void uip_arp_init(void)
{
	u8_t i;
	for (i = 0; i < UIP_ARPTAB_SIZE; ++i)
		memset(&arp_table[i], 0, sizeof(arp_table[i]));

	pthread_mutex_init(&arp_table_mutex, NULL);
}

/*----------------------------------------------------------------------------*/
/**
 * Periodic ARP processing function.
 *
 * This function performs periodic timer processing in the ARP module
 * and should be called at regular intervals. The recommended interval
 * is 10 seconds between the calls.
 *
 */
/*----------------------------------------------------------------------------*/
void uip_arp_timer(void)
{
	u8_t i;
	struct arp_entry *tabptr;

	++arptime;
	for (i = 0; i < UIP_ARPTAB_SIZE; ++i) {
		tabptr = &arp_table[i];
		if ((tabptr->ipaddr[0] | tabptr->ipaddr[1]) != 0 &&
		    (u8_t)(arptime - tabptr->time) >= UIP_ARP_MAXAGE)
			memset(tabptr->ipaddr, 0, 4);
	}

}

/*----------------------------------------------------------------------------*/
static void uip_arp_update(u16_t *ipaddr, struct uip_eth_addr *ethaddr)
{
	u8_t i;
	struct arp_entry *tabptr;

	pthread_mutex_lock(&arp_table_mutex);
	/* Walk through the ARP mapping table and try to find an entry to
	   update. If none is found, the IP -> MAC address mapping is
	   inserted in the ARP table. */
	for (i = 0; i < UIP_ARPTAB_SIZE; ++i) {

		tabptr = &arp_table[i];
		/* Only check those entries that are actually in use. */
		if (tabptr->ipaddr[0] != 0 && tabptr->ipaddr[1] != 0) {

			/* Check if the source IP address of the incoming packet
			   matches the IP address in this ARP table entry. */
			if (ipaddr[0] == tabptr->ipaddr[0] &&
			    ipaddr[1] == tabptr->ipaddr[1]) {

				tabptr->time = arptime;

				pthread_mutex_unlock(&arp_table_mutex);
				return;
			}
		}
	}

	/* If we get here, no existing ARP table entry was found, so we
	   create one. */

	/* First, we try to find an unused entry in the ARP table. */
	for (i = 0; i < UIP_ARPTAB_SIZE; ++i) {
		tabptr = &arp_table[i];
		if (tabptr->ipaddr[0] == 0 && tabptr->ipaddr[1] == 0)
			break;
	}

	/* If no unused entry is found, we try to find the oldest entry and
	   throw it away. */
	if (i == UIP_ARPTAB_SIZE) {
		u8_t c;
		u8_t tmpage = 0;
		c = 0;
		for (i = 0; i < UIP_ARPTAB_SIZE; ++i) {
			tabptr = &arp_table[i];
			if ((u8_t)(arptime - tabptr->time) > tmpage) {
				tmpage = (u8_t)(arptime - tabptr->time);
				c = i;
			}
		}
		i = c;
		tabptr = &arp_table[i];
	}

	/* Now, i is the ARP table entry which we will fill with the new
	   information. */
	memcpy(tabptr->ipaddr, ipaddr, 4);
	memcpy(tabptr->ethaddr.addr, ethaddr->addr, 6);
	tabptr->time = arptime;

	pthread_mutex_unlock(&arp_table_mutex);
}

/**
 * ARP processing for incoming ARP packets.
 *
 * This function should be called by the device driver when an ARP
 * packet has been received. The function will act differently
 * depending on the ARP packet type: if it is a reply for a request
 * that we previously sent out, the ARP cache will be filled in with
 * the values from the ARP reply. If the incoming ARP packet is an ARP
 * request for our IP address, an ARP reply packet is created and put
 * into the uip_buf[] buffer.
 *
 * When the function returns, the value of the global variable uip_len
 * indicates whether the device driver should send out a packet or
 * not. If uip_len is zero, no packet should be sent. If uip_len is
 * non-zero, it contains the length of the outbound packet that is
 * present in the uip_buf[] buffer.
 *
 * This function expects an ARP packet with a prepended Ethernet
 * header in the uip_buf[] buffer, and the length of the packet in the
 * global variable uip_len.
 */
void uip_arp_ipin(struct uip_stack *ustack, packet_t *pkt)
{
	struct ip_hdr *ip;
	struct uip_eth_hdr *eth;

	eth = (struct uip_eth_hdr *)pkt->data_link_layer;
	ip = (struct ip_hdr *)pkt->network_layer;

	if (uip_ip4addr_cmp(ip->destipaddr, ustack->hostaddr)) {
		/* First, we register the one who made the request in our ARP
		   table, since it is likely that we will do more communication
		   with this host in the future. */
		uip_arp_update(ip->srcipaddr, &eth->src);
	}
}

void
uip_arp_arpin(nic_interface_t *nic_iface,
	      struct uip_stack *ustack, packet_t *pkt)
{
	struct arp_hdr *arp;
	struct uip_eth_hdr *eth;

	if (pkt->buf_size < sizeof(struct arp_hdr)) {
		pkt->buf_size = 0;
		return;
	}
	pkt->buf_size = 0;

	eth = (struct uip_eth_hdr *)pkt->data_link_layer;
	arp = (struct arp_hdr *)pkt->network_layer;

	switch (arp->opcode) {
	case const_htons(ARP_REQUEST):
		/* ARP request. If it asked for our address, we send out a
		   reply. */
		if (uip_ip4addr_cmp(arp->dipaddr, ustack->hostaddr)) {
			/* First, we register the one who made the request in
			   our ARP table, since it is likely that we will do
			   more communication with this host in the future. */
			uip_arp_update(arp->sipaddr, &arp->shwaddr);

			/* The reply opcode is 2. */
			arp->opcode = htons(2);

			memcpy(arp->dhwaddr.addr, arp->shwaddr.addr, 6);
			memcpy(arp->shwaddr.addr, ustack->uip_ethaddr.addr, 6);
			memcpy(eth->src.addr, ustack->uip_ethaddr.addr, 6);
			memcpy(eth->dest.addr, arp->dhwaddr.addr, 6);

			arp->dipaddr[0] = arp->sipaddr[0];
			arp->dipaddr[1] = arp->sipaddr[1];
			arp->sipaddr[0] = ustack->hostaddr[0];
			arp->sipaddr[1] = ustack->hostaddr[1];

			if (nic_iface->vlan_id == 0) {
				eth->type = htons(UIP_ETHTYPE_ARP);
				pkt->buf_size = sizeof(*arp) + sizeof(*eth);
			} else {
				eth->type = htons(UIP_ETHTYPE_8021Q);
				pkt->buf_size = sizeof(*arp) +
						sizeof(struct uip_vlan_eth_hdr);
			}
		}
		break;
	case const_htons(ARP_REPLY):
		uip_arp_update(arp->sipaddr, &arp->shwaddr);
		break;
	default:
		LOG_WARN("Unknown ARP opcode: %d", ntohs(arp->opcode));
		break;
	}

	return;
}

/**
 * Prepend Ethernet header to an outbound IP packet and see if we need
 * to send out an ARP request.
 *
 * This function should be called before sending out an IP packet. The
 * function checks the destination IP address of the IP packet to see
 * what Ethernet MAC address that should be used as a destination MAC
 * address on the Ethernet.
 *
 * If the destination IP address is in the local network (determined
 * by logical ANDing of netmask and our IP address), the function
 * checks the ARP cache to see if an entry for the destination IP
 * address is found. If so, an Ethernet header is prepended and the
 * function returns. If no ARP cache entry is found for the
 * destination IP address, the packet in the uip_buf[] is replaced by
 * an ARP request packet for the IP address. The IP packet is dropped
 * and it is assumed that they higher level protocols (e.g., TCP)
 * eventually will retransmit the dropped packet.
 *
 * If the destination IP address is not on the local network, the IP
 * address of the default router is used instead.
 *
 * When the function returns, a packet is present in the uip_buf[]
 * buffer, and the length of the packet is in the global variable
 * uip_len.
 */

dest_ipv4_addr_t
uip_determine_dest_ipv4_addr(struct uip_stack *ustack, u16_t *ipaddr)
{
	struct uip_eth_hdr *eth;
	struct ip_hdr *ip_buf;

	eth = (struct uip_eth_hdr *)ustack->data_link_layer;
	ip_buf = (struct ip_hdr *)ustack->network_layer;

	/* Find the destination IP address in the ARP table and construct
	   the Ethernet header. If the destination IP addres isn't on the
	   local network, we use the default router's IP address instead.

	   If not ARP table entry is found, we overwrite the original IP
	   packet with an ARP request for the IP address. */

	/* First check if destination is a local broadcast. */
	if (uip_ip4addr_cmp(ip_buf->destipaddr, broadcast_ipaddr)) {
		memcpy(&eth->dest, broadcast_ethaddr.addr, 6);

		return LOCAL_BROADCAST;
	} else {
		/* Check if the destination address is on the local network. */
		if (!uip_ip4addr_maskcmp(ip_buf->destipaddr,
					 ustack->hostaddr, ustack->netmask)) {
			/* Destination address was not on the local network,
			   so we need to use the default router's IP address
			   instead of the destination address when determining
			   the MAC address. */
			uip_ip4addr_copy(ipaddr, ustack->default_route_addr);
		} else {
			/* Else, we use the destination IP address. */
			uip_ip4addr_copy(ipaddr, ip_buf->destipaddr);
		}

		return NONLOCAL_BROADCAST;
	}
}

arp_out_t is_in_arp_table(u16_t *ipaddr, struct arp_entry **tabptr)
{
	u8_t i;

	pthread_mutex_lock(&arp_table_mutex);

	for (i = 0; i < UIP_ARPTAB_SIZE; ++i) {
		if (uip_ip4addr_cmp(ipaddr, arp_table[i].ipaddr)) {
			*tabptr = &arp_table[i];
			break;
		}
	}

	pthread_mutex_unlock(&arp_table_mutex);

	if (i == UIP_ARPTAB_SIZE)
		return NOT_IN_ARP_TABLE;
	else
		return IS_IN_ARP_TABLE;
}

void uip_build_arp_request(struct uip_stack *ustack, u16_t *ipaddr)
{
	struct arp_hdr *arp;
	struct uip_eth_hdr *eth;

	arp = (struct arp_hdr *)ustack->network_layer;
	eth = (struct uip_eth_hdr *)ustack->data_link_layer;

	/* The destination address was not in our ARP table, so we
	   overwrite the IP packet with an ARP request. */

	memset(eth->dest.addr, 0xff, 6);
	memset(arp->dhwaddr.addr, 0x00, 6);
	memcpy(eth->src.addr, ustack->uip_ethaddr.addr, 6);
	memcpy(arp->shwaddr.addr, ustack->uip_ethaddr.addr, 6);

	uip_ip4addr_copy(arp->dipaddr, ipaddr);
	uip_ip4addr_copy(arp->sipaddr, ustack->hostaddr);
	arp->opcode = const_htons(ARP_REQUEST);	/* ARP request. */
	arp->hwtype = const_htons(ARP_HWTYPE_ETH);
	arp->protocol = const_htons(UIP_ETHTYPE_IPv4);
	arp->hwlen = 6;
	arp->protolen = 4;
	eth->type = const_htons(UIP_ETHTYPE_ARP);

	ustack->uip_appdata = &ustack->uip_buf[UIP_TCP_IPv4_HLEN + UIP_LLH_LEN];

	ustack->uip_len = sizeof(*arp) + sizeof(*eth);
}

void
uip_build_eth_header(struct uip_stack *ustack,
		     u16_t *ipaddr,
		     struct arp_entry *tabptr,
		     struct packet *pkt, u16_t vlan_id)
{
	struct uip_ipv4_hdr *ip_buf;
	struct uip_eth_hdr *eth;
	struct uip_vlan_eth_hdr *eth_vlan;

	ip_buf = (struct uip_ipv4_hdr *)ustack->network_layer;
	eth = (struct uip_eth_hdr *)ustack->data_link_layer;
	eth_vlan = (struct uip_vlan_eth_hdr *)ustack->data_link_layer;

	/* First check if destination is a local broadcast. */
	if (uip_ip4addr_cmp(ip_buf->destipaddr, broadcast_ipaddr)) {
		memcpy(eth->dest.addr, broadcast_ethaddr.addr, 6);
	} else {
		/* Build an ethernet header. */
		memcpy(eth->dest.addr, tabptr->ethaddr.addr, 6);
	}
	memcpy(eth->src.addr, ustack->uip_ethaddr.addr, 6);

	if (vlan_id == 0) {
		eth->type = htons(UIP_ETHTYPE_IPv4);

		ustack->uip_len += sizeof(struct uip_eth_hdr);
		pkt->buf_size += sizeof(struct uip_eth_hdr);
	} else {
		eth_vlan->tpid = htons(UIP_ETHTYPE_8021Q);
		eth_vlan->vid = htons(vlan_id);
		eth_vlan->type = htons(UIP_ETHTYPE_IPv4);

		ustack->uip_len += sizeof(struct uip_vlan_eth_hdr);
		pkt->buf_size += sizeof(struct uip_vlan_eth_hdr);
	}
}

static struct arp_entry *uip_get_arp_entry(int index)
{
	return &arp_table[index];
}

int uip_lookup_arp_entry(uint32_t ip_addr, uint8_t *mac_addr)
{
	int i;
	int rc = -EINVAL;

	pthread_mutex_lock(&arp_table_mutex);

	for (i = 0; i < UIP_ARPTAB_SIZE; ++i) {
		struct arp_entry *entry = uip_get_arp_entry(i);

		if (((entry->ipaddr[1] << 16) == (ip_addr & 0xffff0000)) &&
		    ((entry->ipaddr[0]) == (ip_addr & 0x0000ffff))) {
			struct in_addr addr;
			char *addr_str;

			addr.s_addr = ip_addr;
			addr_str = inet_ntoa(addr);

			memcpy(mac_addr, entry->ethaddr.addr, 6);

			LOG_INFO("Found %s at %02x:%02x:%02x:%02x:%02x:%02x",
				 addr_str,
				 mac_addr[0], mac_addr[1], mac_addr[2],
				 mac_addr[3], mac_addr[4], mac_addr[5]);
			rc = 0;
			break;
		}
	}

	pthread_mutex_unlock(&arp_table_mutex);
	return rc;
}

/*----------------------------------------------------------------------------*/

/** @} */
/** @} */
