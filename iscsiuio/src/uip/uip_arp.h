/**
 * \addtogroup uip
 * @{
 */

/**
 * \addtogroup uiparp
 * @{
 */

/**
 * \file
 * Macros and definitions for the ARP module.
 * \author Adam Dunkels <adam@dunkels.com>
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

#ifndef __UIP_ARP_H__
#define __UIP_ARP_H__

#include "packet.h"
#include "uip.h"
#include "uip_eth.h"

#define ARP_REQUEST 1
#define ARP_REPLY   2

#define ARP_HWTYPE_ETH 1

struct __attribute__ ((__packed__)) arp_hdr {
	u16_t hwtype;
	u16_t protocol;
	u8_t hwlen;
	u8_t protolen;
	u16_t opcode;
	struct uip_eth_addr shwaddr;
	u16_t sipaddr[2];
	struct uip_eth_addr dhwaddr;
	u16_t dipaddr[2];
};

struct __attribute__ ((__packed__)) ip_hdr {
	/* IP header. */
	u8_t vhl, tos, len[2], ipid[2], ipoffset[2], ttl, proto;
	u16_t ipchksum;
	u16_t srcipaddr[2], destipaddr[2];
};

struct __attribute__ ((__packed__)) ethip_hdr {
	struct uip_eth_hdr ethhdr;
	/* IP header. */
	u8_t vhl, tos, len[2], ipid[2], ipoffset[2], ttl, proto;
	u16_t ipchksum;
	u16_t srcipaddr[2], destipaddr[2];
};

struct arp_entry {
	u16_t ipaddr[2];
	struct uip_eth_addr ethaddr;
	u8_t time;
};

/* The uip_arp_init() function must be called before any of the other
   ARP functions. */
void uip_arp_init(void);

/* The uip_arp_ipin() function should be called whenever an IP packet
   arrives from the Ethernet. This function refreshes the ARP table or
   inserts a new mapping if none exists. The function assumes that an
   IP packet with an Ethernet header is present in the uip_buf buffer
   and that the length of the packet is in the uip_len variable. */
/*void uip_arp_ipin(void);*/
/* #define uip_arp_ipin() */
void uip_arp_ipin(struct uip_stack *ustack, struct packet *pkt);

/* The uip_arp_arpin() should be called when an ARP packet is received
   by the Ethernet driver. This function also assumes that the
   Ethernet frame is present in the uip_buf buffer. When the
   uip_arp_arpin() function returns, the contents of the uip_buf
   buffer should be sent out on the Ethernet if the uip_len variable
   is > 0. */
void uip_arp_arpin(nic_interface_t *nic_iface,
		   struct uip_stack *ustack, struct packet *pkt);

typedef enum {
	ARP_SENT = 1,
	ETH_HEADER_APPEDEND = 2,
} arp_out_t;

typedef enum {
	LOCAL_BROADCAST = 1,
	NONLOCAL_BROADCAST = 2,
} dest_ipv4_addr_t;

typedef enum {
	IS_IN_ARP_TABLE = 1,
	NOT_IN_ARP_TABLE = 2,
} arp_table_query_t;

dest_ipv4_addr_t
uip_determine_dest_ipv4_addr(struct uip_stack *ustack, u16_t *ipaddr);
arp_out_t is_in_arp_table(u16_t *ipaddr, struct arp_entry **tabptr);

void uip_build_arp_request(struct uip_stack *ustack, u16_t *ipaddr);

void
uip_build_eth_header(struct uip_stack *ustack,
		     u16_t *ipaddr,
		     struct arp_entry *tabptr,
		     struct packet *pkt, u16_t vlan_id);

/* The uip_arp_out() function should be called when an IP packet
   should be sent out on the Ethernet. This function creates an
   Ethernet header before the IP header in the uip_buf buffer. The
   Ethernet header will have the correct Ethernet MAC destination
   address filled in if an ARP table entry for the destination IP
   address (or the IP address of the default router) is present. If no
   such table entry is found, the IP packet is overwritten with an ARP
   request and we rely on TCP to retransmit the packet that was
   overwritten. In any case, the uip_len variable holds the length of
   the Ethernet frame that should be transmitted. */
arp_out_t uip_arp_out(struct uip_stack *ustack);

/* The uip_arp_timer() function should be called every ten seconds. It
   is responsible for flushing old entries in the ARP table. */
void uip_arp_timer(void);

int uip_lookup_arp_entry(uint32_t ip_addr, uint8_t *mac_addr);

/** @} */

/**
 * \addtogroup uipconffunc
 * @{
 */

/**
 * Specifiy the Ethernet MAC address.
 *
 * The ARP code needs to know the MAC address of the Ethernet card in
 * order to be able to respond to ARP queries and to generate working
 * Ethernet headers.
 *
 * \note This macro only specifies the Ethernet MAC address to the ARP
 * code. It cannot be used to change the MAC address of the Ethernet
 * card.
 *
 * \param eaddr A pointer to a struct uip_eth_addr containing the
 * Ethernet MAC address of the Ethernet card.
 *
 * \hideinitializer
 */
#define uip_setethaddr(eaddr)	do {					     \
					uip_ethaddr.addr[0] = eaddr.addr[0]; \
					uip_ethaddr.addr[1] = eaddr.addr[1]; \
					uip_ethaddr.addr[2] = eaddr.addr[2]; \
					uip_ethaddr.addr[3] = eaddr.addr[3]; \
					uip_ethaddr.addr[4] = eaddr.addr[4]; \
					uip_ethaddr.addr[5] = eaddr.addr[5]; \
				} while (0)

/** @} */
/** @} */

#endif /* __UIP_ARP_H__ */
