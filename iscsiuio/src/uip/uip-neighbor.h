/*
 * Copyright (c) 2006, Swedish Institute of Computer Science.
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
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the uIP TCP/IP stack
 *
 */

/**
 * \file
 *         Header file for database of link-local neighbors, used by
 *         IPv6 code and to be used by future ARP code.
 * \author
 *         Adam Dunkels <adam@sics.se>
 */

#ifndef __UIP_NEIGHBOR_H__
#define __UIP_NEIGHBOR_H__

#include "uip.h"
#include "uip_eth.h"

/*  ICMP types */
/*  ICMPv6 error Messages */
#define ICMPV6_DEST_UNREACH		1
#define ICMPV6_PKT_TOOBIG		2
#define ICMPV6_TIME_EXCEED		3
#define ICMPV6_PARAMPROB		4

/*  ICMPv6 Informational Messages */
#define ICMPV6_ECHO_REQUEST		128
#define ICMPV6_ECHO_REPLY		129
#define ICMPV6_MGM_QUERY		130
#define ICMPV6_MGM_REPORT		131
#define ICMPV6_MGM_REDUCTION		132

/* Codes for Destination Unreachable  */
#define ICMPV6_NOROUTE			0
#define ICMPV6_ADM_PROHIBITED		1
#define ICMPV6_NOT_NEIGHBOUR		2
#define ICMPV6_ADDR_UNREACH		3
#define ICMPV6_PORT_UNREACH		4

/* Codes for Time Exceeded */
#define ICMPV6_EXC_HOPLIMIT             0
#define ICMPV6_EXC_FRAGTIME             1

/* Codes for Parameter Problem */
#define ICMPV6_HDR_FIELD                0
#define ICMPV6_UNK_NEXTHDR              1
#define ICMPV6_UNK_OPTION               2

#if 0
struct __attribute__ ((__packed__)) icmpv6_hdr {
	u8_t type;
	u8_t code;
	u16_t checksum;
	union {
		struct {
			u16_t id;
			u16_t sequence;
		} echo;
		u32_t gateway;
		struct {
			u16_t unused;
			u16_t mtu;
		} frag;
	} un;
};
#endif

void uip_neighbor_init(struct uip_stack *ustack);
void uip_neighbor_add(struct uip_stack *ustack,
		      struct in6_addr *addr6, struct uip_eth_addr *addr);
void uip_neighbor_update(struct uip_stack *ustack, struct in6_addr *addr6);
int uip_neighbor_lookup(struct uip_stack *ustack, struct in6_addr *ipaddr,
			uint8_t *mac_addr);
void uip_neighbor_periodic(void);
void uip_neighbor_out(struct uip_stack *ustack);

#endif /* __UIP-NEIGHBOR_H__ */
