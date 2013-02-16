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
 *         Database of link-local neighbors, used by IPv6 code and
 *         to be used by a future ARP code rewrite.
 * \author
 *         Adam Dunkels <adam@sics.se>
 */

#include "logger.h"
#include "uip.h"
#include "uip-neighbor.h"

#include <errno.h>
#include <string.h>
#include <arpa/inet.h>

/*******************************************************************************
 * Constants
 ******************************************************************************/
#define PFX "uip-neigh "

#define MAX_TIME 128

/*---------------------------------------------------------------------------*/
void uip_neighbor_init(struct uip_stack *ustack)
{
	int i;

	pthread_mutex_lock(&ustack->lock);
	for (i = 0; i < UIP_NEIGHBOR_ENTRIES; ++i) {
		memset(&(ustack->neighbor_entries[i].ipaddr), 0,
		       sizeof(ustack->neighbor_entries[i].ipaddr));
		memset(&(ustack->neighbor_entries[i].mac_addr), 0,
		       sizeof(ustack->neighbor_entries[i].mac_addr));
		ustack->neighbor_entries[i].time = MAX_TIME;
	}
	pthread_mutex_unlock(&ustack->lock);
}

void uip_neighbor_add(struct uip_stack *ustack,
		      struct in6_addr *addr6, struct uip_eth_addr *addr)
{
	int i, oldest;
	u8_t oldest_time;
	char buf[INET6_ADDRSTRLEN];

	inet_ntop(AF_INET6, addr6, buf, sizeof(buf));

	pthread_mutex_lock(&ustack->lock);

	/* Find the first unused entry or the oldest used entry. */
	oldest_time = 0;
	oldest = 0;
	for (i = 0; i < UIP_NEIGHBOR_ENTRIES; ++i) {
		if (ustack->neighbor_entries[i].time == MAX_TIME) {
			oldest = i;
			break;
		}
		if (uip_ip6addr_cmp
		    (ustack->neighbor_entries[i].ipaddr.s6_addr, addr6)) {
			oldest = i;
			break;
		}
		if (ustack->neighbor_entries[i].time > oldest_time) {
			oldest = i;
			oldest_time = ustack->neighbor_entries[i].time;
		}
	}

	/* Use the oldest or first free entry (either pointed to by the
	   "oldest" variable). */
	ustack->neighbor_entries[oldest].time = 0;
	uip_ip6addr_copy(ustack->neighbor_entries[oldest].ipaddr.s6_addr,
			 addr6);
	memcpy(&ustack->neighbor_entries[oldest].mac_addr, addr,
	       sizeof(struct uip_eth_addr));

	LOG_DEBUG("Adding neighbor %s with "
		  "mac address %02x:%02x:%02x:%02x:%02x:%02x at %d",
		  buf, addr->addr[0], addr->addr[1], addr->addr[2],
		  addr->addr[3], addr->addr[4], addr->addr[5], oldest);

	pthread_mutex_unlock(&ustack->lock);
}

/*---------------------------------------------------------------------------*/
static struct neighbor_entry *find_entry(struct uip_stack *ustack,
					 struct in6_addr *addr6)
{
	int i;

	for (i = 0; i < UIP_NEIGHBOR_ENTRIES; ++i) {
		if (uip_ip6addr_cmp
		    (ustack->neighbor_entries[i].ipaddr.s6_addr,
		     addr6->s6_addr)) {
			return &ustack->neighbor_entries[i];
		}
	}

	return NULL;
}

/*---------------------------------------------------------------------------*/
void uip_neighbor_update(struct uip_stack *ustack, struct in6_addr *addr6)
{
	struct neighbor_entry *e;

	pthread_mutex_lock(&ustack->lock);

	e = find_entry(ustack, addr6);
	if (e != NULL)
		e->time = 0;

	pthread_mutex_unlock(&ustack->lock);
}

/*---------------------------------------------------------------------------*/
int uip_neighbor_lookup(struct uip_stack *ustack,
			struct in6_addr *addr6, uint8_t *mac_addr)
{
	struct neighbor_entry *e;

	pthread_mutex_lock(&ustack->lock);
	e = find_entry(ustack, addr6);
	if (e != NULL) {
		char addr6_str[INET6_ADDRSTRLEN];
		uint8_t *entry_mac_addr;

		addr6_str[0] = '\0';
		inet_ntop(AF_INET6, addr6->s6_addr, addr6_str,
			  sizeof(addr6_str));
		entry_mac_addr = (uint8_t *)&e->mac_addr.addr;

		LOG_DEBUG(PFX
			  "Found %s at %02x:%02x:%02x:%02x:%02x:%02x",
			  addr6_str,
			  entry_mac_addr[0], entry_mac_addr[1],
			  entry_mac_addr[2], entry_mac_addr[3],
			  entry_mac_addr[4], entry_mac_addr[5]);

		memcpy(mac_addr, entry_mac_addr, sizeof(e->mac_addr));
		pthread_mutex_unlock(&ustack->lock);
		return 0;
	}

	pthread_mutex_unlock(&ustack->lock);
	return -ENOENT;
}

void uip_neighbor_out(struct uip_stack *ustack)
{
	struct neighbor_entry *e;
	struct uip_eth_hdr *eth_hdr =
	    (struct uip_eth_hdr *)ustack->data_link_layer;
	struct uip_ipv6_hdr *ipv6_hdr =
	    (struct uip_ipv6_hdr *)ustack->network_layer;

	pthread_mutex_lock(&ustack->lock);

	/* Find the destination IP address in the neighbor table and construct
	   the Ethernet header. If the destination IP addres isn't on the
	   local network, we use the default router's IP address instead.

	   If not ARP table entry is found, we overwrite the original IP
	   packet with an ARP request for the IP address. */
	e = find_entry(ustack, (struct in6_addr *)ipv6_hdr->destipaddr);
	if (e == NULL) {
		struct uip_eth_addr eth_addr_tmp;

		memcpy(&eth_addr_tmp, eth_hdr->src.addr, sizeof(eth_addr_tmp));
		memcpy(eth_hdr->src.addr, ustack->uip_ethaddr.addr,
		       sizeof(eth_hdr->src.addr));
		memcpy(eth_hdr->dest.addr, &eth_addr_tmp,
		       sizeof(eth_hdr->dest.addr));

		pthread_mutex_unlock(&ustack->lock);
		return;
	}

	memcpy(eth_hdr->dest.addr, &e->mac_addr, sizeof(eth_hdr->dest.addr));
	memcpy(eth_hdr->src.addr, ustack->uip_ethaddr.addr,
	       sizeof(eth_hdr->src.addr));

	pthread_mutex_unlock(&ustack->lock);
}

/*---------------------------------------------------------------------------*/
