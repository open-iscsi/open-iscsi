/*
 * Copyright (c) 2011, Broadcom Corporation
 * Copyright (c) 2014, QLogic Corporation
 *
 * Written by:  Eddie Wai  (eddie.wai@broadcom.com)
 *              Based on the Swedish Institute of Computer Science's
 *              dhcpc.c code
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
 * ipv6_ndpc.c - Top level IPv6 Network Discovery Protocol Engine (RFC4861)
 *
 */
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "uip.h"
#include "ipv6_ndpc.h"
#include "timer.h"
#include "pt.h"

#include "debug.h"
#include "logger.h"
#include "nic.h"
#include "nic_utils.h"
#include "ipv6.h"
#include "ipv6_pkt.h"
#include "dhcpv6.h"

const int dhcpv6_retry_timeout[DHCPV6_NUM_OF_RETRY] = { 1, 2, 4, 8 };

static PT_THREAD(handle_ndp(struct uip_stack *ustack, int force))
{
	struct ndpc_state *s;
	struct ipv6_context *ipv6c;
	struct dhcpv6_context *dhcpv6c = NULL;
	u16_t task = 0;
	char buf[INET6_ADDRSTRLEN];

	s = ustack->ndpc;
	if (s == NULL) {
		LOG_DEBUG("NDP: Could not find ndpc state");
		return PT_ENDED;
	}

	ipv6c = s->ipv6_context;
	if (!ipv6c)
		goto ndpc_state_null;

	dhcpv6c = s->dhcpv6_context;

	PT_BEGIN(&s->pt);

	if (s->state == NDPC_STATE_BACKGROUND_LOOP)
		goto ipv6_loop;

	if (s->state == NDPC_STATE_RTR_ADV)
		goto rtr_adv;

	/* For AUTOCFG == DHCPv6, do all
	   For         == ND, skip DHCP only and do RTR
	   For         == UNUSED/UNSPEC, do all as according to DHCP or not */
	s->state = NDPC_STATE_RTR_SOL;
	/* try_again: */
	s->ticks = CLOCK_SECOND * IPV6_MAX_ROUTER_SOL_DELAY;
	s->retry_count = 0;
	do {
		/* Perform router solicitation and wait for
		   router advertisement */
		LOG_DEBUG("%s: ndpc_handle send rtr sol", s->nic->log_name);
		ipv6_autoconfig(s->ipv6_context);

		timer_set(&s->timer, s->ticks);
wait_rtr:
		s->ustack->uip_flags &= ~UIP_NEWDATA;
		LOG_DEBUG("%s: ndpc_handle wait for rtr adv flags=0x%x",
			  s->nic->log_name, ipv6c->flags);
		PT_WAIT_UNTIL(&s->pt, uip_newdata(s->ustack)
			      || timer_expired(&s->timer) || force);

		if (uip_newdata(s->ustack)) {
			/* Validate incoming packets
			   Note that the uip_len is init from nic loop */
			ipv6_rx_packet(ipv6c, (u16_t) uip_datalen(s->ustack));
			if (ipv6c->flags & IPV6_FLAGS_ROUTER_ADV_RECEIVED) {
				LOG_INFO("%s: ROUTER_ADV_RECEIVED",
					 s->nic->log_name);
				/* Success */
				break;
			} else if (!timer_expired(&s->timer)) {
				/* Yes new data, but not what we want,
				   check for timer expiration before bumping
				   tick */
				goto wait_rtr;
			}
		}
		s->retry_count++;
		if (s->retry_count >= IPV6_MAX_ROUTER_SOL_RETRY)
			/* Max router solicitation retry reached.  Move to
			   IPv6 loop (no DHCPv6) */
			goto no_rtr_adv;

	} while (!(ipv6c->flags & IPV6_FLAGS_ROUTER_ADV_RECEIVED));

	LOG_DEBUG("%s: ndpc_handle got rtr adv", s->nic->log_name);
	s->retry_count = 0;

no_rtr_adv:
	s->state = NDPC_STATE_RTR_ADV;

rtr_adv:
	if (!(ustack->ip_config & IPV6_CONFIG_DHCP))
		goto staticv6;

	/* Only DHCPv6 comes here */
	task = ipv6_do_stateful_dhcpv6(ipv6c, ISCSI_FLAGS_DHCP_TCPIP_CONFIG);
	if (task) {
		/* Run the DHCPv6 engine */

		if (!dhcpv6c)
			goto ipv6_loop;

		dhcpv6c->dhcpv6_task = task;
		s->retry_count = 0;
		s->state = NDPC_STATE_DHCPV6_DIS;
		do {
			/* Do dhcpv6 */
			dhcpv6c->timeout = dhcpv6_retry_timeout[s->retry_count];
			s->ticks = CLOCK_SECOND * dhcpv6c->timeout;
			LOG_DEBUG("%s: ndpc_handle send dhcpv6 sol retry "
				  "cnt=%d", s->nic->log_name, s->retry_count);
			dhcpv6_do_discovery(dhcpv6c);

			timer_set(&s->timer, s->ticks);
wait_dhcp:
			s->ustack->uip_flags &= ~UIP_NEWDATA;
			PT_WAIT_UNTIL(&s->pt, uip_newdata(s->ustack)
				      || timer_expired(&s->timer) || force);

			if (uip_newdata(s->ustack)) {
				/* Validate incoming packets
				   Note that the uip_len is init from nic
				   loop */
				ipv6_rx_packet(ipv6c,
					       (u16_t) uip_datalen(s->ustack));
				if (dhcpv6c->dhcpv6_done == TRUE)
					break;
				else if (!timer_expired(&s->timer)) {
					/* Yes new data, but not what we want,
					   check for timer expiration before
					   bumping tick */
					goto wait_dhcp;
				}
			}
			s->retry_count++;
			if (s->retry_count < DHCPV6_NUM_OF_RETRY) {
				dhcpv6c->seconds += dhcpv6c->timeout;
			} else {
				LOG_DEBUG("%s: ndpc_handle DHCP failed",
					  s->nic->log_name);
				/* Allow to goto background loop */
				goto ipv6_loop;
			}
		} while (dhcpv6c->dhcpv6_done == FALSE);
		s->state = NDPC_STATE_DHCPV6_DONE;

		LOG_DEBUG("%s: ndpc_handle got dhcpv6", s->nic->log_name);

		/* End of DHCPv6 engine */
	} else {
		/* Static IPv6 */
		if (ustack->ip_config == IPV6_CONFIG_DHCP) {
			s->retry_count++;
			if (s->retry_count > DHCPV6_NUM_OF_RETRY) {
				LOG_DEBUG("%s: ndpc_handle DHCP failed",
					  s->nic->log_name);
			} else {
				PT_RESTART(&s->pt);
			}
		}
staticv6:
		ipv6_disable_dhcpv6(ipv6c);
	}
	/* Copy out the default_router_addr6 and ll */
	if (ustack->router_autocfg != IPV6_RTR_AUTOCFG_OFF)
		memcpy(&ustack->default_route_addr6,
		       &ipv6c->default_router, sizeof(struct ipv6_addr));
	inet_ntop(AF_INET6, &ustack->default_route_addr6,
		  buf, sizeof(buf));
	LOG_INFO("%s: Default router IP: %s", s->nic->log_name,
		 buf);

	if (ustack->linklocal_autocfg != IPV6_LL_AUTOCFG_OFF)
		memcpy(&ustack->linklocal6, &ipv6c->link_local_addr,
		       sizeof(struct ipv6_addr));
	inet_ntop(AF_INET6, &ustack->linklocal6,
		  buf, sizeof(buf));
	LOG_INFO("%s: Linklocal IP: %s", s->nic->log_name,
		 buf);

ipv6_loop:
	s->state = NDPC_STATE_BACKGROUND_LOOP;
	LOG_DEBUG("%s: Loop", s->nic->log_name);
	/* Background IPv6 loop */
	while (1) {
		/* Handle all neightbor solicitation/advertisement here */
		s->ustack->uip_flags &= ~UIP_NEWDATA;
		PT_WAIT_UNTIL(&s->pt, uip_newdata(s->ustack));

		/* Validate incoming packets */
		ipv6_rx_packet(ipv6c, (u16_t) uip_datalen(s->ustack));
	}

ndpc_state_null:

	while (1)
		PT_YIELD(&s->pt);

	PT_END(&(s->pt));
}

/*---------------------------------------------------------------------------*/
int ndpc_init(nic_t *nic, struct uip_stack *ustack,
	      const void *mac_addr, int mac_len)
{
	struct ipv6_context *ipv6c;
	struct dhcpv6_context *dhcpv6c;
	struct ndpc_state *s = ustack->ndpc;
	struct ipv6_addr src, gw, ll;
	char buf[INET6_ADDRSTRLEN];

	if (s) {
		LOG_DEBUG("NDP: NDP context already allocated");
		/* Already allocated, skip*/
		return -EALREADY;
	}
	s = malloc(sizeof(*s));
	if (s == NULL) {
		LOG_ERR("%s: Couldn't allocate size for ndpc info",
			nic->log_name);
		goto error;
	}
	memset(s, 0, sizeof(*s));

	if (s->ipv6_context) {
		LOG_DEBUG("NDP: IPv6 context already allocated");
		ipv6c = s->ipv6_context;
		goto init1;
	}
	ipv6c = malloc(sizeof(struct ipv6_context));
	if (ipv6c == NULL) {
		LOG_ERR("%s: Couldn't allocate mem for IPv6 context info",
		nic->log_name);
		goto error1;
	}
init1:
	if (s->dhcpv6_context) {
		LOG_DEBUG("NDP: DHCPv6 context already allocated");
		dhcpv6c = s->dhcpv6_context;
		goto init2;
	}
	dhcpv6c = malloc(sizeof(struct dhcpv6_context));
	if (dhcpv6c == NULL) {
		LOG_ERR("%s: Couldn't allocate mem for DHCPv6 context info",
		nic->log_name);
		goto error2;
	}
init2:
	memset(s, 0, sizeof(*s));
	memset(ipv6c, 0, sizeof(*ipv6c));
	memset(dhcpv6c, 0, sizeof(*dhcpv6c));

	s->ipv6_context = ipv6c;
	s->dhcpv6_context = dhcpv6c;

	s->nic = nic;
	s->ustack = ustack;
	s->mac_addr = (void *)mac_addr;
	s->mac_len = mac_len;
	s->state = NDPC_STATE_INIT;

	/* Init IPV6_CONTEXT */
	ipv6_init(s, ustack->ip_config);

	dhcpv6c->ipv6_context = ipv6c;
	ipv6c->dhcpv6_context = dhcpv6c;

	/* Init DHCPV6_CONTEXT */
	dhcpv6_init(dhcpv6c);

	ustack->ndpc = s;

	PT_INIT(&s->pt);

	if (ustack->ip_config == IPV6_CONFIG_DHCP) {
		/* DHCPv6 specific */
		memset(&src, 0, sizeof(src));
	} else {
		/* Static v6 specific */
		memcpy(&src.addr8, &ustack->hostaddr6,
		       sizeof(struct ipv6_addr));
		ipv6_add_solit_node_address(ipv6c, &src);

		inet_ntop(AF_INET6, &src.addr8, buf, sizeof(buf));
		LOG_INFO("%s: Static hostaddr IP: %s", s->nic->log_name,
			 buf);
	}
	/* Copy out the default_router_addr6 and ll */
	if (ustack->router_autocfg == IPV6_RTR_AUTOCFG_OFF)
		memcpy(&gw.addr8, &ustack->default_route_addr6,
		       sizeof(struct ipv6_addr));
	else
		memset(&gw, 0, sizeof(gw));

	if (ustack->linklocal_autocfg == IPV6_LL_AUTOCFG_OFF)
		memcpy(&ll.addr8, &ustack->linklocal6,
		       sizeof(struct ipv6_addr));
	else
		memset(&ll, 0, sizeof(ll));
	ipv6_set_ip_params(ipv6c, &src,
			   ustack->prefix_len, &gw, &ll);

	return 0;
error2:
	free(ipv6c);
	s->ipv6_context = NULL;
error1:
	free(s);
	ustack->ndpc = NULL;
error:
	return -ENOMEM;
}

/*---------------------------------------------------------------------------*/
void ndpc_call(struct uip_stack *ustack)
{
	handle_ndp(ustack, 0);
}

void ndpc_exit(struct ndpc_state *ndp)
{
	LOG_DEBUG("NDP - Exit ndpc_state = %p", ndp);
	if (!ndp)
		return;
	if (ndp->ipv6_context)
		free(ndp->ipv6_context);
	if (ndp->dhcpv6_context)
		free(ndp->dhcpv6_context);
	free(ndp);
}

int ndpc_request(struct uip_stack *ustack, void *in, void *out, int request)
{
	struct ndpc_state *s;
	struct ipv6_context *ipv6c;
	int ret = 0;

	if (!ustack) {
		LOG_DEBUG("NDP: ustack == NULL");
		return -EINVAL;
	}
	s = ustack->ndpc;
	if (s == NULL) {
		LOG_DEBUG("NDP: Could not find ndpc state for request %d",
			  request);
		return -EINVAL;
	}
	while (s->state != NDPC_STATE_BACKGROUND_LOOP) {
		LOG_DEBUG("%s: ndpc state not in background loop, run handler "
			  "request = %d", s->nic->log_name, request);
		handle_ndp(ustack, 1);
	}

	ipv6c = s->ipv6_context;
	switch (request) {
	case NEIGHBOR_SOLICIT:
		*(int *)out = ipv6_send_nd_solicited_packet(ipv6c,
			(struct eth_hdr *)((struct ndpc_reqptr *)in)->eth,
			(struct ipv6_hdr *)((struct ndpc_reqptr *)in)->ipv6);
		break;
	case CHECK_LINK_LOCAL_ADDR:
		*(int *)out = ipv6_is_it_our_link_local_address(ipv6c,
							(struct ipv6_addr *)in);
		break;
	case CHECK_ARP_TABLE:
		*(int *)out = ipv6_ip_in_arp_table(ipv6c,
			(struct ipv6_addr *)((struct ndpc_reqptr *)in)->ipv6,
			(struct mac_address *)((struct ndpc_reqptr *)in)->eth);
		break;
	case GET_HOST_ADDR:
		*(struct ipv6_addr **)out = ipv6_find_longest_match(ipv6c,
							(struct ipv6_addr *)in);
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

/*---------------------------------------------------------------------------*/
