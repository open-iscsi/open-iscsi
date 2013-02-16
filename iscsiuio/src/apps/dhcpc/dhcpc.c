/*
 * Copyright (c) 2005, Swedish Institute of Computer Science
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

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "uip.h"
#include "dhcpc.h"
#include "timer.h"
#include "pt.h"

#include "debug.h"
#include "logger.h"
#include "nic.h"
#include "nic_utils.h"

struct __attribute__ ((__packed__)) dhcp_msg {
	u8_t op, htype, hlen, hops;
	u8_t xid[4];
	u16_t secs, flags;
	u8_t ciaddr[4];
	u8_t yiaddr[4];
	u8_t siaddr[4];
	u8_t giaddr[4];
	u8_t chaddr[16];
#ifndef UIP_CONF_DHCP_LIGHT
	u8_t sname[64];
	u8_t file[128];
#endif
	u8_t options[312];
};

#define BOOTP_BROADCAST 0x8000

#define DHCP_REQUEST        1
#define DHCP_REPLY          2
#define DHCP_HTYPE_ETHERNET 1
#define DHCP_HLEN_ETHERNET  6
#define DHCP_MSG_LEN      236

#define DHCPC_SERVER_PORT  67
#define DHCPC_CLIENT_PORT  68

#define DHCPDISCOVER  1
#define DHCPOFFER     2
#define DHCPREQUEST   3
#define DHCPDECLINE   4
#define DHCPACK       5
#define DHCPNAK       6
#define DHCPRELEASE   7

#define DHCP_OPTION_SUBNET_MASK   1
#define DHCP_OPTION_ROUTER        3
#define DHCP_OPTION_DNS_SERVER    6
#define DHCP_OPTION_REQ_IPADDR   50
#define DHCP_OPTION_LEASE_TIME   51
#define DHCP_OPTION_MSG_TYPE     53
#define DHCP_OPTION_SERVER_ID    54
#define DHCP_OPTION_REQ_LIST     55
#define DHCP_OPTION_END         255

static u8_t xid[4] = { 0xad, 0xde, 0x12, 0x23 };
static const u8_t magic_cookie[4] = { 99, 130, 83, 99 };

struct dhcpc_options dhcpc_opt = {
	.enable_random_xid = 1,
};

/*---------------------------------------------------------------------------*/
static u8_t *add_msg_type(u8_t *optptr, u8_t type)
{
	*optptr++ = DHCP_OPTION_MSG_TYPE;
	*optptr++ = 1;
	*optptr++ = type;
	return optptr;
}

/*---------------------------------------------------------------------------*/
static u8_t *add_server_id(struct dhcpc_state *s, u8_t *optptr)
{
	*optptr++ = DHCP_OPTION_SERVER_ID;
	*optptr++ = 4;
	memcpy(optptr, s->serverid, 4);
	return optptr + 4;
}

/*---------------------------------------------------------------------------*/
static u8_t *add_req_ipaddr(struct dhcpc_state *s, u8_t *optptr)
{
	*optptr++ = DHCP_OPTION_REQ_IPADDR;
	*optptr++ = 4;
	memcpy(optptr, s->ipaddr, 4);
	return optptr + 4;
}

/*---------------------------------------------------------------------------*/
static u8_t *add_req_options(u8_t *optptr)
{
	*optptr++ = DHCP_OPTION_REQ_LIST;
	*optptr++ = 3;
	*optptr++ = DHCP_OPTION_SUBNET_MASK;
	*optptr++ = DHCP_OPTION_ROUTER;
	*optptr++ = DHCP_OPTION_DNS_SERVER;
	return optptr;
}

/*---------------------------------------------------------------------------*/
static u8_t *add_end(u8_t *optptr)
{
	*optptr++ = DHCP_OPTION_END;
	return optptr;
}

/*---------------------------------------------------------------------------*/
static void create_msg(struct dhcpc_state *s, struct dhcp_msg *m)
{
	m->op = DHCP_REQUEST;
	m->htype = DHCP_HTYPE_ETHERNET;
	m->hlen = s->mac_len;
	m->hops = 0;
	memcpy(m->xid, xid, sizeof(m->xid));
	m->secs = 0;
	m->flags = const_htons(BOOTP_BROADCAST);	/*  Broadcast bit. */
	/*  uip_ipaddr_copy(m->ciaddr, uip_hostaddr); */
	memcpy(m->ciaddr, s->ustack->hostaddr, sizeof(m->ciaddr));
	memset(m->yiaddr, 0, sizeof(m->yiaddr));
	memset(m->siaddr, 0, sizeof(m->siaddr));
	memset(m->giaddr, 0, sizeof(m->giaddr));
	memcpy(m->chaddr, s->mac_addr, s->mac_len);
	memset(&m->chaddr[s->mac_len], 0, sizeof(m->chaddr) - s->mac_len);
#ifndef UIP_CONF_DHCP_LIGHT
	memset(m->sname, 0, sizeof(m->sname));
	memset(m->file, 0, sizeof(m->file));
#endif

	memcpy(m->options, magic_cookie, sizeof(magic_cookie));
}

/*---------------------------------------------------------------------------*/
static void send_discover(struct dhcpc_state *s)
{
	u8_t *end;
	struct dhcp_msg *m = (struct dhcp_msg *)s->ustack->uip_appdata;

	create_msg(s, m);

	end = add_msg_type(&m->options[4], DHCPDISCOVER);
	end = add_req_options(end);
	end = add_end(end);

	uip_appsend(s->ustack, s->ustack->uip_appdata,
		    end - (u8_t *) s->ustack->uip_appdata);
}

/*---------------------------------------------------------------------------*/
static void send_request(struct dhcpc_state *s)
{
	u8_t *end;
	struct dhcp_msg *m = (struct dhcp_msg *)s->ustack->uip_appdata;

	create_msg(s, m);

	end = add_msg_type(&m->options[4], DHCPREQUEST);
	end = add_server_id(s, end);
	end = add_req_ipaddr(s, end);
	end = add_end(end);

	uip_appsend(s->ustack, s->ustack->uip_appdata,
		    end - (u8_t *) s->ustack->uip_appdata);
}

/*---------------------------------------------------------------------------*/
static u8_t parse_options(struct dhcpc_state *s, u8_t *optptr, int len)
{
	u8_t *end = optptr + len;
	u8_t type = 0;

	while (optptr < end) {
		switch (*optptr) {
		case DHCP_OPTION_SUBNET_MASK:
			memcpy(s->netmask, optptr + 2, 4);
			break;
		case DHCP_OPTION_ROUTER:
			memcpy(s->default_router, optptr + 2, 4);
			break;
		case DHCP_OPTION_DNS_SERVER:
			memcpy(s->dnsaddr, optptr + 2, 4);
			break;
		case DHCP_OPTION_MSG_TYPE:
			type = *(optptr + 2);
			break;
		case DHCP_OPTION_SERVER_ID:
			memcpy(s->serverid, optptr + 2, 4);
			break;
		case DHCP_OPTION_LEASE_TIME:
			memcpy(s->lease_time, optptr + 2, 4);
			break;
		case DHCP_OPTION_END:
			return type;
		}

		optptr += optptr[1] + 2;
	}
	return type;
}

/*---------------------------------------------------------------------------*/
static u8_t parse_msg(struct dhcpc_state *s)
{
	struct dhcp_msg *m = (struct dhcp_msg *)s->ustack->uip_appdata;

	if (m->op == DHCP_REPLY &&
	    memcmp(m->xid, xid, sizeof(xid)) == 0 &&
	    memcmp(m->chaddr, s->mac_addr, s->mac_len) == 0) {
		memcpy(s->ipaddr, m->yiaddr, 4);
		return parse_options(s, &m->options[4], uip_datalen(s->ustack));
	}
	return 0;
}

/*---------------------------------------------------------------------------*/
static PT_THREAD(handle_dhcp(struct uip_stack *ustack))
{
	struct dhcpc_state *s;
	s = ustack->dhcpc;

	if (s == NULL) {
		LOG_WARN("Could not find dhcpc state");
		return PT_ENDED;
	}

	PT_BEGIN(&s->pt);

	/* try_again: */
	s->state = STATE_SENDING;
	s->ticks = CLOCK_SECOND;

	do {
		send_discover(s);
		timer_set(&s->timer, s->ticks);
		PT_WAIT_UNTIL(&s->pt, uip_newdata(s->ustack)
			      || timer_expired(&s->timer));

		if (uip_newdata(s->ustack) && parse_msg(s) == DHCPOFFER) {
			s->state = STATE_OFFER_RECEIVED;
			break;
		}

		if (s->ticks < CLOCK_SECOND * 60)
			s->ticks += CLOCK_SECOND;
		else
			PT_RESTART(&s->pt);
	} while (s->state != STATE_OFFER_RECEIVED);

	s->ticks = CLOCK_SECOND;

	do {
		send_request(s);
		timer_set(&s->timer, s->ticks);
		s->ustack->uip_flags &= ~UIP_NEWDATA;
		PT_WAIT_UNTIL(&s->pt, uip_newdata(s->ustack)
			      || timer_expired(&s->timer));

		if (uip_newdata(s->ustack) && parse_msg(s) == DHCPACK) {
			s->state = STATE_CONFIG_RECEIVED;
			break;
		}

		if (s->ticks <= CLOCK_SECOND * 10)
			s->ticks += CLOCK_SECOND;
		else
			PT_RESTART(&s->pt);
	} while (s->state != STATE_CONFIG_RECEIVED);

	LOG_INFO("Got IP address %d.%d.%d.%d",
		 uip_ipaddr1(s->ipaddr), uip_ipaddr2(s->ipaddr),
		 uip_ipaddr3(s->ipaddr), uip_ipaddr4(s->ipaddr));
	LOG_INFO("Got netmask %d.%d.%d.%d",
		 uip_ipaddr1(s->netmask), uip_ipaddr2(s->netmask),
		 uip_ipaddr3(s->netmask), uip_ipaddr4(s->netmask));
	LOG_INFO("Got DNS server %d.%d.%d.%d",
		 uip_ipaddr1(s->dnsaddr), uip_ipaddr2(s->dnsaddr),
		 uip_ipaddr3(s->dnsaddr), uip_ipaddr4(s->dnsaddr));
	LOG_INFO("Got default router %d.%d.%d.%d",
		 uip_ipaddr1(s->default_router), uip_ipaddr2(s->default_router),
		 uip_ipaddr3(s->default_router),
		 uip_ipaddr4(s->default_router));
	s->lease_time_nl32 =
	    ntohs(s->lease_time[0]) * 65536ul + ntohs(s->lease_time[1]);
	LOG_INFO("Lease expires in %ld seconds", s->lease_time_nl32);

	s->last_update = time(NULL);

	set_uip_stack(s->ustack,
		      (uip_ip4addr_t *) s->ipaddr,
		      (uip_ip4addr_t *) s->netmask,
		      (uip_ip4addr_t *) s->default_router,
		      (uint8_t *) s->mac_addr);

	/*  Put the stack thread back into a long sleep */
	s->nic->flags |= NIC_LONG_SLEEP;

	/*  timer_stop(&s.timer); */

	/* Handle DHCP lease expiration */
	s->ticks = CLOCK_SECOND * s->lease_time_nl32;
	timer_set(&s->timer, s->ticks);
	PT_WAIT_UNTIL(&s->pt, timer_expired(&s->timer));
	LOG_INFO("Lease expired, re-acquire IP address");
	s->nic->flags &= ~NIC_LONG_SLEEP;
	PT_RESTART(&s->pt);

	/*
	 * PT_END restarts the thread so we do this instead. Eventually we
	 * should reacquire expired leases here.
	 */

	while (1)
		PT_YIELD(&s->pt);

	PT_END(&(s->pt));
}

/*---------------------------------------------------------------------------*/
int dhcpc_init(nic_t *nic, struct uip_stack *ustack,
	       const void *mac_addr, int mac_len)
{
	uip_ip4addr_t addr;
	struct dhcpc_state *s = ustack->dhcpc;

	if (s) {
		LOG_DEBUG("DHCP: DHCP context already allocated");
		return -EALREADY;
	}
	s = malloc(sizeof(*s));
	if (s == NULL) {
		LOG_ERR("Couldn't allocate size for dhcpc info");
		return -ENOMEM;
	}

	memset(s, 0, sizeof(*s));
	s->nic = nic;
	s->ustack = ustack;
	s->mac_addr = mac_addr;
	s->mac_len = mac_len;
	s->state = STATE_INITIAL;

	/*  Initialize XID to randomly */
	if (dhcpc_opt.enable_random_xid == 1) {
		u32_t gen_xid;
		gen_xid = random();
		memcpy(xid, &gen_xid, sizeof(gen_xid));
	}
	uip_ipaddr(addr, 255, 255, 255, 255);
	s->conn = uip_udp_new(ustack, &addr, const_htons(DHCPC_SERVER_PORT));
	if (s->conn != NULL)
		uip_udp_bind(s->conn, const_htons(DHCPC_CLIENT_PORT));

	ustack->dhcpc = s;

	/* Let the RX poll value take over */
	nic->flags &= ~NIC_LONG_SLEEP;

	PT_INIT(&s->pt);

	return 0;
}

/*---------------------------------------------------------------------------*/
void dhcpc_appcall(struct uip_stack *ustack)
{
	handle_dhcp(ustack);
}

/*---------------------------------------------------------------------------*/
void dhcpc_request(struct uip_stack *ustack)
{
	struct dhcpc_state *s = ustack->dhcpc;

	if (s != NULL && s->state == STATE_INITIAL)
		handle_dhcp(ustack);
}

/*---------------------------------------------------------------------------*/
