/*
 * Copyright (c) 2011, Broadcom Corporation
 * Copyright (c) 2014, QLogic Corporation
 *
 * Written by:  Eddie Wai  (eddie.wai@broadcom.com)
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
 * ipv6_ndpc.h - Top level IPv6 Network Discovery Protocol Engine (RFC4861)
 *
 */
#ifndef __NDPC_H__
#define __NDPC_H__

#include <time.h>

#include "nic.h"
#include "timer.h"
#include "pt.h"

struct ndpc_reqptr {
	void *eth;
	void *ipv6;
};

struct ndpc_state {
	struct pt pt;

	nic_t *nic;
	struct uip_stack *ustack;
	char state;
	struct timer timer;
	u16_t ticks;
	void *mac_addr;
	int mac_len;
	int retry_count;

	time_t last_update;

	void *ipv6_context;
	void *dhcpv6_context;
};

enum {
	NDPC_STATE_INIT,
	NDPC_STATE_RTR_SOL,
	NDPC_STATE_RTR_ADV,
	NDPC_STATE_DHCPV6_DIS,
	NDPC_STATE_DHCPV6_DONE,
	NDPC_STATE_BACKGROUND_LOOP
};

int ndpc_init(nic_t *nic, struct uip_stack *ustack,
	      const void *mac_addr, int mac_len);
void ndpc_call(struct uip_stack *ustack);
void ndpc_exit(struct ndpc_state *ndp);

enum {
	NEIGHBOR_SOLICIT,
	CHECK_LINK_LOCAL_ADDR,
	GET_LINK_LOCAL_ADDR,
	GET_DEFAULT_ROUTER_ADDR,
	CHECK_ARP_TABLE,
	GET_HOST_ADDR
};

int ndpc_request(struct uip_stack *ustack, void *in, void *out, int request);

#define UIP_NDP_CALL ndpc_call

#endif /* __NDPC_H__ */
