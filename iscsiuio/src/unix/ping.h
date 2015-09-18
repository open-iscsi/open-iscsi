/*
 * Copyright (c) 2015, QLogic Corporation
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
 * ping.h - PING header file
 *
 */

#ifndef __PING_H__
#define __PING_H__

#include "nic_nl.h"
#include "uip.h"

#define ICMP_ECHO_REPLY 0
#define ICMP_ECHO       8

#define ICMPV6_ECHO_REQ		128
#define ICMPV6_ECHO_REPLY	129

#define DEF_ICMP_PAYLOAD	32
#define DEF_ICMPV6_PAYLOAD	16

#define PING_INIT_STATE (-1)

struct ping_conf
{
	nic_t *nic;
	nic_interface_t *nic_iface;
	void *data;
	int state;
	void *dst_addr;
	u16_t proto;
	u16_t id;
	u16_t seqno;
	u16_t datalen;
};

void ping_init(struct ping_conf *png_c, void *addr, u16_t type, int datalen);

int do_ping_from_nic_iface(struct ping_conf *png_c);

int process_icmp_packet(uip_icmp_echo_hdr_t *icmp_hdr,
			struct uip_stack *ustack);

#endif /* __PING_H__ */
