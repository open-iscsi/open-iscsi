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
 * ping.c - Ping implementation for iscsiuio using ICMP/ICMPv6
 *
 */
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "iscsi_if.h"

#include "uip.h"
#include "uip_arp.h"
#include "uip_eth.h"
#include "dhcpc.h"
#include "ipv6_ndpc.h"
#include "ipv6.h"

#include "logger.h"
#include "nic.h"
#include "nic_utils.h"
#include "options.h"
#include "packet.h"
#include "bnx2.h"
#include "bnx2x.h"
#include "cnic.h"
#include "ping.h"

#define PFX "ping "

static void fill_payload_data(struct uip_stack *ustack)
{
	if (ustack->uip_slen)
		memset(ustack->uip_appdata, 'A', ustack->uip_slen);
}

static int prepare_icmpv4_req_pkt(struct ping_conf *png_c, struct packet *pkt,
				  uip_ip4addr_t *dst_addr)
{
	nic_interface_t *nic_iface = png_c->nic_iface;
	struct uip_stack *ustack = &nic_iface->ustack;
	struct uip_ipv4_hdr *ipv4_hdr = NULL;
	struct uip_icmpv4_hdr *icmpv4_hdr = NULL;
	u16_t uip_iph_len = 0;
	u16_t icmpv4_hdr_len = 0;
	u16_t uip_ip_icmph_len = 0;
	int mtu = 1500;
	int rc = 0;

	uip_iph_len = UIP_IPv4_H_LEN;
	icmpv4_hdr_len = sizeof(*icmpv4_hdr);
	uip_ip_icmph_len = uip_iph_len + icmpv4_hdr_len;

	ipv4_hdr = (struct uip_ipv4_hdr *)ustack->network_layer;

	icmpv4_hdr = (struct uip_icmpv4_hdr *) (ustack->network_layer +
						sizeof(struct uip_ipv4_hdr));

	/* fill IP header */
	ipv4_hdr->vhl = 0x45;
	ipv4_hdr->tos = 0;
	++ustack->ipid;
	ipv4_hdr->ipid[0] = ustack->ipid >> 8;
	ipv4_hdr->ipid[1] = ustack->ipid & 0xff;
	ipv4_hdr->ipoffset[0] = 0;
	ipv4_hdr->ipoffset[1] = 0;
	ipv4_hdr->ttl = UIP_TTL;
	ipv4_hdr->proto = UIP_PROTO_ICMP;
	uip_ip4addr_copy(ipv4_hdr->srcipaddr, ustack->hostaddr);
	uip_ip4addr_copy(ipv4_hdr->destipaddr, dst_addr);

	LOG_INFO(PFX "src ipaddr: %d.%d.%d.%d",
		 uip_ipaddr1(ipv4_hdr->srcipaddr),
		 uip_ipaddr2(ipv4_hdr->srcipaddr),
		 uip_ipaddr3(ipv4_hdr->srcipaddr),
		 uip_ipaddr4(ipv4_hdr->srcipaddr));

	LOG_INFO(PFX "dest ipaddr: %d.%d.%d.%d",
		 uip_ipaddr1(ipv4_hdr->destipaddr),
		 uip_ipaddr2(ipv4_hdr->destipaddr),
		 uip_ipaddr3(ipv4_hdr->destipaddr),
		 uip_ipaddr4(ipv4_hdr->destipaddr));

	/* fill ICMP header */
	icmpv4_hdr->type = ICMP_ECHO;
	icmpv4_hdr->icode = 0;
	icmpv4_hdr->id = getpid() & 0xffff;
	png_c->id = icmpv4_hdr->id;
	icmpv4_hdr->seqno = ustack->ipid;
	png_c->seqno =icmpv4_hdr->seqno;

	/* appdata and sappdata point to the icmp payload */
	ustack->uip_appdata = ustack->network_layer + uip_ip_icmph_len;
	ustack->uip_sappdata = ustack->uip_appdata;

	if (nic_iface->mtu)
		mtu = nic_iface->mtu;

	if ((mtu - uip_ip_icmph_len) > png_c->datalen) {
		ustack->uip_slen = png_c->datalen;
	} else {
		png_c->state = ISCSI_PING_OVERSIZE_PACKET;
		LOG_ERR(PFX "MTU=%d, payload=%d\n",
			mtu, png_c->datalen);
		rc = -EINVAL;
		goto done;
	}

	fill_payload_data(ustack);

	/* Calculate ICMP checksum. */
	icmpv4_hdr->icmpchksum = 0;
	icmpv4_hdr->icmpchksum = ~(uip_chksum((u16_t *)icmpv4_hdr,
					      icmpv4_hdr_len +
					      ustack->uip_slen));
	if (icmpv4_hdr->icmpchksum == 0)
		icmpv4_hdr->icmpchksum = 0xffff;

	/* IPv4 total length = IPv4 HLEN + ICMP HLEN + Payload len */
	ustack->uip_len = uip_ip_icmph_len + ustack->uip_slen;
	ipv4_hdr->len[0] = (ustack->uip_len >> 8);
	ipv4_hdr->len[1] = (ustack->uip_len & 0xff);

	/* Calculate IP checksum. */
	ipv4_hdr->ipchksum = 0;
	ipv4_hdr->ipchksum = ~(uip_ipchksum(ustack));
	if (ipv4_hdr->ipchksum == 0)
		ipv4_hdr->ipchksum = 0xffff;

        ++ustack->stats.ip.sent;
        /* Return and let the caller do the actual transmission. */
        ustack->uip_flags = 0;

done:
	return rc;
}

static void prepare_icmpv6_req_pkt(struct ping_conf *png_c, struct packet *pkt,
				   uip_ip6addr_t *dst_addr,
				   uip_ip6addr_t *src_addr)
{
	nic_interface_t *nic_iface = png_c->nic_iface;
	struct uip_stack *ustack = &nic_iface->ustack;
	struct uip_ipv6_hdr *ipv6_hdr = NULL;
	uip_icmp_echo_hdr_t *icmp_echo_hdr = NULL;
	u16_t uip_iph_len = 0;
	u16_t icmp_echo_hdr_len = 0;
	u16_t uip_ip_icmph_len = 0;
	char ipbuf[INET6_ADDRSTRLEN] = {0};

	uip_iph_len = UIP_IPv6_H_LEN;
	icmp_echo_hdr_len = sizeof(*icmp_echo_hdr);
	uip_ip_icmph_len = uip_iph_len + icmp_echo_hdr_len;

	ipv6_hdr = (struct uip_ipv6_hdr *)ustack->network_layer;

	icmp_echo_hdr = (uip_icmp_echo_hdr_t *) (ustack->network_layer +
						 sizeof(struct uip_ipv6_hdr));

	/* fill IPv6 header */
	ipv6_hdr->vtc = 0x60;
	ipv6_hdr->tcflow = 0;
	ipv6_hdr->flow = 0;
	ipv6_hdr->proto = UIP_PROTO_ICMP6;
	ipv6_hdr->ttl = UIP_TTL;
	uip_ip6addr_copy(ipv6_hdr->srcipaddr, src_addr);
	uip_ip6addr_copy(ipv6_hdr->destipaddr, dst_addr);

	memset(ipbuf, 0, sizeof(ipbuf));
	if (inet_ntop(AF_INET6, &ipv6_hdr->srcipaddr, ipbuf, INET6_ADDRSTRLEN))
		LOG_INFO(PFX "src ipaddr=%s", ipbuf);

	memset(ipbuf, 0, sizeof(ipbuf));
	if (inet_ntop(AF_INET6, &ipv6_hdr->destipaddr, ipbuf, INET6_ADDRSTRLEN))
		LOG_INFO(PFX "dest ipaddr=%s", ipbuf);

	/* fill ICMP header */
	icmp_echo_hdr->type = ICMPV6_ECHO_REQ;
	icmp_echo_hdr->icode = 0;
	icmp_echo_hdr->id = HOST_TO_NET16(getpid() & 0xffff);
	png_c->id = icmp_echo_hdr->id;
	++ustack->ipid;
	icmp_echo_hdr->seqno = HOST_TO_NET16(ustack->ipid);
	png_c->seqno = icmp_echo_hdr->seqno;

	/* appdata and sappdata point to the icmp payload */
	ustack->uip_appdata = ustack->network_layer + uip_ip_icmph_len;
	ustack->uip_sappdata = ustack->uip_appdata;
	ustack->uip_slen = png_c->datalen;

	fill_payload_data(ustack);

	/* Total length = ETH HLEN + IPv6 HLEN + ICMP HLEN + Data len */
	ustack->uip_len =  UIP_LLH_LEN + uip_ip_icmph_len + ustack->uip_slen;
	/* IPv6 payload len */
	ipv6_hdr->len = HOST_TO_NET16(icmp_echo_hdr_len + ustack->uip_slen);

	/* Calculate ICMP checksum. */
	icmp_echo_hdr->icmpchksum = 0;
	icmp_echo_hdr->icmpchksum = ~(uip_icmp6chksum(ustack));

        ++ustack->stats.ip.sent;
        /* Return and let the caller do the actual transmission. */
        ustack->uip_flags = 0;
	return;
}

static int chk_arp_entry_for_dst_addr(nic_t *nic, nic_interface_t *nic_iface,
				      void *addr)
{
	struct iscsi_path path;
	uip_ip4addr_t dst_addr4;
	uip_ip6addr_t dst_addr6;

	if (nic_iface->protocol == AF_INET) {
		memcpy(dst_addr4, addr, sizeof(uip_ip4addr_t));
		memcpy(&path.dst.v4_addr, dst_addr4, sizeof(struct in_addr));
		path.ip_addr_len = 4;
	} else {
		memcpy(dst_addr6, addr, sizeof(uip_ip6addr_t));
		memcpy(&path.dst.v6_addr, dst_addr6, sizeof(struct in6_addr));
		path.ip_addr_len = 16;
	}

	return cnic_handle_iscsi_path_req(nic, 0, NULL, &path, nic_iface);
}

static int fill_icmpv6_eth_hdr(struct uip_stack *ustack,
				uip_ip6addr_t *dst_addr6)
{
	struct uip_eth_hdr *eth;
	__u8 mac_addr[6];
	struct ndpc_reqptr req_ptr;
	int rc = 0;
	int ret = 0;

	eth = (struct uip_eth_hdr *)ustack->data_link_layer;
	memcpy(eth->src.addr, ustack->uip_ethaddr.addr, sizeof(eth->src.addr));

	memset(mac_addr, 0, sizeof(mac_addr));
	req_ptr.eth = (void *)mac_addr;
	req_ptr.ipv6 = (void *)dst_addr6;

	ret = ndpc_request(ustack, &req_ptr, &rc, CHECK_ARP_TABLE);
	if (ret) {
		LOG_DEBUG(PFX "ndpc request failed");
		rc = ret;
	} else if (rc) {
		memcpy(eth->dest.addr, mac_addr, sizeof(eth->dest.addr));
		LOG_DEBUG(PFX "ipv6 arp entry present");
		rc = 0;
	} else {
		LOG_DEBUG(PFX "ipv6 arp entry not present");
		rc = -EAGAIN;
	}

	return rc;
}

static int determine_src_ipv6_addr(nic_interface_t *nic_iface,
				   uip_ip6addr_t *dst_addr6,
				   uip_ip6addr_t *src_addr6)
{
	struct in6_addr *addr;
	int rc = 0;
	int ret = 0;

	if (nic_iface->ustack.ip_config == IPV6_CONFIG_STATIC) {
		memcpy(src_addr6, &nic_iface->ustack.hostaddr6,
		       sizeof(uip_ip6addr_t));
		goto done;
	}

	ret = ndpc_request(&nic_iface->ustack, dst_addr6,
			 &rc, CHECK_LINK_LOCAL_ADDR);
	if (ret) {
		LOG_DEBUG(PFX "Check LL failed");
		rc = ret;
		goto done;
	}

	if (rc) {
		LOG_DEBUG(PFX "Use LL");
		/* Get link local IPv6 address */
		addr = (struct in6_addr *)&nic_iface->ustack.linklocal6;
		rc = 0;
	} else {
		LOG_DEBUG(PFX "Use Best matched");
		ret = ndpc_request(&nic_iface->ustack,
				 dst_addr6,
				 &addr, GET_HOST_ADDR);
		if (ret) {
			LOG_DEBUG(PFX "Use Best matched failed");
			rc = ret;
			goto done;
		}
		if (addr == NULL) {
			LOG_DEBUG(PFX "No Best matched found");
			rc = -EINVAL;
			goto done;
		}
	}

	/* Got the best matched src IP address */
	memcpy(src_addr6, addr, sizeof(struct in6_addr));

done:
	return rc;
}

void ping_init(struct ping_conf *png_c, void *addr, u16_t type, int datalen)
{
	png_c->dst_addr = addr;
	png_c->proto = type;
	png_c->state = PING_INIT_STATE;
	png_c->datalen = datalen;
	return;
}

int do_ping_from_nic_iface(struct ping_conf *png_c)
{
	packet_t *pkt;
	nic_interface_t *nic_iface = png_c->nic_iface;
	nic_t *nic = nic_iface->parent;
	struct uip_stack *ustack = &nic_iface->ustack;
	uip_ip4addr_t dst_addr4;
	uip_ip6addr_t dst_addr6;
	uip_ip6addr_t src_addr6;
	struct timer ping_timer;
	int rc = 0;

	memset(dst_addr4, 0, sizeof(uip_ip4addr_t));
	memset(dst_addr6, 0, sizeof(uip_ip6addr_t));
	memset(src_addr6, 0, sizeof(uip_ip6addr_t));

	if (nic_iface->protocol == AF_INET)
		memcpy(dst_addr4, png_c->dst_addr, sizeof(uip_ip4addr_t));
	else
		memcpy(dst_addr6, png_c->dst_addr, sizeof(uip_ip6addr_t));

	rc = chk_arp_entry_for_dst_addr(nic, nic_iface, png_c->dst_addr);

	if (rc && (nic_iface->protocol == AF_INET)) {
		png_c->state = ISCSI_PING_NO_ARP_RECEIVED;
		LOG_ERR(PFX "ARP failure for IPv4 dest addr");
		goto done;
	} else if ((rc < 1) && (nic_iface->protocol == AF_INET6)) {
		png_c->state = ISCSI_PING_NO_ARP_RECEIVED;
		LOG_ERR(PFX "ARP failure for IPv6 dest addr");
		goto done;
	} else if (rc < 0) {
		LOG_ERR(PFX "ARP failure");
		goto done;
	}

	pthread_mutex_lock(&nic->nic_mutex);
	pkt = get_next_free_packet(nic);
	if (pkt == NULL) {
		pthread_mutex_unlock(&nic->nic_mutex);
		LOG_ERR(PFX "Unable to get a free packet buffer");
		rc = -EIO;
		goto done;
	}

	prepare_ustack(nic, nic_iface, ustack, pkt);

	if (nic_iface->protocol == AF_INET) {
		rc = prepare_icmpv4_req_pkt(png_c, pkt, &dst_addr4);
		if (rc)
			goto put_pkt;

		/* If the above function invocation resulted
		 * in data that should be sent out on the
		 * network, the global variable uip_len is
		 * set to a value > 0. */
		if (ustack->uip_len > 0) {
			pkt->buf_size = ustack->uip_len;

			prepare_ipv4_packet(nic, nic_iface, ustack, pkt);

			LOG_DEBUG(PFX "Send ICMP echo request");
			(*nic->ops->write) (nic, nic_iface, pkt);
			ustack->uip_len = 0;
		}
	} else {
		rc = determine_src_ipv6_addr(nic_iface, &dst_addr6, &src_addr6);
		if (rc)
			goto put_pkt;

		prepare_icmpv6_req_pkt(png_c, pkt, &dst_addr6, &src_addr6);

		/* If the above function invocation resulted
		 * in data that should be sent out on the
		 * network, the global variable uip_len is
		 * set to a value > 0. */
		if (ustack->uip_len > 0) {
			pkt->buf_size = ustack->uip_len;

			prepare_ipv6_packet(nic, nic_iface, ustack, pkt);
			rc = fill_icmpv6_eth_hdr(ustack, &dst_addr6);
			if (rc) {
				ustack->uip_len = 0;
				goto put_pkt;
			}

			LOG_DEBUG(PFX "Send ICMPv6 echo request");
			(*nic->ops->write) (nic, nic_iface, pkt);
			ustack->uip_len = 0;
		}
	}

put_pkt:
	put_packet_in_free_queue(pkt, nic);
	pthread_mutex_unlock(&nic->nic_mutex);

	if (rc) {
		LOG_DEBUG(PFX "Ping request not transmitted");
		goto done;
	}

	timer_set(&ping_timer, CLOCK_SECOND * 10);

	while ((event_loop_stop == 0) &&
	       (nic->flags & NIC_ENABLED) && !(nic->flags & NIC_GOING_DOWN)) {

		rc = nic_process_intr(nic, 1);

		while ((rc > 0) && (!(nic->flags & NIC_GOING_DOWN))) {
			rc = process_packets(nic, NULL, NULL, nic_iface);
		}

		if (!rc && (png_c->state == ISCSI_PING_SUCCESS)) {
			LOG_INFO(PFX "PING successful!");
			break;
		}

		if (timer_expired(&ping_timer)) {
			png_c->state = ISCSI_PING_TIMEOUT;
			LOG_ERR(PFX "PING timeout");
			rc = -EIO;
			break;
		}
	}

done:
	return rc;
}

int process_icmp_packet(uip_icmp_echo_hdr_t *icmp_hdr,
			struct uip_stack *ustack)
{
	struct ping_conf *png_c = (struct ping_conf *)ustack->ping_conf;
	int rc = 0;

	LOG_INFO(PFX "Verify ICMP echo reply");

	if ((icmp_hdr->type == ICMPV6_ECHO_REPLY &&
	     png_c->proto == AF_INET6) ||
	     (icmp_hdr->type == ICMP_ECHO_REPLY &&
	      png_c->proto == AF_INET)) {

		if ((icmp_hdr->icode == 0) &&
		    (icmp_hdr->id == png_c->id) &&
		    (icmp_hdr->seqno == png_c->seqno)) {
				png_c->state = ISCSI_PING_SUCCESS;
		} else {
			rc = 1;
		}
	} else {
		rc = 1;
	}

	if (rc) {
		LOG_INFO(PFX "ICMP echo reply verification failed!");
	} else {
		LOG_INFO(PFX "ICMP echo reply OK");
	}

	return rc;
}
