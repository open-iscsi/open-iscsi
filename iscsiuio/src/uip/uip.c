#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include "uip.h"
#include "dhcpc.h"
#include "ipv6_ndpc.h"
#include "brcm_iscsi.h"
#include "ping.h"

/**
 * \defgroup uip The uIP TCP/IP stack
 * @{
 *
 * uIP is an implementation of the TCP/IP protocol stack intended for
 * small 8-bit and 16-bit microcontrollers.
 *
 * uIP provides the necessary protocols for Internet communication,
 * with a very small code footprint and RAM requirements - the uIP
 * code size is on the order of a few kilobytes and RAM usage is on
 * the order of a few hundred bytes.
 */

/**
 * \file
 * The uIP TCP/IP stack code.
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

/*
 * uIP is a small implementation of the IP, UDP and TCP protocols (as
 * well as some basic ICMP stuff). The implementation couples the IP,
 * UDP, TCP and the application layers very tightly. To keep the size
 * of the compiled code down, this code frequently uses the goto
 * statement. While it would be possible to break the uip_process()
 * function into many smaller functions, this would increase the code
 * size because of the overhead of parameter passing and the fact that
 * the optimier would not be as efficient.
 *
 * The principle is that we have a small buffer, called the uip_buf,
 * in which the device driver puts an incoming packet. The TCP/IP
 * stack parses the headers in the packet, and calls the
 * application. If the remote host has sent data to the application,
 * this data is present in the uip_buf and the application read the
 * data from there. It is up to the application to put this data into
 * a byte stream if needed. The application will not be fed with data
 * that is out of sequence.
 *
 * If the application whishes to send data to the peer, it should put
 * its data into the uip_buf. The uip_appdata pointer points to the
 * first available byte. The TCP/IP stack will calculate the
 * checksums, and fill in the necessary header fields and finally send
 * the packet back to the peer.
*/

#include "logger.h"

#include "uip.h"
#include "uipopt.h"
#include "uip_arch.h"
#include "uip_eth.h"
#include "uip-neighbor.h"

#include <string.h>

/*******************************************************************************
 * Constants
 ******************************************************************************/
#define PFX "uip "

static const uip_ip4addr_t all_ones_addr4 = { 0xffff, 0xffff };

const uip_ip6addr_t all_zeroes_addr6 = {
	0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000
};
const uip_ip4addr_t all_zeroes_addr4 = { 0x0000, 0x0000 };

const uint8_t mutlicast_ipv6_prefix[16] = {
	0xfc, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

const uint8_t link_local_addres_prefix[16] = {
	0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
const uint32_t link_local_address_prefix_length = 10;

/* Structures and definitions. */
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
#define TCP_CTL 0x3f

#define TCP_OPT_END     0	/* End of TCP options list */
#define TCP_OPT_NOOP    1	/* "No-operation" TCP option */
#define TCP_OPT_MSS     2	/* Maximum segment size TCP option */

#define TCP_OPT_MSS_LEN 4	/* Length of TCP MSS option. */

#define ICMP_ECHO_REPLY 0
#define ICMP_ECHO       8

#define ICMP6_ECHO_REPLY             129
#define ICMP6_ECHO                   128
#define ICMP6_NEIGHBOR_SOLICITATION  135
#define ICMP6_NEIGHBOR_ADVERTISEMENT 136

#define ICMP6_FLAG_S (1 << 6)

#define ICMP6_OPTION_SOURCE_LINK_ADDRESS 1
#define ICMP6_OPTION_TARGET_LINK_ADDRESS 2

/* Macros. */
#define FBUF ((struct uip_tcpip_hdr *)&uip_reassbuf[0])
#define UDPBUF(ustack) ((struct uip_udpip_hdr *)ustack->network_layer)

/******************************************************************************
 * Utility Functions
 *****************************************************************************/
static int is_ipv6(struct uip_stack *ustack)
{
	u16_t type;

	type = ETH_BUF(ustack->uip_buf)->type;
	type = ntohs(type);
	if (type == UIP_ETHTYPE_8021Q)
		type = ntohs(VLAN_ETH_BUF(ustack->uip_buf)->type);
	else
		type = ntohs(ETH_BUF(ustack->uip_buf)->type);

	return (type == UIP_ETHTYPE_IPv6);
}

int is_ipv6_link_local_address(uip_ip6addr_t *addr)
{
	u8_t *test_adddr = (u8_t *) addr;
	u8_t test_remainder;

	if (test_adddr[0] != link_local_addres_prefix[0])
		return 0;

	test_remainder = (test_adddr[1] & 0xC0) >> 6;
	if (test_remainder != 2)
		return 0;

	return 1;
}

void uip_sethostaddr4(struct uip_stack *ustack, uip_ip4addr_t *addr)
{
	pthread_mutex_lock(&ustack->lock);
	uip_ip4addr_copy(ustack->hostaddr, (addr));
	pthread_mutex_unlock(&ustack->lock);
}

void uip_setdraddr4(struct uip_stack *ustack, uip_ip4addr_t *addr)
{
	pthread_mutex_lock(&ustack->lock);
	uip_ip4addr_copy(ustack->default_route_addr, (addr));
	pthread_mutex_unlock(&ustack->lock);
}

void uip_setnetmask4(struct uip_stack *ustack, uip_ip4addr_t *addr)
{
	pthread_mutex_lock(&ustack->lock);
	uip_ip4addr_copy(ustack->netmask, (addr));
	pthread_mutex_unlock(&ustack->lock);
}

void uip_setethernetmac(struct uip_stack *ustack, uint8_t *mac)
{
	pthread_mutex_lock(&ustack->lock);
	memcpy(ustack->uip_ethaddr.addr, (mac), 6);
	pthread_mutex_unlock(&ustack->lock);
}

void set_uip_stack(struct uip_stack *ustack,
		   uip_ip4addr_t *ip,
		   uip_ip4addr_t *netmask,
		   uip_ip4addr_t *default_route, uint8_t *mac_addr)
{
	if (ip)
		uip_sethostaddr4(ustack, ip);
	if (netmask)
		uip_setnetmask4(ustack, netmask);
	if (default_route)
		uip_setdraddr4(ustack, default_route);
	if (mac_addr)
		uip_setethernetmac(ustack, mac_addr);
}

#if !UIP_ARCH_ADD32
void uip_add32(u8_t *op32, u16_t op16, u8_t *uip_acc32)
{
	uip_acc32[3] = op32[3] + (op16 & 0xff);
	uip_acc32[2] = op32[2] + (op16 >> 8);
	uip_acc32[1] = op32[1];
	uip_acc32[0] = op32[0];

	if (uip_acc32[2] < (op16 >> 8)) {
		++uip_acc32[1];
		if (uip_acc32[1] == 0)
			++uip_acc32[0];
	}

	if (uip_acc32[3] < (op16 & 0xff)) {
		++uip_acc32[2];
		if (uip_acc32[2] == 0) {
			++uip_acc32[1];
			if (uip_acc32[1] == 0)
				++uip_acc32[0];
		}
	}
}

#endif /* UIP_ARCH_ADD32 */

#if !UIP_ARCH_CHKSUM
/*---------------------------------------------------------------------------*/
static u16_t chksum(u16_t sum, const u8_t *data, u16_t len)
{
	u16_t t;
	const u8_t *dataptr;
	const u8_t *last_byte;

	dataptr = data;
	last_byte = data + len - 1;

	while (dataptr < last_byte) {	/* At least two more bytes */
		t = (dataptr[0] << 8) + dataptr[1];
		sum += t;
		if (sum < t)
			sum++;	/* carry */
		dataptr += 2;
	}

	if (dataptr == last_byte) {
		t = (dataptr[0] << 8) + 0;
		sum += t;
		if (sum < t)
			sum++;	/* carry */
	}

	/* Return sum in host byte order. */
	return sum;
}

/*---------------------------------------------------------------------------*/
u16_t uip_chksum(u16_t *data, u16_t len)
{
	return htons(chksum(0, (u8_t *)data, len));
}

/*---------------------------------------------------------------------------*/
#ifndef UIP_ARCH_IPCHKSUM
u16_t uip_ipchksum(struct uip_stack *ustack)
{
	u16_t sum;
	u16_t uip_iph_len;

	if (is_ipv6(ustack))
		uip_iph_len = UIP_IPv6_H_LEN;
	else
		uip_iph_len = UIP_IPv4_H_LEN;

	sum = chksum(0, ustack->network_layer, uip_iph_len);
	return (sum == 0) ? 0xffff : htons(sum);
}
#endif

/*---------------------------------------------------------------------------*/
static u16_t upper_layer_chksum_ipv4(struct uip_stack *ustack, u8_t proto)
{
	u16_t upper_layer_len;
	u16_t sum;
	struct uip_tcp_ipv4_hdr *tcp_ipv4_hdr = NULL;

	tcp_ipv4_hdr = (struct uip_tcp_ipv4_hdr *)ustack->network_layer;

	upper_layer_len = (((u16_t) (tcp_ipv4_hdr->len[0]) << 8) +
			   tcp_ipv4_hdr->len[1]);
	/* check for underflow from an invalid length field */
	if (upper_layer_len < UIP_IPv4_H_LEN) {
		/* return 0 as an invalid checksum */
		return 0;
	}
	upper_layer_len -= UIP_IPv4_H_LEN;

	/* First sum pseudoheader. */
	/* IP protocol and length fields. This addition cannot carry. */
	sum = upper_layer_len + proto;

	sum =
	    chksum(sum, (u8_t *)&tcp_ipv4_hdr->srcipaddr[0],
		   2 * sizeof(uip_ip4addr_t));
	/* Sum TCP header and data. */
	sum = chksum(sum, ustack->network_layer + UIP_IPv4_H_LEN,
		     upper_layer_len);

	return (sum == 0) ? 0xffff : htons(sum);
}

/*---------------------------------------------------------------------------*/
static uint16_t upper_layer_checksum_ipv6(uint8_t *data, uint8_t proto)
{
	uint16_t upper_layer_len;
	uint16_t sum;
	struct ip6_hdr *ipv6_hdr;
	uint8_t *upper_layer;
	uint32_t val;

	ipv6_hdr = (struct ip6_hdr *)data;

	upper_layer_len = ntohs(ipv6_hdr->ip6_plen);

	/* First sum pseudoheader. */
	sum = 0;
	sum = chksum(sum, (const u8_t *)ipv6_hdr->ip6_src.s6_addr,
		     sizeof(ipv6_hdr->ip6_src));
	sum = chksum(sum, (const u8_t *)ipv6_hdr->ip6_dst.s6_addr,
		     sizeof(ipv6_hdr->ip6_dst));

	val = htons(upper_layer_len);
	sum = chksum(sum, (u8_t *)&val, sizeof(val));

	val = htons(proto);
	sum = chksum(sum, (u8_t *)&val, sizeof(val));

	upper_layer = (uint8_t *)(ipv6_hdr + 1);
	sum = chksum(sum, upper_layer, upper_layer_len);

	return (sum == 0) ? 0xffff : htons(sum);
}

/*---------------------------------------------------------------------------*/

u16_t uip_icmp6chksum(struct uip_stack *ustack)
{
	uint8_t *data = ustack->network_layer;

	return upper_layer_checksum_ipv6(data, UIP_PROTO_ICMP6);
}

uint16_t icmpv6_checksum(uint8_t *data)
{
	return upper_layer_checksum_ipv6(data, IPPROTO_ICMPV6);
}

/*---------------------------------------------------------------------------*/
u16_t uip_tcpchksum(struct uip_stack *ustack)
{
	return upper_layer_chksum_ipv4(ustack, UIP_PROTO_TCP);
}

/*---------------------------------------------------------------------------*/
#if UIP_UDP_CHECKSUMS
static u16_t uip_udpchksum_ipv4(struct uip_stack *ustack)
{
	return upper_layer_chksum_ipv4(ustack, UIP_PROTO_UDP);
}

static u16_t uip_udpchksum_ipv6(struct uip_stack *ustack)
{
	uint8_t *data = ustack->network_layer;

	return upper_layer_checksum_ipv6(data, UIP_PROTO_UDP);
}

u16_t uip_udpchksum(struct uip_stack *ustack)
{
	if (is_ipv6(ustack))
		return uip_udpchksum_ipv6(ustack);
	else
		return uip_udpchksum_ipv4(ustack);
}
#endif /* UIP_UDP_CHECKSUMS */
#endif /* UIP_ARCH_CHKSUM */
/*---------------------------------------------------------------------------*/
void uip_init(struct uip_stack *ustack, uint8_t ipv6_enabled)
{
	u8_t c;

	for (c = 0; c < UIP_LISTENPORTS; ++c)
		ustack->uip_listenports[c] = 0;
	for (c = 0; c < UIP_CONNS; ++c)
		ustack->uip_conns[c].tcpstateflags = UIP_CLOSED;
#if UIP_ACTIVE_OPEN
	ustack->lastport = 1024;
#endif /* UIP_ACTIVE_OPEN */

#if UIP_UDP
	for (c = 0; c < UIP_UDP_CONNS; ++c)
		ustack->uip_udp_conns[c].lport = 0;
#endif /* UIP_UDP */

	/* IPv4 initialization. */
#if UIP_FIXEDADDR == 0
	/*  uip_hostaddr[0] = uip_hostaddr[1] = 0; */
#endif /* UIP_FIXEDADDR */

	/*  zero out the uIP statistics */
	memset(&ustack->stats, 0, sizeof(ustack->stats));

	/*  prepare the uIP lock */
	pthread_mutex_init(&ustack->lock, NULL);

	if (ipv6_enabled)
		ustack->enable_IPv6 = UIP_SUPPORT_IPv6_ENABLED;
	else
		ustack->enable_IPv6 = UIP_SUPPORT_IPv6_DISABLED;

	ustack->dhcpc = NULL;
	ustack->ndpc = NULL;
	ustack->ping_conf = NULL;
}
void uip_reset(struct uip_stack *ustack)
{
	/*  There was an associated DHCP object, this memory needs to be
	 *  freed */
	if (ustack->dhcpc)
		free(ustack->dhcpc);

	ndpc_exit(ustack->ndpc);

	memset(ustack, 0, sizeof(*ustack));
}

/*---------------------------------------------------------------------------*/
#if UIP_ACTIVE_OPEN
struct uip_conn *uip_connect(struct uip_stack *ustack, uip_ip4addr_t *ripaddr,
			     u16_t rport)
{
	u8_t c;
	register struct uip_conn *conn, *cconn;

	/* Find an unused local port. */
again:
	++ustack->lastport;

	if (ustack->lastport >= 32000)
		ustack->lastport = 4096;

	/* Check if this port is already in use, and if so try to find
	   another one. */
	for (c = 0; c < UIP_CONNS; ++c) {
		conn = &ustack->uip_conns[c];
		if (conn->tcpstateflags != UIP_CLOSED &&
		    conn->lport == htons(ustack->lastport)) {
			goto again;
		}
	}

	conn = 0;
	for (c = 0; c < UIP_CONNS; ++c) {
		cconn = &ustack->uip_conns[c];
		if (cconn->tcpstateflags == UIP_CLOSED) {
			conn = cconn;
			break;
		}
		if (cconn->tcpstateflags == UIP_TIME_WAIT) {
			if (conn == 0 || cconn->timer > conn->timer)
				conn = cconn;
		}
	}

	if (conn == 0)
		return 0;

	conn->tcpstateflags = UIP_SYN_SENT;

	conn->snd_nxt[0] = ustack->iss[0];
	conn->snd_nxt[1] = ustack->iss[1];
	conn->snd_nxt[2] = ustack->iss[2];
	conn->snd_nxt[3] = ustack->iss[3];

	conn->initialmss = conn->mss = UIP_TCP_MSS;

	conn->len = 1;		/* TCP length of the SYN is one. */
	conn->nrtx = 0;
	conn->timer = 1;	/* Send the SYN next time around. */
	conn->rto = UIP_RTO;
	conn->sa = 0;
	conn->sv = 16;		/* Initial value of the RTT variance. */
	conn->lport = htons(ustack->lastport);
	conn->rport = rport;
	uip_ip4addr_copy(&conn->ripaddr, ripaddr);

	return conn;
}
#endif /* UIP_ACTIVE_OPEN */
/*---------------------------------------------------------------------------*/
#if UIP_UDP
struct uip_udp_conn *uip_udp_new(struct uip_stack *ustack,
				 uip_ip4addr_t *ripaddr, u16_t rport)
{
	u8_t c;
	register struct uip_udp_conn *conn;

	/* Find an unused local port. */
again:
	++ustack->lastport;

	if (ustack->lastport >= 32000)
		ustack->lastport = 4096;

	for (c = 0; c < UIP_UDP_CONNS; ++c) {
		if (ustack->uip_udp_conns[c].lport == htons(ustack->lastport))
			goto again;
	}

	conn = 0;
	for (c = 0; c < UIP_UDP_CONNS; ++c) {
		if (ustack->uip_udp_conns[c].lport == 0) {
			conn = &ustack->uip_udp_conns[c];
			break;
		}
	}

	if (conn == 0)
		return 0;

	conn->lport = htons(ustack->lastport);
	conn->rport = rport;
	if (ripaddr == NULL)
		memset(conn->ripaddr, 0, sizeof(uip_ip4addr_t));
	else
		uip_ip4addr_copy(&conn->ripaddr, ripaddr);
	conn->ttl = UIP_TTL;

	return conn;
}
#endif /* UIP_UDP */
/*---------------------------------------------------------------------------*/
void uip_unlisten(struct uip_stack *ustack, u16_t port)
{
	u8_t c;

	for (c = 0; c < UIP_LISTENPORTS; ++c) {
		if (ustack->uip_listenports[c] == port) {
			ustack->uip_listenports[c] = 0;
			return;
		}
	}
}

/*---------------------------------------------------------------------------*/
void uip_listen(struct uip_stack *ustack, u16_t port)
{
	u8_t c;

	for (c = 0; c < UIP_LISTENPORTS; ++c) {
		if (ustack->uip_listenports[c] == 0) {
			ustack->uip_listenports[c] = port;
			return;
		}
	}
}

/**
 * Is new incoming data available?
 *
 * Will reduce to non-zero if there is new data for the application
 * present at the uip_appdata pointer. The size of the data is
 * avaliable through the uip_len variable.
 *
 * \hideinitializer
 */
int uip_newdata(struct uip_stack *ustack)
{
	return ustack->uip_flags & UIP_NEWDATA;
}

/**
 * Has previously sent data been acknowledged?
 *
 * Will reduce to non-zero if the previously sent data has been
 * acknowledged by the remote host. This means that the application
 * can send new data.
 *
 * \hideinitializer
 */
#define uip_acked()   (uip_flags & UIP_ACKDATA)

/**
 * Has the connection just been connected?
 *
 * Reduces to non-zero if the current connection has been connected to
 * a remote host. This will happen both if the connection has been
 * actively opened (with uip_connect()) or passively opened (with
 * uip_listen()).
 *
 * \hideinitializer
 */
int uip_connected(struct uip_stack *ustack)
{
	return ustack->uip_flags & UIP_CONNECTED;
}

/**
 * Has the connection been closed by the other end?
 *
 * Is non-zero if the connection has been closed by the remote
 * host. The application may then do the necessary clean-ups.
 *
 * \hideinitializer
 */
int uip_closed(struct uip_stack *ustack)
{
	return ustack->uip_flags & UIP_CLOSE;
}

/**
 * Has the connection been aborted by the other end?
 *
 * Non-zero if the current connection has been aborted (reset) by the
 * remote host.
 *
 * \hideinitializer
 */
int uip_aborted(struct uip_stack *ustack)
{
	return ustack->uip_flags & UIP_ABORT;
}

/**
 * Has the connection timed out?
 *
 * Non-zero if the current connection has been aborted due to too many
 * retransmissions.
 *
 * \hideinitializer
 */
int uip_timedout(struct uip_stack *ustack)
{
	return ustack->uip_flags & UIP_TIMEDOUT;
}

/**
 * Do we need to retransmit previously data?
 *
 * Reduces to non-zero if the previously sent data has been lost in
 * the network, and the application should retransmit it. The
 * application should send the exact same data as it did the last
 * time, using the uip_send() function.
 *
 * \hideinitializer
 */
int uip_rexmit(struct uip_stack *ustack)
{
	return ustack->uip_flags & UIP_REXMIT;
}

/**
 * Is the connection being polled by uIP?
 *
 * Is non-zero if the reason the application is invoked is that the
 * current connection has been idle for a while and should be
 * polled.
 *
 * The polling event can be used for sending data without having to
 * wait for the remote host to send data.
 *
 * \hideinitializer
 */
int uip_poll(struct uip_stack *ustack)
{
	return ustack->uip_flags & UIP_POLL;
}

int uip_initialmss(struct uip_stack *ustack)
{
	return ustack->uip_conn->initialmss;
}

int uip_mss(struct uip_stack *ustack)
{
	return ustack->uip_conn->mss;
}

/*---------------------------------------------------------------------------*/
/* XXX: IP fragment reassembly: not well-tested. */

#if UIP_REASSEMBLY && !UIP_CONF_IPV6
#define UIP_REASS_BUFSIZE (UIP_BUFSIZE - UIP_LLH_LEN)
static u8_t uip_reassbuf[UIP_REASS_BUFSIZE];
static u8_t uip_reassbitmap[UIP_REASS_BUFSIZE / (8 * 8)];
static const u8_t bitmap_bits[8] = { 0xff, 0x7f, 0x3f, 0x1f,
	0x0f, 0x07, 0x03, 0x01
};
static u16_t uip_reasslen;
static u8_t uip_reassflags;
#define UIP_REASS_FLAG_LASTFRAG 0x01
static u8_t uip_reasstmr;

#define IP_MF   0x20

static u8_t uip_reass(void)
{
	u16_t offset, len;
	u16_t i;

	/* If ip_reasstmr is zero, no packet is present in the buffer, so we
	   write the IP header of the fragment into the reassembly
	   buffer. The timer is updated with the maximum age. */
	if (uip_reasstmr == 0) {
		memcpy(uip_reassbuf, &BUF(ustack)->vhl, uip_iph_len);
		uip_reasstmr = UIP_REASS_MAXAGE;
		uip_reassflags = 0;
		/* Clear the bitmap. */
		memset(uip_reassbitmap, 0, sizeof(uip_reassbitmap));
	}

	/* Check if the incoming fragment matches the one currently present
	   in the reasembly buffer. If so, we proceed with copying the
	   fragment into the buffer. */
	if (BUF(ustack)->srcipaddr[0] == FBUF(ustack)->srcipaddr[0] &&
	    BUF(ustack)->srcipaddr[1] == FBUF(ustack)->srcipaddr[1] &&
	    BUF(ustack)->destipaddr[0] == FBUF(ustack)->destipaddr[0] &&
	    BUF(ustack)->destipaddr[1] == FBUF(ustack)->destipaddr[1] &&
	    BUF(ustack)->ipid[0] == FBUF(ustack)->ipid[0] &&
	    BUF(ustack)->ipid[1] == FBUF(ustack)->ipid[1]) {

		len =
		    (BUF(ustack)->len[0] << 8) + BUF(ustack)->len[1] -
		    (BUF(ustack)->vhl & 0x0f) * 4;
		offset =
		    (((BUF(ustack)->ipoffset[0] & 0x3f) << 8) +
		     BUF(ustack)->ipoffset[1]) * 8;

		/* If the offset or the offset + fragment length overflows the
		   reassembly buffer, we discard the entire packet. */
		if (offset > UIP_REASS_BUFSIZE ||
		    offset + len > UIP_REASS_BUFSIZE) {
			uip_reasstmr = 0;
			goto nullreturn;
		}

		/* Copy the fragment into the reassembly buffer, at the right
		   offset. */
		memcpy(&uip_reassbuf[uip_iph_len + offset],
		       (char *)BUF + (int)((BUF(ustack)->vhl & 0x0f) * 4), len);

		/* Update the bitmap. */
		if (offset / (8 * 8) == (offset + len) / (8 * 8)) {
			/* If the two endpoints are in the same byte, we only
			   update that byte. */

			uip_reassbitmap[offset / (8 * 8)] |=
			    bitmap_bits[(offset / 8) & 7] &
			    ~bitmap_bits[((offset + len) / 8) & 7];
		} else {
			/* If the two endpoints are in different bytes, we
			   update the bytes in the endpoints and fill the
			   stuff inbetween with 0xff. */
			uip_reassbitmap[offset / (8 * 8)] |=
			    bitmap_bits[(offset / 8) & 7];
			for (i = 1 + offset / (8 * 8);
			     i < (offset + len) / (8 * 8); ++i) {
				uip_reassbitmap[i] = 0xff;
			}
			uip_reassbitmap[(offset + len) / (8 * 8)] |=
			    ~bitmap_bits[((offset + len) / 8) & 7];
		}

		/* If this fragment has the More Fragments flag set to zero, we
		   know that this is the last fragment, so we can calculate the
		   size of the entire packet. We also set the
		   IP_REASS_FLAG_LASTFRAG flag to indicate that we have received
		   the final fragment. */

		if ((BUF(ustack)->ipoffset[0] & IP_MF) == 0) {
			uip_reassflags |= UIP_REASS_FLAG_LASTFRAG;
			uip_reasslen = offset + len;
		}

		/* Finally, we check if we have a full packet in the buffer.
		   We do this by checking if we have the last fragment and if
		   all bits in the bitmap are set. */
		if (uip_reassflags & UIP_REASS_FLAG_LASTFRAG) {
			/* Check all bytes up to and including all but the last
			   byte in the bitmap. */
			for (i = 0; i < uip_reasslen / (8 * 8) - 1; ++i) {
				if (uip_reassbitmap[i] != 0xff)
					goto nullreturn;
			}
			/* Check the last byte in the bitmap. It should contain
			   just the right amount of bits. */
			if (uip_reassbitmap[uip_reasslen / (8 * 8)] !=
			    (u8_t) ~bitmap_bits[uip_reasslen / 8 & 7])
				goto nullreturn;

			/* If we have come this far, we have a full packet in
			   the buffer, so we allocate a pbuf and copy the
			   packet into it. We also reset the timer. */
			uip_reasstmr = 0;
			memcpy(BUF, FBUF, uip_reasslen);

			/* Pretend to be a "normal" (i.e., not fragmented) IP
			   packet from now on. */
			BUF(ustack)->ipoffset[0] = BUF(ustack)->ipoffset[1] = 0;
			BUF(ustack)->len[0] = uip_reasslen >> 8;
			BUF(ustack)->len[1] = uip_reasslen & 0xff;
			BUF(ustack)->ipchksum = 0;
			BUF(ustack)->ipchksum = ~(uip_ipchksum());

			return uip_reasslen;
		}
	}

nullreturn:
	return 0;
}
#endif /* UIP_REASSEMBLY */
/*---------------------------------------------------------------------------*/
static void uip_add_rcv_nxt(struct uip_stack *ustack, u16_t n)
{
	u8_t uip_acc32[4];

	uip_add32(ustack->uip_conn->rcv_nxt, n, uip_acc32);
	ustack->uip_conn->rcv_nxt[0] = uip_acc32[0];
	ustack->uip_conn->rcv_nxt[1] = uip_acc32[1];
	ustack->uip_conn->rcv_nxt[2] = uip_acc32[2];
	ustack->uip_conn->rcv_nxt[3] = uip_acc32[3];
}

/*---------------------------------------------------------------------------*/

/** @} */

/**
 * \defgroup uipdevfunc uIP device driver functions
 * @{
 *
 * These functions are used by a network device driver for interacting
 * with uIP.
 */

/**
 * Process an incoming packet.
 *
 * This function should be called when the device driver has received
 * a packet from the network. The packet from the device driver must
 * be present in the uip_buf buffer, and the length of the packet
 * should be placed in the uip_len variable.
 *
 * When the function returns, there may be an outbound packet placed
 * in the uip_buf packet buffer. If so, the uip_len variable is set to
 * the length of the packet. If no packet is to be sent out, the
 * uip_len variable is set to 0.
 *
 * The usual way of calling the function is presented by the source
 * code below.
 \code
	uip_len = devicedriver_poll();
	if(uip_len > 0) {
		uip_input();
		if(uip_len > 0) {
			devicedriver_send();
		}
	}
 \endcode
 *
 * \note If you are writing a uIP device driver that needs ARP
 * (Address Resolution Protocol), e.g., when running uIP over
 * Ethernet, you will need to call the uIP ARP code before calling
 * this function:
 \code
  #define BUF ((struct uip_eth_hdr *)&uip_buf[0])
  uip_len = ethernet_devicedrver_poll();
  if(uip_len > 0) {
	if (BUF(ustack)->type == HTONS(UIP_ETHTYPE_IP)) {
		uip_arp_ipin();
		uip_input();
		if (uip_len > 0) {
			uip_arp_out();
			ethernet_devicedriver_send();
		}
	} else if (BUF(ustack)->type == HTONS(UIP_ETHTYPE_ARP)) {
		uip_arp_arpin();
		if (uip_len > 0)
			ethernet_devicedriver_send();
	}
 \endcode
 *
 * \hideinitializer
 */
void uip_input(struct uip_stack *ustack)
{
	uip_process(ustack, UIP_DATA);
}

/**
 * Periodic processing for a connection identified by its number.
 *
 * This function does the necessary periodic processing (timers,
 * polling) for a uIP TCP conneciton, and should be called when the
 * periodic uIP timer goes off. It should be called for every
 * connection, regardless of whether they are open of closed.
 *
 * When the function returns, it may have an outbound packet waiting
 * for service in the uIP packet buffer, and if so the uip_len
 * variable is set to a value larger than zero. The device driver
 * should be called to send out the packet.
 *
 * The ususal way of calling the function is through a for() loop like
 * this:
 \code
	for(i = 0; i < UIP_CONNS; ++i) {
		uip_periodic(i);
		if(uip_len > 0) {
			devicedriver_send();
		}
	}
 \endcode
 *
 * \note If you are writing a uIP device driver that needs ARP
 * (Address Resolution Protocol), e.g., when running uIP over
 * Ethernet, you will need to call the uip_arp_out() function before
 * calling the device driver:
 \code
	for(i = 0; i < UIP_CONNS; ++i) {
		uip_periodic(i);
		if(uip_len > 0) {
			uip_arp_out();
			ethernet_devicedriver_send();
		}
	}
 \endcode
 *
 * \param conn The number of the connection which is to be periodically polled.
 *
 * \hideinitializer
 */
void uip_periodic(struct uip_stack *ustack, int conn)
{
	ustack->uip_conn = &ustack->uip_conns[conn];
	uip_process(ustack, UIP_TIMER);
}

#if UIP_UDP
/**
 * Periodic processing for a UDP connection identified by its number.
 *
 * This function is essentially the same as uip_periodic(), but for
 * UDP connections. It is called in a similar fashion as the
 * uip_periodic() function:
 \code
  for(i = 0; i < UIP_UDP_CONNS; i++) {
    uip_udp_periodic(i);
    if(uip_len > 0) {
      devicedriver_send();
    }
  }
 \endcode
 *
 * \note As for the uip_periodic() function, special care has to be
 * taken when using uIP together with ARP and Ethernet:
 \code
  for(i = 0; i < UIP_UDP_CONNS; i++) {
    uip_udp_periodic(i);
    if(uip_len > 0) {
      uip_arp_out();
      ethernet_devicedriver_send();
    }
  }
 \endcode
 *
 * \param conn The number of the UDP connection to be processed.
 *
 * \hideinitializer
 */
void uip_udp_periodic(struct uip_stack *ustack, int conn)
{
	ustack->uip_udp_conn = &ustack->uip_udp_conns[conn];
	uip_process(ustack, UIP_UDP_TIMER);
}
#endif

void uip_ndp_periodic(struct uip_stack *ustack)
{
	uip_process(ustack, UIP_NDP_TIMER);
}

void uip_process(struct uip_stack *ustack, u8_t flag)
{
	u8_t c;
	u16_t tmp16;
	register struct uip_conn *uip_connr = ustack->uip_conn;

	u16_t uip_iph_len = 0;
	u16_t uip_ip_udph_len = 0;
	u16_t uip_ip_tcph_len = 0;
	struct ip6_hdr *ipv6_hdr = NULL;
	struct uip_tcp_ipv4_hdr *tcp_ipv4_hdr = NULL;
	struct uip_tcp_hdr *tcp_hdr = NULL;
	struct uip_icmpv4_hdr *icmpv4_hdr = NULL;
	struct uip_icmpv6_hdr *icmpv6_hdr __attribute__((__unused__)) = NULL;
	struct uip_udp_hdr *udp_hdr = NULL;

	/*  Drop invalid packets */
	if (ustack->uip_buf == NULL) {
		LOG_ERR(PFX "ustack->uip_buf == NULL.");
		return;
	}

	if (is_ipv6(ustack)) {
		uint8_t *buf;
		uip_iph_len = UIP_IPv6_H_LEN;
		uip_ip_udph_len = UIP_IPv6_UDPH_LEN;
		uip_ip_tcph_len = UIP_IPv6_TCPH_LEN;

		ipv6_hdr = (struct ip6_hdr *)ustack->network_layer;

		buf = ustack->network_layer;
		buf += sizeof(struct uip_ipv6_hdr);
		tcp_hdr = (struct uip_tcp_hdr *)buf;

		buf = ustack->network_layer;
		buf += sizeof(struct uip_ipv6_hdr);
		udp_hdr = (struct uip_udp_hdr *)buf;

		buf = ustack->network_layer;
		buf += sizeof(struct uip_ipv6_hdr);
		icmpv6_hdr = (struct uip_icmpv6_hdr *)buf;
	} else {
		uint8_t *buf;

		uip_iph_len = UIP_IPv4_H_LEN;
		uip_ip_udph_len = UIP_IPv4_UDPH_LEN;
		uip_ip_tcph_len = UIP_IPv4_TCPH_LEN;

		tcp_ipv4_hdr = (struct uip_tcp_ipv4_hdr *)ustack->network_layer;

		buf = ustack->network_layer;
		buf += sizeof(struct uip_ipv4_hdr);
		tcp_hdr = (struct uip_tcp_hdr *)buf;

		buf = ustack->network_layer;
		buf += sizeof(struct uip_ipv4_hdr);
		icmpv4_hdr = (struct uip_icmpv4_hdr *)buf;

		buf = ustack->network_layer;
		buf += sizeof(struct uip_ipv4_hdr);
		udp_hdr = (struct uip_udp_hdr *)buf;
	}			/* End of ipv6 */

#if UIP_UDP
	if (flag == UIP_UDP_SEND_CONN)
		goto udp_send;
#endif /* UIP_UDP */
	ustack->uip_sappdata = ustack->uip_appdata = ustack->network_layer +
	    uip_ip_tcph_len;

	/* Check if we were invoked because of a poll request for a
	   particular connection. */
	if (flag == UIP_POLL_REQUEST) {
		if ((uip_connr->tcpstateflags & UIP_TS_MASK) == UIP_ESTABLISHED
		    && !uip_outstanding(uip_connr)) {
			ustack->uip_flags = UIP_POLL;
			UIP_APPCALL(ustack);
			goto appsend;
		}
		goto drop;

		/* Check if we were invoked because of the perodic timer
		   firing. */
	} else if (flag == UIP_TIMER) {
#if UIP_REASSEMBLY
		if (uip_reasstmr != 0)
			--uip_reasstmr;
#endif /* UIP_REASSEMBLY */
		/* Increase the initial sequence number. */
		if (++ustack->iss[3] == 0) {
			if (++ustack->iss[2] == 0) {
				if (++ustack->iss[1] == 0)
					++ustack->iss[0];
			}
		}

		/* Reset the length variables. */
		ustack->uip_len = 0;
		ustack->uip_slen = 0;

		/* Check if the connection is in a state in which we simply wait
		   for the connection to time out. If so, we increase the
		   connection's timer and remove the connection if it times
		   out. */
		if (uip_connr->tcpstateflags == UIP_TIME_WAIT ||
		    uip_connr->tcpstateflags == UIP_FIN_WAIT_2) {
			++(uip_connr->timer);
			if (uip_connr->timer == UIP_TIME_WAIT_TIMEOUT)
				uip_connr->tcpstateflags = UIP_CLOSED;
		} else if (uip_connr->tcpstateflags != UIP_CLOSED) {
			/* If the connection has outstanding data, we increase
			   the connection's timer and see if it has reached the
			   RTO value in which case we retransmit. */
			if (uip_outstanding(uip_connr)) {
				if (uip_connr->timer-- == 0) {
					if (uip_connr->nrtx == UIP_MAXRTX ||
					    ((uip_connr->tcpstateflags ==
					      UIP_SYN_SENT
					      || uip_connr->tcpstateflags ==
					      UIP_SYN_RCVD)
					     && uip_connr->nrtx ==
					     UIP_MAXSYNRTX)) {
						uip_connr->tcpstateflags =
						    UIP_CLOSED;

						/* We call UIP_APPCALL() with
						   uip_flags set to UIP_TIMEDOUT
						   to inform the application
						   that the connection has timed
						   out. */
						ustack->uip_flags =
						    UIP_TIMEDOUT;
						UIP_APPCALL(ustack);

						/* We also send a reset packet
						   to the remote host. */
						tcp_hdr->flags =
						    TCP_RST | TCP_ACK;
						goto tcp_send_nodata;
					}

					/* Exponential backoff. */
					uip_connr->timer =
					    UIP_RTO << (uip_connr->nrtx >
							4 ? 4 : uip_connr->
							nrtx);
					++(uip_connr->nrtx);

					/* Ok, so we need to retransmit.
					   We do this differently depending on
					   which state we are in.
					   In ESTABLISHED, we call upon the
					   application so that it may prepare
					   the data for the retransmit.
					   In SYN_RCVD, we resend the SYNACK
					   that we sent earlier and in LAST_ACK
					   we have to retransmit our FINACK. */
					++ustack->stats.tcp.rexmit;
					switch (uip_connr->
						tcpstateflags & UIP_TS_MASK) {
					case UIP_SYN_RCVD:
						/* In the SYN_RCVD state, we
						   should retransmit our SYNACK
						 */
						goto tcp_send_synack;
#if UIP_ACTIVE_OPEN
					case UIP_SYN_SENT:
						/* In the SYN_SENT state,
						   we retransmit out SYN. */
						tcp_hdr->flags = 0;
						goto tcp_send_syn;
#endif /* UIP_ACTIVE_OPEN */

					case UIP_ESTABLISHED:
						/* In the ESTABLISHED state,
						   we call upon the application
						   to do the actual retransmit
						   after which we jump into
						   the code for sending out the
						   packet (the apprexmit
						   label). */
						ustack->uip_flags = UIP_REXMIT;
						UIP_APPCALL(ustack);
						goto apprexmit;

					case UIP_FIN_WAIT_1:
					case UIP_CLOSING:
					case UIP_LAST_ACK:
						/* In all these states we should
						   retransmit a FINACK. */
						goto tcp_send_finack;

					}
				}
			} else if ((uip_connr->tcpstateflags & UIP_TS_MASK) ==
				   UIP_ESTABLISHED) {
				/* If there was no need for a retransmission,
				   we poll the application for new data. */
				ustack->uip_flags = UIP_POLL;
				UIP_APPCALL(ustack);
				goto appsend;
			}
		}
		goto drop;
	}			/* End of UIP_TIMER */
#if UIP_UDP
	if (flag == UIP_UDP_TIMER) {
		/* This is for IPv4 DHCP only! */
		if (ustack->uip_udp_conn->lport != 0) {
			ustack->uip_conn = NULL;
			ustack->uip_sappdata = ustack->uip_appdata =
			    ustack->network_layer + uip_ip_udph_len;
			ustack->uip_len = ustack->uip_slen = 0;
			ustack->uip_flags = UIP_POLL;
			UIP_UDP_APPCALL(ustack);
			goto udp_send;
		} else {
			goto drop;
		}
	}
#endif
	if (flag == UIP_NDP_TIMER) {
		/* This is for IPv6 NDP Only! */
		if (1) {	/* If NDP engine active */
			ustack->uip_len = ustack->uip_slen = 0;
			ustack->uip_flags = UIP_POLL;
			goto ndp_send;
		}
	}

	/* This is where the input processing starts. */
	++ustack->stats.ip.recv;

	/* Start of IP input header processing code. */

	if (is_ipv6(ustack)) {
		u8_t version = ((ipv6_hdr->ip6_vfc) & 0xf0) >> 4;

		/* Check validity of the IP header. */
		if (version != 0x6) {	/* IP version and header length. */
			++ustack->stats.ip.drop;
			++ustack->stats.ip.vhlerr;
			LOG_DEBUG(PFX "ipv6: invalid version(0x%x).", version);
			goto drop;
		}
	} else {
		/* Check validity of the IP header. */
		if (tcp_ipv4_hdr->vhl != 0x45) {
			/* IP version and header length. */
			++ustack->stats.ip.drop;
			++ustack->stats.ip.vhlerr;
			LOG_DEBUG(PFX
				  "ipv4: invalid version or header length: "
				  "0x%x.",
				  tcp_ipv4_hdr->vhl);
			goto drop;
		}
	}

	/* Check the size of the packet. If the size reported to us in
	   uip_len is smaller the size reported in the IP header, we assume
	   that the packet has been corrupted in transit. If the size of
	   uip_len is larger than the size reported in the IP packet header,
	   the packet has been padded and we set uip_len to the correct
	   value.. */

	if (is_ipv6(ustack)) {
		u16_t len = ntohs(ipv6_hdr->ip6_plen);
		if (len > ustack->uip_len) {
			LOG_DEBUG(PFX
				 "ip: packet shorter than reported in IP header"
				 ":IPv6_BUF(ustack)->len: %d ustack->uip_len: "
				 "%d", len, ustack->uip_len);
			goto drop;
		}
	} else {
		if ((tcp_ipv4_hdr->len[0] << 8) +
		    tcp_ipv4_hdr->len[1] <= ustack->uip_len) {
			ustack->uip_len = (tcp_ipv4_hdr->len[0] << 8) +
			    tcp_ipv4_hdr->len[1];
		} else {
			LOG_DEBUG(PFX
				 "ip: packet shorter than reported in IP header"
				 ":tcp_ipv4_hdr->len: %d ustack->uip_len:%d.",
				 (tcp_ipv4_hdr->len[0] << 8) +
				 tcp_ipv4_hdr->len[1], ustack->uip_len);
			goto drop;
		}
	}

	if (!is_ipv6(ustack)) {
		/* Check the fragment flag. */
		if ((tcp_ipv4_hdr->ipoffset[0] & 0x3f) != 0 ||
		    tcp_ipv4_hdr->ipoffset[1] != 0) {
#if UIP_REASSEMBLY
			uip_len = uip_reass();
			if (uip_len == 0)
				goto drop;
#else /* UIP_REASSEMBLY */
			++ustack->stats.ip.drop;
			++ustack->stats.ip.fragerr;
			LOG_WARN(PFX "ip: fragment dropped.");
			goto drop;
#endif /* UIP_REASSEMBLY */
		}
	}

	if (!is_ipv6(ustack)) {
		/* ipv4 */
		if (uip_ip4addr_cmp(ustack->hostaddr, all_zeroes_addr4)) {
			/* If we are configured to use ping IP address
			   configuration and hasn't been assigned an IP
			   address yet, we accept all ICMP packets. */
#if UIP_PINGADDRCONF && !UIP_CONF_IPV6
			if (tcp_ipv4_hdr->proto == UIP_PROTO_ICMP) {
				LOG_WARN(PFX
					 "ip: possible ping config packet "
					 "received.");
				goto icmp_input;
			} else {
				LOG_WARN(PFX
					 "ip: packet dropped since no "
					 "address assigned.");
				goto drop;
			}
#endif /* UIP_PINGADDRCONF */
		} else {
			int broadcast_addr = 0xFFFFFFFF;
			/* If IP broadcast support is configured, we check for
			   a broadcast UDP packet, which may be destined to us
			 */
			if ((tcp_ipv4_hdr->proto == UIP_PROTO_UDP) &&
			    (uip_ip4addr_cmp
			     (tcp_ipv4_hdr->destipaddr, &broadcast_addr))
			    /*&&
			       uip_ipchksum() == 0xffff */
			    ) {
				goto udp_input;
			}

			/* Check if the packet is destined for our IP address
			 */
			if (!uip_ip4addr_cmp(tcp_ipv4_hdr->destipaddr,
					     ustack->hostaddr)) {
				++ustack->stats.ip.drop;
				goto drop;
			}
		}
		if (uip_ipchksum(ustack) != 0xffff) {
			/* Compute and check the IP header checksum. */
			++ustack->stats.ip.drop;
			++ustack->stats.ip.chkerr;
			LOG_ERR(PFX "ip: bad checksum.");
			goto drop;
		}
	}  /* End of ipv4 */

	if (is_ipv6(ustack)) {
		if (ipv6_hdr->ip6_nxt == UIP_PROTO_TCP) {
			/* Check for TCP packet. If so, proceed with TCP input
			   processing. */
			goto ndp_newdata;
		}
#if UIP_UDP
		if (ipv6_hdr->ip6_nxt == UIP_PROTO_UDP)
			goto ndp_newdata;
#endif /* UIP_UDP */

		/* This is IPv6 ICMPv6 processing code. */
		if (ipv6_hdr->ip6_nxt != UIP_PROTO_ICMP6) {
			/* We only allow ICMPv6 packets from here. */
			++ustack->stats.ip.drop;
			++ustack->stats.ip.protoerr;
			goto drop;
		}

		++ustack->stats.icmp.recv;

ndp_newdata:
		/* This call is to handle the IPv6 Network Discovery Protocol */
		ustack->uip_flags = UIP_NEWDATA;
		ustack->uip_slen = 0;
ndp_send:
		UIP_NDP_CALL(ustack);
		if (ustack->uip_slen != 0) {
			ustack->uip_len = ustack->uip_slen;
			goto send;
		} else {
			goto drop;
		}
	} else {
		/* IPv4 Processing */
		if (tcp_ipv4_hdr->proto == UIP_PROTO_TCP) {
			/* Check for TCP packet. If so, proceed with TCP input
			   processing. */
			goto tcp_input;
		}
#if UIP_UDP
		if (tcp_ipv4_hdr->proto == UIP_PROTO_UDP)
			goto udp_input;
#endif /* UIP_UDP */

		/* ICMPv4 processing code follows. */
		if (tcp_ipv4_hdr->proto != UIP_PROTO_ICMP) {
			/* We only allow ICMP packets from here. */
			++ustack->stats.ip.drop;
			++ustack->stats.ip.protoerr;
			LOG_DEBUG(PFX "ip: neither tcp nor icmp.");
			goto drop;
		}
#if UIP_PINGADDRCONF
icmp_input:
#endif /* UIP_PINGADDRCONF */
		++ustack->stats.icmp.recv;

		if (icmpv4_hdr->type == ICMP_ECHO_REPLY) {
			if (process_icmp_packet(icmpv4_hdr, ustack) == 0)
				goto drop;
		}

		/* ICMP echo (i.e., ping) processing. This is simple, we only
		   change the ICMP type from ECHO to ECHO_REPLY and adjust the
		   ICMP checksum before we return the packet. */
		if (icmpv4_hdr->type != ICMP_ECHO) {
			++ustack->stats.icmp.drop;
			++ustack->stats.icmp.typeerr;
			LOG_DEBUG(PFX "icmp: not icmp echo.");
			goto drop;
		}

		/* If we are configured to use ping IP address assignment, we
		   use the destination IP address of this ping packet and assign
		   it to ourself. */
#if UIP_PINGADDRCONF
		if ((ustack->hostaddr[0] | ustack->hostaddr[1]) == 0) {
			ustack->hostaddr[0] = tcp_ipv4_hdr->destipaddr[0];
			ustack->hostaddr[1] = tcp_ipv4_hdr->destipaddr[1];
		}
#endif /* UIP_PINGADDRCONF */

		icmpv4_hdr->type = ICMP_ECHO_REPLY;

		if (icmpv4_hdr->icmpchksum >= htons(0xffff -
						    (ICMP_ECHO << 8))) {
			icmpv4_hdr->icmpchksum += htons(ICMP_ECHO << 8) + 1;
		} else {
			icmpv4_hdr->icmpchksum += htons(ICMP_ECHO << 8);
		}

		/* Swap IP addresses. */
		uip_ip4addr_copy(tcp_ipv4_hdr->destipaddr,
				 tcp_ipv4_hdr->srcipaddr);
		uip_ip4addr_copy(tcp_ipv4_hdr->srcipaddr, ustack->hostaddr);

		++ustack->stats.icmp.sent;
		goto send;

		/* End of IPv4 input header processing code. */
	}

#if UIP_UDP
	/* UDP input processing. */
udp_input:
	/* UDP processing is really just a hack. We don't do anything to the
	   UDP/IP headers, but let the UDP application do all the hard
	   work. If the application sets uip_slen, it has a packet to
	   send. */
#if UIP_UDP_CHECKSUMS
	ustack->uip_len = ustack->uip_len - uip_ip_udph_len;
	ustack->uip_appdata = ustack->network_layer + uip_ip_udph_len;
	if (UDPBUF(ustack)->udpchksum != 0 && uip_udpchksum(ustack) != 0xffff) {
		++ustack->stats.udp.drop;
		++ustack->stats.udp.chkerr;
		LOG_DEBUG(PFX "udp: bad checksum.");
		goto drop;
	}
#else /* UIP_UDP_CHECKSUMS */
	uip_len = uip_len - uip_ip_udph_len;
#endif /* UIP_UDP_CHECKSUMS */

	if (is_ipv6(ustack))
		goto udp_found;

	/* Demultiplex this UDP packet between the UDP "connections". */
	for (ustack->uip_udp_conn = &ustack->uip_udp_conns[0];
	     ustack->uip_udp_conn < &ustack->uip_udp_conns[UIP_UDP_CONNS];
	     ++ustack->uip_udp_conn) {
		/* If the local UDP port is non-zero, the connection is
		   considered to be used. If so, the local port number is
		   checked against the destination port number in the
		   received packet. If the two port
		   numbers match, the remote port number is checked if the
		   connection is bound to a remote port. Finally, if the
		   connection is bound to a remote IP address, the source IP
		   address of the packet is checked. */

		if (ustack->uip_udp_conn->lport != 0 &&
		    UDPBUF(ustack)->destport == ustack->uip_udp_conn->lport &&
		    (ustack->uip_udp_conn->rport == 0 ||
		     UDPBUF(ustack)->srcport == ustack->uip_udp_conn->rport) &&
		    (uip_ip4addr_cmp(ustack->uip_udp_conn->ripaddr,
				     all_zeroes_addr4) ||
		     uip_ip4addr_cmp(ustack->uip_udp_conn->ripaddr,
				     all_ones_addr4) ||
		     uip_ip4addr_cmp(tcp_ipv4_hdr->srcipaddr,
				     ustack->uip_udp_conn->ripaddr))) {
			goto udp_found;
		}
	}
	LOG_DEBUG(PFX
		  "udp: no matching connection found: dest port: %d src port: "
		  "%d", udp_hdr->destport, udp_hdr->srcport);
	goto drop;

udp_found:
	ustack->uip_conn = NULL;
	ustack->uip_flags = UIP_NEWDATA;
	ustack->uip_sappdata = ustack->uip_appdata = ustack->network_layer +
	    uip_ip_udph_len;
	ustack->uip_slen = 0;
	if (is_ipv6(ustack))
		UIP_NDP_CALL(ustack);
	else
		UIP_UDP_APPCALL(ustack);
udp_send:
	if (ustack->uip_slen == 0)
		goto drop;

	ustack->uip_len = ustack->uip_slen + uip_ip_udph_len;

	if (is_ipv6(ustack)) {
		goto ip_send_nolen;
	} else {
		tcp_ipv4_hdr->len[0] = (ustack->uip_len >> 8);
		tcp_ipv4_hdr->len[1] = (ustack->uip_len & 0xff);
		tcp_ipv4_hdr->ttl = ustack->uip_udp_conn->ttl;
		tcp_ipv4_hdr->proto = UIP_PROTO_UDP;
	}

	udp_hdr->udplen = htons(ustack->uip_slen + UIP_UDPH_LEN);
	udp_hdr->udpchksum = 0;

	udp_hdr->srcport = ustack->uip_udp_conn->lport;
	udp_hdr->destport = ustack->uip_udp_conn->rport;

	uip_ip4addr_copy(tcp_ipv4_hdr->srcipaddr, ustack->hostaddr);
	uip_ip4addr_copy(tcp_ipv4_hdr->destipaddr,
			 ustack->uip_udp_conn->ripaddr);

	ustack->uip_appdata = ustack->network_layer + uip_ip_tcph_len;

	if (ustack->uip_buf == NULL) {
		LOG_WARN(PFX "uip_buf == NULL on udp send");
		goto drop;
	}
#if UIP_UDP_CHECKSUMS
	/* Calculate UDP checksum. */
	udp_hdr->udpchksum = ~(uip_udpchksum(ustack));
	if (udp_hdr->udpchksum == 0)
		udp_hdr->udpchksum = 0xffff;
#endif /* UIP_UDP_CHECKSUMS */

	goto ip_send_nolen;
#endif /* UIP_UDP */

	/* TCP input processing. */
tcp_input:
	++ustack->stats.tcp.recv;

	/* Start of TCP input header processing code. */

	if (uip_tcpchksum(ustack) != 0xffff) {	/* Compute and check the TCP
						   checksum. */
		++ustack->stats.tcp.drop;
		++ustack->stats.tcp.chkerr;
		LOG_WARN(PFX "tcp: bad checksum.");
		goto drop;
	}

	if (is_ipv6(ustack)) {
		/* Demultiplex this segment. */
		/* First check any active connections. */
		for (uip_connr = &ustack->uip_conns[0];
		     uip_connr <= &ustack->uip_conns[UIP_CONNS - 1];
		     ++uip_connr) {
			if (uip_connr->tcpstateflags != UIP_CLOSED &&
			    tcp_hdr->destport == uip_connr->lport &&
			    tcp_hdr->srcport == uip_connr->rport &&
			    uip_ip6addr_cmp(IPv6_BUF(ustack)->srcipaddr,
					    uip_connr->ripaddr)) {
				goto found;
			}
		}
	} else {
		/* Demultiplex this segment. */
		/* First check any active connections. */
		for (uip_connr = &ustack->uip_conns[0];
		     uip_connr <= &ustack->uip_conns[UIP_CONNS - 1];
		     ++uip_connr) {
			if (uip_connr->tcpstateflags != UIP_CLOSED &&
			    tcp_hdr->destport == uip_connr->lport &&
			    tcp_hdr->srcport == uip_connr->rport &&
			    uip_ip4addr_cmp(tcp_ipv4_hdr->srcipaddr,
					    uip_connr->ripaddr)) {
				goto found;
			}
		}
	}

	/* If we didn't find and active connection that expected the packet,
	   either this packet is an old duplicate, or this is a SYN packet
	   destined for a connection in LISTEN. If the SYN flag isn't set,
	   it is an old packet and we send a RST. */
	if ((tcp_hdr->flags & TCP_CTL) != TCP_SYN)
		goto reset;

	tmp16 = tcp_hdr->destport;
	/* Next, check listening connections. */
	for (c = 0; c < UIP_LISTENPORTS; ++c) {
		if (tmp16 == ustack->uip_listenports[c])
			goto found_listen;
	}

	/* No matching connection found, so we send a RST packet. */
	++ustack->stats.tcp.synrst;
reset:

	/* We do not send resets in response to resets. */
	if (tcp_hdr->flags & TCP_RST)
		goto drop;

	++ustack->stats.tcp.rst;

	tcp_hdr->flags = TCP_RST | TCP_ACK;
	ustack->uip_len = uip_ip_tcph_len;
	tcp_hdr->tcpoffset = 5 << 4;

	/* Flip the seqno and ackno fields in the TCP header. */
	c = tcp_hdr->seqno[3];
	tcp_hdr->seqno[3] = tcp_hdr->ackno[3];
	tcp_hdr->ackno[3] = c;

	c = tcp_hdr->seqno[2];
	tcp_hdr->seqno[2] = tcp_hdr->ackno[2];
	tcp_hdr->ackno[2] = c;

	c = tcp_hdr->seqno[1];
	tcp_hdr->seqno[1] = tcp_hdr->ackno[1];
	tcp_hdr->ackno[1] = c;

	c = tcp_hdr->seqno[0];
	tcp_hdr->seqno[0] = tcp_hdr->ackno[0];
	tcp_hdr->ackno[0] = c;

	/* We also have to increase the sequence number we are
	   acknowledging. If the least significant byte overflowed, we need
	   to propagate the carry to the other bytes as well. */
	if (++tcp_hdr->ackno[3] == 0) {
		if (++tcp_hdr->ackno[2] == 0) {
			if (++tcp_hdr->ackno[1] == 0)
				++tcp_hdr->ackno[0];
		}
	}

	/* Swap port numbers. */
	tmp16 = tcp_hdr->srcport;
	tcp_hdr->srcport = tcp_hdr->destport;
	tcp_hdr->destport = tmp16;

	/* Swap IP addresses. */
	if (is_ipv6(ustack)) {
		uip_ip6addr_copy(IPv6_BUF(ustack)->destipaddr,
				 IPv6_BUF(ustack)->srcipaddr);
		uip_ip6addr_copy(IPv6_BUF(ustack)->srcipaddr,
				 ustack->hostaddr6);
	} else {
		uip_ip4addr_copy(tcp_ipv4_hdr->destipaddr,
				 tcp_ipv4_hdr->srcipaddr);
		uip_ip4addr_copy(tcp_ipv4_hdr->srcipaddr, ustack->hostaddr);
	}

	/* And send out the RST packet! */
	goto tcp_send_noconn;

	/* This label will be jumped to if we matched the incoming packet
	   with a connection in LISTEN. In that case, we should create a new
	   connection and send a SYNACK in return. */
found_listen:
	/* First we check if there are any connections avaliable. Unused
	   connections are kept in the same table as used connections, but
	   unused ones have the tcpstate set to CLOSED. Also, connections in
	   TIME_WAIT are kept track of and we'll use the oldest one if no
	   CLOSED connections are found. Thanks to Eddie C. Dost for a very
	   nice algorithm for the TIME_WAIT search. */
	uip_connr = 0;
	for (c = 0; c < UIP_CONNS; ++c) {
		if (ustack->uip_conns[c].tcpstateflags == UIP_CLOSED) {
			uip_connr = &ustack->uip_conns[c];
			break;
		}
		if (ustack->uip_conns[c].tcpstateflags == UIP_TIME_WAIT) {
			if (uip_connr == 0 ||
			    ustack->uip_conns[c].timer > uip_connr->timer) {
				uip_connr = &ustack->uip_conns[c];
			}
		}
	}

	if (uip_connr == 0) {
		/* All connections are used already, we drop packet and hope
		   that the remote end will retransmit the packet at a time when
		   we have more spare connections. */
		++ustack->stats.tcp.syndrop;
		LOG_WARN(PFX "tcp: found no unused connections.");
		goto drop;
	}
	ustack->uip_conn = uip_connr;

	/* Fill in the necessary fields for the new connection. */
	uip_connr->rto = uip_connr->timer = UIP_RTO;
	uip_connr->sa = 0;
	uip_connr->sv = 4;
	uip_connr->nrtx = 0;
	uip_connr->lport = tcp_hdr->destport;
	uip_connr->rport = tcp_hdr->srcport;
	if (is_ipv6(ustack)) {
		uip_ip6addr_copy(uip_connr->ripaddr,
				 IPv6_BUF(ustack)->srcipaddr);
	} else {
		uip_ip4addr_copy(uip_connr->ripaddr, tcp_ipv4_hdr->srcipaddr);
	}
	uip_connr->tcpstateflags = UIP_SYN_RCVD;

	uip_connr->snd_nxt[0] = ustack->iss[0];
	uip_connr->snd_nxt[1] = ustack->iss[1];
	uip_connr->snd_nxt[2] = ustack->iss[2];
	uip_connr->snd_nxt[3] = ustack->iss[3];
	uip_connr->len = 1;

	/* rcv_nxt should be the seqno from the incoming packet + 1. */
	uip_connr->rcv_nxt[3] = tcp_hdr->seqno[3];
	uip_connr->rcv_nxt[2] = tcp_hdr->seqno[2];
	uip_connr->rcv_nxt[1] = tcp_hdr->seqno[1];
	uip_connr->rcv_nxt[0] = tcp_hdr->seqno[0];
	uip_add_rcv_nxt(ustack, 1);

	/* Parse the TCP MSS option, if present. */
	if ((tcp_hdr->tcpoffset & 0xf0) > 0x50) {
		for (c = 0; c < ((tcp_hdr->tcpoffset >> 4) - 5) << 2;) {
			ustack->opt =
			    ustack->uip_buf[uip_ip_tcph_len + UIP_LLH_LEN + c];
			if (ustack->opt == TCP_OPT_END) {
				/* End of options. */
				break;
			} else if (ustack->opt == TCP_OPT_NOOP) {
				++c;
				/* NOP option. */
			} else if (ustack->opt == TCP_OPT_MSS &&
				   ustack->uip_buf[uip_ip_tcph_len +
						   UIP_LLH_LEN + 1 + c] ==
				   TCP_OPT_MSS_LEN) {
				/* An MSS option with the right option length.*/
				tmp16 =
				    ((u16_t) ustack->
				     uip_buf[uip_ip_tcph_len + UIP_LLH_LEN + 2 +
					     c] << 8) | (u16_t) ustack->
				    uip_buf[uip_ip_tcph_len + UIP_LLH_LEN + 3 +
					    c];
				uip_connr->initialmss = uip_connr->mss =
				    tmp16 > UIP_TCP_MSS ? UIP_TCP_MSS : tmp16;

				/* And we are done processing options. */
				break;
			} else {
				/* All other options have a length field, so
				   that we easily can skip past them. */
				if (ustack->uip_buf[uip_ip_tcph_len + UIP_LLH_LEN + 1 + c] == 0) {
					/* If the length field is zero, the
					   options are malformed
					   and we don't process them further. */
					break;
				}
				if ((ustack->uip_buf[uip_ip_tcph_len + UIP_LLH_LEN + 1 + c]) > (256 - c)) {
					/* u8 overflow, actually there should
					 * never be more than 40 bytes of options */
					break;
				}
				c += ustack->uip_buf[uip_ip_tcph_len + UIP_LLH_LEN + 1 + c];
			}
		}
	}

	/* Our response will be a SYNACK. */
#if UIP_ACTIVE_OPEN
tcp_send_synack:
	tcp_hdr->flags = TCP_ACK;

tcp_send_syn:
	tcp_hdr->flags |= TCP_SYN;
#else /* UIP_ACTIVE_OPEN */
tcp_send_synack:
	tcp_hdr->flags = TCP_SYN | TCP_ACK;
#endif /* UIP_ACTIVE_OPEN */

	/* We send out the TCP Maximum Segment Size option with our
	   SYNACK. */
	tcp_hdr->optdata[0] = TCP_OPT_MSS;
	tcp_hdr->optdata[1] = TCP_OPT_MSS_LEN;
	tcp_hdr->optdata[2] = (UIP_TCP_MSS) / 256;
	tcp_hdr->optdata[3] = (UIP_TCP_MSS) & 255;
	ustack->uip_len = uip_ip_tcph_len + TCP_OPT_MSS_LEN;
	tcp_hdr->tcpoffset = ((UIP_TCPH_LEN + TCP_OPT_MSS_LEN) / 4) << 4;
	goto tcp_send;

	/* This label will be jumped to if we found an active connection. */
found:
	ustack->uip_conn = uip_connr;
	ustack->uip_flags = 0;
	/* We do a very naive form of TCP reset processing; we just accept
	   any RST and kill our connection. We should in fact check if the
	   sequence number of this reset is wihtin our advertised window
	   before we accept the reset. */
	if (tcp_hdr->flags & TCP_RST) {
		uip_connr->tcpstateflags = UIP_CLOSED;
		LOG_WARN(PFX "tcp: got reset, aborting connection.");
		ustack->uip_flags = UIP_ABORT;
		UIP_APPCALL(ustack);
		goto drop;
	}
	/* Calculated the length of the data, if the application has sent
	   any data to us. */
	c = (tcp_hdr->tcpoffset >> 4) << 2;
	/* uip_len will contain the length of the actual TCP data. This is
	   calculated by subtracing the length of the TCP header (in
	   c) and the length of the IP header (20 bytes). */
	ustack->uip_len = ustack->uip_len - c - uip_iph_len;

	/* First, check if the sequence number of the incoming packet is
	   what we're expecting next. If not, we send out an ACK with the
	   correct numbers in. */
	if (!(((uip_connr->tcpstateflags & UIP_TS_MASK) == UIP_SYN_SENT) &&
	      ((tcp_hdr->flags & TCP_CTL) == (TCP_SYN | TCP_ACK)))) {
		if ((ustack->uip_len > 0
		     || ((tcp_hdr->flags & (TCP_SYN | TCP_FIN)) != 0))
		    && (tcp_hdr->seqno[0] != uip_connr->rcv_nxt[0]
			|| tcp_hdr->seqno[1] != uip_connr->rcv_nxt[1]
			|| tcp_hdr->seqno[2] != uip_connr->rcv_nxt[2]
			|| tcp_hdr->seqno[3] != uip_connr->rcv_nxt[3])) {
			goto tcp_send_ack;
		}
	}

	{
		u8_t uip_acc32[4];

		/* Next, check if the incoming segment acks any outstanding
		   data. If so, we update the sequence number, reset the len of
		   the outstanding data, calc RTT estimations, and reset the
		   retransmission timer. */
		if ((tcp_hdr->flags & TCP_ACK) && uip_outstanding(uip_connr)) {
			uip_add32(uip_connr->snd_nxt, uip_connr->len,
				  uip_acc32);

			if (tcp_hdr->ackno[0] == uip_acc32[0] &&
			    tcp_hdr->ackno[1] == uip_acc32[1] &&
			    tcp_hdr->ackno[2] == uip_acc32[2] &&
			    tcp_hdr->ackno[3] == uip_acc32[3]) {
				/* Update sequence number. */
				uip_connr->snd_nxt[0] = uip_acc32[0];
				uip_connr->snd_nxt[1] = uip_acc32[1];
				uip_connr->snd_nxt[2] = uip_acc32[2];
				uip_connr->snd_nxt[3] = uip_acc32[3];

				/* Do RTT estimation, unless we have done
				   retransmissions. */
				if (uip_connr->nrtx == 0) {
					signed char m;
					m = uip_connr->rto - uip_connr->timer;
					/* This is taken directly from VJs
					   original code in his paper */
					m = m - (uip_connr->sa >> 3);
					uip_connr->sa += m;
					if (m < 0)
						m = -m;
					m = m - (uip_connr->sv >> 2);
					uip_connr->sv += m;
					uip_connr->rto =
					    (uip_connr->sa >> 3) +
					    uip_connr->sv;

				}
				/* Set the acknowledged flag. */
				ustack->uip_flags = UIP_ACKDATA;
				/* Reset the retransmission timer. */
				uip_connr->timer = uip_connr->rto;

				/* Reset length of outstanding data. */
				uip_connr->len = 0;
			}

		}

	}

	/* Do different things depending on in what state the connection is. */
	switch (uip_connr->tcpstateflags & UIP_TS_MASK) {
		/* CLOSED and LISTEN are not handled here. CLOSE_WAIT is not
		   implemented, since we force the application to close when the
		   peer sends a FIN (hence the application goes directly from
		   ESTABLISHED to LAST_ACK). */
	case UIP_SYN_RCVD:
		/* In SYN_RCVD we have sent out a SYNACK in response to a SYN,
		   and we are waiting for an ACK that acknowledges the data we
		   sent out the last time. Therefore, we want to have the
		   UIP_ACKDATA flag set.
		   If so, we enter the ESTABLISHED state. */
		if (ustack->uip_flags & UIP_ACKDATA) {
			uip_connr->tcpstateflags = UIP_ESTABLISHED;
			ustack->uip_flags = UIP_CONNECTED;
			uip_connr->len = 0;
			if (ustack->uip_len > 0) {
				ustack->uip_flags |= UIP_NEWDATA;
				uip_add_rcv_nxt(ustack, ustack->uip_len);
			}
			ustack->uip_slen = 0;
			UIP_APPCALL(ustack);
			goto appsend;
		}
		goto drop;
#if UIP_ACTIVE_OPEN
	case UIP_SYN_SENT:
		/* In SYN_SENT, we wait for a SYNACK that is sent in response to
		   our SYN. The rcv_nxt is set to sequence number in the SYNACK
		   plus one, and we send an ACK. We move into the ESTABLISHED
		   state. */
		if ((ustack->uip_flags & UIP_ACKDATA) &&
		    (tcp_hdr->flags & TCP_CTL) == (TCP_SYN | TCP_ACK)) {

			/* Parse the TCP MSS option, if present. */
			if ((tcp_hdr->tcpoffset & 0xf0) > 0x50) {
				for (c = 0;
				     c <
				     ((tcp_hdr->tcpoffset >> 4) - 5) << 2;) {
					ustack->opt =
					    ustack->uip_buf[uip_ip_tcph_len +
							    UIP_LLH_LEN + c];
					if (ustack->opt == TCP_OPT_END) {
						/* End of options. */
						break;
					} else if (ustack->opt ==
						   TCP_OPT_NOOP) {
						++c;
						/* NOP option. */
					} else if (ustack->opt == TCP_OPT_MSS &&
						   ustack->
						   uip_buf[uip_ip_tcph_len +
							   UIP_LLH_LEN + 1 +
							   c] ==
						   TCP_OPT_MSS_LEN) {
						/* An MSS option with the right
						   option length. */
						tmp16 =
						    (ustack->
						     uip_buf[uip_ip_tcph_len +
							     UIP_LLH_LEN + 2 +
							     c] << 8) | ustack->
						    uip_buf[uip_ip_tcph_len +
							    UIP_LLH_LEN + 3 +
							    c];
						uip_connr->initialmss =
						    uip_connr->mss =
						    tmp16 >
						    UIP_TCP_MSS ? UIP_TCP_MSS :
						    tmp16;

						/* And we are done processing
						   options. */
						break;
					} else {
						/* All other options have a
						   length field, so that we
						   easily can skip past them */
						if (ustack->
						    uip_buf[uip_ip_tcph_len +
							    UIP_LLH_LEN + 1 +
							    c] == 0) {
							/* If the length field
							   is zero, the options
							   are malformed and we
							   don't process them
							   further. */
							break;
						}
						if ((ustack->uip_buf[uip_ip_tcph_len
							  + UIP_LLH_LEN + 1 +
							  c]) > (256 - c)) {
							/* u8 overflow, actually there should
							 * never be more than 40 bytes of
							 * options */
							break;
						}
						c += ustack->
						    uip_buf[uip_ip_tcph_len +
							    UIP_LLH_LEN + 1 +
							    c];
					}
				}
			}
			uip_connr->tcpstateflags = UIP_ESTABLISHED;
			uip_connr->rcv_nxt[0] = tcp_hdr->seqno[0];
			uip_connr->rcv_nxt[1] = tcp_hdr->seqno[1];
			uip_connr->rcv_nxt[2] = tcp_hdr->seqno[2];
			uip_connr->rcv_nxt[3] = tcp_hdr->seqno[3];
			uip_add_rcv_nxt(ustack, 1);
			ustack->uip_flags = UIP_CONNECTED | UIP_NEWDATA;
			uip_connr->len = 0;
			ustack->uip_len = 0;
			ustack->uip_slen = 0;
			UIP_APPCALL(ustack);
			goto appsend;
		}
		/* Inform the application that the connection failed */
		ustack->uip_flags = UIP_ABORT;
		UIP_APPCALL(ustack);
		/* The connection is closed after we send the RST */
		ustack->uip_conn->tcpstateflags = UIP_CLOSED;
		goto reset;
#endif /* UIP_ACTIVE_OPEN */

	case UIP_ESTABLISHED:
		/* In the ESTABLISHED state, we call upon the application to
		   feed data into the uip_buf. If the UIP_ACKDATA flag is set,
		   the application should put new data into the buffer,
		   otherwise we are retransmitting an old segment, and the
		   application should put that data into the buffer.

		   If the incoming packet is a FIN, we should close the
		   connection on this side as well, and we send out a FIN and
		   enter the LAST_ACK state. We require that there is no
		   outstanding data; otherwise the sequence numbers will be
		   screwed up. */

		if (tcp_hdr->flags & TCP_FIN
		    && !(uip_connr->tcpstateflags & UIP_STOPPED)) {
			if (uip_outstanding(uip_connr))
				goto drop;
			uip_add_rcv_nxt(ustack, 1 + ustack->uip_len);
			ustack->uip_flags |= UIP_CLOSE;
			if (ustack->uip_len > 0)
				ustack->uip_flags |= UIP_NEWDATA;
			UIP_APPCALL(ustack);
			uip_connr->len = 1;
			uip_connr->tcpstateflags = UIP_LAST_ACK;
			uip_connr->nrtx = 0;
tcp_send_finack:
			tcp_hdr->flags = TCP_FIN | TCP_ACK;
			goto tcp_send_nodata;
		}

		/* Check the URG flag. If this is set, the segment carries
		   urgent data that we must pass to the application. */
		if ((tcp_hdr->flags & TCP_URG) != 0) {
#if UIP_URGDATA > 0
			uip_urglen = (tcp_hdr->urgp[0] << 8) | tcp_hdr->urgp[1];
			if (uip_urglen > uip_len) {
				/* There is more urgent data in the next segment
				   to come. */
				uip_urglen = uip_len;
			}
			uip_add_rcv_nxt(uip_urglen);
			uip_len -= uip_urglen;
			uip_urgdata = uip_appdata;
			uip_appdata += uip_urglen;
		} else {
			uip_urglen = 0;
#else /* UIP_URGDATA > 0 */
			tmp16 = (tcp_hdr->urgp[0] << 8) | tcp_hdr->urgp[1];
			if (tmp16 <= ustack->uip_len) {
				ustack->uip_appdata = ((char *)ustack->uip_appdata) + tmp16;
				ustack->uip_len -= tmp16;
			} else {
				/* invalid urgent pointer length greater than frame */
				/* we're discarding urgent data anyway, throw it all out */
				ustack->uip_appdata = ((char *)ustack->uip_appdata) + ustack->uip_len;
				ustack->uip_len = 0;
			}
#endif /* UIP_URGDATA > 0 */
		}

		/* If uip_len > 0 we have TCP data in the packet, and we flag
		   this by setting the UIP_NEWDATA flag and update the sequence
		   number we acknowledge. If the application has stopped the
		   dataflow using uip_stop(), we must not accept any data
		   packets from the remote host. */
		if (ustack->uip_len > 0
		    && !(uip_connr->tcpstateflags & UIP_STOPPED)) {
			ustack->uip_flags |= UIP_NEWDATA;
			uip_add_rcv_nxt(ustack, ustack->uip_len);
		}

		/* Check if the available buffer space advertised by the other
		   end is smaller than the initial MSS for this connection.
		   If so, we set the current MSS to the window size to ensure
		   that the application does not send more data than the other
		   end can handle.

		   If the remote host advertises a zero window, we set the MSS
		   to the initial MSS so that the application will send an
		   entire MSS of data. This data will not be acknowledged by
		   the receiver, and the application will retransmit it.
		   This is called the "persistent timer" and uses the
		   retransmission mechanim.
		 */
		tmp16 =
		    ((u16_t) tcp_hdr->wnd[0] << 8) + (u16_t) tcp_hdr->wnd[1];
		if (tmp16 > uip_connr->initialmss || tmp16 == 0)
			tmp16 = uip_connr->initialmss;
		uip_connr->mss = tmp16;

		/* If this packet constitutes an ACK for outstanding data
		   (flagged by the UIP_ACKDATA flag, we should call the
		   application since it might want to send more data.
		   If the incoming packet had data from the peer
		   (as flagged by the UIP_NEWDATA flag), the application
		   must also be notified.

		   When the application is called, the global variable uip_len
		   contains the length of the incoming data. The application can
		   access the incoming data through the global pointer
		   uip_appdata, which usually points uip_ip_tcph_len +
		   UIP_LLH_LEN bytes into the uip_buf array.

		   If the application wishes to send any data, this data should
		   be put into the uip_appdata and the length of the data should
		   be put into uip_len. If the application don't have any data
		   to send, uip_len must be set to 0. */
		if (ustack->uip_flags & (UIP_NEWDATA | UIP_ACKDATA)) {
			ustack->uip_slen = 0;
			UIP_APPCALL(ustack);

appsend:

			if (ustack->uip_flags & UIP_ABORT) {
				ustack->uip_slen = 0;
				uip_connr->tcpstateflags = UIP_CLOSED;
				tcp_hdr->flags = TCP_RST | TCP_ACK;
				goto tcp_send_nodata;
			}

			if (ustack->uip_flags & UIP_CLOSE) {
				ustack->uip_slen = 0;
				uip_connr->len = 1;
				uip_connr->tcpstateflags = UIP_FIN_WAIT_1;
				uip_connr->nrtx = 0;
				tcp_hdr->flags = TCP_FIN | TCP_ACK;
				goto tcp_send_nodata;
			}

			/* If uip_slen > 0, the application has data to be sent
			 */
			if (ustack->uip_slen > 0) {

				/* If the connection has acknowledged data, the
				   contents of the ->len variable should be
				   discarded. */
				if ((ustack->uip_flags & UIP_ACKDATA) != 0)
					uip_connr->len = 0;

				/* If the ->len variable is non-zero the
				   connection has already data in transit and
				   cannot send anymore right now. */
				if (uip_connr->len == 0) {

					/* The application cannot send more than
					   what is allowed by the mss (the
					   minumum of the MSS and the available
					   window). */
					if (ustack->uip_slen > uip_connr->mss) {
						ustack->uip_slen =
						    uip_connr->mss;
					}

					/* Remember how much data we send out
					   now so that we know when everything
					   has been acknowledged. */
					uip_connr->len = ustack->uip_slen;
				} else {

					/* If the application already had
					   unacknowledged data, we make sure
					   that the application does not send
					   (i.e., retransmit) out more than it
					   previously sent out. */
					ustack->uip_slen = uip_connr->len;
				}
			}
			uip_connr->nrtx = 0;
apprexmit:
			ustack->uip_appdata = ustack->uip_sappdata;

			/* If the application has data to be sent, or if the
			   incoming packet had new data in it, we must send
			   out a packet. */
			if (ustack->uip_slen > 0 && uip_connr->len > 0) {
				/* Add the length of the IP and TCP headers. */
				ustack->uip_len =
				    uip_connr->len + uip_ip_tcph_len;
				/* We always set the ACK flag in response
				   packets. */
				tcp_hdr->flags = TCP_ACK | TCP_PSH;
				/* Send the packet. */
				goto tcp_send_noopts;
			}
			/* If there is no data to send, just send out a pure ACK
			   if there is newdata. */
			if (ustack->uip_flags & UIP_NEWDATA) {
				ustack->uip_len = uip_ip_tcph_len;
				tcp_hdr->flags = TCP_ACK;
				goto tcp_send_noopts;
			}
		}
		goto drop;
	case UIP_LAST_ACK:
		/* We can close this connection if the peer has acknowledged our
		   FIN. This is indicated by the UIP_ACKDATA flag. */
		if (ustack->uip_flags & UIP_ACKDATA) {
			uip_connr->tcpstateflags = UIP_CLOSED;
			ustack->uip_flags = UIP_CLOSE;
			UIP_APPCALL(ustack);
		}
		break;

	case UIP_FIN_WAIT_1:
		/* The application has closed the connection, but the remote
		   host hasn't closed its end yet. Thus we do nothing but wait
		   for a FIN from the other side. */
		if (ustack->uip_len > 0)
			uip_add_rcv_nxt(ustack, ustack->uip_len);
		if (tcp_hdr->flags & TCP_FIN) {
			if (ustack->uip_flags & UIP_ACKDATA) {
				uip_connr->tcpstateflags = UIP_TIME_WAIT;
				uip_connr->timer = 0;
				uip_connr->len = 0;
			} else {
				uip_connr->tcpstateflags = UIP_CLOSING;
			}
			uip_add_rcv_nxt(ustack, 1);
			ustack->uip_flags = UIP_CLOSE;
			UIP_APPCALL(ustack);
			goto tcp_send_ack;
		} else if (ustack->uip_flags & UIP_ACKDATA) {
			uip_connr->tcpstateflags = UIP_FIN_WAIT_2;
			uip_connr->len = 0;
			goto drop;
		}
		if (ustack->uip_len > 0)
			goto tcp_send_ack;
		goto drop;

	case UIP_FIN_WAIT_2:
		if (ustack->uip_len > 0)
			uip_add_rcv_nxt(ustack, ustack->uip_len);
		if (tcp_hdr->flags & TCP_FIN) {
			uip_connr->tcpstateflags = UIP_TIME_WAIT;
			uip_connr->timer = 0;
			uip_add_rcv_nxt(ustack, 1);
			ustack->uip_flags = UIP_CLOSE;
			UIP_APPCALL(ustack);
			goto tcp_send_ack;
		}
		if (ustack->uip_len > 0)
			goto tcp_send_ack;
		goto drop;

	case UIP_TIME_WAIT:
		goto tcp_send_ack;

	case UIP_CLOSING:
		if (ustack->uip_flags & UIP_ACKDATA) {
			uip_connr->tcpstateflags = UIP_TIME_WAIT;
			uip_connr->timer = 0;
		}
	}
	goto drop;

	/* We jump here when we are ready to send the packet, and just want
	   to set the appropriate TCP sequence numbers in the TCP header. */
tcp_send_ack:
	tcp_hdr->flags = TCP_ACK;
tcp_send_nodata:
	ustack->uip_len = uip_ip_tcph_len;
tcp_send_noopts:
	tcp_hdr->tcpoffset = (UIP_TCPH_LEN / 4) << 4;
tcp_send:
	/* We're done with the input processing. We are now ready to send a
	   reply. Our job is to fill in all the fields of the TCP and IP
	   headers before calculating the checksum and finally send the
	   packet. */
	tcp_hdr->ackno[0] = uip_connr->rcv_nxt[0];
	tcp_hdr->ackno[1] = uip_connr->rcv_nxt[1];
	tcp_hdr->ackno[2] = uip_connr->rcv_nxt[2];
	tcp_hdr->ackno[3] = uip_connr->rcv_nxt[3];

	tcp_hdr->seqno[0] = uip_connr->snd_nxt[0];
	tcp_hdr->seqno[1] = uip_connr->snd_nxt[1];
	tcp_hdr->seqno[2] = uip_connr->snd_nxt[2];
	tcp_hdr->seqno[3] = uip_connr->snd_nxt[3];

	if (is_ipv6(ustack)) {
		IPv6_BUF(ustack)->proto = UIP_PROTO_TCP;
		uip_ip6addr_copy(IPv6_BUF(ustack)->srcipaddr,
				 ustack->hostaddr6);
		uip_ip6addr_copy(IPv6_BUF(ustack)->destipaddr,
				 uip_connr->ripaddr6);
	} else {
		tcp_ipv4_hdr->proto = UIP_PROTO_TCP;
		uip_ip4addr_copy(tcp_ipv4_hdr->srcipaddr, ustack->hostaddr);
		uip_ip4addr_copy(tcp_ipv4_hdr->destipaddr, uip_connr->ripaddr);
	}

	tcp_hdr->srcport = uip_connr->lport;
	tcp_hdr->destport = uip_connr->rport;

	if (uip_connr->tcpstateflags & UIP_STOPPED) {
		/* If the connection has issued uip_stop(), we advertise a zero
		   window so that the remote host will stop sending data. */
		tcp_hdr->wnd[0] = tcp_hdr->wnd[1] = 0;
	} else {
		tcp_hdr->wnd[0] = ((UIP_RECEIVE_WINDOW) >> 8);
		tcp_hdr->wnd[1] = ((UIP_RECEIVE_WINDOW) & 0xff);
	}

tcp_send_noconn:
	if (is_ipv6(ustack)) {
		IPv6_BUF(ustack)->ttl = UIP_TTL;

		/* For IPv6, the IP length field does not include the IPv6 IP
		   header length. */
		IPv6_BUF(ustack)->len[0] =
		    ((ustack->uip_len - uip_iph_len) >> 8);
		IPv6_BUF(ustack)->len[1] =
		    ((ustack->uip_len - uip_iph_len) & 0xff);
	} else {
		tcp_ipv4_hdr->ttl = UIP_TTL;
		tcp_ipv4_hdr->len[0] = (ustack->uip_len >> 8);
		tcp_ipv4_hdr->len[1] = (ustack->uip_len & 0xff);
	}

	tcp_hdr->urgp[0] = tcp_hdr->urgp[1] = 0;

	/* Calculate TCP checksum. */
	tcp_hdr->tcpchksum = 0;
	tcp_hdr->tcpchksum = ~(uip_tcpchksum(ustack));

ip_send_nolen:

	if (!is_ipv6(ustack)) {
		tcp_ipv4_hdr->vhl = 0x45;
		tcp_ipv4_hdr->tos = 0;
		tcp_ipv4_hdr->ipoffset[0] = tcp_ipv4_hdr->ipoffset[1] = 0;
		++ustack->ipid;
		tcp_ipv4_hdr->ipid[0] = ustack->ipid >> 8;
		tcp_ipv4_hdr->ipid[1] = ustack->ipid & 0xff;
		/* Calculate IP checksum. */
		tcp_ipv4_hdr->ipchksum = 0;
		tcp_ipv4_hdr->ipchksum = ~(uip_ipchksum(ustack));
	}

	++ustack->stats.tcp.sent;
send:
	if (is_ipv6(ustack)) {
		LOG_DEBUG(PFX "Sending packet with length %d (%d)",
			  ustack->uip_len, ipv6_hdr ? ipv6_hdr->ip6_plen : 0);
	} else {
		LOG_DEBUG(PFX "Sending packet with length %d (%d)",
			  ustack->uip_len,
			  (tcp_ipv4_hdr->len[0] << 8) | tcp_ipv4_hdr->len[1]);
	}
	++ustack->stats.ip.sent;
	/* Return and let the caller do the actual transmission. */
	ustack->uip_flags = 0;
	return;
drop:
	ustack->uip_len = 0;
	ustack->uip_flags = 0;
	return;
}

/*---------------------------------------------------------------------------*/
void uip_send(struct uip_stack *ustack, const void *data, int len)
{
	if (len > 0) {
		ustack->uip_slen = len;
		if (data != ustack->uip_buf)
			memcpy(ustack->uip_buf, (data), ustack->uip_slen);
	}
}

void uip_appsend(struct uip_stack *ustack, const void *data, int len)
{
	if (len > 0) {
		ustack->uip_slen = len;
		if (data != ustack->uip_sappdata)
			memcpy(ustack->uip_sappdata, (data), ustack->uip_slen);
	}
}

u16_t uip_datalen(struct uip_stack *ustack)
{
	return ustack->uip_len;
}

/** @} */
