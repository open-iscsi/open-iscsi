
/**
 * \addtogroup uip
 * @{
 */

/**
 * \file
 * Header file for the uIP TCP/IP stack.
 * \author Adam Dunkels <adam@dunkels.com>
 *
 * The uIP TCP/IP stack header file contains definitions for a number
 * of C macros that are used by uIP programs as well as internal uIP
 * structures, TCP/IP header structures and function declarations.
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

#ifndef __UIP_H__
#define __UIP_H__

#include <netinet/in.h>
#include <pthread.h>

#include "uipopt.h"

#include "debug.h"

#include "uip_eth.h"

/*  Forware declaration */
struct uip_stack;

/**
 * Repressentation of an IP address.
 *
 */
typedef u16_t uip_ip4addr_t[2];
typedef u16_t uip_ip6addr_t[8];

const uip_ip6addr_t all_zeroes_addr6;
const uip_ip4addr_t all_zeroes_addr4;

#define ETH_BUF(buf) ((struct uip_eth_hdr *)buf)
#define VLAN_ETH_BUF(buf) ((struct uip_vlan_eth_hdr *)buf)
#define IPv4_BUF(buf) ((struct uip_tcp_ipv4_hdr *)buf)
#define IPv6_BUF(buf) ((struct uip_tcp_ipv6_hdr *)buf)

/*---------------------------------------------------------------------------*/
/* First, the functions that should be called from the
 * system. Initialization, the periodic timer and incoming packets are
 * handled by the following three functions.
 */

/**
 * Set the IP address of this host.
 *
 * The IP address is represented as a 4-byte array where the first
 * octet of the IP address is put in the first member of the 4-byte
 * array.
 *
 * Example:
 \code

 uip_ipaddr_t addr;

 uip_ipaddr(&addr, 192,168,1,2);
 uip_sethostaddr(&addr);

 \endcode
 * \param addr A pointer to an IP address of type uip_ipaddr_t;
 *
 * \sa uip_ipaddr()
 *
 * \hideinitializer
 */
void uip_sethostaddr4(struct uip_stack *ustack, uip_ip4addr_t *addr);

/**
 * Set the default router's IP address.
 *
 * \param addr A pointer to a uip_ipaddr_t variable containing the IP
 * address of the default router.
 *
 * \sa uip_ipaddr()
 *
 * \hideinitializer
 */
void uip_setdraddr4(struct uip_stack *ustack, uip_ip4addr_t *addr);

/**
 * Set the netmask.
 *
 * \param addr A pointer to a uip_ipaddr_t variable containing the IP
 * address of the netmask.
 *
 * \sa uip_ipaddr()
 *
 * \hideinitializer
 */
void uip_setnetmask4(struct uip_stack *ustack, uip_ip4addr_t *addr);

/**
 * Set the ethernet MAC address.
 *
 * \param addr A pointer to a uip_ipaddr_t variable containing the IP
 * address of the netmask.
 *
 * \sa uip_ipaddr()
 *
 * \hideinitializer
 */
void uip_setethernetmac(struct uip_stack *ustack, uint8_t *mac);

/**
 * Get the default router's IP address.
 *
 * \param addr A pointer to a uip_ipaddr_t variable that will be
 * filled in with the IP address of the default router.
 *
 * \hideinitializer
 */
#define uip_getdraddr(addr) uip_ipaddr_copy((addr), uip_draddr)

/**
 * Get the netmask.
 *
 * \param addr A pointer to a uip_ipaddr_t variable that will be
 * filled in with the value of the netmask.
 *
 * \hideinitializer
 */
#define uip_getnetmask(addr) uip_ipaddr_copy((addr), uip_netmask)

void set_uip_stack(struct uip_stack *ustack,
		   uip_ip4addr_t *ip,
		   uip_ip4addr_t *netmask,
		   uip_ip4addr_t *default_route, uint8_t *mac_addr);

/** @} */

/**
 * \defgroup uipinit uIP initialization functions
 * @{
 *
 * The uIP initialization functions are used for booting uIP.
 */

/**
 * uIP initialization function.
 *
 * This function should be called at boot up to initilize the uIP
 * TCP/IP stack.
 */
void uip_init(struct uip_stack *ustack, uint8_t enable_ipv6);

/**
 * uIP reset function.
 *
 * This function should be called at to reset the uIP TCP/IP stack.
 */
void uip_reset(struct uip_stack *ustack);

/**
 * uIP initialization function.
 *
 * This function may be used at boot time to set the initial ip_id.
 */
void uip_setipid(u16_t id);

/**
 *
 *
 */
#define uip_conn_active(conn) (uip_conns[conn].tcpstateflags != UIP_CLOSED)

#if UIP_UDP
void uip_udp_periodic(struct uip_stack *ustack, int conn);
#endif /* UIP_UDP */

void uip_ndp_periodic(struct uip_stack *ustack);

/**
 * The uIP packet buffer.
 *
 * The uip_buf array is used to hold incoming and outgoing
 * packets. The device driver should place incoming data into this
 * buffer. When sending data, the device driver should read the link
 * level headers and the TCP/IP headers from this buffer. The size of
 * the link level headers is configured by the UIP_LLH_LEN define.
 *
 * \note The application data need not be placed in this buffer, so
 * the device driver must read it from the place pointed to by the
 * uip_appdata pointer as illustrated by the following example:
 \code
 void
 devicedriver_send(void)
 {
    hwsend(&uip_buf[0], UIP_LLH_LEN);
    if(uip_len <= UIP_LLH_LEN + UIP_TCPIP_HLEN) {
      hwsend(&uip_buf[UIP_LLH_LEN], uip_len - UIP_LLH_LEN);
    } else {
      hwsend(&uip_buf[UIP_LLH_LEN], UIP_TCPIP_HLEN);
      hwsend(uip_appdata, uip_len - UIP_TCPIP_HLEN - UIP_LLH_LEN);
    }
 }
 \endcode
 */
/*extern u8_t uip_buf[UIP_BUFSIZE+2]; */

/** @} */

/*---------------------------------------------------------------------------*/
/* Functions that are used by the uIP application program. Opening and
 * closing connections, sending and receiving data, etc. is all
 * handled by the functions below.
*/
/**
 * \defgroup uipappfunc uIP application functions
 * @{
 *
 * Functions used by an application running of top of uIP.
 */

/**
 * Start listening to the specified port.
 *
 * \note Since this function expects the port number in network byte
 * order, a conversion using HTONS() or htons() is necessary.
 *
 \code
 uip_listen(HTONS(80));
 \endcode
 *
 * \param port A 16-bit port number in network byte order.
 */
void uip_listen(struct uip_stack *ustack, u16_t port);

/**
 * Stop listening to the specified port.
 *
 * \note Since this function expects the port number in network byte
 * order, a conversion using HTONS() or htons() is necessary.
 *
 \code
 uip_unlisten(HTONS(80));
 \endcode
 *
 * \param port A 16-bit port number in network byte order.
 */
void uip_unlisten(struct uip_stack *ustack, u16_t port);

/**
 * Connect to a remote host using TCP.
 *
 * This function is used to start a new connection to the specified
 * port on the specied host. It allocates a new connection identifier,
 * sets the connection to the SYN_SENT state and sets the
 * retransmission timer to 0. This will cause a TCP SYN segment to be
 * sent out the next time this connection is periodically processed,
 * which usually is done within 0.5 seconds after the call to
 * uip_connect().
 *
 * \note This function is avaliable only if support for active open
 * has been configured by defining UIP_ACTIVE_OPEN to 1 in uipopt.h.
 *
 * \note Since this function requires the port number to be in network
 * byte order, a conversion using HTONS() or htons() is necessary.
 *
 \code
 uip_ipaddr_t ipaddr;

 uip_ipaddr(&ipaddr, 192,168,1,2);
 uip_connect(&ipaddr, HTONS(80));
 \endcode
 *
 * \param ripaddr The IP address of the remote hot.
 *
 * \param port A 16-bit port number in network byte order.
 *
 * \return A pointer to the uIP connection identifier for the new connection,
 * or NULL if no connection could be allocated.
 *
 */
struct uip_conn *uip_connect(struct uip_stack *ustack,
			     uip_ip4addr_t *ripaddr, u16_t port);

/**
 * \internal
 *
 * Check if a connection has outstanding (i.e., unacknowledged) data.
 *
 * \param conn A pointer to the uip_conn structure for the connection.
 *
 * \hideinitializer
 */
#define uip_outstanding(conn) ((conn)->len)

/**
 * Send data on the current connection.
 *
 * This function is used to send out a single segment of TCP
 * data. Only applications that have been invoked by uIP for event
 * processing can send data.
 *
 * The amount of data that actually is sent out after a call to this
 * funcion is determined by the maximum amount of data TCP allows. uIP
 * will automatically crop the data so that only the appropriate
 * amount of data is sent. The function uip_mss() can be used to query
 * uIP for the amount of data that actually will be sent.
 *
 * \note This function does not guarantee that the sent data will
 * arrive at the destination. If the data is lost in the network, the
 * application will be invoked with the uip_rexmit() event being
 * set. The application will then have to resend the data using this
 * function.
 *
 * \param data A pointer to the data which is to be sent.
 *
 * \param len The maximum amount of data bytes to be sent.
 *
 * \hideinitializer
 */
void uip_send(struct uip_stack *ustack, const void *data, int len);
void uip_appsend(struct uip_stack *ustack, const void *data, int len);

/**
 * The length of any incoming data that is currently avaliable (if avaliable)
 * in the uip_appdata buffer.
 *
 * The test function uip_data() must first be used to check if there
 * is any data available at all.
 *
 * \hideinitializer
 */
/*void uip_datalen(void);*/
u16_t uip_datalen(struct uip_stack *ustack);

/**
 * The length of any out-of-band data (urgent data) that has arrived
 * on the connection.
 *
 * \note The configuration parameter UIP_URGDATA must be set for this
 * function to be enabled.
 *
 * \hideinitializer
 */
#define uip_urgdatalen()    uip_urglen

/**
 * Close the current connection.
 *
 * This function will close the current connection in a nice way.
 *
 * \hideinitializer
 */
#define uip_close()         (uip_flags = UIP_CLOSE)

/**
 * Abort the current connection.
 *
 * This function will abort (reset) the current connection, and is
 * usually used when an error has occured that prevents using the
 * uip_close() function.
 *
 * \hideinitializer
 */
#define uip_abort()         (uip_flags = UIP_ABORT)

/**
 * Tell the sending host to stop sending data.
 *
 * This function will close our receiver's window so that we stop
 * receiving data for the current connection.
 *
 * \hideinitializer
 */
#define uip_stop()          (uip_conn->tcpstateflags |= UIP_STOPPED)

/**
 * Find out if the current connection has been previously stopped with
 * uip_stop().
 *
 * \hideinitializer
 */
#define uip_stopped(conn)   ((conn)->tcpstateflags & UIP_STOPPED)

/**
 * Restart the current connection, if is has previously been stopped
 * with uip_stop().
 *
 * This function will open the receiver's window again so that we
 * start receiving data for the current connection.
 *
 * \hideinitializer
 */
#define uip_restart()	do { uip_flags |= UIP_NEWDATA; \
				uip_conn->tcpstateflags &= ~UIP_STOPPED; \
			} while (0)

/* uIP tests that can be made to determine in what state the current
   connection is, and what the application function should do. */

/**
 * Is the current connection a UDP connection?
 *
 * This function checks whether the current connection is a UDP connection.
 *
 * \hideinitializer
 *
 */
#define uip_udpconnection() (uip_conn == NULL)

/**
 *  Function declarations for hte uip_flags
 */
/**
 * Is new incoming data available?
 *
 * Will reduce to non-zero if there is new data for the application
 * present at the uip_appdata pointer. The size of the data is
 * avaliable through the uip_len variable.
 *
 * \hideinitializer
 */
int uip_newdata(struct uip_stack *ustack);

/**
 * Has previously sent data been acknowledged?
 *
 * Will reduce to non-zero if the previously sent data has been
 * acknowledged by the remote host. This means that the application
 * can send new data.
 *
 * \hideinitializer
 */
int uip_acked(struct uip_stack *ustack);

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
int uip_connected(struct uip_stack *ustack);

/**
 * Has the connection been closed by the other end?
 *
 * Is non-zero if the connection has been closed by the remote
 * host. The application may then do the necessary clean-ups.
 *
 * \hideinitializer
 */
int uip_closed(struct uip_stack *ustack);

/**
 * Has the connection been aborted by the other end?
 *
 * Non-zero if the current connection has been aborted (reset) by the
 * remote host.
 *
 * \hideinitializer
 */
int uip_aborted(struct uip_stack *ustack);

/**
 * Has the connection timed out?
 *
 * Non-zero if the current connection has been aborted due to too many
 * retransmissions.
 *
 * \hideinitializer
 */
int uip_timedout(struct uip_stack *ustack);

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
int uip_rexmit(struct uip_stack *ustack);

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
int uip_poll(struct uip_stack *ustack);

/**
 * Get the initial maxium segment size (MSS) of the current
 * connection.
 *
 * \hideinitializer
 */
int uip_initialmss(struct uip_stack *ustack);

/**
 * Get the current maxium segment size that can be sent on the current
 * connection.
 *
 * The current maxiumum segment size that can be sent on the
 * connection is computed from the receiver's window and the MSS of
 * the connection (which also is available by calling
 * uip_initialmss()).
 *
 * \hideinitializer
 */
int uip_mss(struct uip_stack *ustack);

/**
 * Set up a new UDP connection.
 *
 * This function sets up a new UDP connection. The function will
 * automatically allocate an unused local port for the new
 * connection. However, another port can be chosen by using the
 * uip_udp_bind() call, after the uip_udp_new() function has been
 * called.
 *
 * Example:
 \code
 uip_ipaddr_t addr;
 struct uip_udp_conn *c;

 uip_ipaddr(&addr, 192,168,2,1);
 c = uip_udp_new(&addr, HTONS(12345));
 if(c != NULL) {
   uip_udp_bind(c, HTONS(12344));
 }
 \endcode
 * \param ripaddr The IP address of the remote host.
 *
 * \param rport The remote port number in network byte order.
 *
 * \return The uip_udp_conn structure for the new connection or NULL
 * if no connection could be allocated.
 */
struct uip_udp_conn *uip_udp_new(struct uip_stack *ustack,
				 uip_ip4addr_t *ripaddr, u16_t rport);

/**
 * Removed a UDP connection.
 *
 * \param conn A pointer to the uip_udp_conn structure for the connection.
 *
 * \hideinitializer
 */
#define uip_udp_remove(conn) ((conn)->lport = 0)

/**
 * Bind a UDP connection to a local port.
 *
 * \param conn A pointer to the uip_udp_conn structure for the
 * connection.
 *
 * \param port The local port number, in network byte order.
 *
 * \hideinitializer
 */
#define uip_udp_bind(conn, port) ((conn)->lport = port)

/**
 * Send a UDP datagram of length len on the current connection.
 *
 * This function can only be called in response to a UDP event (poll
 * or newdata). The data must be present in the uip_buf buffer, at the
 * place pointed to by the uip_appdata pointer.
 *
 * \param len The length of the data in the uip_buf buffer.
 *
 * \hideinitializer
 */
#define uip_udp_send(len) uip_appsend((char *)uip_appdata, len)

/** @} */

/* uIP convenience and converting functions. */

/**
 * \defgroup uipconvfunc uIP conversion functions
 * @{
 *
 * These functions can be used for converting between different data
 * formats used by uIP.
 */

/**
 * Construct an IP address from four bytes.
 *
 * This function constructs an IP address of the type that uIP handles
 * internally from four bytes. The function is handy for specifying IP
 * addresses to use with e.g. the uip_connect() function.
 *
 * Example:
 \code
 uip_ipaddr_t ipaddr;
 struct uip_conn *c;

 uip_ipaddr(&ipaddr, 192,168,1,2);
 c = uip_connect(&ipaddr, HTONS(80));
 \endcode
 *
 * \param addr A pointer to a uip_ipaddr_t variable that will be
 * filled in with the IP address.
 *
 * \param addr0 The first octet of the IP address.
 * \param addr1 The second octet of the IP address.
 * \param addr2 The third octet of the IP address.
 * \param addr3 The forth octet of the IP address.
 *
 * \hideinitializer
 */
#define uip_ipaddr(addr, addr0, addr1, addr2, addr3) do { \
		((u16_t *)(addr))[0] = const_htons(((addr0) << 8) | (addr1)); \
		((u16_t *)(addr))[1] = const_htons(((addr2) << 8) | (addr3)); \
	} while (0)

/**
 * Construct an IPv6 address from eight 16-bit words.
 *
 * This function constructs an IPv6 address.
 *
 * \hideinitializer
 */
#define uip_ip6addr(addr, addr0, addr1, addr2, addr3, addr4, addr5, addr6, \
		    addr7)				\
	do {						\
		((u16_t *)(addr))[0] = HTONS((addr0));	\
		((u16_t *)(addr))[1] = HTONS((addr1));	\
		((u16_t *)(addr))[2] = HTONS((addr2));	\
		((u16_t *)(addr))[3] = HTONS((addr3));	\
		((u16_t *)(addr))[4] = HTONS((addr4));	\
		((u16_t *)(addr))[5] = HTONS((addr5));	\
		((u16_t *)(addr))[6] = HTONS((addr6));	\
		((u16_t *)(addr))[7] = HTONS((addr7));	\
	} while (0)

/**
 * Copy an IP address to another IP address.
 *
 * Copies an IP address from one place to another.
 *
 * Example:
 \code
 uip_ipaddr_t ipaddr1, ipaddr2;

 uip_ipaddr(&ipaddr1, 192,16,1,2);
 uip_ipaddr_copy(&ipaddr2, &ipaddr1);
 \endcode
 *
 * \param dest The destination for the copy.
 * \param src The source from where to copy.
 *
 * \hideinitializer
 */
#define uip_ip4addr_copy(dest, src) memcpy(dest, src, sizeof(uip_ip4addr_t))
#define uip_ip6addr_copy(dest, src) memcpy(dest, src, sizeof(uip_ip6addr_t))

/**
 * Compare two IP addresses
 *
 * Compares two IP addresses.
 *
 * Example:
 \code
 uip_ipaddr_t ipaddr1, ipaddr2;

 uip_ipaddr(&ipaddr1, 192,16,1,2);
 if(uip_ipaddr_cmp(&ipaddr2, &ipaddr1)) {
    printf("They are the same");
 }
 \endcode
 *
 * \param addr1 The first IP address.
 * \param addr2 The second IP address.
 *
 * \hideinitializer
 */
#define uip_ip4addr_cmp(addr1, addr2) (memcmp(addr1, addr2, \
				       sizeof(uip_ip4addr_t)) == 0)
#define uip_ip6addr_cmp(addr1, addr2) (memcmp(addr1, addr2, \
				       sizeof(uip_ip6addr_t)) == 0)

/**
 * Compare two IP addresses with netmasks
 *
 * Compares two IP addresses with netmasks. The masks are used to mask
 * out the bits that are to be compared.
 *
 * Example:
 \code
 uip_ipaddr_t ipaddr1, ipaddr2, mask;

 uip_ipaddr(&mask, 255,255,255,0);
 uip_ipaddr(&ipaddr1, 192,16,1,2);
 uip_ipaddr(&ipaddr2, 192,16,1,3);
 if(uip_ipaddr_maskcmp(&ipaddr1, &ipaddr2, &mask)) {
    printf("They are the same");
 }
 \endcode
 *
 * \param addr1 The first IP address.
 * \param addr2 The second IP address.
 * \param mask The netmask.
 *
 * \hideinitializer
 */
#define uip_ip4addr_maskcmp(addr1, addr2, mask) \
			(((((u16_t *)addr1)[0] & ((u16_t *)mask)[0]) == \
			(((u16_t *)addr2)[0] & ((u16_t *)mask)[0])) && \
			((((u16_t *)addr1)[1] & ((u16_t *)mask)[1]) == \
			(((u16_t *)addr2)[1] & ((u16_t *)mask)[1])))

/**
 * Mask out the network part of an IP address.
 *
 * Masks out the network part of an IP address, given the address and
 * the netmask.
 *
 * Example:
 \code
 uip_ipaddr_t ipaddr1, ipaddr2, netmask;

 uip_ipaddr(&ipaddr1, 192,16,1,2);
 uip_ipaddr(&netmask, 255,255,255,0);
 uip_ipaddr_mask(&ipaddr2, &ipaddr1, &netmask);
 \endcode
 *
 * In the example above, the variable "ipaddr2" will contain the IP
 * address 192.168.1.0.
 *
 * \param dest Where the result is to be placed.
 * \param src The IP address.
 * \param mask The netmask.
 *
 * \hideinitializer
 */
#define uip_ip4addr_mask(dest, src, mask) do { \
		((u16_t *)dest)[0] = ((u16_t *)src)[0] & ((u16_t *)mask)[0]; \
		((u16_t *)dest)[1] = ((u16_t *)src)[1] & ((u16_t *)mask)[1]; \
	} while (0)

/**
 * Pick the first octet of an IP address.
 *
 * Picks out the first octet of an IP address.
 *
 * Example:
 \code
 uip_ipaddr_t ipaddr;
 u8_t octet;

 uip_ipaddr(&ipaddr, 1,2,3,4);
 octet = uip_ipaddr1(&ipaddr);
 \endcode
 *
 * In the example above, the variable "octet" will contain the value 1.
 *
 * \hideinitializer
 */
#define uip_ipaddr1(addr) (htons(((u16_t *)(addr))[0]) >> 8)

/**
 * Pick the second octet of an IP address.
 *
 * Picks out the second octet of an IP address.
 *
 * Example:
 \code
 uip_ipaddr_t ipaddr;
 u8_t octet;

 uip_ipaddr(&ipaddr, 1,2,3,4);
 octet = uip_ipaddr2(&ipaddr);
 \endcode
 *
 * In the example above, the variable "octet" will contain the value 2.
 *
 * \hideinitializer
 */
#define uip_ipaddr2(addr) (htons(((u16_t *)(addr))[0]) & 0xff)

/**
 * Pick the third octet of an IP address.
 *
 * Picks out the third octet of an IP address.
 *
 * Example:
 \code
 uip_ipaddr_t ipaddr;
 u8_t octet;

 uip_ipaddr(&ipaddr, 1,2,3,4);
 octet = uip_ipaddr3(&ipaddr);
 \endcode
 *
 * In the example above, the variable "octet" will contain the value 3.
 *
 * \hideinitializer
 */
#define uip_ipaddr3(addr) (htons(((u16_t *)(addr))[1]) >> 8)

/**
 * Pick the fourth octet of an IP address.
 *
 * Picks out the fourth octet of an IP address.
 *
 * Example:
 \code
 uip_ipaddr_t ipaddr;
 u8_t octet;

 uip_ipaddr(&ipaddr, 1,2,3,4);
 octet = uip_ipaddr4(&ipaddr);
 \endcode
 *
 * In the example above, the variable "octet" will contain the value 4.
 *
 * \hideinitializer
 */
#define uip_ipaddr4(addr) (htons(((u16_t *)(addr))[1]) & 0xff)

/**
 * Convert 16-bit quantity from host byte order to network byte order.
 *
 * This macro is primarily used for converting constants from host
 * byte order to network byte order. For converting variables to
 * network byte order, use the htons() function instead.
 *
 * \hideinitializer
 */
#if 0
#ifndef HTONS
#   if UIP_BYTE_ORDER == UIP_BIG_ENDIAN
#      define HTONS(n) (n)
#   else /* UIP_BYTE_ORDER == UIP_BIG_ENDIAN */
#      define HTONS(n) (u16_t)((((u16_t) (n)) << 8) | (((u16_t) (n)) >> 8))
#   endif /* UIP_BYTE_ORDER == UIP_BIG_ENDIAN */
#else
#error "HTONS already defined!"
#endif /* HTONS */
#endif

#if UIP_BYTE_ORDER == UIP_BIG_ENDIAN
#      error "Should not be here"
#      define const_htons(n) (n)
#   else /* UIP_BYTE_ORDER == UIP_BIG_ENDIAN */
#     define const_htons(n) (u16_t)((((u16_t) (n)) << 8) | (((u16_t) (n)) >> 8))
#   endif /* UIP_BYTE_ORDER == UIP_BIG_ENDIAN */

/*  BWL */
#if 0
/**
 * Convert 16-bit quantity from host byte order to network byte order.
 *
 * This function is primarily used for converting variables from host
 * byte order to network byte order. For converting constants to
 * network byte order, use the HTONS() macro instead.
 */
#ifndef htons
u16_t htons(u16_t val);
#endif /* htons */
#ifndef ntohs
#define ntohs htons
#endif
#endif

/** @} */

/**
 * Pointer to the application data in the packet buffer.
 *
 * This pointer points to the application data when the application is
 * called. If the application wishes to send data, the application may
 * use this space to write the data into before calling uip_send().
 */
/* extern void *uip_appdata; */

#if UIP_URGDATA > 0
/* u8_t *uip_urgdata:
 *
 * This pointer points to any urgent data that has been received. Only
 * present if compiled with support for urgent data (UIP_URGDATA).
 */
extern void *uip_urgdata;
#endif /* UIP_URGDATA > 0 */

/**
 * \defgroup uipdrivervars Variables used in uIP device drivers
 * @{
 *
 * uIP has a few global variables that are used in device drivers for
 * uIP.
 */

/**
 * The length of the packet in the uip_buf buffer.
 *
 * The global variable uip_len holds the length of the packet in the
 * uip_buf buffer.
 *
 * When the network device driver calls the uIP input function,
 * uip_len should be set to the length of the packet in the uip_buf
 * buffer.
 *
 * When sending packets, the device driver should use the contents of
 * the uip_len variable to determine the length of the outgoing
 * packet.
 *
 */
/* extern u16_t uip_len; */

/** @} */

#if UIP_URGDATA > 0
extern u16_t uip_urglen, uip_surglen;
#endif /* UIP_URGDATA > 0 */

/**
 * Representation of a uIP TCP connection.
 *
 * The uip_conn structure is used for identifying a connection. All
 * but one field in the structure are to be considered read-only by an
 * application. The only exception is the appstate field whos purpose
 * is to let the application store application-specific state (e.g.,
 * file pointers) for the connection. The type of this field is
 * configured in the "uipopt.h" header file.
 */
struct __attribute__ ((__packed__)) uip_conn {
	uip_ip4addr_t ripaddr;
	uip_ip6addr_t ripaddr6;
			   /**< The IP address of the remote host. */

	u16_t lport;  /**< The local TCP port, in network byte order. */
	u16_t rport;  /**< The local remote TCP port, in network byte
			 order. */

	u8_t rcv_nxt[4];
		      /**< The sequence number that we expect to
			 receive next. */
	u8_t snd_nxt[4];
		      /**< The sequence number that was last sent by
			 us. */
	u16_t len;    /**< Length of the data that was previously sent. */
	u16_t mss;    /**< Current maximum segment size for the
			 connection. */
	u16_t initialmss;
		      /**< Initial maximum segment size for the
			 connection. */
	u8_t sa;      /**< Retransmission time-out calculation state
			 variable. */
	u8_t sv;      /**< Retransmission time-out calculation state
			 variable. */
	u8_t rto;     /**< Retransmission time-out. */
	u8_t tcpstateflags;
		      /**< TCP state and flags. */
	u8_t timer;   /**< The retransmission timer. */
	u8_t nrtx;    /**< The number of retransmissions for the last
			 segment sent. */
};

/**
 * \addtogroup uiparch
 * @{
 */

/**
 * 4-byte array used for the 32-bit sequence number calculations.
 */
extern u8_t uip_acc32[4];

/** @} */

#if UIP_UDP
/**
 * Representation of a uIP UDP connection.
 */
struct uip_udp_conn {
	uip_ip4addr_t ripaddr;
			   /**< The IP address of the remote peer. */
	u16_t lport;  /**< The local port number in network byte order. */
	u16_t rport;  /**< The remote port number in network byte order. */
	u8_t ttl;     /**< Default time-to-live. */

  /** The application state. */
/* uip_udp_appstate_t appstate; */
};

#endif /* UIP_UDP */

/**
 * The structure holding the TCP/IP statistics that are gathered if
 * UIP_STATISTICS is set to 1.
 *
 */
struct uip_stats {
	struct {
		uip_stats_t drop;
			  /**< Number of dropped packets at the IP
			     layer. */
		uip_stats_t recv;
			  /**< Number of received packets at the IP
			     layer. */
		uip_stats_t sent;
			  /**< Number of sent packets at the IP
			     layer. */
		uip_stats_t vhlerr;
			  /**< Number of packets dropped due to wrong
			     IP version or header length. */
		uip_stats_t hblenerr;
			  /**< Number of packets dropped due to wrong
			     IP length, high byte. */
		uip_stats_t lblenerr;
			  /**< Number of packets dropped due to wrong
			     IP length, low byte. */
		uip_stats_t fragerr;
			  /**< Number of packets dropped since they
			     were IP fragments. */
		uip_stats_t chkerr;
			  /**< Number of packets dropped due to IP
			     checksum errors. */
		uip_stats_t protoerr;
			  /**< Number of packets dropped since they
			     were neither ICMP, UDP nor TCP. */
	} ip;		  /**< IP statistics. */
	struct {
		uip_stats_t drop;
			  /**< Number of dropped ICMP packets. */
		uip_stats_t recv;
			  /**< Number of received ICMP packets. */
		uip_stats_t sent;
			  /**< Number of sent ICMP packets. */
		uip_stats_t typeerr;
			  /**< Number of ICMP packets with a wrong
			     type. */
	} icmp;		  /**< ICMP statistics. */
	struct {
		uip_stats_t drop;
			  /**< Number of dropped TCP segments. */
		uip_stats_t recv;
			  /**< Number of recived TCP segments. */
		uip_stats_t sent;
			  /**< Number of sent TCP segments. */
		uip_stats_t chkerr;
			  /**< Number of TCP segments with a bad
			     checksum. */
		uip_stats_t ackerr;
			  /**< Number of TCP segments with a bad ACK
			     number. */
		uip_stats_t rst;
			  /**< Number of recevied TCP RST (reset) segments. */
		uip_stats_t rexmit;
			  /**< Number of retransmitted TCP segments. */
		uip_stats_t syndrop;
			  /**< Number of dropped SYNs due to too few
			     connections was avaliable. */
		uip_stats_t synrst;
			  /**< Number of SYNs for closed ports,
			     triggering a RST. */
	} tcp;		  /**< TCP statistics. */
#if UIP_UDP
	struct {
		uip_stats_t drop;
			  /**< Number of dropped UDP segments. */
		uip_stats_t recv;
			  /**< Number of recived UDP segments. */
		uip_stats_t sent;
			  /**< Number of sent UDP segments. */
		uip_stats_t chkerr;
			  /**< Number of UDP segments with a bad
			     checksum. */
	} udp;		  /**< UDP statistics. */
#endif				/* UIP_UDP */
};

/*---------------------------------------------------------------------------*/
/* All the stuff below this point is internal to uIP and should not be
 * used directly by an application or by a device driver.
 */
/*---------------------------------------------------------------------------*/
/* u8_t uip_flags:
 *
 * When the application is called, uip_flags will contain the flags
 * that are defined in this file. Please read below for more
 * infomation.
 */
/* extern u8_t uip_flags; */

/* The following flags may be set in the global variable uip_flags
   before calling the application callback. The UIP_ACKDATA,
   UIP_NEWDATA, and UIP_CLOSE flags may both be set at the same time,
   whereas the others are mutualy exclusive. Note that these flags
   should *NOT* be accessed directly, but only through the uIP
   functions/macros. */

#define UIP_ACKDATA   1		/* Signifies that the outstanding data was
				   acked and the application should send
				   out new data instead of retransmitting
				   the last data. */
#define UIP_NEWDATA   2		/* Flags the fact that the peer has sent
				   us new data. */
#define UIP_REXMIT    4		/* Tells the application to retransmit the
				   data that was last sent. */
#define UIP_POLL      8		/* Used for polling the application, to
				   check if the application has data that
				   it wants to send. */
#define UIP_CLOSE     16	/* The remote host has closed the
				   connection, thus the connection has
				   gone away. Or the application signals
				   that it wants to close the
				   connection. */
#define UIP_ABORT     32	/* The remote host has aborted the
				   connection, thus the connection has
				   gone away. Or the application signals
				   that it wants to abort the
				   connection. */
#define UIP_CONNECTED 64	/* We have got a connection from a remote
				   host and have set up a new connection
				   for it, or an active connection has
				   been successfully established. */

#define UIP_TIMEDOUT  128	/* The connection has been aborted due to
				   too many retransmissions. */

void uip_input(struct uip_stack *ustack);
void uip_periodic(struct uip_stack *ustack, int conn);

/* uip_process(flag):
 *
 * The actual uIP function which does all the work.
 */
void uip_process(struct uip_stack *ustack, u8_t flag);

/* The following flags are passed as an argument to the uip_process()
   function. They are used to distinguish between the two cases where
   uip_process() is called. It can be called either because we have
   incoming data that should be processed, or because the periodic
   timer has fired. These values are never used directly, but only in
   the macrose defined in this file. */

#define UIP_DATA          1	/* Tells uIP that there is incoming
				   data in the uip_buf buffer. The
				   length of the data is stored in the
				   global variable uip_len. */
#define UIP_TIMER         2	/* Tells uIP that the periodic timer
				   has fired. */
#define UIP_POLL_REQUEST  3	/* Tells uIP that a connection should
				   be polled. */
#define UIP_UDP_SEND_CONN 4	/* Tells uIP that a UDP datagram
				   should be constructed in the
				   uip_buf buffer. */
#if UIP_UDP
#define UIP_UDP_TIMER     5
#endif /* UIP_UDP */

#define UIP_NDP_TIMER     6

/* The TCP states used in the uip_conn->tcpstateflags. */
#define UIP_CLOSED      0
#define UIP_SYN_RCVD    1
#define UIP_SYN_SENT    2
#define UIP_ESTABLISHED 3
#define UIP_FIN_WAIT_1  4
#define UIP_FIN_WAIT_2  5
#define UIP_CLOSING     6
#define UIP_TIME_WAIT   7
#define UIP_LAST_ACK    8
#define UIP_TS_MASK     15

#define UIP_STOPPED      16

struct __attribute__ ((__packed__)) uip_tcp_hdr {
	/* TCP header. */
	u16_t srcport, destport;
	u8_t seqno[4], ackno[4], tcpoffset, flags, wnd[2];
	u16_t tcpchksum;
	u8_t urgp[2];
	u8_t optdata[4];
};

struct __attribute__ ((__packed__)) uip_ipv4_hdr {
	/* IPv4 header. */
	u8_t vhl, tos, len[2], ipid[2], ipoffset[2], ttl, proto;
	u16_t ipchksum;
	u16_t srcipaddr[2], destipaddr[2];
};

struct __attribute__ ((__packed__)) uip_ipv6_hdr {
	/* IPv6 header. */
	u8_t vtc, tcflow;
	u16_t flow;
	u16_t len;
	u8_t proto, ttl;
	uip_ip6addr_t srcipaddr, destipaddr;
};

/* The TCP and IPv4 headers. */
struct __attribute__ ((__packed__)) uip_tcp_ipv4_hdr {
	/* IPv4 header. */
	u8_t vhl, tos, len[2], ipid[2], ipoffset[2], ttl, proto;
	u16_t ipchksum;
	u16_t srcipaddr[2], destipaddr[2];

	/* TCP header. */
	u16_t srcport, destport;
	u8_t seqno[4], ackno[4], tcpoffset, flags, wnd[2];
	u16_t tcpchksum;
	u8_t urgp[2];
	u8_t optdata[4];
};

/* The TCP and IP headers. */
struct __attribute__ ((__packed__)) uip_tcp_ipv6_hdr {
	/* IPv6 header. */
	u8_t vtc, tcflow;
	u16_t flow;
	u8_t len[2];
	u8_t proto, ttl;
	uip_ip6addr_t srcipaddr, destipaddr;

	/* TCP header. */
	u16_t srcport, destport;
	u8_t seqno[4], ackno[4], tcpoffset, flags, wnd[2];
	u16_t tcpchksum;
	u8_t urgp[2];
	u8_t optdata[4];
};

/* The ICMPv4 */
struct __attribute__ ((__packed__)) uip_icmpv4_hdr {
	/* ICMP (echo) header. */
	u8_t type, icode;
	u16_t icmpchksum;
	u16_t id, seqno;
};

typedef struct uip_icmpv4_hdr uip_icmp_echo_hdr_t;

/* The ICMPv6 */
struct __attribute__ ((__packed__)) uip_icmpv6_hdr {
	/* ICMP (echo) header. */
	u8_t type, icode;
	u16_t icmpchksum;
	u8_t flags, reserved1, reserved2, reserved3;
	u8_t icmp6data[16];
	u8_t options[1];
};

/* The ICMP and IP headers. */
struct __attribute__ ((__packed__)) uip_icmpip_hdr {
#if UIP_CONF_IPV6
	/* IPv6 header. */
	u8_t vtc, tcf;
	u16_t flow;
	u8_t len[2];
	u8_t proto, ttl;
	uip_ip6addr_t srcipaddr, destipaddr;
#else /* UIP_CONF_IPV6 */
	/* IPv4 header. */
	u8_t vhl, tos, len[2], ipid[2], ipoffset[2], ttl, proto;
	u16_t ipchksum;
	u16_t srcipaddr[2], destipaddr[2];
#endif /* UIP_CONF_IPV6 */

	/* ICMP (echo) header. */
	u8_t type, icode;
	u16_t icmpchksum;
#if !UIP_CONF_IPV6
	u16_t id, seqno;
#else /* !UIP_CONF_IPV6 */
	u8_t flags, reserved1, reserved2, reserved3;
	u8_t icmp6data[16];
	u8_t options[1];
#endif /* !UIP_CONF_IPV6 */
};

/* The UDP  */
struct __attribute__ ((__packed__)) uip_udp_hdr {
	/* UDP header. */
	u16_t srcport, destport;
	u16_t udplen;
	u16_t udpchksum;
};

/* The UDP and IP headers. */
struct __attribute__ ((__packed__)) uip_udpip_hdr {
#if UIP_CONF_IPV6
	/* IPv6 header. */
	u8_t vtc, tcf;
	u16_t flow;
	u8_t len[2];
	u8_t proto, ttl;
	uip_ip6addr_t srcipaddr, destipaddr;
#else /* UIP_CONF_IPV6 */
	/* IP header. */
	u8_t vhl, tos, len[2], ipid[2], ipoffset[2], ttl, proto;
	u16_t ipchksum;
	u16_t srcipaddr[2], destipaddr[2];
#endif /* UIP_CONF_IPV6 */

	/* UDP header. */
	u16_t srcport, destport;
	u16_t udplen;
	u16_t udpchksum;
};

/**
 * The buffer size available for user data in the \ref uip_buf buffer.
 *
 * This macro holds the available size for user data in the \ref
 * uip_buf buffer. The macro is intended to be used for checking
 * bounds of available user data.
 *
 * Example:
 \code
 snprintf(uip_appdata, UIP_APPDATA_SIZE, "%u\n", i);
 \endcode
 *
 * \hideinitializer
 */
#define UIP_APPDATA_SIZE (UIP_BUFSIZE - UIP_LLH_LEN - UIP_TCPIP_HLEN)

#define UIP_PROTO_ICMP  1
#define UIP_PROTO_TCP   6
#define UIP_PROTO_UDP   17
#define UIP_PROTO_ICMP6 58

/* Header sizes. */
#define UIP_IPv6_H_LEN    40	/* Size of IPv6 header */
#define UIP_IPv4_H_LEN    20	/* Size of IPv4 header */

#define UIP_UDPH_LEN    8	/* Size of UDP header */
#define UIP_TCPH_LEN   20	/* Size of TCP header */

#define UIP_IPv4_UDPH_LEN (UIP_UDPH_LEN + UIP_IPv4_H_LEN)	/* Size of IPv4
								   + UDP
								   header */
#define UIP_IPv4_TCPH_LEN (UIP_TCPH_LEN + UIP_IPv4_H_LEN)	/* Size of IPv4
								   + TCP
								   header */
#define UIP_TCP_IPv4_HLEN UIP_IPv4_TCPH_LEN

#define UIP_IPv6_UDPH_LEN (UIP_UDPH_LEN + UIP_IPv6_H_LEN)	/* Size of IPv6
								   + UDP
								   header */
#define UIP_IPv6_TCPH_LEN (UIP_TCPH_LEN + UIP_IPv6_H_LEN)	/* Size of IPv6
								   + TCP
								   header */
#define UIP_TCP_IPv6_HLEN UIP_IPv6_TCPH_LEN

/**
 * Calculate the Internet checksum over a buffer.
 *
 * The Internet checksum is the one's complement of the one's
 * complement sum of all 16-bit words in the buffer.
 *
 * See RFC1071.
 *
 * \param buf A pointer to the buffer over which the checksum is to be
 * computed.
 *
 * \param len The length of the buffer over which the checksum is to
 * be computed.
 *
 * \return The Internet checksum of the buffer.
 */
u16_t uip_chksum(u16_t *buf, u16_t len);

/**
 * Calculate the IP header checksum of the packet header in uip_buf.
 *
 * The IP header checksum is the Internet checksum of the 20 bytes of
 * the IP header.
 *
 * \return The IP header checksum of the IP header in the uip_buf
 * buffer.
 */
u16_t uip_ipchksum(struct uip_stack *ustack);

/**
 * Calculate the TCP checksum of the packet in uip_buf and uip_appdata.
 *
 * The TCP checksum is the Internet checksum of data contents of the
 * TCP segment, and a pseudo-header as defined in RFC793.
 *
 * \return The TCP checksum of the TCP segment in uip_buf and pointed
 * to by uip_appdata.
 */
u16_t uip_tcpchksum(struct uip_stack *ustack);

/**
 * Calculate the UDP checksum of the packet in uip_buf and uip_appdata.
 *
 * The UDP checksum is the Internet checksum of data contents of the
 * UDP segment, and a pseudo-header as defined in RFC768.
 *
 * \return The UDP checksum of the UDP segment in uip_buf and pointed
 * to by uip_appdata.
 */
u16_t uip_udpchksum(struct uip_stack *ustack);

/*  IPv6 checksum */
uint16_t icmpv6_checksum(uint8_t *data);

struct neighbor_entry {
	struct in6_addr ipaddr;
	struct uip_eth_addr mac_addr;
	u8_t time;
};

struct uip_stack {
	struct uip_eth_addr uip_ethaddr;

	u8_t *uip_buf;

	uint8_t *data_link_layer;	/* Pointer to the data link layer */
	uint8_t *network_layer;	/* Pointer to the network layer   */
	void *uip_appdata;	/* The uip_appdata pointer points to
				   application data. */
	void *uip_sappdata;	/* The uip_appdata pointer points to
				   the application data which is to
				   be sent. */
#if UIP_URGDATA > 0
	void *uip_urgdata;	/* The uip_urgdata pointer points to
				   urgent data (out-of-band data), if
				   present. */
	u16_t uip_urglen, uip_surglen;
#endif				/* UIP_URGDATA > 0 */

	u16_t uip_len, uip_slen;	/* The uip_len is either 8 or 16 bits,
					   depending on the maximum packet
					   size. */
	u8_t uip_flags;		/* The uip_flags variable is used for
				   communication between the TCP/IP stack
				   and the application program. */
	struct uip_conn *uip_conn;	/* uip_conn always points to the current
					   connection. */

	struct uip_conn uip_conns[UIP_CONNS];
	/* The uip_conns array holds all TCP
	   connections. */
	u16_t uip_listenports[UIP_LISTENPORTS];
	/* The uip_listenports list all currently
	   listning ports. */
#if UIP_UDP
	struct uip_udp_conn *uip_udp_conn;
	struct uip_udp_conn uip_udp_conns[UIP_UDP_CONNS];
#endif				/* UIP_UDP */

	u16_t ipid;		/* This ipid variable is an increasing
				   number that is used for the IP ID
				   field. */

	u8_t iss[4];		/* The iss variable is used for the TCP
				   initial sequence number. */

#if UIP_ACTIVE_OPEN
	u16_t lastport;		/* Keeps track of the last port used for
				   a new connection. */
#endif				/* UIP_ACTIVE_OPEN */

#define IP_CONFIG_OFF			0x00
#define IPV4_CONFIG_OFF			0x01
#define IPV4_CONFIG_STATIC		0x02
#define IPV4_CONFIG_DHCP		0x04
#define IPV6_CONFIG_OFF			0x10
#define IPV6_CONFIG_STATIC		0x20
#define IPV6_CONFIG_DHCP		0x40
	u8_t ip_config;

	uip_ip4addr_t hostaddr, netmask, default_route_addr;
	uip_ip6addr_t hostaddr6, netmask6, default_route_addr6,
		      linklocal6;
	int prefix_len;
	u8_t ipv6_autocfg;
#define IPV6_AUTOCFG_DHCPV6		(1<<0)
#define IPV6_AUTOCFG_ND			(1<<1)
#define IPV6_AUTOCFG_NOTSPEC		(1<<6)
#define IPV6_AUTOCFG_NOTUSED		(1<<7)
	u8_t linklocal_autocfg;
#define IPV6_LL_AUTOCFG_ON		(1<<0)
#define IPV6_LL_AUTOCFG_OFF		(1<<1)
#define IPV6_LL_AUTOCFG_NOTSPEC		(1<<6)
#define IPV6_LL_AUTOCFG_NOTUSED		(1<<7)
	u8_t router_autocfg;
#define IPV6_RTR_AUTOCFG_ON		(1<<0)
#define IPV6_RTR_AUTOCFG_OFF		(1<<1)
#define IPV6_RTR_AUTOCFG_NOTSPEC	(1<<6)
#define IPV6_RTR_AUTOCFG_NOTUSED	(1<<7)

#define UIP_NEIGHBOR_ENTRIES 8
	struct neighbor_entry neighbor_entries[UIP_NEIGHBOR_ENTRIES];

	struct uip_stats stats;

	u8_t opt;

	pthread_mutex_t lock;

	/*  IPv6 support */
#define UIP_SUPPORT_IPv6_ENABLED	0x01
#define UIP_SUPPORT_IPv6_DISABLED	0x02
	u8_t enable_IPv6;

	/*  DHCPC client attached */
	void *dhcpc;

	/* NDP client */
	void *ndpc;

	void *ping_conf;
};

/*******************************************************************************
 * IPv6 Support
 ******************************************************************************/
int set_ipv6_link_local_address(struct uip_stack *ustack);
int is_ipv6_link_local_address(uip_ip6addr_t *addr);

void dump_uip_packet(struct uip_stack *ustack);
u16_t uip_icmp6chksum(struct uip_stack *ustack);

#endif /* __UIP_H__ */

/** @} */
