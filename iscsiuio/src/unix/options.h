/*
 * Copyright (c) 2009-2011, Broadcom Corporation
 * Copyright (c) 2014, QLogic Corporation
 *
 * Written by:  Benjamin Li  (benli@broadcom.com)
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
 * options.h - CNIC UIO uIP user space stack
 *
 */
#ifndef __OPTIONS_H__
#define __OPTIONS_H__

#include <byteswap.h>
#include <time.h>
#include <sys/types.h>

/******************************************************************************
 * Constants which are tuned at compile time by the user
 *****************************************************************************/

/**
 * MAX_COUNT_NIC_NL_RESP - This is the maximum number of polls uIP will
 *                         try for a kernel response after a PATH_REQ
 */
#define MAX_COUNT_NIC_NL_RESP 128

/**
 * NLM_BUF_DEFAULT_MAX - This is the buffer size allocated for the send/receive
 *                       buffers used by the uIP Netlink subsystem.  This
 *                       value is in bytes.
 */
#define NLM_BUF_DEFAULT_MAX	8192	/* bytes */

/******************************************************************************
 * Non adjustable constants
 *****************************************************************************/
#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP                    0x0800	/* IP */
#endif /* ETHERTYPE_IP */

#ifndef ETHERTYPE_IPV6
#define ETHERTYPE_IPV6                  0x86dd	/* IP protocol version 6 */
#endif /* ETHERTYPE_IPV6 */

#ifndef ETHERTYPE_ARP
#define ETHERTYPE_ARP                   0x0806	/* Address resolution */
#endif /* ETHERTYPE_ARP */

#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN                  0x8100	/* IEEE 802.1Q VLAN tagging */
#endif /* ETHERTYPE_VLAN */

#define APP_NAME "iscsiuio"
/* BUILD_DATE is automatically generated from the Makefile */

#define DEBUG_OFF	0x1
#define DEBUG_ON	0x2

#define INVALID_FD	-1
#define INVALID_THREAD	(pthread_t)-1
#define INVALID_HOST_NO	-1

struct options {
	char debug;

	/*  Time the userspace daemon was started */
	time_t start_time;
};

extern int event_loop_stop;
extern struct options opt;

#ifdef WORDS_BIGENDIAN
#define ntohll(x)  (x)
#define htonll(x)  (x)
#else
#define ntohll(x)  bswap_64(x)
#define htonll(x)  bswap_64(x)
#endif

# define likely(x)      __builtin_expect(!!(x), 1)
# define unlikely(x)    __builtin_expect(!!(x), 0)

/*  taken from Linux kernel, include/linux/compiler-gcc.h */
/* Optimization barrier */
/* The "volatile" is due to gcc bugs */
#define barrier() __asm__ __volatile__("": : :"memory")

#endif
