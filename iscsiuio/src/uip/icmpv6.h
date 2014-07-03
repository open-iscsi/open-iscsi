/*
 * Copyright (c) 2011, Broadcom Corporation
 * Copyright (c) 2014, QLogic Corporation
 *
 * Written by: Eddie Wai  (eddie.wai@broadcom.com)
 *             Based on Kevin Tran's iSCSI boot code
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
 * icmpv6.h - This file contains macro definitions pertaining to ICMPv6
 *
 *     RFC 2463 : ICMPv6 Specification
 *     RFC 2461 : Neighbor Discovery for IPv6
 *
 */
#ifndef __ICMPV6_H__
#define __ICMPV6_H__

/* Base ICMP Header sizes */
#define IPV6_RTR_SOL_HDR_SIZE           8
#define IPV6_RTR_ADV_HDR_SIZE           16
#define IPV6_NEIGH_SOL_HDR_SIZE         24
#define IPV6_NEIGH_ADV_HDR_SIZE         24
#define IPV6_LINK_LAYER_OPT_SIZE        2
#define IPV6_LINK_LAYER_OPT_LENGTH      8
#define IPV6_MTU_OPT_SIZE               8
#define IPV6_PREFIX_OPT_SIZE            32
#define IPV6_ECHO_REQUEST_HDR_SIZE      8
#define IPV6_ECHO_REPLY_HDR_SIZE        8
#define IPV6_REDIRECT_SIZE              40
#define IPV6_DHAAD_REQ_HDR_SIZE         8
#define IPV6_DHAAD_REPLY_HDR_SIZE       8
#define IPV6_PRFXSOL_HDR_SIZE           8
#define IPV6_PRFXADV_HDR_SIZE           8
#define IPV6_RTR_ADV_INT_OPT_SIZE       8

/* ICMP Message Types */
/* Error messages are always less than 128 */
#define ICMPV6_DST_UNREACH           1	/* Destination Unreachable */
#define ICMPV6_PACKET_TOO_BIG        2	/* Packet Too Big */
#define ICMPV6_TIME_EXCEEDED         3	/* Time Exceeded */
#define ICMPV6_PARAM_PROB            4	/* Parameter Problem */

#define ICMPV6_RTR_SOL               133	/* Router Solicitation */
#define ICMPV6_RTR_ADV               134	/* Router Advertisement */
#define ICMPV6_NEIGH_SOL             135	/* Neighbor Solicitation */
#define ICMPV6_NEIGH_ADV             136	/* Neighbor Advertisement */
#define ICMPV6_REDIRECT              137	/* Redirect */
#define ICMPV6_ECHO_REQUEST          128	/* Echo Request */
#define ICMPV6_ECHO_REPLY            129	/* Echo Reply */
#define ICMPV6_WRUREQUEST            139	/* Who Are You Request */
#define ICMPV6_WRUREPLY              140	/* Who Are You Reply */
#define ICMPV6_ROUTER_RENUMBERING    138	/* Router Renumbering */
#define ICMPV6_HA_ADDR_DISC_REQ      144	/* Dynamic Home Agent Address
						   Discovery Request */
#define ICMPV6_HA_ADDR_DISC_REPLY    145	/* Dynamic Home Agent Address
						   Discovery Reply */
#define ICMPV6_MP_SOLICIT            146	/* Mobile Prefix Solicitation */
#define ICMPV6_MP_ADV                147	/* Mobile Prefix Reply */

/* Destination Unreachable Codes */
#define ICMPV6_DST_UNREACH_NOROUTE   0
#define ICMPV6_DST_UNREACH_ADMIN     1
#define ICMPV6_DST_UNREACH_ADDRESS   3
#define ICMPV6_DST_UNREACH_PORT      4

/* Time Exceeded Codes */
#define ICMPV6_TIME_EXCD_HPLMT       0	/* Hop Limit exceeded in transit */
#define ICMPV6_TIME_EXCD_REASM       1	/* Fragment reassembly time exceeded */

/* Parameter Problem Codes */
#define ICMPV6_PARM_PROB_HEADER      0
#define ICMPV6_PARM_PROB_NEXT_HDR    1
#define ICMPV6_PARM_PROB_OPTION      2

/* ICMP Option Types */
#define IPV6_ICMP_OPTION_SRC_ADDR       1	/* Source Link-Layer Address */
#define IPV6_ICMP_OPTION_TAR_ADDR       2	/* Target Link-Layer Address */
#define IPV6_ICMP_OPTION_PREFIX         3	/* Prefix */
#define IPV6_ICMP_OPTION_RED_HDR        4	/* Redirect Header */
#define IPV6_ICMP_OPTION_MTU            5	/* Link MTU */
#define IPV6_ICMP_OPTION_RTR_ADV_INT    7	/* Rtr Advertisement Interval */

/* ICMP Offsets */
#define IPV6_ICMP_TYPE_OFFSET                   0
#define IPV6_ICMP_CODE_OFFSET                   1
#define IPV6_ICMP_CKSUM_OFFSET                  2
#define IPV6_ICMP_RESERVED_OFFSET               4
#define IPV6_ICMP_DATA_OFFSET                   8

/* ICMP Router Solicitation Offsets */
#define IPV6_ICMP_RTR_SOL_RES_OFFSET            4
#define IPV6_ICMP_RTR_SOL_OPTIONS_OFFSET        8

/* ICMP Router Advertisement Offsets */
#define IPV6_ICMP_RTR_ADV_CURHOPLMT_OFFSET      4
#define IPV6_ICMP_RTR_ADV_MGDANDCFG_BIT_OFFSET  5
#define IPV6_ICMP_RTR_ADV_RTR_LIFETIME_OFFSET   6
#define IPV6_ICMP_RTR_ADV_RCHBL_TIME_OFFSET     8
#define IPV6_ICMP_RTR_ADV_RTRNS_TMR_OFFSET      12
#define IPV6_ICMP_RTR_ADV_OPTIONS_OFFSET        16

/* ICMP Neighbor Solicitation Offsets */
#define IPV6_ICMP_NEIGH_SOL_RES_OFFSET          4
#define IPV6_ICMP_NEIGH_SOL_TRGT_ADDRS_OFFSET   8
#define IPV6_ICMP_NEIGH_SOL_OPTIONS_OFFSET      24

/* ICMP Neighbor Advertisement Offsets */
#define IPV6_ICMP_NEIGH_ADV_FLAG_OFFSET         4
#define IPV6_ICMP_NEIGH_ADV_TRGT_ADDRS_OFFSET   8
#define IPV6_ICMP_NEIGH_ADV_OPTIONS_OFFSET      24

/* ICMP Redirect Offsets */
#define IPV6_ICMP_REDIRECT_TRGT_ADDRS_OFFSET    8
#define IPV6_ICMP_REDIRECT_DEST_ADDRS_OFFSET    24
#define IPV6_ICMP_REDIRECT_OPTIONS_OFFSET       40

/* ICMP Option Offsets */
#define IPV6_ICMP_OPTION_TYPE_OFFSET            0
#define IPV6_ICMP_OPTION_LENGTH_OFFSET          1

/* ICMP Link-Layer Address Option Offsets */
#define IPV6_ICMP_LL_OPTION_ADDRESS_OFFSET      2

/* ICMP Prefix Option Offsets */
#define IPV6_ICMP_PREFIX_PRE_LENGTH_OFFSET      2
#define IPV6_ICMP_PREFIX_FLAG_OFFSET            3
#define IPV6_ICMP_PREFIX_VALID_LIFETIME_OFFSET  4
#define IPV6_ICMP_PREFIX_PREF_LIFETIME_OFFSET   8
#define IPV6_ICMP_PREFIX_RES2_OFFSET            12
#define IPV6_ICMP_PREFIX_PREFIX_OFFSET          16

/* ICMP Redirected Header Option Offsets */
#define IPV6_ICMP_RED_OPTION_TYPE_OFFSET        0
#define IPV6_ICMP_RED_OPTION_LEN_OFFSET         1
#define IPV6_ICMP_RED_OPTION_RES1_OFFSET        2
#define IPV6_ICMP_RED_OPTION_RES2_OFFSET        4
#define IPV6_ICMP_RED_OPTION_DATA_OFFSET        8

/* ICMP MTU Option Offsets */
#define IPV6_ICMP_MTU_RESERVED_OFFSET           2
#define IPV6_ICMP_MTU_OFFSET                    4

/* ICMP Echo Request Offsets */
#define IPV6_ICMP_ECHO_ID                       4
#define IPV6_ICMP_ECHO_SEQ                      6
#define IPV6_ICMP_ECHO_DATA                     8

/* ICMP Destination Unreachable Offsets */
#define IPV6_DST_UNREACH_UNUSED                 4
#define IPV6_DST_UNREACH_DATA                   8

/* ICMP Parameter Problem Offsets */
#define IPV6_PARAM_PROB_PTR                     4
#define IPV6_PARAM_PROT_DATA                    8

/* ICMP Time Exceeded Offsets */
#define IPV6_TIME_EXCEEDED_DATA                 8

/* ICMP Packet Too Big Offsets */
#define IPV6_PKT_TOO_BIG_MTU                    4
#define IPV6_PKT_TOO_BIG_DATA                   8

/* Home Agent Address Discovery Request Header Offsets */
#define ICMPV6_HA_ADDR_DISC_REQ_ID_OFFSET        4
#define ICMPV6_HA_ADDR_DISC_REQ_RSVD_OFFSET      6

/* Home Agent Address Discovery Reply Header Offsets */
#define ICMPV6_HA_ADDR_DISC_REPLY_ID_OFFSET      4
#define ICMPV6_HA_ADDR_DISC_REPLY_RSVD_OFFSET    6
#define ICMPV6_HA_ADDR_DISC_REPLY_HA_ADDR_OFFSET 8

/* Mobile Prefix Solicitation Header Offsets */
#define ICMPV6_MP_SOLICIT_ID_OFFSET      4
#define ICMPV6_MP_SOLICIT_RSVD_OFFSET    6

/* Mobile Prefix Advertisement Header Offsets */
#define ICMPV6_MP_ADV_ID_OFFSET              4
#define ICMPV6_MP_ADV_MGDANDCFG_BIT_OFFSET   6
#define ICMPV6_MP_ADV_OPT_OFFSET             8

/* Advertisement Interval Option Header Offsets */
#define ICMPV6_ADV_INT_TYPE_OFFSET       0
#define ICMPV6_ADV_INT_LEN_OFFSET        1
#define ICMPV6_ADV_INT_RSVD_OFFSET       2
#define ICMPV6_ADV_INT_ADV_INT_OFFSET    4

#define ICMPV6_HEADER_LEN            4

#define IPV6_PREFIX_FLAG_ONLINK      0x80
#define IPV6_PREFIX_FLAG_AUTO        0x40
#define IPV6_PREFIX_FLAG_ROUTER      0x20

#define IPV6_NA_FLAG_ROUTER      0x80
#define IPV6_NA_FLAG_SOLICITED   0x40
#define IPV6_NA_FLAG_OVERRIDE    0x20

/* Router Advertisement Flags */
#define IPV6_RA_MANAGED_FLAG     0x80
#define IPV6_RA_CONFIG_FLAG      0x40

/* Mobile Prefix Advertisement Flags */
#define IPV6_PA_MANAGED_FLAG     0x80
#define IPV6_PA_CONFIG_FLAG      0x40

/* Validation Values */
#define ICMPV6_VALID_HOP_LIMIT           255	/* Valid Hop Limit */
#define ICMPV6_VALID_CODE                0	/* Valid Code */
#define ICMPV6_RTRSOL_MIN_LENGTH         8	/* Minimum valid length for
						   Router Solicitation */
#define ICMPV6_RTRADV_MIN_LENGTH         16	/* Minimum valid length for
						   Router Advertisement */
#define ICMPV6_NEIGHSOL_MIN_LENGTH       24	/* Minimum valid length for
						   Neighbor Solicitation */
#define ICMPV6_NEIGHADV_MIN_LENGTH       24	/* Minimum valid length for
						   Neighbor Advertisement */
#define ICMPV6_REDIRECT_MIN_LENGTH       40	/* Minimum valid length for
						   Neighbor Advertisement */

/* ICMPV6 Header */
struct icmpv6_hdr {
	u8_t icmpv6_type;	/* type field */
	u8_t icmpv6_code;	/* code field */
	u16_t icmpv6_cksum;	/* checksum field */
	union {
		u32_t icmpv6_un_data32[1];	/* type-specific field */
		u16_t icmpv6_un_data16[2];	/* type-specific field */
		u8_t icmpv6_un_data8[4];	/* type-specific field */
	} data;
};

#define icmpv6_data  data.icmpv6_un_data32[0]

struct icmpv6_opt_hdr {
	u8_t type;
	u8_t len;
};

struct icmpv6_opt_link_addr {
	struct icmpv6_opt_hdr hdr;
	u8_t link_addr[6];
};

struct icmpv6_opt_prefix {
	struct icmpv6_opt_hdr hdr;
	u8_t prefix_len;
	u8_t flags;
#define ICMPV6_OPT_PREFIX_FLAG_ON_LINK  (1 << 7)
#define ICMPV6_OPT_PREFIX_FLAG_BIT_A    (1 << 6)
	u32_t valid_lifetime;
	u32_t preferred_lifetime;
	u32_t reserved;
	struct ipv6_addr prefix;
};

/* Neighbor Solicitation */
struct icmpv6_nd_solicit {
	struct icmpv6_hdr nd_ns_hdr;
};

/* Router Advertisement */
struct icmpv6_router_advert {
	struct icmpv6_hdr header;
	u32_t reachable_time;
	u32_t retransmit_timer;
};

#define nd_ra_type              header.icmpv6_type
#define nd_ra_code              header.icmpv6_code
#define nd_ra_cksum             header.icmpv6_cksum
#define nd_ra_curhoplimit       header.data.icmpv6_un_data8[0]
#define nd_ra_flags_reserved    header.data.icmpv6_un_data8[1]
#define nd_ra_router_lifetime   header.data.icmpv6_un_data16[1]

#endif /*  __ICMPV6_H__ */
