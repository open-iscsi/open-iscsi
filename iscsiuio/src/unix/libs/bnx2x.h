/*
 * Copyright (c) 2009-2011, Broadcom Corporation
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
 * bnx2x.h - bnx2x user space driver
 *
 */
#ifndef __BNX2X_H__
#define __BNX2X_H__

#include "nic.h"

/******************************************************************************
 *  Default CNIC values
 ******************************************************************************/
#define DEFAULT_BNX2X_NUM_RXBD	15
#define DEFAULT_BNX2X_RX_LEN	0x400

/******************************************************************************
 *  BNX2X Hardware structures
 ******************************************************************************/
#define HC_USTORM_DEF_SB_NUM_INDICES 8
#define HC_CSTORM_DEF_SB_NUM_INDICES 8
#define HC_XSTORM_DEF_SB_NUM_INDICES 4
#define HC_TSTORM_DEF_SB_NUM_INDICES 4

struct atten_def_status_block {
	volatile __u32 attn_bits;
	volatile __u32 attn_bits_ack;
	volatile __u8 status_block_id;
	volatile __u8 reserved0;
	volatile __u16 attn_bits_index;
	volatile __u32 reserved1;
};

struct cstorm_def_status_block_u {
	volatile __u16 index_values[HC_USTORM_DEF_SB_NUM_INDICES];
	volatile __u16 status_block_index;
	volatile __u8 func;
	volatile __u8 status_block_id;
	volatile __u32 __flags;
};

struct cstorm_def_status_block_c {
	volatile __u16 index_values[HC_CSTORM_DEF_SB_NUM_INDICES];
	volatile __u16 status_block_index;
	volatile __u8 func;
	volatile __u8 status_block_id;
	volatile __u32 __flags;
};

struct xstorm_def_status_block {
	volatile __u16 index_values[HC_XSTORM_DEF_SB_NUM_INDICES];
	volatile __u16 status_block_index;
	volatile __u8 func;
	volatile __u8 status_block_id;
	volatile __u32 __flags;
};

struct tstorm_def_status_block {
	volatile __u16 index_values[HC_TSTORM_DEF_SB_NUM_INDICES];
	volatile __u16 status_block_index;
	volatile __u8 func;
	volatile __u8 status_block_id;
	volatile __u32 __flags;
};

struct host_def_status_block {
	struct atten_def_status_block atten_status_block;
	struct cstorm_def_status_block_u u_def_status_block;
	struct cstorm_def_status_block_c c_def_status_block;
	struct xstorm_def_status_block x_def_status_block;
	struct tstorm_def_status_block t_def_status_block;
};

#define HC_INDEX_DEF_U_ETH_ISCSI_RX_CQ_CONS 1
#define HC_INDEX_DEF_U_ETH_ISCSI_RX_BD_CONS 3
#define HC_INDEX_DEF_C_ETH_ISCSI_CQ_CONS 5

struct atten_sp_status_block {
	__u32 attn_bits;
	__u32 attn_bits_ack;
	__u8 status_block_id;
	__u8 reserved0;
	__u16 attn_bits_index;
	__u32 reserved1;
};

#define HC_SP_SB_MAX_INDICES	16

struct hc_sp_status_block {
	__u16 index_values[HC_SP_SB_MAX_INDICES];
	__u16 running_index;
	__u16 rsrv;
	__u32 rsrv1;
};

struct host_sp_status_block {
	struct atten_sp_status_block atten_status_block;
	struct hc_sp_status_block sp_sb;
};

#define HC_SP_INDEX_ETH_ISCSI_CQ_CONS		5
#define HC_SP_INDEX_ETH_ISCSI_RX_CQ_CONS	1

/*
 * VLAN mode on TX BDs
 */
enum eth_tx_vlan_type {
	X_ETH_NO_VLAN = 0,
	X_ETH_OUTBAND_VLAN = 1,
	X_ETH_INBAND_VLAN = 2,
	X_ETH_FW_ADDED_VLAN = 3,
	MAX_ETH_TX_VLAN_TYPE
};

/*  TX Buffer descriptor */
struct eth_tx_bd_flags {
	__u8 as_bitfield;
/* t6.X HSI */
#define ETH_TX_BD_FLAGS_IP_CSUM_T6X (0x1<<0)
#define ETH_TX_BD_FLAGS_IP_CSUM_SHIFT_T6X 0
#define ETH_TX_BD_FLAGS_L4_CSUM_T6X (0x1<<1)
#define ETH_TX_BD_FLAGS_L4_CSUM_SHIFT_T6X 1
#define ETH_TX_BD_FLAGS_VLAN_MODE_T6X (0x3<<2)
#define ETH_TX_BD_FLAGS_VLAN_MODE_SHIFT_T6X 2
#define ETH_TX_BD_FLAGS_START_BD_T6X (0x1<<4)
#define ETH_TX_BD_FLAGS_START_BD_SHIFT_T6X 4
#define ETH_TX_BD_FLAGS_IS_UDP_T6X (0x1<<5)
#define ETH_TX_BD_FLAGS_IS_UDP_SHIFT_T6X 5
#define ETH_TX_BD_FLAGS_SW_LSO_T6X (0x1<<6)
#define ETH_TX_BD_FLAGS_SW_LSO_SHIFT_T6X 6
#define ETH_TX_BD_FLAGS_IPV6_T6X (0x1<<7)
#define ETH_TX_BD_FLAGS_IPV6_SHIFT_T6X 7

/* Legacy t5.2 HSI defines */
#define ETH_TX_BD_FLAGS_VLAN_TAG_T5X (0x1<<0)
#define ETH_TX_BD_FLAGS_VLAN_TAG_SHIFT_T5X 0
#define ETH_TX_BD_FLAGS_IP_CSUM_T5X (0x1<<1)
#define ETH_TX_BD_FLAGS_IP_CSUM_SHIFT_T5X 1
#define ETH_TX_BD_FLAGS_L4_CSUM_T5X (0x1<<2)
#define ETH_TX_BD_FLAGS_L4_CSUM_SHIFT_T5X 2
#define ETH_TX_BD_FLAGS_END_BD_T5X (0x1<<3)
#define ETH_TX_BD_FLAGS_END_BD_SHIFT_T5X 3
#define ETH_TX_BD_FLAGS_START_BD_T5X (0x1<<4)
#define ETH_TX_BD_FLAGS_START_BD_SHIFT_T5X 4
#define ETH_TX_BD_FLAGS_HDR_POOL_T5X (0x1<<5)
#define ETH_TX_BD_FLAGS_HDR_POOL_SHIFT_T5X 5
#define ETH_TX_BD_FLAGS_SW_LSO_T5X (0x1<<6)
#define ETH_TX_BD_FLAGS_SW_LSO_SHIFT_T5X 6
#define ETH_TX_BD_FLAGS_IPV6_T5X (0x1<<7)
#define ETH_TX_BD_FLAGS_IPV6_SHIFT_T5X 7
};

#define ETH_TX_BD_FLAGS_VLAN_TAG_T6X		\
	(X_ETH_OUTBAND_VLAN << ETH_TX_BD_FLAGS_VLAN_MODE_SHIFT_T6X)

#define BNX2X_SET_TX_VLAN(bp, txbd, vlan_id)				\
	do {								\
		if (vlan_id) {						\
			(txbd)->vlan = vlan_id;				\
			(txbd)->bd_flags.as_bitfield |=			\
				(bp)->tx_vlan_tag_bit;			\
		} else {						\
			(txbd)->vlan = (bp)->tx_prod;			\
			(txbd)->bd_flags.as_bitfield &=			\
				~(bp)->tx_vlan_tag_bit;			\
		}							\
	} while (0)

struct eth_tx_start_bd {
	__u32 addr_lo;
	__u32 addr_hi;
	__u16 nbd;
	__u16 nbytes;
	__u16 vlan;
	struct eth_tx_bd_flags bd_flags;
	__u8 general_data;
#define ETH_TX_START_BD_HDR_NBDS (0x3F<<0)
#define ETH_TX_START_BD_HDR_NBDS_SHIFT 0
#define ETH_TX_START_BD_ETH_ADDR_TYPE (0x3<<6)
#define ETH_TX_START_BD_ETH_ADDR_TYPE_SHIFT 6
};

struct eth_tx_bd {
	__u32 addr_lo;
	__u32 addr_hi;
	__u16 total_pkt_bytes;
	__u16 nbytes;
	__u8 reserved[4];
};

/*  RX Buffer descriptor */
struct eth_rx_bd {
	__u32 addr_lo;
	__u32 addr_hi;
};

struct ramrod_data {
	volatile __u32 data_lo;
	volatile __u32 data_hi;
};

struct common_ramrod_eth_rx_cqe {
	volatile __u8 ramrod_type;
#define COMMON_RAMROD_ETH_RX_CQE_TYPE (0x1<<0)
#define COMMON_RAMROD_ETH_RX_CQE_TYPE_SHIFT 0
#define COMMON_RAMROD_ETH_RX_CQE_RESERVED0 (0x7F<<1)
#define COMMON_RAMROD_ETH_RX_CQE_RESERVED0_SHIFT 1
	volatile __u8 conn_type;
	volatile __u16 reserved1;
	volatile __u32 conn_and_cmd_data;
#define COMMON_RAMROD_ETH_RX_CQE_CID (0xFFFFFF<<0)
#define COMMON_RAMROD_ETH_RX_CQE_CID_SHIFT 0
#define COMMON_RAMROD_ETH_RX_CQE_CMD_ID (0xFF<<24)
#define COMMON_RAMROD_ETH_RX_CQE_CMD_ID_SHIFT 24
	struct ramrod_data protocol_data;
	__u32 reserved2[4];
};

struct common_ramrod_eth_rx_cqe_70 {
	volatile __u8 ramrod_type;
	volatile __u8 conn_type;
	volatile __u16 reserved1;
	volatile __u32 conn_and_cmd_data;
	struct ramrod_data protocol_data;
	__u32 echo;
	__u32 reserved2[11];
};

struct parsing_flags {
	volatile __u16 flags;
};

struct eth_fast_path_rx_cqe {
	volatile __u8 type_error_flags;
#define ETH_FAST_PATH_RX_CQE_TYPE (0x1<<0)
#define ETH_FAST_PATH_RX_CQE_TYPE_SHIFT 0
#define ETH_FAST_PATH_RX_CQE_PHY_DECODE_ERR_FLG (0x1<<1)
#define ETH_FAST_PATH_RX_CQE_PHY_DECODE_ERR_FLG_SHIFT 1
#define ETH_FAST_PATH_RX_CQE_IP_BAD_XSUM_FLG (0x1<<2)
#define ETH_FAST_PATH_RX_CQE_IP_BAD_XSUM_FLG_SHIFT 2
#define ETH_FAST_PATH_RX_CQE_L4_BAD_XSUM_FLG (0x1<<3)
#define ETH_FAST_PATH_RX_CQE_L4_BAD_XSUM_FLG_SHIFT 3
#define ETH_FAST_PATH_RX_CQE_START_FLG (0x1<<4)
#define ETH_FAST_PATH_RX_CQE_START_FLG_SHIFT 4
#define ETH_FAST_PATH_RX_CQE_END_FLG (0x1<<5)
#define ETH_FAST_PATH_RX_CQE_END_FLG_SHIFT 5
#define ETH_FAST_PATH_RX_CQE_RESERVED0 (0x3<<6)
#define ETH_FAST_PATH_RX_CQE_RESERVED0_SHIFT 6
	volatile __u8 status_flags;
#define ETH_FAST_PATH_RX_CQE_RSS_HASH_TYPE (0x7<<0)
#define ETH_FAST_PATH_RX_CQE_RSS_HASH_TYPE_SHIFT 0
#define ETH_FAST_PATH_RX_CQE_RSS_HASH_FLG (0x1<<3)
#define ETH_FAST_PATH_RX_CQE_RSS_HASH_FLG_SHIFT 3
#define ETH_FAST_PATH_RX_CQE_BROADCAST_FLG (0x1<<4)
#define ETH_FAST_PATH_RX_CQE_BROADCAST_FLG_SHIFT 4
#define ETH_FAST_PATH_RX_CQE_MAC_MATCH_FLG (0x1<<5)
#define ETH_FAST_PATH_RX_CQE_MAC_MATCH_FLG_SHIFT 5
#define ETH_FAST_PATH_RX_CQE_IP_XSUM_NO_VALIDATION_FLG (0x1<<6)
#define ETH_FAST_PATH_RX_CQE_IP_XSUM_NO_VALIDATION_FLG_SHIFT 6
#define ETH_FAST_PATH_RX_CQE_L4_XSUM_NO_VALIDATION_FLG (0x1<<7)
#define ETH_FAST_PATH_RX_CQE_L4_XSUM_NO_VALIDATION_FLG_SHIFT 7
	volatile __u8 placement_offset;
	volatile __u8 queue_index;
	volatile __u32 rss_hash_result;
	volatile __u16 vlan_tag;
	volatile __u16 pkt_len;
	volatile __u16 len_on_bd;
	struct parsing_flags pars_flags;
	volatile __u16 sgl[8];
};

union eth_sgl_or_raw_data {
	volatile __u16 sgl[8];
	volatile __u32 raw_data[4];
};

struct eth_fast_path_rx_cqe_64 {
	volatile __u8 type_error_flags;
#define ETH_FAST_PATH_RX_CQE_TYPE_64 (0x3<<0)
#define ETH_FAST_PATH_RX_CQE_TYPE_SHIFT_64	0
#define ETH_FAST_PATH_RX_CQE_SGL_RAW_SEL (0x1<<2)
#define ETH_FAST_PATH_RX_CQE_SGL_RAW_SEL_SHIFT 2
#define ETH_FAST_PATH_RX_CQE_PHY_DECODE_ERR_FLG_64	(0x1<<3)
#define ETH_FAST_PATH_RX_CQE_PHY_DECODE_ERR_FLG_SHIFT_64 3
#define ETH_FAST_PATH_RX_CQE_IP_BAD_XSUM_FLG_64 (0x1<<4)
#define ETH_FAST_PATH_RX_CQE_IP_BAD_XSUM_FLG_SHIFT_64 4
#define ETH_FAST_PATH_RX_CQE_L4_BAD_XSUM_FLG_64 (0x1<<5)
#define ETH_FAST_PATH_RX_CQE_L4_BAD_XSUM_FLG_SHIFT_64 5
#define ETH_FAST_PATH_RX_CQE_RESERVED0_64 (0x3<<6)
#define ETH_FAST_PATH_RX_CQE_RESERVED0_SHIFT_64 6
	volatile __u8 status_flags;
#define ETH_FAST_PATH_RX_CQE_RSS_HASH_TYPE (0x7<<0)
#define ETH_FAST_PATH_RX_CQE_RSS_HASH_TYPE_SHIFT 0
#define ETH_FAST_PATH_RX_CQE_RSS_HASH_FLG (0x1<<3)
#define ETH_FAST_PATH_RX_CQE_RSS_HASH_FLG_SHIFT	3
#define ETH_FAST_PATH_RX_CQE_BROADCAST_FLG (0x1<<4)
#define ETH_FAST_PATH_RX_CQE_BROADCAST_FLG_SHIFT 4
#define ETH_FAST_PATH_RX_CQE_MAC_MATCH_FLG (0x1<<5)
#define ETH_FAST_PATH_RX_CQE_MAC_MATCH_FLG_SHIFT 5
#define ETH_FAST_PATH_RX_CQE_IP_XSUM_NO_VALIDATION_FLG (0x1<<6)
#define ETH_FAST_PATH_RX_CQE_IP_XSUM_NO_VALIDATION_FLG_SHIFT 6
#define ETH_FAST_PATH_RX_CQE_L4_XSUM_NO_VALIDATION_FLG (0x1<<7)
#define ETH_FAST_PATH_RX_CQE_L4_XSUM_NO_VALIDATION_FLG_SHIFT 7
	volatile __u8 queue_index;
	volatile __u8 placement_offset;
	volatile __u32 rss_hash_result;
	volatile __u16 vlan_tag;
	volatile __u16 pkt_len;
	volatile __u16 len_on_bd;
	struct parsing_flags pars_flags;
	union eth_sgl_or_raw_data sgl_or_raw_data;
};

struct eth_fast_path_rx_cqe_70 {
	volatile __u8 type_error_flags;
	volatile __u8 status_flags;
	volatile __u8 queue_index;
	volatile __u8 placement_offset;
	volatile __u32 rss_hash_result;
	volatile __u16 vlan_tag;
	volatile __u16 pkt_len;
	volatile __u16 len_on_bd;
	struct parsing_flags pars_flags;
	union eth_sgl_or_raw_data sgl_or_raw_data;
	__u32 reserved1[8];
};

struct eth_rx_cqe_next_page {
	__u32 addr_lo;
	__u32 addr_hi;
	__u32 reserved[6];
};

struct eth_rx_cqe_next_page_70 {
	__u32 addr_lo;
	__u32 addr_hi;
	__u32 reserved[14];
};

union eth_rx_cqe {
	struct eth_fast_path_rx_cqe fast_path_cqe;
	struct eth_fast_path_rx_cqe_64 fast_path_cqe_64;
	struct common_ramrod_eth_rx_cqe ramrod_cqe;
	struct eth_rx_cqe_next_page next_page_cqe;
};

union eth_rx_cqe_70 {
	struct eth_fast_path_rx_cqe_70 fast_path_cqe_70;
	struct common_ramrod_eth_rx_cqe_70 ramrod_cqe_70;
	struct eth_rx_cqe_next_page_70 next_page_cqe_70;
};

struct uio_init_data {
	__u32 cid;
	__u32 tx_db_off;
	__u32 cid_override_key;
#define UIO_USE_TX_DOORBELL	0x017855DB
};

struct client_init_general_data {
	__u8 client_id;
	__u8 statistics_counter_id;
	__u8 statistics_en_flg;
	__u8 is_fcoe_flg;
	__u8 activate_flg;
	__u8 sp_client_id;
	__u16 mtu;
	__u8 statistics_zero_flg;
	__u8 func_id;
	__u8 cos;
	__u8 traffic_type;
	struct uio_init_data uid;
};

/******************************************************************************
 *  BNX2X Registers and HSI
 ******************************************************************************/
#define BNX2X_BAR_SIZE			0x500000
#define BNX2X_BAR2_SIZE			0x12000

#define BNX2X_CHIP_ID(bp)		(bp->chip_id & 0xfffffff0)

#define PORT_MAX			2

/* [R 4] This field indicates the type of the device. '0' - 2 Ports; '1' - 1
 *    Port. */
#define BNX2X_MISC_REG_BOND_ID                                         0xa400
/* [R 8] These bits indicate the metal revision of the chip. This value
 *    starts at 0x00 for each all-layer tape-out and increments by one for each
 *       tape-out. */
#define BNX2X_MISC_REG_CHIP_METAL                                      0xa404
/* [R 16] These bits indicate the part number for the chip. */
#define BNX2X_MISC_REG_CHIP_NUM                                        0xa408
/* [R 4] These bits indicate the base revision of the chip. This value
 *    starts at 0x0 for the A0 tape-out and increments by one for each
 *       all-layer tape-out. */
#define BNX2X_MISC_REG_CHIP_REV                                        0xa40c

/* From the bnx2x driver */
#define CHIP_NUM(bp)			(bp->chip_id >> 16)
#define CHIP_NUM_57710			0x164e
#define CHIP_NUM_57711			0x164f
#define CHIP_NUM_57711E			0x1650
#define CHIP_NUM_57712			0x1662
#define CHIP_NUM_57712_MF		0x1663
#define CHIP_NUM_57712_VF		0x166f
#define CHIP_NUM_57713			0x1651
#define CHIP_NUM_57713E			0x1652
#define CHIP_NUM_57800			0x168a
#define CHIP_NUM_57800_MF		0x16a5
#define CHIP_NUM_57800_VF		0x16a9
#define CHIP_NUM_57810			0x168e
#define CHIP_NUM_57810_MF		0x16ae
#define CHIP_NUM_57810_VF		0x16af
#define CHIP_NUM_57811			0x163d
#define CHIP_NUM_57811_MF		0x163e
#define CHIP_NUM_57811_VF		0x163f
#define CHIP_NUM_57840_OBSOLETE		0x168d
#define CHIP_NUM_57840_MF_OBSOLETE	0x16ab
#define CHIP_NUM_57840_4_10		0x16a1
#define CHIP_NUM_57840_2_20		0x16a2
#define CHIP_NUM_57840_MF		0x16a4
#define CHIP_NUM_57840_VF		0x16ad

#define CHIP_IS_E1(bp)			(CHIP_NUM(bp) == CHIP_NUM_57710)
#define CHIP_IS_57711(bp)		(CHIP_NUM(bp) == CHIP_NUM_57711)
#define CHIP_IS_57711E(bp)		(CHIP_NUM(bp) == CHIP_NUM_57711E)
#define CHIP_IS_57712(bp)		(CHIP_NUM(bp) == CHIP_NUM_57712)
#define CHIP_IS_57712_VF(bp)		(CHIP_NUM(bp) == CHIP_NUM_57712_VF)
#define CHIP_IS_57712_MF(bp)		(CHIP_NUM(bp) == CHIP_NUM_57712_MF)
#define CHIP_IS_57800(bp)		(CHIP_NUM(bp) == CHIP_NUM_57800)
#define CHIP_IS_57800_VF(bp)		(CHIP_NUM(bp) == CHIP_NUM_57800_MF)
#define CHIP_IS_57800_MF(bp)		(CHIP_NUM(bp) == CHIP_NUM_57800_VF)
#define CHIP_IS_57810(bp)		(CHIP_NUM(bp) == CHIP_NUM_57810)
#define CHIP_IS_57810_VF(bp)		(CHIP_NUM(bp) == CHIP_NUM_57810_MF)
#define CHIP_IS_57810_MF(bp)		(CHIP_NUM(bp) == CHIP_NUM_57810_VF)
#define CHIP_IS_57811(bp)		(CHIP_NUM(bp) == CHIP_NUM_57811)
#define CHIP_IS_57811_VF(bp)		(CHIP_NUM(bp) == CHIP_NUM_57811_MF)
#define CHIP_IS_57811_MF(bp)		(CHIP_NUM(bp) == CHIP_NUM_57811_VF)

#define CHIP_IS_57840(bp)		\
		((CHIP_NUM(bp) == CHIP_NUM_57840_4_10) || \
		(CHIP_NUM(bp) == CHIP_NUM_57840_2_20) || \
		(CHIP_NUM(bp) == CHIP_NUM_57840_OBSOLETE))
#define CHIP_IS_57840_MF(bp)	((CHIP_NUM(bp) == CHIP_NUM_57840_MF) || \
		(CHIP_NUM(bp) == CHIP_NUM_57840_MF_OBSOLETE))
#define CHIP_IS_57840_VF(bp)		(CHIP_NUM(bp) == CHIP_NUM_57840_VF)
#define CHIP_IS_E1H(bp)			(CHIP_IS_57711(bp) || \
					 CHIP_IS_57711E(bp))

#define CHIP_IS_E2(bp)			(CHIP_IS_57712(bp) || \
					 CHIP_IS_57712_MF(bp) || \
					 CHIP_IS_57712_VF(bp))
#define CHIP_IS_E3(bp)			(CHIP_IS_57800(bp) || \
					 CHIP_IS_57800_MF(bp) || \
					 CHIP_IS_57800_VF(bp) || \
					 CHIP_IS_57810(bp) || \
					 CHIP_IS_57810_MF(bp) || \
					 CHIP_IS_57810_VF(bp) || \
					 CHIP_IS_57840(bp) || \
					 CHIP_IS_57840_MF(bp) || \
					 CHIP_IS_57840_VF(bp) || \
					 CHIP_IS_57811(bp) || \
					 CHIP_IS_57811_MF(bp) || \
					 CHIP_IS_57811_VF(bp))

#define CHIP_IS_E1x(bp)			(CHIP_IS_E1((bp)) || CHIP_IS_E1H((bp)))
#define USES_WARPCORE(bp)		(CHIP_IS_E3(bp))
#define IS_E1H_OFFSET			(!CHIP_IS_E1H(bp))
/* End of From the bnx2x driver */

#define CHIP_IS_E2_PLUS(bp)		(CHIP_IS_E2(bp) || CHIP_IS_E3(bp))

#define MISC_REG_SHARED_MEM_ADDR			0xa2b4

#define MISC_REG_BOND_ID				0xa400
#define MISC_REG_CHIP_METAL				0xa404
#define MISC_REG_CHIP_NUM				0xa408
#define MISC_REG_CHIP_REV				0xa40c

#define MISC_REG_PORT4MODE_EN				0xa750
#define MISC_REG_PORT4MODE_EN_OVWR			0xa720

#define MISC_REG_GENERIC_CR_0				0xa460
#define MISC_REG_GENERIC_CR_1				0xa464

#define BAR_USTRORM_INTMEM				0x400000
#define BAR_CSTRORM_INTMEM				0x410000
#define BAR_XSTRORM_INTMEM				0x420000
#define BAR_TSTRORM_INTMEM				0x430000

#define BAR_ME_REGISTER					0x450000
#define ME_REG_PF_NUM_SHIFT		0
#define ME_REG_PF_NUM\
	(7L<<ME_REG_PF_NUM_SHIFT) /* Relative PF Num */
#define ME_REG_VF_VALID			(1<<8)
#define ME_REG_VF_NUM_SHIFT		9
#define ME_REG_VF_NUM_MASK		(0x3f<<ME_REG_VF_NUM_SHIFT)
#define ME_REG_VF_ERR			(0x1<<3)
#define ME_REG_ABS_PF_NUM_SHIFT		16
#define ME_REG_ABS_PF_NUM\
	(7L<<ME_REG_ABS_PF_NUM_SHIFT) /* Absolute PF Num */

#define USTORM_RX_PRODS_OFFSET(port, client_id) \
	(IS_E1H_OFFSET ? (0x4000 + (port * 0x360) + (client_id * 0x30)) \
	:(0x1000 + (port * 0x680) + (client_id * 0x40)))

struct iro {
	__u32 base;
	__u16 m1;
	__u16 m2;
	__u16 m3;
	__u16 size;
};

#define IRO_ENT (bp->iro[bp->iro_idx])

#define USTORM_RX_PRODS_E1X_OFFSET(port, client_id) \
	(IRO_ENT.base + ((port) * IRO_ENT.m1) + ((client_id) * IRO_ENT.m2))

#define USTORM_RX_PRODS_E2_OFFSET(qzone_id) \
	(IRO_ENT.base + ((qzone_id) * IRO_ENT.m1))

#define ETH_MAX_RX_CLIENTS_E1H		28
#define ETH_MAX_RX_CLIENTS_E2		28

#define BNX2X_CL_QZONE_ID(bp, cli)					\
		(cli + (bp->port * (CHIP_IS_E2(bp) ?			\
				   ETH_MAX_RX_CLIENTS_E2 :		\
				   ETH_MAX_RX_CLIENTS_E1H)))

#define BNX2X_CL_QZONE_ID_64(bp, cli)					\
		(CHIP_IS_E2_PLUS(bp) ? (cli) :				\
		 (cli + (bp->port * ETH_MAX_RX_CLIENTS_E1H)))

#define BNX2X_PATH(bp)		(!CHIP_IS_E2_PLUS(bp) ? 0 : (bp)->func & 1)

#define	SHMEM_P0_ISCSI_MAC_UPPER	0x4c
#define	SHMEM_P0_ISCSI_MAC_LOWER	0x50
#define	SHMEM_P1_ISCSI_MAC_UPPER	0x1dc
#define	SHMEM_P1_ISCSI_MAC_LOWER	0x1e0

#define SHMEM_ISCSI_MAC_UPPER(bp)	\
	(((bp)->port == 0) ?		\
	SHMEM_P0_ISCSI_MAC_UPPER : SHMEM_P1_ISCSI_MAC_UPPER)

#define SHMEM_ISCSI_MAC_LOWER(bp)	\
	(((bp)->port == 0) ?		\
	SHMEM_P0_ISCSI_MAC_LOWER : SHMEM_P1_ISCSI_MAC_LOWER)

#define BNX2X_RCQ_DESC_CNT	(4096 / sizeof(union eth_rx_cqe))
#define BNX2X_RCQ_DESC_CNT_70	(4096 / sizeof(union eth_rx_cqe_70))
#define BNX2X_MAX_RCQ_DESC_CNT(bp)	\
	((bnx2x_is_ver70(bp) ? BNX2X_RCQ_DESC_CNT_70 : BNX2X_RCQ_DESC_CNT) - 1)

#define BNX2X_RX_DESC_CNT	(4096 / sizeof(struct eth_rx_bd))
#define BNX2X_MAX_RX_DESC_CNT		(BNX2X_RX_DESC_CNT - 2)
#define BNX2X_NUM_RX_BD			(BNX2X_RX_DESC_CNT * 1)
#define BNX2X_MAX_RX_BD			(BNX2X_NUM_RX_BD - 1)

#define BNX2X_TX_DESC_CNT	(4096 / sizeof(struct eth_tx_start_bd))
#define BNX2X_MAX_TX_DESC_CNT		(BNX2X_TX_DESC_CNT - 1)

#define BNX2X_NEXT_RX_IDX(x)	((((x) & (BNX2X_RX_DESC_CNT - 1)) ==	\
				  (BNX2X_MAX_RX_DESC_CNT - 1)) ?	\
				 (x) + 3 : (x) + 1)

#define BNX2X_NEXT_RCQ_IDX(bp, x)	\
			((((x) & BNX2X_MAX_RCQ_DESC_CNT(bp)) == \
			  (BNX2X_MAX_RCQ_DESC_CNT(bp) - 1)) ? (x) + 2 : (x) + 1)
#define BNX2X_RX_BD(x)		((x) & BNX2X_MAX_RX_BD)

#define BNX2X_NEXT_TX_BD(x) ((((x) & (BNX2X_MAX_TX_DESC_CNT - 1)) ==	\
		(BNX2X_MAX_TX_DESC_CNT - 1)) ?				\
		(x) + 2 : (x) + 1)

#define BNX2X_TX_RING_IDX(x) ((x) & BNX2X_MAX_TX_DESC_CNT)

struct ustorm_eth_rx_producers {
	__u16 cqe_prod;
	__u16 bd_prod;
	__u16 sge_prod;
	__u16 reserved;
};

#define BNX2X_DEFAULT_MAJOR_VERSION	1
#define BNX2X_DEFAULT_MINOR_VERSION	70
#define BNX2X_DEFAULT_SUB_MINOR_VERSION	1
#define BNX2X_UNKNOWN_MAJOR_VERSION	-1
#define BNX2X_UNKNOWN_MINOR_VERSION	-1
#define BNX2X_UNKNOWN_SUB_MINOR_VERSION	-1
struct bnx2x_driver_version {
	uint16_t major;
	uint16_t minor;
	uint16_t sub_minor;
};

typedef struct bnx2x {
	nic_t *parent;

	struct bnx2x_driver_version version;

	uint16_t flags;
#define CNIC_UIO_UNITIALIZED		0x0001
#define CNIC_UIO_INITIALIZED		0x0002
#define CNIC_UIO_ENABLED		0x0004
#define CNIC_UIO_DISABLED		0x0008
#define CNIC_UIO_IPv6_ENABLED		0x0010
#define CNIC_UIO_ADDED_MULICAST		0x0020
#define CNIC_UIO_MSIX_ENABLED		0x0200
#define CNIC_UIO_TX_HAS_SENT		0x0400
#define BNX2X_OPENED			0x0800

	void *reg;		/* Pointer to the BAR1 mapped registers */
	void *reg2;		/* Pointer to the BAR2 mapped registers */

	int bar0_fd;
	int bar2_fd;

	__u32 chip_id;
	__u32 shmem_base;
	__u32 shmem_base2;
	int func;
	int port;
	int pfid;
	__u32 cid;
	__u32 client_id;

	struct iro *iro;
	int iro_idx;

	__u32 tx_doorbell;

	__u16 tx_prod;
	__u16 tx_bd_prod;
	__u16 tx_cons;
	__u8 tx_vlan_tag_bit;

	__u32 rx_prod_io;

	__u16 rx_prod;
	__u16 rx_bd_prod;
	__u16 rx_cons;
	__u16 rx_bd_cons;
	__u16 rx_hw_prod;

	 __u16(*get_rx_cons) (struct bnx2x *);
	 __u16(*get_tx_cons) (struct bnx2x *);

	/*  RX ring parameters */
	uint32_t rx_ring_size;
	uint32_t rx_buffer_size;

	void *bufs;		/* Pointer to the mapped buffer space   */

	/*  Hardware Status Block locations */
	void *sblk_map;
	union {
		struct host_def_status_block *def;
		struct host_sp_status_block *sp;
	} status_blk;

	int status_blk_size;

	uint16_t rx_index;
	union {
		union eth_rx_cqe *cqe;
		union eth_rx_cqe_70 *cqe70;
	} rx_comp_ring;
	void **rx_pkt_ring;

	struct eth_tx_start_bd *tx_ring;
	void *tx_pkt;

} bnx2x_t;

/******************************************************************************
 *  bnx2x Function Declarations
 ******************************************************************************/
void bnx2x_start_xmit(nic_t *nic, size_t len, u16_t vlan_id);

struct nic_ops *bnx2x_get_ops();
#endif /* __BNX2X_H__ */
