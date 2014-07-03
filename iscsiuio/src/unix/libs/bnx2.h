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
 * bnx2.h - bnx2 user space driver
 *
 */
#ifndef __BNX2_H__
#define __BNX2_H__

#include "nic.h"

/******************************************************************************
 *  Default BNX2 values
 ******************************************************************************/
#define DEFAULT_NUM_RXBD	3
#define DEFAULT_RX_LEN		0x400

/******************************************************************************
 *  BNX2 Hardware structures
 ******************************************************************************/
/* status_block definition for MSI */
struct status_block {
	volatile __u32 status_attn_bits;
	volatile __u32 status_attn_bits_ack;
	volatile __u32 tx0;
	volatile __u32 tx2;
	volatile __u32 rx0;
	volatile __u32 rx2;
	volatile __u32 rx4;
	volatile __u32 rx6;
	volatile __u32 rx8;
	volatile __u32 rx10;
	volatile __u32 rx12;
	volatile __u32 rx14;
	volatile __u32 cmd;
	volatile __u32 idx;
};

/* status_block definition for MSI-X */
struct status_block_msix {
#if 0
#if defined(__BIG_ENDIAN)
	__u16 status_tx_quick_consumer_index;
	__u16 status_rx_quick_consumer_index;
	__u16 status_completion_producer_index;
	__u16 status_cmd_consumer_index;
	__u32 status_unused;
	__u16 status_idx;
	__u8 status_unused2;
	__u8 status_blk_num;
#elif defined(__LITTLE_ENDIAN)
	__u16 status_rx_quick_consumer_index;
	__u16 status_tx_quick_consumer_index;
	__u16 status_cmd_consumer_index;
	__u16 status_completion_producer_index;
	__u32 status_unused;
	__u8 status_blk_num;
	__u8 status_unused2;
	__u16 status_idx;
#endif
#endif
	__u16 status_rx_quick_consumer_index;
	__u16 status_tx_quick_consumer_index;
	__u16 status_cmd_consumer_index;
	__u16 status_completion_producer_index;
	__u32 status_unused;
	__u8 status_blk_num;
	__u8 status_unused2;
	__u16 status_idx;
};

/*  TX Buffer descriptor */
struct tx_bd {
	__u32 tx_bd_haddr_hi;
	__u32 tx_bd_haddr_lo;
	__u32 tx_bd_mss_nbytes;
	__u32 tx_bd_vlan_tag_flags;
#define TX_BD_FLAGS_VLAN_TAG		(1<<3)
#define TX_BD_FLAGS_END			(1<<6)
#define TX_BD_FLAGS_START		(1<<7)
};

/*  RX Buffer descriptor */
struct rx_bd {
	__u32 rx_bd_haddr_hi;
	__u32 rx_bd_haddr_lo;

	__u32 rx_bd_len;
	__u32 rx_bd_flags;
#define RX_BD_FLAGS_END			(1<<2)
#define RX_BD_FLAGS_START		(1<<3)

};

/*  This is the RX L2 Frame header */
struct l2_fhdr {
	__u32 l2_fhdr_status;
#define L2_FHDR_ERRORS_BAD_CRC          (1<<17)
#define L2_FHDR_ERRORS_PHY_DECODE       (1<<18)
#define L2_FHDR_ERRORS_ALIGNMENT        (1<<19)
#define L2_FHDR_ERRORS_TOO_SHORT        (1<<20)
#define L2_FHDR_ERRORS_GIANT_FRAME      (1<<21)
#define L2_FHDR_ERRORS_TCP_XSUM         (1<<28)
#define L2_FHDR_ERRORS_UDP_XSUM         (1<<31)

#define L2_FHDR_STATUS_UDP_DATAGRAM	(1<<15)
#define L2_FHDR_STATUS_TCP_DATAGRAM	(1<<14)
#define L2_FHDR_STATUS_IP_DATAGRAM	(1<<13)
#define L2_FHDR_STATUS_LLC_SNAP		(1<<7)
#define L2_FHDR_STATUS_VLAN_TAG		(1<<6)

	__u32 l2_fhdr_hash;

	__u32 l2_fhdr_vtag_len;
	__u32 l2_fhdr_xsum;
};

/******************************************************************************
 *  BNX2 Registers Defitions/Values
 ******************************************************************************/
#define BNX2_MISC_ID			0x00000808
#define BNX2_EMAC_MAC_MATCH4		0x00001420
#define BNX2_EMAC_MAC_MATCH5		0x00001424

#define BNX2_EMAC_RX_MODE				0x000014c8
#define BNX2_EMAC_RX_MODE_RESET				(1L<<0)
#define BNX2_EMAC_RX_MODE_FLOW_EN			(1L<<2)
#define BNX2_EMAC_RX_MODE_KEEP_MAC_CONTROL		(1L<<3)
#define BNX2_EMAC_RX_MODE_KEEP_PAUSE			(1L<<4)
#define BNX2_EMAC_RX_MODE_ACCEPT_OVERSIZE		(1L<<5)
#define BNX2_EMAC_RX_MODE_ACCEPT_RUNTS			(1L<<6)
#define BNX2_EMAC_RX_MODE_LLC_CHK			(1L<<7)
#define BNX2_EMAC_RX_MODE_PROMISCUOUS			(1L<<8)
#define BNX2_EMAC_RX_MODE_NO_CRC_CHK			(1L<<9)
#define BNX2_EMAC_RX_MODE_KEEP_VLAN_TAG			(1L<<10)
#define BNX2_EMAC_RX_MODE_FILT_BROADCAST		(1L<<11)
#define BNX2_EMAC_RX_MODE_SORT_MODE			(1L<<12)

#define BNX2_RPM_SORT_USER2				0x00001828
#define BNX2_RPM_SORT_USER2_PM_EN			(0xffffL<<0)
#define BNX2_RPM_SORT_USER2_BC_EN			(1L<<16)
#define BNX2_RPM_SORT_USER2_MC_EN			(1L<<17)
#define BNX2_RPM_SORT_USER2_MC_HSH_EN			(1L<<18)
#define BNX2_RPM_SORT_USER2_PROM_EN			(1L<<19)
#define BNX2_RPM_SORT_USER2_VLAN_EN			(0xfL<<20)
#define BNX2_RPM_SORT_USER2_PROM_VLAN			(1L<<24)
#define BNX2_RPM_SORT_USER2_ENA				(1L<<31)

/*
 * tsch_reg definition
 * offset: 0x4c00
 */
#define BNX2_TSCH_TSS_CFG				0x00004c1c
#define BNX2_TSCH_TSS_CFG_TSS_START_CID			(0x7ffL<<8)
#define BNX2_TSCH_TSS_CFG_NUM_OF_TSS_CON		(0xfL<<24)
#define CNIC_UIO_INVALID_FD	-1

#define BNX2_L2CTX_TX_HOST_BIDX				0x00000088
#define BNX2_L2CTX_TX_HOST_BSEQ				0x00000090

#define BNX2_L2CTX_HOST_BDIDX				0x00000004
#define BNX2_L2CTX_HOST_BSEQ				0x00000008

/* Used to determin the CHIP ID */
/* chip num:16-31, rev:12-15, metal:4-11, bond_id:0-3 */
#define BNX2_CHIP_NUM(bp)               ((bp) & 0xffff0000)
#define CHIP_NUM_5706                   0x57060000
#define CHIP_NUM_5708                   0x57080000
#define CHIP_NUM_5709                   0x57090000

#define CHIP_REV(bp)                    ((bp) & 0x0000f000)
#define CHIP_REV_Ax                     0x00000000
#define CHIP_REV_Bx                     0x00001000
#define CHIP_REV_Cx                     0x00002000

#define CHIP_METAL(bp)                  ((bp) & 0x00000ff0)
#define CHIP_BONDING(bp)                ((bp) & 0x0000000f)

#define CHIP_ID(bp)                     ((bp) & 0xfffffff0)
#define CHIP_ID_5706_A0                 0x57060000
#define CHIP_ID_5706_A1                 0x57060010
#define CHIP_ID_5706_A2                 0x57060020
#define CHIP_ID_5708_A0                 0x57080000
#define CHIP_ID_5708_B0                 0x57081000
#define CHIP_ID_5708_B1                 0x57081010
#define CHIP_ID_5709_A0                 0x57090000
#define CHIP_ID_5709_A1                 0x57090010

#define CHIP_BOND_ID(bp)                ((bp) & 0xf)

#define BNX2_SBLK_EVEN_IDX(x)		(((x) & 0xffff0000) >> 16)

#define TX_DESC_CNT  (4096 / sizeof(struct tx_bd))
#define MAX_TX_DESC_CNT (TX_DESC_CNT - 1)

#define NEXT_TX_BD(x)	((((x) & (MAX_TX_DESC_CNT - 1)) ==	\
			(MAX_TX_DESC_CNT - 1)) ?		\
			(x) + 2 : (x) + 1)

#define TX_RING_IDX(x) ((x) & MAX_TX_DESC_CNT)

#define RX_DESC_CNT  (4096 / sizeof(struct rx_bd))
#define MAX_RX_DESC_CNT (RX_DESC_CNT - 1)

#define NEXT_RX_BD(x)	((((x) & (MAX_RX_DESC_CNT - 1)) ==	\
			(MAX_RX_DESC_CNT - 1)) ?		\
			(x) + 2 : (x) + 1)

#define MB_KERNEL_CTX_SHIFT         8
#define MB_KERNEL_CTX_SIZE          (1 << MB_KERNEL_CTX_SHIFT)
#define MB_KERNEL_CTX_MASK          (MB_KERNEL_CTX_SIZE - 1)
#define MB_GET_CID_ADDR(_cid)       (0x10000 + ((_cid) << MB_KERNEL_CTX_SHIFT))

typedef struct bnx2 {
	nic_t *parent;

	uint16_t flags;
#define BNX2_UIO_MSIX_ENABLED		0x0001
#define BNX2_UIO_TX_HAS_SENT		0x0002
#define BNX2_OPENED			0x0004

	int bar0_fd;
	void *reg;		/* Pointer to the mapped registers      */

	__u32 tx_bidx_io;
	__u32 tx_bseq_io;

	__u16 tx_prod;
	__u16 tx_cons;
	__u32 tx_bseq;

	__u32 rx_bidx_io;
	__u32 rx_bseq_io;

	__u16 rx_prod;
	__u16 rx_cons;
	__u32 rx_bseq;

	/*  RX ring parameters */
	uint32_t rx_ring_size;
	uint32_t rx_buffer_size;

	void *bufs;		/* Pointer to the mapped buffer space   */

	/*  Hardware Status Block locations */
	void *sblk_map;
	union {
		struct status_block *msi;
		struct status_block_msix *msix;
	} status_blk;
	size_t status_blk_size;

	 __u16(*get_rx_cons) (struct bnx2 *);
	 __u16(*get_tx_cons) (struct bnx2 *);

	uint16_t rx_index;
	struct l2_fhdr **rx_ring;
	void **rx_pkt_ring;

	struct tx_bd *tx_ring;
	void *tx_pkt;

	struct l2_fhdr rcv_l2_fhdr;
	__u8 rcv_buf[1500 + 2];
	__u32 rcv_size;
} bnx2_t;

/******************************************************************************
 *  bnx2 Function Declarations
 ******************************************************************************/
struct nic_ops *bnx2_get_ops();
#endif /* __BNX2_H__ */
