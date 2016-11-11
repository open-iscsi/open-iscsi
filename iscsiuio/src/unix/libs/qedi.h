/*
 * Copyright (c) 2016, Cavium Inc.
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
 * qedi.h - qedi user space driver
 *
 */
#ifndef __QEDI_H__
#define __QEDI_H__

#include "nic.h"

#define RX_RING_SIZE	15
#define PKT_BUF_SIZE 0X400
#define QEDI_PAGE_SIZE 4096

#define QEDI_UNKNOWN_MAJOR_VERSION	-1
#define QEDI_UNKNOWN_MINOR_VERSION	-1
#define QEDI_UNKNOWN_SUB_MINOR_VERSION	-1
struct qedi_driver_version {
	uint16_t major;
	uint16_t minor;
	uint16_t sub_minor;
};

#define QEDI_UCTRL_MAP_REG	0
#define QEDI_RING_MAP_REG	1
#define QEDI_BUF_MAP_REG	2
#define UIO_ATTR_TMPL	"/sys/class/uio/uio%u/maps/map%u/%s"
#define UIO_ADDR_TMPL	"/sys/class/uio/uio%u/maps/map%u/addr"
#define UIO_OFFSET_TMPL	"/sys/class/uio/uio%u/maps/map%u/offset"
#define UIO_SIZE_TMPL	"/sys/class/uio/uio%u/maps/map%u/size"

struct qedi_uio_ctrl {
	/* meta data */
	__u32 uio_hsi_version;

	/* user writes */
	__u32 host_tx_prod;
	__u32 host_rx_cons;
	__u32 host_rx_bd_cons;
	__u32 host_tx_pkt_len;
	__u32 host_rx_cons_cnt;

	/* driver writes */
	__u32 hw_tx_cons;
	__u32 hw_rx_prod;
	__u32 hw_rx_bd_prod;
	__u32 hw_rx_prod_cnt;

	/* other */
	__u8 mac_addr[6];
	__u8 reserve[2];
};

struct qedi_rx_bd {
	__u32 rx_pkt_index;
	__u32 rx_pkt_len;
	__u16 vlan_id;
};

#define QEDI_RX_DESC_CNT	(QEDI_PAGE_SIZE / sizeof(struct qedi_rx_bd))
#define QEDI_MAX_RX_DESC_CNT	(QEDI_RX_DESC_CNT - 1)
#define QEDI_NUM_RX_BD		(QEDI_RX_DESC_CNT * 1)
#define QEDI_MAX_RX_BD		(QEDI_NUM_RX_BD - 1)

#define QEDI_NEXT_RX_IDX(x)	((((x) & (QEDI_MAX_RX_DESC_CNT)) ==     \
				  (QEDI_MAX_RX_DESC_CNT - 1)) ?         \
				 (x) + 2 : (x) + 1)

#define QEDI_PATH_HANDLE	0xFE0000000

typedef struct qedi {
	nic_t *parent;

	struct qedi_driver_version version;

	uint16_t flags;
#define CNIC_UIO_UNITIALIZED		0x0001
#define CNIC_UIO_INITIALIZED		0x0002
#define CNIC_UIO_ENABLED		0x0004
#define CNIC_UIO_DISABLED		0x0008
#define CNIC_UIO_IPv6_ENABLED		0x0010
#define CNIC_UIO_ADDED_MULICAST		0x0020
#define CNIC_UIO_MSIX_ENABLED		0x0200
#define CNIC_UIO_TX_HAS_SENT		0x0400
#define QEDI_OPENED			0x0800

	__u32 chip_id;
	int func;
	int port;
	int pfid;
	__u32 cid;
	__u32 client_id;

	__u32 tx_prod;
	__u32 tx_bd_prod;
	__u32 tx_cons;
	__u8 tx_vlan_tag_bit;

	__u32 rx_prod;
	__u32 rx_bd_prod;
	__u32 rx_cons;
	__u32 rx_bd_cons;
	__u32 rx_hw_prod;

	 __u32 (*get_rx_cons)(struct qedi *);
	 __u32 (*get_tx_cons)(struct qedi *);

	/* RX ring parameters */
	uint32_t rx_ring_size;
	uint32_t rx_buffer_size;

	void *bufs; /* Pointer to the mapped buffer space */
	void *uctrl_map; /* UIO control structure */
	uint32_t uctrl_map_offset; /* UIO control structure mmap offset */

	uint32_t rx_index;
	void *rx_comp_ring;
	void **rx_pkt_ring;
	void *tx_pkt;
	void *rx_pkts;
} qedi_t;

/******************************************************************************
 *  qedi Function Declarations
 ******************************************************************************/
void qedi_start_xmit(nic_t *nic, size_t len, u16_t vlan_id);
struct nic_ops *qedi_get_ops();

#endif /* __QEDI_H__ */
