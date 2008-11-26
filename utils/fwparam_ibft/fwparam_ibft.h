/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 *
 * Copyright (C) IBM Corporation, 2006,2007
 *
 * Authors: 	Doug Maxey <dwm@austin.ibm.com>
 * 		Patrick Mansfield <patmans@us.ibm.com>
 *
 */

#ifndef FWPARAM_IBFT_H_
#define FWPARAM_IBFT_H_

/* #include <sys/types.h> */
#include <stdint.h>
#include "fw_context.h"

/*
 * Structures here are is based on Doug's original code, and Patrick's
 * interpretation of the IBM internal design document title the "iSCSI
 * Boot Firmware Table (iBFT)".
 */
#define iBFTSTR "iBFT"
#define iBFT_SIG { 'i','B','F','T' }

#define iBFT_REV 1

/*
 * These macros are lower case to make the verify_hdr macro easier.
 */
#define version_control	1
#define version_initiator	1
#define version_nic	1
#define version_target	1
#define version_extensions	1

enum ibft_id {
	id_control = 1,
	id_initiator,
	id_nic,
	id_target,
	id_extensions,
};

struct ibft_hdr {
	uint8_t id;
	uint8_t version;
	uint16_t length;
	uint8_t ind;
	uint8_t flags;
};

struct ibft_table_hdr {
	uint8_t signature[4];
	uint32_t length;
	uint8_t revision;
	uint8_t checksum;
	uint8_t oemid[6];
	uint8_t oem_table_id[8];
	uint8_t rsvd1[24];
} __attribute__((__packed__));

struct ibft_control {
	struct ibft_hdr hdr;
	uint16_t extensions;
	uint16_t initiator_off;
	uint16_t nic0_off;
	uint16_t tgt0_off;
	uint16_t nic1_off;
	uint16_t tgt1_off;
} __attribute__((__packed__));

struct ibft_initiator {
#define INIT_FLAG_VALID 1
#define INIT_FLAG_FW_SEL_BOOT 2
	struct ibft_hdr hdr;
	uint8_t isns_server[16];
	uint8_t slp_server[16];
	uint8_t pri_radius_server[16];
	uint8_t sec_radius_server[16];
	uint16_t initiator_name_len;
	uint16_t initiator_name_off;
} __attribute__((__packed__));

struct ibft_nic {
#define NIC_FLAG_VALID 1
#define NIC_FLAG_FW_SEL_BOOT 2
	struct ibft_hdr hdr;
	uint8_t ip_addr[16];
	uint8_t subnet_mask_prefix;
	uint8_t origin;
	uint8_t gateway[16];
	uint8_t primary_dns[16];
	uint8_t secondary_dns[16];
	uint8_t dhcp[16];
	uint16_t vlan;
	uint8_t mac[6];
	uint16_t pci_bdf;
	uint16_t hostname_len;
	uint16_t hostname_off;
} __attribute__((__packed__));

struct ibft_tgt {
#define TGT_FLAG_VALID 1
#define TGT_FLAG_FW_SEL_BOOT 2
#define TGT_FLAG_USE_RADIUS_CHAT 4
#define TGT_FLAG_USE_RADIUS_RCHAT 8
	struct ibft_hdr hdr;
	uint8_t ip_addr[16];
	uint16_t port;
	uint8_t lun[8];
#define TGT_CHAP 1
#define TGT_MUTUAL_CHAP 2
	uint8_t chap_type;
	uint8_t nic_assoc;
	uint16_t tgt_name_len;
	uint16_t tgt_name_off;
	uint16_t chap_name_len;
	uint16_t chap_name_off;
	uint16_t chap_secret_len;
	uint16_t chap_secret_off;
	uint16_t rev_chap_name_len;
	uint16_t rev_chap_name_off;
	uint16_t rev_chap_secret_len;
	uint16_t rev_chap_secret_off;
} __attribute__((__packed__));

/* Common variables */
#define FILENAMESZ (256)
extern char filename[FILENAMESZ];
#define X86_DEFAULT_FILENAME "/dev/mem"
extern int debug;
extern int dev_count;

extern int fwparam_ibft(struct boot_context *context, const char *filepath);
#endif /* FWPARAM_IBFT_H_ */
