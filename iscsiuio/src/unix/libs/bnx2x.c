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
 * bnx2x.c - bnx2x user space driver
 *
 */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/types.h>	/* Needed for linux/ethtool.h on RHEL 5.x */
#include <linux/sockios.h>
#include <linux/ethtool.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <fcntl.h>
#include <unistd.h>

#include "config.h"

#include "build_date.h"
#include "bnx2x.h"
#include "cnic.h"
#include "logger.h"
#include "nic.h"
#include "nic_id.h"
#include "nic_utils.h"
#include "options.h"

#define PFX	"bnx2x "

/*  Foward struct declarations */
struct nic_ops bnx2x_op;

/*******************************************************************************
 * NIC Library Strings
 ******************************************************************************/
static const char library_name[] = "bnx2x";
static const char library_version[] = PACKAGE_VERSION;
static const char library_uio_name[] = "bnx2x_cnic";

/*  The name that should be returned from /sys/class/uio/uio0/name */
static const char cnic_uio_sysfs_name_tempate[] = "/sys/class/uio/uio%i/name";
static const char bnx2x_uio_sysfs_name[] = "bnx2x_cnic";

/*******************************************************************************
 * String constants used to display human readable adapter name
 ******************************************************************************/
static const char brcm_57710[] = "QLogic NetXtreme II BCM57710 10-Gigabit";
static const char brcm_57711[] = "QLogic NetXtreme II BCM57711 10-Gigabit";
static const char brcm_57711e[] = "QLogic NetXtreme II BCM57711E 10-Gigabit";
static const char brcm_57712[] = "QLogic NetXtreme II BCM57712 10-Gigabit";
static const char brcm_57712_MF[] = "QLogic NetXtreme II BCM57712 MF "
				    "10-Gigabit";
static const char brcm_57712_VF[] = "QLogic NetXtreme II BCM57712 VF "
				    "10-Gigabit";
static const char brcm_57713[] = "QLogic NetXtreme II BCM57713 10-Gigabit";
static const char brcm_57713e[] = "QLogic NetXtreme II BCM57713E 10-Gigabit";
static const char brcm_57800[] = "QLogic NetXtreme II BCM57800 10-Gigabit";
static const char brcm_57800_MF[] = "QLogic NetXtreme II BCM57800 MF "
				    "10-Gigabit";
static const char brcm_57800_VF[] = "QLogic NetXtreme II BCM57800 VF "
				    "10-Gigabit";
static const char brcm_57810[] = "QLogic NetXtreme II BCM57810 10-Gigabit";
static const char brcm_57810_MF[] = "QLogic NetXtreme II BCM57810 MF "
				    "10-Gigabit";
static const char brcm_57810_VF[] = "QLogic NetXtreme II BCM57810 VF "
				    "10-Gigabit";
static const char brcm_57811[] = "QLogic NetXtreme II BCM57811 10-Gigabit";
static const char brcm_57811_MF[] = "QLogic NetXtreme II BCM57811 MF "
				    "10-Gigabit";
static const char brcm_57811_VF[] = "QLogic NetXtreme II BCM57811 VF "
				    "10-Gigabit";
static const char brcm_57840[] = "QLogic NetXtreme II BCM57840 10-Gigabit";
static const char brcm_57840_MF[] = "QLogic NetXtreme II BCM57840 MF "
				    "10-Gigabit";
static const char brcm_57840_VF[] = "QLogic NetXtreme II BCM57840 VF "
				    "10-Gigabit";
static const char brcm_57840_4_10[] = "QLogic NetXtreme II BCM57840 4x"
				      "10-Gigabit";
static const char brcm_57840_2_20[] = "QLogic NetXtreme II BCM57840 2x"
				      "20-Gigabit";

/*******************************************************************************
 * PCI ID constants
 ******************************************************************************/
#define PCI_VENDOR_ID_BROADCOM			0x14e4
#define PCI_VENDOR_ID_QLOGIC			0x1077
#define PCI_DEVICE_ID_NX2_57710			0x164e
#define PCI_DEVICE_ID_NX2_57711			0x164f
#define PCI_DEVICE_ID_NX2_57711E		0x1650
#define PCI_DEVICE_ID_NX2_57712			0x1662
#define PCI_DEVICE_ID_NX2_57712_MF		0x1663
#define PCI_DEVICE_ID_NX2_57712_VF		0x166f
#define PCI_DEVICE_ID_NX2_57713			0x1651
#define PCI_DEVICE_ID_NX2_57713E		0x1652
#define PCI_DEVICE_ID_NX2_57800			0x168a
#define PCI_DEVICE_ID_NX2_57800_MF		0x16a5
#define PCI_DEVICE_ID_NX2_57800_VF		0x16a9
#define PCI_DEVICE_ID_NX2_57810			0x168e
#define PCI_DEVICE_ID_NX2_57810_MF		0x16ae
#define PCI_DEVICE_ID_NX2_57810_VF		0x16af
#define PCI_DEVICE_ID_NX2_57811			0x163d
#define PCI_DEVICE_ID_NX2_57811_MF		0x163e
#define PCI_DEVICE_ID_NX2_57811_VF		0x163f
#define PCI_DEVICE_ID_NX2_57840_OBSOLETE	0x168d
#define PCI_DEVICE_ID_NX2_57840_MF_OBSOLETE	0x16ab
#define PCI_DEVICE_ID_NX2_57840_4_10		0x16a1
#define PCI_DEVICE_ID_NX2_57840_2_20		0x16a2
#define PCI_DEVICE_ID_NX2_57840_MF		0x16a4
#define PCI_DEVICE_ID_NX2_57840_VF		0x16ad
#define PCI_ANY_ID (~0)

/*  This is the table used to match PCI vendor and device ID's to the
 *  human readable string names of the devices */
static const struct pci_device_id bnx2x_pci_tbl[] = {
	{PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_57710,
	 PCI_ANY_ID, PCI_ANY_ID, brcm_57710},
	{PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_57711,
	 PCI_ANY_ID, PCI_ANY_ID, brcm_57711},
	{PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_57711E,
	 PCI_ANY_ID, PCI_ANY_ID, brcm_57711e},
	{PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_57712,
	 PCI_ANY_ID, PCI_ANY_ID, brcm_57712},
	{PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_57712_MF,
	 PCI_ANY_ID, PCI_ANY_ID, brcm_57712_MF},
	{PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_57712_VF,
	 PCI_ANY_ID, PCI_ANY_ID, brcm_57712_VF},
	{PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_57713,
	 PCI_ANY_ID, PCI_ANY_ID, brcm_57713},
	{PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_57713E,
	 PCI_ANY_ID, PCI_ANY_ID, brcm_57713e},
	{PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_57800,
	 PCI_ANY_ID, PCI_ANY_ID, brcm_57800},
	{PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_57800_MF,
	 PCI_ANY_ID, PCI_ANY_ID, brcm_57800_MF},
	{PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_57800_VF,
	 PCI_ANY_ID, PCI_ANY_ID, brcm_57800_VF},
	{PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_57810,
	 PCI_ANY_ID, PCI_ANY_ID, brcm_57810},
	{PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_57810_MF,
	 PCI_ANY_ID, PCI_ANY_ID, brcm_57810_MF},
	{PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_57810_VF,
	 PCI_ANY_ID, PCI_ANY_ID, brcm_57810_VF},
	{PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_57811,
	 PCI_ANY_ID, PCI_ANY_ID, brcm_57811},
	{PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_57811_MF,
	 PCI_ANY_ID, PCI_ANY_ID, brcm_57811_MF},
	{PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_57811_VF,
	 PCI_ANY_ID, PCI_ANY_ID, brcm_57811_VF},
	{PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_57840_OBSOLETE,
	 PCI_ANY_ID, PCI_ANY_ID, brcm_57840},
	{PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_57840_MF_OBSOLETE,
	 PCI_ANY_ID, PCI_ANY_ID, brcm_57840_MF},
	{PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_57840_4_10,
	 PCI_ANY_ID, PCI_ANY_ID, brcm_57840_4_10},
	{PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_57840_2_20,
	 PCI_ANY_ID, PCI_ANY_ID, brcm_57840_2_20},
	{PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_57840_MF,
	 PCI_ANY_ID, PCI_ANY_ID, brcm_57840_MF},
	{PCI_VENDOR_ID_BROADCOM, PCI_DEVICE_ID_NX2_57840_VF,
	 PCI_ANY_ID, PCI_ANY_ID, brcm_57840_VF},
	{PCI_VENDOR_ID_QLOGIC, PCI_DEVICE_ID_NX2_57840_4_10,
	 PCI_ANY_ID, PCI_ANY_ID, brcm_57840_4_10},
	{PCI_VENDOR_ID_QLOGIC, PCI_DEVICE_ID_NX2_57840_2_20,
	 PCI_ANY_ID, PCI_ANY_ID, brcm_57840_2_20},
	{PCI_VENDOR_ID_QLOGIC, PCI_DEVICE_ID_NX2_57840_MF,
	 PCI_ANY_ID, PCI_ANY_ID, brcm_57840_MF},
	{PCI_VENDOR_ID_QLOGIC, PCI_DEVICE_ID_NX2_57840_VF,
	 PCI_ANY_ID, PCI_ANY_ID, brcm_57840_VF},
};

static struct iro e1_iro[2] = {
	{0x45a0, 0x90, 0x8, 0x0, 0x8},	/* T6.0 */
	{0x50c8, 0x90, 0x8, 0x0, 0x8},	/* T6.4 */
};

static struct iro e1h_iro[2] = {
	{0x1c40, 0xe0, 0x8, 0x0, 0x8},	/* T6.0 */
	{0x1e00, 0xe0, 0x8, 0x0, 0x8},	/* T6.4 */
};

static struct iro e2_iro[2] = {
	{0x6000, 0x20, 0x0, 0x0, 0x8},	/* T6.0 */
	{0x6000, 0x20, 0x0, 0x0, 0x8},	/* T6.4 */
};

struct bnx2x_driver_version bnx2x_version = {
	BNX2X_UNKNOWN_MAJOR_VERSION,
	BNX2X_UNKNOWN_MINOR_VERSION,
	BNX2X_UNKNOWN_SUB_MINOR_VERSION,
};

static int bnx2x_clear_tx_intr(nic_t *nic);

/*******************************************************************************
 * BNX2X Library Functions
 ******************************************************************************/
/**
 *  bnx2x_get_library_name() - Used to get the name of this NIC libary
 *  @param name - This function will return the pointer to this NIC
 *                library name
 *  @param name_size
 */
static void bnx2x_get_library_name(char **name, size_t *name_size)
{
	*name = (char *)library_name;
	*name_size = sizeof(library_name);
}

/**
 *  bnx2x_get_library_version() - Used to get the version string of this
 *                                NIC libary
 *  @param version - This function will return the pointer to this NIC
 *                   library version string
 *  @param version_size - This will be set with the version size
 */
static void bnx2x_get_library_version(char **version, size_t *version_size)
{
	*version = (char *)library_version;
	*version_size = sizeof(library_version);
}

/**
 *  bnx2x_get_build_date() - Used to get the build date string of this library
 *  @param version - This function will return the pointer to this NIC
 *                   library build date string
 *  @param version_size - This will be set with the build date string size
 */
static void bnx2x_get_build_date(char **build, size_t *build_size)
{
	*build = (char *)build_date;
	*build_size = sizeof(build_date);
}

/**
 *  bnx2x_get_transport_name() - Used to get the transport name associated
 *                              with this this NIC libary
 *  @param transport_name - This function will return the pointer to this NIC
 *                          library's associated transport string
 *  @param transport_name_size - This will be set with the transport name size
 */
static void bnx2x_get_transport_name(char **transport_name,
				     size_t *transport_name_size)
{
	*transport_name = (char *)bnx2i_library_transport_name;
	*transport_name_size = bnx2i_library_transport_name_size;
}

/**
 *  bnx2x_get_uio_name() - Used to get the uio name associated with this this
 *                        NIC libary
 *  @param uio_name - This function will return the pointer to this NIC
 *                    library's associated uio string
 *  @param transport_name_size - This will be set with the uio name size
 */
static void bnx2x_get_uio_name(char **uio_name, size_t *uio_name_size)
{
	*uio_name = (char *)library_uio_name;
	*uio_name_size = sizeof(library_uio_name);
}

/**
 *  bnx2x_get_pci_table() - Used to get the PCI table for this NIC libary to
 *			    determine which NIC's based off of PCI ID's are
 *			    supported
 *  @param table - This function will return the pointer to the PCI table
 *  @param entries - This function will return the number of entries in the NIC
 *                   library's PCI table
 */
static void bnx2x_get_pci_table(struct pci_device_id **table,
				uint32_t *entries)
{
	*table = (struct pci_device_id *)bnx2x_pci_tbl;
	*entries =
	    (uint32_t) (sizeof(bnx2x_pci_tbl) / sizeof(bnx2x_pci_tbl[0]));
}

/**
 *  bnx2x_get_ops() - Used to get the NIC library op table
 *  @param op - The op table of this NIC library
 */
struct nic_ops *bnx2x_get_ops()
{
	return &bnx2x_op;
}

/*******************************************************************************
 * bnx2x Utility Functions
 ******************************************************************************/
/*******************************************************************************
 * Utility Functions Used to read register from the bnx2x device
 ******************************************************************************/
static void bnx2x_set_drv_version_unknown(bnx2x_t *bp)
{
	bp->version.major = BNX2X_UNKNOWN_MAJOR_VERSION;
	bp->version.minor = BNX2X_UNKNOWN_MINOR_VERSION;
	bp->version.sub_minor = BNX2X_UNKNOWN_SUB_MINOR_VERSION;
}

/* Return: 1 = Unknown, 0 = Known */
static int bnx2x_is_drv_version_unknown(struct bnx2x_driver_version *version)
{
	if ((version->major == (uint16_t)BNX2X_UNKNOWN_MAJOR_VERSION) &&
	    (version->minor == (uint16_t)BNX2X_UNKNOWN_MINOR_VERSION) &&
	    (version->sub_minor == (uint16_t)BNX2X_UNKNOWN_SUB_MINOR_VERSION)) {
		return 1;
	}

	return 0;
}

/**
 * bnx2x_get_drv_version() - Used to determine the driver version
 * @param bp - Device used to determine bnx2x driver version
 */
static int bnx2x_get_drv_version(bnx2x_t *bp)
{
	nic_t *nic = bp->parent;
	int fd, rc;
	struct ifreq ifr;
	struct ethtool_drvinfo drvinfo;
	char *tok, *save_ptr = NULL;

	/* Setup our control structures. */
	memset(&ifr, 0, sizeof(ifr));
	strcpy(ifr.ifr_name, nic->eth_device_name);

	/* Open control socket. */
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) {
		LOG_ERR(PFX "%s: Cannot get socket to determine version "
			"[0x%x %s]", nic->log_name, errno, strerror(errno));
		return -EIO;
	}

	memset(&drvinfo, 0, sizeof(drvinfo));
	drvinfo.cmd = ETHTOOL_GDRVINFO;
	ifr.ifr_data = (caddr_t) &drvinfo;
	rc = ioctl(fd, SIOCETHTOOL, &ifr);
	if (rc < 0) {
		LOG_ERR(PFX "%s: call to ethool IOCTL failed [0x%x %s]",
			nic->log_name, errno, strerror(errno));
		goto error;
	}

	tok = strtok_r(drvinfo.version, ".", &save_ptr);
	if (tok == NULL) {
		rc = -EIO;
		goto error;
	}
	bp->version.major = atoi(tok);

	tok = strtok_r(NULL, ".", &save_ptr);
	if (tok == NULL) {
		rc = -EIO;
		goto error;
	}
	bp->version.minor = atoi(tok);

	tok = strtok_r(NULL, ".", &save_ptr);
	if (tok == NULL) {
		rc = -EIO;
		goto error;
	}
	bp->version.sub_minor = atoi(tok);

	LOG_INFO(PFX "%s: bnx2x driver using version %d.%d.%d",
		 nic->log_name,
		 bp->version.major, bp->version.minor, bp->version.sub_minor);

	close(fd);

	return 0;

error:
	close(fd);
	bnx2x_set_drv_version_unknown(bp);

	LOG_ERR(PFX "%s: error parsing driver string: '%s'",
		nic->log_name, drvinfo.version);

	return rc;

}

static inline int bnx2x_is_ver70(bnx2x_t *bp)
{
	return (bp->version.major == 1 && bp->version.minor >= 70);
}

static inline int bnx2x_is_ver60(bnx2x_t *bp)
{
	return (bp->version.major == 1 && (bp->version.minor == 60 ||
					   bp->version.minor == 62 ||
					   bp->version.minor == 64));
}

static inline int bnx2x_is_ver60_plus(bnx2x_t *bp)
{
	return bnx2x_is_ver60(bp) || bnx2x_is_ver70(bp);
}

static inline int bnx2x_is_ver52(bnx2x_t *bp)
{
	return (bp->version.major == 1 && bp->version.minor == 52);
}

static void bnx2x_wr32(bnx2x_t *bp, __u32 off, __u32 val)
{
	*((volatile __u32 *)(bp->reg + off)) = val;
}

static void bnx2x_doorbell(bnx2x_t *bp, __u32 off, __u32 val)
{
	*((volatile __u32 *)(bp->reg2 + off)) = val;
}

static void bnx2x_flush_doorbell(bnx2x_t *bp, __u32 off)
{
	volatile __u32 tmp __attribute__((__unused__));

	barrier();
	tmp = *((volatile __u32 *)(bp->reg2 + off));
}

static __u32 bnx2x_rd32(bnx2x_t *bp, __u32 off)
{
	return *((volatile __u32 *)(bp->reg + off));
}

static int bnx2x_reg_sync(bnx2x_t *bp, __u32 off, __u16 length)
{
	return msync(bp->reg + off, length, MS_SYNC);
}

static void bnx2x_update_rx_prod(bnx2x_t *bp)
{
	struct ustorm_eth_rx_producers rx_prods = { 0 };
	int i;

	rx_prods.bd_prod = bp->rx_bd_prod;
	rx_prods.cqe_prod = bp->rx_prod;

	barrier();

	for (i = 0; i < sizeof(struct ustorm_eth_rx_producers) / 4; i++)
		bnx2x_wr32(bp, bp->rx_prod_io + i * 4,
			   ((__u32 *)&rx_prods)[i]);

	barrier();

	bnx2x_reg_sync(bp, bp->rx_prod_io,
		       sizeof(struct ustorm_eth_rx_producers));
}

/**
 * bnx2x_get_chip_id() - Used to retrive the chip ID from the nic
 * @param dev - Device used to determin NIC type
 * @return Chip ID read from the MISC ID register
 */
static int bnx2x_get_chip_id(bnx2x_t *bp)
{
	int val, id;

	/* Get the chip revision id and number. */
	/* chip num:16-31, rev:12-15, metal:4-11, bond_id:0-3 */
	val = bnx2x_rd32(bp, BNX2X_MISC_REG_CHIP_NUM);
	id = ((val & 0xffff) << 16);
	val = bnx2x_rd32(bp, BNX2X_MISC_REG_CHIP_REV);
	id |= ((val & 0xf) << 12);
	val = bnx2x_rd32(bp, BNX2X_MISC_REG_CHIP_METAL);
	id |= ((val & 0xff) << 4);
	val = bnx2x_rd32(bp, BNX2X_MISC_REG_BOND_ID);
	id |= (val & 0xf);

	return id;
}

/**
 *  bnx2x_uio_verify()
 *
 */
static int bnx2x_uio_verify(nic_t *nic)
{
	char *raw = NULL, *raw_tmp;
	uint32_t raw_size = 0;
	char temp_path[sizeof(cnic_uio_sysfs_name_tempate) + 8];
	int rc = 0;

	/*  Build the path to determine uio name */
	snprintf(temp_path, sizeof(temp_path),
		 cnic_uio_sysfs_name_tempate, nic->uio_minor);

	rc = capture_file(&raw, &raw_size, temp_path);
	if (rc != 0)
		goto error;

	/* sanitize name string by replacing newline with null termination */
	raw_tmp = raw;
	while (*raw_tmp != '\n')
		raw_tmp++;
	*raw_tmp = '\0';

	if (strncmp(raw, bnx2x_uio_sysfs_name,
		    sizeof(bnx2x_uio_sysfs_name)) != 0) {
		LOG_ERR(PFX "%s: uio names not equal: "
			"expecting %s got %s from %s",
			nic->log_name, bnx2x_uio_sysfs_name, raw, temp_path);
		rc = -EIO;
	}

	free(raw);

	LOG_INFO(PFX "%s: Verified is a cnic_uio device", nic->log_name);

error:
	return rc;
}

/*******************************************************************************
 * bnx2x Utility Functions to get to the hardware consumer indexes
 ******************************************************************************/
static __u16 bnx2x_get_rx(bnx2x_t *bp)
{
	struct host_def_status_block *sblk = bp->status_blk.def;
	__u16 rx_comp_cons;

	msync(sblk, sizeof(*sblk), MS_SYNC);
	rx_comp_cons =
	    sblk->u_def_status_block.
	    index_values[HC_INDEX_DEF_U_ETH_ISCSI_RX_CQ_CONS];
	if ((rx_comp_cons & BNX2X_MAX_RCQ_DESC_CNT(bp)) ==
	    BNX2X_MAX_RCQ_DESC_CNT(bp))
		rx_comp_cons++;

	return rx_comp_cons;
}

static __u16 bnx2x_get_rx_60(bnx2x_t *bp)
{
	struct host_sp_status_block *sblk = bp->status_blk.sp;
	__u16 rx_comp_cons;

	msync(sblk, sizeof(*sblk), MS_SYNC);
	rx_comp_cons =
	    sblk->sp_sb.index_values[HC_SP_INDEX_ETH_ISCSI_RX_CQ_CONS];
	if ((rx_comp_cons & BNX2X_MAX_RCQ_DESC_CNT(bp)) ==
	    BNX2X_MAX_RCQ_DESC_CNT(bp))
		rx_comp_cons++;

	return rx_comp_cons;
}

static __u16 bnx2x_get_tx(bnx2x_t *bp)
{
	struct host_def_status_block *sblk = bp->status_blk.def;
	__u16 tx_cons;

	msync(sblk, sizeof(*sblk), MS_SYNC);
	tx_cons =
	    sblk->c_def_status_block.
	    index_values[HC_INDEX_DEF_C_ETH_ISCSI_CQ_CONS];

	return tx_cons;
}

static __u16 bnx2x_get_tx_60(bnx2x_t *bp)
{
	struct host_sp_status_block *sblk = bp->status_blk.sp;
	__u16 tx_cons;

	msync(sblk, sizeof(*sblk), MS_SYNC);
	tx_cons = sblk->sp_sb.index_values[HC_SP_INDEX_ETH_ISCSI_CQ_CONS];

	return tx_cons;
}

typedef enum {
	CNIC_VLAN_STRIPPING_ENABLED = 1,
	CNIC_VLAN_STRIPPING_DISABLED = 2,
} CNIC_VLAN_STRIPPING_MODE;

/**
 *  bnx2x_strip_vlan_enabled() - This will query the device to determine whether
 *                              VLAN tag stripping is enabled or not
 *  @param dev - device to check stripping or not
 *  @ return CNIC_VLAN_STRIPPING_ENABLED stripping is enabled
 *           CNIC_VLAN_STRIPPING_DISABLED stripping is not enabled
 */
static CNIC_VLAN_STRIPPING_MODE bnx2x_strip_vlan_enabled(bnx2x_t *bp)
{
	return CNIC_VLAN_STRIPPING_DISABLED;
}

/**
 *  bnx2x_free() - Used to free a bnx2x structure
 */
static void bnx2x_free(nic_t *nic)
{
	if (nic->priv)
		free(nic->priv);
	nic->priv = NULL;
}

/**
 *  bnx2x_alloc() - Used to allocate a bnx2x structure
 */
static bnx2x_t *bnx2x_alloc(nic_t *nic)
{
	bnx2x_t *bp = malloc(sizeof(*bp));

	if (bp == NULL) {
		LOG_ERR(PFX "%s: Could not allocate BNX2X space",
			nic->log_name);
		return NULL;
	}

	/*  Clear out the CNIC contents */
	memset(bp, 0, sizeof(*bp));

	bp->bar0_fd = INVALID_FD;
	bp->bar2_fd = INVALID_FD;

	bp->parent = nic;
	nic->priv = (void *)bp;

	bnx2x_set_drv_version_unknown(bp);

	return bp;
}

/**
 * bnx2x_open() - This will initialize all the hardware resources underneath
 *               a struct cnic_uio device
 * @param dev - The struct cnic_uio device to attach the hardware with
 * @return 0 on success, on failure a errno will be returned
 */
static int bnx2x_open(nic_t *nic)
{
	bnx2x_t *bp;
	struct stat uio_stat;
	int i, rc;
	__u32 val;
	int count;
	char sysfs_resc_path[80];
	uint32_t bus;
	uint32_t slot;
	uint32_t func;
	uint32_t mode;
	__u32 proto_offset;
	__u32 ovtag_offset;

	/*  Sanity Check: validate the parameters */
	if (nic == NULL) {
		LOG_ERR(PFX "nic == NULL");
		return -EINVAL;
	}

	if ((nic->priv) != NULL &&
	    (((bnx2x_t *) (nic->priv))->flags & BNX2X_OPENED)) {
		return 0;
	}

	bp = bnx2x_alloc(nic);
	if (bp == NULL)
		return -ENOMEM;

	if (bnx2x_is_drv_version_unknown(&bnx2x_version)) {
		/* If version is unknown, go read from ethtool */
		rc = bnx2x_get_drv_version(bp);
		if (rc)
			goto open_error;
	} else {
		/* Version is not unknown, just use it */
		bnx2x_version.major = bp->version.major;
		bnx2x_version.minor = bp->version.minor;
		bnx2x_version.sub_minor = bp->version.sub_minor;
	}

	count = 0;
	while ((nic->fd < 0) && count < 15) {
		/*  udev might not have created the file yet */
		pthread_mutex_unlock(&nic->nic_mutex);
		sleep(1);
		pthread_mutex_lock(&nic->nic_mutex);

		nic->fd = open(nic->uio_device_name, O_RDWR | O_NONBLOCK);
		if (nic->fd != INVALID_FD) {
			LOG_ERR(PFX "%s: uio device has been brought up "
				"via pid: %d on fd: %d",
				nic->uio_device_name, getpid(), nic->fd);

			rc = bnx2x_uio_verify(nic);
			if (rc != 0)
				continue;

			break;
		} else {
			LOG_WARN(PFX "%s: Could not open device: %s, [%s]",
				 nic->log_name, nic->uio_device_name,
				 strerror(errno));

			manually_trigger_uio_event(nic, nic->uio_minor);

			/*  udev might not have created the file yet */
			pthread_mutex_unlock(&nic->nic_mutex);
			sleep(1);
			pthread_mutex_lock(&nic->nic_mutex);

			count++;
		}
	}
	if (fstat(nic->fd, &uio_stat) < 0) {
		LOG_ERR(PFX "%s: Could not fstat device", nic->log_name);
		rc = -ENODEV;
		goto open_error;
	}
	nic->uio_minor = minor(uio_stat.st_rdev);

	cnic_get_sysfs_pci_resource_path(nic, 0, sysfs_resc_path, 80);
	bp->bar0_fd = open(sysfs_resc_path, O_RDWR | O_SYNC);
	if (bp->bar0_fd < 0) {
		LOG_ERR(PFX "%s: Could not open %s", nic->log_name,
			sysfs_resc_path);
		rc = -ENODEV;
		goto open_error;
	}

	bp->reg = mmap(NULL, BNX2X_BAR_SIZE, PROT_READ | PROT_WRITE,
			MAP_SHARED, bp->bar0_fd, (off_t) 0);

	if (bp->reg == MAP_FAILED) {
		LOG_INFO(PFX "%s: Couldn't mmap BAR registers: %s",
			 nic->log_name, strerror(errno));
		bp->reg = NULL;
		rc = errno;
		goto open_error;
	}

	msync(bp->reg, BNX2X_BAR_SIZE, MS_SYNC);

	cnic_get_sysfs_pci_resource_path(nic, 2, sysfs_resc_path, 80);
	bp->bar2_fd = open(sysfs_resc_path, O_RDWR | O_SYNC);
	if (bp->bar2_fd < 0) {
		LOG_ERR(PFX "%s: Could not open %s", nic->log_name,
			sysfs_resc_path);
		rc = -ENODEV;
		goto open_error;
	}

	bp->reg2 = mmap(NULL, BNX2X_BAR2_SIZE, PROT_READ | PROT_WRITE,
			MAP_SHARED, bp->bar2_fd, (off_t) 0);

	if (bp->reg2 == MAP_FAILED) {
		LOG_INFO(PFX "%s: Couldn't mmap BAR2 registers: %s",
			 nic->log_name, strerror(errno));
		bp->reg2 = NULL;
		rc = errno;
		goto open_error;
	}

	/*  TODO: hardcoded with the cnic driver */
	bp->rx_ring_size = 15;
	bp->rx_buffer_size = 0x400;

	LOG_DEBUG(PFX "%s: using rx ring size: %d, rx buffer size: %d",
		  nic->log_name, bp->rx_ring_size, bp->rx_buffer_size);

	/*  Determine the number of UIO events that have already occured */
	rc = detemine_initial_uio_events(nic, &nic->intr_count);
	if (rc != 0) {
		LOG_ERR("Could not determine the number ofinitial UIO events");
		nic->intr_count = 0;
	}

	/*  Allocate space for rx pkt ring */
	bp->rx_pkt_ring = malloc(sizeof(void *) * bp->rx_ring_size);
	if (bp->rx_pkt_ring == NULL) {
		LOG_ERR(PFX "%s: Could not allocate space for rx_pkt_ring",
			nic->log_name);
		rc = errno;
		goto open_error;
	}

	if (bnx2x_is_ver60_plus(bp))
		bp->status_blk_size = sizeof(struct host_sp_status_block);
	else if (bnx2x_is_ver52(bp))
		bp->status_blk_size = sizeof(struct host_def_status_block);
	else {
		LOG_INFO(PFX "%s: Unsupported bnx2x driver [%d.%d]",
			 nic->log_name, bp->version.major, bp->version.minor);

		rc = -ENOTSUP;
		goto open_error;
	}

	bp->status_blk.def = mmap(NULL, bp->status_blk_size,
				  PROT_READ | PROT_WRITE, MAP_SHARED,
				  nic->fd, (off_t) nic->page_size);
	if (bp->status_blk.def == MAP_FAILED) {
		LOG_INFO(PFX "%s: Could not mmap status block: %s",
			 nic->log_name, strerror(errno));
		bp->status_blk.def = NULL;
		rc = errno;
		goto open_error;
	}

	bp->tx_ring = mmap(NULL, 4 * nic->page_size,
			   PROT_READ | PROT_WRITE,
			   MAP_SHARED | MAP_LOCKED,
			   nic->fd, (off_t) 2 * nic->page_size);
	if (bp->tx_ring == MAP_FAILED) {
		LOG_INFO(PFX "%s: Could not mmap tx ring: %s",
			 nic->log_name, strerror(errno));
		bp->tx_ring = NULL;
		rc = errno;
		goto open_error;
	}

	bp->rx_comp_ring.cqe = (union eth_rx_cqe *)
	    (((__u8 *) bp->tx_ring) + 2 * nic->page_size);

	bp->bufs = mmap(NULL, (bp->rx_ring_size + 1) * bp->rx_buffer_size,
			PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_LOCKED,
			nic->fd, (off_t) 3 * nic->page_size);
	if (bp->bufs == MAP_FAILED) {
		LOG_INFO(PFX "%s: Could not mmap buffers: %s",
			 nic->log_name, strerror(errno));
		bp->bufs = NULL;
		rc = errno;
		goto open_error;
	}

	bp->chip_id = bnx2x_get_chip_id(bp);
	LOG_DEBUG(PFX "Chip ID: %x", bp->chip_id);

	rc = get_bus_slot_func_num(nic, &bus, &slot, &func);
	if (rc != 0) {
		LOG_INFO(PFX "%s: Couldn't determine bus:slot.func",
			 nic->log_name);
		goto open_error;
	}
	/* In E1/E1H use pci device function as read from sysfs.
	 * In E2/E3 read physical function from ME register since these chips
	 * support Physical Device Assignment where kernel BDF maybe arbitrary
	 * (depending on hypervisor).
	 */
	if (CHIP_IS_E2_PLUS(bp)) {
		func = (bnx2x_rd32(bp, BAR_ME_REGISTER) & ME_REG_ABS_PF_NUM) >>
			ME_REG_ABS_PF_NUM_SHIFT;
	}
	bp->func = func;
	bp->port = bp->func % PORT_MAX;

	if (CHIP_IS_E2_PLUS(bp)) {
		__u32 val = bnx2x_rd32(bp, MISC_REG_PORT4MODE_EN_OVWR);
		if (!(val & 1))
			val = bnx2x_rd32(bp, MISC_REG_PORT4MODE_EN);
		else
			val = (val >> 1) & 1;

		if (val)
			bp->pfid = func >> 1;
		else
			bp->pfid = func & 0x6;
	} else {
		bp->pfid = func;
	}

	if (bnx2x_is_ver60_plus(bp))
		bp->port = bp->pfid & 1;

	bp->cid = 17;
	bp->client_id = 17;

	if (bnx2x_is_ver60_plus(bp)) {
		struct client_init_general_data *data = bp->bufs;

		bp->client_id = data->client_id;
		if (data->uid.cid)
			bp->cid = data->uid.cid;
		if (bp->version.minor >= 78 && bp->version.sub_minor >= 55 &&
		    data->uid.cid_override_key == UIO_USE_TX_DOORBELL) {
			bp->tx_doorbell = data->uid.tx_db_off;
			LOG_INFO(PFX "%s: tx doorbell override offset = 0x%x",
				 nic->log_name, bp->tx_doorbell);
		}
	}

	LOG_INFO(PFX "%s: func 0x%x, pfid 0x%x, client_id 0x%x, cid 0x%x",
		 nic->log_name, bp->func, bp->pfid, bp->client_id, bp->cid);

	if (CHIP_IS_E1(bp))
		bp->iro = e1_iro;
	else if (CHIP_IS_E1H(bp))
		bp->iro = e1h_iro;
	else if (CHIP_IS_E2_PLUS(bp))
		bp->iro = e2_iro;

	if (bnx2x_is_ver60_plus(bp)) {
		__u32 cl_qzone_id = BNX2X_CL_QZONE_ID(bp, bp->client_id);

		bp->iro_idx = 0;
		if (bp->version.minor >= 64) {
			bp->iro_idx = 1;
			cl_qzone_id = BNX2X_CL_QZONE_ID_64(bp, bp->client_id);
		}

		bp->rx_prod_io = BAR_USTRORM_INTMEM +
		    (CHIP_IS_E2_PLUS(bp) ?
		     USTORM_RX_PRODS_E2_OFFSET(cl_qzone_id) :
		     USTORM_RX_PRODS_E1X_OFFSET(bp->port, bp->client_id));

		if (!bp->tx_doorbell)
			bp->tx_doorbell = bp->cid * 0x80 + 0x40;

		bp->get_rx_cons = bnx2x_get_rx_60;
		bp->get_tx_cons = bnx2x_get_tx_60;
		bp->tx_vlan_tag_bit = ETH_TX_BD_FLAGS_VLAN_TAG_T6X;
	} else {
		bp->rx_prod_io = BAR_USTRORM_INTMEM +
		    USTORM_RX_PRODS_OFFSET(bp->port, bp->client_id);

		bp->tx_doorbell = bp->cid * nic->page_size + 0x40;

		bp->get_rx_cons = bnx2x_get_rx;
		bp->get_tx_cons = bnx2x_get_tx;
		bp->tx_vlan_tag_bit = ETH_TX_BD_FLAGS_VLAN_TAG_T5X;
	}

	bp->tx_cons = 0;
	bp->tx_prod = 0;
	bp->tx_bd_prod = 0;
	bp->tx_pkt = bp->bufs;

	bp->rx_index = 0;
	bp->rx_cons = 0;
	bp->rx_bd_cons = 0;
	bp->rx_prod = 127;
	bp->rx_bd_prod = bp->rx_ring_size;

	for (i = 0; i < bp->rx_ring_size; i++) {
		void *ptr = bp->bufs + (bp->rx_buffer_size * (i + 1));

		bp->rx_pkt_ring[i] = ptr;
	}

	val = bnx2x_rd32(bp, MISC_REG_SHARED_MEM_ADDR);

	bp->shmem_base = val;
	val = bnx2x_rd32(bp, bp->shmem_base + SHMEM_ISCSI_MAC_UPPER(bp));
	nic->mac_addr[0] = (__u8) (val >> 8);
	nic->mac_addr[1] = (__u8) val;
	val = bnx2x_rd32(bp, bp->shmem_base + SHMEM_ISCSI_MAC_LOWER(bp));
	nic->mac_addr[2] = (__u8) (val >> 24);
	nic->mac_addr[3] = (__u8) (val >> 16);
	nic->mac_addr[4] = (__u8) (val >> 8);
	nic->mac_addr[5] = (__u8) val;

	if (bnx2x_is_ver60_plus(bp) && CHIP_IS_E2_PLUS(bp)) {
		__u32 mf_cfg_addr = 0;
		__u32 mac_offset;
		__u8 mac[6];

		val = bnx2x_rd32(bp, (BNX2X_PATH(bp) ? MISC_REG_GENERIC_CR_1 :
				      MISC_REG_GENERIC_CR_0));
		bp->shmem_base2 = val;
		if (bp->shmem_base2) {
			/* size */
			val = bnx2x_rd32(bp, bp->shmem_base2);

			if (val > 0x10)
				mf_cfg_addr =
				    bnx2x_rd32(bp, bp->shmem_base2 + 0x10);
		}

		if (!mf_cfg_addr)
			mf_cfg_addr = bp->shmem_base + 0x7e4;

		/* shared_feat_cfg.config */
		mode = bnx2x_rd32(bp, bp->shmem_base + 0x354);
		mode &= 0x700;
		LOG_DEBUG(PFX "%s: mode = 0x%x", nic->log_name, mode);
		switch (mode) {
		case 0x300: /* SI mode */
			mac_offset = 0xe4 + (bp->func * 0x28) + 4;
			val = bnx2x_rd32(bp, mf_cfg_addr + mac_offset);
			mac[0] = (__u8) (val >> 8);
			mac[1] = (__u8) val;
			mac_offset += 4;
			val = bnx2x_rd32(bp, mf_cfg_addr + mac_offset);
			mac[2] = (__u8) (val >> 24);
			mac[3] = (__u8) (val >> 16);
			mac[4] = (__u8) (val >> 8);
			mac[5] = (__u8) val;

			if (mac[0] != 0xff) {
				memcpy(nic->mac_addr, mac, 6);
			} else if (bp->func > 1) {
				LOG_INFO(PFX "%s:  Invalid mac address: "
					 "%02x:%02x:%02x:%02x:%02x:%02x, abort",
					 nic->log_name,
					 mac[0], mac[1], mac[2],
					 mac[3], mac[4], mac[5]);
				rc = -ENOTSUP;
				goto open_error;
			}
			break;

		case 0x0: /* MF SD mode */
		case 0x500:
		case 0x600:
			proto_offset = 0x24 + (bp->func * 0x18);
			ovtag_offset = proto_offset + 0xc;

			rc = -ENOTSUP;
			val = bnx2x_rd32(bp, mf_cfg_addr + ovtag_offset);
			val &= 0xffff;
			/* SD mode, check for valid outer VLAN */
			if (val == 0xffff) {
				LOG_ERR(PFX "%s: Invalid OV detected for SD, "
					" fallback to SF mode!\n",
					nic->log_name);
				goto SF;
			}
			/* Check for iSCSI protocol */
			val = bnx2x_rd32(bp, mf_cfg_addr + proto_offset);
			if ((val & 6) != 6)
				goto open_error;

			mac_offset = proto_offset + 0x4;
			val = bnx2x_rd32(bp, mf_cfg_addr + mac_offset);
			mac[0] = (__u8) (val >> 8);
			mac[1] = (__u8) val;
			mac_offset += 4;
			val = bnx2x_rd32(bp, mf_cfg_addr + mac_offset);
			mac[2] = (__u8) (val >> 24);
			mac[3] = (__u8) (val >> 16);
			mac[4] = (__u8) (val >> 8);
			mac[5] = (__u8) val;
			memcpy(nic->mac_addr, mac, 6);
			break;
		}
	}
SF:
	LOG_INFO(PFX "%s:  Using mac address: %02x:%02x:%02x:%02x:%02x:%02x",
		 nic->log_name,
		 nic->mac_addr[0], nic->mac_addr[1], nic->mac_addr[2],
		 nic->mac_addr[3], nic->mac_addr[4], nic->mac_addr[5]);

	/*  Determine if Hardware VLAN tag stripping is enabled or not */
	if (CNIC_VLAN_STRIPPING_ENABLED == bnx2x_strip_vlan_enabled(bp))
		nic->flags |= NIC_VLAN_STRIP_ENABLED;

	msync(bp->reg, BNX2X_BAR_SIZE, MS_SYNC);

	LOG_INFO("%s: bnx2x initialized", nic->log_name);

	bnx2x_update_rx_prod(bp);
	bp->flags |= BNX2X_OPENED;

	return 0;

open_error:
	if (bp->tx_ring) {
		munmap(bp->tx_ring, 4 * nic->page_size);
		bp->tx_ring = NULL;
	}

	if (bp->status_blk.def) {
		munmap(bp->status_blk.def, bp->status_blk_size);
		bp->status_blk.def = NULL;
	}

	if (bp->reg) {
		munmap(bp->reg, BNX2X_BAR_SIZE);
		bp->reg = NULL;
	}

	if (bp->reg2) {
		munmap(bp->reg2, BNX2X_BAR2_SIZE);
		bp->reg2 = NULL;
	}

	if (bp->rx_pkt_ring) {
		free(bp->rx_pkt_ring);
		bp->rx_pkt_ring = NULL;
	}

	if (bp->bar2_fd != INVALID_FD) {
		close(bp->bar2_fd);
		bp->bar2_fd = INVALID_FD;
	}

	if (bp->bar0_fd != INVALID_FD) {
		close(bp->bar0_fd);
		bp->bar0_fd = INVALID_FD;
	}
	if (nic->fd != INVALID_FD) {
		close(nic->fd);
		nic->fd = INVALID_FD;
	}
	bnx2x_free(nic);

	return rc;
}

/**
 *  bnx2x_uio_close_resources() - Used to free resource for the NIC/CNIC
 *  @param nic - NIC device to free resource
 *  @param graceful - whether to wait to close gracefully
 *  @return 0 on success, <0 on failure
 */
static int bnx2x_uio_close_resources(nic_t *nic, NIC_SHUTDOWN_T graceful)
{
	bnx2x_t *bp = (bnx2x_t *) nic->priv;
	int rc = 0;

	/*  Check if there is an assoicated bnx2x device */
	if (bp == NULL) {
		LOG_WARN(PFX "%s: when closing resources there is "
			 "no assoicated bnx2x", nic->log_name);
		return -EIO;
	}

	/*  Clean up allocated memory */

	if (bp->rx_pkt_ring != NULL) {
		free(bp->rx_pkt_ring);
		bp->rx_pkt_ring = NULL;
	}

	/*  Clean up mapped registers */
	if (bp->bufs != NULL) {
		rc = munmap(bp->bufs,
			    (bp->rx_ring_size + 1) * bp->rx_buffer_size);
		if (rc != 0)
			LOG_WARN(PFX "%s: Couldn't unmap bufs", nic->log_name);
		bp->bufs = NULL;
	}

	if (bp->tx_ring != NULL) {
		rc = munmap(bp->tx_ring, 4 * nic->page_size);
		if (rc != 0)
			LOG_WARN(PFX "%s: Couldn't unmap tx_rings",
				 nic->log_name);
		bp->tx_ring = NULL;
	}

	if (bp->status_blk.def != NULL) {
		rc = munmap(bp->status_blk.def, bp->status_blk_size);
		if (rc != 0)
			LOG_WARN(PFX "%s: Couldn't unmap status block",
				 nic->log_name);
		bp->status_blk.def = NULL;
	}

	if (bp->reg != NULL) {
		rc = munmap(bp->reg, BNX2X_BAR_SIZE);
		if (rc != 0)
			LOG_WARN(PFX "%s: Couldn't unmap regs", nic->log_name);
		bp->reg = NULL;
	}

	if (bp->reg2 != NULL) {
		rc = munmap(bp->reg2, BNX2X_BAR2_SIZE);
		if (rc != 0)
			LOG_WARN(PFX "%s: Couldn't unmap regs", nic->log_name);
		bp->reg2 = NULL;
	}

	if (bp->bar2_fd != INVALID_FD) {
		close(bp->bar2_fd);
		bp->bar2_fd = INVALID_FD;
	}

	if (bp->bar0_fd != INVALID_FD) {
		close(bp->bar0_fd);
		bp->bar0_fd = INVALID_FD;
	}

	if (nic->fd != INVALID_FD) {
		rc = close(nic->fd);
		if (rc != 0) {
			LOG_WARN(PFX
				 "%s: Couldn't close uio file descriptor: %d",
				 nic->log_name, nic->fd);
		} else {
			LOG_DEBUG(PFX "%s: Closed uio file descriptor: %d",
				  nic->log_name, nic->fd);
		}

		nic->fd = INVALID_FD;
	} else {
		LOG_WARN(PFX "%s: Invalid uio file descriptor: %d",
			 nic->log_name, nic->fd);
	}

	bnx2x_set_drv_version_unknown(bp);

	LOG_INFO(PFX "%s: Closed all resources", nic->log_name);

	return 0;
}

/**
 *  bnx2x_close() - Used to close the NIC device
 *  @param nic - NIC device to close
 *  @param graceful - whether to wait to close gracefully
 *  @return 0 if successful, <0 if there is an error
 */
static int bnx2x_close(nic_t *nic, NIC_SHUTDOWN_T graceful)
{
	/*  Sanity Check: validate the parameters */
	if (nic == NULL) {
		LOG_ERR(PFX "bnx2x_close(): nic == NULL");
		return -EINVAL;
	}
	if (nic->priv == NULL) {
		LOG_ERR(PFX "bnx2x_close(): nic->priv == NULL");
		return -EINVAL;
	}

	LOG_INFO(PFX "Closing NIC device: %s", nic->log_name);

	bnx2x_uio_close_resources(nic, graceful);
	bnx2x_free(nic);

	return 0;
}

static void bnx2x_prepare_xmit_packet(nic_t *nic,
				      nic_interface_t *nic_iface,
				      struct packet *pkt)
{
	bnx2x_t *bp = (bnx2x_t *) nic->priv;
	struct uip_vlan_eth_hdr *eth_vlan = (struct uip_vlan_eth_hdr *)pkt->buf;
	struct uip_eth_hdr *eth = (struct uip_eth_hdr *)bp->tx_pkt;

	if (eth_vlan->tpid == htons(UIP_ETHTYPE_8021Q)) {
		memcpy(bp->tx_pkt, pkt->buf, sizeof(struct uip_eth_hdr));
		eth->type = eth_vlan->type;
		pkt->buf_size -= (sizeof(struct uip_vlan_eth_hdr) -
				  sizeof(struct uip_eth_hdr));
		memcpy(bp->tx_pkt + sizeof(struct uip_eth_hdr),
		       pkt->buf + sizeof(struct uip_vlan_eth_hdr),
		       pkt->buf_size - sizeof(struct uip_eth_hdr));
	} else
		memcpy(bp->tx_pkt, pkt->buf, pkt->buf_size);

	msync(bp->tx_pkt, pkt->buf_size, MS_SYNC);
}

/**
 *  bnx2x_get_tx_pkt() - This function is used to a TX packet from the NIC
 *  @param nic - The NIC device to send the packet
 */
void *bnx2x_get_tx_pkt(nic_t *nic)
{
	bnx2x_t *bp = (bnx2x_t *) nic->priv;
	return bp->tx_pkt;
}

/**
 *  bnx2x_start_xmit() - This function is used to send a packet of data
 *  @param nic - The NIC device to send the packet
 *  @param len - the length of the TX packet
 *
 */
void bnx2x_start_xmit(nic_t *nic, size_t len, u16_t vlan_id)
{
	bnx2x_t *bp = (bnx2x_t *) nic->priv;
	uint16_t ring_prod;
	struct eth_tx_start_bd *txbd;
	struct eth_tx_bd *txbd2;
	struct eth_rx_bd *rx_bd;
	rx_bd = (struct eth_rx_bd *)(((__u8 *) bp->tx_ring) + nic->page_size);

	if ((rx_bd->addr_hi == 0) && (rx_bd->addr_lo == 0)) {
		LOG_PACKET(PFX "%s: trying to transmit when device is closed",
			   nic->log_name);
		pthread_mutex_unlock(&nic->xmit_mutex);
		return;
	}

	ring_prod = BNX2X_TX_RING_IDX(bp->tx_bd_prod);
	txbd = &bp->tx_ring[ring_prod];

	BNX2X_SET_TX_VLAN(bp, txbd, vlan_id);

	bp->tx_prod++;
	bp->tx_bd_prod = BNX2X_NEXT_TX_BD(bp->tx_bd_prod);
	bp->tx_bd_prod = BNX2X_NEXT_TX_BD(bp->tx_bd_prod);

	ring_prod = BNX2X_TX_RING_IDX(bp->tx_bd_prod);
	txbd2 = (struct eth_tx_bd *)&bp->tx_ring[ring_prod];

	txbd2->nbytes = len - 0x10;
	txbd2->total_pkt_bytes = len;

	bp->tx_bd_prod = BNX2X_NEXT_TX_BD(bp->tx_bd_prod);

	barrier();
	if (nic->nl_process_if_down == 0) {
		bnx2x_doorbell(bp, bp->tx_doorbell, 0x02 |
			       (bp->tx_bd_prod << 16));
		bnx2x_flush_doorbell(bp, bp->tx_doorbell);
	} else {
		/* If the doorbell is not rung, the packet will not
		   get sent.  Hence, the xmit_mutex lock will not
		   get freed.
		 */
		pthread_mutex_unlock(&nic->xmit_mutex);
	}
	LOG_PACKET(PFX "%s: sent %d bytes using bp->tx_prod: %d",
		   nic->log_name, len, bp->tx_prod);
}

/**
 *  bnx2x_write() - Used to write the data to the hardware
 *  @param nic - NIC hardware to read from
 *  @param pkt - The packet which will hold the data to be sent on the wire
 *  @return 0 if successful, <0 if failed
 */
int bnx2x_write(nic_t *nic, nic_interface_t *nic_iface, packet_t *pkt)
{
	bnx2x_t *bp;
	struct uip_stack *uip;
	int i = 0;

	/* Sanity Check: validate the parameters */
	if (nic == NULL || nic_iface == NULL || pkt == NULL) {
		LOG_ERR(PFX "%s: bnx2x_write() nic == 0x%p || "
			" nic_iface == 0x%p || "
			" pkt == 0x%x", nic, nic_iface, pkt);
		return -EINVAL;
	}
	bp = (bnx2x_t *) nic->priv;
	uip = &nic_iface->ustack;

	if (pkt->buf_size == 0) {
		LOG_ERR(PFX "%s: Trying to transmitted 0 sized packet",
			nic->log_name);
		return -EINVAL;
	}

	/*  Try to wait for a TX completion */
	for (i = 0; i < 15; i++) {
		struct timespec sleep_req = {.tv_sec = 0, .tv_nsec = 5000000 },
		    sleep_rem;

		if (bnx2x_clear_tx_intr(nic) == 0)
			break;

		nanosleep(&sleep_req, &sleep_rem);
	}

	if (pthread_mutex_trylock(&nic->xmit_mutex) != 0) {
		LOG_PACKET(PFX "%s: Dropped previous transmitted packet",
			   nic->log_name);
		return -EINVAL;
	}

	bnx2x_prepare_xmit_packet(nic, nic_iface, pkt);
	bnx2x_start_xmit(nic, pkt->buf_size,
			 (nic_iface->vlan_priority << 12) |
			 nic_iface->vlan_id);

	/*  bump the cnic dev send statistics */
	nic->stats.tx.packets++;
	nic->stats.tx.bytes += uip->uip_len;

	LOG_PACKET(PFX "%s: transmitted %d bytes "
		   "dev->tx_cons: %d, dev->tx_prod: %d, dev->tx_bd_prod:%d",
		   nic->log_name, pkt->buf_size,
		   bp->tx_cons, bp->tx_prod, bp->tx_bd_prod);

	return 0;
}

static inline int bnx2x_get_rx_pad(bnx2x_t *bp, union eth_rx_cqe *cqe)
{
	int pad = 0;

	if (bnx2x_is_ver70(bp))
		pad = ((union eth_rx_cqe_70 *)cqe)->fast_path_cqe_70. \
						    placement_offset;
	else if (bnx2x_is_ver60(bp)) {
		if (bp->version.minor >= 64)
			pad = cqe->fast_path_cqe_64.placement_offset;
		else
			pad = cqe->fast_path_cqe.placement_offset;
	}
	return pad;
}

/**
 *  bnx2x_read() - Used to read the data from the hardware
 *  @param nic - NIC hardware to read from
 *  @param pkt - The packet which will hold the data
 *  @return 0 if successful, <0 if failed
 */
static int bnx2x_read(nic_t *nic, packet_t *pkt)
{
	bnx2x_t *bp;
	int rc = 0;
	uint16_t hw_cons, sw_cons, bd_cons, bd_prod;

	/* Sanity Check: validate the parameters */
	if (nic == NULL || pkt == NULL) {
		LOG_ERR(PFX "%s: bnx2x_read() nic == 0x%p || "
			" pkt == 0x%x", nic, pkt);
		return -EINVAL;
	}
	bp = (bnx2x_t *) nic->priv;

	hw_cons = bp->get_rx_cons(bp);
	sw_cons = bp->rx_cons;
	bd_cons = BNX2X_RX_BD(bp->rx_bd_cons);
	bd_prod = BNX2X_RX_BD(bp->rx_bd_prod);

	if (sw_cons != hw_cons) {
		uint16_t comp_ring_index = sw_cons & BNX2X_MAX_RCQ_DESC_CNT(bp);
		uint8_t ring_index;
		union eth_rx_cqe *cqe;
		__u8 cqe_fp_flags;
		void *rx_pkt;
		int len, pad, cqe_size, max_len;
		rc = 1;

		if (bnx2x_is_ver70(bp)) {
			cqe = (union eth_rx_cqe *)
			      &bp->rx_comp_ring.cqe70[comp_ring_index];
			cqe_size = sizeof(union eth_rx_cqe_70);
		} else {
			cqe = &bp->rx_comp_ring.cqe[comp_ring_index];
			cqe_size = sizeof(union eth_rx_cqe);
		}
		cqe_fp_flags = cqe->fast_path_cqe.type_error_flags;

		LOG_PACKET(PFX "%s: clearing rx interrupt: %d %d",
			   nic->log_name, sw_cons, hw_cons);

		msync(cqe, cqe_size, MS_SYNC);

		if (!(cqe_fp_flags & ETH_FAST_PATH_RX_CQE_TYPE)) {
			ring_index = bd_cons % 15;
			len = cqe->fast_path_cqe.pkt_len;
			pad = bnx2x_get_rx_pad(bp, cqe);
			rx_pkt = bp->rx_pkt_ring[ring_index] + pad;

			/*  Doto query MTU size of physical device */
			/*  Ensure len is valid */
			max_len = pkt->max_buf_size < bp->rx_buffer_size ?
				  pkt->max_buf_size : bp->rx_buffer_size;
			if (len + pad > max_len) {
				LOG_DEBUG(PFX "%s: bad BD length: %d",
					  nic->log_name, len);
				len = max_len - pad;
			}
			if (len > 0) {
				msync(rx_pkt, len, MS_SYNC);
				/*  Copy the data */
				memcpy(pkt->buf, rx_pkt, len);
				pkt->buf_size = len;

				/*  Properly set the packet flags */
				/*  check if there is VLAN tagging */
				if (cqe->fast_path_cqe.vlan_tag != 0) {
					pkt->vlan_tag =
					    cqe->fast_path_cqe.vlan_tag;
					pkt->flags |= VLAN_TAGGED;
				} else {
					pkt->vlan_tag = 0;
				}

				LOG_PACKET(PFX
					   "%s: processing packet length: %d",
					   nic->log_name, len);

				/*  bump the cnic dev recv statistics */
				nic->stats.rx.packets++;
				nic->stats.rx.bytes += pkt->buf_size;
			}

			bd_cons = BNX2X_NEXT_RX_IDX(bd_cons);
			bd_prod = BNX2X_NEXT_RX_IDX(bd_prod);

		}
		sw_cons = BNX2X_NEXT_RCQ_IDX(bp, sw_cons);
		bp->rx_prod = BNX2X_NEXT_RCQ_IDX(bp, bp->rx_prod);
	}
	bp->rx_cons = sw_cons;
	bp->rx_bd_cons = bd_cons;
	bp->rx_bd_prod = bd_prod;
	bp->rx_hw_prod = hw_cons;

	if (rc)
		bnx2x_update_rx_prod(bp);

	return rc;
}

/*******************************************************************************
 * Clearing TX interrupts
 ******************************************************************************/
/**
 *  bnx2x_clear_tx_intr() - This routine is called when a TX interrupt occurs
 *  @param nic - the nic the interrupt occured on
 *  @return  0 on success
 */
static int bnx2x_clear_tx_intr(nic_t *nic)
{
	bnx2x_t *bp;
	uint16_t hw_cons;

	/* Sanity check: ensure the parameters passed in are valid */
	if (unlikely(nic == NULL)) {
		LOG_ERR(PFX "bnx2x_read() nic == NULL");
		return -EINVAL;
	}
	bp = (bnx2x_t *) nic->priv;
	hw_cons = bp->get_tx_cons(bp);

	if (bp->tx_cons == hw_cons) {
		if (bp->tx_cons == bp->tx_prod) {
			/* Make sure the xmit_mutex lock is unlock */
			if (pthread_mutex_trylock(&nic->xmit_mutex))
				LOG_ERR(PFX "bnx2x tx lock with prod == cons");

			pthread_mutex_unlock(&nic->xmit_mutex);
			return 0;
		}
		return -EAGAIN;
	}

	LOG_PACKET(PFX "%s: clearing tx interrupt [%d %d]",
		   nic->log_name, bp->tx_cons, hw_cons);
	bp->tx_cons = hw_cons;

	/*  There is a queued TX packet that needs to be sent out.  The usual
	 *  case is when stack will send an ARP packet out before sending the
	 *  intended packet */
	if (nic->tx_packet_queue != NULL) {
		packet_t *pkt;
		int i;

		LOG_PACKET(PFX "%s: sending queued tx packet", nic->log_name);
		pkt = nic_dequeue_tx_packet(nic);

		/*  Got a TX packet buffer of the TX queue and put it onto
		 *  the hardware */
		if (pkt != NULL) {
			bnx2x_prepare_xmit_packet(nic, pkt->nic_iface, pkt);

			bnx2x_start_xmit(nic, pkt->buf_size,
					 (pkt->nic_iface->vlan_priority << 12) |
					 pkt->nic_iface->vlan_id);

			LOG_PACKET(PFX "%s: transmitted queued packet %d bytes "
				   "dev->tx_cons: %d, dev->tx_prod: %d, "
				   "dev->tx_bd_prod:%d",
				   nic->log_name, pkt->buf_size,
				   bp->tx_cons, bp->tx_prod, bp->tx_bd_prod);

			return 0;
		}

		/*  Try to wait for a TX completion */
		for (i = 0; i < 15; i++) {
			struct timespec sleep_req = {.tv_sec = 0,
				.tv_nsec = 5000000
			}, sleep_rem;

			hw_cons = bp->get_tx_cons(bp);
			if (bp->tx_cons != hw_cons) {
				LOG_PACKET(PFX
					   "%s: clearing tx interrupt [%d %d]",
					   nic->log_name, bp->tx_cons, hw_cons);
				bp->tx_cons = hw_cons;

				break;
			}

			nanosleep(&sleep_req, &sleep_rem);
		}
	}

	pthread_mutex_unlock(&nic->xmit_mutex);

	return 0;
}

/*******************************************************************************
 * bnx2x NIC op's table
 ******************************************************************************/
struct nic_ops bnx2x_op = {
	.description = "bnx2x",
	.open = bnx2x_open,
	.close = bnx2x_close,
	.write = bnx2x_write,
	.get_tx_pkt = bnx2x_get_tx_pkt,
	.start_xmit = bnx2x_start_xmit,
	.read = bnx2x_read,
	.clear_tx_intr = bnx2x_clear_tx_intr,
	.handle_iscsi_path_req = cnic_handle_iscsi_path_req,

	.lib_ops = {
		    .get_library_name = bnx2x_get_library_name,
		    .get_pci_table = bnx2x_get_pci_table,
		    .get_library_version = bnx2x_get_library_version,
		    .get_build_date = bnx2x_get_build_date,
		    .get_transport_name = bnx2x_get_transport_name,
		    .get_uio_name = bnx2x_get_uio_name,
		    },
};
