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
 * qedi.c - qedi user space driver
 * This file handles different qedi NIC operations,
 * qedi_open - initializes all hardware resources under NIC device
 * qedi_close - closes the NIC device
 * qedi_read - reads data to the hardware
 * qedi_write - writes data to the hardware
 * qedi_start_xmit - sends a pkt of data on NIC device
 * qedi_get_tx_pkt - gets a Tx pkt from NIC
 * qedi_clear_tx_intr - clears the Tx interrupt
 * NOTE: nic_t is used as NIC device,
 * 	 qedi is not attached to netdev hence it is not mandatory
 * 	 for netdev to be upd
 */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <linux/types.h>
#include <linux/sockios.h>
#include <linux/netlink.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/user.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/sysmacros.h>

#include "config.h"

#include "build_date.h"
#include "bnx2x.h"
#include "qedi.h"
#include "cnic.h"
#include "logger.h"
#include "nic.h"
#include "nic_id.h"
#include "nic_utils.h"
#include "options.h"

#define PFX	"qedi "

extern int nl_sock;

static pthread_mutex_t host_mutex = PTHREAD_MUTEX_INITIALIZER;

/*  Foward struct declarations */
struct nic_ops qedi_op;

/*******************************************************************************
 * NIC Library Strings
 ******************************************************************************/
static const char library_name[] = "qedi";
static const char library_version[] = PACKAGE_VERSION;
static const char library_uio_name[] = "qedi_uio";

/*  The name that should be returned from /sys/class/uio/uio0/name */
static const char cnic_uio_sysfs_name_tempate[] = "/sys/class/uio/uio%i/name";
static const char qedi_uio_sysfs_name[] = "qedi_uio";
static const char qedi_host_mac_template[] =
	"/sys/class/iscsi_host/host%i/hwaddress";

struct qedi_driver_version qedi_version = {
	QEDI_UNKNOWN_MAJOR_VERSION,
	QEDI_UNKNOWN_MINOR_VERSION,
	QEDI_UNKNOWN_SUB_MINOR_VERSION,
};

static int qedi_clear_tx_intr(nic_t *nic);

/*******************************************************************************
 * QEDI Library Functions
 ******************************************************************************/
/**
 *  qedi_get_library_name() - Used to get the name of this NIC library
 *  @param name - This function will return the pointer to this NIC
 *                library name
 *  @param name_size
 */
static void qedi_get_library_name(char **name, size_t *name_size)
{
	*name = (char *)library_name;
	*name_size = sizeof(library_name);
}

/**
 *  qedi_get_library_version() - Used to get the version string of this
 *                                NIC library
 *  @param version - This function will return the pointer to this NIC
 *                   library version string
 *  @param version_size - This will be set with the version size
 */
static void qedi_get_library_version(char **version, size_t *version_size)
{
	*version = (char *)library_version;
	*version_size = sizeof(library_version);
}

/**
 *  qedi_get_build_date() - Used to get the build date string of this library
 *  @param version - This function will return the pointer to this NIC
 *                   library build date string
 *  @param version_size - This will be set with the build date string size
 */
static void qedi_get_build_date(char **build, size_t *build_size)
{
	*build = (char *)build_date;
	*build_size = sizeof(build_date);
}

/**
 *  qedi_get_transport_name() - Used to get the transport name associated
 *                              with this this NIC library
 *  @param transport_name - This function will return the pointer to this NIC
 *                          library's associated transport string
 *  @param transport_name_size - This will be set with the transport name size
 */
static void qedi_get_transport_name(char **transport_name,
				    size_t *transport_name_size)
{
	*transport_name = (char *)qedi_library_transport_name;
	*transport_name_size = qedi_library_transport_name_size;
}

/**
 *  qedi_get_uio_name() - Used to get the uio name associated with this this
 *                        NIC library
 *  @param uio_name - This function will return the pointer to this NIC
 *                    library's associated uio string
 *  @param transport_name_size - This will be set with the uio name size
 */
static void qedi_get_uio_name(char **uio_name, size_t *uio_name_size)
{
	*uio_name = (char *)library_uio_name;
	*uio_name_size = sizeof(library_uio_name);
}

/**
 *  qedi_get_ops() - Used to get the NIC library op table
 *  @param op - The op table of this NIC library
 */
struct nic_ops *qedi_get_ops()
{
	return &qedi_op;
}

/*******************************************************************************
 * qedi Utility Functions
 ******************************************************************************/
/*******************************************************************************
 * Utility Functions Used to read register from the qedi device
 ******************************************************************************/
static void qedi_set_drv_version_unknown(qedi_t *bp)
{
	bp->version.major = QEDI_UNKNOWN_MAJOR_VERSION;
	bp->version.minor = QEDI_UNKNOWN_MINOR_VERSION;
	bp->version.sub_minor = QEDI_UNKNOWN_SUB_MINOR_VERSION;
}

/* Return: 1 = Unknown, 0 = Known */
static int qedi_is_drv_version_unknown(struct qedi_driver_version *version)
{
	if ((version->major == (uint16_t)QEDI_UNKNOWN_MAJOR_VERSION) &&
	    (version->minor == (uint16_t)QEDI_UNKNOWN_MINOR_VERSION) &&
	    (version->sub_minor == (uint16_t)QEDI_UNKNOWN_SUB_MINOR_VERSION)) {
		return 1;
	}

	return 0;
}

/**
 * qedi_get_drv_version() - Used to determine the driver version
 * @param bp - Device used to determine qedi driver version
 */
static int qedi_get_drv_version(qedi_t *bp)
{
	nic_t *nic = bp->parent;

	/*
	 * CAPABILITIES: Get the iscsi driver version from qedi
	 * This may be obtained from sysfs
	 */
	LOG_INFO(PFX "%s: qedi driver using version %d.%d.%d",
		 nic->log_name,
		 bp->version.major, bp->version.minor, bp->version.sub_minor);

	return 0;
}

/******************************************************************************/

/**
 * qedi_get_chip_id() - Used to retrieve the chip ID from the nic
 * @param dev - Device used to determin NIC type
 * @return Chip ID read from the MISC ID register
 */
static int qedi_get_chip_id(qedi_t *bp)
{
	/* int val, id; */

	/* Get the chip revision id and number. */
	/* chip num:16-31, rev:12-15, metal:4-11, bond_id:0-3 */
	/*
	 * CAPABILITIES: Get the CHIP info from qedi through sysfs or uio struct.
	 */
	return 0;
}

/**
 *  qedi_uio_verify()
 *
 */
static int qedi_uio_verify(nic_t *nic)
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

	if (strncmp(raw, qedi_uio_sysfs_name,
		    sizeof(qedi_uio_sysfs_name)) != 0) {
		LOG_ERR(PFX "%s: uio names not equal: expecting %s got %s from %s",
			nic->log_name, qedi_uio_sysfs_name, raw, temp_path);
		rc = -EIO;
	}

	free(raw);

	LOG_INFO(PFX "%s: Verified is a qedi_uio device", nic->log_name);

error:
	return rc;
}

static int qedi_get_mac_addr(qedi_t *bp)
{
	nic_t *nic = bp->parent;
	char *raw = NULL, *raw_tmp;
	uint32_t raw_size = 0;
	char temp_path[sizeof(qedi_host_mac_template) + 8];
	int rc = 0;

	/*  Build the path to determine mac address */
	snprintf(temp_path, sizeof(temp_path),
		 qedi_host_mac_template, nic->host_no);

	rc = capture_file(&raw, &raw_size, temp_path);
	if (rc != 0)
		goto error;

	/* sanitize name string by replacing newline with null termination */
	raw_tmp = raw;
	while (*raw_tmp != '\n')
		raw_tmp++;
	*raw_tmp = '\0';

	rc = sscanf(raw, "%02x:%02x:%02x:%02x:%02x:%02x",
	       (uint32_t *)&nic->mac_addr[0], (uint32_t *)&nic->mac_addr[1],
	       (uint32_t *)&nic->mac_addr[2], (uint32_t *)&nic->mac_addr[3],
	       (uint32_t *)&nic->mac_addr[4], (uint32_t *)&nic->mac_addr[5]);
	if (rc != 1) {
		LOG_WARN(PFX "%s: Could not parse mac_addr",
			nic->log_name);
		rc = -ENODEV;
		goto error;
	}

error:
	if (raw)
		free(raw);
	return rc;
}

/*******************************************************************************
 * qedi Utility Functions to get to the hardware consumer indexes
 ******************************************************************************/

static __u32 qedi_get_rx(qedi_t *bp)
{
	return ((struct qedi_uio_ctrl *)bp->uctrl_map)->host_rx_cons;
}

static __u32 qedi_get_tx(qedi_t *bp)
{
	return ((struct qedi_uio_ctrl *)bp->uctrl_map)->hw_tx_cons;
}

/**
 *  qedi_free() - Used to free a qedi structure
 */
static void qedi_free(nic_t *nic)
{
	if (nic->priv)
		free(nic->priv);
	nic->priv = NULL;
}

/**
 *  qedi_alloc() - Used to allocate a qedi structure
 */
static qedi_t *qedi_alloc(nic_t *nic)
{
	qedi_t *bp = malloc(sizeof(*bp));

	if (!bp) {
		LOG_ERR(PFX "%s: Could not allocate QEDI space",
			nic->log_name);
		return NULL;
	}

	/*  Clear out the CNIC contents */
	memset(bp, 0, sizeof(*bp));

	bp->parent = nic;
	nic->priv = (void *)bp;
	get_iscsi_transport_handle(nic, &nic->transport_handle);
	qedi_set_drv_version_unknown(bp);

	return bp;
}

int uio_get_map_offset(nic_t *nic, uint8_t map, uint32_t *offset)
{
	char *raw = NULL;
	uint32_t raw_size = 0;
	ssize_t elements_read;
	char temp_path[sizeof(UIO_OFFSET_TMPL) + 8];
	int rc = 0;

	/*  Capture RX buffer size */
	snprintf(temp_path, sizeof(temp_path),
		 UIO_OFFSET_TMPL, nic->uio_minor, map);

	rc = capture_file(&raw, &raw_size, temp_path);
	if (rc != 0)
		goto error;

	elements_read = sscanf(raw, "0x%x", offset);
	if (elements_read != 1) {
		LOG_ERR(PFX "%s: Couldn't get the offset from %s",
			nic->log_name, temp_path);
		rc = -EIO;
		goto error;
	}

	rc = 0;
error:
	if (raw)
		free(raw);

	return rc;
}

int uio_get_map_info(nic_t *nic, uint8_t map, char *attr, uint32_t *val)
{
	char *raw = NULL;
	uint32_t raw_size = 0;
	ssize_t elements_read;
	char temp_path[sizeof(UIO_ATTR_TMPL) + 8];
	int rc = 0;

	/*  Capture RX buffer size */
	snprintf(temp_path, sizeof(temp_path),
		 UIO_ATTR_TMPL, nic->uio_minor, map, attr);

	rc = capture_file(&raw, &raw_size, temp_path);
	if (rc != 0)
		goto error;

	elements_read = sscanf(raw, "0x%x", val);
	if (elements_read != 1) {
		LOG_ERR(PFX "%s: Couldn't get the offset from %s",
			nic->log_name, temp_path);
		rc = -EIO;
		goto error;
	}

	rc = 0;
error:
	if (raw)
		free(raw);

	return rc;
}

/**
 * qedi_open() - This will initialize all the hardware resources underneath
 *               a struct cnic_uio device
 * @param dev - The struct cnic_uio device to attach the hardware with
 * @return 0 on success, on failure a errno will be returned
 */
static int qedi_open(nic_t *nic)
{
	qedi_t *bp = NULL;
	struct stat uio_stat;
	int i, rc;
	size_t count;
	uint32_t bus;
	uint32_t slot;
	uint32_t func;
	uint32_t offset;

	/*  Sanity Check: validate the parameters */
	if (!nic) {
		LOG_ERR(PFX "nic == NULL");
		return -EINVAL;
	}

	if ((nic->priv) != NULL &&
	    (((qedi_t *)(nic->priv))->flags & QEDI_OPENED)) {
		return 0;
	}

	if (nic->host_no == INVALID_HOST_NO) {
		rc = sscanf(nic->config_device_name, "host%d", &nic->host_no);
		if (rc != 1) {
			LOG_WARN(PFX "%s: Could not parse for host number",
				 nic->config_device_name);
			rc = -ENODEV;
			goto open_error;
		}
	}

	bp = qedi_alloc(nic);
	if (!bp)
		return -ENOMEM;

	if (qedi_is_drv_version_unknown(&qedi_version)) {
		/* If version is unknown, go read from ethtool */
		rc = qedi_get_drv_version(bp);
		if (rc)
			goto open_error;
	} else {
		/* Version is not unknown, just use it */
		qedi_version.major = bp->version.major;
		qedi_version.minor = bp->version.minor;
		qedi_version.sub_minor = bp->version.sub_minor;
	}

	count = 0;
	while ((nic->fd < 0) && count < 15) {
		/*  udev might not have created the file yet */
		pthread_mutex_unlock(&nic->nic_mutex);
		sleep(1);
		pthread_mutex_lock(&nic->nic_mutex);

		nic->fd = open(nic->uio_device_name, O_RDWR | O_NONBLOCK);
		if (nic->fd != INVALID_FD) {
			LOG_ERR(PFX "%s: uio device has been brought up via pid: %d on fd: %d",
				nic->uio_device_name, getpid(), nic->fd);

			rc = qedi_uio_verify(nic);
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
	if (nic->fd == INVALID_FD) {
		LOG_ERR(PFX "%s: Could not open device: %s, [%s]",
			nic->log_name, nic->uio_device_name,
			strerror(errno));
		rc = errno;
		goto open_error;
	}
	if (fstat(nic->fd, &uio_stat) < 0) {
		LOG_ERR(PFX "%s: Could not fstat device", nic->log_name);
		rc = -ENODEV;
		goto open_error;
	}
	nic->uio_minor = minor(uio_stat.st_rdev);

	/*
	 * CAPABILITIES: acquire the rx buffer size and rx ring size from qedi
	 */

	bp->rx_ring_size = RX_RING_SIZE;
	bp->rx_buffer_size = PKT_BUF_SIZE;

	LOG_DEBUG(PFX "%s: using rx ring size: %d, rx buffer size: %d",
		  nic->log_name, bp->rx_ring_size, bp->rx_buffer_size);

	/* Determine the number of UIO events that have already occurred */
	rc = detemine_initial_uio_events(nic, &nic->intr_count);
	if (rc != 0) {
		LOG_ERR(PFX "Could not get the no. of initial UIO events");
		nic->intr_count = 0;
	}

	/* Allocate space for rx pkt ring */
	bp->rx_pkt_ring = malloc(sizeof(void *) * bp->rx_ring_size);
	if (!bp->rx_pkt_ring) {
		LOG_ERR(PFX "%s: Could not allocate space for rx_pkt_ring",
			nic->log_name);
		rc = errno;
		goto open_error;
	}

	/*
	 * Map the uio struct and packet buffer
	 */
	offset = 0;
	rc = uio_get_map_info(nic, QEDI_UCTRL_MAP_REG, "size", &offset);
	if (rc) {
		LOG_INFO(PFX "Failed to get the map size rc=%d", rc);
		goto open_error;
	}
	LOG_INFO(PFX "uctrl map size=%u", offset);

	offset = 0;
	rc = uio_get_map_info(nic, QEDI_RING_MAP_REG, "size", &offset);
	if (rc) {
		LOG_INFO(PFX "Failed to get the map size rc=%d", rc);
		goto open_error;
	}
	LOG_INFO(PFX "ring map size=%u", offset);

	offset = 0;
	rc = uio_get_map_info(nic, QEDI_BUF_MAP_REG, "size", &offset);
	if (rc) {
		LOG_INFO(PFX "Failed to get the map size rc=%d", rc);
		goto open_error;
	}
	LOG_INFO(PFX "buf map size=%u", offset);

	offset = 0;
	rc = uio_get_map_offset(nic, QEDI_UCTRL_MAP_REG, &offset);
	if (rc) {
		LOG_INFO(PFX "Failed to get the map offset rc=%d", rc);
		goto open_error;
	}

	bp->uctrl_map = mmap(NULL, sizeof(struct qedi_uio_ctrl),
			    PROT_READ | PROT_WRITE,
			    MAP_SHARED | MAP_LOCKED,
			    nic->fd, (off_t)0);
	if (bp->uctrl_map == MAP_FAILED) {
		LOG_INFO(PFX "%s: Could not mmap uio ctrl struct: %s",
			 nic->log_name, strerror(errno));
		bp->uctrl_map = NULL;
		rc = errno;
		goto open_error;
	}

	bp->uctrl_map_offset = offset;
	bp->uctrl_map += offset;

	bp->rx_comp_ring = mmap(NULL, nic->page_size,
			   PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED,
			   nic->fd, (off_t)nic->page_size);
	if (bp->rx_comp_ring == MAP_FAILED) {
		LOG_INFO(PFX "%s: Could not mmap rx_comp_ring: %s",
			 nic->log_name, strerror(errno));
		bp->rx_comp_ring = NULL;
		rc = errno;
		goto open_error;
	}

	bp->bufs = mmap(NULL, (bp->rx_ring_size + 1) * bp->rx_buffer_size,
			PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED,
			nic->fd, (off_t)2 * nic->page_size);
	if (bp->bufs == MAP_FAILED) {
		LOG_INFO(PFX "%s: Could not mmap pkt buffers: %s",
			 nic->log_name, strerror(errno));
		bp->bufs = NULL;
		rc = errno;
		goto open_error;
	}

	/*
	 * Get all CHIP related info from qedi
	 */
	bp->chip_id = qedi_get_chip_id(bp);
	LOG_DEBUG(PFX "Chip ID: %x", bp->chip_id);

	rc = get_bus_slot_func_num(nic, &bus, &slot, &func);
	if (rc != 0) {
		LOG_INFO(PFX "%s: Couldn't determine bus:slot.func",
			 nic->log_name);
		goto open_error;
	}

	/*
	 * Get all function, pfid, client_id and cid info from qedi
	 */
	LOG_INFO(PFX "%s: func 0x%x, pfid 0x%x, client_id 0x%x, cid 0x%x",
		 nic->log_name, bp->func, bp->pfid, bp->client_id, bp->cid);

	bp->get_rx_cons = qedi_get_rx;
	bp->get_tx_cons = qedi_get_tx;
	bp->tx_cons = 0;
	bp->tx_prod = 0;
	bp->tx_bd_prod = 0;
	bp->tx_pkt = bp->bufs;
	bp->rx_pkts = bp->bufs + bp->rx_buffer_size;

	bp->rx_index = 0;
	bp->rx_cons = 0;
	bp->rx_bd_cons = 0;
	bp->rx_prod = 127;
	bp->rx_bd_prod = bp->rx_ring_size;

	for (i = 0; i < bp->rx_ring_size; i++) {
		void *ptr = bp->bufs + (bp->rx_buffer_size * (i + 1));

		bp->rx_pkt_ring[i] = ptr;
	}

	qedi_get_mac_addr(bp);
	LOG_INFO(PFX "%s:  Using mac address: %02x:%02x:%02x:%02x:%02x:%02x",
		 nic->log_name,
		 nic->mac_addr[0], nic->mac_addr[1], nic->mac_addr[2],
		 nic->mac_addr[3], nic->mac_addr[4], nic->mac_addr[5]);

	qedi_get_library_name(&nic->library_name, &count);
	LOG_INFO("%s: qedi initialized", nic->log_name);

	bp->flags |= QEDI_OPENED;

	return 0;

open_error:

	if (bp->bufs) {
		munmap(bp->bufs, (bp->rx_ring_size + 1) * bp->rx_buffer_size);
		bp->bufs = NULL;
	}

	if (bp->rx_comp_ring) {
		munmap(bp->rx_comp_ring, nic->page_size);
		bp->rx_comp_ring = NULL;
	}

	if (bp->uctrl_map) {
		bp->uctrl_map -= bp->uctrl_map_offset;
		munmap(bp->uctrl_map, sizeof(struct qedi_uio_ctrl));
		bp->uctrl_map = NULL;
	}

	if (bp->rx_pkt_ring) {
		free(bp->rx_pkt_ring);
		bp->rx_pkt_ring = NULL;
	}

	if (nic->fd != INVALID_FD) {
		close(nic->fd);
		nic->fd = INVALID_FD;
	}

	qedi_free(nic);

	return rc;
}

/**
 *  qedi_uio_close_resources() - Used to free resource for the NIC/CNIC
 *  @param nic - NIC device to free resource
 *  @param graceful - whether to wait to close gracefully
 *  @return 0 on success, <0 on failure
 */
static int qedi_uio_close_resources(nic_t *nic, NIC_SHUTDOWN_T graceful)
{
	qedi_t *bp = (qedi_t *)nic->priv;
	int rc = 0;

	/*  Check if there is an assoicated qedi device */
	if (!bp) {
		LOG_WARN(PFX "%s: when closing resources there is no assoicated qedi",
			 nic->log_name);
		return -EIO;
	}

	/*  Clean up allocated memory */

	if (bp->rx_pkt_ring) {
		free(bp->rx_pkt_ring);
		bp->rx_pkt_ring = NULL;
	}

	/*  Clean up mapped registers */
	if (bp->bufs) {
		rc = munmap(bp->bufs,
			    (bp->rx_ring_size + 1) * bp->rx_buffer_size);
		if (rc != 0)
			LOG_ERR(PFX "%s: Couldn't unmap bufs", nic->log_name);
		bp->bufs = NULL;
	}

	if (bp->rx_comp_ring) {
		rc = munmap(bp->rx_comp_ring, nic->page_size);
		if (rc != 0)
			LOG_ERR(PFX "%s: Couldn't unmap ring", nic->log_name);
		bp->rx_comp_ring = NULL;
	}

	if (bp->uctrl_map) {
		bp->uctrl_map -= bp->uctrl_map_offset;
		rc = munmap(bp->uctrl_map, sizeof(struct qedi_uio_ctrl));
		if (rc != 0) {
			LOG_ERR(PFX "%s: Couldn't unmap uio ctrl",
				nic->log_name);
		}
		bp->uctrl_map = NULL;
	}

	if (nic->fd != INVALID_FD) {
		rc = close(nic->fd);
		if (rc != 0) {
			LOG_ERR(PFX
				 "%s: Couldn't close uio file descriptor: %d",
				 nic->log_name, nic->fd);
		} else {
			LOG_DEBUG(PFX "%s: Closed uio file descriptor: %d",
				  nic->log_name, nic->fd);
		}

		nic->fd = INVALID_FD;
	} else {
		LOG_ERR(PFX "%s: Invalid uio file descriptor: %d",
			nic->log_name, nic->fd);
	}

	qedi_set_drv_version_unknown(bp);

	LOG_INFO(PFX "%s: Closed all resources", nic->log_name);

	return 0;
}

/**
 *  qedi_close() - Used to close the NIC device
 *  @param nic - NIC device to close
 *  @param graceful - whether to wait to close gracefully
 *  @return 0 if successful, <0 if there is an error
 */
static int qedi_close(nic_t *nic, NIC_SHUTDOWN_T graceful)
{
	/*  Sanity Check: validate the parameters */
	if (!nic) {
		LOG_ERR(PFX "%s: nic == NULL", __func__);
		return -EINVAL;
	}
	if (!nic->priv) {
		LOG_ERR(PFX "%s: nic->priv == NULL", __func__);
		return -EINVAL;
	}

	LOG_INFO(PFX "Closing NIC device: %s", nic->log_name);

	qedi_uio_close_resources(nic, graceful);
	qedi_free(nic);

	return 0;
}

static void qedi_prepare_xmit_packet(nic_t *nic,
				     nic_interface_t *nic_iface,
				     struct packet *pkt)
{
	qedi_t *bp = (qedi_t *)nic->priv;
	struct uip_vlan_eth_hdr *eth_vlan = (struct uip_vlan_eth_hdr *)pkt->buf;
	struct uip_eth_hdr *eth = (struct uip_eth_hdr *)bp->tx_pkt;

	LOG_DEBUG(PFX "%s: pkt->buf_size=%d tpid=0x%x", nic->log_name,
		  pkt->buf_size, eth_vlan->tpid);
	
	if (eth_vlan->tpid == htons(UIP_ETHTYPE_8021Q)) {
		memcpy(bp->tx_pkt, pkt->buf, sizeof(struct uip_eth_hdr));
		eth->type = eth_vlan->type;
		pkt->buf_size -= (sizeof(struct uip_vlan_eth_hdr) -
				  sizeof(struct uip_eth_hdr));

	LOG_DEBUG(PFX "%s: pkt->buf_size=%d type=0x%x", nic->log_name,
		  pkt->buf_size, eth->type);
	LOG_DEBUG(PFX "%s: pkt->buf_size - eth_hdr_size = %d", nic->log_name,
		  pkt->buf_size - sizeof(struct uip_eth_hdr));

		memcpy(bp->tx_pkt + sizeof(struct uip_eth_hdr),
		       pkt->buf + sizeof(struct uip_vlan_eth_hdr),
		       pkt->buf_size - sizeof(struct uip_eth_hdr));
	} else {
		LOG_DEBUG(PFX "%s: NO VLAN pkt->buf_size=%d", nic->log_name,
			  pkt->buf_size);
		memcpy(bp->tx_pkt, pkt->buf, pkt->buf_size);
	}

	msync(bp->tx_pkt, pkt->buf_size, MS_SYNC);
}

/**
 *  qedi_get_tx_pkt() - This function is used to a TX packet from the NIC
 *  @param nic - The NIC device to send the packet
 */
void *qedi_get_tx_pkt(nic_t *nic)
{
	qedi_t *bp = (qedi_t *)nic->priv;

	return bp->tx_pkt;
}

/**
 *  qedi_start_xmit() - This function is used to send a packet of data
 *  @param nic - The NIC device to send the packet
 *  @param len - the length of the TX packet
 *
 */
void qedi_start_xmit(nic_t *nic, size_t len, u16_t vlan_id)
{
	qedi_t *bp = (qedi_t *)nic->priv;
	uint8_t *ubuf;
	struct iscsi_uevent *ev;
	struct iscsi_path *path_data;
	struct qedi_uio_ctrl *uctrl;
	int rc = 0;
	uint16_t buflen;

	uctrl = (struct qedi_uio_ctrl *)bp->uctrl_map;

	buflen = sizeof(struct iscsi_uevent) + sizeof(struct iscsi_path);
	ubuf = calloc(1, NLMSG_SPACE(buflen));
	if (!ubuf) {
		LOG_ERR(PFX "%s: alloc failed for uevent buf", __func__);
		return;
	}

	memset(ubuf, 0, NLMSG_SPACE(buflen));

	/*  prepare the iscsi_uevent buffer */
	ev = (struct iscsi_uevent *)ubuf;
	ev->type = ISCSI_UEVENT_PATH_UPDATE;
	ev->transport_handle = nic->transport_handle;
	ev->u.set_path.host_no = nic->host_no;

	/*  Prepare the iscsi_path buffer */
	path_data = (struct iscsi_path *)(ubuf + sizeof(struct iscsi_uevent));
	path_data->handle = QEDI_PATH_HANDLE;
	path_data->vlan_id = vlan_id;
	uctrl->host_tx_pkt_len = len;
	LOG_DEBUG(PFX "%s: host_no:%d vlan_id=%d, tx_pkt_len=%d",
		  nic->log_name, ev->u.set_path.host_no, path_data->vlan_id, uctrl->host_tx_pkt_len);

	LOG_DEBUG(PFX "%s: ACQUIRE HOST MUTEX", nic->log_name);
	pthread_mutex_lock(&host_mutex);
	rc = __kipc_call(nl_sock, ev, buflen);
	if (rc > 0) {
		bp->tx_prod++;
		uctrl->host_tx_prod++;
		LOG_DEBUG(PFX "%s: bp->tx_prod: %d, uctrl->host_tx_prod=%d",
			  nic->log_name, bp->tx_prod, uctrl->host_tx_prod);

		msync(uctrl, sizeof(struct qedi_uio_ctrl), MS_SYNC);
		LOG_PACKET(PFX "%s: sent %d bytes using bp->tx_prod: %d",
			   nic->log_name, len, bp->tx_prod);
	} else {
		LOG_ERR(PFX "Pkt transmission failed: %d", rc);
	}

	LOG_DEBUG(PFX "%s: RELEASE HOST MUTEX", nic->log_name);
	pthread_mutex_unlock(&host_mutex);
	free(ubuf);
}

/**
 *  qedi_write() - Used to write the data to the hardware
 *  @param nic - NIC hardware to read from
 *  @param pkt - The packet which will hold the data to be sent on the wire
 *  @return 0 if successful, <0 if failed
 */
int qedi_write(nic_t *nic, nic_interface_t *nic_iface, packet_t *pkt)
{
	qedi_t *bp;
	struct uip_stack *uip;
	int i = 0;

	/* Sanity Check: validate the parameters */
	if (!nic || !nic_iface || !pkt) {
		LOG_ERR(PFX "%s: qedi_write() nic == 0x%p || nic_iface == 0x%p || pkt == 0x%x",
			nic, nic_iface, pkt);
		return -EINVAL;
	}
	bp = (qedi_t *)nic->priv;
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

		LOG_DEBUG(PFX "%s: host:%d - calling clear_tx_intr from qedi_write",
			  nic->log_name, nic->host_no);
		if (qedi_clear_tx_intr(nic) == 0)
			break;

		nanosleep(&sleep_req, &sleep_rem);
	}

	LOG_DEBUG(PFX "%s: host:%d - try getting xmit mutex",
		   nic->log_name, nic->host_no);
	if (pthread_mutex_trylock(&nic->xmit_mutex) != 0) {
		LOG_DEBUG(PFX "%s: Dropped previous transmitted packet",
			   nic->log_name);
		return -EINVAL;
	}

	qedi_prepare_xmit_packet(nic, nic_iface, pkt);
	qedi_start_xmit(nic, pkt->buf_size,
			(nic_iface->vlan_priority << 12) |
			nic_iface->vlan_id);

	/* bump up the tx stats */
	nic->stats.tx.packets++;
	nic->stats.tx.bytes += uip->uip_len;

	LOG_DEBUG(PFX "%s: transmitted %d bytes dev->tx_cons: %d, dev->tx_prod: %d, dev->tx_bd_prod:%d",
		   nic->log_name, pkt->buf_size,
		   bp->tx_cons, bp->tx_prod, bp->tx_bd_prod);

	LOG_DEBUG(PFX "%s: host:%d - releasing xmit mutex",
		  nic->log_name, nic->host_no);
	pthread_mutex_unlock(&nic->xmit_mutex);

	return 0;
}

/**
 *  qedi_read() - Used to read the data from the hardware
 *  @param nic - NIC hardware to read from
 *  @param pkt - The packet which will hold the data
 *  @return 0 if successful, < 0 if failed
 */
static int qedi_read(nic_t *nic, packet_t *pkt)
{
	qedi_t *bp;
	void *rx_pkt;
	int rc = 0;
	uint32_t sw_cons, bd_cons;
	uint32_t hw_prod, bd_prod;
	uint32_t rx_pkt_idx;
	int len;
	struct qedi_rx_bd *rx_bd;
	struct qedi_uio_ctrl *uctrl;
	uint16_t vlan_id;

	/* Sanity Check: validate the parameters */
	if (!nic || !pkt) {
		LOG_ERR(PFX "%s: qedi_read() nic == 0x%p || pkt == 0x%x",
			nic, pkt);
		return -EINVAL;
	}

	bp = (qedi_t *)nic->priv;
	msync(bp->uctrl_map, sizeof(struct qedi_uio_ctrl), MS_SYNC);
	msync(bp->rx_comp_ring, nic->page_size, MS_SYNC);
	uctrl = (struct qedi_uio_ctrl *)bp->uctrl_map;
	hw_prod = uctrl->hw_rx_prod;
	bd_prod = uctrl->hw_rx_bd_prod;
	sw_cons = uctrl->host_rx_cons;
	bd_cons = uctrl->host_rx_bd_cons;
	rx_bd = bp->rx_comp_ring + (bd_prod * sizeof(*rx_bd));
	len = rx_bd->rx_pkt_len;
	rx_pkt_idx = rx_bd->rx_pkt_index;
	vlan_id = rx_bd->vlan_id;

	LOG_DEBUG(PFX "%s:hw_prod %d bd_prod %d, rx_pkt_idx %d, rxlen %d",
		  nic->log_name, hw_prod, bd_prod, rx_bd->rx_pkt_index, len);
	LOG_DEBUG(PFX "%s: sw_con %d bd_cons %d num BD %d",
		  nic->log_name, sw_cons, bd_cons, QEDI_NUM_RX_BD);

	if (bd_cons != bd_prod) {
		LOG_DEBUG(PFX "%s: clearing rx interrupt: %d %d",
			  nic->log_name, sw_cons, hw_prod);
		rc = 1;
		rx_pkt = bp->rx_pkts + (bp->rx_buffer_size * rx_pkt_idx);

		if (len > 0) {
			msync(rx_pkt, len, MS_SYNC);
			/*  Copy the data */
			memcpy(pkt->buf, rx_pkt, len);
			pkt->buf_size = len;
			if (vlan_id) {
				pkt->vlan_tag = vlan_id;
				pkt->flags |= VLAN_TAGGED;
			} else {
				pkt->vlan_tag = 0;
			}

			LOG_DEBUG(PFX "%s: processing packet length: %d",
				  nic->log_name, len);

			/* bump up the recv stats */
			nic->stats.rx.packets++;
			nic->stats.rx.bytes += pkt->buf_size;
		} else {
			rc = 0;
		}

		sw_cons = (sw_cons + 1) % RX_RING_SIZE;
		bd_cons = (bd_cons + 1) % QEDI_NUM_RX_BD;
		uctrl->host_rx_cons_cnt++;
	}

	uctrl->host_rx_bd_cons = bd_cons;
	uctrl->host_rx_cons = sw_cons;

	msync(uctrl, sizeof(struct qedi_uio_ctrl), MS_SYNC);
	msync(bp->rx_comp_ring, nic->page_size, MS_SYNC);
	return rc;
}

/*******************************************************************************
 * Clearing TX interrupts
 ******************************************************************************/
/**
 *  qedi_clear_tx_intr() - This routine is called when a TX interrupt occurs
 *  @param nic - the nic the interrupt occurred on
 *  @return  0 on success
 */

static int qedi_clear_tx_intr(nic_t *nic)
{
	qedi_t *bp;
	uint32_t hw_cons;
	struct qedi_uio_ctrl *uctrl;

	/* Sanity check: ensure the parameters passed in are valid */
	if (unlikely(!nic)) {
		LOG_ERR(PFX "%s: nic == NULL", __func__);
		return -EINVAL;
	}

	bp = (qedi_t *)nic->priv;
	uctrl = (struct qedi_uio_ctrl *)bp->uctrl_map;
	msync(bp->uctrl_map, sizeof(struct qedi_uio_ctrl), MS_SYNC);
	hw_cons = uctrl->hw_tx_cons;

	if (bp->tx_cons == hw_cons) {
		if (bp->tx_cons == bp->tx_prod)
			return 0;
		return -EAGAIN;
	}

	if (pthread_mutex_trylock(&nic->xmit_mutex)) {
		LOG_ERR(PFX "%s: unable to get xmit_mutex.", nic->log_name);
		return -EINVAL;
	}

	LOG_DEBUG(PFX "%s: clearing tx interrupt [%d %d]",
		   nic->log_name, bp->tx_cons, hw_cons);
	bp->tx_cons = hw_cons;

	/* There is a queued TX packet that needs to be sent out.  The usual
	 * case is when stack will send an ARP packet out before sending the
	 * intended packet
	 */
	if (nic->tx_packet_queue) {
		packet_t *pkt;
		int i;

		LOG_DEBUG(PFX "%s: sending queued tx packet", nic->log_name);
		pkt = nic_dequeue_tx_packet(nic);

		/* Got a TX packet buffer of the TX queue and put it onto
		 * the hardware
		 */
		if (pkt) {
			qedi_prepare_xmit_packet(nic, pkt->nic_iface, pkt);

			qedi_start_xmit(nic, pkt->buf_size,
					(pkt->nic_iface->vlan_priority << 12) |
					pkt->nic_iface->vlan_id);

			LOG_DEBUG(PFX "%s: transmitted queued packet %d bytes, dev->tx_cons: %d, dev->tx_prod: %d, dev->tx_bd_prod:%d",
				   nic->log_name, pkt->buf_size,
				   bp->tx_cons, bp->tx_prod, bp->tx_bd_prod);

			pthread_mutex_unlock(&nic->xmit_mutex);
			return 0;
		}

		/* Try to wait for a TX completion */
		for (i = 0; i < 15; i++) {
			struct timespec sleep_req = {.tv_sec = 0,
				.tv_nsec = 5000000
			}, sleep_rem;

			hw_cons = uctrl->hw_tx_cons;
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

	LOG_DEBUG(PFX "%s: host:%d - releasing xmit mutex",
		   nic->log_name, nic->host_no);
	pthread_mutex_unlock(&nic->xmit_mutex);

	return 0;
}

/*******************************************************************************
 * qedi NIC op's table
 ******************************************************************************/
struct nic_ops qedi_op = {
	.description = "qedi",
	.open = qedi_open,
	.close = qedi_close,
	.write = qedi_write,
	.get_tx_pkt = qedi_get_tx_pkt,
	.start_xmit = qedi_start_xmit,
	.read = qedi_read,
	.clear_tx_intr = qedi_clear_tx_intr,
	.handle_iscsi_path_req = cnic_handle_iscsi_path_req,

	.lib_ops = {
		    .get_library_name = qedi_get_library_name,
		    .get_library_version = qedi_get_library_version,
		    .get_build_date = qedi_get_build_date,
		    .get_transport_name = qedi_get_transport_name,
		    .get_uio_name = qedi_get_uio_name,
		    },
};
