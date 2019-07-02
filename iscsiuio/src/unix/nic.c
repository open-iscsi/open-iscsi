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
 * nic.c - Generic NIC management/utility functions
 *
 */
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "dhcpc.h"
#include "ipv6_ndpc.h"

#include "logger.h"
#include "nic.h"
#include "nic_utils.h"
#include "options.h"

#include "uip.h"
#include "uip_arp.h"
#include "uip_eth.h"
#include "uip-neighbor.h"

#include "bnx2.h"
#include "bnx2x.h"
#include "qedi.h"
#include "ipv6.h"

/******************************************************************************
 *  Constants
 *****************************************************************************/
#define PFX "nic "
#define PCI_ANY_ID (~0)

/******************************************************************************
 *  Global variables
 *****************************************************************************/
/*  Used to store a list of NIC libraries */
pthread_mutex_t nic_lib_list_mutex = PTHREAD_MUTEX_INITIALIZER;
nic_lib_handle_t *nic_lib_list;

/*  Used to store a list of active cnic devices */
pthread_mutex_t nic_list_mutex = PTHREAD_MUTEX_INITIALIZER;
nic_t *nic_list;

/******************************************************************************
 *  Functions to handle NIC libraries
 *****************************************************************************/
/**
 *  alloc_nic_library_handle() - Used to allocate a NIC library handle
 *  @return NULL if memory couldn't be allocated, pointer to the handle
 *    to the NIC library handle
 */
static nic_lib_handle_t *alloc_nic_library_handle()
{
	nic_lib_handle_t *handle;

	handle = malloc(sizeof(*handle));
	if (handle == NULL) {
		LOG_ERR("Could not allocate memory for library handle");
		return NULL;
	}

	memset(handle, 0, sizeof(*handle));
	handle->ops = NULL;

	pthread_mutex_init(&handle->mutex, NULL);

	return handle;
}

static void free_nic_library_handle(nic_lib_handle_t *handle)
{
	free(handle);
}

/**
 *  load_nic_library() - This function is used to load a NIC library
 *  @param handle - This is the library handle to load
 *  @return 0 = Success; <0 = failure
 */
static int load_nic_library(nic_lib_handle_t *handle)
{
	int rc;
	char *library_name;
	size_t library_name_size;
	char *library_version;
	size_t library_version_size;
	char *build_date_str;
	size_t build_date_str_size;

	pthread_mutex_lock(&handle->mutex);

	/* Validate the NIC ops table ensure that all the fields are not NULL */
	if ((handle->ops->open) == NULL ||
	    (handle->ops->close) == NULL ||
	    (handle->ops->read) == NULL ||
	    (handle->ops->write) == NULL ||
	    (handle->ops->clear_tx_intr == NULL)) {
		LOG_ERR("Invalid NIC ops table: open: 0x%x, close: 0x%x,"
			"read: 0x%x, write: 0x%x clear_tx_intr: 0x%x "
			"lib_ops: 0x%x",
			handle->ops->open, handle->ops->close,
			handle->ops->read, handle->ops->write,
			handle->ops->clear_tx_intr, handle->ops->lib_ops);
		rc = -EINVAL;
		handle->ops = NULL;
		goto error;
	}

	/*  Validate the NIC library ops table to ensure that all the proper
	 *  fields are filled */
	if ((handle->ops->lib_ops.get_library_name == NULL) ||
	    (handle->ops->lib_ops.get_library_version == NULL) ||
	    (handle->ops->lib_ops.get_build_date == NULL) ||
	    (handle->ops->lib_ops.get_transport_name == NULL)) {
		rc = -EINVAL;
		goto error;
	}

	(*handle->ops->lib_ops.get_library_name) (&library_name,
						  &library_name_size);
	(*handle->ops->lib_ops.get_library_version) (&library_version,
						     &library_version_size);
	(*handle->ops->lib_ops.get_build_date) (&build_date_str,
						&build_date_str_size);

	LOG_DEBUG("Loaded nic library '%s' Version: '%s' build on %s'",
		  library_name, library_version, build_date_str);

	pthread_mutex_unlock(&handle->mutex);

	return 0;

error:
	pthread_mutex_unlock(&handle->mutex);

	return rc;
}

static struct nic_ops *(*nic_get_ops[]) () = {
bnx2_get_ops, bnx2x_get_ops, qedi_get_ops};

int load_all_nic_libraries()
{
	int rc, i = 0;
	nic_lib_handle_t *handle;

	for (i = 0; i < sizeof(nic_get_ops) / sizeof(nic_get_ops[0]); i++) {
		/*  Add the CNIC library */
		handle = alloc_nic_library_handle();
		if (handle == NULL) {
			LOG_ERR("Could not allocate memory for CNIC nic lib");
			return -ENOMEM;
		}

		handle->ops = (*nic_get_ops[i]) ();

		rc = load_nic_library(handle);
		if (rc != 0) {
			free_nic_library_handle(handle);
			return rc;
		}
		/*  Add the CNIC library to the list of library handles */
		pthread_mutex_lock(&nic_lib_list_mutex);

		/*  Add this library to the list of nic libraries we
		 *  know about */
		if (nic_lib_list == NULL) {
			nic_lib_list = handle;
		} else {
			nic_lib_handle_t *current = nic_lib_list;

			while (current->next != NULL)
				current = current->next;

			current->next = handle;
		}
		pthread_mutex_unlock(&nic_lib_list_mutex);

		LOG_DEBUG("Added '%s' nic library", handle->ops->description);
	}

	return rc;
}

int unload_all_nic_libraries()
{
	nic_lib_handle_t *current, *next;

	pthread_mutex_lock(&nic_lib_list_mutex);
	current = nic_lib_list;

	while (current != NULL) {
		next = current->next;
		free_nic_library_handle(current);

		current = next;
	}

	pthread_mutex_unlock(&nic_lib_list_mutex);

	nic_lib_list = NULL;

	return 0;
}

NIC_LIBRARY_EXIST_T does_nic_uio_name_exist(char *name,
					    nic_lib_handle_t **handle)
{
	NIC_LIBRARY_EXIST_T rc;
	nic_lib_handle_t *current;

	pthread_mutex_lock(&nic_lib_list_mutex);
	current = nic_lib_list;

	while (current != NULL) {
		char *uio_name;
		size_t uio_name_size;

		(*current->ops->lib_ops.get_uio_name) (&uio_name,
						       &uio_name_size);

		if (strncmp(name, uio_name, uio_name_size) == 0) {
			if (handle)
				*handle = current;

			rc = NIC_LIBRARY_EXSITS;
			goto done;
		}

		current = current->next;
	}

	rc = NIC_LIBRARY_DOESNT_EXIST;

done:
	pthread_mutex_unlock(&nic_lib_list_mutex);
	return rc;
}

NIC_LIBRARY_EXIST_T does_nic_library_exist(char *name,
					   nic_lib_handle_t **handle)
{
	NIC_LIBRARY_EXIST_T rc;
	nic_lib_handle_t *current;

	pthread_mutex_lock(&nic_lib_list_mutex);
	current = nic_lib_list;

	while (current != NULL) {
		char *library_name;
		size_t library_name_size;

		(*current->ops->lib_ops.get_library_name) (&library_name,
							   &library_name_size);

		if (strncmp(name, library_name, library_name_size) == 0) {
			if (handle)
				*handle = current;

			rc = NIC_LIBRARY_EXSITS;
			goto done;
		}

		current = current->next;
	}

	rc = NIC_LIBRARY_DOESNT_EXIST;

done:
	pthread_mutex_unlock(&nic_lib_list_mutex);
	return rc;
}

/**
 *  find_nic_lib_using_pci_id() - Find the proper NIC library using the
 *     PCI ID's
 *  @param vendor - PCI vendor ID to search on
 *  @param device - PCI device ID to search on
 *  @param subvendor - PCI subvendor ID to search on
 *  @param subdevice - PCI subdevice ID to search on
 *  @param handle - This function will return the nic lib handle if found
 *  @return 0 if found, <0 not found
 */
int find_nic_lib_using_pci_id(uint32_t vendor, uint32_t device,
			      uint32_t subvendor, uint32_t subdevice,
			      nic_lib_handle_t **handle,
			      struct pci_device_id **pci_entry)
{
	int rc;
	nic_lib_handle_t *current;

	pthread_mutex_lock(&nic_lib_list_mutex);
	current = nic_lib_list;

	while (current != NULL) {
		struct pci_device_id *pci_table;
		uint32_t entries;
		int i;

		if (current->ops->lib_ops.get_pci_table != NULL) {
			current->ops->lib_ops.get_pci_table(&pci_table,
							    &entries);
		} else {
			current = current->next;
			continue;
		}
		/*  Sanity check the the pci table coming from the
		 *  hardware library */
		if (entries > MAX_PCI_DEVICE_ENTRIES) {
			LOG_WARN(PFX "Too many pci_table entries(%d) skipping",
				 entries);
			continue;
		}

		for (i = 0; i < entries; i++) {
			LOG_DEBUG(PFX "Checking against: "
				  "vendor: 0x%x device:0x%x "
				  "subvendor:0x%x subdevice:0x%x",
				  pci_table[i].vendor, pci_table[i].device,
				  pci_table[i].subvendor,
				  pci_table[i].subdevice);

			if ((pci_table[i].vendor == vendor) &&
			    (pci_table[i].device == device) &&
			    (pci_table[i].subvendor == PCI_ANY_ID ||
			     pci_table[i].subvendor == subvendor) &&
			    (pci_table[i].subdevice == PCI_ANY_ID ||
			     pci_table[i].subdevice == subdevice)) {
				*handle = current;
				*pci_entry = &pci_table[i];
				rc = 0;
				goto done;
			}
		}

		current = current->next;
	}
	rc = -EINVAL;

done:
	pthread_mutex_unlock(&nic_lib_list_mutex);

	return rc;
}

/**
 * nic_init() - This will properly initialize a struct cnic_uio device
 * @return NULL is there is a failure and pointer to an allocated/initialized
 *         struct cnic_uio on success
 */
nic_t *nic_init()
{
	nic_t *nic;

	nic = malloc(sizeof(*nic));
	if (nic == NULL) {
		LOG_ERR("Couldn't malloc space for nic");
		return NULL;
	}

	memset(nic, 0, sizeof(*nic));
	nic->uio_minor = -1;
	nic->fd = INVALID_FD;
	nic->host_no = INVALID_HOST_NO;
	nic->next = NULL;
	nic->thread = INVALID_THREAD;
	nic->enable_thread = INVALID_THREAD;
	nic->flags |= NIC_DISABLED;
	nic->state = NIC_STOPPED;
	nic->free_packet_queue = NULL;
	nic->tx_packet_queue = NULL;
	nic->nic_library = NULL;
	nic->pci_id = NULL;
	nic->page_size = getpagesize();

	/* nic_mutex is used to protect nic ops */
	pthread_mutex_init(&nic->nic_mutex, NULL);
	pthread_mutex_init(&nic->xmit_mutex, NULL);
	pthread_mutex_init(&nic->free_packet_queue_mutex, NULL);

	pthread_cond_init(&nic->enable_wait_cond, NULL);
	pthread_cond_init(&nic->enable_done_cond, NULL);
	pthread_cond_init(&nic->nic_loop_started_cond, NULL);
	pthread_cond_init(&nic->disable_wait_cond, NULL);

	nic->rx_poll_usec = DEFAULT_RX_POLL_USEC;

	pthread_mutex_init(&nic->nl_process_mutex, NULL);
	pthread_cond_init(&nic->nl_process_if_down_cond, NULL);
	pthread_cond_init(&nic->nl_process_cond, NULL);
	nic->nl_process_thread = INVALID_THREAD;
	nic->nl_process_if_down = 0;
	nic->nl_process_head = 0;
	nic->nl_process_tail = 0;
	memset(&nic->nl_process_ring, 0, sizeof(nic->nl_process_ring));

	nic->ping_thread = INVALID_THREAD;

	return nic;
}

void nic_add(nic_t *nic)
{
	/*  Add this device to our list of nics */
	if (nic_list == NULL) {
		nic_list = nic;
	} else {
		nic_t *current = nic_list;

		while (current->next != NULL)
			current = current->next;

		current->next = nic;
	}
}

/**
 *  nic_remove() - Used to remove the NIC for the nic list
 *  @param nic - the nic to remove
 */
int nic_remove(nic_t *nic)
{
	int rc;
	nic_t *prev, *current;
	struct stat file_stat;
	nic_interface_t *nic_iface, *next_nic_iface, *vlan_iface;

	pthread_mutex_lock(&nic->nic_mutex);

	/*  Check if the file node exists before closing */
	if (nic->uio_device_name) {
		rc = stat(nic->uio_device_name, &file_stat);
		if ((rc == 0) && (nic->ops))
			nic->ops->close(nic, 0);
	}
	pthread_mutex_unlock(&nic->nic_mutex);

	nic->state = NIC_EXIT;

	if (nic->enable_thread != INVALID_THREAD) {
		LOG_DEBUG(PFX "%s: Canceling nic enable thread", nic->log_name);

		rc = pthread_cancel(nic->enable_thread);
		if (rc != 0)
			LOG_DEBUG(PFX "%s: Couldn't send cancel to nic enable "
				  "thread", nic->log_name);

		nic->enable_thread = INVALID_THREAD;
		LOG_DEBUG(PFX "%s: nic enable thread cleaned", nic->log_name);
	} else {
		LOG_DEBUG(PFX "%s: NIC enable thread already canceled",
			  nic->log_name);
	}

	if (nic->thread != INVALID_THREAD) {
		LOG_DEBUG(PFX "%s: Canceling nic thread", nic->log_name);

		rc = pthread_cancel(nic->thread);
		if (rc != 0)
			LOG_DEBUG(PFX "%s: Couldn't send cancel to nic",
				  nic->log_name);

		nic->thread = INVALID_THREAD;
		LOG_DEBUG(PFX "%s: nic thread cleaned", nic->log_name);
	} else {
		LOG_DEBUG(PFX "%s: NIC thread already canceled", nic->log_name);
	}

	if (nic->nl_process_thread != INVALID_THREAD) {
		LOG_DEBUG(PFX "%s: Canceling nic nl thread", nic->log_name);

		rc = pthread_cancel(nic->nl_process_thread);
		if (rc != 0)
			LOG_DEBUG(PFX "%s: Couldn't send cancel to nic nl "
				  "thread", nic->log_name);

		nic->nl_process_thread = INVALID_THREAD;
		LOG_DEBUG(PFX "%s: nic nl thread cleaned", nic->log_name);
	} else {
		LOG_DEBUG(PFX "%s: NIC nl thread already canceled",
			  nic->log_name);
	}

	current = prev = nic_list;
	while (current != NULL) {
		if (current == nic)
			break;

		prev = current;
		current = current->next;
	}

	if (current != NULL) {
		if (current == nic_list)
			nic_list = current->next;
		else
			prev->next = current->next;

		/* Before freeing the nic, must free all the associated
		   nic_iface */
		nic_iface = current->nic_iface;
		while (nic_iface != NULL) {
			vlan_iface = nic_iface->vlan_next;
			while (vlan_iface != NULL) {
				next_nic_iface = vlan_iface->vlan_next;
				free(vlan_iface);
				vlan_iface = next_nic_iface;
			}
			next_nic_iface = nic_iface->next;
			free(nic_iface);
			nic_iface = next_nic_iface;
		}
		free(nic);
	} else {
		LOG_ERR(PFX "%s: Couldn't find nic to remove", nic->log_name);
	}

	return 0;
}

/**
 *  nic_close() - Used to indicate to a NIC that it should close
 *                Must be called with nic->nic_mutex
 *  @param nic - the nic to close
 *  @param graceful -  ALLOW_GRACEFUL_SHUTDOWN will check the nic state
 *                     before proceeding to close()
 *                     FORCE_SHUTDOWN will force the nic to close()
 *                     reguardless of the state
 *  @param clean    -  this will free the proper strings assoicated
 *                     with the NIC
 *
 */
void nic_close(nic_t *nic, NIC_SHUTDOWN_T graceful, int clean)
{
	int rc;
	nic_interface_t *nic_iface, *vlan_iface;
	struct stat file_stat;

	/*  The NIC could be configured by the uIP config file
	 *  but not assoicated with a hardware library just yet
	 *  we will need to check for this */
	if (nic->ops == NULL) {
		LOG_WARN(PFX "%s: when closing nic->ops == NULL",
			 nic->log_name);
		goto error;
	}

	/*  Check if the file node exists */
	rc = stat(nic->uio_device_name, &file_stat);
	if ((rc == 0) && (nic->ops))
		rc = (*nic->ops->close) (nic, graceful);
	if (rc != 0) {
		LOG_ERR(PFX "%s: Could not close nic", nic->log_name);
	} else {
		nic->state = NIC_STOPPED;
		nic->flags &= ~NIC_ENABLED;
		nic->flags |= NIC_DISABLED;
	}

	nic_iface = nic->nic_iface;
	while (nic_iface != NULL) {
		if (!((nic_iface->flags & NIC_IFACE_PERSIST) ==
		      NIC_IFACE_PERSIST)) {
			uip_reset(&nic_iface->ustack);
			vlan_iface = nic_iface->vlan_next;
			while (vlan_iface != NULL) {
				uip_reset(&vlan_iface->ustack);
				vlan_iface = vlan_iface->vlan_next;
			}
		}
		nic_iface = nic_iface->next;
	}

	/*  The NIC must be destroyed and init'ed once again,
	 *  POSIX defines that the mutex will be undefined it
	 *  init'ed twice without a destroy */
	pthread_mutex_destroy(&nic->xmit_mutex);
	pthread_mutex_init(&nic->xmit_mutex, NULL);

	if (clean & FREE_CONFIG_NAME) {
		/*  Free any named strings we might be holding onto */
		if (nic->flags & NIC_CONFIG_NAME_MALLOC) {
			free(nic->config_device_name);
			nic->flags &= ~NIC_CONFIG_NAME_MALLOC;
		}
		nic->config_device_name = NULL;
	}

	if (clean & FREE_UIO_NAME) {
		if (nic->flags & NIC_UIO_NAME_MALLOC) {
			free(nic->uio_device_name);
			nic->uio_device_name = NULL;

			nic->flags &= ~NIC_UIO_NAME_MALLOC;
		}
	}

	LOG_ERR(PFX "%s: nic closed", nic->log_name);
error:
	return;
}

/**
 *  nic_iface_init() - This function is used to add an interface to the
 *                     structure cnic_uio
 *  @return 0 on success, <0 on failure
 */
nic_interface_t *nic_iface_init()
{
	nic_interface_t *nic_iface = malloc(sizeof(*nic_iface));
	if (nic_iface == NULL) {
		LOG_ERR("Could not allocate space for nic iface");
		return NULL;
	}

	memset(nic_iface, 0, sizeof(*nic_iface));
	nic_iface->next = NULL;
	nic_iface->vlan_next = NULL;
	nic_iface->iface_num = IFACE_NUM_INVALID;
	nic_iface->request_type = IP_CONFIG_OFF;

	return nic_iface;
}

/**
 *  nic_add_nic_iface() - This function is used to add an interface to the
 *                        nic structure
 *  Called with nic_mutex held
 *  @param nic - struct nic device to add the interface to
 *  @param nic_iface - network interface used to add to the nic
 *  @return 0 on success, <0 on failure
 */
int nic_add_nic_iface(nic_t *nic, nic_interface_t *nic_iface)
{
	nic_interface_t *current, *prev;

	/* Make sure it doesn't already exist */
	current = nic_find_nic_iface(nic, nic_iface->protocol,
				     nic_iface->vlan_id, nic_iface->iface_num,
				     nic_iface->request_type);
	if (current) {
		LOG_DEBUG(PFX "%s: nic interface for VLAN: %d, protocol: %d"
			  " already exist", nic->log_name, nic_iface->vlan_id,
			  nic_iface->protocol);
		return 0;
	}

	prev = NULL;
	current = nic->nic_iface;
	while (current != NULL) {
		if (current->protocol == nic_iface->protocol) {
			/* Replace parent */
			nic_iface->vlan_next = current;
			nic_iface->next = current->next;
			current->next = NULL;
			if (prev)
				prev->next = nic_iface;
			else
				nic->nic_iface = nic_iface;
			goto done;
		}
		prev = current;
		current = current->next;
	}
	nic_iface->next = nic->nic_iface;
	nic->nic_iface = nic_iface;
done:
	/* Set nic_interface common fields */
	nic_iface->parent = nic;
	memcpy(&nic_iface->ustack.uip_ethaddr.addr, nic->mac_addr, ETH_ALEN);
	nic->num_of_nic_iface++;

	LOG_INFO(PFX "%s: Added nic interface for VLAN: %d, protocol: %d",
		 nic->log_name, nic_iface->vlan_id, nic_iface->protocol);

	return 0;
}

/******************************************************************************
 * Routine to process interrupts from the NIC device
 ******************************************************************************/
/**
 *  nic_process_intr() - Routine used to process interrupts from the hardware
 *  @param nic - NIC hardware to process the interrupt on
 *  @return 0 on success, <0 on failure
 */
int nic_process_intr(nic_t *nic, int discard_check)
{
	fd_set fdset;
	int ret;
	int count;
	struct timeval tv;

	/*  Simple sanity checks */
	if (discard_check != 1 && nic->state != NIC_RUNNING) {
		LOG_ERR(PFX "%s: Couldn't process interrupt NIC not running",
			nic->log_name);
		return -EBUSY;
	}

	if (discard_check != 1 && nic->fd == INVALID_FD) {
		LOG_ERR(PFX "%s: NIC fd not valid", nic->log_name);
		return -EIO;
	}

	FD_ZERO(&fdset);
	FD_SET(nic->fd, &fdset);

	tv.tv_sec = 0;
	pthread_mutex_lock(&nic->nic_mutex);
	if (nic->flags & NIC_LONG_SLEEP)
		tv.tv_usec = 1000;
	else
		tv.tv_usec = nic->rx_poll_usec;
	pthread_mutex_unlock(&nic->nic_mutex);

	/*  Wait for an interrupt to come in or timeout */
	ret = select(nic->fd + 1, &fdset, NULL, NULL, &tv);
	switch (ret) {
	case 1:
		/* Usually there should only be one file descriptor ready
		 * to read */
		break;
	case 0:
		return ret;
	case -1:
		LOG_ERR(PFX "%s: error waiting for interrupt: %s",
			nic->log_name, strerror(errno));
		return 0;
	default:
		LOG_ERR(PFX "%s: unknown number of FD's, ignoring: %d ret",
			nic->log_name, ret);
		return 0;
	}

	ret = read(nic->fd, &count, sizeof(count));
	pthread_mutex_lock(&nic->nic_mutex);
	if (ret > 0) {
		nic->stats.interrupts++;
		LOG_PACKET(PFX "%s: interrupt count: %d prev: %d",
			   nic->log_name, count, nic->intr_count);

		if (count == nic->intr_count) {
			LOG_PACKET(PFX "%s: got interrupt but count still the "
				   "same", nic->log_name, count);
		}

		/*  Check if we missed an interrupt.  With UIO,
		 *  the count should be incremental */
		if (count != nic->intr_count + 1) {
			nic->stats.missed_interrupts++;
			LOG_PACKET(PFX "%s: Missed interrupt! on %d not %d",
				   nic->log_name, count, nic->intr_count);
		}

		nic->intr_count = count;

		if (strcmp(nic->ops->description, "qedi")) {
			LOG_DEBUG(PFX "%s: host:%d - calling clear_tx_intr from process_intr",
			          nic->log_name, nic->host_no);
			(*nic->ops->clear_tx_intr) (nic);
		}

		ret = 1;
	}
	pthread_mutex_unlock(&nic->nic_mutex);

	return ret;
}

void prepare_ipv4_packet(nic_t *nic,
			 nic_interface_t *nic_iface,
			 struct uip_stack *ustack, packet_t *pkt)
{
	u16_t ipaddr[2];
	arp_table_query_t arp_query;
	dest_ipv4_addr_t dest_ipv4_addr;
	struct arp_entry *tabptr;
	int queue_rc;
	int vlan_id = 0;

	/* If the rx vlan tag is not stripped and vlan is present in the pkt,
	   manual stripping is required because tx is using hw vlan tag! */
	if (pkt->network_layer == pkt->data_link_layer +
				  sizeof(struct uip_vlan_eth_hdr)) {
		/* VLAN is detected in the pkt buf */
		memcpy(pkt->data_link_layer + 12, pkt->network_layer - 2,
		       pkt->buf_size - sizeof(struct uip_vlan_eth_hdr) + 2);
	}
	dest_ipv4_addr = uip_determine_dest_ipv4_addr(ustack, ipaddr);
	if (dest_ipv4_addr == LOCAL_BROADCAST) {
		uip_build_eth_header(ustack, ipaddr, NULL, pkt, vlan_id);
		return;
	}

	arp_query = is_in_arp_table(ipaddr, &tabptr);

	switch (arp_query) {
	case IS_IN_ARP_TABLE:
		uip_build_eth_header(ustack,
				     ipaddr, tabptr, pkt, vlan_id);
		break;
	case NOT_IN_ARP_TABLE:
		queue_rc = nic_queue_tx_packet(nic, nic_iface, pkt);
		if (queue_rc) {
			LOG_ERR("could not queue TX packet: %d", queue_rc);
		} else {
			uip_build_arp_request(ustack, ipaddr);
		}
		break;
	default:
		LOG_ERR("Unknown arp state");
		break;
	}
}

void prepare_ipv6_packet(nic_t *nic,
			 nic_interface_t *nic_iface,
			 struct uip_stack *ustack, packet_t *pkt)
{
	struct uip_eth_hdr *eth;
	struct uip_vlan_eth_hdr *eth_vlan;
	int vlan_id = 0;

	if (pkt->network_layer == pkt->data_link_layer +
				  sizeof(struct uip_vlan_eth_hdr)) {
		/* VLAN is detected in the pkt buf */
		memcpy(pkt->data_link_layer + 12, pkt->network_layer - 2,
		       pkt->buf_size - sizeof(struct uip_vlan_eth_hdr) + 2);
	}
	eth = (struct uip_eth_hdr *)ustack->data_link_layer;
	eth_vlan = (struct uip_vlan_eth_hdr *)ustack->data_link_layer;
	if (vlan_id == 0) {
		eth->type = htons(UIP_ETHTYPE_IPv6);
	} else {
		eth_vlan->tpid = htons(UIP_ETHTYPE_8021Q);
		eth_vlan->vid = htons(vlan_id);
		eth_vlan->type = htons(UIP_ETHTYPE_IPv6);
	}
}

void prepare_ustack(nic_t *nic,
		    nic_interface_t *nic_iface,
		    struct uip_stack *ustack, struct packet *pkt)
{
	struct ether_header *eth = NULL;
	ustack->uip_buf = pkt->buf;
	ustack->uip_len = pkt->buf_size;

	pkt->nic = nic;
	pkt->nic_iface = nic_iface;

	ustack->data_link_layer = pkt->buf;
	/*  Adjust the network layer pointer depending if
	 *  there is a VLAN tag or not, or if the hardware
	 *  has stripped out the
	 *  VLAN tag */
	ustack->network_layer = ustack->data_link_layer +
				sizeof(struct uip_eth_hdr);
	/* Init buffer to be IPv6 */
	if (nic_iface->ustack.ip_config == IPV6_CONFIG_DHCP ||
	    nic_iface->ustack.ip_config == IPV6_CONFIG_STATIC) {
		eth = (struct ether_header *)ustack->data_link_layer;
		eth->ether_type = htons(UIP_ETHTYPE_IPv6);
	}
}

int do_timers_per_nic_iface(nic_t *nic, nic_interface_t *nic_iface,
			    struct timer *arp_timer)
{
	packet_t *pkt;
	struct uip_stack *ustack = &nic_iface->ustack;
	int i;

	pkt = get_next_free_packet(nic);
	if (pkt == NULL)
		return -EIO;

	if (nic_iface->protocol == AF_INET) {
		for (i = 0; i < UIP_UDP_CONNS; i++) {
			prepare_ustack(nic, nic_iface, ustack, pkt);

			uip_udp_periodic(ustack, i);
			/* If the above function invocation resulted
			 * in data that should be sent out on the
			 * network, the global variable uip_len is
			 * set to a value > 0. */
			if (ustack->uip_len > 0) {
				pkt->buf_size = ustack->uip_len;

				prepare_ipv4_packet(nic, nic_iface, ustack,
						    pkt);

				(*nic->ops->write) (nic, nic_iface, pkt);
				ustack->uip_len = 0;
			}
		}
	} else {
		/* Added periodic poll for IPv6 NDP engine */
		if (ustack->ndpc != NULL) {	/* If engine is active */
			prepare_ustack(nic, nic_iface, ustack, pkt);

			uip_ndp_periodic(ustack);
			/* If the above function invocation resulted
			 * in data that should be sent out on the
			 * network, the global variable uip_len is
			 * set to a value > 0. */
			if (ustack->uip_len > 0) {
				pkt->buf_size = ustack->uip_len;
				prepare_ipv6_packet(nic, nic_iface, ustack,
						    pkt);
				(*nic->ops->write) (nic, nic_iface, pkt);
				ustack->uip_len = 0;
			}
		}
	}
	/* Call the ARP timer function every 10 seconds. */
	if (timer_expired(arp_timer)) {
		timer_reset(arp_timer);
		uip_arp_timer();
	}
	put_packet_in_free_queue(pkt, nic);
	return 0;
}

static int check_timers(nic_t *nic,
			struct timer *periodic_timer, struct timer *arp_timer)
{
	if (timer_expired(periodic_timer)) {
		nic_interface_t *nic_iface, *vlan_iface;

		timer_reset(periodic_timer);

		pthread_mutex_lock(&nic->nic_mutex);

		nic_iface = nic->nic_iface;
		while (nic_iface != NULL) {
			do_timers_per_nic_iface(nic, nic_iface, arp_timer);
			vlan_iface = nic_iface->vlan_next;
			while (vlan_iface != NULL) {
				do_timers_per_nic_iface(nic, vlan_iface,
							arp_timer);
				vlan_iface = vlan_iface->vlan_next;
			}
			nic_iface = nic_iface->next;
		}

		pthread_mutex_unlock(&nic->nic_mutex);
	}
	return 0;
}

int process_packets(nic_t *nic,
		    struct timer *periodic_timer,
		    struct timer *arp_timer, nic_interface_t *nic_iface)
{
	int rc;
	packet_t *pkt;

	pkt = get_next_free_packet(nic);
	if (pkt == NULL) {
		LOG_DEBUG(PFX "%s: Couldn't get buffer for processing packet",
			  nic->log_name);
		return -ENOMEM;
	}

	pthread_mutex_lock(&nic->nic_mutex);
	rc = (*nic->ops->read) (nic, pkt);
	pthread_mutex_unlock(&nic->nic_mutex);

	if ((rc != 0) && (pkt->buf_size > 0)) {
		uint16_t type = 0;
		int af_type = 0;
		struct uip_stack *ustack;
		uint16_t vlan_id;

		pkt->data_link_layer = pkt->buf;

		vlan_id = pkt->vlan_tag & 0xFFF;
		if ((vlan_id == 0) ||
		    (NIC_VLAN_STRIP_ENABLED & nic->flags)) {
			struct uip_eth_hdr *hdr = ETH_BUF(pkt->buf);
			type = ntohs(hdr->type);
			pkt->network_layer = pkt->data_link_layer +
					     sizeof(struct uip_eth_hdr);
		} else {
			struct uip_vlan_eth_hdr *hdr = VLAN_ETH_BUF(pkt->buf);
			type = ntohs(hdr->type);
			pkt->network_layer = pkt->data_link_layer +
					     sizeof(struct uip_vlan_eth_hdr);
		}

		switch (type) {
		case UIP_ETHTYPE_IPv6:
			af_type = AF_INET6;
			break;
		case UIP_ETHTYPE_IPv4:
		case UIP_ETHTYPE_ARP:
			af_type = AF_INET;
			LOG_DEBUG(PFX "%s: ARP or IPv4 vlan:0x%x ethertype:0x%x",
				   nic->log_name, vlan_id, type);
			break;
		default:
			LOG_DEBUG(PFX "%s: Ignoring vlan:0x%x ethertype:0x%x",
				   nic->log_name, vlan_id, type);
			goto done;
		}

		pthread_mutex_lock(&nic->nic_mutex);

		/*  check if we have the given VLAN interface */
		if (nic_iface != NULL) {
			if (vlan_id != nic_iface->vlan_id) {
				/* Matching nic_iface not found, drop */
				pthread_mutex_unlock(&nic->nic_mutex);
				rc = EINVAL;  /* Return the +error code */
				goto done;
			}
			goto nic_iface_present;
		}

		/* Best effort to find the correct instance
		   Input: protocol and vlan_tag */
		nic_iface = nic_find_nic_iface(nic, af_type, vlan_id,
					       IFACE_NUM_INVALID,
					       IP_CONFIG_OFF);
		if (nic_iface == NULL) {
			/* Matching nic_iface not found */
			pthread_mutex_unlock(&nic->nic_mutex);
			LOG_DEBUG(PFX "%s: Couldn't find interface for "
				   "VLAN: %d af_type %d",
				nic->log_name, vlan_id, af_type);
			rc = EINVAL;  /* Return the +error code */
			goto done;
		}
nic_iface_present:
		pkt->nic_iface = nic_iface;
		LOG_DEBUG(PFX "%s: found nic iface, type=0x%x, bufsize=%d",
			  nic->log_name, type, pkt->buf_size);

		ustack = &nic_iface->ustack;

		ustack->uip_buf = pkt->buf;
		ustack->uip_len = pkt->buf_size;
		ustack->data_link_layer = pkt->buf;

		/*  Adjust the network layer pointer depending if there is a
		 *  VLAN tag or not, or if the hardware has stripped out the
		 *  VLAN tag */
		if ((vlan_id == 0) ||
		    (NIC_VLAN_STRIP_ENABLED & nic->flags))
			ustack->network_layer = ustack->data_link_layer +
			    sizeof(struct uip_eth_hdr);
		else
			ustack->network_layer = ustack->data_link_layer +
			    sizeof(struct uip_vlan_eth_hdr);

		/*  determine how we should process this packet based on the
		 *  ethernet type */
		switch (type) {
		case UIP_ETHTYPE_IPv6:
			uip_input(ustack);
			if (ustack->uip_len > 0) {
				/* The pkt generated has already consulted
				   the IPv6 ARP table */
				pkt->buf_size = ustack->uip_len;
				prepare_ipv6_packet(nic, nic_iface,
						    ustack, pkt);

				(*nic->ops->write) (nic, nic_iface, pkt);
			}
			break;
		case UIP_ETHTYPE_IPv4:
			uip_arp_ipin(ustack, pkt);
			uip_input(ustack);
			/* If the above function invocation resulted
			 * in data that should be sent out on the
			 * network, the global variable uip_len is
			 * set to a value > 0. */
			if (ustack->uip_len > 0) {
				pkt->buf_size = ustack->uip_len;
				prepare_ipv4_packet(nic, nic_iface,
						    ustack, pkt);

				LOG_DEBUG(PFX "%s: write called after arp_ipin, uip_len=%d",
					  nic->log_name, ustack->uip_len);
				(*nic->ops->write) (nic, nic_iface, pkt);
			}

			break;
		case UIP_ETHTYPE_ARP:
			uip_arp_arpin(nic_iface, ustack, pkt);

			/* If the above function invocation resulted
			 * in data that should be sent out on the
			 * network, the global variable uip_len
			 * is set to a value > 0. */
			if (pkt->buf_size > 0) {
				pkt->buf_size = ustack->uip_len;
				LOG_DEBUG(PFX "%s: write called after arp_arpin, bufsize=%d",
					   nic->log_name, pkt->buf_size);
				(*nic->ops->write) (nic, nic_iface, pkt);
			}
			break;
		}
		ustack->uip_len = 0;
		pthread_mutex_unlock(&nic->nic_mutex);
	}

done:
	put_packet_in_free_queue(pkt, nic);

	return rc;
}

static int process_dhcp_loop(nic_t *nic,
			     nic_interface_t *nic_iface,
			     struct timer *periodic_timer,
			     struct timer *arp_timer)
{
	struct dhcpc_state *s;
	struct ndpc_state *n;
	int rc;
	struct timeval start_time;
	struct timeval current_time;
	struct timeval wait_time;
	struct timeval total_time;

	/* 10s loop time to wait for DHCP */
	switch (nic_iface->ustack.ip_config) {
	case IPV4_CONFIG_DHCP:
		wait_time.tv_sec = 10;
		break;
	case IPV6_CONFIG_DHCP:
		wait_time.tv_sec = 15;
		break;
	case IPV6_CONFIG_STATIC:
		wait_time.tv_sec = 4;
		break;
	default:
		wait_time.tv_sec = 2;
	}
	wait_time.tv_usec = 0;

	s = nic_iface->ustack.dhcpc;
	n = nic_iface->ustack.ndpc;

	if (gettimeofday(&start_time, NULL)) {
		LOG_ERR(PFX "%s: Couldn't get time of day to start DHCP timer",
			nic->log_name);
		return -EIO;
	}

	timeradd(&start_time, &wait_time, &total_time);

	periodic_timer->start = periodic_timer->start -
	    periodic_timer->interval;

	while ((event_loop_stop == 0) &&
	       (nic->flags & NIC_ENABLED) && !(nic->flags & NIC_GOING_DOWN)) {

		if (nic_iface->ustack.ip_config == IPV4_CONFIG_DHCP) {
			if (s->state == STATE_CONFIG_RECEIVED)
				break;
		}
		if (nic_iface->ustack.ip_config == IPV6_CONFIG_DHCP ||
		    nic_iface->ustack.ip_config == IPV6_CONFIG_STATIC) {
			if (n->state == NDPC_STATE_BACKGROUND_LOOP)
				break;
		}

		/*  Check the periodic and ARP timer */
		check_timers(nic, periodic_timer, arp_timer);

		rc = nic_process_intr(nic, 1);

		while ((rc > 0) && (!(nic->flags & NIC_GOING_DOWN))) {
			rc = process_packets(nic,
					     periodic_timer,
					     arp_timer, nic_iface);
		}

		if (gettimeofday(&current_time, NULL)) {
			LOG_ERR(PFX "%s: Couldn't get current time for "
				"DHCP start", nic->log_name);
			return -EIO;
		}

		if (timercmp(&total_time, &current_time, <)) {
			LOG_ERR(PFX "%s: timeout waiting for DHCP/NDP",
				nic->log_name);
			if (nic_iface->ustack.ip_config == IPV6_CONFIG_DHCP ||
			    nic_iface->ustack.ip_config == IPV6_CONFIG_STATIC)
				n->retry_count = IPV6_MAX_ROUTER_SOL_RETRY;
			return -EIO;
		}
	}

	if (nic->flags & NIC_GOING_DOWN)
		return -EIO;
	else if (nic->flags & NIC_DISABLED)
		return -EINVAL;
	else
		return 0;
}

/* Called with nic_mutex locked */
static int do_acquisition(nic_t *nic, nic_interface_t *nic_iface,
			  struct timer *periodic_timer, struct timer *arp_timer)
{
	struct in_addr addr;
	struct in6_addr addr6;
	char buf[INET6_ADDRSTRLEN];
	int rc = -1;

	/* New acquisition */
	uip_init(&nic_iface->ustack, nic->flags & NIC_IPv6_ENABLED);
	memcpy(&nic_iface->ustack.uip_ethaddr.addr, nic->mac_addr, ETH_ALEN);

	LOG_INFO(PFX "%s: Initialized ip stack: VLAN: %d",
		 nic->log_name, nic_iface->vlan_id);

	LOG_INFO(PFX "%s: mac: %02x:%02x:%02x:%02x:%02x:%02x",
		 nic->log_name,
		 nic_iface->mac_addr[0],
		 nic_iface->mac_addr[1],
		 nic_iface->mac_addr[2],
		 nic_iface->mac_addr[3],
		 nic_iface->mac_addr[4],
		 nic_iface->mac_addr[5]);

	switch (nic_iface->ustack.ip_config) {
	case IPV4_CONFIG_STATIC:
		memcpy(&addr.s_addr, nic_iface->ustack.hostaddr,
		       sizeof(addr.s_addr));

		LOG_INFO(PFX "%s: Using IP address: %s",
			 nic->log_name, inet_ntoa(addr));

		memcpy(&addr.s_addr, nic_iface->ustack.netmask,
		       sizeof(addr.s_addr));

		LOG_INFO(PFX "%s: Using netmask: %s",
			 nic->log_name, inet_ntoa(addr));

		set_uip_stack(&nic_iface->ustack,
			      NULL, NULL, NULL,
			      nic_iface->mac_addr);
		break;

	case IPV4_CONFIG_DHCP:
		set_uip_stack(&nic_iface->ustack,
			      NULL, NULL, NULL,
			      nic_iface->mac_addr);
		if (dhcpc_init(nic, &nic_iface->ustack,
			       nic_iface->mac_addr, ETH_ALEN)) {
			if (nic_iface->ustack.dhcpc) {
				LOG_DEBUG(PFX "%s: DHCPv4 engine already "
					  "initialized!", nic->log_name);
				goto skip;
			} else {
				LOG_DEBUG(PFX "%s: DHCPv4 engine failed "
					  "initialization!", nic->log_name);
				goto error;
			}
		}
		pthread_mutex_unlock(&nic->nic_mutex);
		rc = process_dhcp_loop(nic, nic_iface, periodic_timer,
				       arp_timer);
		pthread_mutex_lock(&nic->nic_mutex);

		if (rc) {
			LOG_ERR(PFX "%s: DHCP failed", nic->log_name);
			/* For DHCPv4 failure, the ustack must be cleaned so
			   it can re-acquire on the next iscsid request */
			uip_reset(&nic_iface->ustack);
			goto error;
		}

		if (nic->flags & NIC_DISABLED) {
			/* Break out of this loop */
			break;
		}

		LOG_INFO(PFX "%s: Initialized dhcp client", nic->log_name);
		break;

	case IPV6_CONFIG_DHCP:
	case IPV6_CONFIG_STATIC:
		if (ndpc_init(nic, &nic_iface->ustack, nic_iface->mac_addr,
			      ETH_ALEN)) {
			LOG_DEBUG(PFX "%s: IPv6 engine already initialized!",
				  nic->log_name);
			goto skip;
		}
		pthread_mutex_unlock(&nic->nic_mutex);
		rc = process_dhcp_loop(nic, nic_iface, periodic_timer,
				       arp_timer);
		pthread_mutex_lock(&nic->nic_mutex);
		if (rc) {
			/* Don't reset and allow to use RA and LL */
			LOG_ERR(PFX "%s: IPv6 DHCP/NDP failed", nic->log_name);
		}
		if (nic_iface->ustack.ip_config == IPV6_CONFIG_STATIC) {
			memcpy(&addr6.s6_addr, nic_iface->ustack.hostaddr6,
			       sizeof(addr6.s6_addr));
			inet_ntop(AF_INET6, addr6.s6_addr, buf, sizeof(buf));
			LOG_INFO(PFX "%s: hostaddr IP: %s", nic->log_name, buf);
			memcpy(&addr6.s6_addr, nic_iface->ustack.netmask6,
			       sizeof(addr6.s6_addr));
			inet_ntop(AF_INET6, addr6.s6_addr, buf, sizeof(buf));
			LOG_INFO(PFX "%s: netmask IP: %s", nic->log_name, buf);
		}
		break;

	default:
		LOG_INFO(PFX "%s: ipconfig = %d?", nic->log_name,
			 nic_iface->ustack.ip_config);
	}
skip:
	/* Mark acquisition done for this nic iface */
	nic_iface->flags &= ~NIC_IFACE_ACQUIRE;

	LOG_INFO(PFX "%s: enabled vlan %d protocol: %d", nic->log_name,
		 nic_iface->vlan_id, nic_iface->protocol);
	return 0;

error:
	return -EIO;
}


void *nic_loop(void *arg)
{
	nic_t *nic = (nic_t *) arg;
	int rc = -1;
	sigset_t set;
	struct timer periodic_timer, arp_timer;

	sigfillset(&set);
	rc = pthread_sigmask(SIG_BLOCK, &set, NULL);
	if (rc != 0) {
		/* TODO: determine if we need to exit this thread if we fail
		 * to set the signal mask */
		LOG_ERR(PFX "%s: Couldn't set signal mask", nic->log_name);
	}

	/*  Signal the device to enable itself */
	pthread_mutex_lock(&nic->nic_mutex);
	pthread_cond_signal(&nic->nic_loop_started_cond);

	/* nic_mutex must be locked */
	while ((event_loop_stop == 0) &&
	       !(nic->flags & NIC_EXIT_MAIN_LOOP) &&
	       !(nic->flags & NIC_GOING_DOWN)) {
		nic_interface_t *nic_iface, *vlan_iface;

		if (nic->flags & NIC_DISABLED) {
			LOG_DEBUG(PFX "%s: Waiting to be enabled",
				  nic->log_name);

			/*  Wait for the device to be enabled */
			/* nic_mutex is already locked */
			pthread_cond_wait(&nic->enable_wait_cond,
					  &nic->nic_mutex);

			if (nic->state == NIC_EXIT) {
				pthread_mutex_unlock(&nic->nic_mutex);
				pthread_exit(NULL);
			}
			LOG_DEBUG(PFX "%s: is now enabled", nic->log_name);
		}
		/*  initialize the device to send/rec data */
		rc = (*nic->ops->open) (nic);
		if (rc != 0) {
			LOG_ERR(PFX "%s: Could not initialize CNIC UIO device",
				nic->log_name);

			if (rc == -ENOTSUP)
				nic->flags |= NIC_EXIT_MAIN_LOOP;
			else
				nic->flags &= ~NIC_ENABLED;

			/* Signal that the device enable is done */
			pthread_cond_broadcast(&nic->enable_done_cond);
			pthread_mutex_unlock(&nic->nic_mutex);
			goto dev_close;
		}
		nic_set_all_nic_iface_mac_to_parent(nic);
		pthread_mutex_unlock(&nic->nic_mutex);

		rc = alloc_free_queue(nic, 5);
		if (rc != 5) {
			if (rc != 0) {
				LOG_WARN(PFX "%s: Allocated %d packets "
					 "instead of %d", nic->log_name, rc, 5);
			} else {
				LOG_ERR(PFX "%s: No packets allocated "
					"instead of %d", nic->log_name, 5);
				/*  Signal that the device enable is done */
				pthread_cond_broadcast(&nic->enable_done_cond);
				goto dev_close;
			}
		}
		/* Indication for the nic_disable routine that the nic
		   has started running */
		nic->state = NIC_STARTED_RUNNING;

		/*  Initialize the system clocks */
		timer_set(&periodic_timer, CLOCK_SECOND / 2);
		timer_set(&arp_timer, CLOCK_SECOND * 10);

		/*  Prepare the stack for each of the VLAN interfaces */
		pthread_mutex_lock(&nic->nic_mutex);

		/* If DHCP fails, exit loop and restart the engine */
		nic_iface = nic->nic_iface;
		while (nic_iface != NULL) {
			if (nic_iface->flags & NIC_IFACE_ACQUIRE) {
				do_acquisition(nic, nic_iface,
					       &periodic_timer,
					       &arp_timer);
			}
			vlan_iface = nic_iface->vlan_next;
			while (vlan_iface != NULL) {
				if (vlan_iface->flags & NIC_IFACE_ACQUIRE) {
					do_acquisition(nic, vlan_iface,
						       &periodic_timer,
						       &arp_timer);
				}
				vlan_iface = vlan_iface->next;
			}
			nic_iface = nic_iface->next;
		}
		if (nic->flags & NIC_DISABLED) {
			LOG_WARN(PFX "%s: nic was disabled during nic loop, "
				 "closing flag 0x%x",
				 nic->log_name, nic->flags);
			/*  Signal that the device enable is done */
			pthread_cond_broadcast(&nic->enable_done_cond);
			pthread_mutex_unlock(&nic->nic_mutex);
			goto dev_close_free;
		}

		/*  This is when we start the processing of packets */
		nic->start_time = time(NULL);
		nic->state = NIC_RUNNING;

		nic->flags &= ~NIC_ENABLED_PENDING;

		/*  Signal that the device enable is done */
		pthread_cond_broadcast(&nic->enable_done_cond);

		LOG_INFO(PFX "%s: entering main nic loop", nic->log_name);

		while ((nic->state == NIC_RUNNING) &&
		       (event_loop_stop == 0) &&
		       !(nic->flags & NIC_GOING_DOWN)) {
			pthread_mutex_unlock(&nic->nic_mutex);
			/*  Check the periodic and ARP timer */
			check_timers(nic, &periodic_timer, &arp_timer);
			rc = nic_process_intr(nic, 0);
			while ((rc > 0) &&
			       (nic->state == NIC_RUNNING) &&
			       !(nic->flags & NIC_GOING_DOWN)) {
				rc = process_packets(nic,
						     &periodic_timer,
						     &arp_timer, NULL);
			}
			pthread_mutex_lock(&nic->nic_mutex);
		}

		LOG_INFO(PFX "%s: exited main processing loop", nic->log_name);

dev_close_free:
		free_free_queue(nic);
dev_close:

		if (nic->flags & NIC_GOING_DOWN) {
			nic_close(nic, 1, FREE_NO_STRINGS);

			nic->flags &= ~NIC_GOING_DOWN;
		} else {
			pthread_mutex_destroy(&nic->xmit_mutex);
			pthread_mutex_init(&nic->xmit_mutex, NULL);
		}
		nic->pending_count = 0;

		if (!(nic->flags & NIC_EXIT_MAIN_LOOP)) {
			/*  Signal we are done closing CNIC/UIO device */
			pthread_cond_broadcast(&nic->disable_wait_cond);
		}
	}
	/* clean up the nic flags */
	nic->flags &= ~NIC_ENABLED_PENDING;

	pthread_mutex_unlock(&nic->nic_mutex);

	LOG_INFO(PFX "%s: nic loop thread exited", nic->log_name);

	nic->thread = INVALID_THREAD;

	pthread_exit(NULL);
}
