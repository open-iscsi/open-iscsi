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
 * nic.h - NIC header file
 *
 */

#include <errno.h>

#ifndef __NIC_H__
#define __NIC_H__

#include <stdint.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <linux/limits.h>
#include <stdlib.h>
#include <pthread.h>

#include "nic_nl.h"
#include "packet.h"
#include "uip.h"
#include "timer.h"

#include "iscsi_if.h"

/*  Foward declarations */
struct nic_ops;
struct nic_lib_handle;
struct packet;
struct nic_op;

extern pthread_mutex_t nic_lib_list_mutex;
extern struct nic_lib_handle *nic_lib_list;

/*  Used to store a list of active cnic devices */
extern pthread_mutex_t nic_list_mutex;
extern struct nic *nic_list;

extern void *nl_process_handle_thread(void *arg);

/*******************************************************************************
 *  Constants
 ******************************************************************************/
#define MAX_PCI_DEVICE_ENTRIES	64	/* Maxium number of pci_device_id
					   entries a hw library may contain */

#define FREE_CONFIG_NAME	0x0001
#define FREE_UIO_NAME		0x0002
#define FREE_ALL_STRINGS	(FREE_CONFIG_NAME | FREE_UIO_NAME)
#define FREE_NO_STRINGS		0x0000

/******************************************************************************
 * Enumerations
 ******************************************************************************/
typedef enum {
	ALLOW_GRACEFUL_SHUTDOWN = 1,
	FORCE_SHUTDOWN = 2,
} NIC_SHUTDOWN_T;

/*******************************************************************************
 * Structure used to hold PCI vendor, device, subvendor and subdevice ID's
 ******************************************************************************/
struct pci_device_id {
	const uint32_t vendor, device;	/* Vendor and device ID or PCI_ANY_ID */
	const uint32_t subvendor, subdevice;	/* Subsystem ID's/PCI_ANY_ID */
	const char *device_name;	/* Data private to the driver */
};

/******************************************************************************
 * NIC statistics structure
 ******************************************************************************/
struct nic_stats {
	uint64_t interrupts;
	uint64_t missed_interrupts;

	struct {
		uint64_t packets;
		uint64_t bytes;
	} tx;

	struct {
		uint64_t packets;
		uint64_t bytes;
	} rx;
};

/******************************************************************************
 * NIC interface structure
 ******************************************************************************/
typedef struct nic_interface {
	struct nic_interface *vlan_next;
	struct nic_interface *next;
	struct nic *parent;

	uint16_t protocol;
	uint16_t flags;
#define NIC_IFACE_PERSIST	(1<<0)
#define NIC_IFACE_ACQUIRE	(1<<1)
#define NIC_IFACE_PATHREQ_WAIT1	(1<<2)
#define NIC_IFACE_PATHREQ_WAIT2 (1<<3)
#define NIC_IFACE_PATHREQ_WAIT	(NIC_IFACE_PATHREQ_WAIT1 | \
				 NIC_IFACE_PATHREQ_WAIT2)
	uint8_t mac_addr[ETH_ALEN];
	uint8_t vlan_priority;
	uint16_t vlan_id;
#define NO_VLAN		0x8000

	uint16_t mtu;
	time_t start_time;

	struct uip_stack ustack;

#define IFACE_NUM_PRESENT (1<<0)
#define IFACE_NUM_INVALID -1
	int iface_num;
	int request_type;
} nic_interface_t;

/******************************************************************************
 * NIC lib operations structure
 ******************************************************************************/
struct nic_lib_ops {
	/*  Used to get the NIC library name */
	void (*get_library_name) (char **library_name,
				  size_t *library_name_size);

	/*  Used to get to the PCI table supported by the NIC library */
	void (*get_pci_table) (struct pci_device_id **table,
			       uint32_t *entries);

	/*  Used to get the version of this NIC library */
	void (*get_library_version) (char **version_string,
				     size_t *version_string_size);

	/*  Used to get the NIC library build date */
	void (*get_build_date) (char **build_date_string,
				size_t *build_date_string_size);

	/*  Used to get the transport name assoicated with this library */
	void (*get_transport_name) (char **transport_name,
				    size_t *transport_name_size);

	/*  Used to get the uio name assoicated with this library */
	void (*get_uio_name) (char **uio_name, size_t *uio_name_size);

};

/*******************************************************************************
 * NIC op table definition
 ******************************************************************************/
typedef struct nic_ops {
	struct nic_lib_ops lib_ops;

	char *description;
	int (*open) (struct nic *);
	int (*close) (struct nic *, NIC_SHUTDOWN_T);
	int (*read) (struct nic *, struct packet *);
	int (*write) (struct nic *, nic_interface_t *, struct packet *);
	void *(*get_tx_pkt) (struct nic *);
	void (*start_xmit) (struct nic *, size_t, u16_t vlan_id);
	int (*clear_tx_intr) (struct nic *);
	int (*handle_iscsi_path_req) (struct nic *,
				      int,
				      struct iscsi_uevent *ev,
				      struct iscsi_path *path,
				      nic_interface_t *nic_iface);
} net_ops_t;

typedef struct nic_lib_handle {
	struct nic_lib_handle *next;

	pthread_mutex_t mutex;
	struct nic_ops *ops;
} nic_lib_handle_t;

typedef struct nic {
	struct nic *next;

	uint32_t flags;
#define NIC_UNITIALIZED		0x0001
#define NIC_INITIALIZED		0x0002
#define NIC_ENABLED		0x0004
#define NIC_DISABLED		0x0008
#define NIC_IPv6_ENABLED	0x0010
#define NIC_ADDED_MULICAST	0x0020
#define NIC_LONG_SLEEP		0x0040
#define NIC_PATHREQ_WAIT	0x0080

#define NIC_VLAN_STRIP_ENABLED	0x0100
#define NIC_MSIX_ENABLED	0x0200
#define NIC_TX_HAS_SENT		0x0400
#define NIC_ENABLED_PENDING	0x0800

#define NIC_UIO_NAME_MALLOC	0x1000
#define NIC_CONFIG_NAME_MALLOC	0x2000
#define NIC_EXIT_MAIN_LOOP	0x4000
#define NIC_GOING_DOWN		0x8000
#define NIC_RESET_UIP		0x10000

	uint16_t state;
#define NIC_STOPPED		0x0001
#define NIC_STARTED_RUNNING	0x0002
#define NIC_RUNNING		0x0004
#define NIC_EXIT		0x0010

	int fd;			/* Holds the file descriptor to UIO */
	uint16_t uio_minor;	/* Holds the UIO minor number */

	uint32_t host_no;	/* Holds the associated host number */

	char *library_name;	/* Name of the library to assoicate with */
	char *log_name;		/* Human friendly name used in the log
				   file                                 */
	char *config_device_name;	/* Name read from the XML configuration
					   file                         */
	char eth_device_name[IFNAMSIZ];	/* Network interface name       */
	char *uio_device_name;	/* UIO device name                      */

	uint32_t intr_count;	/* Total UIO interrupt count            */

	int page_size;

	/* Held for nic ops manipulation */
	pthread_mutex_t nic_mutex;

	/*  iSCSI ring ethernet MAC address */
	__u8 mac_addr[ETH_ALEN];

	/*  Used to manage the network interfaces of this device */
	__u32 num_of_nic_iface;
	nic_interface_t *nic_iface;

	/*  Wait for the device to be enabled */
	pthread_cond_t enable_wait_cond;

	/*  Wait for the device to be finished enabled */
	pthread_cond_t enable_done_cond;

	/*  Wait for the nic loop to start */
	pthread_cond_t nic_loop_started_cond;

	/*  Wait for the device to be disabled */
	pthread_cond_t disable_wait_cond;

	/* Held when transmitting */
	pthread_mutex_t xmit_mutex;

	/* The thread this device is running on */
	pthread_t thread;

	/* The thread used to enable the device */
	pthread_t enable_thread;

	/* Statistical Information on this device */
	time_t start_time;
	struct nic_stats stats;

	/*  Number of retrys from iscsid */
	uint32_t pending_count;
	uint32_t pathreq_pending_count;

#define DEFAULT_RX_POLL_USEC	100	/* usec */
	/* options enabled by the user */
	uint32_t rx_poll_usec;

	/*  Used to hold hardware specific data */
	void *priv;

	/*  Used to hold the TX packets that are needed to be sent */
	struct packet *tx_packet_queue;

	/* Mutex to protect the list of free packets */
	pthread_mutex_t free_packet_queue_mutex;

	/*  Used to hold the free packets that are needed to be sent */
	struct packet *free_packet_queue;

	/*  Points to the NIC library */
	nic_lib_handle_t *nic_library;

	/*  Points to the PCI table entry */
	struct pci_device_id *pci_id;

	/*  Used to process the interrupt */
	int (*process_intr) (struct nic *nic);

	struct nic_ops *ops;

	/* NL processing parameters */
	pthread_t nl_process_thread;
	pthread_cond_t nl_process_cond;
	pthread_cond_t nl_process_if_down_cond;
	pthread_mutex_t nl_process_mutex;
	int nl_process_if_down;
	int nl_process_head;
	int nl_process_tail;
#define NIC_NL_PROCESS_MAX_RING_SIZE        128
#define NIC_NL_PROCESS_LAST_ENTRY           (NIC_NL_PROCESS_MAX_RING_SIZE - 1)
#define NIC_NL_PROCESS_NEXT_ENTRY(x) ((x + 1) & NIC_NL_PROCESS_MAX_RING_SIZE)
	void *nl_process_ring[NIC_NL_PROCESS_MAX_RING_SIZE];

	/* The thread used to perform ping */
	pthread_t ping_thread;
	uint64_t transport_handle;
} nic_t;

/******************************************************************************
 * Function Prototypes
 *****************************************************************************/
int load_all_nic_libraries();

nic_t *nic_init();
void nic_add(nic_t *nic);
int nic_remove(nic_t *nic);

int nic_add_nic_iface(nic_t *nic, nic_interface_t *nic_iface);
int nic_process_intr(nic_t *nic, int discard_check);

nic_interface_t *nic_iface_init();

typedef enum {
	NIC_LIBRARY_EXSITS = 1,
	NIC_LIBRARY_DOESNT_EXIST = 2,
} NIC_LIBRARY_EXIST_T;

NIC_LIBRARY_EXIST_T does_nic_uio_name_exist(char *name,
					    nic_lib_handle_t **handle);
NIC_LIBRARY_EXIST_T does_nic_library_exist(char *name,
					   nic_lib_handle_t **handle);

/*******************************************************************************
 *  Packet management utility functions
 ******************************************************************************/
struct packet *get_next_tx_packet(nic_t *nic);
struct packet *get_next_free_packet(nic_t *nic);
void put_packet_in_tx_queue(struct packet *pkt, nic_t *nic);
void put_packet_in_free_queue(struct packet *pkt, nic_t *nic);

int unload_all_nic_libraries();
void nic_close(nic_t *nic, NIC_SHUTDOWN_T graceful, int clean);

/*  Use this function to fill in minor number and uio, and eth names */
int nic_fill_name(nic_t *nic);

int enable_multicast(nic_t *nic);
int disable_multicast(nic_t *nic);

void nic_set_all_nic_iface_mac_to_parent(nic_t *nic);
int find_nic_lib_using_pci_id(uint32_t vendor, uint32_t device,
			      uint32_t subvendor, uint32_t subdevice,
			      nic_lib_handle_t **handle,
			      struct pci_device_id **pci_entry);

void *nic_loop(void *arg);

int nic_packet_capture(struct nic *, struct packet *pkt);

int process_packets(nic_t *nic,
		    struct timer *periodic_timer,
		    struct timer *arp_timer, nic_interface_t *nic_iface);

void prepare_ustack(nic_t *nic,
		    nic_interface_t *nic_iface,
		    struct uip_stack *ustack, struct packet *pkt);

void prepare_ipv4_packet(nic_t *nic,
			 nic_interface_t *nic_iface,
			 struct uip_stack *ustack, struct packet *pkt);

void prepare_ipv6_packet(nic_t *nic,
			 nic_interface_t *nic_iface,
			 struct uip_stack *ustack, struct packet *pkt);

#endif /* __NIC_H__ */
