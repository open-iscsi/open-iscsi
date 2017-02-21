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
 * nic_util.h - NIC utility functions
 *
 */
#ifndef __NIC_UTILS_H__
#define __NIC_UTILS_H__

#include "nic.h"

/******************************************************************************
 * Function Prototype
 ******************************************************************************/
int manually_trigger_uio_event(nic_t *nic, int uio_minor);

int nic_discover_iscsi_hosts();

int enable_mutlicast(nic_t *nic);
int disable_mutlicast(nic_t *nic);

int from_netdev_name_find_nic(char *interface_name, nic_t **nic);

int from_host_no_find_associated_eth_device(int host_no, nic_t **nic);

int from_phys_name_find_assoicated_uio_device(nic_t *nic);

int nic_queue_tx_packet(nic_t *nic,
			nic_interface_t *nic_iface, packet_t *pkt);

packet_t *nic_dequeue_tx_packet(nic_t *nic);

void nic_fill_ethernet_header(nic_interface_t *nic_iface,
			      void *data,
			      void *src_addr, void *dest_addr,
			      int *pkt_size, void **start_addr,
			      uint16_t ether_type);

struct nic_interface *nic_find_nic_iface(nic_t *nic, uint16_t protocol,
					 uint16_t vlan_id, int iface_num,
					 int request_type);
void set_nic_iface(nic_t *nic, nic_interface_t *nic_iface);

void persist_all_nic_iface(nic_t *nic);

int add_vlan_interfaces(nic_t *nic);

int nic_verify_uio_sysfs_name(nic_t *nic);
void cnic_get_sysfs_pci_resource_path(nic_t *nic, int resc_no,
				      char *sys_path, size_t size);
void nic_close_all();
void nic_remove_all();

int detemine_initial_uio_events(nic_t *nic, uint32_t *num_of_events);

uint32_t calculate_default_netmask(uint32_t ip_addr);

void prepare_nic_thread(nic_t *nic);
void prepare_library(nic_t *nic);

int nic_enable(nic_t *nic);
void nic_disable(nic_t *nic, int going_down);

void dump_packet_to_log(struct nic_interface *iface,
			uint8_t *buf, uint16_t buf_len);

int determine_file_size_read(const char *filepath);
int capture_file(char **raw, uint32_t *raw_size, const char *path);

int get_iscsi_transport_handle(nic_t *nic, uint64_t *handle);

#endif /* __NIC_UTILS_H__ */
