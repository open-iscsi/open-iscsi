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
 * nic_vlan.h - uIP user space stack VLAN utilities
 *
 */
#ifndef __NIC_VLAN_H__
#define __NIC_VLAN_H__

#include <sys/types.h>

/*  Used to hold entries in the vlan table */
struct vlan_entry {
	char vlan_iface_name[16];
	char phy_iface_name[16];
	uint16_t vlan_id;
};

struct vlan_handle {
	struct vlan_entry *entries;
	uint32_t num_of_entries;

	uint32_t outstanding_found_handles;
};

struct vlan_found_entry {
#define VLAN_ENTRY_FOUND	1
#define VLAN_ENTRY_NOT_FOUND	0
	uint8_t found;
};

struct vlan_found_handle {
	struct vlan_handle *handle;
	uint32_t num_of_entries;
	struct vlan_found_entry *entries;
};

/*******************************************************************************
 * Function Prototypes
 ******************************************************************************/
void init_vlan_table(struct vlan_handle *handle);
int capture_vlan_table(struct vlan_handle *handle);
void release_vlan_table(struct vlan_handle *handle);

int find_phy_using_vlan_interface(struct vlan_handle *handle,
				  char *vlan_iface_name,
				  char **phy_iface_name, uint16_t *vlan_id);
int find_vlans_using_phy_interface(struct vlan_handle *handle,
				   struct vlan_found_handle *found_handle,
				   char *phy_iface_name);

int init_vlan_found_handle(struct vlan_found_handle *found_handle,
			   struct vlan_handle *handle);
void release_vlan_found_handle(struct vlan_found_handle *found_handle);

int valid_vlan(short int vlan);
#endif /* __NIC_VLAN_H__ */
