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
 * nic_vlan.c - uIP user space stack VLAN utilities
 *
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/stat.h>

#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "logger.h"
#include "nic.h"
#include "nic_utils.h"
#include "nic_vlan.h"

/*******************************************************************************
 * Constants
 ******************************************************************************/
#define PFX "vlan"

static const char proc_vlan_config_path[] = "/proc/net/vlan/config";

/*******************************************************************************
 * Resolving Found VLAN's for CNIC
 ******************************************************************************/
int init_vlan_found_handle(struct vlan_found_handle *found_handle,
			   struct vlan_handle *handle)
{
	memset(found_handle, 0, sizeof(*found_handle));

	found_handle->entries = malloc(found_handle->num_of_entries *
				       sizeof(struct vlan_found_entry));
	if (found_handle->entries == NULL) {
		LOG_ERR("Could not allocate space for found entries");
		return -ENOMEM;
	}

	found_handle->handle = handle;
	found_handle->num_of_entries = handle->num_of_entries;

	memset(found_handle->entries, 0, found_handle->num_of_entries *
	       sizeof(struct vlan_found_entry));

	handle->outstanding_found_handles++;

	return 0;
}

void release_vlan_found_handle(struct vlan_found_handle *found_handle)
{
	if (found_handle->entries != NULL) {
		free(found_handle->entries);
		found_handle->entries = NULL;
	}

	found_handle->num_of_entries = 0;

	found_handle->handle->outstanding_found_handles--;

	found_handle->handle = NULL;

}

/*******************************************************************************
 * Resolving VLAN's for CNIC
 ******************************************************************************/
/**
 *  init_vlan_handle() - Used to initialize struct ipv4_route_handle so
 *                            that is can be used
 *  @param handle - Pointer to struct ipv4_route_handle to initialize
 *  @return 0 on success and <0 on failure
 */
void init_vlan_table(struct vlan_handle *handle)
{
	handle->entries = NULL;
	handle->num_of_entries = 0;
}

/**
 *  parse_vlan_table() - Given the raw dump of a Linux vlan table, this
 *                       function will parse the into entries held by
 *                       struct vlan_handle
 *  @param handle - struct vlan_handle used to hold the parsed contents
 *  @param raw    - buffer to parse the contents from
 *  @param raw_size  - size of the buffer in bytes
 *  @return 0 on success, <0 on failure
 */
int parse_vlan_table(struct vlan_handle *handle, char *raw, uint32_t raw_size)
{
	FILE *fp;
	int i;
	char *token;
	size_t size;
	int rc;

	token = raw;

	/*  determine the number of entries */
	while (*token != '\0') {
		if (*token == '\n')
			handle->num_of_entries++;

		token++;
	}

	/*  There are 2 lines which describe the vlan table
	 *  This lines need to be skipped with counting */
	handle->num_of_entries -= 2;

	LOG_INFO("Number of vlan entries: %d", handle->num_of_entries);

	size = handle->num_of_entries * sizeof(struct vlan_entry);
	handle->entries = malloc(size);
	if (handle->entries == NULL) {
		LOG_ERR
		    ("Couldn't malloc space to parse vlan table. entires: %d "
		     "size: %d",
		     handle->num_of_entries, size);
		return -ENOMEM;
	}

	fp = fmemopen(raw, raw_size, "r");
	if (fp == NULL) {
		LOG_ERR("Could not open raw dump of vlan table");
		rc = errno;
		goto fmemopen_error;
	}

	if (fscanf(fp, "%*[^\n]\n") < 0) {	/* Skip the first line. */
		LOG_ERR("Empty or missing line, or read error");
		rc = -EIO;
		goto error;
	}

	if (fscanf(fp, "%*[^\n]\n") < 0) {	/* Skip the second line. */
		LOG_ERR("Empty or missing line, or read error");
		rc = -EIO;
		goto error;
	}

	i = 0;
	/*  Time to parse the routing table */
	while (1) {
		struct vlan_entry *entry = &handle->entries[i];
		int r;

		r = fscanf(fp, "%15s |%hu |%15s",
			   entry->vlan_iface_name,
			   &entry->vlan_id, entry->phy_iface_name);
		if (r != 3) {
			if (feof(fp)) {	/* EOF with no (nonspace) chars read. */
				break;
			}

			LOG_WARN("Parsing error: parsed %d elements", r);
			break;
		}

		i++;

		LOG_DEBUG("Vlan %d: vlan iface:%s vlan id:%d phys iface:%s",
			  i,
			  entry->vlan_iface_name,
			  entry->vlan_id, entry->phy_iface_name);
	}

	fclose(fp);

	return 0;

error:
	fclose(fp);

fmemopen_error:
	if (handle->entries != NULL)
		free(handle->entries);

	return rc;
}

/**
 *  capture_vlan_table() - This function will snapshot the Linux vlan
 *                         routing table for further processing
 *  @param handle - struct vlan_handle used to hold the routing context
 *  @return 0 on success, <0 on failure
 */
int capture_vlan_table(struct vlan_handle *handle)
{
	char *raw = NULL;
	uint32_t raw_size = 0;
	int rc;

	rc = capture_file(&raw, &raw_size, proc_vlan_config_path);
	if (rc != 0)
		goto error;

	rc = parse_vlan_table(handle, raw, raw_size);
	if (rc != 0)
		goto error;

error:
	if (raw != NULL)
		free(raw);

	return rc;
}

/**
 *  release_vlan_table() - This function will free all resources used by
 *                         the handle
 *  @param handle -  struct vlan_handle used to hold the routing context
 */
void release_vlan_table(struct vlan_handle *handle)
{
	if (handle->entries != NULL) {
		free(handle->entries);
		handle->entries = NULL;
	}

	handle->num_of_entries = 0;
}

/**
 *  find_phy_using_vlan_interface() - Given the interface name determine VLAN
 *      tag ID to match either the physical or VLAN interface name
 *  @param vlan_iface_name - VLAN interface used to find the physical
 *                           interface
 *  @param phy_iface_name - returned value is the physical interface name
 *  @param vlan_id - returned value is the VLAN id
 *  @return 1 is returned if the interface is a VLAN, 0 if the interface is not
 *          <0 is returned if there is an error
 */
int find_phy_using_vlan_interface(struct vlan_handle *handle,
				  char *vlan_iface_name,
				  char **phy_iface_name, uint16_t *vlan_id)
{
	int i, rc = 0;

	for (i = 0; i < handle->num_of_entries; i++) {
		struct vlan_entry *entry = &handle->entries[i];

		/*  Compare VLAN interface names to find a match */
		if (strcmp(entry->vlan_iface_name, vlan_iface_name) == 0) {
			*phy_iface_name = entry->phy_iface_name;
			*vlan_id = entry->vlan_id;
			rc = 1;
			break;
		}
	}

	return rc;
}

/**
 *  find_vlans_using_phy_interface() - Given the physical interface name this
 *      function will determine the VLAN interface name and VLAN ID
 *  @param iface_name - physical interface used to find the vlan interface
 *  @param vlan_iface_name - returned value is the VLAN interface name
 *  @return The number of VLAN interfaces found
 */
int find_vlans_using_phy_interface(struct vlan_handle *handle,
				   struct vlan_found_handle *found_handle,
				   char *phy_iface_name)
{
	int i, num_found = 0;

	for (i = 0; i < handle->num_of_entries; i++) {
		struct vlan_entry *entry = &handle->entries[i];

		/*  Compare interface names to find a match */
		if (strcmp(entry->phy_iface_name, phy_iface_name) == 0) {
			found_handle->entries[i].found = VLAN_ENTRY_FOUND;
			num_found++;
		}
	}

	return num_found;
}

/**
 *  valid_vlan() - determine if the vlan value which is passed is valid
 *  @param vlan - vlan value to test
 *  @return 0 - not valid, 1 - valid
 */
int valid_vlan(short int vlan)
{
	/* Allow vlan 1 to connect */
	if (vlan > 0 && vlan < 4095)
		return 1;

	return 0;
}
