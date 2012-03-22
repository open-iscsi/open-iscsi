/*
 * iSCSI host helpers
 *
 * Copyright (C) 2008 Mike Christie
 * Copyright (C) 2008 Red Hat, Inc. All rights reserved.
 * maintained by open-iscsi@@googlegroups.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * See the file COPYING included with this distribution for more details.
 */
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "list.h"
#include "iscsi_util.h"
#include "log.h"
#include "iscsi_sysfs.h"
#include "version.h"
#include "iscsi_settings.h"
#include "mgmt_ipc.h"
#include "host.h"
#include "session_info.h"
#include "transport.h"
#include "initiator.h"
#include "iface.h"
#include "iscsi_err.h"

static int match_host_to_session(void *data, struct session_info *info)
{
	uint32_t host_no = *(uint32_t *) data;
	uint32_t info_host_no;
	int rc;

	info_host_no = iscsi_sysfs_get_host_no_from_sid(info->sid, &rc);
	if (rc) {
		log_error("could not get host_no for session%d err %d.",
			  info->sid, rc);
		return 0;
	}

	return host_no == info_host_no;
}

static void print_host_info(struct iface_rec *iface, char *prefix)
{
	if (strlen(iface->transport_name))
		printf("%sTransport: %s\n", prefix,
		      iface->transport_name);
	else
		printf("%sTransport: %s\n", prefix, UNKNOWN_VALUE);

	if (strlen(iface->iname))
		printf("%sInitiatorname: %s\n", prefix,
		      iface->iname);
	else
		printf("%sInitiatorname: %s\n", prefix, UNKNOWN_VALUE);

	if (!strlen(iface->ipaddress))
		printf("%sIPaddress: %s\n", prefix, UNKNOWN_VALUE);
	else if (strchr(iface->ipaddress, '.'))
		printf("%sIPaddress: %s\n", prefix, iface->ipaddress);
	else
		printf("%sIPaddress: [%s]\n", prefix, iface->ipaddress);

	if (strlen(iface->hwaddress))
		printf("%sHWaddress: %s\n", prefix, iface->hwaddress);
	else
		printf("%sHWaddress: %s\n", prefix, UNKNOWN_VALUE);

	if (strlen(iface->netdev))
		printf("%sNetdev: %s\n", prefix, iface->netdev);
	else
		printf("%sNetdev: %s\n", prefix, UNKNOWN_VALUE);
}

static int host_info_print_flat(void *data, struct host_info *hinfo)
{
	struct iface_rec *iface = &hinfo->iface;

	if (strlen(iface->transport_name))
		printf("%s: ", iface->transport_name);
	else
		printf("%s: ", UNKNOWN_VALUE);

	printf("[%u] ", hinfo->host_no);

	if (!strlen(iface->ipaddress))
		printf("%s,", UNKNOWN_VALUE);
	else if (strchr(iface->ipaddress, '.'))
		printf("%s,", iface->ipaddress);
	else
		printf("[%s],", iface->ipaddress);

	if (strlen(iface->hwaddress))
		printf("[%s],", iface->hwaddress);
	else
		printf("[%s],", UNKNOWN_VALUE);

	if (strlen(iface->netdev))
		printf("%s ", iface->netdev);
	else
		printf("%s ", UNKNOWN_VALUE);

	if (strlen(iface->iname))
		printf("%s\n", iface->iname);
	else
		printf("%s\n", UNKNOWN_VALUE);
	return 0;
}

static int print_host_iface(void *data, struct iface_rec *iface)
{
	char *prefix = data;

	printf("%s**********\n", prefix);
	printf("%sInterface:\n", prefix);
	printf("%s**********\n", prefix);

	printf("%sKernel Name: %s\n", prefix, iface->name);

	if (!strlen(iface->ipaddress))
		printf("%sIPaddress: %s\n", prefix, UNKNOWN_VALUE);
	else if (strchr(iface->ipaddress, '.')) {
		printf("%sIPaddress: %s\n", prefix, iface->ipaddress);

		if (!strlen(iface->gateway))
			printf("%sGateway: %s\n", prefix, UNKNOWN_VALUE);
		else
			printf("%sGateway: %s\n", prefix, iface->gateway);
		if (!strlen(iface->subnet_mask))
			printf("%sSubnet: %s\n", prefix, UNKNOWN_VALUE);
		else
			printf("%sSubnet: %s\n", prefix, iface->subnet_mask);
		if (!strlen(iface->bootproto))
			printf("%sBootProto: %s\n", prefix, UNKNOWN_VALUE);
		else
			printf("%sBootProto: %s\n", prefix, iface->bootproto);
	} else {
		printf("%sIPaddress: [%s]\n", prefix, iface->ipaddress);

		if (!strlen(iface->ipv6_autocfg))
			printf("%sIPaddress Autocfg: %s\n", prefix,
			       UNKNOWN_VALUE);
		else
			printf("%sIPaddress Autocfg: %s\n", prefix,
			       iface->ipv6_autocfg);
		if (!strlen(iface->ipv6_linklocal))
			printf("%sLink Local Address: %s\n", prefix,
			       UNKNOWN_VALUE);
		else
			printf("%sLink Local Address: [%s]\n", prefix,
			       iface->ipv6_linklocal);
		if (!strlen(iface->linklocal_autocfg))
			printf("%sLink Local Autocfg: %s\n", prefix,
			       UNKNOWN_VALUE);
		else
			printf("%sLink Local Autocfg: %s\n", prefix,
			       iface->linklocal_autocfg);
		if (!strlen(iface->ipv6_router))
			printf("%sRouter Address: %s\n", prefix,
			      UNKNOWN_VALUE);
		else
			printf("%sRouter Address: [%s]\n", prefix,
			       iface->ipv6_router);
	}

	if (!strlen(iface->port_state))
		printf("%sPort State: %s\n", prefix, UNKNOWN_VALUE);
	else
		printf("%sPort State: %s\n", prefix, iface->port_state);

	if (!strlen(iface->port_speed))
		printf("%sPort Speed: %s\n", prefix, UNKNOWN_VALUE);
	else
		printf("%sPort Speed: %s\n", prefix, iface->port_speed);

	if (!iface->port)
		printf("%sPort: %s\n", prefix, UNKNOWN_VALUE);
	else
		printf("%sPort: %u\n", prefix, iface->port);

	if (!iface->mtu)
		printf("%sMTU: %s\n", prefix, UNKNOWN_VALUE);
	else
		printf("%sMTU: %u\n", prefix, iface->mtu);

	if (iface->vlan_id == UINT16_MAX)
		printf("%sVLAN ID: %s\n", prefix, UNKNOWN_VALUE);
	else
		printf("%sVLAN ID: %u\n", prefix, iface->vlan_id);

	if (iface->vlan_priority == UINT8_MAX)
		printf("%sVLAN priority: %s\n", prefix, UNKNOWN_VALUE);
	else
		printf("%sVLAN priority: %u\n", prefix, iface->vlan_priority);
	return 0;
}

static void print_host_ifaces(struct host_info *hinfo, char *prefix)
{
	int nr_found;

	iscsi_sysfs_for_each_iface_on_host(prefix, hinfo->host_no, &nr_found,
					   print_host_iface);
}

static int host_info_print_tree(void *data, struct host_info *hinfo)
{
	struct list_head sessions;
	struct session_link_info link_info;
	int err, num_found = 0;
	unsigned int session_info_flags = *(unsigned int *)data;
	char state[SCSI_MAX_STATE_VALUE];

	INIT_LIST_HEAD(&sessions);


	printf("Host Number: %u\n", hinfo->host_no);
	if (!iscsi_sysfs_get_host_state(state, hinfo->host_no))
		printf("\tState: %s\n", state);
	else
		printf("\tState: Unknown\n");
	print_host_info(&hinfo->iface, "\t");

	print_host_ifaces(hinfo, "\t");

	if (!session_info_flags)
		return 0;

	link_info.list = &sessions;
	link_info.match_fn = match_host_to_session;
	link_info.data = &hinfo->host_no;

	err = iscsi_sysfs_for_each_session(&link_info, &num_found,
					   session_info_create_list);
	if (err || !num_found)
		return 0;

	printf("\t*********\n");
	printf("\tSessions:\n");
	printf("\t*********\n");

	session_info_print_tree(&sessions, "\t", session_info_flags, 0);
	session_info_free_list(&sessions);
	return 0;
}

int host_info_print(int info_level, uint32_t host_no)
{
	int num_found = 0, err = 0;
	char *version;
	unsigned int flags = 0;

	switch (info_level) {
	case 0:
	case -1:
		err = iscsi_sysfs_for_each_host(NULL, &num_found,
						host_info_print_flat);
		break;
	case 4:
		version = iscsi_sysfs_get_iscsi_kernel_version();
		if (version) {
			printf("iSCSI Transport Class version %s\n",
			       version);
			printf("version %s\n", ISCSI_VERSION_STR);
		}

		flags |= SESSION_INFO_SCSI_DEVS;
		/* fall through */
	case 3:
		flags |= SESSION_INFO_ISCSI_PARAMS;
		/* fall through */
	case 2:
		flags |= SESSION_INFO_ISCSI_STATE | SESSION_INFO_IFACE;
		/* fall through */
	case 1:
		if (host_no != -1) {
			struct host_info hinfo;

			memset(&hinfo, 0, sizeof(struct host_info));
			hinfo.host_no = host_no;
			iscsi_sysfs_get_hostinfo_by_host_no(&hinfo);
			host_info_print_tree(&flags, &hinfo);
			num_found = 1;
			break;
		}

		transport_probe_for_offload();
		err = iscsi_sysfs_for_each_host(&flags, &num_found,
						host_info_print_tree);
		break;
	default:
		log_error("Invalid info level %d. Try 0 - 4.", info_level);
		return ISCSI_ERR_INVAL;
	}

	if (err) {
		log_error("Can not get list of iSCSI hosts: %s",
			  iscsi_err_to_str(err));
		return err;
	} else if (!num_found) {
		log_error("No iSCSI hosts.");
		return ISCSI_ERR_NO_OBJS_FOUND;
	}
	return 0;
}
