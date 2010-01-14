/*
 * net helpers
 *
 * Copyright (C) 2010 Mike Christie
 * Copyright (C) 2010 Red Hat, Inc. All rights reserved.
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
 */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <net/if.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include "sysdeps.h"
#include "ethtool-copy.h"
#include "iscsi_net_util.h"
#include "log.h"

/**
 * net_get_dev_from_hwaddress - given a hwaddress return the ethX
 * @hwaddress: hw address no larger than ISCSI_HWADDRESS_BUF_SIZE
 * @netdev: buffer of IFNAMSIZ size that will hold the ethX
 *
 * Does not support interfaces like a bond or alias because
 * multiple interfaces will have the same hwaddress.
 */
int net_get_dev_from_hwaddress(char *hwaddress, char *netdev)
{
	struct if_nameindex *ifni;
	struct ifreq if_hwaddr;
	int found = 0, sockfd, i = 0;
	unsigned char *hwaddr;
	char tmp_hwaddress[ISCSI_HWADDRESS_BUF_SIZE];

	ifni = if_nameindex();
	if (ifni == NULL) {
		log_error("Could not match hwaddress %s to netdev. "
			  "getifaddrs failed %d", hwaddress, errno);
		return errno;
	}

	/* Open a basic socket. */
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		log_error("Could not open socket for ioctl.");
		goto free_ifni;
	}

	for (i = 0; ifni[i].if_index && ifni[i].if_name; i++) {
		struct if_nameindex *n = &ifni[i];

		strlcpy(if_hwaddr.ifr_name, n->if_name, IFNAMSIZ);
		if (ioctl(sockfd, SIOCGIFHWADDR, &if_hwaddr) < 0) {
			log_error("Could not match %s to netdevice.",
				  hwaddress);
			continue;
		}

		/* check for ARPHRD_ETHER (ethernet) */
		if (if_hwaddr.ifr_hwaddr.sa_family != 1)
			continue;
		hwaddr = (unsigned char *)if_hwaddr.ifr_hwaddr.sa_data;

		memset(tmp_hwaddress, 0, ISCSI_HWADDRESS_BUF_SIZE);
		/* TODO should look and covert so we do not need tmp buf */
		sprintf(tmp_hwaddress, "%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x",
			hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3],
			hwaddr[4], hwaddr[5]);
		log_debug(4, "Found hardware address %s", tmp_hwaddress);
		if (!strcasecmp(tmp_hwaddress, hwaddress)) {
			log_debug(4, "Matches %s to %s", hwaddress,
				  n->if_name);
			memset(netdev, 0, IFNAMSIZ); 
			strlcpy(netdev, n->if_name, IFNAMSIZ);
			found = 1;
			break;
		}
	}

	close(sockfd);
free_ifni:
	if_freenameindex(ifni);
	if (!found)
		return ENODEV;
	return 0;
}


