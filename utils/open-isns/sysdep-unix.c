/*
 * System dependent stuff
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#include <net/if.h>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>
#include "isns.h"
#include "util.h"

int isns_get_nr_portals(void)
{
	char		buffer[8192], *end, *ptr;
	struct ifconf	ifc;
	unsigned int	nportals = 0;
	int		fd = -1;

	if ((fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		isns_error("%s: no socket - %m\n", __FUNCTION__);
		return 0;
	}

	ifc.ifc_buf = buffer;
	ifc.ifc_len = sizeof(buffer);
	if (ioctl(fd, SIOCGIFCONF, &ifc) < 0) {
		isns_error("ioctl(SIOCGIFCONF): %m\n");
		goto out;
	}

	ptr = buffer;
	end = buffer + ifc.ifc_len;
	while (ptr < end) {
		struct ifreq	ifr;
		struct sockaddr_storage ifaddr;
		int		ifflags;

		memcpy(&ifr, ptr, sizeof(ifr));
		ptr += sizeof(ifr);

		/* Get the interface addr */
		memcpy(&ifaddr, &ifr.ifr_addr, sizeof(ifr.ifr_addr));

		if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
			isns_error("ioctl(%s, SIOCGIFFLAGS): %m\n",
					ifr.ifr_name);
			continue;
		}
		ifflags = ifr.ifr_flags;

		if ((ifflags & IFF_UP) == 0)
			continue;
		if ((ifflags & IFF_LOOPBACK) != 0)
			continue;

		if (ifaddr.ss_family == AF_INET6 || ifaddr.ss_family == AF_INET)
			nportals++;
	}

out:
	if (fd >= 0)
		close(fd);
	return nportals;
}

int
isns_enumerate_portals(isns_portal_info_t *result, unsigned int max)
{
	char		buffer[8192], *end, *ptr;
	struct ifconf	ifc;
	unsigned int	nportals = 0;
	int		fd = -1;

	if ((fd = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
		isns_error("%s: no socket - %m\n", __FUNCTION__);
		return 0;
	}

	ifc.ifc_buf = buffer;
	ifc.ifc_len = sizeof(buffer);
	if (ioctl(fd, SIOCGIFCONF, &ifc) < 0) {
		isns_error("ioctl(SIOCGIFCONF): %m\n");
		goto out;
	}

	ptr = buffer;
	end = buffer + ifc.ifc_len;
	while (ptr < end) {
		struct ifreq	ifr;
		struct sockaddr_storage ifaddr;
		isns_portal_info_t portal;
		int		ifflags;

		memcpy(&ifr, ptr, sizeof(ifr));
		ptr += sizeof(ifr);

		/* Get the interface addr */
		memcpy(&ifaddr, &ifr.ifr_addr, sizeof(ifr.ifr_addr));

		if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
			isns_error("ioctl(%s, SIOCGIFFLAGS): %m\n",
					ifr.ifr_name);
			continue;
		}
		ifflags = ifr.ifr_flags;

		if ((ifflags & IFF_UP) == 0)
			continue;
		if ((ifflags & IFF_LOOPBACK) != 0)
			continue;

		if (!isns_portal_from_sockaddr(&portal, &ifaddr))
			continue;

		isns_debug_socket("Got interface %u: %s %s\n",
				nportals, ifr.ifr_name,
				isns_portal_string(&portal));
		if (nportals < max)
			result[nportals++] = portal;
	}

out:
	if (fd >= 0)
		close(fd);
	return nportals;
}

int
isns_portal_from_sockaddr(isns_portal_info_t *portal,
		const struct sockaddr_storage *addr)
{
	struct sockaddr_in6 *six;
	struct sockaddr_in *sin;

	memset(portal, 0, sizeof(*portal));

	/* May have to convert AF_INET to AF_INET6 */
	six = &portal->addr;
	switch (addr->ss_family) {
	case AF_INET6:
		memcpy(six, addr, sizeof(*six));
		break;

	case AF_INET:
		sin = (struct sockaddr_in *) addr;
		six->sin6_family = AF_INET6;
		six->sin6_addr.s6_addr32[3] = sin->sin_addr.s_addr;
		six->sin6_port = sin->sin_port;
		break;

	default:
		return 0;
	}

	return 1;
}

int
isns_portal_to_sockaddr(const isns_portal_info_t *portal,
		struct sockaddr_storage *addr)
{
	const struct sockaddr_in6 *six = &portal->addr;
	struct sockaddr_in *sin;

	/* Check if this is really a v4 address is disguise.
	 * If so, explicitly use an AF_INET socket - the
	 * stack may not support IPv6.
	 */
	if (IN6_IS_ADDR_V4MAPPED(&six->sin6_addr)
	 || IN6_IS_ADDR_V4COMPAT(&six->sin6_addr)) {
		sin = (struct sockaddr_in *) addr;

		memset(sin, 0, sizeof(*sin));
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = six->sin6_addr.s6_addr32[3];
		sin->sin_port = six->sin6_port;

		return sizeof(*sin);
	}
	
	/* This is the genuine article */
	memcpy(addr, six, sizeof(*six));
	return sizeof(*six);
}
