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
 * iscsi_ipc.c - Generic NIC management/utility functions
 *
 */

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>

#define PFX "iscsi_ipc "

/* TODO fix me */
#define IFNAMSIZ 15

#include "nic.h"
#include "nic_utils.h"
#include "nic_vlan.h"
#include "options.h"
#include "mgmt_ipc.h"
#include "iscsid_ipc.h"
#include "uip.h"
#include "uip_mgmt_ipc.h"

#include "logger.h"
#include "uip.h"
#include "ping.h"

/*  private iscsid options stucture */
struct iscsid_options {
	int fd;
	pthread_t thread;
};

struct iface_rec_decode {
	/* General */
	int32_t			iface_num;
	uint32_t		ip_type;

	/* IPv4 */
	struct in_addr		ipv4_addr;
	struct in_addr		ipv4_subnet_mask;
	struct in_addr		ipv4_gateway;

	/* IPv6 */
	struct in6_addr		ipv6_addr;
	struct in6_addr		ipv6_subnet_mask;
	uint32_t		prefix_len;
	struct in6_addr		ipv6_linklocal;
	struct in6_addr		ipv6_router;

	uint8_t			ipv6_autocfg;
	uint8_t                 linklocal_autocfg;
	uint8_t                 router_autocfg;

	uint8_t			vlan_state;
	uint8_t			vlan_priority;
	uint16_t		vlan_id;

#define MIN_MTU_SUPPORT		46
#define MAX_MTU_SUPPORT		9000
	uint16_t		mtu;
};


/******************************************************************************
 *  iscsid_ipc Constants
 *****************************************************************************/
static const char uio_udev_path_template[] = "/dev/uio%d";

/******************************************************************************
 *  Globals
 *****************************************************************************/
static struct iscsid_options iscsid_opts = {
	.fd = INVALID_FD,
	.thread = INVALID_THREAD,
};

/******************************************************************************
 *  iscsid Functions
 *****************************************************************************/

static void *enable_nic_thread(void *data)
{
	nic_t *nic = (nic_t *) data;

	prepare_nic_thread(nic);
	LOG_INFO(PFX "%s: started NIC enable thread state: 0x%x",
		 nic->log_name, nic->state)

	/*  Enable the NIC */
	nic_enable(nic);

	nic->enable_thread = INVALID_THREAD;

	pthread_exit(NULL);
}

static int decode_cidr(char *in_ipaddr_str, struct iface_rec_decode *ird)
{
	int rc = 0, i;
	char *tmp, *tok;
	char ipaddr_str[NI_MAXHOST];
	char str[INET6_ADDRSTRLEN];
	int keepbits = 0;
	struct in_addr ia;
	struct in6_addr ia6;

	if (strlen(in_ipaddr_str) > NI_MAXHOST)
		strncpy(ipaddr_str, in_ipaddr_str, NI_MAXHOST);
	else
		strcpy(ipaddr_str, in_ipaddr_str);

	/* Find the CIDR if any */
	tmp = strchr(ipaddr_str, '/');
	if (tmp) {
		/* CIDR found, now decode, tmpbuf = ip, tmp = netmask */
		tmp = ipaddr_str;
		tok = strsep(&tmp, "/");
		LOG_INFO(PFX "in cidr: bitmask '%s' ip '%s'", tmp, tok);
		keepbits = atoi(tmp);
		strcpy(ipaddr_str, tok);
	}

	/*  Determine if the IP address passed from the iface file is
	 *  an IPv4 or IPv6 address */
	rc = inet_pton(AF_INET, ipaddr_str, &ird->ipv6_addr);
	if (rc == 0) {
		/* Test to determine if the addres is an IPv6 address */
		rc = inet_pton(AF_INET6, ipaddr_str, &ird->ipv6_addr);
		if (rc == 0) {
			LOG_ERR(PFX "Could not parse IP address: '%s'",
				ipaddr_str);
			goto out;
		}
		ird->ip_type = AF_INET6;
		if (keepbits > 128) {
			LOG_ERR(PFX "CIDR netmask > 128 for IPv6: %d(%s)",
				keepbits, tmp);
			goto out;
		}
		if (!keepbits) {
			/* Default prefix mask to 64 */
			memcpy(&ird->ipv6_subnet_mask.s6_addr, all_zeroes_addr6,
			       sizeof(struct in6_addr));
			ird->prefix_len = 64;
			for (i = 0; i < 2; i++)
				ird->ipv6_subnet_mask.s6_addr32[i] = 0xffffffff;
			goto out;
		}
		ird->prefix_len = keepbits;
		memcpy(&ia6.s6_addr, all_zeroes_addr6, sizeof(struct in6_addr));
		for (i = 0; i < 4; i++) {
			if (keepbits < 32) {
				ia6.s6_addr32[i] = keepbits > 0 ?
				    0x00 - (1 << (32 - keepbits)) : 0;
				ia6.s6_addr32[i] = htonl(ia6.s6_addr32[i]);
				break;
			} else
				ia6.s6_addr32[i] = 0xFFFFFFFF;
			keepbits -= 32;
		}
		ird->ipv6_subnet_mask = ia6;
		if (inet_ntop(AF_INET6, &ia6, str, sizeof(str)))
			LOG_INFO(PFX "Using netmask: %s", str);
	} else {
		ird->ip_type = AF_INET;
		rc = inet_pton(AF_INET, ipaddr_str, &ird->ipv4_addr);

		if (keepbits > 32) {
			LOG_ERR(PFX "CIDR netmask > 32 for IPv4: %d(%s)",
				keepbits, tmp);
			goto out;
		}
		ia.s_addr = keepbits > 0 ? 0x00 - (1 << (32 - keepbits)) : 0;
		ird->ipv4_subnet_mask.s_addr = htonl(ia.s_addr);
		LOG_INFO(PFX "Using netmask: %s",
			 inet_ntoa(ird->ipv4_subnet_mask));
	}
out:
	return rc;
}

static int decode_iface(struct iface_rec_decode *ird, struct iface_rec *rec)
{
	int rc = 0;
	char ipaddr_str[NI_MAXHOST];

	/* Decodes the rec contents */
	memset(ird, 0, sizeof(struct iface_rec_decode));

	/*  Detect for CIDR notation and strip off the netmask if present */
	rc = decode_cidr(rec->ipaddress, ird);
	if (rc && !ird->ip_type) {
		LOG_ERR(PFX "cidr decode err: rc=%d, ip_type=%d",
			rc, ird->ip_type);
		/* Can't decode address, just exit */
		return rc;
	}
	rc = 0;
	ird->iface_num = rec->iface_num;
	ird->vlan_id = rec->vlan_id;
	if (rec->iface_num != IFACE_NUM_INVALID) {
		ird->mtu = rec->mtu;
		if (rec->vlan_id && strcmp(rec->vlan_state, "disable")) {
			ird->vlan_state = 1;
			ird->vlan_priority = rec->vlan_priority;
			ird->vlan_id = rec->vlan_id;
		}
		if (ird->ip_type == AF_INET6) {
			if (!strcmp(rec->ipv6_autocfg, "dhcpv6"))
				ird->ipv6_autocfg = IPV6_AUTOCFG_DHCPV6;
			else if (!strcmp(rec->ipv6_autocfg, "nd"))
				ird->ipv6_autocfg = IPV6_AUTOCFG_ND;
			else
				ird->ipv6_autocfg = IPV6_AUTOCFG_NOTSPEC;

			if (!strcmp(rec->linklocal_autocfg, "auto"))
				ird->linklocal_autocfg = IPV6_LL_AUTOCFG_ON;
			else if (!strcmp(rec->linklocal_autocfg, "off"))
				ird->linklocal_autocfg = IPV6_LL_AUTOCFG_OFF;
			else /* default */
				ird->linklocal_autocfg = IPV6_LL_AUTOCFG_ON;

			if (!strcmp(rec->router_autocfg, "auto"))
				ird->router_autocfg = IPV6_RTR_AUTOCFG_ON;
			else if (!strcmp(rec->router_autocfg, "off"))
				ird->router_autocfg = IPV6_RTR_AUTOCFG_OFF;
			else /* default */
				ird->router_autocfg = IPV6_RTR_AUTOCFG_ON;

			/* Decode the addresses based on the control flags */
			/* For DHCP, ignore the IPv6 addr in the iface */
			if (ird->ipv6_autocfg == IPV6_AUTOCFG_DHCPV6)
				memcpy(&ird->ipv6_addr, all_zeroes_addr6,
				       sizeof(struct in6_addr));
			/* Subnet mask priority: CIDR, then rec */
			if (!ird->ipv6_subnet_mask.s6_addr)
				inet_pton(AF_INET6, rec->subnet_mask,
					  &ird->ipv6_subnet_mask);

			/* For LL on, ignore the IPv6 addr in the iface */
			if (ird->linklocal_autocfg == IPV6_LL_AUTOCFG_OFF) {
				if (strlen(rec->ipv6_linklocal) > NI_MAXHOST)
					strncpy(ipaddr_str, rec->ipv6_linklocal,
						NI_MAXHOST);
				else
					strcpy(ipaddr_str, rec->ipv6_linklocal);
				inet_pton(AF_INET6, ipaddr_str,
					  &ird->ipv6_linklocal);
			}

			/* For RTR on, ignore the IPv6 addr in the iface */
			if (ird->router_autocfg == IPV6_RTR_AUTOCFG_OFF) {
				if (strlen(rec->ipv6_router) > NI_MAXHOST)
					strncpy(ipaddr_str, rec->ipv6_router,
						NI_MAXHOST);
				else
					strcpy(ipaddr_str, rec->ipv6_router);
				inet_pton(AF_INET6, ipaddr_str,
					  &ird->ipv6_router);
			}
		} else {
			/* Subnet mask priority: CIDR, rec, default */
			if (!ird->ipv4_subnet_mask.s_addr)
				inet_pton(AF_INET, rec->subnet_mask,
					  &ird->ipv4_subnet_mask);
			if (!ird->ipv4_subnet_mask.s_addr)
				ird->ipv4_subnet_mask.s_addr =
					calculate_default_netmask(
							ird->ipv4_addr.s_addr);

			if (strlen(rec->gateway) > NI_MAXHOST)
				strncpy(ipaddr_str, rec->gateway, NI_MAXHOST);
			else
				strcpy(ipaddr_str, rec->gateway);
			inet_pton(AF_INET, ipaddr_str, &ird->ipv4_gateway);
		}
	} else {
		ird->ipv6_autocfg = IPV6_AUTOCFG_NOTUSED;
		ird->linklocal_autocfg = IPV6_LL_AUTOCFG_NOTUSED;
		ird->router_autocfg = IPV6_RTR_AUTOCFG_NOTUSED;
	}
	return rc;
}

static void *perform_ping(void *arg)
{
	struct ping_conf *png_c = (struct ping_conf *)arg;
	nic_interface_t *nic_iface = png_c->nic_iface;
	nic_t *nic = nic_iface->parent;
	iscsid_uip_broadcast_t *data;
	struct sockaddr_in *addr;
	struct sockaddr_in6 *addr6;
	uip_ip6addr_t dst_addr;
	int rc = 0;
	int datalen;
	struct timespec ts = {.tv_sec = 5,
			      .tv_nsec = 0};

	data = (iscsid_uip_broadcast_t *)png_c->data;
	datalen = data->u.ping_rec.datalen;

	memset(dst_addr, 0, sizeof(uip_ip6addr_t));
	if (nic_iface->protocol == AF_INET) {
		/* IPv4 */
		addr = (struct sockaddr_in *)&data->u.ping_rec.ipaddr;
		memcpy(dst_addr, &addr->sin_addr.s_addr, sizeof(uip_ip4addr_t));
	} else {
		/* IPv6 */
		addr6 = (struct sockaddr_in6 *)&data->u.ping_rec.ipaddr;
		memcpy(dst_addr, &addr6->sin6_addr.s6_addr,
		       sizeof(uip_ip6addr_t));
	}

	/*  Ensure that the NIC is RUNNING */
	if ((nic->state != NIC_RUNNING) || !(nic->flags & NIC_ENABLED)) {
		pthread_mutex_lock(&nic->nic_mutex);
		rc = pthread_cond_timedwait(&nic->enable_done_cond,
					    &nic->nic_mutex, &ts);
		if ((rc == 0) && (nic->state == NIC_RUNNING)) {
			LOG_DEBUG(PFX "%s: nic running", nic->log_name);
		} else if (rc) {
			LOG_DEBUG(PFX "%s: err %d", nic->log_name, rc);
			rc = -EAGAIN;
		}
		pthread_mutex_unlock(&nic->nic_mutex);
	}

	if (rc || nic->state != NIC_RUNNING) {
		png_c->state = rc;
		goto ping_done;
	}

	ping_init(png_c, dst_addr, nic_iface->protocol, datalen);

	rc = do_ping_from_nic_iface(png_c);
	if (png_c->state == -1)
		png_c->state = rc;

ping_done:
	LOG_INFO(PFX "ping thread end");
	nic->ping_thread = INVALID_THREAD;
	pthread_exit(NULL);
}

static int parse_iface(void *arg, int do_ping)
{
	int rc, i;
	nic_t *nic = NULL;
	nic_interface_t *nic_iface;
	char *transport_name;
	size_t transport_name_size;
	nic_lib_handle_t *handle;
	iscsid_uip_broadcast_t *data;
	char ipv6_buf_str[INET6_ADDRSTRLEN];
	int request_type = 0;
	struct iface_rec *rec;
	struct iface_rec_decode ird;
	struct in_addr src_match, dst_match;
	pthread_attr_t attr;
	struct ping_conf *png_c;

	data = (iscsid_uip_broadcast_t *) arg;
	if (do_ping)
		rec = &data->u.ping_rec.ifrec;
	else
		rec = &data->u.iface_rec.rec;

	LOG_INFO(PFX "Received request for '%s' to set IP address: '%s' "
		 "VLAN: '%d'",
		 rec->netdev,
		 rec->ipaddress,
		 rec->vlan_id);

	rc = decode_iface(&ird, rec);
	if (ird.vlan_id && valid_vlan(ird.vlan_id) == 0) {
		LOG_ERR(PFX "Invalid VLAN tag: %d", ird.vlan_id);
		rc = -EIO;
		goto early_exit;
	}
	if (rc && !ird.ip_type) {
		LOG_ERR(PFX "iface err: rc=%d, ip_type=%d", rc, ird.ip_type);
		goto early_exit;
	}

	for (i = 0; i < 10; i++) {
		struct timespec sleep_req, sleep_rem;

		if (pthread_mutex_trylock(&nic_list_mutex) == 0)
			break;

		sleep_req.tv_sec = 0;
		sleep_req.tv_nsec = 100000;
		nanosleep(&sleep_req, &sleep_rem);
	}

	if (i >= 10) {
		LOG_WARN(PFX "Could not acquire nic_list_mutex lock");
		rc = -EIO;
		goto early_exit;
	}

	/* nic_list_mutex locked */

	/*  Check if we can find the NIC device using the netdev
	 *  name */
	rc = from_netdev_name_find_nic(rec->netdev, &nic);

	if (rc != 0) {
		LOG_WARN(PFX "Couldn't find NIC: %s, creating an instance",
			 rec->netdev);

		nic = nic_init();
		if (nic == NULL) {
			LOG_ERR(PFX "Couldn't allocate space for NIC %s",
				rec->netdev);

			rc = -ENOMEM;
			goto done;
		}

		strncpy(nic->eth_device_name,
			rec->netdev,
			sizeof(nic->eth_device_name));
		nic->config_device_name = nic->eth_device_name;
		nic->log_name = nic->eth_device_name;

		if (nic_fill_name(nic) != 0) {
			free(nic);
			rc = -EIO;
			goto done;
		}

		nic_add(nic);
	} else {
		LOG_INFO(PFX " %s, using existing NIC",
			 rec->netdev);
	}

	pthread_mutex_lock(&nic->nic_mutex);
	if (nic->flags & NIC_GOING_DOWN) {
		pthread_mutex_unlock(&nic->nic_mutex);
		rc = -EIO;
		LOG_INFO(PFX "nic->flags GOING DOWN");
		goto done;
	}

	/*  If we retry too many times allow iscsid to timeout */
	if (nic->pending_count > 1000) {
		nic->pending_count = 0;
		nic->flags &= ~NIC_ENABLED_PENDING;
		pthread_mutex_unlock(&nic->nic_mutex);

		LOG_WARN(PFX "%s: pending count exceeded 1000", nic->log_name);

		rc = 0;
		goto done;
	}

	if (nic->flags & NIC_ENABLED_PENDING) {
		struct timespec sleep_req, sleep_rem;

		nic->pending_count++;
		pthread_mutex_unlock(&nic->nic_mutex);

		sleep_req.tv_sec = 2;
		sleep_req.tv_nsec = 0;
		nanosleep(&sleep_req, &sleep_rem);

		pthread_mutex_lock(&nic->nic_mutex);
		if (!(nic->flags & NIC_ENABLED) ||
		    nic->state != NIC_RUNNING) {
			pthread_mutex_unlock(&nic->nic_mutex);
			LOG_INFO(PFX "%s: enabled pending", nic->log_name);
			rc = -EAGAIN;
			goto done;
		}
	}
	pthread_mutex_unlock(&nic->nic_mutex);

	prepare_library(nic);

	/*  Sanity Check to ensure the transport names are the same */
	handle = nic->nic_library;
	if (handle != NULL) {
		(*handle->ops->lib_ops.get_transport_name) (&transport_name,
							  &transport_name_size);

		if (strncmp(transport_name,
			    rec->transport_name,
			    transport_name_size) != 0) {
			LOG_ERR(PFX "%s Transport name is not equal "
				"expected: %s got: %s",
				nic->log_name,
				rec->transport_name,
				transport_name);
		}
	} else {
		LOG_ERR(PFX "%s Couldn't find nic library ", nic->log_name);
		rc = -EIO;
		goto done;
	}

	LOG_INFO(PFX "%s library set using transport_name %s",
		 nic->log_name, transport_name);

	/*  Determine how to configure the IP address */
	if (ird.ip_type == AF_INET) {
		if (memcmp(&ird.ipv4_addr,
			   all_zeroes_addr4, sizeof(uip_ip4addr_t)) == 0) {
			LOG_INFO(PFX "%s: requesting configuration using DHCP",
				 nic->log_name);
			request_type = IPV4_CONFIG_DHCP;
		} else {
			LOG_INFO(PFX "%s: requesting configuration using "
				 "static IP address", nic->log_name);
			request_type = IPV4_CONFIG_STATIC;
		}
	} else if (ird.ip_type == AF_INET6) {
		/* For the new 872_22, check ipv6_autocfg for DHCPv6 instead */
		switch (ird.ipv6_autocfg) {
		case IPV6_AUTOCFG_DHCPV6:
			request_type = IPV6_CONFIG_DHCP;
			break;
		case IPV6_AUTOCFG_ND:
			request_type = IPV6_CONFIG_STATIC;
			break;
		case IPV6_AUTOCFG_NOTSPEC:
			/* Treat NOTSPEC the same as NOTUSED for now */
		case IPV6_AUTOCFG_NOTUSED:
			/* For 871 */
		default:
			/* Just the IP address to determine */
			if (memcmp(&ird.ipv6_addr,
				   all_zeroes_addr6,
				   sizeof(struct in6_addr)) == 0)
				request_type = IPV6_CONFIG_DHCP;
			else
				request_type = IPV6_CONFIG_STATIC;
		}
	} else {
		LOG_ERR(PFX "%s: unknown ip_type to configure: 0x%x",
			nic->log_name, ird.ip_type);

		rc = -EIO;
		goto done;
	}

	pthread_mutex_lock(&nic->nic_mutex);

	nic_iface = nic_find_nic_iface(nic, ird.ip_type, ird.vlan_id,
				       ird.iface_num, request_type);

	if (nic->flags & NIC_PATHREQ_WAIT) {
		if (!nic_iface ||
		    !(nic_iface->flags & NIC_IFACE_PATHREQ_WAIT)) {
			int pathreq_wait;

			if (nic_iface &&
			    (nic_iface->flags & NIC_IFACE_PATHREQ_WAIT2))
				pathreq_wait = 12;
			else
				pathreq_wait = 10;

			if (nic->pathreq_pending_count < pathreq_wait) {
				struct timespec sleep_req, sleep_rem;

				pthread_mutex_unlock(&nic->nic_mutex);

				nic->pathreq_pending_count++;
				sleep_req.tv_sec = 0;
				sleep_req.tv_nsec = 100000;
				nanosleep(&sleep_req, &sleep_rem);
				/* Somebody else is waiting for PATH_REQ */
				LOG_INFO(PFX "%s: path req pending cnt=%d",
					 nic->log_name,
					 nic->pathreq_pending_count);
				rc = -EAGAIN;
				goto done;
			} else {
				nic->pathreq_pending_count = 0;
				LOG_DEBUG(PFX "%s: path req pending cnt "
					  "exceeded!", nic->log_name);
				/* Allow to fall thru */
			}
		}
	}

	nic->flags |= NIC_PATHREQ_WAIT;

	/* Create the network interface if it doesn't exist */
	if (nic_iface == NULL) {
		LOG_DEBUG(PFX "%s couldn't find interface with "
			  "ip_type: 0x%x creating it",
			  nic->log_name, ird.ip_type);
		nic_iface = nic_iface_init();

		if (nic_iface == NULL) {
			pthread_mutex_unlock(&nic->nic_mutex);
			LOG_ERR(PFX "%s Couldn't allocate "
				"interface with ip_type: 0x%x",
				nic->log_name, ird.ip_type);
			goto done;
		}
		nic_iface->protocol = ird.ip_type;
		nic_iface->vlan_id = ird.vlan_id;
		nic_iface->vlan_priority = ird.vlan_priority;
		if (ird.mtu >= MIN_MTU_SUPPORT && ird.mtu <= MAX_MTU_SUPPORT)
			nic_iface->mtu = ird.mtu;
		nic_iface->iface_num = ird.iface_num;
		nic_iface->request_type = request_type;
		nic_add_nic_iface(nic, nic_iface);

		persist_all_nic_iface(nic);

		LOG_INFO(PFX "%s: created network interface",
			 nic->log_name);
	} else {
		/* Move the nic_iface to the front */
		set_nic_iface(nic, nic_iface);
		LOG_INFO(PFX "%s: using existing network interface",
			 nic->log_name);
	}

	nic_iface->flags |= NIC_IFACE_PATHREQ_WAIT1;
	if (nic->nl_process_thread == INVALID_THREAD) {
		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		rc = pthread_create(&nic->nl_process_thread, &attr,
				    nl_process_handle_thread, nic);
		if (rc != 0) {
			LOG_ERR(PFX "%s: Could not create NIC NL "
				"processing thread [%s]", nic->log_name,
				strerror(rc));
			nic->nl_process_thread = INVALID_THREAD;
			/* Reset both WAIT flags */
			nic_iface->flags &= ~NIC_IFACE_PATHREQ_WAIT;
			nic->flags &= ~NIC_PATHREQ_WAIT;
		}
	}

	pthread_mutex_unlock(&nic->nic_mutex);

	if (nic_iface->ustack.ip_config == request_type) {
		/* Same request_type, check for STATIC address change */
		if (request_type == IPV4_CONFIG_STATIC) {
			if (memcmp(nic_iface->ustack.hostaddr, &ird.ipv4_addr,
				   sizeof(struct in_addr)))
				goto reacquire;
		} else if (request_type == IPV6_CONFIG_STATIC) {
			if (memcmp(nic_iface->ustack.hostaddr6, &ird.ipv6_addr,
				   sizeof(struct in6_addr)))
				goto reacquire;
			else
				inet_ntop(AF_INET6, &ird.ipv6_addr,
					  ipv6_buf_str,
					  sizeof(ipv6_buf_str));
		}
		LOG_INFO(PFX "%s: IP configuration didn't change using 0x%x",
			 nic->log_name, nic_iface->ustack.ip_config);
		/* No need to acquire the IP address */
		inet_ntop(AF_INET6, &ird.ipv6_addr, ipv6_buf_str,
			  sizeof(ipv6_buf_str));

		goto enable_nic;
	}
reacquire:
	/* Config needs to re-acquire for this nic_iface */
	pthread_mutex_lock(&nic->nic_mutex);
	nic_iface->flags |= NIC_IFACE_ACQUIRE;
	pthread_mutex_unlock(&nic->nic_mutex);

	/* Disable the nic loop from further processing, upon returned,
	   the nic_iface should be cleared */
	nic_disable(nic, 0);

	/*  Check to see if this is using DHCP or if this is
	 *  a static IPv4 address.  This is done by checking
	 *  if the IP address is equal to 0.0.0.0.  If it is
	 *  then the user has specified to use DHCP.  If not
	 *  then the user has spcicied to use a static IP address
	 *  an the default netmask will be used */
	switch (request_type) {
	case IPV4_CONFIG_DHCP:
		memset(nic_iface->ustack.hostaddr, 0, sizeof(struct in_addr));
		LOG_INFO(PFX "%s: configuring using DHCP", nic->log_name);
		nic_iface->ustack.ip_config = IPV4_CONFIG_DHCP;
		break;

	case IPV4_CONFIG_STATIC:
		memcpy(nic_iface->ustack.hostaddr, &ird.ipv4_addr,
		       sizeof(struct in_addr));
		LOG_INFO(PFX "%s: configuring using static IP "
			 "IPv4 address :%s ",
			 nic->log_name, inet_ntoa(ird.ipv4_addr));

		if (ird.ipv4_subnet_mask.s_addr)
			memcpy(nic_iface->ustack.netmask,
			       &ird.ipv4_subnet_mask, sizeof(struct in_addr));
		LOG_INFO(PFX " netmask: %s", inet_ntoa(ird.ipv4_subnet_mask));

		/* Default route */
		if (ird.ipv4_gateway.s_addr) {
			/* Check for validity */
			src_match.s_addr = ird.ipv4_addr.s_addr &
					   ird.ipv4_subnet_mask.s_addr;
			dst_match.s_addr = ird.ipv4_gateway.s_addr &
					   ird.ipv4_subnet_mask.s_addr;
			if (src_match.s_addr == dst_match.s_addr)
				memcpy(nic_iface->ustack.default_route_addr,
				       &ird.ipv4_gateway,
				       sizeof(struct in_addr));
		}
		nic_iface->ustack.ip_config = IPV4_CONFIG_STATIC;
		break;

	case IPV6_CONFIG_DHCP:
		memset(nic_iface->ustack.hostaddr6, 0,
		       sizeof(struct in6_addr));
		nic_iface->ustack.prefix_len = ird.prefix_len;
		nic_iface->ustack.ipv6_autocfg = ird.ipv6_autocfg;
		nic_iface->ustack.linklocal_autocfg = ird.linklocal_autocfg;
		nic_iface->ustack.router_autocfg = ird.router_autocfg;

		if (memcmp(&ird.ipv6_subnet_mask, all_zeroes_addr6,
			   sizeof(struct in6_addr)))
			memcpy(nic_iface->ustack.netmask6,
			       &ird.ipv6_subnet_mask, sizeof(struct in6_addr));
		if (ird.linklocal_autocfg == IPV6_LL_AUTOCFG_OFF)
			memcpy(nic_iface->ustack.linklocal6,
			       &ird.ipv6_linklocal, sizeof(struct in6_addr));
		if (ird.router_autocfg == IPV6_RTR_AUTOCFG_OFF)
			memcpy(nic_iface->ustack.default_route_addr6,
			       &ird.ipv6_router, sizeof(struct in6_addr));
		inet_ntop(AF_INET6, &ird.ipv6_addr, ipv6_buf_str,
			  sizeof(ipv6_buf_str));
		LOG_INFO(PFX "%s: configuring using DHCPv6",
			 nic->log_name);
		nic_iface->ustack.ip_config = IPV6_CONFIG_DHCP;
		break;

	case IPV6_CONFIG_STATIC:
		memcpy(nic_iface->ustack.hostaddr6, &ird.ipv6_addr,
		       sizeof(struct in6_addr));
		nic_iface->ustack.prefix_len = ird.prefix_len;
		nic_iface->ustack.ipv6_autocfg = ird.ipv6_autocfg;
		nic_iface->ustack.linklocal_autocfg = ird.linklocal_autocfg;
		nic_iface->ustack.router_autocfg = ird.router_autocfg;

		if (memcmp(&ird.ipv6_subnet_mask, all_zeroes_addr6,
			   sizeof(struct in6_addr)))
			memcpy(nic_iface->ustack.netmask6,
			       &ird.ipv6_subnet_mask, sizeof(struct in6_addr));
		if (ird.linklocal_autocfg == IPV6_LL_AUTOCFG_OFF)
			memcpy(nic_iface->ustack.linklocal6,
			       &ird.ipv6_linklocal, sizeof(struct in6_addr));
		if (ird.router_autocfg == IPV6_RTR_AUTOCFG_OFF)
			memcpy(nic_iface->ustack.default_route_addr6,
			       &ird.ipv6_router, sizeof(struct in6_addr));

		inet_ntop(AF_INET6, &ird.ipv6_addr, ipv6_buf_str,
			  sizeof(ipv6_buf_str));
		LOG_INFO(PFX "%s: configuring using static IP "
			 "IPv6 address: '%s'", nic->log_name, ipv6_buf_str);

		nic_iface->ustack.ip_config = IPV6_CONFIG_STATIC;
		break;

	default:
		LOG_INFO(PFX "%s: Unknown request type: 0x%x",
			 nic->log_name, request_type);

	}

enable_nic:
	switch (nic->state) {
	case NIC_STOPPED:
		/* This thread will be thrown away when completed */
		if (nic->enable_thread != INVALID_THREAD) {
			rc = pthread_cancel(nic->enable_thread);
			if (rc != 0) {
				LOG_INFO(PFX "%s: failed to cancel enable NIC "
					 "thread\n", nic->log_name);
				goto eagain;
			}
		}
		pthread_attr_init(&attr);
		pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
		rc = pthread_create(&nic->enable_thread, &attr,
				    enable_nic_thread, (void *)nic);
		if (rc != 0)
			LOG_WARN(PFX "%s: failed starting enable NIC thread\n",
				 nic->log_name);
eagain:
		rc = -EAGAIN;
		break;

	case NIC_RUNNING:
		LOG_INFO(PFX "%s: NIC already enabled "
			 "flags: 0x%x state: 0x%x\n",
			 nic->log_name, nic->flags, nic->state);
		rc = 0;
		break;
	default:
		LOG_INFO(PFX "%s: NIC enable still in progress "
			 "flags: 0x%x state: 0x%x\n",
			 nic->log_name, nic->flags, nic->state);
		rc = -EAGAIN;
	}

	LOG_INFO(PFX "ISCSID_UIP_IPC_GET_IFACE: command: %x "
		 "name: %s, netdev: %s ipaddr: %s vlan: %d transport_name:%s",
		 data->header.command, rec->name, rec->netdev,
		 (ird.ip_type == AF_INET) ? inet_ntoa(ird.ipv4_addr) :
					     ipv6_buf_str,
		 ird.vlan_id, rec->transport_name);

	if (do_ping) {
		if (nic->ping_thread != INVALID_THREAD) {
			rc = pthread_cancel(nic->ping_thread);
			if (rc != 0) {
				LOG_INFO(PFX "%s: failed to cancel ping thread",
					 nic->log_name);
				rc = -EAGAIN;
				goto done;
			}
		}

		png_c = malloc(sizeof(struct ping_conf));
		if (!png_c) {
			LOG_ERR(PFX "Memory alloc failed for ping conf");
			rc = -ENOMEM;
			goto done;
		}

		memset(png_c, 0, sizeof(struct ping_conf));
		png_c->nic_iface = nic_iface;
		png_c->data = arg;
		nic_iface->ustack.ping_conf = png_c;

		/* Spawn a thread to perform ping operation.
		 * This thread will exit when done.
		 */
		rc = pthread_create(&nic->ping_thread, NULL,
				    perform_ping, (void *)png_c);
		if (rc != 0) {
			LOG_WARN(PFX "%s: failed starting ping thread\n",
				 nic->log_name);
		} else {
			pthread_join(nic->ping_thread, NULL);
			rc = png_c->state;
			if (rc == -EAGAIN)
				png_c->state = 0;
		}
		free(png_c);
		nic_iface->ustack.ping_conf = NULL;
	}

done:
	pthread_mutex_unlock(&nic_list_mutex);

early_exit:
	return rc;
}

/**
 *  process_iscsid_broadcast() - This function is used to process the
 *                               broadcast messages from iscsid
 */
int process_iscsid_broadcast(int s2)
{
	int rc = 0;
	iscsid_uip_broadcast_t *data;
	iscsid_uip_rsp_t rsp;
	FILE *fd;
	size_t size;
	iscsid_uip_cmd_e cmd;
	uint32_t payload_len;

	fd = fdopen(s2, "r+");
	if (fd == NULL) {
		LOG_ERR(PFX "Couldn't open file descriptor: %d(%s)",
			errno, strerror(errno));
		return -EIO;
	}

	/*  This will be freed by parse_iface_thread() */
	data = (iscsid_uip_broadcast_t *) calloc(1, sizeof(*data));
	if (data == NULL) {
		LOG_ERR(PFX "Couldn't allocate memory for iface data");
		rc = -ENOMEM;
		goto error;
	}
	memset(data, 0, sizeof(*data));

	size = fread(data, sizeof(iscsid_uip_broadcast_header_t), 1, fd);
	if (!size) {
		LOG_ERR(PFX "Could not read request: %d(%s)",
			errno, strerror(errno));
		rc = ferror(fd);
		goto error;
	}

	cmd = data->header.command;
	payload_len = data->header.payload_len;

	LOG_DEBUG(PFX "recv iscsid request: cmd: %d, payload_len: %d",
		  cmd, payload_len);

	switch (cmd) {
	case ISCSID_UIP_IPC_GET_IFACE:
		size = fread(&data->u.iface_rec, payload_len, 1, fd);
		if (!size) {
			LOG_ERR(PFX "Could not read data: %d(%s)",
				errno, strerror(errno));
			goto error;
		}

		rc = parse_iface(data, 0);
		switch (rc) {
		case 0:
			rsp.command = cmd;
			rsp.err = ISCSID_UIP_MGMT_IPC_DEVICE_UP;
			break;
		case -EAGAIN:
			rsp.command = cmd;
			rsp.err = ISCSID_UIP_MGMT_IPC_DEVICE_INITIALIZING;
			break;
		default:
			rsp.command = cmd;
			rsp.err = ISCSID_UIP_MGMT_IPC_ERR;
		}

		break;
	case ISCSID_UIP_IPC_PING:
		size = fread(&data->u.ping_rec, payload_len, 1, fd);
		if (!size) {
			LOG_ERR(PFX "Could not read data: %d(%s)",
				errno, strerror(errno));
			goto error;
		}

		rc = parse_iface(data, 1);
		rsp.command = cmd;
		rsp.ping_sc = rc;

		switch (rc) {
		case 0:
			rsp.err = ISCSID_UIP_MGMT_IPC_DEVICE_UP;
			break;
		case -EAGAIN:
			rsp.err = ISCSID_UIP_MGMT_IPC_DEVICE_INITIALIZING;
			break;
		default:
			rsp.err = ISCSID_UIP_MGMT_IPC_ERR;
		}

		break;
	default:
		LOG_WARN(PFX "Unknown iscsid broadcast command: %x",
			 data->header.command);

		/*  Send a response back to iscsid to tell it the
		   operation succeeded */
		rsp.command = cmd;
		rsp.err = ISCSID_UIP_MGMT_IPC_OK;
		break;
	}

	size = fwrite(&rsp, sizeof(rsp), 1, fd);
	if (size == -1) {
		LOG_ERR(PFX "Could not send response: %d(%s)",
			errno, strerror(errno));
		rc = ferror(fd);
	}

error:
	free(data);
	fclose(fd);

	return rc;
}

static void iscsid_loop_close(void *arg)
{
	close(iscsid_opts.fd);

	LOG_INFO(PFX "iSCSI daemon socket closed");
}

/**
 *  iscsid_loop() - This is the function which will process the broadcast
 *                  messages from iscsid
 *
 */
static void *iscsid_loop(void *arg)
{
	int rc;
	sigset_t set;

	pthread_cleanup_push(iscsid_loop_close, arg);

	sigfillset(&set);
	rc = pthread_sigmask(SIG_BLOCK, &set, NULL);
	if (rc != 0) {
		LOG_ERR(PFX
			"Couldn't set signal mask for the iscisd listening "
			"thread");
	}

	LOG_DEBUG(PFX "Started iscsid listening thread");

	while (1) {
		struct sockaddr_un remote;
		socklen_t sock_len;
		int s2;

		LOG_DEBUG(PFX "Waiting for iscsid command");

		sock_len = sizeof(remote);
		s2 = accept(iscsid_opts.fd,
			    (struct sockaddr *)&remote, &sock_len);
		if (s2 == -1) {
			if (errno == EAGAIN) {
				LOG_DEBUG("Got EAGAIN from accept");
				sleep(1);
				continue;
			} else if (errno == EINTR) {
				LOG_DEBUG("Got EINTR from accept");
				/*  The program is terminating, time to exit */
				break;
			}

			LOG_ERR(PFX "Could not accept: %d(%s)",
				s2, strerror(errno));
			continue;
		}

		process_iscsid_broadcast(s2);
		close(s2);
	}

	pthread_cleanup_pop(0);

	LOG_ERR(PFX "exit iscsid listening thread");

	pthread_exit(NULL);
}

#define SD_SOCKET_FDS_START 3

static int ipc_systemd(void)
{
	char *env;

	env = getenv("LISTEN_PID");

	if (!env || (strtoul(env, NULL, 10) != getpid()))
		return -EINVAL;

	env = getenv("LISTEN_FDS");

	if (!env)
		return -EINVAL;

	if (strtoul(env, NULL, 10) != 1) {
		LOG_ERR("Did not receive exactly one IPC socket from systemd");
		return -EINVAL;
	}

	return SD_SOCKET_FDS_START;
}

/******************************************************************************
 *  Initialize/Cleanup routines
 ******************************************************************************/
/**
 *  iscsid_init() - This function will setup the thread used to listen for
 *                  the iscsid broadcast messages
 *  @return 0 on success, <0 on failure
 */
int iscsid_init()
{
	int rc, addr_len;
	struct sockaddr_un addr;

	iscsid_opts.fd = ipc_systemd();
	if (iscsid_opts.fd >= 0)
		return 0;

	iscsid_opts.fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (iscsid_opts.fd < 0) {
		LOG_ERR(PFX "Can not create IPC socket");
		return iscsid_opts.fd;
	}

	addr_len = offsetof(struct sockaddr_un, sun_path) + strlen(ISCSID_UIP_NAMESPACE) + 1;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	memcpy((char *)&addr.sun_path + 1, ISCSID_UIP_NAMESPACE,
	       strlen(ISCSID_UIP_NAMESPACE));

	rc = bind(iscsid_opts.fd, (struct sockaddr *)&addr, addr_len);
	if (rc < 0) {
		LOG_ERR(PFX "Can not bind IPC socket: %s", strerror(errno));
		goto error;
	}

	rc = listen(iscsid_opts.fd, 32);
	if (rc < 0) {
		LOG_ERR(PFX "Can not listen IPC socket: %s", strerror(errno));
		goto error;
	}

	return 0;
error:
	close(iscsid_opts.fd);
	iscsid_opts.fd = INVALID_FD;

	return rc;
}

/**
 *  iscsid_start() - This function will start the thread used to listen for
 *                  the iscsid broadcast messages
 *  @return 0 on success, <0 on failure
 */
int iscsid_start()
{
	pthread_attr_t attr;
	int rc;

	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	rc = pthread_create(&iscsid_opts.thread, &attr, iscsid_loop, NULL);
	if (rc != 0) {
		LOG_ERR(PFX "Could not start iscsid listening thread rc=%d",
			rc);
		goto error;
	}

	return 0;

error:
	close(iscsid_opts.fd);
	iscsid_opts.fd = INVALID_FD;

	return rc;
}

/**
 *  iscsid_cleanup() - This is called when stoping the thread listening
 *                     for the iscsid broadcast messages
 */
void iscsid_cleanup()
{
	int rc;

	if (iscsid_opts.fd != INVALID_FD) {
		rc = pthread_cancel(iscsid_opts.thread);
		if (rc != 0) {
			LOG_ERR("Could not cancel iscsid listening thread: %s",
				strerror(rc));
		}
	}

	LOG_INFO(PFX "iscsid listening thread has shutdown");
}
