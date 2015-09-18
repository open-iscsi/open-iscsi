/*
 * Copyright (c) 2009-2011, Broadcom Corporation
 * Copyright (c) 2014, QLogic Corporation
 *
 * Written by: Benjamin Li  (benli@broadcom.com)
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
 * cnic.c - CNIC UIO uIP user space stack
 *
 */
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <linux/limits.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <linux/netlink.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/socket.h>

#include "uip_arp.h"
#include "nic.h"
#include "nic_utils.h"
#include "logger.h"
#include "options.h"

#include "cnic.h"
#include "iscsi_if.h"
#include "ipv6_ndpc.h"

/*******************************************************************************
 * Constants
 ******************************************************************************/
#define PFX "CNIC "

static const uip_ip6addr_t all_ones_addr6 = {
	0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff };

/*******************************************************************************
 * Constants shared between the bnx2 and bnx2x modules
 ******************************************************************************/
const char bnx2i_library_transport_name[] = "bnx2i";
const size_t bnx2i_library_transport_name_size =
			sizeof(bnx2i_library_transport_name);

/******************************************************************************
 * Netlink Functions
 ******************************************************************************/

static int cnic_arp_send(nic_t *nic, nic_interface_t *nic_iface, int fd,
			 __u8 *mac_addr, __u32 ip_addr, char *addr_str)
{
	struct ether_header *eth;
	struct ether_arp *arp;
	__u32 dst_ip = ip_addr;
	int pkt_size = sizeof(*eth) + sizeof(*arp);
	int rc;
	struct in_addr addr;
	static const uint8_t multicast_mac[] = {
				0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	rc = pthread_mutex_trylock(&nic->xmit_mutex);
	if (rc != 0) {
		LOG_DEBUG(PFX "%s: could not get xmit_mutex", nic->log_name);
		return -EAGAIN;
	}

	eth = (*nic->ops->get_tx_pkt) (nic);
	if (eth == NULL) {
		LOG_WARN(PFX "%s: couldn't get tx packet", nic->log_name);
		return -EAGAIN;
	}

	nic_fill_ethernet_header(nic_iface, eth,
				 nic->mac_addr, (void *)multicast_mac,
				 &pkt_size, (void *)&arp, ETHERTYPE_ARP);

	arp->arp_hrd = htons(ARPHRD_ETHER);
	arp->arp_pro = htons(ETHERTYPE_IP);
	arp->arp_hln = ETH_ALEN;
	arp->arp_pln = 4;
	arp->arp_op = htons(ARPOP_REQUEST);
	memcpy(arp->arp_sha, nic->mac_addr, ETH_ALEN);
	memset(arp->arp_tha, 0, ETH_ALEN);

	/*  Copy the IP address's into the ARP response */
	memcpy(arp->arp_spa, nic_iface->ustack.hostaddr, 4);
	memcpy(arp->arp_tpa, &dst_ip, 4);

	(*nic->nic_library->ops->start_xmit) (nic, pkt_size,
					      (nic_iface->vlan_priority << 12) |
					      nic_iface->vlan_id);

	memcpy(&addr.s_addr, &dst_ip, sizeof(addr.s_addr));
	LOG_DEBUG(PFX "%s: Sent cnic arp request for IP: %s",
		  nic->log_name, addr_str);

	return 0;
}

static int cnic_neigh_soliciation_send(nic_t *nic,
				       nic_interface_t *nic_iface, int fd,
				       __u8 *mac_addr,
				       struct in6_addr *addr6_dst,
				       char *addr_str)
{
	struct ether_header *eth;
	struct ip6_hdr *ipv6_hdr;
	int rc, pkt_size;
	char buf[INET6_ADDRSTRLEN];
	struct ndpc_reqptr req_ptr;

	rc = pthread_mutex_trylock(&nic->xmit_mutex);
	if (rc != 0) {
		LOG_WARN(PFX "%s: could not get xmit_mutex", nic->log_name);
		return -EAGAIN;
	}

	/*  Build the ethernet header */
	eth = (*nic->ops->get_tx_pkt) (nic);
	if (eth == NULL) {
		LOG_WARN(PFX "%s: couldn't get tx packet", nic->log_name);
		return -EAGAIN;
	}

	/* Copy the requested target address to the ipv6.dst */
	ipv6_hdr =
	    (struct ip6_hdr *)((u8_t *) eth + sizeof(struct ether_header));

	memcpy(ipv6_hdr->ip6_dst.s6_addr, addr6_dst->s6_addr,
	       sizeof(struct in6_addr));

	nic_fill_ethernet_header(nic_iface, eth, nic->mac_addr, nic->mac_addr,
				 &pkt_size, (void *)&ipv6_hdr, ETHERTYPE_IPV6);
	req_ptr.eth = (void *)eth;
	req_ptr.ipv6 = (void *)ipv6_hdr;
	if (ndpc_request(&nic_iface->ustack, &req_ptr, &pkt_size,
			 NEIGHBOR_SOLICIT))
		return -EAGAIN;

	/* Debug to print out the pkt context */
	inet_ntop(AF_INET6, ipv6_hdr->ip6_dst.s6_addr, buf, sizeof(buf));
	LOG_DEBUG(PFX "%s: ipv6 dst addr: %s", nic->log_name, buf);
	LOG_DEBUG(PFX "neighbor sol content "
		  "dst mac %02x:%02x:%02x:%02x:%02x:%02x",
		  eth->ether_dhost[0], eth->ether_dhost[1],
		  eth->ether_dhost[2], eth->ether_dhost[3],
		  eth->ether_dhost[4], eth->ether_dhost[5]);
	LOG_DEBUG(PFX "src mac %02x:%02x:%02x:%02x:%02x:%02x",
		  eth->ether_shost[0], eth->ether_shost[1],
		  eth->ether_shost[2], eth->ether_shost[3],
		  eth->ether_shost[4], eth->ether_shost[5]);
	(*nic->nic_library->ops->start_xmit) (nic, pkt_size,
					      (nic_iface->vlan_priority << 12) |
					      nic_iface->vlan_id);

	LOG_DEBUG(PFX "%s: Sent cnic ICMPv6 neighbor request %s",
		  nic->log_name, addr_str);

	return 0;
}

static int cnic_nl_neigh_rsp(nic_t *nic, int fd,
			     struct iscsi_uevent *ev,
			     struct iscsi_path *path_req,
			     __u8 *mac_addr,
			     nic_interface_t *nic_iface, int status, int type)
{
	int rc;
	uint8_t *ret_buf;
	struct iscsi_uevent *ret_ev;
	struct iscsi_path *path_rsp;
	struct sockaddr_nl dest_addr;
	char addr_dst_str[INET6_ADDRSTRLEN];

	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = 0;
	dest_addr.nl_groups = 0;	/* unicast */

	ret_buf = calloc(1, NLMSG_SPACE(sizeof(struct iscsi_uevent) + 256));
	if (ret_buf == NULL) {
		LOG_ERR(PFX "Could not allocate memory for path req resposne");
		return -ENOMEM;
	}

	memset(ret_buf, 0, NLMSG_SPACE(sizeof(struct iscsi_uevent) + 256));

	/*  prepare the iscsi_uevent buffer */
	ret_ev = (struct iscsi_uevent *)ret_buf;
	ret_ev->type = ISCSI_UEVENT_PATH_UPDATE;
	ret_ev->transport_handle = ev->transport_handle;
	ret_ev->u.set_path.host_no = ev->r.req_path.host_no;

	/*  Prepare the iscsi_path buffer */
	path_rsp = (struct iscsi_path *)(ret_buf + sizeof(*ret_ev));
	path_rsp->handle = path_req->handle;
	if (type == AF_INET) {
		path_rsp->ip_addr_len = 4;
		memcpy(&path_rsp->src.v4_addr, nic_iface->ustack.hostaddr,
		       sizeof(nic_iface->ustack.hostaddr));

		inet_ntop(AF_INET, &path_rsp->src.v4_addr,
			  addr_dst_str, sizeof(addr_dst_str));
	} else {
		u8_t *src_ipv6;
		int ret;

		/*  Depending on the IPv6 address of the target we will need to
		 *  determine whether we use the assigned IPv6 address or the
		 *  link local IPv6 address */
		if (ndpc_request(&nic_iface->ustack, &path_req->dst.v6_addr,
				 &ret, CHECK_LINK_LOCAL_ADDR)) {
			src_ipv6 = (u8_t *)all_zeroes_addr6;
			LOG_DEBUG(PFX "RSP Check LL failed");
			goto src_done;
		}
		if (ret) {
			/* Get link local IPv6 address */
			src_ipv6 = (u8_t *)&nic_iface->ustack.linklocal6;
		} else {
			if (ndpc_request(&nic_iface->ustack,
					 &path_req->dst.v6_addr,
					 &src_ipv6, GET_HOST_ADDR)) {
				src_ipv6 = (u8_t *)all_zeroes_addr6;
				LOG_DEBUG(PFX "RSP Get host addr failed");
			}
			if (src_ipv6 == NULL) {
				src_ipv6 = (u8_t *)all_zeroes_addr6;
				LOG_DEBUG(PFX "RSP no Best matched addr found");
			}
		}
src_done:
		path_rsp->ip_addr_len = 16;
		memcpy(&path_rsp->src.v6_addr, src_ipv6,
		       sizeof(nic_iface->ustack.hostaddr6));

		inet_ntop(AF_INET6, &path_rsp->src.v6_addr,
			  addr_dst_str, sizeof(addr_dst_str));
	}
	memcpy(path_rsp->mac_addr, mac_addr, 6);
	path_rsp->vlan_id = (nic_iface->vlan_priority << 12) |
			    nic_iface->vlan_id;
	path_rsp->pmtu = nic_iface->mtu ? nic_iface->mtu : path_req->pmtu;

	rc = __kipc_call(fd, ret_ev, sizeof(*ret_ev) + sizeof(*path_rsp));
	if (rc > 0) {
		LOG_DEBUG(PFX "neighbor reply sent back to kernel "
			  "%s at %02x:%02x:%02x:%02x:%02x:%02x with vlan %d",
			  addr_dst_str,
			  mac_addr[0], mac_addr[1],
			  mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5],
			  nic_iface->vlan_id);

	} else {
		LOG_ERR(PFX "send neighbor reply failed: %d", rc);
	}

	free(ret_buf);

	return rc;
}

static const struct timeval tp_wait = {
	.tv_sec = 0,
	.tv_usec = 250000,
};

/**
 * cnic_handle_ipv4_iscsi_path_req() - This function will handle the IPv4
 *				       path req calls the bnx2i kernel module
 * @param nic - The nic the message is directed towards
 * @param fd  - The file descriptor to be used to extract the private data
 * @param ev  - The iscsi_uevent
 * @param buf - The private message buffer
 */
int cnic_handle_ipv4_iscsi_path_req(nic_t *nic, int fd,
				    struct iscsi_uevent *ev,
				    struct iscsi_path *path,
				    nic_interface_t *nic_iface)
{
	struct in_addr src_addr, dst_addr,
	    src_matching_addr, dst_matching_addr, netmask;
	__u8 mac_addr[6];
	int rc;
	uint16_t arp_retry;
	int status = 0;
#define MAX_ARP_RETRY 4

	memset(mac_addr, 0, sizeof(mac_addr));
	memcpy(&dst_addr, &path->dst.v4_addr, sizeof(dst_addr));
	memcpy(&src_addr, nic_iface->ustack.hostaddr, sizeof(src_addr));

	if (nic_iface->ustack.netmask[0] | nic_iface->ustack.netmask[1])
		memcpy(&netmask.s_addr, nic_iface->ustack.netmask,
		       sizeof(src_addr));
	else
		netmask.s_addr = calculate_default_netmask(dst_addr.s_addr);

	src_matching_addr.s_addr = src_addr.s_addr & netmask.s_addr;
	dst_matching_addr.s_addr = dst_addr.s_addr & netmask.s_addr;

	LOG_DEBUG(PFX "%s: src=%s", nic->log_name, inet_ntoa(src_addr));
	LOG_DEBUG(PFX "%s: dst=%s", nic->log_name, inet_ntoa(dst_addr));
	LOG_DEBUG(PFX "%s: nm=%s", nic->log_name, inet_ntoa(netmask));
	if (src_matching_addr.s_addr != dst_matching_addr.s_addr) {
		/*  If there is an assigned gateway address then use it
		 *  if the source address doesn't match */
		if (nic_iface->ustack.default_route_addr[0] |
		    nic_iface->ustack.default_route_addr[1]) {
			memcpy(&dst_addr,
			       &nic_iface->ustack.default_route_addr,
			       sizeof(dst_addr));
		} else {
			arp_retry = MAX_ARP_RETRY;
			LOG_DEBUG(PFX "%s: no default", nic->log_name);
			goto done;
		}
	}
	arp_retry = 0;

	rc = uip_lookup_arp_entry(dst_addr.s_addr, mac_addr);
	if (rc != 0) {
		while ((arp_retry < MAX_ARP_RETRY) && (event_loop_stop == 0)) {
			char *dst_addr_str;
			int count;
			struct timespec ts;
			struct timeval tp;
			struct timeval tp_abs;

			dst_addr_str = inet_ntoa(dst_addr);

			LOG_INFO(PFX "%s: Didn't find IPv4: '%s' in ARP table",
				 nic->log_name, dst_addr_str);
			rc = cnic_arp_send(nic, nic_iface, fd,
					   mac_addr,
					   dst_addr.s_addr, dst_addr_str);
			if (rc != 0) {
				status = -EIO;
				goto done;
			}

			for (count = 0; count < 8; count++) {
				/* Convert from timeval to timespec */
				rc = gettimeofday(&tp, NULL);

				timeradd(&tp, &tp_wait, &tp_abs);

				ts.tv_sec = tp_abs.tv_sec;
				ts.tv_nsec = tp_abs.tv_usec * 1000;

				/* Wait 1s for if_down */
				pthread_mutex_lock(&nic->nl_process_mutex);
				rc = pthread_cond_timedwait
						(&nic->nl_process_if_down_cond,
						 &nic->nl_process_mutex, &ts);

				if (rc == ETIMEDOUT) {
					pthread_mutex_unlock
						(&nic->nl_process_mutex);

					rc = uip_lookup_arp_entry(dst_addr.
								  s_addr,
								  mac_addr);
					if (rc == 0)
						goto done;
				} else {
					nic->nl_process_if_down = 0;
					pthread_mutex_unlock
						(&nic->nl_process_mutex);

					arp_retry = MAX_ARP_RETRY;
					goto done;

				}
			}

			arp_retry++;
		}
	}

done:

	if (arp_retry >= MAX_ARP_RETRY) {
		status = -EIO;
		rc = -EIO;
	}

	if (status != 0 || rc != 0)
		pthread_mutex_unlock(&nic->xmit_mutex);

	if (ev) {
		cnic_nl_neigh_rsp(nic, fd, ev, path, mac_addr,
				  nic_iface, status, AF_INET);
	}

	return rc;
}

/**
 * cnic_handle_ipv6_iscsi_path_req() - This function will handle the IPv4
 *				       path req calls the bnx2i kernel module
 * @param nic - The nic the message is directed towards
 * @param fd  - The file descriptor to be used to extract the private data
 * @param ev  - The iscsi_uevent
 * @param buf - The private message buffer
 */
int cnic_handle_ipv6_iscsi_path_req(nic_t *nic, int fd,
				    struct iscsi_uevent *ev,
				    struct iscsi_path *path,
				    nic_interface_t *nic_iface)
{
	__u8 mac_addr[6];
	int rc, i;
	uint16_t neighbor_retry;
	int status = 0;
	char addr_dst_str[INET6_ADDRSTRLEN];
	struct in6_addr src_addr, dst_addr,
			src_matching_addr, dst_matching_addr, netmask;
	struct in6_addr *addr;
	struct ndpc_reqptr req_ptr;

	memset(mac_addr, 0, sizeof(mac_addr));

	inet_ntop(AF_INET6, &path->dst.v6_addr,
		  addr_dst_str, sizeof(addr_dst_str));

	/*  Depending on the IPv6 address of the target we will need to
	 *  determine whether we use the assigned IPv6 address or the
	 *  link local IPv6 address */
	memcpy(&dst_addr, &path->dst.v6_addr, sizeof(struct in6_addr));
	if (ndpc_request(&nic_iface->ustack, &dst_addr,
			 &rc, CHECK_LINK_LOCAL_ADDR)) {
		neighbor_retry = MAX_ARP_RETRY;
		LOG_DEBUG(PFX "Check LL failed");
		goto done;
	}
	if (rc) {
		LOG_DEBUG(PFX "Use LL");
		/* Get link local IPv6 address */
		addr = (struct in6_addr *)&nic_iface->ustack.linklocal6;
	} else {
		LOG_DEBUG(PFX "Use Best matched");
		if (ndpc_request(&nic_iface->ustack,
				 &dst_addr,
				 &addr, GET_HOST_ADDR)) {
			neighbor_retry = MAX_ARP_RETRY;
			LOG_DEBUG(PFX "Use Best matched failed");
			goto done;
		}
		if (addr == NULL) {
			neighbor_retry = MAX_ARP_RETRY;
			LOG_DEBUG(PFX "No Best matched found");
			goto done;
		}
	}
	/* Got the best matched src IP address */
	memcpy(&src_addr, addr, sizeof(struct in6_addr));

	if (nic_iface->ustack.netmask6[0] | nic_iface->ustack.netmask6[1] |
	    nic_iface->ustack.netmask6[2] | nic_iface->ustack.netmask6[3] |
	    nic_iface->ustack.netmask6[4] | nic_iface->ustack.netmask6[5] |
	    nic_iface->ustack.netmask6[6] | nic_iface->ustack.netmask6[7])
		memcpy(&netmask.s6_addr, nic_iface->ustack.netmask6,
		       sizeof(struct in6_addr));
	else
		memcpy(&netmask.s6_addr, all_zeroes_addr6,
		       sizeof(struct in6_addr));

	inet_ntop(AF_INET6, &src_addr.s6_addr16, addr_dst_str,
		  sizeof(addr_dst_str));
	LOG_DEBUG(PFX "src IP addr %s", addr_dst_str);
	inet_ntop(AF_INET6, &dst_addr.s6_addr16, addr_dst_str,
		  sizeof(addr_dst_str));
	LOG_DEBUG(PFX "dst IP addr %s", addr_dst_str);
	inet_ntop(AF_INET6, &netmask.s6_addr16, addr_dst_str,
		  sizeof(addr_dst_str));
	LOG_DEBUG(PFX "prefix mask %s", addr_dst_str);

	for (i = 0; i < 4; i++) {
		src_matching_addr.s6_addr32[i] = src_addr.s6_addr32[i] &
		    netmask.s6_addr32[i];
		dst_matching_addr.s6_addr32[i] = dst_addr.s6_addr32[i] &
		    netmask.s6_addr32[i];
		if (src_matching_addr.s6_addr32[i] !=
		    dst_matching_addr.s6_addr32[i]) {
			/* No match with the prefix mask, use default route */
			if (memcmp(nic_iface->ustack.default_route_addr6,
				   all_zeroes_addr6, sizeof(*addr))) {
				memcpy(&dst_addr,
				       nic_iface->ustack.default_route_addr6,
				       sizeof(dst_addr));
				inet_ntop(AF_INET6, &dst_addr.s6_addr16,
					  addr_dst_str, sizeof(addr_dst_str));
				LOG_DEBUG(PFX "Use default router IP addr %s",
					  addr_dst_str);
				break;
			} else {
				neighbor_retry = MAX_ARP_RETRY;
				goto done;
			}
		}
	}

#define MAX_ARP_RETRY 4
	neighbor_retry = 0;

	req_ptr.eth = (void *)mac_addr;
	req_ptr.ipv6 = (void *)&dst_addr;
	if (ndpc_request(&nic_iface->ustack, &req_ptr, &rc, CHECK_ARP_TABLE)) {
		/* ndpc request failed, skip neighbor solicit send */
		neighbor_retry = MAX_ARP_RETRY;
		goto done;
	}
	if (!rc) {
		inet_ntop(AF_INET6, &dst_addr.s6_addr16,
			  addr_dst_str, sizeof(addr_dst_str));
		LOG_DEBUG(PFX
			  "%s: Preparing to send IPv6 neighbor solicitation "
			  "to dst: '%s'", nic->log_name, addr_dst_str);
		while ((neighbor_retry < MAX_ARP_RETRY)
		       && (event_loop_stop == 0)) {
			int count;
			struct timespec ts;
			struct timeval tp;
			struct timeval tp_abs;

			LOG_INFO(PFX "%s: Didn't find IPv6: '%s'\n",
				 nic->log_name, addr_dst_str);

			rc = cnic_neigh_soliciation_send(nic, nic_iface, fd,
							 mac_addr,
							 &dst_addr,
							 addr_dst_str);
			if (rc != 0) {
				status = -EIO;
				goto done;
			}

			for (count = 0; count < 8; count++) {
				/* Convert from timeval to timespec */
				rc = gettimeofday(&tp, NULL);

				timeradd(&tp, &tp_wait, &tp_abs);

				ts.tv_sec = tp_abs.tv_sec;
				ts.tv_nsec = tp_abs.tv_usec * 1000;

				pthread_mutex_lock(&nic->nl_process_mutex);
				rc = pthread_cond_timedwait
				    (&nic->nl_process_if_down_cond,
				     &nic->nl_process_mutex, &ts);

				if (rc == ETIMEDOUT) {
					pthread_mutex_unlock
						(&nic->nl_process_mutex);

					req_ptr.eth = (void *)mac_addr;
					req_ptr.ipv6 = (void *)&dst_addr;
					if (ndpc_request
					    (&nic_iface->ustack, &req_ptr, &rc,
					     CHECK_ARP_TABLE)) {
						/* ndpc request failed,
						   force retry */
						rc = 0;
					}
					if (rc)
						goto done;
				} else {
					nic->nl_process_if_down = 0;
					pthread_mutex_unlock
						(&nic->nl_process_mutex);

					neighbor_retry = MAX_ARP_RETRY;
					goto done;
				}
			}
			neighbor_retry++;
		}
	}

done:
	if (neighbor_retry >= MAX_ARP_RETRY) {
		status = -EIO;
		rc = -EIO;
	}

	if (status != 0 || rc != 0)
		pthread_mutex_unlock(&nic->xmit_mutex);

	if (ev) {
		cnic_nl_neigh_rsp(nic, fd, ev, path, mac_addr,
				  nic_iface, status, AF_INET6);
	}
	return rc;
}

/**
 * cnic_handle_iscsi_path_req() - This function will handle the path req calls
 *				  the bnx2i kernel module
 * @param nic - The nic the message is directed towards
 * @param fd  - The file descriptor to be used to extract the private data
 * @param ev  - The iscsi_uevent
 * @param path - The private message buffer
 * @param nic_iface - The nic_iface to use for this connection request
 */
int cnic_handle_iscsi_path_req(nic_t *nic, int fd, struct iscsi_uevent *ev,
			       struct iscsi_path *path,
			       nic_interface_t *nic_iface)
{

	LOG_DEBUG(PFX "%s: Netlink message with VLAN ID: %d, path MTU: %d "
		  "minor: %d ip_addr_len: %d",
		  nic->log_name, path->vlan_id, path->pmtu, 0 /* TODO FIX */ ,
		  path->ip_addr_len);

	if (path->ip_addr_len == 4)
		return cnic_handle_ipv4_iscsi_path_req(nic, fd, ev, path,
						       nic_iface);
	else if (path->ip_addr_len == 16)
		return cnic_handle_ipv6_iscsi_path_req(nic, fd, ev, path,
						       nic_iface);
	else {
		LOG_DEBUG(PFX "%s: unknown ip_addr_len: %d size dropping ",
			  nic->log_name, path->ip_addr_len);
		return -EIO;
	}
}
