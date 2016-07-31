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
 * nic_nl.c - NIC uIP NetLink user space stack
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
#include <linux/netlink.h>
#include <iscsi_if.h>
#include <sys/ioctl.h>
#include <sys/poll.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/socket.h>

#include "uip_arp.h"
#include "logger.h"
#include "options.h"

#include "nic.h"
#include "nic_nl.h"
#include "nic_utils.h"

/*******************************************************************************
 * Constants
 ******************************************************************************/
#define PFX "NIC_NL "

static u8_t nlm_sendbuf[NLM_BUF_DEFAULT_MAX];

static struct sockaddr_nl src_addr;

static const struct sockaddr_nl dest_addr = {
	.nl_family = AF_NETLINK,
	.nl_pid = 0,		/* kernel */
	.nl_groups = 0,		/* unicast */
};

#define POLL_NL		0
#define POLL_MAX        1

/* Netlink */
int nl_sock = INVALID_FD;

static int nl_read(int ctrl_fd, char *data, int size, int flags)
{
	int rc;
	struct iovec iov;
	struct msghdr msg;

	iov.iov_base = data;
	iov.iov_len = size;

	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();
	src_addr.nl_groups = 1;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (void *)&src_addr;
	msg.msg_namelen = sizeof(src_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	rc = recvmsg(ctrl_fd, &msg, flags);

	return rc;
}

static int
kwritev(int fd, enum iscsi_uevent_e type, struct iovec *iovp, int count)
{
	int i, rc;
	struct nlmsghdr *nlh;
	struct msghdr msg;
	struct iovec iov;
	int datalen = 0;

	for (i = 0; i < count; i++)
		datalen += iovp[i].iov_len;

	nlh = (struct nlmsghdr *)nlm_sendbuf;
	memset(nlh, 0, NLMSG_SPACE(datalen));

	nlh->nlmsg_len = NLMSG_SPACE(datalen);
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_type = type;

	datalen = 0;
	for (i = 0; i < count; i++) {
		memcpy(NLMSG_DATA(nlh) + datalen, iovp[i].iov_base,
		       iovp[i].iov_len);
		datalen += iovp[i].iov_len;
	}
	iov.iov_base = (void *)nlh;
	iov.iov_len = nlh->nlmsg_len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (void *)&dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	do {
		rc = sendmsg(fd, &msg, 0);
		if (rc == -ENOMEM) {
			LOG_ERR(PFX "sendmsg: alloc_skb() failed");
			sleep(1);
		} else if (rc < 0) {
			LOG_ERR(PFX "sendmsg: bug?: on %d %s[0x%x]",
				fd, strerror(errno), errno);
			sleep(1);
		}
	} while ((rc < 0) && (event_loop_stop == 0));

	return rc;
}

/*
 * __kipc_call() should never block. Therefore
 * Netlink's xmit logic is serialized. This means we do not allocate on
 * xmit path. Instead we reuse nlm_sendbuf buffer.
 *
 * Transport must assure non-blocking operations for:
 *
 *	- session_create()
 *	- conn_create()
 *	- conn_bind()
 *	_ set_param()
 *	- conn_start()
 *	- conn_stop()
 *
 * Its OK to block for cleanup for short period of time in operatations for:
 *
 *	- conn_destroy()
 *	- session_destroy()
 *
 * FIXME: interface needs to be extended to allow longer blocking on
 *        cleanup. (Dima)
 */
int __kipc_call(int fd, void *iov_base, int iov_len)
{
	int rc;
	struct iovec iov;
	struct iscsi_uevent *ev = iov_base;
	enum iscsi_uevent_e type = ev->type;

	/* Sanity check */
	if (iov_base == NULL)
		return -EINVAL;

	iov.iov_base = iov_base;
	iov.iov_len = iov_len;

	rc = kwritev(fd, type, &iov, 1);

	return rc;
}

static int pull_from_nl(char **buf)
{
	int rc;
	size_t ev_size, payload_size, alloc_size;
	char nlm_ev[NLMSG_SPACE(sizeof(struct iscsi_uevent))];
	struct nlmsghdr *nlh;
	char *data = NULL;
	struct iscsi_uevent *ev;

	/*  Take a quick peek at what how much uIP will need to read */
	rc = nl_read(nl_sock, nlm_ev,
		     NLMSG_SPACE(sizeof(struct iscsi_uevent)),
		     MSG_PEEK | MSG_WAITALL);
	if (rc <= 0) {
		LOG_ERR("can not read nlm_ev, error %s[%d]",
			strerror(errno), rc);
		if (rc == 0)
			return -EIO;
		else
			return errno;
	}
	nlh = (struct nlmsghdr *)nlm_ev;

	if (unlikely(nlh->nlmsg_len < NLMSG_ALIGN(sizeof(struct nlmsghdr)))) {
		LOG_ERR(PFX "Invalid nlh->nlmsg_len length: "
			"nlh->nlmsg_len(%d) < "
			"NLMSG_ALIGN(sizeof(struct nlmsghdr))(%d)",
			nlh->nlmsg_len, NLMSG_ALIGN(sizeof(struct nlmsghdr)));
		return -EINVAL;
	}

	ev = (struct iscsi_uevent *)NLMSG_DATA(nlh);
	if (ev->type == ISCSI_KEVENT_PATH_REQ) {
		ev_size = nlh->nlmsg_len - NLMSG_ALIGN(sizeof(struct nlmsghdr));
		payload_size = ev_size - sizeof(struct iscsi_uevent);
		if (payload_size < sizeof(struct iscsi_path))
			alloc_size = nlh->nlmsg_len + (payload_size -
				     sizeof(struct iscsi_path));
		else
			alloc_size = nlh->nlmsg_len;
	} else {
		alloc_size = nlh->nlmsg_len;
	}
	data = (char *)malloc(alloc_size);
	if (unlikely(data == NULL)) {
		LOG_ERR(PFX "Couldn't allocate %d bytes for Netlink "
			"iSCSI message", alloc_size);
		return -ENOMEM;
	}

	memset(data, 0, alloc_size);
	rc = nl_read(nl_sock, data, (int)nlh->nlmsg_len, MSG_WAITALL);
	if (rc <= 0) {
		LOG_ERR("can not read nlm_ev, error %s[%d]",
			strerror(errno), rc);
		if (rc == 0)
			rc = -EIO;
		else
			rc = errno;

		goto error;
	}
	*buf = data;
	return 0;
error:
	if (data != NULL)
		free(data);

	return rc;
}

static const struct timespec ctldev_sleep_req = {
	.tv_sec = 0,
	.tv_nsec = 250000000,
};

static int ctldev_handle(char *data, nic_t *nic)
{
	int rc;
	struct iscsi_uevent *ev;
	uint8_t *payload;
	struct iscsi_path *path;
	char *msg_type_str;
	int i;
	nic_interface_t *nic_iface = NULL;

	ev = (struct iscsi_uevent *)NLMSG_DATA(data);
	switch (ev->type) {
	case ISCSI_KEVENT_PATH_REQ:
		msg_type_str = "path_req";
		break;
	default:
		/*  We don't care about other iSCSI Netlink messages */
		LOG_DEBUG(PFX "Received ev->type: 0x%x", ev->type);
		rc = 0;
		goto error;
	}

	/*  This is a message that drivers should be interested in */
	LOG_INFO(PFX "%s: Processing '%s'", nic->log_name, msg_type_str);

	payload = (uint8_t *) ((uint8_t *) ev) + sizeof(*ev);
	path = (struct iscsi_path *)payload;

	if (ev->type == ISCSI_KEVENT_PATH_REQ) {
		struct timespec sleep_rem;
		nic_interface_t *vlan_iface;
		uint16_t ip_type;
		int iface_num, vlan_id;

		if (path->ip_addr_len == 4)
			ip_type = AF_INET;
		else if (path->ip_addr_len == 16)
			ip_type = AF_INET6;
		else
			ip_type = 0;
#ifdef REQ_PATH_IFACE_NUM
		/* Find the nic_iface to use */
		iface_num = ev->r.req_path.iface_num ?
			    ev->r.req_path.iface_num : IFACE_NUM_INVALID;
#else
		iface_num = IFACE_NUM_INVALID;
#endif
		vlan_id = path->vlan_id ? path->vlan_id : NO_VLAN;

		LOG_DEBUG(PFX "%s: PATH_REQ with iface_num %d VLAN %d",
			  nic->log_name, iface_num, vlan_id);

		pthread_mutex_lock(&nic->nic_mutex);

		nic_iface = nic_find_nic_iface(nic, ip_type, vlan_id,
					       iface_num, IP_CONFIG_OFF);
		if (nic_iface == NULL) {
			nic_iface = nic_find_nic_iface(nic, ip_type,
						       NO_VLAN,
						       IFACE_NUM_INVALID,
						       IP_CONFIG_OFF);
			if (nic_iface == NULL) {
				pthread_mutex_unlock(&nic->nic_mutex);
				LOG_ERR(PFX "%s: Couldn't find nic iface parent"
					" vlan: %d ip_type: %d "
					"ip_addr_len: %d to clone",
					nic->log_name, path->vlan_id, ip_type,
					path->ip_addr_len);
				goto error;
			}
			if (nic_iface->iface_num != IFACE_NUM_INVALID) {
				/* New VLAN support:
				   Use the nic_iface found from the top
				   of the protocol family and ignore
				   the VLAN id from the path_req */
				if (!(nic_iface->iface_num == 0 &&
				      nic_iface->vlan_id == 0 &&
				      path->vlan_id)) {
					pthread_mutex_unlock(&nic->nic_mutex);
					goto nic_iface_done;
				}
				/* If iface_num == 0 and vlan_id == 0 but
				   the vlan_id from path_req is > 0,
				   then fallthru to the legacy support since
				   this is most likely from an older iscsid
				   (RHEL6.2/6.3 but has iface_num support)
				*/
			}
			/* Legacy VLAN support:
			   This newly created nic_iface must inherit the
			   network parameters from the parent nic_iface
			*/
			LOG_DEBUG(PFX "%s: Created the nic_iface for vlan: %d "
				  "ip_type: %d", nic->log_name, path->vlan_id,
				  ip_type);
			vlan_iface = nic_iface_init();
			if (vlan_iface == NULL) {
				pthread_mutex_unlock(&nic->nic_mutex);
				LOG_ERR(PFX "%s: Couldn't allocate "
					"space for vlan: %d ip_type: "
					"%d", nic->log_name, path->vlan_id,
					ip_type);
				goto error;
			}
			vlan_iface->protocol = ip_type;
			vlan_iface->vlan_id = path->vlan_id;
			nic_add_nic_iface(nic, vlan_iface);

			vlan_iface->ustack.ip_config =
				nic_iface->ustack.ip_config;
			memcpy(vlan_iface->ustack.hostaddr,
			       nic_iface->ustack.hostaddr,
			       sizeof(nic_iface->ustack.hostaddr));
			memcpy(vlan_iface->ustack.netmask,
			       nic_iface->ustack.netmask,
			       sizeof(nic_iface->ustack.netmask));
			memcpy(vlan_iface->ustack.netmask6,
			       nic_iface->ustack.netmask6,
			       sizeof(nic_iface->ustack.netmask6));
			memcpy(vlan_iface->ustack.hostaddr6,
			       nic_iface->ustack.hostaddr6,
			       sizeof(nic_iface->ustack.hostaddr6));

			/* Persist so when nic_close won't call uip_reset
			   to nullify nic_iface->ustack */
			persist_all_nic_iface(nic);

			nic_iface = vlan_iface;
			nic_iface->flags |= NIC_IFACE_ACQUIRE;

			pthread_mutex_unlock(&nic->nic_mutex);

			/* nic_disable but not going down */
			nic_disable(nic, 0);
		} else {
			pthread_mutex_unlock(&nic->nic_mutex);
		}
nic_iface_done:
		/*  Force enable the NIC */
		if (nic->state == NIC_STOPPED)
			nic_enable(nic);

		/*  Ensure that the NIC is RUNNING */
		rc = -EIO;
		for (i = 0; i < 10; i++) {
			if (nic->state == NIC_RUNNING) {
				rc = 0;
				break;
			}

			nanosleep(&ctldev_sleep_req, &sleep_rem);
		}

		if (rc != 0) {
			LOG_WARN(PFX "%s[vlan: %d protocol: %d]: not running, "
				 "cmd: 0x%x nic state: 0x%x flags: 0x%x",
				 nic->log_name,
				 nic_iface->vlan_id, nic_iface->protocol,
				 ev->type, nic->state, nic->flags);
			goto error;
		}
	}

	if (nic->ops) {
		switch (ev->type) {
		case ISCSI_KEVENT_PATH_REQ:
			/*  pass the request up to the user space
			 *  library driver */
			nic_iface->flags |= NIC_IFACE_PATHREQ_WAIT2;
			nic_iface->flags &= ~NIC_IFACE_PATHREQ_WAIT1;
			if (nic->ops->handle_iscsi_path_req)
				nic->ops->handle_iscsi_path_req(nic,
								nl_sock, ev,
								path,
								nic_iface);
			nic_iface->flags &= ~NIC_IFACE_PATHREQ_WAIT;
			pthread_mutex_lock(&nic->nic_mutex);
			nic->flags &= ~NIC_PATHREQ_WAIT;
			pthread_mutex_unlock(&nic->nic_mutex);
			LOG_INFO(PFX "%s: 'path_req' operation finished",
				 nic->log_name);

			rc = 0;
			break;
		default:
			rc = -EAGAIN;
			break;
		}
	}

error:

	return rc;
}

/* NIC specific nl processing thread */
void *nl_process_handle_thread(void *arg)
{
	int rc;
	nic_t *nic = (nic_t *)arg;

	if (nic == NULL)
		goto error;

	while (!event_loop_stop) {
		char *data = NULL;

		pthread_mutex_lock(&nic->nl_process_mutex);
		rc = pthread_cond_wait(&nic->nl_process_cond,
				       &nic->nl_process_mutex);
		if (rc != 0) {
			pthread_mutex_unlock(&nic->nl_process_mutex);
			LOG_ERR("Fatal error in NL processing thread "
				"during wait[%s]", strerror(rc));
			break;
		}

		data = nic->nl_process_ring[nic->nl_process_head];
		nic->nl_process_ring[nic->nl_process_head] = NULL;
		nic->nl_process_tail =
				NIC_NL_PROCESS_NEXT_ENTRY(nic->nl_process_tail);

		pthread_mutex_unlock(&nic->nl_process_mutex);

		if (data) {
			ctldev_handle(data, nic);
			free(data);
		}
	}
error:
	return NULL;
}

static void flush_nic_nl_process_ring(nic_t *nic)
{
	int i;

	for (i = 0; i < NIC_NL_PROCESS_MAX_RING_SIZE; i++) {
		if (nic->nl_process_ring[i] != NULL) {
			free(nic->nl_process_ring[i]);
			nic->nl_process_ring[i] = NULL;
		}
	}

	nic->nl_process_head = 0;
	nic->nl_process_tail = 0;

	LOG_DEBUG(PFX "%s: Flushed NIC NL ring", nic->log_name);
}

/**
 *  nic_nl_open() - This is called when opening/creating the Netlink listening
 *                   thread
 *  @param dev - CNIC UIO device to create a NetLink listener on
 *  @return 0 on success, <0 on failure
 */
int nic_nl_open()
{
	int rc;
	char *msg_type_str;

	/* Prepare the thread to issue the ARP's */
	nl_sock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ISCSI);
	if (nl_sock < 0) {
		LOG_ERR(PFX "can not create NETLINK_ISCSI socket [%s]",
			strerror(errno));
		rc = -ENOMEM;
		goto error;
	}

	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();
	src_addr.nl_groups = ISCSI_NL_GRP_UIP;

	while ((!event_loop_stop)) {
		rc = bind(nl_sock,
			  (struct sockaddr *)&src_addr, sizeof(src_addr));
		if (rc == 0)
			break;

		LOG_ERR(PFX "waiting binding to NETLINK_ISCSI socket");

		sleep(1);
	}

	if (event_loop_stop) {
		rc = -EINVAL;
		goto error;
	}

	LOG_INFO(PFX "Netlink to CNIC on pid %d is ready", src_addr.nl_pid);

	while (!event_loop_stop) {
		struct iscsi_uevent *ev;
		char *buf = NULL;
		uint32_t host_no;
		nic_t *nic;

		rc = pull_from_nl(&buf);
		if (rc != 0)
			continue;

		/*  Try to abort ARP'ing if a if_down was received */
		ev = (struct iscsi_uevent *)NLMSG_DATA(buf);
		switch (ev->type) {
		case ISCSI_KEVENT_IF_DOWN:
			host_no = ev->r.notify_if_down.host_no;
			msg_type_str = "if_down";
			break;
		case ISCSI_KEVENT_PATH_REQ:
			host_no = ev->r.req_path.host_no;
			msg_type_str = "path_req";
			break;
		default:
			/*  We don't care about other iSCSI Netlink messages */
			continue;
		}
		LOG_INFO(PFX "Received %s for host %d", msg_type_str, host_no);

		/* Make sure the nic list doesn't get yanked */
		pthread_mutex_lock(&nic_list_mutex);

		rc = from_host_no_find_associated_eth_device(host_no, &nic);
		if (rc != 0) {
			pthread_mutex_unlock(&nic_list_mutex);
			LOG_ERR(PFX "Dropping msg, couldn't find nic with host "
				"no: %d", host_no);
			continue;
		}

		/* Found the nic */
		if (nic->nl_process_thread == INVALID_THREAD) {
			/* If thread is not valid, just drop it */
			pthread_mutex_unlock(&nic_list_mutex);
			LOG_ERR(PFX "Dropping msg, nic nl process thread "
				"not ready for host no: %d", host_no);
			continue;
		}

		if (ev->type == ISCSI_KEVENT_IF_DOWN) {
			char eth_device_name[IFNAMSIZ];

			pthread_mutex_lock(&nic->nl_process_mutex);
			nic->nl_process_if_down = 1;
			flush_nic_nl_process_ring(nic);
			pthread_cond_broadcast(&nic->nl_process_if_down_cond);
			pthread_mutex_unlock(&nic->nl_process_mutex);

			memcpy(eth_device_name, nic->eth_device_name,
			       sizeof(eth_device_name));

			pthread_mutex_lock(&nic->nic_mutex);
			nic->flags &= ~NIC_PATHREQ_WAIT;
			nic->flags |= NIC_EXIT_MAIN_LOOP;
			pthread_cond_broadcast(&nic->enable_done_cond);
			pthread_mutex_unlock(&nic->nic_mutex);

			pthread_mutex_lock(&nic->nl_process_mutex);
			nic->nl_process_if_down = 0;
			pthread_mutex_unlock(&nic->nl_process_mutex);

			nic_disable(nic, 1);

			nic_remove(nic);
			pthread_mutex_unlock(&nic_list_mutex);

			LOG_INFO(PFX "%s: 'if_down' operation finished",
				 eth_device_name);
			continue;
		}

		/* Place msg into the nic specific queue */
		pthread_mutex_lock(&nic->nl_process_mutex);
		if ((nic->nl_process_head + 1 == nic->nl_process_tail) ||
		    (nic->nl_process_tail == 0 &&
		     nic->nl_process_head == NIC_NL_PROCESS_LAST_ENTRY)) {
			pthread_mutex_unlock(&nic->nl_process_mutex);
			pthread_mutex_unlock(&nic_list_mutex);
			LOG_WARN(PFX "%s: No space on Netlink ring",
				 nic->log_name);
			continue;
		}

		nic->nl_process_ring[nic->nl_process_head] = buf;
		nic->nl_process_head =
				NIC_NL_PROCESS_NEXT_ENTRY(nic->nl_process_head);
		pthread_cond_signal(&nic->nl_process_cond);

		pthread_mutex_unlock(&nic->nl_process_mutex);

		pthread_mutex_unlock(&nic_list_mutex);

		LOG_DEBUG(PFX "Pulled nl event");
	}

	LOG_INFO(PFX "Netlink thread exit'ing");
	rc = 0;

error:
	return 0;
}
