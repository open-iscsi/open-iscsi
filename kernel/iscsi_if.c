/*
 * iSCSI Initiator Kernel/User Interface
 *
 * Copyright (C) 2004 Dmitry Yusupov, Alex Aizman
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

#include <linux/module.h>

#include "iscsi_proto.h"
#include "iscsi_if.h"
#include "iscsi_u.h"

struct iscsi_kprovider {
	char			name[ISCSI_PROVIDER_NAME_MAXLEN];
	struct iscsi_ops	ops;
	struct iscsi_caps	caps;
};
static struct iscsi_kprovider provider_table[ISCSI_PROVIDER_MAX];
static struct sock *nls = NULL;
static int daemon_pid = 0;

/* The netlink socket is only to be read by 1 CPU, which lets us assume
 * that list additions and deletions never happen simultaneiously */
static DECLARE_MUTEX(iscsi_netlink_sem);
static LIST_HEAD(nlwork_head);
static spinlock_t nlwork_lock;

#define nlwork_lock() do { \
	if (in_interrupt()) spin_lock(&nlwork_lock); \
	else spin_lock_bh(&nlwork_lock); \
} while (0)

#define nlwork_unlock() do { \
	if (in_interrupt()) spin_unlock(&nlwork_lock); \
	else spin_unlock_bh(&nlwork_lock); \
} while (0)

static void
iscsi_if_nlworker(void *data)
{
	struct list_head *lh, *n;

	spin_lock_bh(&nlwork_lock);
	list_for_each_safe(lh, n, &nlwork_head) {
		struct sk_buff *skb = (struct sk_buff *)((char *)lh -
				offsetof(struct sk_buff, cb));
		list_del((struct list_head *)&skb->cb);
		spin_unlock_bh(&nlwork_lock);
		down(&iscsi_netlink_sem);
		skb_get(skb);
		(void)netlink_unicast(nls, skb, daemon_pid, MSG_DONTWAIT);
		up(&iscsi_netlink_sem);
		spin_lock_bh(&nlwork_lock);
	}
	spin_unlock_bh(&nlwork_lock);
}
static DECLARE_WORK(nlwork, iscsi_if_nlworker, NULL);

int
iscsi_control_recv_pdu(iscsi_cnx_h cp_cnx, iscsi_hdr_t *hdr,
				char *data, int data_size)
{
	struct nlmsghdr	*nlh;
	struct sk_buff	*skb;
	struct iscsi_uevent *ev;
	char *pdu;
	int len = NLMSG_SPACE(sizeof(*ev) + sizeof(iscsi_hdr_t) + data_size);

	skb = alloc_skb(len, in_interrupt() ? GFP_ATOMIC : GFP_KERNEL);
	if (!skb) {
		return -ENOMEM;
	}

	nlh = __nlmsg_put(skb, daemon_pid, 0, 0, (len - sizeof(*nlh)));
	ev = NLMSG_DATA(nlh);
	memset(ev, 0, sizeof(*ev));
	ev->provider_id = 0;
	ev->type = ISCSI_KEVENT_RECV_PDU;
	ev->r.recv_req.cnx_handle = (ulong_t)cp_cnx;
	pdu = (char*)ev + sizeof(*ev);
	memcpy(pdu, hdr, sizeof(iscsi_hdr_t));
	memcpy(pdu + sizeof(iscsi_hdr_t), data, data_size);
	nlwork_lock();
	list_add_tail((struct list_head *)&skb->cb, &nlwork_head);
	nlwork_unlock();
	schedule_work(&nlwork);
	return 0;
}

void
iscsi_control_cnx_error(iscsi_cnx_h cp_cnx, iscsi_err_e error)
{
	struct nlmsghdr	*nlh;
	struct sk_buff	*skb;
	struct iscsi_uevent *ev;
	int len = NLMSG_SPACE(sizeof(*ev));

	skb = alloc_skb(len, in_interrupt() ? GFP_ATOMIC : GFP_KERNEL);
	if (!skb) {
		return;
	}

	nlh = __nlmsg_put(skb, daemon_pid, 0, 0, (len - sizeof(*nlh)));
	ev = NLMSG_DATA(nlh);
	ev->provider_id = 0;
	ev->type = ISCSI_KEVENT_CNX_ERROR;
	ev->r.cnxerror.error = error;
	ev->r.cnxerror.cnx_handle = (ulong_t)cp_cnx;
	nlwork_lock();
	list_add_tail((struct list_head *)&skb->cb, &nlwork_head);
	nlwork_unlock();
	schedule_work(&nlwork);
}

static struct iscsi_kprovider*
iscsi_if_provider_lookup(int id)
{
	/* FIXME: implement provider's container */
	if (id != 0)
		return NULL;
	return &provider_table[id];
}

static int
iscsi_if_send_reply(int pid, int seq, int type, int done, int multi,
		      void *payload, int size)
{
	struct sk_buff	*skb;
	struct nlmsghdr	*nlh;
	int len = NLMSG_SPACE(size);
	int flags = multi ? NLM_F_MULTI : 0;
	int t = done ? NLMSG_DONE  : type;

	skb = alloc_skb(len, GFP_KERNEL);
	if (!skb) {
		return -ENOMEM;
	}

	nlh = __nlmsg_put(skb, pid, seq, t, (len - sizeof(*nlh)));
	nlh->nlmsg_flags = flags;
	memcpy(NLMSG_DATA(nlh), payload, size);
	(void)netlink_unicast(nls, skb, pid, MSG_DONTWAIT);
	return 0;
}

static int
iscsi_if_recv_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	int err = 0;
	struct iscsi_kprovider *provider;
	u32 pid  = NETLINK_CREDS(skb)->pid;
	u32 seq  = nlh->nlmsg_seq;
	struct iscsi_uevent *ev = NLMSG_DATA(nlh);

	if ((provider = iscsi_if_provider_lookup(ev->provider_id)) == NULL)
		return -EEXIST;

	daemon_pid = pid;

	switch (nlh->nlmsg_type) {
	case ISCSI_UEVENT_CREATE_SESSION:
		ev->r.handle = (ulong_t)provider->ops.create_session(
		       (void*)ev->u.c_session.session_handle,
		       ev->u.c_session.sid, ev->u.c_session.initial_cmdsn);
		err = iscsi_if_send_reply(pid, seq, nlh->nlmsg_type, 0, 0,
					       ev, sizeof(*ev));
		break;
	case ISCSI_UEVENT_DESTROY_SESSION:
		provider->ops.destroy_session(
			(void*)ev->u.d_session.session_handle);
		netlink_ack(skb, nlh, 0);
		break;
	case ISCSI_UEVENT_CREATE_CNX: {
		struct socket *sock;

		if (!(sock = sockfd_lookup(ev->u.c_cnx.socket_fd, &err))) {
			break;
		}
		ev->r.handle = (ulong_t)provider->ops.create_cnx(
			(void*)ev->u.c_cnx.session_handle,
			(void*)ev->u.c_cnx.cnx_handle, sock, ev->u.c_cnx.cid);
		err = iscsi_if_send_reply(pid, seq, nlh->nlmsg_type, 0, 0,
					ev, sizeof(*ev));
	} break;
	case ISCSI_UEVENT_DESTROY_CNX:
		provider->ops.destroy_cnx((void*)ev->u.d_cnx.cnx_handle);
		netlink_ack(skb, nlh, 0);
		break;
	case ISCSI_UEVENT_BIND_CNX:
		ev->r.retcode = (ulong_t)provider->ops.bind_cnx(
			(void*)ev->u.b_cnx.session_handle,
			(void*)ev->u.b_cnx.cnx_handle, ev->u.b_cnx.is_leading);
		err = iscsi_if_send_reply(pid, seq, nlh->nlmsg_type, 0, 0,
					ev, sizeof(*ev));
		break;
	case ISCSI_UEVENT_SET_PARAM:
		ev->r.retcode = provider->ops.set_param(
			(void*)ev->u.set_param.cnx_handle,
			ev->u.set_param.param, ev->u.set_param.value);
		err = iscsi_if_send_reply(pid, seq, nlh->nlmsg_type, 0, 0,
					ev, sizeof(*ev));
		break;
	case ISCSI_UEVENT_START_CNX:
		ev->r.retcode = provider->ops.start_cnx(
			(void*)ev->u.start_cnx.cnx_handle);
		err = iscsi_if_send_reply(pid, seq, nlh->nlmsg_type, 0, 0,
					ev, sizeof(*ev));
		break;
	case ISCSI_UEVENT_STOP_CNX:
		provider->ops.stop_cnx((void*)ev->u.stop_cnx.cnx_handle);
		netlink_ack(skb, nlh, 0);
		break;
	case ISCSI_UEVENT_SEND_PDU:
		ev->r.retcode = provider->ops.send_immpdu(
		       (void*)ev->u.send_pdu.cnx_handle,
		       (iscsi_hdr_t*)((char*)ev + sizeof(*ev)),
		       (char*)ev + sizeof(*ev) + ev->u.send_pdu.hdr_size,
			ev->u.send_pdu.data_size);
		err = iscsi_if_send_reply(pid, seq, nlh->nlmsg_type, 0, 0,
					ev, sizeof(*ev));
		break;
	default:
		err = -EINVAL;
		break;
	}

	return err < 0 ? err : 0;
}

/* Get message from skb (based on rtnetlink_rcv_skb).  Each message is
 * processed by iscsi_if_recv_msg.  Malformed skbs with wrong length are
 * discarded silently.  */
static void
iscsi_if_rx(struct sock *sk, int len)
{
	struct sk_buff *skb;

	down(&iscsi_netlink_sem);

	while ((skb = skb_dequeue(&sk->sk_receive_queue)) != NULL) {
		while (skb->len >= NLMSG_SPACE(0)) {
			int err;
			uint32_t rlen;
			struct nlmsghdr	*nlh;

			nlh = (struct nlmsghdr *)skb->data;
			if (nlh->nlmsg_len < sizeof(*nlh) ||
			    skb->len < nlh->nlmsg_len) {
				break;
			}
			rlen = NLMSG_ALIGN(nlh->nlmsg_len);
			if (rlen > skb->len)
				rlen = skb->len;
			if ((err = iscsi_if_recv_msg(skb, nlh))) {
				netlink_ack(skb, nlh, -err);
			} else if (nlh->nlmsg_flags & NLM_F_ACK)
				netlink_ack(skb, nlh, 0);
			skb_pull(skb, rlen);
		}
		kfree_skb(skb);
	}

	up(&iscsi_netlink_sem);
}

static int __init
iscsi_if_init(void)
{
	int rc;

	printk(KERN_INFO "Open-iSCSI Interface, version "
			ISCSI_VERSION_STR " variant (" ISCSI_DATE_STR ")\n");

	nls = netlink_kernel_create(NETLINK_ISCSI, iscsi_if_rx);
	if (nls == NULL)
		return -ENOBUFS;

	spin_lock_init(&nlwork_lock);

	strcpy(provider_table[0].name, "tcp");
	rc = iscsi_tcp_register(&provider_table[0].ops,
				 &provider_table[0].caps);
	if (rc) {
		sock_release(nls->sk_socket);
		return rc;
	}

	return 0;
}

static void __exit
iscsi_if_exit(void)
{
	iscsi_tcp_unregister();
	sock_release(nls->sk_socket);
}

module_init(iscsi_if_init);
module_exit(iscsi_if_exit);
