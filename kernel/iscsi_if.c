/*
 * iSCSI Initiator Kernel/User Interface
 *
 * Copyright (C) 2004 Dmitry Yusupov, Alex Aizman
 * maintained by open-iscsi@googlegroups.com
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
#include <net/tcp.h>
#include <iscsi_if.h>
#include <iscsi_ifev.h>

static struct iscsi_transport *transport_table[ISCSI_TRANSPORT_MAX];
static struct sock *nls;
static int daemon_pid;

int
iscsi_control_recv_pdu(iscsi_cnx_h cp_cnx, struct iscsi_hdr *hdr,
				char *data, uint32_t data_size)
{
	struct nlmsghdr	*nlh;
	struct sk_buff	*skb;
	struct iscsi_uevent *ev;
	char *pdu;
	int len = NLMSG_SPACE(sizeof(*ev) + sizeof(struct iscsi_hdr) +
			      data_size);

	skb = alloc_skb(len, in_interrupt() ? GFP_ATOMIC : GFP_KERNEL);
	if (!skb) {
		return -ENOMEM;
	}

	nlh = __nlmsg_put(skb, daemon_pid, 0, 0, (len - sizeof(*nlh)));
	ev = NLMSG_DATA(nlh);
	memset(ev, 0, sizeof(*ev));
	ev->transport_id = 0;
	ev->type = ISCSI_KEVENT_RECV_PDU;
	ev->r.recv_req.cnx_handle = cp_cnx;
	pdu = (char*)ev + sizeof(*ev);
	memcpy(pdu, hdr, sizeof(struct iscsi_hdr));
	memcpy(pdu + sizeof(struct iscsi_hdr), data, data_size);
	skb_get(skb);
	netlink_unicast(nls, skb, daemon_pid, MSG_DONTWAIT);
	return 0;
}
EXPORT_SYMBOL_GPL(iscsi_control_recv_pdu);

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
	ev->transport_id = 0;
	ev->type = ISCSI_KEVENT_CNX_ERROR;
	ev->r.cnxerror.error = error;
	ev->r.cnxerror.cnx_handle = cp_cnx;
	skb_get(skb);
	netlink_unicast(nls, skb, daemon_pid, MSG_DONTWAIT);
}
EXPORT_SYMBOL_GPL(iscsi_control_cnx_error);

static struct iscsi_transport*
iscsi_if_transport_lookup(int id)
{
	/* FIXME: implement transport's container */
	if (id != 0)
		return NULL;
	return transport_table[id];
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
	struct iscsi_transport *transport;
	struct iscsi_uevent *ev = NLMSG_DATA(nlh);

	if ((transport = iscsi_if_transport_lookup(ev->transport_id)) == NULL)
		return -EEXIST;

	daemon_pid = NETLINK_CREDS(skb)->pid;

	switch (nlh->nlmsg_type) {
	case ISCSI_UEVENT_CREATE_SESSION:
		ev->r.c_session_ret.handle = transport->create_session(
		       ev->u.c_session.session_handle,
		       ev->u.c_session.initial_cmdsn, &ev->r.c_session_ret.sid);
		break;
	case ISCSI_UEVENT_DESTROY_SESSION:
		transport->destroy_session(
			ev->u.d_session.session_handle);
		break;
	case ISCSI_UEVENT_CREATE_CNX:
		ev->r.handle = transport->create_cnx(
			ev->u.c_cnx.session_handle,
			ev->u.c_cnx.cnx_handle,
			 ev->u.c_cnx.transport_fd, ev->u.c_cnx.cid);
		break;
	case ISCSI_UEVENT_DESTROY_CNX:
		transport->destroy_cnx(ev->u.d_cnx.cnx_handle);
		break;
	case ISCSI_UEVENT_BIND_CNX:
		ev->r.retcode = transport->bind_cnx(
			ev->u.b_cnx.session_handle,
			ev->u.b_cnx.cnx_handle,
			ev->u.b_cnx.is_leading);
		break;
	case ISCSI_UEVENT_SET_PARAM:
		ev->r.retcode = transport->set_param(
			ev->u.set_param.cnx_handle,
			ev->u.set_param.param, ev->u.set_param.value);
		break;
	case ISCSI_UEVENT_START_CNX:
		ev->r.retcode = transport->start_cnx(
			ev->u.start_cnx.cnx_handle);
		break;
	case ISCSI_UEVENT_STOP_CNX:
		transport->stop_cnx(
			ev->u.stop_cnx.cnx_handle);
		break;
	case ISCSI_UEVENT_SEND_PDU:
		ev->r.retcode = transport->send_pdu(
		       ev->u.send_pdu.cnx_handle,
		       (struct iscsi_hdr*)((char*)ev + sizeof(*ev)),
		       (char*)ev + sizeof(*ev) + ev->u.send_pdu.hdr_size,
			ev->u.send_pdu.data_size);
		break;
	default:
		err = -EINVAL;
		break;
	}

	return err;
}

/* Get message from skb (based on rtnetlink_rcv_skb).  Each message is
 * processed by iscsi_if_recv_msg.  Malformed skbs with wrong length are
 * discarded silently.  */
static void
iscsi_if_rx(struct sock *sk, int len)
{
	struct sk_buff *skb;
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
			err = iscsi_if_recv_msg(skb, nlh);
			if (err) {
				netlink_ack(skb, nlh, -err);
			} else {
				u32 seq  = nlh->nlmsg_seq;
				u32 pid  = NETLINK_CREDS(skb)->pid;
				struct iscsi_uevent *ev = NLMSG_DATA(nlh);
				err = iscsi_if_send_reply(pid, seq,
					nlh->nlmsg_type, 0, 0, ev, sizeof(*ev));
				if (err)
					netlink_ack(skb, nlh, -err);
			}
			skb_pull(skb, rlen);
		}
		kfree_skb(skb);
	}
}

int iscsi_register_transport(struct iscsi_transport *ops, int id)
{
	transport_table[id] = ops;
	return 0;
}
EXPORT_SYMBOL_GPL(iscsi_register_transport);

void iscsi_unregister_transport(int id)
{
	transport_table[id] = NULL;
}
EXPORT_SYMBOL_GPL(iscsi_unregister_transport);

int __init iscsi_if_init(void)
{
	printk(KERN_INFO "Open-iSCSI Interface, version "
			ISCSI_VERSION_STR " variant (" ISCSI_DATE_STR ")\n");

	nls = netlink_kernel_create(NETLINK_ISCSI, iscsi_if_rx);
	if (nls == NULL)
		return -ENOBUFS;

	return 0;
}

static void __exit
iscsi_if_exit(void)
{
	sock_release(nls->sk_socket);
}

module_init(iscsi_if_init);
module_exit(iscsi_if_exit);
