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
#include <linux/mempool.h>
#include <net/tcp.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_transport.h>
#include <scsi/scsi_transport_iscsi.h>
#include <iscsi_if.h>
#include <iscsi_ifev.h>

MODULE_AUTHOR("Dmitry Yusupov <dmitry_yus@yahoo.com>, "
	      "Alex Aizman <itn780@yahoo.com>");
MODULE_DESCRIPTION("Open-iSCSI Interface");
MODULE_LICENSE("GPL");

static struct iscsi_transport *transport_table[ISCSI_TRANSPORT_MAX];
static struct sock *nls;
static int daemon_pid;
DECLARE_MUTEX(callsema);
static mempool_t *recvpool;
LIST_HEAD(freequeue);
spinlock_t freelock;

struct iscsi_if_cnx {
	struct list_head item;		/* item in cnxlist */
	struct list_head snxitem;	/* item in snx->connections */
	iscsi_cnx_t cp_cnx;
	iscsi_cnx_t dp_cnx;
	struct sk_buff *alarm_skb;
	volatile int active;
	struct Scsi_Host *host;		/* originated shost */
};
LIST_HEAD(cnxlist);
spinlock_t cnxlock;

struct iscsi_if_snx {
	struct list_head item;	/* item in snxlist */
	struct list_head connections;
	iscsi_snx_t cp_snx;
	iscsi_snx_t dp_snx;
};
LIST_HEAD(snxlist);
spinlock_t snxlock;

#define	ISCSI_CTRL_PDU_MAX	DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH
#define	ISCSI_CTRL_POOL_MAX	32

#ifdef CONFIG_SCSI_ISCSI_ATTRS
static struct scsi_transport_template *iscsi_transportt;
#define iscsi_transport_get_fn(field, param)				\
static void								\
iscsi_if_get_##field (struct scsi_target *stgt)				\
{									\
	struct Scsi_Host *host = dev_to_shost(stgt->dev.parent);	\
	iscsi_##field(stgt) = 0;					\
}

iscsi_transport_get_fn(initial_r2t, ISCSI_PARAM_INITIAL_R2T_EN);
iscsi_transport_get_fn(immediate_data, ISCSI_PARAM_IMM_DATA_EN);
iscsi_transport_get_fn(first_burst_len, ISCSI_PARAM_FIRST_BURST);
iscsi_transport_get_fn(max_burst_len, ISCSI_PARAM_MAX_BURST);

static struct iscsi_function_template iscsi_fnt = {
	.get_initial_r2t	= iscsi_if_get_initial_r2t,
	.show_initial_r2t	= 1,
	.get_immediate_data	= iscsi_if_get_immediate_data,
	.show_immediate_data	= 1,
	.get_max_burst_len	= iscsi_if_get_max_burst_len,
	.show_max_burst_len	= 1,
	.get_first_burst_len	= iscsi_if_get_first_burst_len,
	.show_first_burst_len	= 1,
};
#endif

#define CNX_TYPE_CP	0
#define CNX_TYPE_DP	1
static struct iscsi_if_cnx*
iscsi_if_find_cnx(iscsi_cnx_t handle, int type)
{
	unsigned long flags;
	struct iscsi_if_cnx *cnx;

	spin_lock_irqsave(&cnxlock, flags);
	list_for_each_entry(cnx, &cnxlist, item) {
		if ((type == CNX_TYPE_DP && cnx->dp_cnx == handle) ||
		    (type == CNX_TYPE_CP && cnx->cp_cnx == handle)) {
			spin_unlock_irqrestore(&cnxlock, flags);
			return cnx;
		}
	}
	spin_unlock_irqrestore(&cnxlock, flags);
	return NULL;
}

static void
iscsi_recvpool_complete(void)
{
	unsigned long flags;
	struct list_head *lh, *n;

	spin_lock_irqsave(&freelock, flags);
	list_for_each_safe(lh, n, &freequeue) {
		struct sk_buff *skb = (struct sk_buff *)((char *)lh -
				offsetof(struct sk_buff, cb));
		if (!skb_shared(skb)) {
			list_del((void*)&skb->cb);
			mempool_free(skb, recvpool);
		}
	}
	spin_unlock_irqrestore(&freelock, flags);
}

static struct sk_buff*
iscsi_alloc_skb(int len)
{
	struct sk_buff *skb;

	/* complete receive tasks if any */
	iscsi_recvpool_complete();

	/*
	 * Most of the time allocation is done from mempool context i.e.
	 * not directly from the slab, therefore events delivered to
	 * the user-space reliably.
	 *
	 * If cnx_error is not delivered due to OOM, daemon gets the latest
	 * error via per-cnx alarm_skb.
	 *
	 * If PDU is not delivered due to OOM, iSCSI protocol suppouse to
	 * handle this case.
	 */
	skb = len < ISCSI_CTRL_PDU_MAX ?
		mempool_alloc(recvpool, gfp_any()) : alloc_skb(len, gfp_any());
	return skb;
}

static int
iscsi_unicast_skb(struct iscsi_if_cnx *cnx, struct sk_buff *skb, int len)
{
	int rc;

	if (len < ISCSI_CTRL_PDU_MAX)
		skb_get(skb);
	rc = netlink_unicast(nls, skb, daemon_pid, MSG_DONTWAIT);
	if (rc < 0) {
		if (len < ISCSI_CTRL_PDU_MAX)
			mempool_free(skb, recvpool);
		printk("iscsi%d: can not unicast SKB (%d)\n",
		       cnx->host->host_no, rc);
		return rc;
	}

	if (len < ISCSI_CTRL_PDU_MAX && skb != cnx->alarm_skb) {
		unsigned long flags;
		spin_lock_irqsave(&freelock, flags);
		list_add((void*)&skb->cb, &freequeue);
		spin_unlock_irqrestore(&freelock, flags);
	}

	return 0;
}

int iscsi_control_recv_pdu(iscsi_cnx_t cp_cnx, struct iscsi_hdr *hdr,
				char *data, uint32_t data_size)
{
	struct nlmsghdr	*nlh;
	struct sk_buff *skb;
	struct iscsi_uevent *ev;
	struct iscsi_if_cnx *cnx;
	char *pdu;
	int len = NLMSG_SPACE(sizeof(*ev) + sizeof(struct iscsi_hdr) +
			      data_size);

	cnx = iscsi_if_find_cnx(cp_cnx, CNX_TYPE_CP);
	BUG_ON(!cnx);

	skb = iscsi_alloc_skb(len);
	if (!skb) {
		printk("iscsi%d: can not deliver control PDU: OOM\n",
		       cnx->host->host_no);
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
	iscsi_unicast_skb(cnx, skb, len);
	return 0;
}
EXPORT_SYMBOL_GPL(iscsi_control_recv_pdu);

void iscsi_control_cnx_error(iscsi_cnx_t cp_cnx, enum iscsi_err error)
{
	struct nlmsghdr	*nlh;
	struct sk_buff	*skb;
	struct iscsi_uevent *ev;
	struct iscsi_if_cnx *cnx;
	int len = NLMSG_SPACE(sizeof(*ev));
	int resource_error = 0;

	cnx = iscsi_if_find_cnx(cp_cnx, CNX_TYPE_CP);
	BUG_ON(!cnx);

	skb = iscsi_alloc_skb(len);
	if (!skb) {
		unsigned long flags;

		spin_lock_irqsave(&cnxlock, flags);
		if (skb_shared(cnx->alarm_skb)) {
			printk("iscsi%d: gracefully ignored cnx error (%d)\n",
			       cnx->host->host_no, error);
			spin_unlock_irqrestore(&cnxlock, flags);
			return;
		}
		skb = cnx->alarm_skb;
		skb_get(skb);
		resource_error = -ENOBUFS;
		spin_unlock_irqrestore(&cnxlock, flags);
	}

	nlh = __nlmsg_put(skb, daemon_pid, 0, 0, (len - sizeof(*nlh)));
	ev = NLMSG_DATA(nlh);
	ev->transport_id = 0;
	ev->type = ISCSI_KEVENT_CNX_ERROR;
	ev->r.cnxerror.resource_error = resource_error;
	ev->r.cnxerror.error = error;
	ev->r.cnxerror.cnx_handle = cp_cnx;
	iscsi_unicast_skb(cnx, skb, len);
	printk("iscsi%d: detected cnx error (%d:%d)\n", cnx->host->host_no,
	       error, resource_error);
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
		printk("iscsi_if_send_reply: out of memory on alloc_skb\n");
		return -ENOMEM;
	}

	nlh = __nlmsg_put(skb, pid, seq, t, (len - sizeof(*nlh)));
	nlh->nlmsg_flags = flags;
	memcpy(NLMSG_DATA(nlh), payload, size);
	netlink_unicast(nls, skb, pid, MSG_DONTWAIT);
	return 0;
}

/*
 * iSCSI Session's hostdata organization:
 *
 *    /------------------\ <== host->hostdata
 *    | transport_id     |
 *    |------------------| <== iscsi_hostdata(host->hostdata)
 *    | transport's data |
 *    |------------------| <== hostdata_snx(host->hostdata)
 *    | interface's data |
 *    \------------------/
 */

#define hostdata_privsize(_t)	(sizeof(unsigned long) + _t->hostdata_size + \
				 _t->hostdata_size % sizeof(unsigned long) + \
				 sizeof(struct iscsi_if_snx))

#define hostdata_snx(_hostdata)	((void*)_hostdata + sizeof(unsigned long) + \
	 iscsi_if_transport_lookup(*(uint32_t*)_hostdata)->hostdata_size)

static int
iscsi_if_create_snx(struct iscsi_transport *transport, struct iscsi_uevent *ev)
{
	struct iscsi_if_snx *snx;
	struct Scsi_Host *host;
	unsigned long flags;
	int res;

	host = scsi_host_alloc(transport->host_template,
			       hostdata_privsize(transport));
	if (!host) {
		ev->r.c_session_ret.handle = iscsi_handle(NULL);
		printk("iscsi: can not allocate SCSI host for session %p\n",
			iscsi_ptr(ev->u.c_session.session_handle));
		return -ENOMEM;
	}
	host->max_id = 1;
	host->max_channel = 0;
	host->max_lun = transport->max_lun;

	/* store transport_id in hostdata */
	*(uint32_t*)host->hostdata = ev->transport_id;

	ev->r.c_session_ret.handle = transport->create_session(
	       ev->u.c_session.session_handle, ev->u.c_session.initial_cmdsn,
	       host);
	if (ev->r.c_session_ret.handle == iscsi_handle(NULL)) {
		scsi_host_put(host);
		return 0;
	}

	/* host_no becomes assigned SID */
	ev->r.c_session_ret.sid = host->host_no;
	/* initialize snx */
	snx = hostdata_snx(host->hostdata);
	INIT_LIST_HEAD(&snx->connections);
	snx->cp_snx = ev->u.c_session.session_handle;
	snx->dp_snx = ev->r.c_session_ret.handle;

	res = scsi_add_host(host, NULL);
	if (res) {
		transport->destroy_session(ev->r.c_session_ret.handle);
		scsi_host_put(host);
		ev->r.c_session_ret.handle = iscsi_handle(NULL);
		printk("iscsi%d: can not add host (%d)\n",
		       host->host_no, res);
		return res;
	}

	/* add this session to the list of active sessions */
	spin_lock_irqsave(&snxlock, flags);
	list_add(&snx->item, &snxlist);
	spin_unlock_irqrestore(&snxlock, flags);
	printk("iscsi%d: active\n", host->host_no);
	return 0;
}

static int
iscsi_if_destroy_snx(struct iscsi_transport *transport, struct iscsi_uevent *ev)
{
	struct Scsi_Host *host;
	struct iscsi_if_snx *snx;
	unsigned long flags;
	struct iscsi_if_cnx *cnx;

	host = scsi_host_lookup(ev->u.d_session.sid);
	if (host == ERR_PTR(-ENXIO))
		return -EEXIST;
	snx = hostdata_snx(host->hostdata);

	/* check if we have active connections */
	spin_lock_irqsave(&cnxlock, flags);
	list_for_each_entry(cnx, &snx->connections, snxitem) {
		if (cnx->active) {
			printk("iscsi%d: can not destroy session: "
			       "has active connection (%p)\n",
			       host->host_no, iscsi_ptr(cnx->dp_cnx));
			spin_unlock_irqrestore(&cnxlock, flags);
			return -EIO;
		}
	}
	spin_unlock_irqrestore(&cnxlock, flags);

	scsi_remove_host(host);
	transport->destroy_session(ev->u.d_session.session_handle);

	/* now free connections */
	spin_lock_irqsave(&cnxlock, flags);
	list_for_each_entry(cnx, &snx->connections, snxitem) {
		list_del(&cnx->item);
		if (skb_shared(cnx->alarm_skb))
			kfree_skb(cnx->alarm_skb);
		kfree_skb(cnx->alarm_skb);
		kfree(cnx);
	}
	spin_unlock_irqrestore(&cnxlock, flags);

	scsi_host_put(host);
	printk("iscsi%d: deactivated\n", ev->u.d_session.sid);
	return 0;
}

static int
iscsi_if_create_cnx(struct iscsi_transport *transport, struct iscsi_uevent *ev)
{
	struct iscsi_if_snx *snx;
	struct Scsi_Host *host;
	struct iscsi_if_cnx *cnx;

	host = scsi_host_lookup(ev->u.c_cnx.sid);
	if (host == ERR_PTR(-ENXIO))
		return -EEXIST;
	snx = hostdata_snx(host->hostdata);

	cnx = kmalloc(sizeof(struct iscsi_if_cnx), GFP_KERNEL);
	if (!cnx)
		return -ENOMEM;
	memset(cnx, 0, sizeof(struct iscsi_if_cnx));
	cnx->host = host;
	cnx->alarm_skb = alloc_skb(NLMSG_SPACE(sizeof(struct iscsi_uevent)),
				     GFP_KERNEL);
	if (!cnx->alarm_skb) {
		kfree(cnx);
		return -ENOMEM;
	}

	ev->r.handle = transport->create_cnx(ev->u.c_cnx.session_handle,
			     ev->u.c_cnx.cnx_handle, ev->u.c_cnx.cid);
	if (!ev->r.handle) {
		kfree_skb(cnx->alarm_skb);
		kfree(cnx);
	} else {
		unsigned long flags;

		cnx->cp_cnx = ev->u.c_cnx.cnx_handle;
		cnx->dp_cnx = ev->r.handle;
		spin_lock_irqsave(&cnxlock, flags);
		list_add(&cnx->item, &cnxlist);
		list_add(&cnx->snxitem, &snx->connections);
		spin_unlock_irqrestore(&cnxlock, flags);
		cnx->active = 1;
		printk("iscsi%d: cid %d active\n", cnx->host->host_no,
		       ev->u.c_cnx.cid);
	}
	return 0;
}

static int
iscsi_if_destroy_cnx(struct iscsi_transport *transport, struct iscsi_uevent *ev)
{
	unsigned long flags;
	struct iscsi_if_cnx *cnx;

	cnx = iscsi_if_find_cnx(ev->u.d_cnx.cnx_handle, CNX_TYPE_DP);
	if (!cnx)
		return -EEXIST;

	transport->destroy_cnx(ev->u.d_cnx.cnx_handle);
	cnx->active = 0;
	printk("iscsi%d: cid %d deactivated\n", cnx->host->host_no,
	       ev->u.d_cnx.cid);

	spin_lock_irqsave(&cnxlock, flags);
	list_del(&cnx->snxitem);
	spin_unlock_irqrestore(&cnxlock, flags);
	return 0;
}

static int
iscsi_if_recv_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	int err = 0;
	struct iscsi_transport *transport;
	struct iscsi_uevent *ev = NLMSG_DATA(nlh);

	transport = iscsi_if_transport_lookup(ev->transport_id);
	if (!transport)
		return -EEXIST;

	daemon_pid = NETLINK_CREDS(skb)->pid;

	switch (nlh->nlmsg_type) {
	case ISCSI_UEVENT_CREATE_SESSION:
		err = iscsi_if_create_snx(transport, ev);
		break;
	case ISCSI_UEVENT_DESTROY_SESSION:
		err = iscsi_if_destroy_snx(transport, ev);
		break;
	case ISCSI_UEVENT_CREATE_CNX:
		err = iscsi_if_create_cnx(transport, ev);
		break;
	case ISCSI_UEVENT_DESTROY_CNX:
		err = iscsi_if_destroy_cnx(transport, ev);
		break;
	case ISCSI_UEVENT_BIND_CNX: {
		struct iscsi_if_cnx *cnx;
		cnx = iscsi_if_find_cnx(ev->u.b_cnx.cnx_handle, CNX_TYPE_DP);
		if (!cnx)
			return -EEXIST;
		ev->r.retcode = transport->bind_cnx(
			ev->u.b_cnx.session_handle,
			ev->u.b_cnx.cnx_handle,
			ev->u.b_cnx.transport_fd,
			ev->u.b_cnx.is_leading);
		if (!ev->r.retcode && skb_shared(cnx->alarm_skb))
			kfree_skb(cnx->alarm_skb);
		} break;
	case ISCSI_UEVENT_SET_PARAM:
		if (!iscsi_if_find_cnx(ev->u.set_param.cnx_handle, CNX_TYPE_DP))
			return -EEXIST;
		ev->r.retcode = transport->set_param(
			ev->u.set_param.cnx_handle,
			ev->u.set_param.param, ev->u.set_param.value);
		break;
	case ISCSI_UEVENT_START_CNX:
		if (!iscsi_if_find_cnx(ev->u.start_cnx.cnx_handle, CNX_TYPE_DP))
			return -EEXIST;
		ev->r.retcode = transport->start_cnx(
			ev->u.start_cnx.cnx_handle);
		break;
	case ISCSI_UEVENT_STOP_CNX:
		if (!iscsi_if_find_cnx(ev->u.stop_cnx.cnx_handle, CNX_TYPE_DP))
			return -EEXIST;
		transport->stop_cnx(ev->u.stop_cnx.cnx_handle,
			ev->u.stop_cnx.flag);
		break;
	case ISCSI_UEVENT_SEND_PDU:
		if (!iscsi_if_find_cnx(ev->u.send_pdu.cnx_handle, CNX_TYPE_DP))
			return -EEXIST;
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

	down(&callsema);
	while ((skb = skb_dequeue(&sk->sk_receive_queue)) != NULL) {
		while (skb->len >= NLMSG_SPACE(0)) {
			int err;
			uint32_t rlen;
			struct nlmsghdr	*nlh;
			struct iscsi_uevent *ev;

			nlh = (struct nlmsghdr *)skb->data;
			if (nlh->nlmsg_len < sizeof(*nlh) ||
			    skb->len < nlh->nlmsg_len) {
				break;
			}
			ev = NLMSG_DATA(nlh);
			rlen = NLMSG_ALIGN(nlh->nlmsg_len);
			if (rlen > skb->len)
				rlen = skb->len;
			err = iscsi_if_recv_msg(skb, nlh);
			if (err) {
				ev->type = ISCSI_KEVENT_IF_ERROR;
				ev->iferror = err;
			}
			do {
				err = iscsi_if_send_reply(
					NETLINK_CREDS(skb)->pid, nlh->nlmsg_seq,
					nlh->nlmsg_type, 0, 0, ev, sizeof(*ev));
			} while (err);
			skb_pull(skb, rlen);
		}
		kfree_skb(skb);
	}
	up(&callsema);

	/* now complete receive tasks if any */
	iscsi_recvpool_complete();
}

static void*
iscsi_mempool_alloc_skb(int gfp_mask, void *pool_data)
{
	return alloc_skb(ISCSI_CTRL_PDU_MAX, gfp_mask);
}

static void
iscsi_mempool_free_skb(void *element, void *pool_data)
{
	kfree_skb(element);
}

int iscsi_register_transport(struct iscsi_transport *ops, int id)
{
	transport_table[id] = ops;
	return 0;
}
EXPORT_SYMBOL_GPL(iscsi_register_transport);

void iscsi_unregister_transport(int id)
{
	down(&callsema);
	transport_table[id] = NULL;
	up(&callsema);
}
EXPORT_SYMBOL_GPL(iscsi_unregister_transport);

static int __init
iscsi_if_init(void)
{
	spin_lock_init(&freelock);
	spin_lock_init(&cnxlock);
	spin_lock_init(&snxlock);

	nls = netlink_kernel_create(NETLINK_ISCSI, iscsi_if_rx);
	if (nls == NULL)
		return -ENOBUFS;

	recvpool = mempool_create(ISCSI_CTRL_POOL_MAX,
			iscsi_mempool_alloc_skb, iscsi_mempool_free_skb, NULL);
	if (!recvpool) {
		sock_release(nls->sk_socket);
		return -ENOMEM;
	}

#ifdef CONFIG_SCSI_ISCSI_ATTRS
	iscsi_transportt = iscsi_attach_transport(&iscsi_fnt);
	if (!iscsi_transportt) {
		mempool_destroy(recvpool);
		sock_release(nls->sk_socket);
		return -ENOMEM;
	}
#endif

	printk(KERN_INFO "Open-iSCSI Interface, version "
			ISCSI_VERSION_STR " variant (" ISCSI_DATE_STR ")\n");

	return 0;
}

static void __exit
iscsi_if_exit(void)
{
#ifdef CONFIG_SCSI_ISCSI_ATTRS
	iscsi_release_transport(iscsi_transportt);
#endif
	mempool_destroy(recvpool);
	sock_release(nls->sk_socket);
}

module_init(iscsi_if_init);
module_exit(iscsi_if_exit);
