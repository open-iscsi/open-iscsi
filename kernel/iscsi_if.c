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
#ifdef CONFIG_SCSI_ISCSI_ATTRS
#include <scsi/scsi_transport_iscsi.h>
#endif
#include <iscsi_iftrans.h>
#include <iscsi_ifev.h>

MODULE_AUTHOR("Dmitry Yusupov <dmitry_yus@yahoo.com>, "
	      "Alex Aizman <itn780@yahoo.com>");
MODULE_DESCRIPTION("Open-iSCSI Interface");
MODULE_LICENSE("GPL");

static struct iscsi_transport *transport_table[ISCSI_TRANSPORT_MAX];
static struct sock *nls;
static int daemon_pid;
static DECLARE_MUTEX(callsema);

struct mempool_zone {
	mempool_t *pool;
	volatile int allocated;
	int size;
	int max;
	int hiwat;
	struct list_head freequeue;
	spinlock_t freelock;
};

static struct mempool_zone z_reply;

#define Z_SIZE_REPLY	NLMSG_SPACE(sizeof(struct iscsi_uevent))
#define Z_MAX_REPLY	8
#define Z_HIWAT_REPLY	6

#define Z_SIZE_PDU	NLMSG_SPACE(sizeof(struct iscsi_uevent) + \
				    sizeof(struct iscsi_hdr) + \
				    DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH)
#define Z_MAX_PDU	8
#define Z_HIWAT_PDU	6

#define Z_SIZE_ERROR	NLMSG_SPACE(sizeof(struct iscsi_uevent))
#define Z_MAX_ERROR	16
#define Z_HIWAT_ERROR	12

struct iscsi_if_cnx {
	struct list_head item;		/* item in cnxlist */
	struct list_head snxitem;	/* item in snx->connections */
	iscsi_cnx_t cnxh;
	volatile int active;
	struct Scsi_Host *host;		/* originated shost */
	struct iscsi_transport *transport;
	struct mempool_zone z_error;
	struct mempool_zone z_pdu;
	struct list_head freequeue;
};
static LIST_HEAD(cnxlist);
static DEFINE_SPINLOCK(cnxlock);

struct iscsi_if_snx {
	struct list_head item;	/* item in snxlist */
	struct list_head connections;
	iscsi_snx_t snxh;
	struct iscsi_transport *transport;
};
static LIST_HEAD(snxlist);
static DEFINE_SPINLOCK(snxlock);

#define H_TYPE_TRANS	1
#define H_TYPE_HOST	2
static struct iscsi_if_cnx*
iscsi_if_find_cnx(uint64_t key, int type)
{
	unsigned long flags;
	struct iscsi_if_cnx *cnx;

	spin_lock_irqsave(&cnxlock, flags);
	list_for_each_entry(cnx, &cnxlist, item) {
		if ((type == H_TYPE_TRANS && cnx->cnxh == key) ||
		    (type == H_TYPE_HOST && cnx->host == iscsi_ptr(key))) {
			spin_unlock_irqrestore(&cnxlock, flags);
			return cnx;
		}
	}
	spin_unlock_irqrestore(&cnxlock, flags);
	return NULL;
}

static struct iscsi_if_snx*
iscsi_if_find_snx(struct iscsi_transport *t)
{
	unsigned long flags;
	struct iscsi_if_snx *snx;

	spin_lock_irqsave(&snxlock, flags);
	list_for_each_entry(snx, &snxlist, item) {
		if (snx->transport == t) {
			spin_unlock_irqrestore(&snxlock, flags);
			return snx;
		}
	}
	spin_unlock_irqrestore(&snxlock, flags);
	return NULL;
}

static int
iscsi_if_transport_lookup(struct iscsi_transport *t)
{
	int i;

	for (i=0; i < ISCSI_TRANSPORT_MAX; i++) {
		if (transport_table[i] == t) {
			return i;
		}
	}
	return -1;
}

#ifdef CONFIG_SCSI_ISCSI_ATTRS
static struct scsi_transport_template *iscsi_transportt;
#define iscsi_transport_get_fn(_field, _param)				\
static void								\
iscsi_if_get_##_field (struct scsi_target *stgt)			\
{									\
	struct Scsi_Host *host = dev_to_shost(stgt->dev.parent);	\
	struct iscsi_if_cnx *cnx = iscsi_if_find_cnx(			\
				     iscsi_handle(host), H_TYPE_HOST);	\
	if (cnx) {							\
		uint32_t value = 0;					\
		struct iscsi_transport *t =				\
				iscsi_ptr(*(uint64_t *)host->hostdata);	\
		t->get_param(cnx->cnxh, _param, &value);		\
		iscsi_##_field(stgt) = value;				\
	} else								\
		iscsi_##_field(stgt) = 0;				\
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

static void*
mempool_zone_alloc_skb(unsigned int gfp_mask, void *pool_data)
{
	struct mempool_zone *zone = pool_data;

	return alloc_skb(zone->size, gfp_mask);
}

static void
mempool_zone_free_skb(void *element, void *pool_data)
{
	kfree_skb(element);
}

static void
mempool_zone_complete(struct mempool_zone *zone)
{
	unsigned long flags;
	struct list_head *lh, *n;

	spin_lock_irqsave(&zone->freelock, flags);
	list_for_each_safe(lh, n, &zone->freequeue) {
		struct sk_buff *skb = (struct sk_buff *)((char *)lh -
				offsetof(struct sk_buff, cb));
		if (!skb_shared(skb)) {
			list_del((void*)&skb->cb);
			mempool_free(skb, zone->pool);
			zone->allocated--;
			BUG_ON(zone->allocated < 0);
		}
	}
	spin_unlock_irqrestore(&zone->freelock, flags);
}

static int zone_init(struct mempool_zone *zp, unsigned max,
		unsigned size, unsigned hiwat)
{
	zp->pool = mempool_create(max, mempool_zone_alloc_skb,
				  mempool_zone_free_skb, zp);
	if (!zp->pool)
		return -ENOMEM;

	zp->max = max;
	zp->size = size;
	zp->hiwat = hiwat;

	INIT_LIST_HEAD(&zp->freequeue);
	spin_lock_init(&zp->freelock);
	zp->allocated = 0;

	return 0;
}


static struct sk_buff*
mempool_zone_get_skb(struct mempool_zone *zone)
{
	struct sk_buff *skb;

	if (zone->allocated < zone->max) {
		skb = mempool_alloc(zone->pool, GFP_ATOMIC);
		BUG_ON(!skb);
		zone->allocated++;
	} else
		return NULL;

	return skb;
}

static int
iscsi_unicast_skb(struct mempool_zone *zone, struct sk_buff *skb)
{
	unsigned long flags;
	int rc;

	skb_get(skb);
	rc = netlink_unicast(nls, skb, daemon_pid, MSG_DONTWAIT);
	if (rc < 0) {
		mempool_free(skb, zone->pool);
		printk("iscsi: can not unicast skb (%d)\n", rc);
		return rc;
	}

	spin_lock_irqsave(&zone->freelock, flags);
	list_add((void*)&skb->cb, &zone->freequeue);
	spin_unlock_irqrestore(&zone->freelock, flags);

	return 0;
}

int iscsi_recv_pdu(iscsi_cnx_t cnxh, struct iscsi_hdr *hdr,
				char *data, uint32_t data_size)
{
	struct nlmsghdr	*nlh;
	struct sk_buff *skb;
	struct iscsi_uevent *ev;
	struct iscsi_if_cnx *cnx;
	char *pdu;
	int len = NLMSG_SPACE(sizeof(*ev) + sizeof(struct iscsi_hdr) +
			      data_size);

	cnx = iscsi_if_find_cnx(cnxh, H_TYPE_TRANS);
	BUG_ON(!cnx);

	mempool_zone_complete(&cnx->z_pdu);

	skb = mempool_zone_get_skb(&cnx->z_pdu);
	if (!skb) {
		iscsi_cnx_error(cnxh, ISCSI_ERR_CNX_FAILED);
		printk("iscsi%d: can not deliver control PDU: OOM\n",
		       cnx->host->host_no);
		return -ENOMEM;
	}

	nlh = __nlmsg_put(skb, daemon_pid, 0, 0, (len - sizeof(*nlh)));
	ev = NLMSG_DATA(nlh);
	memset(ev, 0, sizeof(*ev));
	ev->transport_handle = iscsi_handle(cnx->transport);
	ev->type = ISCSI_KEVENT_RECV_PDU;
	if (cnx->z_pdu.allocated >= cnx->z_pdu.hiwat)
		ev->iferror = -ENOMEM;
	ev->r.recv_req.cnx_handle = cnxh;
	pdu = (char*)ev + sizeof(*ev);
	memcpy(pdu, hdr, sizeof(struct iscsi_hdr));
	memcpy(pdu + sizeof(struct iscsi_hdr), data, data_size);

	return iscsi_unicast_skb(&cnx->z_pdu, skb);
}
EXPORT_SYMBOL_GPL(iscsi_recv_pdu);

void iscsi_cnx_error(iscsi_cnx_t cnxh, enum iscsi_err error)
{
	struct nlmsghdr	*nlh;
	struct sk_buff	*skb;
	struct iscsi_uevent *ev;
	struct iscsi_if_cnx *cnx;
	int len = NLMSG_SPACE(sizeof(*ev));

	cnx = iscsi_if_find_cnx(cnxh, H_TYPE_TRANS);
	BUG_ON(!cnx);

	mempool_zone_complete(&cnx->z_error);

	skb = mempool_zone_get_skb(&cnx->z_error);
	if (!skb) {
		printk("iscsi%d: gracefully ignored cnx error (%d)\n",
		       cnx->host->host_no, error);
		return;
	}

	nlh = __nlmsg_put(skb, daemon_pid, 0, 0, (len - sizeof(*nlh)));
	ev = NLMSG_DATA(nlh);
	ev->transport_handle = iscsi_handle(cnx->transport);
	ev->type = ISCSI_KEVENT_CNX_ERROR;
	if (cnx->z_error.allocated >= cnx->z_error.hiwat)
		ev->iferror = -ENOMEM;
	ev->r.cnxerror.error = error;
	ev->r.cnxerror.cnx_handle = cnxh;

	iscsi_unicast_skb(&cnx->z_error, skb);

	printk("iscsi%d: detected cnx error (%d)\n", cnx->host->host_no, error);
}
EXPORT_SYMBOL_GPL(iscsi_cnx_error);

static int
iscsi_if_send_reply(int pid, int seq, int type, int done, int multi,
		      void *payload, int size)
{
	struct sk_buff	*skb;
	struct nlmsghdr	*nlh;
	int len = NLMSG_SPACE(size);
	int flags = multi ? NLM_F_MULTI : 0;
	int t = done ? NLMSG_DONE  : type;

	mempool_zone_complete(&z_reply);

	skb = mempool_zone_get_skb(&z_reply);
	/*
	 * user is supposed to react on iferror == -ENOMEM;
	 * see iscsi_if_rx().
	 */
	BUG_ON(!skb);

	nlh = __nlmsg_put(skb, pid, seq, t, (len - sizeof(*nlh)));
	nlh->nlmsg_flags = flags;
	memcpy(NLMSG_DATA(nlh), payload, size);
	return iscsi_unicast_skb(&z_reply, skb);
}

/*
 * iSCSI Session's hostdata organization:
 *
 *    /------------------\ <== host->hostdata
 *    | transport        |
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
			((struct iscsi_transport *) \
			 iscsi_ptr(*(uint64_t *)_hostdata))->hostdata_size)

static int
iscsi_if_create_snx(struct iscsi_transport *transport, struct iscsi_uevent *ev)
{
	struct iscsi_if_snx *snx;
	struct Scsi_Host *host;
	unsigned long flags;
	int error;

	if (!try_module_get(transport->owner))
		return -EPERM;

	host = scsi_host_alloc(transport->host_template,
			       hostdata_privsize(transport));
	if (!host) {
		ev->r.c_session_ret.session_handle = iscsi_handle(NULL);
		printk("iscsi: can not allocate SCSI host for session\n");
		error = -ENOMEM;
		goto out_module_put;
	}
	host->max_id = 1;
	host->max_channel = 0;
	host->max_lun = transport->max_lun;
	host->max_cmd_len = transport->max_cmd_len;
#ifdef CONFIG_SCSI_ISCSI_ATTRS
	host->transportt = iscsi_transportt;
#endif

	/* store struct iscsi_transport in hostdata */
	*(uint64_t*)host->hostdata = ev->transport_handle;

	ev->r.c_session_ret.session_handle = transport->create_session(
					ev->u.c_session.initial_cmdsn, host);
	if (ev->r.c_session_ret.session_handle == iscsi_handle(NULL)) {
		error = 0;
		goto out_host_put;
	}

	/* host_no becomes assigned SID */
	ev->r.c_session_ret.sid = host->host_no;
	/* initialize snx */
	snx = hostdata_snx(host->hostdata);
	INIT_LIST_HEAD(&snx->connections);
	snx->snxh = ev->r.c_session_ret.session_handle;
	snx->transport = transport;

	error = scsi_add_host(host, NULL);
	if (error)
		goto out_destroy_session;

	/* add this session to the list of active sessions */
	spin_lock_irqsave(&snxlock, flags);
	list_add(&snx->item, &snxlist);
	spin_unlock_irqrestore(&snxlock, flags);

	return 0;

 out_destroy_session:
	transport->destroy_session(ev->r.c_session_ret.session_handle);
	ev->r.c_session_ret.session_handle = iscsi_handle(NULL);
 out_host_put:
	scsi_host_put(host);
 out_module_put:
	module_put(transport->owner);
	return error;
}

static int
iscsi_if_destroy_snx(struct iscsi_transport *transport, struct iscsi_uevent *ev)
{
	struct Scsi_Host *host;
	struct iscsi_if_snx *snx;
	unsigned long flags;
	struct iscsi_if_cnx *cnx;

	host = scsi_host_lookup(ev->u.d_session.sid);
	if (host == ERR_PTR(-ENXIO)) {
		printk("can not find session with host_no %d\n",
			ev->u.d_session.sid);
		return -EEXIST;
	}
	scsi_host_put(host);
	snx = hostdata_snx(host->hostdata);

	/* check if we have active connections */
	spin_lock_irqsave(&cnxlock, flags);
	list_for_each_entry(cnx, &snx->connections, snxitem) {
		if (cnx->active) {
			printk("iscsi%d: can not destroy session: "
			       "has active connection (%p)\n",
			       host->host_no, iscsi_ptr(cnx->cnxh));
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
		mempool_destroy(cnx->z_pdu.pool);
		mempool_destroy(cnx->z_error.pool);
		kfree(cnx);
	}
	spin_unlock_irqrestore(&cnxlock, flags);

	/* remove this session from the list of active sessions */
	spin_lock_irqsave(&snxlock, flags);
	list_del(&snx->item);
	spin_unlock_irqrestore(&snxlock, flags);

	scsi_host_put(host);
	module_put(transport->owner);
	return 0;
}

static int
iscsi_if_create_cnx(struct iscsi_transport *transport, struct iscsi_uevent *ev)
{
	struct iscsi_if_snx *snx;
	struct Scsi_Host *host;
	struct iscsi_if_cnx *cnx;
	unsigned long flags;
	int error;

	host = scsi_host_lookup(ev->u.c_cnx.sid);
	if (host == ERR_PTR(-ENXIO))
		return -EEXIST;
	scsi_host_put(host);
	snx = hostdata_snx(host->hostdata);

	cnx = kmalloc(sizeof(struct iscsi_if_cnx), GFP_KERNEL);
	if (!cnx)
		return -ENOMEM;
	memset(cnx, 0, sizeof(struct iscsi_if_cnx));
	cnx->host = host;
	snx->transport = transport;

	error = zone_init(&cnx->z_pdu, Z_MAX_PDU, Z_SIZE_PDU, Z_HIWAT_PDU);
	if (error) {
		printk("iscsi%d: can not allocate pdu zone for new cnx\n",
		       host->host_no);
		goto out_free_cnx;
	}
	error = zone_init(&cnx->z_error, Z_MAX_ERROR,
			  Z_SIZE_ERROR, Z_HIWAT_ERROR);
	if (error) {
		printk("iscsi%d: can not allocate error zone for new cnx\n",
		       host->host_no);
		goto out_free_pdu_pool;
	}

	ev->r.handle = transport->create_cnx(ev->u.c_cnx.session_handle,
					ev->u.c_cnx.cid);
	if (!ev->r.handle) {
		error = -ENODEV;
		goto out_free_error_pool;
	}

	cnx->cnxh = ev->r.handle;

	spin_lock_irqsave(&cnxlock, flags);
	list_add(&cnx->item, &cnxlist);
	list_add(&cnx->snxitem, &snx->connections);
	spin_unlock_irqrestore(&cnxlock, flags);

	cnx->active = 1;
	return 0;

 out_free_error_pool:
	mempool_destroy(cnx->z_error.pool);
 out_free_pdu_pool:
	mempool_destroy(cnx->z_pdu.pool);
 out_free_cnx:
	kfree(cnx);
	return error;
}

static int
iscsi_if_destroy_cnx(struct iscsi_transport *transport, struct iscsi_uevent *ev)
{
	unsigned long flags;
	struct iscsi_if_cnx *cnx;

	cnx = iscsi_if_find_cnx(ev->u.d_cnx.cnx_handle, H_TYPE_TRANS);
	if (!cnx)
		return -EEXIST;

	transport->destroy_cnx(ev->u.d_cnx.cnx_handle);
	cnx->active = 0;

	spin_lock_irqsave(&cnxlock, flags);
	list_del(&cnx->snxitem);
	spin_unlock_irqrestore(&cnxlock, flags);
	return 0;
}

static int
iscsi_if_recv_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	int err = 0;
	struct iscsi_uevent *ev = NLMSG_DATA(nlh);
	struct iscsi_transport *transport = iscsi_ptr(ev->transport_handle);

	if (nlh->nlmsg_type != ISCSI_UEVENT_TRANS_LIST &&
	    iscsi_if_transport_lookup(transport) < 0)
		return -EEXIST;

	daemon_pid = NETLINK_CREDS(skb)->pid;

	switch (nlh->nlmsg_type) {
	case ISCSI_UEVENT_TRANS_LIST: {
		int i;
		for (i=0; i < ISCSI_TRANSPORT_MAX; i++) {
			if (transport_table[i]) {
				ev->r.t_list.elements[i].trans_handle =
					iscsi_handle(transport_table[i]);
				strncpy(ev->r.t_list.elements[i].name,
					transport_table[i]->name,
					ISCSI_TRANSPORT_NAME_MAXLEN);
			} else
				ev->r.t_list.elements[i].trans_handle =
					iscsi_handle(NULL);
		}
	      } break;
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
	case ISCSI_UEVENT_BIND_CNX:
		if (!iscsi_if_find_cnx(ev->u.b_cnx.cnx_handle, H_TYPE_TRANS))
			return -EEXIST;
		ev->r.retcode = transport->bind_cnx(
			ev->u.b_cnx.session_handle,
			ev->u.b_cnx.cnx_handle,
			ev->u.b_cnx.transport_fd,
			ev->u.b_cnx.is_leading);
		break;
	case ISCSI_UEVENT_SET_PARAM:
		if (!iscsi_if_find_cnx(ev->u.set_param.cnx_handle,
				       H_TYPE_TRANS))
			return -EEXIST;
		ev->r.retcode = transport->set_param(
			ev->u.set_param.cnx_handle,
			ev->u.set_param.param, ev->u.set_param.value);
		break;
	case ISCSI_UEVENT_START_CNX:
		if (!iscsi_if_find_cnx(ev->u.start_cnx.cnx_handle,
				       H_TYPE_TRANS))
			return -EEXIST;
		ev->r.retcode = transport->start_cnx(
			ev->u.start_cnx.cnx_handle);
		break;
	case ISCSI_UEVENT_STOP_CNX:
		if (!iscsi_if_find_cnx(ev->u.stop_cnx.cnx_handle, H_TYPE_TRANS))
			return -EEXIST;
		transport->stop_cnx(ev->u.stop_cnx.cnx_handle,
			ev->u.stop_cnx.flag);
		break;
	case ISCSI_UEVENT_SEND_PDU:
		if (!iscsi_if_find_cnx(ev->u.send_pdu.cnx_handle,
				       H_TYPE_TRANS))
			return -EEXIST;
		ev->r.retcode = transport->send_pdu(
		       ev->u.send_pdu.cnx_handle,
		       (struct iscsi_hdr*)((char*)ev + sizeof(*ev)),
		       (char*)ev + sizeof(*ev) + ev->u.send_pdu.hdr_size,
			ev->u.send_pdu.data_size);
		break;
	case ISCSI_UEVENT_GET_STATS: {
		struct iscsi_stats *stats;
		struct sk_buff *skbstat;
		struct iscsi_if_cnx *cnx;
		struct nlmsghdr	*nlhstat;
		struct iscsi_uevent *evstat;
		int len = NLMSG_SPACE(sizeof(*ev) +
				DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH);
		int err;

		cnx = iscsi_if_find_cnx(ev->u.get_stats.cnx_handle,
					H_TYPE_TRANS);
		if (!cnx)
			return -EEXIST;

		do {
			skbstat = mempool_zone_get_skb(&cnx->z_pdu);
			if (!skbstat) {
				printk("iscsi%d: can not deliver stats: OOM\n",
				       cnx->host->host_no);
				return -ENOMEM;
			}

			nlhstat = __nlmsg_put(skbstat, daemon_pid, 0, 0,
						(len - sizeof(*nlhstat)));
			evstat = NLMSG_DATA(nlhstat);
			memset(evstat, 0, sizeof(*evstat));
			evstat->transport_handle = iscsi_handle(cnx->transport);
			evstat->type = nlh->nlmsg_type;
			if (cnx->z_pdu.allocated >= cnx->z_pdu.hiwat)
				evstat->iferror = -ENOMEM;
			evstat->u.get_stats.cnx_handle =
					ev->u.get_stats.cnx_handle;
			stats = (struct iscsi_stats *)
					((char*)evstat + sizeof(*evstat));
			memset(stats, 0, sizeof(*stats));

			transport->get_stats(ev->u.get_stats.cnx_handle, stats);

			err = iscsi_unicast_skb(&cnx->z_pdu, skbstat);
		} while (err < 0 && err != -ECONNREFUSED);
		} break;
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
				/*
				 * special case for GET_STATS:
				 * on success - sending reply and stats from
				 * inside of if_recv_msg(),
				 * on error - fall through.
				 */
				if (ev->type == ISCSI_UEVENT_GET_STATS && !err)
					break;
				err = iscsi_if_send_reply(
					NETLINK_CREDS(skb)->pid, nlh->nlmsg_seq,
					nlh->nlmsg_type, 0, 0, ev, sizeof(*ev));
				if (z_reply.allocated >= z_reply.hiwat)
					ev->iferror = -ENOMEM;
			} while (err < 0 && err != -ECONNREFUSED);
			skb_pull(skb, rlen);
		}
		kfree_skb(skb);
	}
	up(&callsema);
}

int iscsi_register_transport(struct iscsi_transport *t)
{
	int i;

	BUG_ON(!t);
	for (i=0; i < ISCSI_TRANSPORT_MAX; i++) {
		if (transport_table[i] == t)
			return -EEXIST;
		if (!transport_table[i]) {
			transport_table[i] = t;
			printk("iscsi: registered transport (%d - %s)\n",
			       i, t->name);
			return 0;
		}
	}
	return -EPERM;
}
EXPORT_SYMBOL_GPL(iscsi_register_transport);

int iscsi_unregister_transport(struct iscsi_transport *t)
{
	int id;

	BUG_ON(!t);
	down(&callsema);
	if (iscsi_if_find_snx(t)) {
		up(&callsema);
		return -EPERM;
	}
	id = iscsi_if_transport_lookup(t);
	BUG_ON (id < 0);
	transport_table[id] = NULL;
	up(&callsema);
	return 0;
}
EXPORT_SYMBOL_GPL(iscsi_unregister_transport);

static int
iscsi_rcv_nl_event(struct notifier_block *this,
                 unsigned long event, void *ptr)
{
	struct netlink_notify *n = ptr;

	if (event == NETLINK_URELEASE &&
	    n->protocol == NETLINK_ISCSI && n->pid) {
		struct iscsi_if_cnx *cnx;
		unsigned long flags;

		mempool_zone_complete(&z_reply);
		spin_lock_irqsave(&cnxlock, flags);
		list_for_each_entry(cnx, &cnxlist, item) {
			mempool_zone_complete(&cnx->z_error);
			mempool_zone_complete(&cnx->z_pdu);
		}
		spin_unlock_irqrestore(&cnxlock, flags);
	}

	return NOTIFY_DONE;
}

static struct notifier_block iscsi_nl_notifier = {
	.notifier_call	= iscsi_rcv_nl_event,
};

static int __init
iscsi_if_init(void)
{
	int error;

	netlink_register_notifier(&iscsi_nl_notifier);
	nls = netlink_kernel_create(NETLINK_ISCSI, iscsi_if_rx);
	if (!nls) {
		error = -ENOBUFS;
		goto out_unregister_notifier;
	}

	error = zone_init(&z_reply, Z_MAX_REPLY, Z_SIZE_REPLY, Z_HIWAT_REPLY);
	if (error)
		goto out_release_sock;

#ifdef CONFIG_SCSI_ISCSI_ATTRS
	iscsi_transportt = iscsi_attach_transport(&iscsi_fnt);
	if (!iscsi_transportt) {
		error = -ENOMEM;
		goto out_reply_pool_destroy;
	}
#endif

	printk(KERN_INFO "Open-iSCSI Interface, version "
			ISCSI_VERSION_STR " variant (" ISCSI_DATE_STR ")\n");

	return 0;

#ifdef CONFIG_SCSI_ISCSI_ATTRS
 out_reply_pool_destroy:
	mempool_destroy(z_reply.pool);
#endif
 out_release_sock:
	sock_release(nls->sk_socket);
 out_unregister_notifier:
	netlink_unregister_notifier(&iscsi_nl_notifier);
	return error;
}

static void __exit
iscsi_if_exit(void)
{
#ifdef CONFIG_SCSI_ISCSI_ATTRS
	iscsi_release_transport(iscsi_transportt);
#endif
	mempool_destroy(z_reply.pool);
	sock_release(nls->sk_socket);
	netlink_unregister_notifier(&iscsi_nl_notifier);
}

module_init(iscsi_if_init);
module_exit(iscsi_if_exit);
