/*
 * iSCSI transport class definitions
 *
 * Copyright (C) IBM Corporation, 2004
 * Copyright (C) Mike Christie, Dmitry Yusupov, Alex Aizman, 2004 - 2005
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 */
#include <linux/module.h>
#include <linux/mempool.h>
#include <net/tcp.h>
#include <scsi/scsi.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_transport.h>
#include <scsi_transport_iscsi.h>
#include <iscsi_ifev.h>

#define ISCSI_SESSION_ATTRS 8
#define ISCSI_CONN_ATTRS 6

struct iscsi_internal {
	struct scsi_transport_template t;
	struct iscsi_transport *tt;

	/*
	 * based on transport capabilities, at register time we sets these
	 * bits to tell the transport class it wants the attributes
	 * displayed in sysfs.
	 */
	uint32_t param_mask;

	/*
	 * We do not have any private or other attrs.
	 */
	struct transport_container connection_cont;
	struct class_device_attribute *connection_attrs[ISCSI_CONN_ATTRS + 1];
	struct transport_container session_cont;
	struct class_device_attribute *session_attrs[ISCSI_SESSION_ATTRS + 1];
};

#define to_iscsi_internal(tmpl) container_of(tmpl, struct iscsi_internal, t)

static DECLARE_TRANSPORT_CLASS(iscsi_session_class,
			       "iscsi_session",
			       NULL,
			       NULL,
			       NULL);

static DECLARE_TRANSPORT_CLASS(iscsi_connection_class,
			       "iscsi_connection",
			       NULL,
			       NULL,
			       NULL);

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
	struct device dev;		/* sysfs transport/container device */
	struct iscsi_transport *transport;
	struct mempool_zone z_error;
	struct mempool_zone z_pdu;
	struct list_head freequeue;
};

#define iscsi_dev_to_if_cnx(_dev) \
	container_of(_dev, struct iscsi_if_cnx, dev)

#define iscsi_cdev_to_if_cnx(_cdev) \
	iscsi_dev_to_if_cnx(_cdev->dev)

static LIST_HEAD(cnxlist);
static DEFINE_SPINLOCK(cnxlock);

struct iscsi_if_snx {
	struct list_head item;	/* item in snxlist */
	struct list_head connections;
	iscsi_snx_t snxh;
	struct iscsi_transport *transport;
	struct device dev;	/* sysfs transport/container device */
};

#define iscsi_dev_to_if_snx(_dev) \
	container_of(_dev, struct iscsi_if_snx, dev)

#define iscsi_cdev_to_if_snx(_cdev) \
	iscsi_dev_to_if_snx(_cdev->dev)

#define iscsi_if_snx_to_shost(_snx) \
	dev_to_shost(_snx->dev.parent)

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

	for (i = 0; i < ISCSI_TRANSPORT_MAX; i++)
		if (transport_table[i] == t)
			return i;
	return -1;
}

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
 *    *------------------* <== host->hostdata
 *    | transport        |
 *    |------------------| <== iscsi_hostdata(host->hostdata)
 *    | transport's data |
 *    |------------------| <== hostdata_snx(host->hostdata)
 *    | interface's data |
 *    *------------------*
 */

#define hostdata_privsize(_t)	(sizeof(unsigned long) + _t->hostdata_size + \
				 _t->hostdata_size % sizeof(unsigned long) + \
				 sizeof(struct iscsi_if_snx))

#define hostdata_snx(_hostdata)	((void*)_hostdata + sizeof(unsigned long) + \
			((struct iscsi_transport *) \
			 iscsi_ptr(*(uint64_t *)_hostdata))->hostdata_size)

static void iscsi_if_snx_dev_release(struct device *dev)
{
	struct iscsi_if_snx *snx = iscsi_dev_to_if_snx(dev);
	struct iscsi_transport *transport = snx->transport;
	struct Scsi_Host *shost = iscsi_if_snx_to_shost(snx);
	struct iscsi_if_cnx *cnx;
	unsigned long flags;

	/* now free connections */
	spin_lock_irqsave(&cnxlock, flags);
	list_for_each_entry(cnx, &snx->connections, snxitem) {
		list_del(&cnx->item);
		mempool_destroy(cnx->z_pdu.pool);
		mempool_destroy(cnx->z_error.pool);
		kfree(cnx);
	}
	spin_unlock_irqrestore(&cnxlock, flags);
	scsi_host_put(shost);
	module_put(transport->owner);
}

static int
iscsi_if_create_snx(struct iscsi_transport *transport, struct iscsi_uevent *ev)
{
	struct iscsi_if_snx *snx;
	struct Scsi_Host *shost;
	unsigned long flags;
	int error;

	if (!try_module_get(transport->owner))
		return -EPERM;

	shost = scsi_host_alloc(transport->host_template,
				hostdata_privsize(transport));
	if (!shost) {
		ev->r.c_session_ret.session_handle = iscsi_handle(NULL);
		printk("iscsi: can not allocate SCSI host for session\n");
		error = -ENOMEM;
		goto out_module_put;
	}
	shost->max_id = 1;
	shost->max_channel = 0;
	shost->max_lun = transport->max_lun;
	shost->max_cmd_len = transport->max_cmd_len;
	shost->transportt = transport->scsi_transport;

	/* store struct iscsi_transport in hostdata */
	*(uint64_t*)shost->hostdata = ev->transport_handle;

	ev->r.c_session_ret.session_handle = transport->create_session(
					ev->u.c_session.initial_cmdsn, shost);
	if (ev->r.c_session_ret.session_handle == iscsi_handle(NULL)) {
		error = 0;
		goto out_host_put;
	}

	/* host_no becomes assigned SID */
	ev->r.c_session_ret.sid = shost->host_no;
	/* initialize snx */
	snx = hostdata_snx(shost->hostdata);
	INIT_LIST_HEAD(&snx->connections);
	snx->snxh = ev->r.c_session_ret.session_handle;
	snx->transport = transport;

	error = scsi_add_host(shost, NULL);
	if (error)
		goto out_destroy_session;

	/*
	 * this is released in the dev's release function)
	 */
	scsi_host_get(shost);
	snprintf(snx->dev.bus_id, BUS_ID_SIZE, "session%u", shost->host_no);
	snx->dev.parent = &shost->shost_gendev;
	snx->dev.release = iscsi_if_snx_dev_release;
	error = device_register(&snx->dev);
	if (error) {
		printk(KERN_ERR "iscsi: could not register session%d's dev\n",
		       shost->host_no);
		goto out_remove_host;
	}
	transport_register_device(&snx->dev);

	/* add this session to the list of active sessions */
	spin_lock_irqsave(&snxlock, flags);
	list_add(&snx->item, &snxlist);
	spin_unlock_irqrestore(&snxlock, flags);

	return 0;

 out_remove_host:
	scsi_remove_host(shost);
 out_destroy_session:
	transport->destroy_session(ev->r.c_session_ret.session_handle);
	ev->r.c_session_ret.session_handle = iscsi_handle(NULL);
 out_host_put:
	scsi_host_put(shost);
 out_module_put:
	module_put(transport->owner);
	return error;
}

static int
iscsi_if_destroy_snx(struct iscsi_transport *transport, struct iscsi_uevent *ev)
{
	struct Scsi_Host *shost;
	struct iscsi_if_snx *snx;
	unsigned long flags;
	struct iscsi_if_cnx *cnx;
	int error = 0;

	shost = scsi_host_lookup(ev->u.d_session.sid);
	if (shost == ERR_PTR(-ENXIO))
		return -EEXIST;
	snx = hostdata_snx(shost->hostdata);

	/* check if we have active connections */
	spin_lock_irqsave(&cnxlock, flags);
	list_for_each_entry(cnx, &snx->connections, snxitem) {
		if (cnx->active) {
			printk("iscsi%d: can not destroy session: "
			       "has active connection (%p)\n",
			       shost->host_no, iscsi_ptr(cnx->cnxh));
			spin_unlock_irqrestore(&cnxlock, flags);
			error = EIO;
			goto out_release_ref;
		}
	}
	spin_unlock_irqrestore(&cnxlock, flags);

	scsi_remove_host(shost);
	transport->destroy_session(ev->u.d_session.session_handle);
	transport_unregister_device(&snx->dev);
	device_unregister(&snx->dev);

	/* remove this session from the list of active sessions */
	spin_lock_irqsave(&snxlock, flags);
	list_del(&snx->item);
	spin_unlock_irqrestore(&snxlock, flags);

	/* ref from host alloc */
	scsi_host_put(shost);
 out_release_ref:
	/* ref from host lookup */
	scsi_host_put(shost);
	return error;
}

static void iscsi_if_cnx_dev_release(struct device *dev)
{
	struct iscsi_if_cnx *cnx = iscsi_dev_to_if_cnx(dev);
	struct Scsi_Host *shost = cnx->host;

	scsi_host_put(shost);
}

static int
iscsi_if_create_cnx(struct iscsi_transport *transport, struct iscsi_uevent *ev)
{
	struct iscsi_if_snx *snx;
	struct Scsi_Host *shost;
	struct iscsi_if_cnx *cnx;
	unsigned long flags;
	int error;

	shost = scsi_host_lookup(ev->u.c_cnx.sid);
	if (shost == ERR_PTR(-ENXIO))
		return -EEXIST;
	snx = hostdata_snx(shost->hostdata);

	cnx = kmalloc(sizeof(struct iscsi_if_cnx), GFP_KERNEL);
	if (!cnx) {
		error = -ENOMEM;
		goto out_release_ref;
	}
	memset(cnx, 0, sizeof(struct iscsi_if_cnx));
	cnx->host = shost;
	snx->transport = transport;

	error = zone_init(&cnx->z_pdu, Z_MAX_PDU, Z_SIZE_PDU, Z_HIWAT_PDU);
	if (error) {
		printk("iscsi%d: can not allocate pdu zone for new cnx\n",
		       shost->host_no);
		goto out_free_cnx;
	}
	error = zone_init(&cnx->z_error, Z_MAX_ERROR,
			  Z_SIZE_ERROR, Z_HIWAT_ERROR);
	if (error) {
		printk("iscsi%d: can not allocate error zone for new cnx\n",
		       shost->host_no);
		goto out_free_pdu_pool;
	}

	ev->r.handle = transport->create_cnx(ev->u.c_cnx.session_handle,
					ev->u.c_cnx.cid);
	if (!ev->r.handle) {
		error = -ENODEV;
		goto out_free_error_pool;
	}

	cnx->cnxh = ev->r.handle;

	/*
	 * this is released in the dev's release function
	 */
	if (!scsi_host_get(shost))
		goto out_destroy_cnx;
	snprintf(cnx->dev.bus_id, BUS_ID_SIZE, "connection%d:%u",
		 shost->host_no, ev->u.c_cnx.cid);
	cnx->dev.parent = &snx->dev;
	cnx->dev.release = iscsi_if_cnx_dev_release;
	error = device_register(&cnx->dev);
	if (error) {
		printk(KERN_ERR "iscsi%d: could not register connections%u "
		       "dev\n", shost->host_no, ev->u.c_cnx.cid);
		goto out_release_parent_ref;
	}
	transport_register_device(&cnx->dev);

	spin_lock_irqsave(&cnxlock, flags);
	list_add(&cnx->item, &cnxlist);
	list_add(&cnx->snxitem, &snx->connections);
	spin_unlock_irqrestore(&cnxlock, flags);

	cnx->active = 1;
	scsi_host_put(shost);
	return 0;

 out_release_parent_ref:
	scsi_host_put(shost);
 out_destroy_cnx:
	transport->destroy_cnx(ev->r.handle);
 out_free_error_pool:
	mempool_destroy(cnx->z_error.pool);
 out_free_pdu_pool:
	mempool_destroy(cnx->z_pdu.pool);
 out_free_cnx:
	kfree(cnx);
 out_release_ref:
	scsi_host_put(shost);
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

	transport_unregister_device(&cnx->dev);
	device_unregister(&cnx->dev);
	return 0;
}

static int
iscsi_if_recv_msg(struct sk_buff *skb, struct nlmsghdr *nlh)
{
	int err = 0;
	struct iscsi_uevent *ev = NLMSG_DATA(nlh);
	struct iscsi_transport *transport;

	if (NETLINK_CREDS(skb)->uid)
		return -EPERM;

	transport = iscsi_ptr(ev->transport_handle);
	if (nlh->nlmsg_type != ISCSI_UEVENT_TRANS_LIST &&
	    iscsi_if_transport_lookup(transport) < 0)
		return -EEXIST;

	daemon_pid = NETLINK_CREDS(skb)->pid;

	switch (nlh->nlmsg_type) {
	case ISCSI_UEVENT_TRANS_LIST: {
		int i;

		for (i = 0; i < ISCSI_TRANSPORT_MAX; i++) {
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
				sizeof(struct iscsi_stats) +
                                sizeof(struct iscsi_stats_custom) *
                                                ISCSI_STATS_CUSTOM_MAX);
		int err;

		cnx = iscsi_if_find_cnx(ev->u.get_stats.cnx_handle,
					H_TYPE_TRANS);
		if (!cnx)
			return -EEXIST;

		do {
			int actual_size;

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
			actual_size = NLMSG_SPACE(sizeof(struct iscsi_uevent) +
					sizeof(struct iscsi_stats) +
                                	sizeof(struct iscsi_stats_custom) *
						stats->custom_length);
			actual_size -= sizeof(*nlhstat);
			actual_size = NLMSG_LENGTH(actual_size);
			skb_trim(skb, NLMSG_ALIGN(actual_size));
			nlhstat->nlmsg_len = actual_size;

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

/*
 * iSCSI connection attrs
 */
#define iscsi_cnx_int_attr_show(param, format)				\
static ssize_t								\
show_cnx_int_param_##param(struct class_device *cdev, char *buf)	\
{									\
	uint32_t value = 0;						\
	struct iscsi_if_cnx *cnx = iscsi_cdev_to_if_cnx(cdev);		\
	struct iscsi_internal *priv;					\
									\
	priv = to_iscsi_internal(cnx->host->transportt);		\
	if (priv->param_mask & (1 << param))				\
		priv->tt->get_param(cnx->cnxh, param, &value);		\
	return snprintf(buf, 20, format"\n", value);			\
}

#define iscsi_cnx_int_attr(field, param, format)			\
	iscsi_cnx_int_attr_show(param, format)				\
static CLASS_DEVICE_ATTR(field, S_IRUGO, show_cnx_int_param_##param, NULL);

iscsi_cnx_int_attr(max_recv_dlength, ISCSI_PARAM_MAX_RECV_DLENGTH, "%u");
iscsi_cnx_int_attr(max_xmit_dlength, ISCSI_PARAM_MAX_XMIT_DLENGTH, "%u");
iscsi_cnx_int_attr(header_digest, ISCSI_PARAM_HDRDGST_EN, "%d");
iscsi_cnx_int_attr(data_digest, ISCSI_PARAM_DATADGST_EN, "%d");
iscsi_cnx_int_attr(ifmarker, ISCSI_PARAM_IFMARKER_EN, "%d");
iscsi_cnx_int_attr(ofmarker, ISCSI_PARAM_OFMARKER_EN, "%d");

/*
 * iSCSI session attrs
 */
#define iscsi_snx_int_attr_show(param, format)				\
static ssize_t								\
show_snx_int_param_##param(struct class_device *cdev, char *buf)	\
{									\
	uint32_t value = 0;						\
	struct iscsi_if_snx *snx = iscsi_cdev_to_if_snx(cdev);		\
	struct Scsi_Host *shost = iscsi_if_snx_to_shost(snx);		\
	struct iscsi_internal *priv = to_iscsi_internal(		\
						shost->transportt);	\
	struct iscsi_if_cnx *cnx = iscsi_if_find_cnx(			\
				     iscsi_handle(shost), H_TYPE_HOST);	\
	if (cnx)							\
		if (priv->param_mask & (1 << param))			\
			priv->tt->get_param(cnx->cnxh, param, &value);	\
	return snprintf(buf, 20, format"\n", value);			\
}

#define iscsi_snx_int_attr(field, param, format)			\
	iscsi_snx_int_attr_show(param, format)				\
static CLASS_DEVICE_ATTR(field, S_IRUGO, show_snx_int_param_##param, NULL);

iscsi_snx_int_attr(initial_r2t, ISCSI_PARAM_INITIAL_R2T_EN, "%d");
iscsi_snx_int_attr(max_outstanding_r2t, ISCSI_PARAM_MAX_R2T, "%hu");
iscsi_snx_int_attr(immediate_data, ISCSI_PARAM_IMM_DATA_EN, "%d");
iscsi_snx_int_attr(first_burst_len, ISCSI_PARAM_FIRST_BURST, "%u");
iscsi_snx_int_attr(max_burst_len, ISCSI_PARAM_MAX_BURST, "%u");
iscsi_snx_int_attr(data_pdu_in_order, ISCSI_PARAM_PDU_INORDER_EN, "%d");
iscsi_snx_int_attr(data_seq_in_order, ISCSI_PARAM_DATASEQ_INORDER_EN, "%d");
iscsi_snx_int_attr(erl, ISCSI_PARAM_ERL, "%d");

#define SETUP_SESSION_RD_ATTR(field, param)				\
	if (priv->param_mask & (1 << param)) {				\
		priv->session_attrs[count] = &class_device_attr_##field;\
		count++;						\
	}

#define SETUP_CONN_RD_ATTR(field, param)				\
	if (priv->param_mask & (1 << param)) {				\
		priv->connection_attrs[count] = &class_device_attr_##field;\
		count++;						\
	}

static int iscsi_is_snx_dev(const struct device *dev)
{
	return dev->release == iscsi_if_snx_dev_release;
}

static int iscsi_snx_match(struct attribute_container *cont,
			   struct device *dev)
{
	struct iscsi_if_snx *snx;
	struct Scsi_Host *shost;
	struct iscsi_internal *priv;

	if (!iscsi_is_snx_dev(dev))
		return 0;

	snx = iscsi_dev_to_if_snx(dev);
	shost = iscsi_if_snx_to_shost(snx);
	if (!shost->transportt)
		return 0;

	priv = to_iscsi_internal(shost->transportt);
	if (priv->session_cont.ac.class != &iscsi_session_class.class)
		return 0;

	return &priv->session_cont.ac == cont;
}

static int iscsi_is_cnx_dev(const struct device *dev)
{
	return dev->release == iscsi_if_cnx_dev_release;
}

static int iscsi_cnx_match(struct attribute_container *cont,
			   struct device *dev)
{
	struct iscsi_if_cnx *cnx;
	struct Scsi_Host *shost;
	struct iscsi_internal *priv;

	if (!iscsi_is_cnx_dev(dev))
		return 0;

	cnx = iscsi_dev_to_if_cnx(dev);
	shost = cnx->host;
	if (!shost->transportt)
		return 0;

	priv = to_iscsi_internal(shost->transportt);
	if (priv->connection_cont.ac.class != &iscsi_connection_class.class)
		return 0;

	return &priv->connection_cont.ac == cont;
}

int iscsi_register_transport(struct iscsi_transport *tt)
{
	struct iscsi_internal *priv;
	int count = 0, i, id = -1;

	BUG_ON(!tt);
	for (i = 0; i < ISCSI_TRANSPORT_MAX; i++) {
		if (transport_table[i] == tt)
			return -EEXIST;
		if (!transport_table[i]) {
			id = i;
			break;
		}
	}
	if (id == -1)
		return -EPERM;

	priv = kmalloc(sizeof(struct iscsi_internal), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;
	memset(priv, 0, sizeof(struct iscsi_internal));

	priv->tt = tt;

	/* setup parameters mask */
	priv->param_mask = 0xFFFFFFFF;
	if (!(tt->caps & CAP_MULTI_R2T))
		priv->param_mask &= ~(1 << ISCSI_PARAM_MAX_R2T);
	if (!(tt->caps & CAP_HDRDGST))
		priv->param_mask &= ~(1 << ISCSI_PARAM_HDRDGST_EN);
	if (!(tt->caps & CAP_DATADGST))
		priv->param_mask &= ~(1 << ISCSI_PARAM_DATADGST_EN);

	/* connection parameters */
	priv->connection_cont.ac.attrs = &priv->connection_attrs[0];
	priv->connection_cont.ac.class = &iscsi_connection_class.class;
	priv->connection_cont.ac.match = iscsi_cnx_match;
	transport_container_register(&priv->connection_cont);

	SETUP_CONN_RD_ATTR(max_recv_dlength, ISCSI_PARAM_MAX_RECV_DLENGTH);
	SETUP_CONN_RD_ATTR(max_xmit_dlength, ISCSI_PARAM_MAX_XMIT_DLENGTH);
	SETUP_CONN_RD_ATTR(header_digest, ISCSI_PARAM_HDRDGST_EN);
	SETUP_CONN_RD_ATTR(data_digest, ISCSI_PARAM_DATADGST_EN);
	SETUP_CONN_RD_ATTR(ifmarker, ISCSI_PARAM_IFMARKER_EN);
	SETUP_CONN_RD_ATTR(ofmarker, ISCSI_PARAM_OFMARKER_EN);

	BUG_ON(count > ISCSI_CONN_ATTRS);
	priv->connection_attrs[count] = NULL;
	count = 0;

	/* session parameters */
	priv->session_cont.ac.attrs = &priv->session_attrs[0];
	priv->session_cont.ac.class = &iscsi_session_class.class;
	priv->session_cont.ac.match = iscsi_snx_match;
	transport_container_register(&priv->session_cont);

	SETUP_SESSION_RD_ATTR(initial_r2t, ISCSI_PARAM_INITIAL_R2T_EN);
	SETUP_SESSION_RD_ATTR(max_outstanding_r2t, ISCSI_PARAM_MAX_R2T);
	SETUP_SESSION_RD_ATTR(immediate_data, ISCSI_PARAM_IMM_DATA_EN);
	SETUP_SESSION_RD_ATTR(first_burst_len, ISCSI_PARAM_FIRST_BURST);
	SETUP_SESSION_RD_ATTR(max_burst_len, ISCSI_PARAM_MAX_BURST);
	SETUP_SESSION_RD_ATTR(data_pdu_in_order, ISCSI_PARAM_PDU_INORDER_EN);
	SETUP_SESSION_RD_ATTR(data_seq_in_order,ISCSI_PARAM_DATASEQ_INORDER_EN)
	SETUP_SESSION_RD_ATTR(erl, ISCSI_PARAM_ERL);

	BUG_ON(count > ISCSI_SESSION_ATTRS);
	priv->session_attrs[count] = NULL;

	transport_table[id] = tt;
	tt->scsi_transport = &priv->t;
	printk("iscsi: registered transport (%d - %s)\n", id, tt->name);
	return 0;
}
EXPORT_SYMBOL_GPL(iscsi_register_transport);

int iscsi_unregister_transport(struct iscsi_transport *tt)
{
	struct iscsi_internal *priv = to_iscsi_internal(tt->scsi_transport);
	int id;

	BUG_ON(!tt);

	down(&callsema);
	if (iscsi_if_find_snx(tt)) {
		up(&callsema);
		return -EPERM;
	}
	id = iscsi_if_transport_lookup(tt);
	BUG_ON (id < 0);
	transport_container_unregister(&priv->connection_cont);
	transport_container_unregister(&priv->session_cont);
	kfree(priv);
	transport_table[id] = NULL;
	up(&callsema);

	return 0;
}
EXPORT_SYMBOL_GPL(iscsi_unregister_transport);

static int
iscsi_rcv_nl_event(struct notifier_block *this, unsigned long event, void *ptr)
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

static __init int iscsi_transport_init(void)
{
	int err;

	err = transport_class_register(&iscsi_connection_class);
	if (err)
		return err;

	err = transport_class_register(&iscsi_session_class);
	if (err)
		goto unregister_cnx_class;

	netlink_register_notifier(&iscsi_nl_notifier);
	nls = netlink_kernel_create(NETLINK_ISCSI, iscsi_if_rx);
	if (!nls) {
		err = -ENOBUFS;
		goto unregister_notifier;
	}

	err = zone_init(&z_reply, Z_MAX_REPLY, Z_SIZE_REPLY, Z_HIWAT_REPLY);
	if (!err)
		return 0;

	sock_release(nls->sk_socket);
 unregister_notifier:
	netlink_unregister_notifier(&iscsi_nl_notifier);
 unregister_cnx_class:
	transport_class_unregister(&iscsi_connection_class);
	return err;
}

static void __exit iscsi_transport_exit(void)
{
	mempool_destroy(z_reply.pool);
	sock_release(nls->sk_socket);
	netlink_unregister_notifier(&iscsi_nl_notifier);
	transport_class_unregister(&iscsi_connection_class);
	transport_class_unregister(&iscsi_session_class);
}

module_init(iscsi_transport_init);
module_exit(iscsi_transport_exit);

MODULE_AUTHOR("Mike Christie <michaelc@cs.wisc.edu>, "
	      "Dmitry Yusupov <dmitry_yus@yahoo.com>, "
	      "Alex Aizman <itn780@yahoo.com>");
MODULE_DESCRIPTION("iSCSI Transport Interface");
MODULE_LICENSE("GPL");
