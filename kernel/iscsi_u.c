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
#include <linux/ioctl.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/poll.h>
#include <asm/uaccess.h>

/* Must go: for scsi_transport... */
#include <scsi/scsi_host.h>

#include "iscsi_proto.h"
#include "iscsi_if.h"
#include "iscsi_u.h"

typedef struct iscsi_kprovider {
	char		name[ISCSI_PROVIDER_NAME_MAXLEN];
	iscsi_ops_t	ops;
	iscsi_caps_t	caps;
} iscsi_kprovider_t;

typedef enum sp_state_e {
	SP_STATE_INVALID	= 0,
	SP_STATE_BUSY	= 1,
	SP_STATE_READY	= 2,
} sp_state_e;

typedef struct sp_item {
	struct list_head item;
	sp_state_e state;
	char pdu[DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH+sizeof(iscsi_hdr_t)+4];
} sp_item_t;

typedef struct sp_context {
	ulong_t cnxh;
	sp_state_e state;
	sp_item_t *spb;
	int hdr_size;
	int data_size;
	int curr_off;
} sp_context_t;

static struct list_head sp_head;
static sp_context_t sp_ctxt;
static iscsi_kprovider_t provider_table[ISCSI_PROVIDER_MAX];
static spinlock_t event_queue_lock = SPIN_LOCK_UNLOCKED;
static LIST_HEAD(event_queue);
DECLARE_WAIT_QUEUE_HEAD(event_wait);

typedef struct kevent {
	iscsi_uevent_t ev;
	struct list_head list;
} kevent_t;

int
iscsi_control_recv_pdu(iscsi_cnx_h cp_cnx, iscsi_hdr_t *hdr, char *data)
{
	BUG_ON(1);
	return 0;
}

void
iscsi_control_cnx_error(iscsi_cnx_h cp_cnx, int error)
{
}

kevent_t*
iscsi_event_get(int del)
{
	kevent_t *kevent = ERR_PTR(-EAGAIN);

	spin_lock(&event_queue_lock);
	if (list_empty(&event_queue))
		goto out;

	kevent = list_entry(event_queue.next, kevent_t, list);
	if (del)
		list_del(&kevent->list);
out:
	spin_unlock(&event_queue_lock);

	return kevent;
}

int
iscsi_event_put(iscsi_uevent_e type, int atomic)
{
	kevent_t *kevent;

	if (atomic) {
		kevent = kmalloc(sizeof(*kevent), GFP_ATOMIC);
		if (!kevent)
			return -ENOMEM;
	} else {
		do {
			kevent = kmalloc(sizeof(*kevent), GFP_KERNEL);
			if (!kevent)
				yield();
		} while (!kevent);
	}

	memset(kevent, 0, sizeof(*kevent));
	INIT_LIST_HEAD(&kevent->list);

	kevent->ev.type = type;

	spin_lock(&event_queue_lock);
	list_add(&kevent->list, &event_queue);
	spin_unlock(&event_queue_lock);

	return 0;
}

static ssize_t
write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	if (sp_ctxt.state != SP_STATE_BUSY)
		return -EBUSY;

	if (sp_ctxt.curr_off + count > sp_ctxt.hdr_size + sp_ctxt.data_size)
		return -EPERM;

	if (copy_from_user(&sp_ctxt.spb->pdu[sp_ctxt.curr_off], buf, count))
			count = -EFAULT;
	sp_ctxt.curr_off += count;

	return count;
}

static ssize_t
read(struct file *file, char *buf, size_t count, loff_t *ppos)
{
	kevent_t *kevent;

	if (count != sizeof(iscsi_uevent_t))
		return -EIO;

	kevent = iscsi_event_get(1);
	if (IS_ERR(kevent))
		return -EAGAIN;

	if (copy_to_user(buf, &kevent->ev, count))
		count = -EFAULT;

	kfree(kevent);

	return count;
}

static int
open(struct inode *inode, struct file *file)
{
	return 0;
}

static int
close(struct inode *inode, struct file *file)
{
	return 0;
}

static unsigned int
poll(struct file *filp, poll_table *wait)
{
	poll_wait(filp, &event_wait, wait);

	return IS_ERR(iscsi_event_get(0)) ? 0 : POLLIN | POLLRDNORM;
}

static iscsi_kprovider_t*
__provider_lookup(int id)
{
	/* FIXME: implement provider's container */
	return &provider_table[id];
}

static int
__create_session(unsigned long ptr)
{
	int rc;
	iscsi_uevent_t ev;
	iscsi_kprovider_t *provider;
	ulong_t handle;

	if ((rc = copy_from_user(&ev, (void *)ptr, sizeof(ev))) < 0)
		return rc;

	if ((provider = __provider_lookup(ev.provider_id)) == NULL)
		return -EEXIST;

	handle = (ulong_t)provider->ops.create_session(
		       (void*)ev.u.c_session.handle, ev.u.c_session.sid,
		       ev.u.c_session.initial_cmdsn);
	if (!handle) {
		return -EIO;
	}

	if ((rc = copy_to_user(&((iscsi_uevent_t*)ptr)->r.handle, &handle,
			       sizeof(ulong_t))) < 0) {
		provider->ops.destroy_session((void*)handle);
		return rc;
	}

	return 0;
}

static int
__create_cnx(unsigned long ptr)
{
	int rc;
	iscsi_uevent_t ev;
	iscsi_kprovider_t *provider;
	ulong_t handle;
	struct socket *sock;

	if ((rc = copy_from_user(&ev, (void *)ptr, sizeof(ev))) < 0)
		return rc;

	if ((provider = __provider_lookup(ev.provider_id)) == NULL)
		return -EEXIST;

	if ((sock = sockfd_lookup(ev.u.c_cnx.socket_fd, &rc)) == NULL) {
		return rc;
	}

	handle = (ulong_t)provider->ops.create_cnx(
	       (void*)ev.u.c_cnx.session_handle, (void*)ev.u.c_cnx.handle,
	       sock, ev.u.c_cnx.cid);
	if (!handle) {
		return -EIO;
	}

	if ((rc = copy_to_user(&((iscsi_uevent_t*)ptr)->r.handle, &handle,
			       sizeof(ulong_t))) < 0) {
		provider->ops.destroy_cnx((void*)handle);
		return rc;
	}

	return 0;
}

static int
__bind_cnx(unsigned long ptr)
{
	int rc;
	iscsi_uevent_t ev;
	iscsi_kprovider_t *provider;

	if ((rc = copy_from_user(&ev, (void *)ptr, sizeof(ev))) < 0)
		return rc;

	if ((provider = __provider_lookup(ev.provider_id)) == NULL)
		return -EEXIST;

	rc = (ulong_t)provider->ops.bind_cnx(
	       (void*)ev.u.b_cnx.session_handle, (void*)ev.u.b_cnx.handle,
	       ev.u.b_cnx.is_leading);
	if (rc) {
		return -EIO;
	}

	if ((rc = copy_to_user(&((iscsi_uevent_t*)ptr)->r.retcode, &rc,
			       sizeof(int))) < 0) {
		return rc;
	}

	return 0;
}

static int
__send_pdu_begin(unsigned long ptr)
{
	int rc;
	iscsi_uevent_t ev;
	struct list_head *lh;

	if ((rc = copy_from_user(&ev, (void *)ptr, sizeof(ev))) < 0)
		return rc;

	if (ev.u.sp_begin.hdr_size + ev.u.sp_begin.data_size >
	    DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH + sizeof(iscsi_hdr_t) + 4)
		return -EPERM;

	if (sp_ctxt.state != SP_STATE_READY)
		return -EBUSY;

	sp_ctxt.spb = NULL;
	list_for_each(lh, &sp_head) {
		sp_item_t *spb;
		spb = list_entry(lh, sp_item_t, item);
		if (spb && spb->state == SP_STATE_READY) {
			spb->state = SP_STATE_BUSY;
			sp_ctxt.spb = spb;
			break;
		}
	}
	if (sp_ctxt.spb == NULL) {
		/* FIXME: allocate up to configured max. */
		return -ENOMEM;
	}

	sp_ctxt.cnxh = ev.u.sp_begin.cnx_handle;
	sp_ctxt.state = SP_STATE_BUSY;
	sp_ctxt.hdr_size = ev.u.sp_begin.hdr_size;
	sp_ctxt.data_size = ev.u.sp_begin.data_size;
	sp_ctxt.curr_off = 0;

	return 0;
}

static int
__send_pdu_end(unsigned long ptr)
{
	int rc;
	iscsi_uevent_t ev;
	iscsi_kprovider_t *provider;

	if ((rc = copy_from_user(&ev, (void *)ptr, sizeof(ev))) < 0)
		return rc;

	if ((provider = __provider_lookup(ev.provider_id)) == NULL)
		return -EEXIST;

	if (sp_ctxt.state != SP_STATE_BUSY)
		return -EPERM;

	if (sp_ctxt.cnxh != ev.u.sp_end.cnx_handle)
		return -EPERM;

	rc = (ulong_t)provider->ops.send_immpdu(
	       (void*)ev.u.sp_end.cnx_handle, (iscsi_hdr_t*)sp_ctxt.spb->pdu,
		sp_ctxt.spb->pdu + sp_ctxt.hdr_size, sp_ctxt.data_size);
	if (rc) {
		return -EIO;
	}

	if ((rc = copy_to_user(&((iscsi_uevent_t*)ptr)->r.retcode, &rc,
			       sizeof(int))) < 0) {
		return rc;
	}

	return 0;
}

static int
ioctl(struct inode *inode, struct file *file,
		 unsigned int cmd, unsigned long arg)
{
	int rc;
	u32 id;

	if ((rc = get_user(id, (u32 *) arg)) != 0)
		return rc;

	switch (cmd) {
	case ISCSI_UEVENT_CREATE_SESSION: return __create_session(arg);
	case ISCSI_UEVENT_CREATE_CNX: return __create_cnx(arg);
	case ISCSI_UEVENT_BIND_CNX: return __bind_cnx(arg);
	case ISCSI_UEVENT_SEND_PDU_BEGIN: return __send_pdu_begin(arg);
	case ISCSI_UEVENT_SEND_PDU_END: return __send_pdu_end(arg);
	default: return -EPERM;
	}

	return -EPERM;
}

struct file_operations ctr_fops = {
	.owner		= THIS_MODULE,
	.open		= open,
	.ioctl		= ioctl,
	.poll		= poll,
	.read		= read,
	.write		= write,
	.release	= close,
};

static int ctr_major;
static char ctr_name[] = "iscsictl";

static int __init
iscsi_init(void)
{
	int rc;
	sp_item_t *spb;

	printk(KERN_INFO "Open-iSCSI Provider Manager, version "
			ISCSI_VERSION_STR " variant (" ISCSI_DATE_STR ")\n");

	INIT_LIST_HEAD(&sp_head);

	spb = kmalloc(sizeof(sp_item_t), GFP_KERNEL);
	if (spb == NULL) {
		printk("failed to allocate send pdu buffer\n");
		return -ENOMEM;
	}
	list_add(&spb->item, &sp_head);
	spb->state = SP_STATE_READY;
	sp_ctxt.state = SP_STATE_READY;

	ctr_major = register_chrdev(0, ctr_name, &ctr_fops);
	if (ctr_major < 0) {
		kfree(spb);
		printk("failed to register the control device %d\n", ctr_major);
		return ctr_major;
	}

	/* FIXME: implement flexible provider register/unregister interface */
	strcpy(provider_table[0].name,"tcp");
	rc = iscsi_tcp_register(&provider_table[0].ops,
				 &provider_table[0].caps);
	if (rc) {
		kfree(spb);
		unregister_chrdev(ctr_major, ctr_name);
		return rc;
	}

	return 0;
}

static void __exit
iscsi_exit(void)
{
	struct list_head *lh, *n;
	iscsi_tcp_unregister();
	unregister_chrdev(ctr_major, ctr_name);
	list_for_each_safe(lh, n, &sp_head) {
		sp_item_t *spb;
		spb = list_entry(lh, sp_item_t, item);
		if (spb) {
			list_del(&spb->item);
			kfree(spb);
		}
	}
}

module_init(iscsi_init);
module_exit(iscsi_exit);
