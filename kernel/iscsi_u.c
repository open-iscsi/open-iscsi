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

#include "iscsi_proto.h"
#include "iscsi_if.h"
#include "iscsi_u.h"

#define CTRL_RECV_ALLOWED	16

typedef struct iscsi_kprovider {
	char		name[ISCSI_PROVIDER_NAME_MAXLEN];
	iscsi_ops_t	ops;
	iscsi_caps_t	caps;
} iscsi_kprovider_t;
static iscsi_kprovider_t provider_table[ISCSI_PROVIDER_MAX];

typedef enum pdu_state_e {
	PDU_STATE_INVALID	= 0,
	PDU_STATE_READY		= 1,
	PDU_STATE_BUSY		= 2,
} pdu_state_e;

typedef struct xmit_context {
	ulong_t cnxh;
	pdu_state_e state;
	char *pdu;
	int hdr_size;
	int data_size;
	int curr_off;
} xmit_context_t;

typedef struct recv_context {
	struct list_head item;
	iscsi_uevent_e type;
	ulong_t cp_cnxh;
	char *pdu;
	int pdu_size;
	pdu_state_e state;
	int curr_off;
} recv_context_t;

static xmit_context_t xmit;
static recv_context_t *recv = NULL;
static struct list_head evqueue;
static struct list_head evqueue_busy;
static spinlock_t evqueue_lock;
static int recv_entry_cnt = 0;
DECLARE_WAIT_QUEUE_HEAD(evwait);

static recv_context_t*
recv_entry_get(int del)
{
	recv_context_t *entry = ERR_PTR(-EAGAIN);

	spin_lock_bh(&evqueue_lock);
	if (list_empty(&evqueue))
		goto out;

	entry = list_entry(evqueue.next, recv_context_t, item);
	if (del) {
		list_del(&entry->item);
		recv_entry_cnt--;
	}
out:
	spin_unlock_bh(&evqueue_lock);

	return entry;
}

int
iscsi_control_recv_pdu(iscsi_cnx_h cp_cnx, iscsi_hdr_t *hdr,
				char *data, int data_size)
{
	recv_context_t *entry;

	if (recv_entry_cnt >= CTRL_RECV_ALLOWED)
		return -EPERM;

	entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
	if (!entry)
		return -ENOMEM;
	memset(entry, 0, sizeof(*entry));

	entry->pdu = kmalloc(data_size + sizeof(iscsi_hdr_t), GFP_KERNEL);
	if (!entry->pdu) {
		kfree(entry);
		return -ENOMEM;
	}
	memcpy(entry->pdu, hdr, sizeof(iscsi_hdr_t));
	if (data)
		memcpy(entry->pdu + sizeof(iscsi_hdr_t), data, data_size);
	entry->type = ISCSI_KEVENT_RECV_PDU;
	entry->state = PDU_STATE_BUSY;
	entry->curr_off = 0;
	entry->cp_cnxh = (ulong_t)cp_cnx;
	entry->pdu_size = sizeof(iscsi_hdr_t) + data_size;

	spin_lock_bh(&evqueue_lock);
	recv_entry_cnt++;
	list_add(&entry->item, &evqueue);
	spin_unlock_bh(&evqueue_lock);

	return 0;
}

void
iscsi_control_cnx_error(iscsi_cnx_h cp_cnx, int error)
{
}

static ssize_t
write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
	if (xmit.state != PDU_STATE_BUSY)
		return -EBUSY;

	if (xmit.curr_off + count > xmit.hdr_size + xmit.data_size)
		return -EPERM;

	if (copy_from_user(&xmit.pdu[xmit.curr_off], buf, count)) {
		count = -EFAULT;
	} else {
		xmit.curr_off += count;
	}

	return count;
}

static ssize_t
read(struct file *file, char *buf, size_t count, loff_t *ppos)
{
	if (copy_to_user(buf, recv->pdu +
			 recv->curr_off, count)) {
		count = -EFAULT;
	} else {
		recv->curr_off += count;
	}

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
	poll_wait(filp, &evwait, wait);

	return IS_ERR(recv_entry_get(0)) ? 0 : POLLIN | POLLRDNORM;
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
		       (void*)ev.u.c_session.session_handle, ev.u.c_session.sid,
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
__destroy_session(unsigned long ptr)
{
	int rc;
	iscsi_uevent_t ev;
	iscsi_kprovider_t *provider;

	if ((rc = copy_from_user(&ev, (void *)ptr, sizeof(ev))) < 0)
		return rc;

	if ((provider = __provider_lookup(ev.provider_id)) == NULL)
		return -EEXIST;

	provider->ops.destroy_session((void*)ev.u.d_session.session_handle);

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
	       (void*)ev.u.c_cnx.session_handle, (void*)ev.u.c_cnx.cnx_handle,
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
__destroy_cnx(unsigned long ptr)
{
	int rc;
	iscsi_uevent_t ev;
	iscsi_kprovider_t *provider;

	if ((rc = copy_from_user(&ev, (void *)ptr, sizeof(ev))) < 0)
		return rc;

	if ((provider = __provider_lookup(ev.provider_id)) == NULL)
		return -EEXIST;

	provider->ops.destroy_cnx((void*)ev.u.d_cnx.cnx_handle);

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
	       (void*)ev.u.b_cnx.session_handle, (void*)ev.u.b_cnx.cnx_handle,
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

	if ((rc = copy_from_user(&ev, (void *)ptr, sizeof(ev))) < 0)
		return rc;

	if (xmit.state != PDU_STATE_READY)
		return -EBUSY;

	xmit.pdu = kmalloc(ev.u.sp_begin.hdr_size + ev.u.sp_begin.data_size,
			   GFP_KERNEL);
	if (xmit.pdu == NULL) {
		return -ENOMEM;
	}

	xmit.cnxh = ev.u.sp_begin.cnx_handle;
	xmit.state = PDU_STATE_BUSY;
	xmit.hdr_size = ev.u.sp_begin.hdr_size;
	xmit.data_size = ev.u.sp_begin.data_size;
	xmit.curr_off = 0;

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

	if (xmit.state != PDU_STATE_BUSY)
		return -EPERM;

	if (xmit.cnxh != ev.u.sp_end.cnx_handle)
		return -EPERM;

	rc = (ulong_t)provider->ops.send_immpdu(
	       (void*)ev.u.sp_end.cnx_handle, (iscsi_hdr_t*)xmit.pdu,
		xmit.pdu + xmit.hdr_size, xmit.data_size);
	if (rc) {
		return -EIO;
	}

	kfree(xmit.pdu);
	xmit.state = PDU_STATE_READY;

	if ((rc = copy_to_user(&((iscsi_uevent_t*)ptr)->r.retcode, &rc,
			       sizeof(int))) < 0) {
		return rc;
	}

	return 0;
}

static int
__recv_pdu_begin(unsigned long ptr)
{
	int rc;
	iscsi_uevent_t ev;
	recv_context_t *entry = NULL;
	struct list_head *lh;

	if ((rc = copy_from_user(&ev, (void *)ptr, sizeof(ev))) < 0)
		return rc;

	list_for_each(lh, &evqueue_busy) {
		entry = list_entry(lh, recv_context_t, item);
		if (entry && entry == (void*)ev.u.rp_begin.recv_handle) {
			spin_lock_bh(&evqueue_lock);
			list_del(&entry->item);
			spin_unlock_bh(&evqueue_lock);
			break;
		}
	}
	if (entry != (void*)ev.u.rp_begin.recv_handle)
		return -EIO;

	ev.r.rp_begin.pdu_handle = (ulong_t)entry->pdu;
	ev.r.rp_begin.pdu_size = entry->pdu_size;

	if ((rc = copy_to_user((void*)ptr, &ev, sizeof(ev))) < 0) {
		spin_lock_bh(&evqueue_lock);
		list_add(&entry->item, &evqueue_busy);
		spin_unlock_bh(&evqueue_lock);
		return rc;
	}

	recv = entry;

	return 0;
}

static int
__recv_pdu_end(unsigned long ptr)
{
	int rc;
	iscsi_uevent_t ev;

	if (recv == NULL)
		return -EIO;

	if ((rc = copy_from_user(&ev, (void *)ptr, sizeof(ev))) < 0)
		return rc;

	if (ev.u.rp_end.cpcnx_handle != (ulong_t)recv->cp_cnxh)
		return -EPERM;

	if (ev.u.rp_end.pdu_handle != (ulong_t)recv->pdu)
		return -EPERM;

	kfree(recv->pdu);
	kfree(recv);
	recv = NULL;

	return 0;
}

static int
__recv_req(unsigned long ptr)
{
	int rc;
	iscsi_uevent_t ev;
	recv_context_t *entry;

	if ((rc = copy_from_user(&ev, (void *)ptr, sizeof(ev))) < 0)
		return rc;

	entry = recv_entry_get(1);
	if (IS_ERR(entry))
		return -EPERM;

	spin_lock_bh(&evqueue_lock);
	list_add(&entry->item, &evqueue_busy);
	spin_unlock_bh(&evqueue_lock);

	ev.type = entry->type;
	ev.r.recv_req.recv_handle = (ulong_t)entry;
	ev.r.recv_req.cnx_handle = (ulong_t)entry->cp_cnxh;

	if ((rc = copy_to_user((void*)ptr, &ev, sizeof(ev))) < 0)
		return rc;

	return 0;
}

static int
__set_param(unsigned long ptr)
{
	int rc;
	iscsi_uevent_t ev;
	iscsi_kprovider_t *provider;

	if ((rc = copy_from_user(&ev, (void *)ptr, sizeof(ev))) < 0)
		return rc;

	if ((provider = __provider_lookup(ev.provider_id)) == NULL)
		return -EEXIST;

	rc = provider->ops.set_param((void*)ev.u.set_param.cnx_handle,
				ev.u.set_param.param, ev.u.set_param.value);
	if (rc)
		return rc;

	return 0;
}

static int
__start_cnx(unsigned long ptr)
{
	int rc;
	iscsi_uevent_t ev;
	iscsi_kprovider_t *provider;

	if ((rc = copy_from_user(&ev, (void *)ptr, sizeof(ev))) < 0)
		return rc;

	if ((provider = __provider_lookup(ev.provider_id)) == NULL)
		return -EEXIST;

	rc = provider->ops.start_cnx((void*)ev.u.start_cnx.cnx_handle);
	if (rc)
		return rc;

	return 0;
}

static int
__stop_cnx(unsigned long ptr)
{
	int rc;
	iscsi_uevent_t ev;
	iscsi_kprovider_t *provider;

	if ((rc = copy_from_user(&ev, (void *)ptr, sizeof(ev))) < 0)
		return rc;

	if ((provider = __provider_lookup(ev.provider_id)) == NULL)
		return -EEXIST;

	provider->ops.stop_cnx((void*)ev.u.stop_cnx.cnx_handle);

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
	case ISCSI_UEVENT_DESTROY_SESSION: return __destroy_session(arg);
	case ISCSI_UEVENT_CREATE_CNX: return __create_cnx(arg);
	case ISCSI_UEVENT_DESTROY_CNX: return __destroy_cnx(arg);
	case ISCSI_UEVENT_BIND_CNX: return __bind_cnx(arg);
	case ISCSI_UEVENT_SEND_PDU_BEGIN: return __send_pdu_begin(arg);
	case ISCSI_UEVENT_SEND_PDU_END: return __send_pdu_end(arg);
	case ISCSI_UEVENT_RECV_PDU_BEGIN: return __recv_pdu_begin(arg);
	case ISCSI_UEVENT_RECV_PDU_END: return __recv_pdu_end(arg);
	case ISCSI_UEVENT_RECV_REQ: return __recv_req(arg);
	case ISCSI_UEVENT_SET_PARAM: return __set_param(arg);
	case ISCSI_UEVENT_START_CNX: return __start_cnx(arg);
	case ISCSI_UEVENT_STOP_CNX: return __stop_cnx(arg);
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

	printk(KERN_INFO "Open-iSCSI Provider Manager, version "
			ISCSI_VERSION_STR " variant (" ISCSI_DATE_STR ")\n");

	INIT_LIST_HEAD(&evqueue);
	INIT_LIST_HEAD(&evqueue_busy);
	evqueue_lock = SPIN_LOCK_UNLOCKED;
	xmit.state = PDU_STATE_READY;

	ctr_major = register_chrdev(0, ctr_name, &ctr_fops);
	if (ctr_major < 0) {
		printk("failed to register the control device %d\n", ctr_major);
		return ctr_major;
	}

	/* FIXME: implement flexible provider register/unregister interface */
	strcpy(provider_table[0].name,"tcp");
	rc = iscsi_tcp_register(&provider_table[0].ops,
				 &provider_table[0].caps);
	if (rc) {
		unregister_chrdev(ctr_major, ctr_name);
		return rc;
	}

	return 0;
}

static void __exit
iscsi_exit(void)
{
	iscsi_tcp_unregister();
	unregister_chrdev(ctr_major, ctr_name);
}

module_init(iscsi_init);
module_exit(iscsi_exit);
