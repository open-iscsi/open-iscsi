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

#if 0
static int
create_session(unsigned long ptr)
{
	int res;
	struct target_info info;

	if ((res = copy_from_user(&info, (void *) ptr, sizeof(info))) < 0)
		return res;
	return 0;
}
#endif

static int
ioctl(struct inode *inode, struct file *file,
		 unsigned int cmd, unsigned long arg)
{
	int res;
	u32 id;

	if ((res = get_user(id, (u32 *) arg)) != 0)
		goto abort;

abort:
	return res;
}

struct file_operations ctr_fops = {
	.owner		= THIS_MODULE,
	.open		= open,
	.ioctl		= ioctl,
	.poll		= poll,
	.read		= read,
	.release	= close,
};

static int ctr_major;
static char ctr_name[] = "iscsictl";

static int __init
iscsi_init(void)
{
	printk(KERN_INFO "Open-iSCSI Provider Manager, version "
			ISCSI_VERSION_STR " build " ISCSI_DATE_STR);

	ctr_major = register_chrdev(0, ctr_name, &ctr_fops);
	if (ctr_major < 0) {
		printk("failed to register the control device %d\n", ctr_major);
		return ctr_major;
	}

	return 0;
}

static void __exit
iscsi_exit(void)
{
	unregister_chrdev(ctr_major, ctr_name);
}

module_init(iscsi_init);
module_exit(iscsi_exit);
