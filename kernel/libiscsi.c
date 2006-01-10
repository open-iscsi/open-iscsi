/*
 * iSCSI lib functions
 *
 * Copyright (C) IBM Corporation, 2004
 * Copyright (C) Mike Christie, 2004 - 2005
 * Copyright (C) Dmitry Yusupov, 2004 - 2005
 * Copyright (C) Alex Aizman, 2004 - 2005
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
#include <scsi/scsi.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_transport.h>
#include <scsi_transport_iscsi.h>

static void iscsi_session_release(struct device *dev)
{
	struct iscsi_cls_session *session = iscsi_dev_to_session(dev);
	struct iscsi_transport *transport = session->transport;
	struct Scsi_Host *shost;

	shost = iscsi_session_to_shost(session);
	scsi_host_put(shost);
	kfree(session);
	module_put(transport->owner);
}

int iscsi_is_session_dev(const struct device *dev)
{
	return dev->release == iscsi_session_release;
}

/**
 * iscsi_create_session - create iscsi class session
 * @shost: scsi host
 * @transport: iscsi transport
 * @isid: iscsi isid
 * @initial_cmdsn: initial iSCSI CmdSN
 *
 * This can be called from a LLD or iscsi_interface
 **/
struct iscsi_cls_session *
iscsi_create_session(struct Scsi_Host *shost, struct iscsi_transport *transport,
		     uint32_t isid, uint32_t initial_cmdsn)
{
	struct iscsi_cls_session *session;
	int err;

	if (!try_module_get(transport->owner))
		return NULL;

	session = kzalloc(sizeof(*session), GFP_KERNEL);
	if (!session)
		goto module_put;
	session->transport = transport;

	/* initialize session */
	if (transport->create_session) {
		err = transport->create_session(shost, initial_cmdsn);
		if (err)
			goto free_session;
	}

	/* this is released in the dev's release function */
	scsi_host_get(shost);
	snprintf(session->dev.bus_id, BUS_ID_SIZE, "session%u", isid);
	session->dev.parent = &shost->shost_gendev;
	session->dev.release = iscsi_session_release;
	err = device_register(&session->dev);
	if (err) {
		dev_printk(KERN_ERR, &session->dev, "iscsi: could not "
			   "register session's dev\n");
		goto destroy_session;
	}
	transport_register_device(&session->dev);

	return session;

destroy_session:
	if (transport->destroy_session)
		transport->destroy_session(shost);
free_session:
	kfree(session);
module_put:
	module_put(transport->owner);
	return NULL;
}

EXPORT_SYMBOL_GPL(iscsi_create_session);

/**
 * iscsi_destroy_session - destroy iscsi session
 * @session: iscsi_session
 *
 * Can be called by a LLD or iscsi_interface. There must not be
 * any running connections.
 **/
int iscsi_destroy_session(struct iscsi_cls_session *session)
{
	struct iscsi_transport *transport = session->transport;
	struct Scsi_Host *shost = iscsi_session_to_shost(session);

	if (transport->destroy_session)
		transport->destroy_session(shost);

	transport_unregister_device(&session->dev);
	device_unregister(&session->dev);

	return 0;
}

EXPORT_SYMBOL_GPL(iscsi_destroy_session);

static void iscsi_conn_release(struct device *dev)
{
	struct iscsi_cls_conn *conn = iscsi_dev_to_conn(dev);
	struct device *parent = conn->dev.parent;

	kfree(conn);
	put_device(parent);
}

int iscsi_is_conn_dev(const struct device *dev)
{
	return dev->release == iscsi_conn_release;
}

struct iscsi_cls_conn *
iscsi_create_conn(struct iscsi_cls_session *session, uint32_t cid)
{
	struct iscsi_transport *transport = session->transport;
	struct Scsi_Host *shost = iscsi_session_to_shost(session);
	struct iscsi_cls_conn *conn;
	int err;

	conn = kzalloc(sizeof(*conn) + transport->conndata_size, GFP_KERNEL);
	if (!conn)
		return NULL;

	if (transport->conndata_size)
		conn->dd_data = &conn[1];

	INIT_LIST_HEAD(&conn->conn_list);
	conn->transport = transport;

	if (transport->create_conn) {
		if (transport->create_conn(shost, conn->dd_data, cid))
			goto free_conn;
	}

	/* this is released in the dev's release function */
	if (!get_device(&session->dev))
		goto destroy_conn;
	snprintf(conn->dev.bus_id, BUS_ID_SIZE, "connection%d:%u",
		 shost->host_no, cid);
	conn->dev.parent = &session->dev;
	conn->dev.release = iscsi_conn_release;
	err = device_register(&conn->dev);
	if (err) {
		dev_printk(KERN_ERR, &conn->dev, "iscsi: could not register "
			   "connection's dev\n");
		goto release_parent_ref;
	}
	transport_register_device(&conn->dev);
	return conn;

release_parent_ref:
	put_device(&session->dev);
destroy_conn:
	if (transport->destroy_conn)
		transport->destroy_conn(conn->dd_data);
free_conn:
	kfree(conn);
	return NULL;
}

EXPORT_SYMBOL_GPL(iscsi_create_conn);

int iscsi_destroy_conn(struct iscsi_cls_conn *conn)
{
	struct iscsi_cls_session *session = iscsi_dev_to_session(conn->dev.parent);
	struct iscsi_transport *transport = session->transport;

	if (transport->destroy_conn)
		transport->destroy_conn(conn->dd_data);

	transport_unregister_device(&conn->dev);
	device_unregister(&conn->dev);
	return 0;
}

EXPORT_SYMBOL_GPL(iscsi_destroy_conn);
