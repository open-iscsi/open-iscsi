/*
 * iSCSI Initiator Control-Path
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

#include <scsi/scsi_host.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_transport.h>
#include <iscsi_if.h>
#include <iscsi_control.h>

static iscsi_provider_t provider_table[ISCSI_PROVIDER_MAX];

static iscsi_initiator_t initiator = {
	.sp.initiator_name = "<not specified>",
	.sp.initiator_alias = "<not specified>",
	.sp.isid = {0,0,0,0,0,0},
	.sp.target_name = "<not specified>",
	.sp.target_alias = "<not specified>",
	.sp.target_portal = "<not specified>",
	.sp.target_address = "<not specified>",
	.sp.tpgt = 1,
	.sp.tsih = 0,
	.sp.first_burst = 131072,
	.cp.max_recv_dlength = 131072,
	.cp.max_xmit_dlength = 131072,
	.sp.max_burst = 262144,
	.sp.max_r2t = 8,
	.sp.max_cnx = 1,
	.sp.erl = 0,
	.sp.initial_r2t_en = 0,
	.sp.imm_data_en = 1,
	.cp.hdrdgst_en = 0,
	.cp.datadgst_en = 0,
	.sp.ifmarker_en = 0,
	.sp.ofmarker_en = 0,
	.sp.pdu_inorder_en = 1,
	.sp.dataseq_inorder_en = 1,
	.sp.time2wait = 2,
	.sp.time2retain = 20,
	.sp.auth_en = 0,
	.sp.cmdsn = 1,
	.sp.exp_cmdsn = 2,
	.sp.max_cmdsn = 2,
};

static iscsi_param_t param_table[] = {
	{1, "initiator_name", &initiator.sp.initiator_name, 0, 0, 1},
	{1, "initiator_alias", &initiator.sp.initiator_alias, 0, 0, 1},
	{1, "isid", &initiator.sp.isid, 0, 0, 0},
	{1, "target_name", &initiator.sp.target_name, 0, 0, 0},
	{1, "target_alias", &initiator.sp.target_alias, 0, 0, 0},
	{1, "target_portal", &initiator.sp.target_portal, 0, 0, 0},
	{1, "target_address", &initiator.sp.target_address, 0, 0, 0},
	{0, "tpgt", &initiator.sp.tpgt, 0, 65535, 0},
	{0, "tsih", &initiator.sp.tsih, 0, 65535, 0},
	{0, "first_burst", &initiator.sp.first_burst, 512, 16777215, 0},
	{0, "max_recv_dlength", &initiator.cp.max_recv_dlength,512,16777215, 0},
	{0, "max_xmit_dlength", &initiator.cp.max_xmit_dlength,512,16777215, 0},
	{0, "max_burst", &initiator.sp.max_burst, 512, 16777215, 0},
	{0, "max_r2t", &initiator.sp.max_r2t, 1, 65535, 0},
	{0, "max_cnx", &initiator.sp.max_cnx, 1, 65535, 0},
	{0, "erl", &initiator.sp.erl, 0, 2, 0},
	{0, "initial_r2t_en", &initiator.sp.initial_r2t_en, 0, 1, 0},
	{0, "imm_data_en", &initiator.sp.imm_data_en, 0, 1, 0},
	{0, "hdrdgst_en", &initiator.cp.hdrdgst_en, 0, 1, 0},
	{0, "datadgst_en", &initiator.cp.datadgst_en, 0, 1, 0},
	{0, "ifmarker_en", &initiator.sp.ifmarker_en, 0, 1, 0},
	{0, "ofmarker_en", &initiator.sp.ofmarker_en, 0, 1, 0},
	{0, "pdu_inorder_en", &initiator.sp.pdu_inorder_en, 0, 1, 0},
	{0, "dataseq_inorder_en", &initiator.sp.dataseq_inorder_en, 0, 1, 0},
	{0, "time2wait", &initiator.sp.time2wait, 0, 3600, 0},
	{0, "time2retain", &initiator.sp.time2retain, 0, 3600, 0},
	{0, "auth_en", &initiator.sp.auth_en, 0, 1, 0},
	{0, "cmdsn", &initiator.sp.auth_en, 0, 0xffffffff, 0},
	{0, "exp_cmdsn", &initiator.sp.auth_en, 0, 0xffffffff, 0},
	{0, "max_cmdsn", &initiator.sp.auth_en, 0, 0xffffffff, 0},
};

static void
iscsi_host_class_release(struct class_device *class_dev)
{
	struct Scsi_Host *shost = transport_class_to_shost(class_dev);
	put_device(&shost->shost_gendev);
}

struct class iscsi_host_class = {
	.name = "iscsi",
	.release = iscsi_host_class_release,
};

static void
iscsi_send_nopin_rsp(iscsi_event_t *ev)
{
	iscsi_nopout_t *hdr = (iscsi_nopout_t*)&ev->rhdr;
	iscsi_provider_t *provider = ev->session->provider;

	memset(hdr, 0, sizeof(iscsi_nopout_t));
	hdr->opcode = ISCSI_OP_NOOP_OUT | ISCSI_OP_IMMEDIATE;
	hdr->flags = ISCSI_FLAG_CMD_FINAL;
	hdr->dlength[0] = ev->hdr.dlength[0];
	hdr->dlength[1] = ev->hdr.dlength[1];
	hdr->dlength[2] = ev->hdr.dlength[2];
	memcpy(hdr->lun, ev->hdr.lun, 8);
	hdr->ttt = ev->hdr.ttt;
	hdr->itt = ISCSI_RESERVED_TAG;

	/* DP fill-ins cmdsn and exp_statsn */
	provider->ops.send_immpdu(ev->cnx->handle, &ev->rhdr, ev->data);
}

static iscsi_provider_t*
iscsi_find_provider(char *name)
{
	int i;

	for (i=0; i<ISCSI_PROVIDER_MAX; i++) {
		if (!strcmp(provider_table[i].name, name))
			return &provider_table[i];
	}
	return NULL;
}

static iscsi_cnx_ctrl_t*
iscsi_find_cnx(iscsi_session_ctrl_t *session, int cid)
{
	struct list_head *lh;

	spin_lock(&session->connections_lock);
	list_for_each(lh, &session->connections) {
		iscsi_cnx_ctrl_t *cnx;
		cnx = list_entry(lh, iscsi_cnx_ctrl_t, item);
		if (cnx && cnx->cid == cid) {
			spin_unlock(&session->connections_lock);
			return cnx;
		}
	}
	spin_unlock(&session->connections_lock);
	return NULL;
}

static iscsi_session_ctrl_t*
iscsi_find_session(int host_no)
{
	struct list_head *lh;

	spin_lock(&initiator.sessions_lock);
	list_for_each(lh, &initiator.sessions) {
		iscsi_session_ctrl_t *session;
		session = list_entry(lh, iscsi_session_ctrl_t, item);
		if (session && session->host_no == host_no) {
			spin_unlock(&initiator.sessions_lock);
			return session;
		}
	}
	spin_unlock(&initiator.sessions_lock);
	return NULL;
}

static iscsi_event_t*
iscsi_event_alloc(iscsi_cnx_ctrl_t *cnx, iscsi_event_e type)
{
	iscsi_event_t *ev;

	if ((ev = kmalloc(sizeof(iscsi_event_t), GFP_KERNEL)) == NULL) {
		return NULL;
	}
	memset(ev, 0, sizeof(iscsi_event_t));

	ev->session = cnx->session;
	ev->cnx = cnx;
	ev->type = type;

	return ev;
}

static iscsi_event_t*
iscsi_event_pdu_alloc(iscsi_cnx_ctrl_t *cnx,
		      iscsi_hdr_t *hdr, char *data)
{
	int datalen = ntoh24(hdr->dlength);
	iscsi_event_t *ev;

	if ((ev = kmalloc(sizeof(iscsi_event_t), GFP_KERNEL)) == NULL) {
		return NULL;
	}

	if ((ev->data = kmalloc(datalen, GFP_KERNEL)) == NULL) {
		kfree(ev);
		return NULL;
	}

	memcpy(&ev->hdr, hdr, sizeof(iscsi_hdr_t));
	memcpy(ev->data, data, datalen);
	ev->session = cnx->session;
	ev->cnx = cnx;
	ev->type = ISCSI_EVENT_PDU;

	return ev;
}

static void
iscsi_event_free(iscsi_event_t *ev)
{
	if (ev->type == ISCSI_EVENT_PDU) {
		kfree(ev->data);
	}
	kfree(ev);
}

static void
iscsi_event_enqueue(iscsi_event_t *ev)
{
	iscsi_session_ctrl_t *session = ev->session;

	spin_lock(&session->eventlock);
	list_add_tail(&ev->item, &session->eventqueue);
	spin_unlock(&session->eventlock);
	schedule_work(&session->eventwork);
}

static void
iscsi_event_process(iscsi_event_t *ev)
{
	int free_ev = 1;

	switch (ev->type) {
	case ISCSI_EVENT_PDU: {
		switch (ev->hdr.opcode) {
		case ISCSI_OP_NOOP_IN:
			iscsi_send_nopin_rsp(ev);
			free_ev = 0;
			break;
		default:
			break;
		}
	}
	break;
	case ISCSI_EVENT_REOPEN: {
		iscsi_session_ctrl_t *session = ev->session;
		iscsi_cnx_ctrl_t *cnx = ev->cnx;
		iscsi_provider_t *provider = session->provider;
		struct Scsi_Host *host = scsi_host_lookup(session->host_no);

		provider->ops.stop_cnx(cnx->handle);
		provider->ops.destroy_cnx(cnx->handle);

		spin_lock(&session->connections_lock);
		list_del(&cnx->item);
		if (list_empty(&session->connections))
			session->leadcnx = NULL;
		spin_unlock(&session->connections_lock);

		printk("<1>iSCSI/CP: attempt to recover session #%d\n",
		       session->host_no);
		kobject_hotplug(&host->transport_classdev.kobj, KOBJ_CHANGE);
	}
	break;
	default:
		BUG_ON(1);
	}

	if (free_ev) {
		iscsi_event_free(ev);
	} else {
		spin_lock_bh(&ev->session->freelock);
		list_add(&ev->item, &ev->session->freequeue);
		spin_unlock_bh(&ev->session->freelock);
	}
}

static void
iscsi_event_worker(void *data)
{
	iscsi_session_ctrl_t *session = (iscsi_session_ctrl_t *)data;
	struct list_head *lh, *n;

	spin_lock_bh(&session->eventlock);
	list_for_each_safe(lh, n, &session->eventqueue) {
		iscsi_event_t *ev;
		ev = list_entry(lh, iscsi_event_t, item);
		if (ev) {
			list_del(&ev->item);
			spin_unlock_bh(&session->eventlock);
			iscsi_event_process(ev);
			spin_lock_bh(&session->eventlock);
		}
	}
	spin_unlock_bh(&session->eventlock);
}

static ssize_t
iscsi_host_class_parameters_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host *shost = transport_class_to_shost(cdev);
	iscsi_session_ctrl_t *session =
		container_of(shost->transportt, struct iscsi_session_ctrl,
			     transportt);
	int count = 0;

	count += sprintf(buf+count, "target_name = %s\n",
			 session->p.target_name);
	count += sprintf(buf+count, "target_alias = %s\n",
			 session->p.target_alias);
	count += sprintf(buf+count, "target_portal = %s\n",
			 session->p.target_portal);
	count += sprintf(buf+count, "target_address = %s\n",
			 session->p.target_address);
	count += sprintf(buf+count, "tsih = %d\n", session->p.tsih);
	count += sprintf(buf+count, "tpgt = %d\n", session->p.tpgt);
	count += sprintf(buf+count, "isid = %02x.%02x.%02x.%02x.%02x.%02x\n",
			 session->p.isid[0], session->p.isid[1],
			 session->p.isid[2], session->p.isid[3],
			 session->p.isid[4], session->p.isid[5]);
	count += sprintf(buf+count, "time2wait = %d\n",
			 session->p.time2wait);
	count += sprintf(buf+count, "time2retain = %d\n",
			 session->p.time2retain);
	count += sprintf(buf+count, "max_cnx = %d\n", session->p.max_cnx);
	count += sprintf(buf+count, "initial_r2t_en = %d\n",
			 session->p.initial_r2t_en);
	count += sprintf(buf+count, "max_r2t = %d\n", session->p.max_r2t);
	count += sprintf(buf+count, "imm_data_en = %d\n",
			 session->p.imm_data_en);
	count += sprintf(buf+count, "first_burst = %d\n",
			 session->p.first_burst);
	count += sprintf(buf+count, "max_burst = %d\n", session->p.max_burst);
	count += sprintf(buf+count, "pdu_inorder_en = %d\n",
			 session->p.pdu_inorder_en);
	count += sprintf(buf+count, "dataseq_inorder_en = %d\n",
			 session->p.dataseq_inorder_en);
	count += sprintf(buf+count, "erl = %d\n",
			 session->p.erl);
	count += sprintf(buf+count, "ifmarker_en = %d\n",
			 session->p.ifmarker_en);
	count += sprintf(buf+count, "ofmarker_en = %d\n",
			 session->p.ofmarker_en);

	return count;
}
static CLASS_DEVICE_ATTR(parameters, S_IRUGO,
			 iscsi_host_class_parameters_show, NULL);

static ssize_t
iscsi_host_class_cnx_parameters_show(struct class_device *cdev, char *buf)
{
	struct Scsi_Host *shost = transport_class_to_shost(cdev);
	iscsi_session_ctrl_t *session =
		container_of(shost->transportt, struct iscsi_session_ctrl,
			     transportt);
	int count = 0;
	struct list_head *lh;

	spin_lock(&session->connections_lock);
	list_for_each_prev(lh, &session->connections) {
		iscsi_cnx_ctrl_t *cnx;
		cnx = list_entry(lh, iscsi_cnx_ctrl_t, item);
		if (cnx) {
			count += sprintf(buf+count,"%d\t%d\t%d\t%d\t%d\n",
					 cnx->cid,
					 cnx->p.max_recv_dlength,
					 cnx->p.max_xmit_dlength,
					 cnx->p.hdrdgst_en,
					 cnx->p.datadgst_en);
		}
	}
	spin_unlock(&session->connections_lock);

	return count;
}
static CLASS_DEVICE_ATTR(cnx_parameters, S_IRUGO,
			 iscsi_host_class_cnx_parameters_show, NULL);

static ssize_t
iscsi_host_class_cnx_parameters_hdr_show(struct class_device *cdev, char *buf)
{
	return sprintf(buf, "CID\tMaxRecv\tMaxXmit\tHdrDgst\tDataDgst\n");
}
static CLASS_DEVICE_ATTR(cnx_parameters_hdr, S_IRUGO,
			 iscsi_host_class_cnx_parameters_hdr_show, NULL);

static ssize_t
iscsi_host_class_cnx_stats_show(struct class_device *cdev, char *buf)
{
	return sprintf(buf, "to be implemented...\n");
}
static CLASS_DEVICE_ATTR(cnx_stats, S_IRUGO,
			 iscsi_host_class_cnx_stats_show, NULL);

static ssize_t
iscsi_host_class_cnx_stats_hdr_show(struct class_device *cdev, char *buf)
{
	return sprintf(buf, "to be implemented...\n");
}
static CLASS_DEVICE_ATTR(cnx_stats_hdr, S_IRUGO,
			 iscsi_host_class_cnx_stats_hdr_show, NULL);

static ssize_t
iscsi_host_class_state(struct class_device *cdev, char *buf)
{
	struct Scsi_Host *shost = transport_class_to_shost(cdev);
	iscsi_session_ctrl_t *session =
		container_of(shost->transportt, struct iscsi_session_ctrl,
			     transportt);
	int count = 0;

	if (session->state == ISCSI_STATE_FREE) {
		count = sprintf(buf, "free\n");
	} else if (session->state == ISCSI_STATE_FAILED) {
		count = sprintf(buf, "failed\n");
	} else {
		count = sprintf(buf, "logged_in\n");
	}

	return count;
}
static CLASS_DEVICE_ATTR(state, S_IRUGO,
			 iscsi_host_class_state, NULL);


static int
iscsi_add_session(iscsi_provider_t *provider, int host_no)
{
	iscsi_session_ctrl_t *session;

	session = kmalloc(sizeof(iscsi_session_ctrl_t), GFP_KERNEL);
	if (session == NULL) {
		return -ENOMEM;
	}
	memset(session, 0, sizeof(iscsi_session_ctrl_t));

	session->class_attrs[0] = &class_device_attr_parameters;
	session->class_attrs[1] = &class_device_attr_cnx_parameters;
	session->class_attrs[2] = &class_device_attr_cnx_parameters_hdr;
	session->class_attrs[3] = &class_device_attr_cnx_stats;
	session->class_attrs[4] = &class_device_attr_cnx_stats_hdr;
	session->class_attrs[5] = &class_device_attr_state;
	session->class_attrs[6] = NULL;
	session->transportt.host_attrs = &session->class_attrs[0];
	session->transportt.host_class = &iscsi_host_class;
	session->transportt.host_setup = NULL;
	session->transportt.host_size = 0;

	session->handle = provider->ops.create_session(session, host_no,
				&session->transportt, initiator.sp.cmdsn);
	if (session->handle == NULL) {
		kfree(session);
		return -EIO;
	}

	memcpy(&session->p, &initiator.sp, sizeof(iscsi_session_params_t));
	session->provider = provider;
	session->host_no = host_no;

	spin_lock(&initiator.sessions_lock);
	list_add(&session->item, &initiator.sessions);
	spin_unlock(&initiator.sessions_lock);

	INIT_LIST_HEAD(&session->connections);
	spin_lock_init(&session->connections_lock);

	INIT_LIST_HEAD(&session->eventqueue);
	INIT_WORK(&session->eventwork, iscsi_event_worker, session);
	spin_lock_init(&session->eventlock);

	INIT_LIST_HEAD(&session->freequeue);
	spin_lock_init(&session->freelock);

	session->state = ISCSI_STATE_FREE;

	return 0;
}

static int
iscsi_remove_session(iscsi_provider_t *provider, int host_no)
{
	iscsi_session_ctrl_t *session;

	if ((session = iscsi_find_session(host_no)) == NULL) {
		return -ENXIO;
	}

	provider->ops.destroy_session(session->handle);

	spin_lock(&initiator.sessions_lock);
	list_del(&session->item);
	spin_unlock(&initiator.sessions_lock);

	kfree(session);

	return 0;
}

static int
iscsi_add_connection(iscsi_provider_t *provider, int host_no,
		     int cid, struct socket *sock)
{
	iscsi_session_ctrl_t *session;
	iscsi_cnx_ctrl_t *cnx;

	if ((session = iscsi_find_session(host_no)) == NULL) {
		return -ENXIO;
	}

	if (iscsi_find_cnx(session, cid)) {
		return -EPERM;
	}

	cnx = kmalloc(sizeof(iscsi_cnx_ctrl_t), GFP_KERNEL);
	if (cnx == NULL) {
		return -ENOMEM;
	}
	memset(cnx, 0, sizeof(iscsi_cnx_ctrl_t));
	memcpy(&cnx->p, &initiator.cp, sizeof(iscsi_cnx_params_t));

	if ((cnx->handle = provider->ops.create_cnx(
				session->handle, cnx, sock, cid)) == NULL) {
		kfree(cnx);
		return -EIO;
	}

	if (provider->ops.bind_cnx(session->handle, cnx->handle, cid == 0)) {
		provider->ops.destroy_cnx(cnx->handle);
		kfree(cnx);
		return -ESRCH;
	}

	/* leading connection */
	if (cid == 0) {
		session->leadcnx = cnx;
	}

	provider->ops.set_param(cnx->handle,
		ISCSI_PARAM_MAX_RECV_DLENGH, initiator.cp.max_recv_dlength);
	provider->ops.set_param(cnx->handle,
		ISCSI_PARAM_MAX_XMIT_DLENGH, initiator.cp.max_xmit_dlength);
	provider->ops.set_param(cnx->handle,
		ISCSI_PARAM_HDRDGST_EN, initiator.cp.hdrdgst_en);
	provider->ops.set_param(cnx->handle,
		ISCSI_PARAM_DATADGST_EN, initiator.cp.datadgst_en);
	provider->ops.set_param(cnx->handle,
		ISCSI_PARAM_INITIAL_R2T_EN, initiator.sp.initial_r2t_en);
	provider->ops.set_param(cnx->handle,
		ISCSI_PARAM_MAX_R2T, initiator.sp.max_r2t);
	provider->ops.set_param(cnx->handle,
		ISCSI_PARAM_IMM_DATA_EN, initiator.sp.imm_data_en);
	provider->ops.set_param(cnx->handle,
		ISCSI_PARAM_FIRST_BURST, initiator.sp.first_burst);
	provider->ops.set_param(cnx->handle,
		ISCSI_PARAM_MAX_BURST, initiator.sp.max_burst);
	provider->ops.set_param(cnx->handle,
		ISCSI_PARAM_PDU_INORDER_EN, initiator.sp.pdu_inorder_en);
	provider->ops.set_param(cnx->handle,
		ISCSI_PARAM_DATASEQ_INORDER_EN,initiator.sp.dataseq_inorder_en);
	provider->ops.set_param(cnx->handle,
		ISCSI_PARAM_ERL, initiator.sp.erl);
	provider->ops.set_param(cnx->handle,
		ISCSI_PARAM_IFMARKER_EN, initiator.sp.ifmarker_en);
	provider->ops.set_param(cnx->handle,
		ISCSI_PARAM_OFMARKER_EN, initiator.sp.ofmarker_en);

	if (provider->ops.start_cnx(cnx->handle)) {
		provider->ops.destroy_cnx(cnx->handle);
		kfree(cnx);
		return -EIO;
	}

	cnx->cid = cid;
	cnx->session = session;

	spin_lock(&session->connections_lock);
	list_add(&cnx->item, &session->connections);
	spin_unlock(&session->connections_lock);

	session->state = ISCSI_STATE_LOGGED_IN;

	return 0;
}

static int
iscsi_remove_connection(iscsi_provider_t *provider, int host_no, int cid)
{
	iscsi_session_ctrl_t *session;
	iscsi_cnx_ctrl_t *cnx;

	if ((session = iscsi_find_session(host_no)) == NULL) {
		return -ENXIO;
	}

	if ((cnx = iscsi_find_cnx(session, cid)) == NULL) {
		return -EPERM;
	}

	provider->ops.destroy_cnx(cnx->handle);

	spin_lock(&session->connections_lock);
	list_del(&cnx->item);
	if (list_empty(&session->connections))
		session->leadcnx = NULL;
	spin_unlock(&session->connections_lock);

	if (cid == 0)
		session->state = ISCSI_STATE_FREE;

	return 0;
}

/*
 * Stop, Logout and Cleanup all active sessions for a given provider.
 */
static void
iscsi_cleanup(iscsi_provider_t *provider)
{
	struct list_head *lhs, *lhc, *ns, *nc;

	spin_lock(&initiator.sessions_lock);
	list_for_each_safe(lhs, ns, &initiator.sessions) {
		iscsi_session_ctrl_t *session;
		session = list_entry(lhs, iscsi_session_ctrl_t, item);
		if (session) {
			spin_lock(&session->connections_lock);
			list_for_each_safe(lhc, nc, &session->connections) {
				iscsi_cnx_ctrl_t *cnx;
				cnx = list_entry(lhc, iscsi_cnx_ctrl_t, item);
				if (cnx) {
					provider->ops.stop_cnx(cnx->handle);
					provider->ops.destroy_cnx(cnx->handle);
					list_del(&cnx->item);
				}
			}
			spin_unlock(&session->connections_lock);
			provider->ops.destroy_session(session->handle);
			list_del(&session->item);
			kfree(session);
		}
	}
	spin_unlock(&initiator.sessions_lock);
}

int
iscsi_control_recv_pdu(iscsi_cnx_h handle, iscsi_hdr_t *hdr, char *data)
{
	iscsi_event_t *ev;
	iscsi_cnx_ctrl_t *cnx = (iscsi_cnx_ctrl_t *)handle;
	iscsi_session_ctrl_t *session = cnx->session;
	struct list_head *lh, *n;

	/* free pending resources based on received statsn */
	spin_lock(&session->freelock);
	list_for_each_safe(lh, n, &session->freequeue) {
		iscsi_event_t *ev;
		ev = list_entry(lh, iscsi_event_t, item);
		if (ev && ev->type == ISCSI_EVENT_PDU &&
		    ntohl(ev->hdr.statsn) < ntohl(hdr->statsn)) {
			list_del(&ev->item);
			iscsi_event_free(ev);
		}
	}
	spin_unlock(&session->freelock);

	switch (hdr->opcode) {
		case ISCSI_OP_NOOP_IN: {
			if (hdr->ttt != ISCSI_RESERVED_TAG) {
				/* its a "ping" from the target */
				if ((ev = iscsi_event_pdu_alloc(
						cnx, hdr, data))) {
					iscsi_event_enqueue(ev);
				} else {
					/* FIXME: send reject (reason 0x6)
					 *	  we should be able allocate
					 *        reject in most cases */
				}
			}
		}
		break;
		case ISCSI_OP_TEXT_RSP:
		case ISCSI_OP_LOGOUT_RSP:
		case ISCSI_OP_ASYNC_EVENT:
		case ISCSI_OP_REJECT_MSG:
		break;
		default: break;
	}

	return 0;
}

void
iscsi_control_cnx_error(iscsi_cnx_h handle, int error)
{
	iscsi_cnx_ctrl_t *cnx = (iscsi_cnx_ctrl_t *)handle;
	iscsi_session_ctrl_t *session = cnx->session;

	switch (error) {
	case ISCSI_ERR_CNX_FAILED: {
		iscsi_event_t *ev;
		if (session->state != ISCSI_STATE_LOGGED_IN) {
			session->state = ISCSI_STATE_FAILED;
			if ((ev = iscsi_event_alloc(cnx, ISCSI_EVENT_REOPEN))) {
				iscsi_event_enqueue(ev);
			}
		}
	}
	break;
	default:
		break;
	}
}

/*
 * iscsi_sysfs_parameters_show - sysfs callback.
 *
 * Usage: cat .../iscsi/parameters
 */
static int
iscsi_host_class_initiator_parameters_show(struct class *class, char * buf)
{
	int count=0, i;

	for (i=0; i<sizeof(param_table)/sizeof(iscsi_param_t); i++) {
		iscsi_param_t *p = &param_table[i];
		if (!p->show)
			continue;
		if (p->type == 0) { /* int type */
			count += sprintf(buf+count, "%s = %d\n", p->key,
					 *(int*)p->value);
		} else {
			count += sprintf(buf+count, "%s = %s\n", p->key,
					 (char*)p->value);
		}
	}
	return count;
}

/*
 * iscsi_sysfs_parameters_store - sysfs callback.
 *
 * Usage: echo "#1 #2" > /sys/class/iscsi/initiator_parameters
 *
 *	#1		- an iSCSI text key
 *	#2		- value
 */
static int
iscsi_host_class_initiator_parameters_store(struct class *class,
				const char * buf, size_t count)
{
	int i, res;
	char key[64];
	char sval[ISCSI_STRING_MAX];

	res = sscanf(buf, "%64s %255s", key, sval);
	if (res != 2) {
		printk("wrong format '%s' (%d)\n", buf, res);
		return count;
	}

	for (i=0; i<sizeof(param_table)/sizeof(iscsi_param_t); i++) {
		iscsi_param_t *p = &param_table[i];
		if (!strnicmp(p->key, key, strlen(key))) {
			if (p->type == 0) { /* int type */
				int ival = simple_strtoul(sval, NULL, 0);
				if (ival < p->min || ival > p->max) {
					printk("bad range '%s'\n", key);
					return count;
				}
				*(int*)p->value = ival;
			} else { /* string type */
				strncpy((char*)p->value, sval, strlen(sval)+1);
			}
			break;
		}
	}
	if (i == sizeof(param_table)/sizeof(iscsi_param_t)) {
		printk("wrong parameter '%s'\n", key);
		return count;
	}
	return count;
}
static CLASS_ATTR(initiator_parameters, S_IWUSR | S_IRUGO,
		  iscsi_host_class_initiator_parameters_show,
		  iscsi_host_class_initiator_parameters_store);

/*
 * iscsi_sysfs_operation_store - sysfs callback.
 *
 * Usage: echo "#provider #mode #op #1 #2 #3" > ../iscsi/operation
 *
 *	#provider	- "tcp", "iser" or specific vendor
 *	#mode		- "session" or "connection"
 *	#op		- "add" or "remove"
 *	#1		- is a session/host number to use
 *	#2		- iSCSI CID ("connection" mode only)
 *	#3		- socket's file descriptor ("connection" mode only)
 *
 * Examples:
 *
 *	echo "tcp session add 0" > /sys/class/iscsi/session_operation
 *	echo "tcp connection remove 0 0 5" > /sys/class/iscsi/session_operation
 */
static int
iscsi_host_class_session_operation_store(struct class *class,
			 const char * buf, size_t count)
{
	char pname[16], mode[10], op[6];
	iscsi_provider_t *provider;
	struct socket *sock;
	int res, host_no, cid, fd;

	res = sscanf(buf, "%16s %10s %6s %d %d %d", pname, mode, op,
		     &host_no, &cid, &fd);
	if (res < 4) {
		printk("wrong format '%s' (%d)\n", buf, res);
		return -1;
	} else if ((provider = iscsi_find_provider(pname)) == NULL) {
		printk("wrong provider '%s'\n", pname);
		return -1;
	} else {
		if (!strcmp("session", mode)) {
			if (!strcmp("add", op) &&
			    (res = iscsi_add_session(provider, host_no))) {
				printk("can't create session (%d)\n", res);
				return -1;
			} else if (!strcmp("remove", op) &&
			    (res = iscsi_remove_session(provider, host_no))) {
				printk("can't remove session (%d)\n", res);
				return -1;
			} else if (res) {
				printk("wrong session operation '%s'\n", op);
				return -1;
			}
		} else if (!strcmp("connection", mode)) {
			if (!strcmp("add", op) &&
			    res == 6 &&
			    (sock = sockfd_lookup(fd, &res)) != NULL &&
			    (res = iscsi_add_connection(provider, host_no,
							cid, sock))) {
				printk("can't add connection (%d)\n", res);
				return -1;
			} else if (!strcmp("remove", op) &&
			    res == 5 &&
			    (res = iscsi_remove_connection(provider,
							   host_no, cid))) {
				printk("can't remove connection (%d)\n", res);
				return -1;
			} else if (res) {
				printk("wrong connection operation '%s'\n", op);
				return -1;
			}
		} else {
			printk("wrong mode '%s'\n", mode);
			return -1;
		}
	}
	return count;
}
static CLASS_ATTR(session_operation, S_IWUSR, NULL,
		  iscsi_host_class_session_operation_store);

static int __init
iscsi_init(void)
{
	int ret;

	ret = class_register(&iscsi_host_class);
	if (ret) {
		printk("iSCSI: failed to register iSCSI class (%d).\n", ret);
		return ret;
	}

	strcpy(provider_table[ISCSI_PROVIDER_TCP].name,"tcp");
	ret = iscsi_tcp_register(&provider_table[ISCSI_PROVIDER_TCP].ops,
				 &provider_table[ISCSI_PROVIDER_TCP].caps);
	if (ret) {
		class_unregister(&iscsi_host_class);
		return ret;
	}

	class_create_file(&iscsi_host_class,
			  &class_attr_initiator_parameters);
	class_create_file(&iscsi_host_class,
			  &class_attr_session_operation);

	INIT_LIST_HEAD(&initiator.sessions);
	spin_lock_init(&initiator.sessions_lock);

	return 0;
}

static void __exit
iscsi_exit(void)
{
	iscsi_cleanup(&provider_table[ISCSI_PROVIDER_TCP]);
	class_remove_file(&iscsi_host_class,
			  &class_attr_session_operation);
	class_remove_file(&iscsi_host_class,
			  &class_attr_initiator_parameters);
	iscsi_tcp_unregister();
	class_unregister(&iscsi_host_class);
}

module_init(iscsi_init);
module_exit(iscsi_exit);
