/*
 * iSCSI Ioctl and SysFS control
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

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "iscsi_u.h"
#include "iscsid.h"
#include "log.h"

#define CTL_DEVICE	"/dev/iscsictl"
#define SYSFS_ROOT	"/sysfs/class/iscsi"

static int ctrl_fd;

int
ctldev_read(iscsi_conn_t *conn, char *data, int count)
{
	return read(ctrl_fd, data, count);
}

int
ctldev_writev(iscsi_conn_t *conn, struct iovec *iovp, int count)
{
	return writev(ctrl_fd, iovp, count);
}

int
ksession_create(iscsi_session_t *session)
{
	int rc;
	iscsi_uevent_t ev;

	memset(&ev, 0, sizeof(iscsi_uevent_t));

	ev.type = ISCSI_UEVENT_CREATE_SESSION;
	ev.provider_id = 0; /* FIXME: hardcoded */
	ev.u.c_session.session_handle = (ulong_t)session;
	ev.u.c_session.sid = session->id;
	ev.u.c_session.initial_cmdsn = session->nrec.session.initial_cmdsn;

	if ((rc = ioctl(ctrl_fd, ISCSI_UEVENT_CREATE_SESSION, &ev)) < 0) {
		log_error("can't create session with id = %d (%d)",
			  session->id, errno);
		return rc;
	}

	session->handle = ev.r.handle;
	log_debug(3, "created new iSCSI session, handle 0x%p",
		  (void*)session->handle);

	return 0;
}

int
ksession_destroy(iscsi_session_t *session)
{
	int rc;
	iscsi_uevent_t ev;

	memset(&ev, 0, sizeof(iscsi_uevent_t));

	ev.type = ISCSI_UEVENT_DESTROY_SESSION;
	ev.provider_id = 0; /* FIXME: hardcoded */
	ev.u.d_session.session_handle = session->handle;

	if ((rc = ioctl(ctrl_fd, ISCSI_UEVENT_DESTROY_SESSION, &ev)) < 0) {
		log_error("can't destroy session with id = %d (%d)",
			  session->id, errno);
		return rc;
	}

	log_warning("destroyed iSCSI session, handle 0x%p",
		  (void*)session->handle);

	return 0;
}

int
ksession_cnx_create(iscsi_session_t *session, iscsi_conn_t *conn)
{
	int rc;
	iscsi_uevent_t ev;

	memset(&ev, 0, sizeof(iscsi_uevent_t));

	ev.type = ISCSI_UEVENT_CREATE_CNX;
	ev.provider_id = 0; /* FIXME: hardcoded */
	ev.u.c_cnx.session_handle = session->handle;
	ev.u.c_cnx.cnx_handle = (ulong_t)conn;
	ev.u.c_cnx.socket_fd = conn->socket_fd;
	ev.u.c_cnx.cid = conn->id;

	if ((rc = ioctl(ctrl_fd, ISCSI_UEVENT_CREATE_CNX, &ev)) < 0) {
		log_error("can't create cnx with id = %d (%d)",
			  conn->id, errno);
		return rc;
	}

	conn->handle = ev.r.handle;
	log_debug(3, "created new iSCSI connection, handle 0x%p",
		  (void*)conn->handle);
	return 0;
}

int
ksession_cnx_destroy(iscsi_conn_t *conn)
{
	int rc;
	iscsi_uevent_t ev;

	memset(&ev, 0, sizeof(iscsi_uevent_t));

	ev.type = ISCSI_UEVENT_DESTROY_CNX;
	ev.provider_id = 0; /* FIXME: hardcoded */
	ev.u.d_cnx.cnx_handle = conn->handle;

	if ((rc = ioctl(ctrl_fd, ISCSI_UEVENT_DESTROY_CNX, &ev)) < 0) {
		log_error("can't destroy cnx with id = %d (%d)",
			  conn->id, errno);
		return rc;
	}

	log_warning("destroyed iSCSI connection, handle 0x%p",
		  (void*)conn->handle);
	return 0;
}

int
ksession_cnx_bind(iscsi_session_t *session, iscsi_conn_t *conn)
{
	int rc;
	iscsi_uevent_t ev;

	memset(&ev, 0, sizeof(iscsi_uevent_t));

	ev.type = ISCSI_UEVENT_BIND_CNX;
	ev.provider_id = 0; /* FIXME: hardcoded */
	ev.u.b_cnx.session_handle = session->handle;
	ev.u.b_cnx.cnx_handle = conn->handle;
	ev.u.b_cnx.is_leading = (conn->id == 0);

	if ((rc = ioctl(ctrl_fd, ISCSI_UEVENT_BIND_CNX, &ev)) < 0) {
		log_error("can't bind a cnx with id = %d (%d), retcode %d",
			  conn->id, errno,  ev.r.retcode);
		return rc;
	}

	log_debug(3, "binded iSCSI connection (handle 0x%p) to "
		  "session (handle 0x%p)", (void*)conn->handle,
		  (void*)session->handle);
	return 0;
}

int
ksession_send_pdu_begin(iscsi_session_t *session, iscsi_conn_t *conn,
			int hdr_size, int data_size)
{
	int rc;
	iscsi_uevent_t ev;

	memset(&ev, 0, sizeof(iscsi_uevent_t));

	ev.type = ISCSI_UEVENT_SEND_PDU_BEGIN;
	ev.provider_id = 0; /* FIXME: hardcoded */
	ev.u.sp_begin.cnx_handle = conn->handle;
	ev.u.sp_begin.hdr_size = hdr_size;
	ev.u.sp_begin.data_size = data_size;

	if ((rc = ioctl(ctrl_fd, ISCSI_UEVENT_SEND_PDU_BEGIN, &ev)) < 0) {
		log_error("can't initiate send PDU operation for cnx with "
			  "id = %d (%d), retcode %d",
			  conn->id, errno, ev.r.retcode);
		return rc;
	}

	log_debug(3, "send PDU began for hdr %d bytes and data %d bytes",
		hdr_size, data_size);
	return 0;
}

int
ksession_send_pdu_end(iscsi_session_t *session, iscsi_conn_t *conn)
{
	int rc;
	iscsi_uevent_t ev;

	memset(&ev, 0, sizeof(iscsi_uevent_t));

	ev.type = ISCSI_UEVENT_SEND_PDU_END;
	ev.provider_id = 0; /* FIXME: hardcoded */
	ev.u.sp_end.cnx_handle = conn->handle;

	if ((rc = ioctl(ctrl_fd, ISCSI_UEVENT_SEND_PDU_END, &ev)) < 0) {
		log_error("can't finish send PDU operation for cnx with "
			  "id = %d (%d), retcode %d",
			  conn->id, errno, ev.r.retcode);
		return rc;
	}

	log_debug(3, "send PDU finished for cnx (handle %p)",
		(void*)conn->handle);
	return 0;
}

int
ksession_set_param(iscsi_conn_t *conn, iscsi_param_e param, uint32_t value)
{
	int rc;
	iscsi_uevent_t ev;

	memset(&ev, 0, sizeof(iscsi_uevent_t));

	ev.type = ISCSI_UEVENT_SET_PARAM;
	ev.provider_id = 0; /* FIXME: hardcoded */
	ev.u.set_param.cnx_handle = (ulong_t)conn->handle;
	ev.u.set_param.param = param;
	ev.u.set_param.value = value;

	if ((rc = ioctl(ctrl_fd, ISCSI_UEVENT_SET_PARAM, &ev)) < 0) {
		log_error("can't set operational parameter %d for cnx with "
			  "id = %d (%d)", param, conn->id, errno);
		return rc;
	}

	log_debug(3, "set operational parameter %d to %u",
			param, value);

	return 0;
}

int
ksession_stop_cnx(iscsi_conn_t *conn)
{
	int rc;
	iscsi_uevent_t ev;

	memset(&ev, 0, sizeof(iscsi_uevent_t));

	ev.type = ISCSI_UEVENT_STOP_CNX;
	ev.provider_id = 0; /* FIXME: hardcoded */
	ev.u.stop_cnx.cnx_handle = conn->handle;

	if ((rc = ioctl(ctrl_fd, ISCSI_UEVENT_STOP_CNX, &ev)) < 0) {
		log_error("can't stop connection 0x%p with "
			  "id = %d (%d)", (void*)conn->handle,
			  conn->id, errno);
		return rc;
	}

	log_debug(3, "connection 0x%p is stopped now",
			(void*)conn->handle);
	return 0;
}

int
ksession_start_cnx(iscsi_conn_t *conn)
{
	int rc;
	iscsi_uevent_t ev;

	memset(&ev, 0, sizeof(iscsi_uevent_t));

	ev.type = ISCSI_UEVENT_START_CNX;
	ev.provider_id = 0; /* FIXME: hardcoded */
	ev.u.start_cnx.cnx_handle = conn->handle;

	if ((rc = ioctl(ctrl_fd, ISCSI_UEVENT_START_CNX, &ev)) < 0) {
		log_error("can't start connection 0x%p with "
			  "id = %d (%d)", (void*)conn->handle,
			  conn->id, errno);
		return rc;
	}

	log_debug(3, "connection 0x%p is operational now",
			(void*)conn->handle);
	return 0;
}

int
ksession_recv_pdu_begin(iscsi_conn_t *conn, ulong_t recv_handle,
				ulong_t *pdu_handle, int *pdu_size)
{
	int rc;
	iscsi_uevent_t ev;

	memset(&ev, 0, sizeof(iscsi_uevent_t));

	ev.type = ISCSI_UEVENT_RECV_PDU_BEGIN;
	ev.provider_id = 0; /* FIXME: hardcoded */
	ev.u.rp_begin.cpcnx_handle = (ulong_t)conn;
	ev.u.rp_begin.recv_handle = recv_handle;

	if ((rc = ioctl(ctrl_fd, ISCSI_UEVENT_RECV_PDU_BEGIN, &ev)) < 0) {
		log_error("can't initiate recv PDU operation for cnx with "
			  "id = %d (%d)", conn->id, errno);
		return rc;
	}

	*pdu_handle = ev.r.rp_begin.pdu_handle;
	*pdu_size = ev.r.rp_begin.pdu_size;

	log_debug(3, "recv PDU began, pdu handle 0x%p size %d",
		  (void*)*pdu_handle, *pdu_size);
	return 0;
}

int
ksession_recv_pdu_end(iscsi_conn_t *conn, ulong_t pdu_handle)
{
	int rc;
	iscsi_uevent_t ev;

	memset(&ev, 0, sizeof(iscsi_uevent_t));

	ev.type = ISCSI_UEVENT_RECV_PDU_END;
	ev.provider_id = 0; /* FIXME: hardcoded */
	ev.u.rp_end.cpcnx_handle = (ulong_t)conn;
	ev.u.rp_end.pdu_handle = pdu_handle;

	if ((rc = ioctl(ctrl_fd, ISCSI_UEVENT_RECV_PDU_END, &ev)) < 0) {
		log_error("can't finish recv PDU operation for cnx with "
			  "id = %d (%d)", conn->id, errno);
		return rc;
	}

	log_debug(3, "recv PDU finished for pdu handle 0x%p",
		  (void*)pdu_handle);
	return 0;
}

int
ctldev_handle(int fd)
{
	int rc;
	iscsi_uevent_t ev;
	struct qelem *item;
	iscsi_session_t *session = NULL;
	iscsi_conn_t *conn = NULL;

	if ((rc = ioctl(fd, ISCSI_UEVENT_RECV_REQ, &ev)) < 0) {
		log_error("can't fetch recv event information "
			  "(%d), retcode %d", errno, rc);
		return rc;
	}

	/* verify connection */
	item = provider[0].sessions.q_forw;
	while (item != &provider[0].sessions) {
		int i;
		session = (iscsi_session_t *)item;
		for (i=0; i<ISCSI_CNX_MAX; i++) {
			if (&session->cnx[i] == (iscsi_conn_t*)
					ev.r.recv_req.cnx_handle) {
				conn = &session->cnx[i];
				break;
			}
		}
		item = item->q_forw;
	}

	if (ev.type == ISCSI_KEVENT_RECV_PDU) {
		if (conn == NULL) {
			log_error("could not verify connection 0x%p for "
				  "event RECV_PDU", conn);
			return -ENXIO;
		}

		/* produce an event, so session manager will handle */
		queue_produce(session->queue, EV_CNX_RECV_PDU, conn,
			sizeof(ulong_t), (void*)&ev.r.recv_req.recv_handle);
		actor_schedule(&session->mainloop);

	} else if (ev.type == ISCSI_KEVENT_CNX_ERROR) {
		if (conn == NULL) {
			log_error("could not verify connection 0x%p for "
				  "event CNX_ERR", conn);
			return -ENXIO;
		}

		/* produce an event, so session manager will handle */
		queue_produce(session->queue, EV_CNX_ERROR, conn,
			sizeof(ulong_t), (void*)&ev.r.recv_req.recv_handle);
		actor_schedule(&session->mainloop);

	} else {
		log_error("unknown kernel event %d", ev.type);
	}

	return 0;
}

int ctldev_open(void)
{
	FILE *f = NULL;
	char devname[256];
	char buf[256];
	int devn;
	int ctlfd;

	f = fopen("/proc/devices", "r");
	if (!f) {
		log_error("cannot open control path to the driver");
		return -1;
	}

	devn = 0;
	while (!feof(f)) {
		if (!fgets(buf, sizeof (buf), f)) {
			break;
		}
		if (sscanf(buf, "%d %s", &devn, devname) != 2) {
			continue;
		}
		if (!strcmp(devname, "iscsictl")) {
			break;
		}
		devn = 0;
	}

	fclose(f);
	if (!devn) {
		log_error("cannot find iscsictl in /proc/devices - "
		     "make sure the module is loaded");
		return -1;
	}

	unlink(CTL_DEVICE);
	if (mknod(CTL_DEVICE, (S_IFCHR | 0600), (devn << 8))) {
		log_error("cannot create %s %d", CTL_DEVICE, errno);
		return -1;
	}

	ctlfd = open(CTL_DEVICE, O_RDWR);
	if (ctlfd < 0) {
		log_error("cannot open %s %d", CTL_DEVICE, errno);
		return -1;
	}

	log_debug(1, CTL_DEVICE " is opened!");

	return ctlfd;
}

void
ctldev_close(int fd)
{
	close(fd);
}
