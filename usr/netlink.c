/*
 * iSCSI Netlink/Linux Interface
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

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/netlink.h>

#include "iscsi_if.h"
#include "iscsi_ifev.h"
#include "iscsid.h"
#include "log.h"

static struct sockaddr_nl src_addr, dest_addr;
static void *xmitbuf = NULL;
static int xmitlen = 0;
static void *recvbuf = NULL;
static int recvlen = 0;

int
ctldev_read(int ctrl_fd, char *data, int count)
{
	memcpy(data, recvbuf + recvlen, count);
	recvlen += count;
	return count;
}

static int
nl_read(int ctrl_fd, struct nlmsghdr *nl, int flags)
{
	int rc;
	struct iovec iov;
	struct msghdr msg;

	iov.iov_base = nl;
	iov.iov_len = sizeof(*nl);

	memset(&msg, 0, sizeof(msg));
	msg.msg_name= (void*)&src_addr;
	msg.msg_namelen = sizeof(src_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	rc = recvmsg(ctrl_fd, &msg, flags);

	return rc;
}

static int
nlpayload_read(int ctrl_fd, char *data, int count, int flags)
{
	int rc;
	struct iovec iov;
	struct msghdr msg;

	iov.iov_base = calloc(1, NLMSG_SPACE(count));
	if (!iov.iov_base)
		return -ENOMEM;
	iov.iov_len = NLMSG_SPACE(count);

	memset(&msg, 0, sizeof(msg));
	msg.msg_name= (void*)&src_addr;
	msg.msg_namelen = sizeof(src_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	rc = recvmsg(ctrl_fd, &msg, flags);

	memcpy(data, NLMSG_DATA(iov.iov_base), count);

	free(iov.iov_base);

	return rc;
}

int
ctldev_writev(int ctrl_fd, enum iscsi_uevent_e type, struct iovec *iovp,
	      int count)
{
	int i, rc;
	struct nlmsghdr *nlh;
	struct msghdr msg;
	struct iovec iov;
	int datalen = 0;

	for (i = 0; i < count; i++) {
		datalen += iovp[i].iov_len;
	}

	if (xmitbuf && type != ISCSI_UEVENT_SEND_PDU) {
		for (i = 0; i < count; i++) {
			memcpy(xmitbuf + xmitlen,
			       iovp[i].iov_base, iovp[i].iov_len);
			xmitlen += iovp[i].iov_len;
		}
		return datalen;
	}

	nlh = (struct nlmsghdr *)calloc(1, NLMSG_SPACE(datalen));
	if (!nlh) {
		log_error("could not allocate memory for NL message");
		return -1;
	}
	nlh->nlmsg_len = NLMSG_SPACE(datalen);
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_type = type;

	datalen = 0;
	for (i = 0; i < count; i++) {
		memcpy(NLMSG_DATA(nlh) + datalen, iovp[i].iov_base,
		       iovp[i].iov_len);
		datalen += iovp[i].iov_len;
	}
	iov.iov_base = (void*)nlh;
	iov.iov_len = nlh->nlmsg_len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name= (void*)&dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	rc = sendmsg(ctrl_fd, &msg, 0);

	free(nlh);
	return rc;
}

static int
__ksession_call(int ctrl_fd, void *iov_base, int iov_len)
{
	int rc;
	struct iovec iov;
	struct iscsi_uevent *ev = iov_base;
	enum iscsi_uevent_e type = ev->type;

	iov.iov_base = iov_base;
	iov.iov_len = iov_len;

	if ((rc = ctldev_writev(ctrl_fd, type, &iov, 1)) < 0) {
		return rc;
	}

	do {
		if ((rc = nlpayload_read(ctrl_fd, (void*)ev,
					 sizeof(*ev), MSG_PEEK)) < 0) {
			return rc;
		}
		if (ev->type != type) {
			/*
			 * receive and queue async. event which as of
			 * today could be:
			 *	- CNX_ERROR
			 *	- RECV_PDU
			 */
			ctldev_handle(ctrl_fd);
		} else {
			if ((rc = nlpayload_read(ctrl_fd, (void*)ev,
						 sizeof(*ev), 0)) < 0) {
				return rc;
			}
			break;
		}
	} while (ev->type != type);

	return rc;
}

int
ksession_create(int ctrl_fd, iscsi_session_t *session)
{
	int rc;
	struct iscsi_uevent ev;

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_CREATE_SESSION;
	ev.transport_id = 0; /* FIXME: hardcoded */
	ev.u.c_session.session_handle = (ulong_t)session;
	ev.u.c_session.initial_cmdsn = session->nrec.session.initial_cmdsn;

	if ((rc = __ksession_call(ctrl_fd, &ev, sizeof(ev))) < 0) {
		log_error("can't create session with id = %d (%d)",
			  session->id, errno);
		return rc;
	}
	if (!ev.r.c_session_ret.handle || ev.r.c_session_ret.sid < 0)
		return -EIO;

	session->handle = ev.r.c_session_ret.handle;
	session->id = ev.r.c_session_ret.sid;
	log_debug(3, "created new iSCSI session, handle 0x%p",
		  (void*)session->handle);

	return 0;
}

int
ksession_destroy(int ctrl_fd, iscsi_session_t *session)
{
	int rc;
	struct iscsi_uevent ev;

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_DESTROY_SESSION;
	ev.transport_id = 0; /* FIXME: hardcoded */
	ev.u.d_session.session_handle = session->handle;

	if ((rc = __ksession_call(ctrl_fd, &ev, sizeof(ev))) < 0) {
		log_error("can't destroy session with id = %d (%d)",
			  session->id, errno);
		return rc;
	}

	log_warning("destroyed iSCSI session, handle 0x%p",
		  (void*)session->handle);

	return 0;
}

int
ksession_cnx_create(int ctrl_fd, iscsi_session_t *session, iscsi_conn_t *conn)
{
	int rc;
	struct iscsi_uevent ev;

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_CREATE_CNX;
	ev.transport_id = 0; /* FIXME: hardcoded */
	ev.u.c_cnx.session_handle = session->handle;
	ev.u.c_cnx.cnx_handle = (ulong_t)conn;
	ev.u.c_cnx.cid = conn->id;

	if ((rc = __ksession_call(ctrl_fd, &ev, sizeof(ev))) < 0) {
		log_error("can't create cnx with id = %d (%d)",
			  conn->id, errno);
		return rc;
	}
	if (!ev.r.handle)
		return -EIO;

	conn->handle = ev.r.handle;
	log_debug(3, "created new iSCSI connection, handle 0x%p",
		  (void*)conn->handle);
	return 0;
}

int
ksession_cnx_destroy(int ctrl_fd, iscsi_conn_t *conn)
{
	int rc;
	struct iscsi_uevent ev;

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_DESTROY_CNX;
	ev.transport_id = 0; /* FIXME: hardcoded */
	ev.u.d_cnx.cnx_handle = conn->handle;

	if ((rc = __ksession_call(ctrl_fd, &ev, sizeof(ev))) < 0) {
		log_error("can't destroy cnx with id = %d (%d)",
			  conn->id, errno);
		return rc;
	}

	log_warning("destroyed iSCSI connection, handle 0x%p",
		  (void*)conn->handle);
	return 0;
}

int
ksession_cnx_bind(int ctrl_fd, iscsi_session_t *session, iscsi_conn_t *conn)
{
	int rc;
	struct iscsi_uevent ev;

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_BIND_CNX;
	ev.transport_id = 0; /* FIXME: hardcoded */
	ev.u.b_cnx.session_handle = session->handle;
	ev.u.b_cnx.cnx_handle = conn->handle;
	ev.u.b_cnx.transport_fd = conn->socket_fd;
	ev.u.b_cnx.is_leading = (conn->id == 0);

	if ((rc = __ksession_call(ctrl_fd, &ev, sizeof(ev))) < 0) {
		log_error("can't bind a cnx with id = %d (%d)",
			  conn->id, errno);
		return rc;
	}
	if (!ev.r.retcode) {
		log_debug(3, "bound iSCSI connection (handle 0x%p) to "
			  "session (handle 0x%p)", (void*)conn->handle,
			  (void*)session->handle);
	} else {
		log_error("can't bind a cnx with id = %d, retcode %d",
			  conn->id, ev.r.retcode);
	}
	return ev.r.retcode;
}

int
ksession_send_pdu_begin(int ctrl_fd, iscsi_session_t *session,
			iscsi_conn_t *conn, int hdr_size, int data_size)
{
	struct iscsi_uevent *ev;

	if (xmitbuf) {
		log_error("send's begin state machine bug?");
		return -EIO;
	}

	xmitbuf = calloc(1, sizeof(*ev) + hdr_size + data_size);
	if (!xmitbuf) {
		log_error("can not allocate memory for xmitbuf");
		return -ENOMEM;
	}
	xmitlen = sizeof(*ev);
	ev = xmitbuf;
	memset(ev, 0, sizeof(*ev));
	ev->type = ISCSI_UEVENT_SEND_PDU;
	ev->transport_id = 0; /* FIXME: hardcoded */
	ev->u.send_pdu.cnx_handle = conn->handle;
	ev->u.send_pdu.hdr_size = hdr_size;
	ev->u.send_pdu.data_size = data_size;

	log_debug(3, "send PDU began for hdr %d bytes and data %d bytes",
		hdr_size, data_size);

	return 0;
}

int
ksession_send_pdu_end(int ctrl_fd, iscsi_session_t *session, iscsi_conn_t *conn)
{
	int rc;
	struct iscsi_uevent *ev;
	struct iovec iov;

	if (!xmitbuf) {
		log_error("send's end state machine bug?");
		return -EIO;
	}
	ev = xmitbuf;
	if (ev->u.send_pdu.cnx_handle != conn->handle) {
		log_error("send's end state machine corruption?");
		free(xmitbuf);
		xmitbuf = NULL;
		return -EIO;
	}

	iov.iov_base = xmitbuf;
	iov.iov_len = xmitlen;

	if ((rc = __ksession_call(ctrl_fd, xmitbuf, xmitlen)) < 0)
		goto err;
	if (ev->r.retcode)
		goto err;
	if (ev->type != ISCSI_UEVENT_SEND_PDU) {
		log_error("bad event?");
		free(xmitbuf);
		xmitbuf = NULL;
		return -EIO;
	}

	log_debug(3, "send PDU finished for cnx (handle %p)",
		(void*)conn->handle);

	free(xmitbuf);
	xmitbuf = NULL;
	return 0;

err:
	log_error("can't finish send PDU operation for cnx with "
		  "id = %d (%d), retcode %d",
		  conn->id, errno, ev->r.retcode);
	free(xmitbuf);
	xmitbuf = NULL;
	xmitlen = 0;
	return rc;
}

int
ksession_set_param(int ctrl_fd, iscsi_conn_t *conn, enum iscsi_param param,
		   uint32_t value)
{
	int rc;
	struct iscsi_uevent ev;

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_SET_PARAM;
	ev.transport_id = 0; /* FIXME: hardcoded */
	ev.u.set_param.cnx_handle = (ulong_t)conn->handle;
	ev.u.set_param.param = param;
	ev.u.set_param.value = value;

	if ((rc = __ksession_call(ctrl_fd, &ev, sizeof(ev))) < 0) {
		log_error("can't set operational parameter %d for cnx with "
			  "id = %d (%d)", param, conn->id, errno);
		return rc;
	}
	if (!ev.r.retcode) {
		log_debug(3, "set operational parameter %d to %u",
				param, value);
	} else {
		log_error("can't set operational parameter %d for cnx with "
			  "id = %d, retcode %d", param, conn->id, ev.r.retcode);
	}

	return ev.r.retcode;
}

int
ksession_stop_cnx(int ctrl_fd, iscsi_conn_t *conn, int flag)
{
	int rc;
	struct iscsi_uevent ev;

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_STOP_CNX;
	ev.transport_id = 0; /* FIXME: hardcoded */
	ev.u.stop_cnx.cnx_handle = conn->handle;
	ev.u.stop_cnx.flag = flag;

	if ((rc = __ksession_call(ctrl_fd, &ev, sizeof(ev))) < 0) {
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
ksession_start_cnx(int ctrl_fd, iscsi_conn_t *conn)
{
	int rc;
	struct iscsi_uevent ev;

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_START_CNX;
	ev.transport_id = 0; /* FIXME: hardcoded */
	ev.u.start_cnx.cnx_handle = conn->handle;

	if ((rc = __ksession_call(ctrl_fd, &ev, sizeof(ev))) < 0) {
		log_error("can't start connection 0x%p with "
			  "id = %d (%d)", (void*)conn->handle,
			  conn->id, errno);
		return rc;
	}
	if (!ev.r.retcode) {
		log_debug(3, "connection 0x%p is operational now",
				(void*)conn->handle);
	} else {
		log_error("can't start connection 0x%p with "
			  "id = %d, retcode %d", (void*)conn->handle,
			  conn->id, ev.r.retcode);
	}
	return ev.r.retcode;
}

int
ksession_recv_pdu_begin(int ctrl_fd, iscsi_conn_t *conn, ulong_t recv_handle,
				ulong_t *pdu_handle, int *pdu_size)
{
	if (recvbuf) {
		log_error("recv's begin state machine bug?");
		return -EIO;
	}
	recvbuf = (void*)recv_handle + sizeof(struct iscsi_uevent);
	recvlen = 0;
	*pdu_handle = recv_handle;

	log_debug(3, "recv PDU began, pdu handle 0x%p",
		  (void*)*pdu_handle);

	return 0;
}

int
ksession_recv_pdu_end(int ctrl_fd, iscsi_conn_t *conn, ulong_t pdu_handle)
{
	if (!recvbuf) {
		log_error("recv's end state machine bug?");
		return -EIO;
	}

	log_debug(3, "recv PDU finished for pdu handle 0x%p",
		  (void*)pdu_handle);

	free((void*)pdu_handle);
	recvbuf = NULL;
	return 0;
}

int
ctldev_handle(int ctrl_fd)
{
	int rc;
	struct iscsi_uevent *ev;
	struct qelem *item;
	iscsi_session_t *session = NULL;
	iscsi_conn_t *conn = NULL;
	ulong_t recv_handle;
	struct nlmsghdr nlh;
	int ev_size;

	if ((rc = nl_read(ctrl_fd, &nlh, MSG_PEEK)) < 0) {
		log_error("can not read nlmsghdr, error %d", rc);
		return rc;
	}

	ev_size = nlh.nlmsg_len - NLMSG_ALIGN(sizeof(struct nlmsghdr));
	recv_handle = (ulong_t)calloc(1, ev_size);
	if (!recv_handle) {
		log_error("can not allocate memory for receive handle");
		return -ENOMEM;
	}

	log_debug(6, "message real length is %d bytes, recv_handle %p",
		nlh.nlmsg_len, (void*)recv_handle);

	if ((rc = nlpayload_read(ctrl_fd, (void*)recv_handle,
				ev_size, 0)) < 0) {
		log_error("can not read from NL socket, error %d", rc);
		return rc;
	}
	ev = (struct iscsi_uevent *)recv_handle;

	/* verify connection */
	item = provider[0].sessions.q_forw;
	while (item != &provider[0].sessions) {
		int i;
		session = (iscsi_session_t *)item;
		for (i=0; i<ISCSI_CNX_MAX; i++) {
			if (&session->cnx[i] == (iscsi_conn_t*)
					iscsi_ptr(ev->r.recv_req.cnx_handle) ||
			    &session->cnx[i] == (iscsi_conn_t*)
					iscsi_ptr(ev->r.cnxerror.cnx_handle)) {
				conn = &session->cnx[i];
				break;
			}
		}
		item = item->q_forw;
	}

	if (ev->type == ISCSI_KEVENT_RECV_PDU) {
		if (conn == NULL) {
			log_error("could not verify connection 0x%p for "
				  "event RECV_PDU", conn);
			return -ENXIO;
		}

		/* produce an event, so session manager will handle */
		queue_produce(session->queue, EV_CNX_RECV_PDU, conn,
			sizeof(ulong_t), &recv_handle);
		actor_schedule(&session->mainloop);

	} else if (ev->type == ISCSI_KEVENT_CNX_ERROR) {
		if (conn == NULL) {
			log_error("could not verify connection 0x%p for "
				  "event CNX_ERR", conn);
			return -ENXIO;
		}

		/* produce an event, so session manager will handle */
		queue_produce(session->queue, EV_CNX_ERROR, conn,
			sizeof(ulong_t), (void*)&ev->r.cnxerror.error);
		actor_schedule(&session->mainloop);

	} else {
		log_error("unknown kernel event %d", ev->type);
		return -EEXIST;
	}

	return 0;
}

int ctldev_open(void)
{
	int ctrl_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ISCSI);
	if (!ctrl_fd) {
		log_error("can not create NETLINK_ISCSI socket");
		return -1;
	}

	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();
	src_addr.nl_groups = 0; /* not in mcast groups */
	if (bind(ctrl_fd, (struct sockaddr *)&src_addr, sizeof(src_addr))) {
		log_error("can not bind NETLINK_ISCSI socket");
		return -1;
	}

	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = 0; /* kernel */
	dest_addr.nl_groups = 0; /* unicast */

	log_debug(7, "created NETLINK_ISCSI socket...");

	return ctrl_fd;
}

void
ctldev_close(int ctrl_fd)
{
	close(ctrl_fd);
}
