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
#include "iscsi_ipc.h"

static int ctrl_fd;
static struct sockaddr_nl src_addr, dest_addr;
static void *xmitbuf = NULL;
static int xmitlen = 0;
static void *recvbuf = NULL;
static int recvlen = 0;
static void *nlm_sendbuf;
static void *nlm_recvbuf;
static void *pdu_sendbuf;

static int ctldev_handle(void);

#define NLM_BUF_DEFAULT_MAX \
	(NLMSG_SPACE(DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH + \
			 sizeof(struct iscsi_hdr)))

#define PDU_SENDBUF_DEFAULT_MAX \
	(DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH + sizeof(struct iscsi_hdr))

static int
kread(char *data, int count)
{
	log_debug(7, "in %s", __FUNCTION__);

	memcpy(data, recvbuf + recvlen, count);
	recvlen += count;
	return count;
}

static int
nl_read(int ctrl_fd, char *data, int size, int flags)
{
	int rc;
	struct iovec iov;
	struct msghdr msg;

	log_debug(7, "in %s", __FUNCTION__);

	iov.iov_base = data;
	iov.iov_len = size;

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

	log_debug(7, "in %s", __FUNCTION__);

	iov.iov_base = nlm_recvbuf;
	iov.iov_len = NLMSG_SPACE(count);
	memset(iov.iov_base, 0, iov.iov_len);

	memset(&msg, 0, sizeof(msg));
	msg.msg_name= (void*)&src_addr;
	msg.msg_namelen = sizeof(src_addr);
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;

	/*
	 * Netlink recvmsg call path:
	 *
	 *  - transport api callback
	 *  - iscsi_control_cnx_error (should succeed)
	 *  - iscsi_unicast_skb (must succeed)
	 *  - netlink_unicast (must succeed)
	 *  - netlink_data_ready (must succeed)
	 *  - netlink_sendskb (must succeed)
	 *  - netlink_recvmsg (must succeed)
	 *  - sock_recvmsg (must succeed)
	 *  - sys_recvmsg (must succeed)
	 *  - sys_socketcall (must succeed)
	 *  - syscall_call (must succeed)
	 *
	 *  Note1: "must succeed" means succeed unless bug in daemon.
	 *        It also means - no sleep and memory allocation on
	 *        the path.
	 *
	 *  Note2: "should succeed" means will succeed in most of cases
	 *        because of mempool preallocation.
	 *
	 *  FIXME: if "Note2" than interface should generate iSCSI error
	 *        level 0 on its own. Interface must always succeed on this.
	 */
	rc = recvmsg(ctrl_fd, &msg, flags);

	memcpy(data, NLMSG_DATA(iov.iov_base), count);

	return rc;
}

static int
kwritev(enum iscsi_uevent_e type, struct iovec *iovp, int count)
{
	int i, rc;
	struct nlmsghdr *nlh;
	struct msghdr msg;
	struct iovec iov;
	int datalen = 0;

	log_debug(7, "in %s", __FUNCTION__);

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

	nlh = nlm_sendbuf;
	memset(nlh, 0, NLMSG_SPACE(datalen));

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

	do {
		/*
		 * Netlink down call path:
		 *
		 *  - transport api call
		 *  - iscsi_if_recv_msg (must succeed)
		 *  - iscsi_if_rx (must succeed)
		 *  - netlink_data_ready (must succeed)
		 *  - netlink_sendskb (must succeed)
		 *  - netlink_sendmsg (alloc_skb() might fail)
		 *  - sock_sendmsg (must succeed)
		 *  - sys_sendmsg (must succeed)
		 *  - sys_socketcall (must succeed)
		 *  - syscall_call (must succeed)
		 *
		 *  Note1: "must succeed" means succeed unless bug in daemon.
		 *        It also means - no sleep and memory allocation on
		 *        the path.
		 *
		 *  Note2: netlink_sendmsg() might fail because of OOM. Since
		 *         we are in user-space, we will sleep until we succeed.
		 */

		rc = sendmsg(ctrl_fd, &msg, 0);
		if (rc == -ENOMEM) {
			log_debug(1, "sendmsg: alloc_skb() failed");
			sleep(1);
		} else if (rc < 0) {
			log_error("sendmsg: bug? ctrl_fd %d", ctrl_fd);
			exit(rc);
		}
	} while (rc < 0);

	return rc;
}

/*
 * __kipc_call() should never block. Therefore
 * Netlink's xmit logic is serialized. This means we do not allocate on
 * xmit path. Instead we reuse nlm_sendbuf buffer.
 *
 * Transport must assure non-blocking operations for:
 *
 *	- snx_create()
 *	- cnx_create()
 *	- cnx_bind()
 *	_ set_param()
 *	- cnx_start()
 *	- cnx_stop()
 *
 * Its OK to block for cleanup for short period of time in operatations for:
 *
 *	- cnx_destroy()
 *	- snx_destroy()
 *
 * FIXME: interface needs to be extended to allow longer blocking on
 *        cleanup. (Dima)
 */
static int
__kipc_call(void *iov_base, int iov_len)
{
	int rc;
	struct iovec iov;
	struct iscsi_uevent *ev = iov_base;
	enum iscsi_uevent_e type = ev->type;

	log_debug(7, "in %s", __FUNCTION__);

	iov.iov_base = iov_base;
	iov.iov_len = iov_len;

	rc = kwritev(type, &iov, 1);

	do {
		if ((rc = nlpayload_read(ctrl_fd, (void*)ev,
					 sizeof(*ev), MSG_PEEK)) < 0) {
			return rc;
		}
		if (ev->type != type) {
			log_debug(1, "expecting event %d, got %d, handling...",
				  type, ev->type);
			if (ev->type == ISCSI_KEVENT_IF_ERROR) {
				if ((rc = nlpayload_read(ctrl_fd, (void*)ev,
							 sizeof(*ev), 0)) < 0) {
					return rc;
				}
				log_error("received iferror %d", ev->iferror);
				return ev->iferror;
			}
			/*
			 * receive and queue async. event which as of
			 * today could be:
			 *	- CNX_ERROR
			 *	- RECV_PDU
			 */
			ctldev_handle();
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

static int
kcreate_session(uint64_t transport_handle, uint32_t initial_cmdsn,
		uint64_t *out_handle, uint32_t *out_sid)
{
	int rc;
	struct iscsi_uevent ev;

	log_debug(7, "in %s", __FUNCTION__);

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_CREATE_SESSION;
	ev.transport_handle = transport_handle;
	ev.u.c_session.initial_cmdsn = initial_cmdsn;

	if ((rc = __kipc_call(&ev, sizeof(ev))) < 0) {
		return rc;
	}
	if (!ev.r.c_session_ret.session_handle || ev.r.c_session_ret.sid < 0)
		return -EIO;

	*out_handle = ev.r.c_session_ret.session_handle;
	*out_sid = ev.r.c_session_ret.sid;

	return 0;
}

static int
kdestroy_session(uint64_t transport_handle, uint64_t snxh, uint32_t sid)
{
	int rc;
	struct iscsi_uevent ev;

	log_debug(7, "in %s", __FUNCTION__);

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_DESTROY_SESSION;
	ev.transport_handle = transport_handle;
	ev.u.d_session.session_handle = snxh;
	ev.u.d_session.sid = sid;

	if ((rc = __kipc_call(&ev, sizeof(ev))) < 0) {
		return rc;
	}

	return 0;
}

static int
kcreate_cnx(uint64_t transport_handle, uint64_t snxh, uint32_t sid,
	    uint32_t cid, uint64_t *out_handle)
{
	int rc;
	struct iscsi_uevent ev;

	log_debug(7, "in %s", __FUNCTION__);

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_CREATE_CNX;
	ev.transport_handle = transport_handle;
	ev.u.c_cnx.session_handle = snxh;
	ev.u.c_cnx.cid = cid;
	ev.u.c_cnx.sid = sid;

	if ((rc = __kipc_call(&ev, sizeof(ev))) < 0) {
		return rc;
	}
	if (!ev.r.handle)
		return -EIO;

	*out_handle = ev.r.handle;
	return 0;
}

static int
kdestroy_cnx(uint64_t transport_handle, uint64_t cnxh, int cid)
{
	int rc;
	struct iscsi_uevent ev;

	log_debug(7, "in %s", __FUNCTION__);

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_DESTROY_CNX;
	ev.transport_handle = transport_handle;
	ev.u.d_cnx.cnx_handle = cnxh;
	ev.u.d_cnx.cid = cid;

	if ((rc = __kipc_call(&ev, sizeof(ev))) < 0) {
		return rc;
	}

	return 0;
}

static int
kbind_cnx(uint64_t transport_handle, uint64_t snxh, uint64_t cnxh,
	  uint32_t transport_fd, int is_leading, int *retcode)
{
	int rc;
	struct iscsi_uevent ev;

	log_debug(7, "in %s", __FUNCTION__);

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_BIND_CNX;
	ev.transport_handle = transport_handle;
	ev.u.b_cnx.session_handle = snxh;
	ev.u.b_cnx.cnx_handle = cnxh;
	ev.u.b_cnx.transport_fd = transport_fd;
	ev.u.b_cnx.is_leading = is_leading;

	if ((rc = __kipc_call(&ev, sizeof(ev))) < 0) {
		return rc;
	}

	*retcode = ev.r.retcode;

	return 0;
}

static void
ksend_pdu_begin(uint64_t transport_handle, uint64_t cnxh,
			int hdr_size, int data_size)
{
	struct iscsi_uevent *ev;

	log_debug(7, "in %s", __FUNCTION__);

	if (xmitbuf) {
		log_error("send's begin state machine bug?");
		exit(-EIO);
	}

	xmitbuf = pdu_sendbuf;
	memset(xmitbuf, 0, sizeof(*ev) + hdr_size + data_size);
	xmitlen = sizeof(*ev);
	ev = xmitbuf;
	memset(ev, 0, sizeof(*ev));
	ev->type = ISCSI_UEVENT_SEND_PDU;
	ev->transport_handle = transport_handle;
	ev->u.send_pdu.cnx_handle = cnxh;
	ev->u.send_pdu.hdr_size = hdr_size;
	ev->u.send_pdu.data_size = data_size;

	log_debug(3, "send PDU began for hdr %d bytes and data %d bytes",
		hdr_size, data_size);
}

static int
ksend_pdu_end(uint64_t transport_handle, uint64_t cnxh, int *retcode)
{
	int rc;
	struct iscsi_uevent *ev;
	struct iovec iov;

	log_debug(7, "in %s", __FUNCTION__);

	if (!xmitbuf) {
		log_error("send's end state machine bug?");
		exit(-EIO);
	}
	ev = xmitbuf;
	if (ev->u.send_pdu.cnx_handle != cnxh) {
		log_error("send's end state machine corruption?");
		exit(-EIO);
	}

	iov.iov_base = xmitbuf;
	iov.iov_len = xmitlen;

	if ((rc = __kipc_call(xmitbuf, xmitlen)) < 0)
		goto err;
	if (ev->r.retcode) {
		*retcode = ev->r.retcode;
		goto err;
	}
	if (ev->type != ISCSI_UEVENT_SEND_PDU) {
		log_error("bad event: bug on send_pdu_end?");
		exit(-EIO);
	}

	log_debug(3, "send PDU finished for cnx (handle %p)", iscsi_ptr(cnxh));

	xmitbuf = NULL;
	return 0;

err:
	xmitbuf = NULL;
	xmitlen = 0;
	return rc;
}

static int
kset_param(uint64_t transport_handle, uint64_t cnxh,
	       enum iscsi_param param, uint32_t value, int *retcode)
{
	int rc;
	struct iscsi_uevent ev;

	log_debug(7, "in %s", __FUNCTION__);

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_SET_PARAM;
	ev.transport_handle = transport_handle;
	ev.u.set_param.cnx_handle = cnxh;
	ev.u.set_param.param = param;
	ev.u.set_param.value = value;

	if ((rc = __kipc_call(&ev, sizeof(ev))) < 0) {
		return rc;
	}

	*retcode = ev.r.retcode;

	return 0;
}

static int
kstop_cnx(uint64_t transport_handle, uint64_t cnxh, int flag)
{
	int rc;
	struct iscsi_uevent ev;

	log_debug(7, "in %s", __FUNCTION__);

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_STOP_CNX;
	ev.transport_handle = transport_handle;
	ev.u.stop_cnx.cnx_handle = cnxh;
	ev.u.stop_cnx.flag = flag;

	if ((rc = __kipc_call(&ev, sizeof(ev))) < 0) {
		return rc;
	}

	return 0;
}

static int
kstart_cnx(uint64_t transport_handle, uint64_t cnxh, int *retcode)
{
	int rc;
	struct iscsi_uevent ev;

	log_debug(7, "in %s", __FUNCTION__);

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_START_CNX;
	ev.transport_handle = transport_handle;
	ev.u.start_cnx.cnx_handle = cnxh;

	if ((rc = __kipc_call(&ev, sizeof(ev))) < 0) {
		return rc;
	}

	*retcode = ev.r.retcode;
	return 0;
}

static int
krecv_pdu_begin(uint64_t transport_handle, uint64_t cnxh,
		uintptr_t recv_handle, uintptr_t *pdu_handle, int *pdu_size)
{
	log_debug(7, "in %s", __FUNCTION__);

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

static int
krecv_pdu_end(uint64_t transport_handle, uintptr_t conn_handle,
	      uintptr_t pdu_handle)
{
	log_debug(7, "in %s", __FUNCTION__);

	if (!recvbuf) {
		log_error("recv's end state machine bug?");
		return -EIO;
	}

	log_debug(3, "recv PDU finished for pdu handle 0x%p",
		  (void*)pdu_handle);

	recvpool_put((void*)conn_handle, (void*)pdu_handle);
	recvbuf = NULL;
	return 0;
}

static int
ktrans_list(struct iscsi_uevent *ev)
{
	int rc;

	log_debug(7, "in %s", __FUNCTION__);

	memset(ev, 0, sizeof(struct iscsi_uevent));

	ev->type = ISCSI_UEVENT_TRANS_LIST;

	if ((rc = __kipc_call(ev, sizeof(*ev))) < 0) {
		return rc;
	}

	return 0;
}

static int
ctldev_handle(void)
{
	int rc;
	struct iscsi_uevent *ev;
	struct qelem *item;
	iscsi_session_t *session = NULL;
	iscsi_conn_t *conn = NULL;
	uintptr_t recv_handle;
	char nlm_ev[NLMSG_SPACE(sizeof(struct iscsi_uevent))];
	struct nlmsghdr *nlh;
	int ev_size;

	log_debug(7, "in %s", __FUNCTION__);

	if ((rc = nl_read(ctrl_fd, nlm_ev,
		NLMSG_SPACE(sizeof(struct iscsi_uevent)), MSG_PEEK)) < 0) {
		log_error("can not read nlm_ev, error %d", rc);
		return rc;
	}
	nlh = (struct nlmsghdr *)nlm_ev;
	ev = (struct iscsi_uevent *)NLMSG_DATA(nlm_ev);

	/* verify connection */
	item = provider[0].sessions.q_forw;
	while (item != &provider[0].sessions) {
		int i;
		session = (iscsi_session_t *)item;
		for (i=0; i<ISCSI_CNX_MAX; i++) {
			if (ev->type == ISCSI_KEVENT_RECV_PDU &&
			    ev->r.recv_req.cnx_handle &&
			    session->cnx[i].handle ==
					ev->r.recv_req.cnx_handle) {
				conn = &session->cnx[i];
				break;
			}
			if (ev->type == ISCSI_KEVENT_CNX_ERROR &&
			    ev->r.cnxerror.cnx_handle &&
			    session->cnx[i].handle ==
					ev->r.cnxerror.cnx_handle) {
				conn = &session->cnx[i];
				break;
			}
		}
		item = item->q_forw;
	}
	if (conn == NULL) {
		log_error("could not verify connection 0x%p ", conn);
		return -ENXIO;
	}

	ev_size = nlh->nlmsg_len - NLMSG_ALIGN(sizeof(struct nlmsghdr));
	recv_handle = (uintptr_t)recvpool_get(conn, ev_size);
	if (!recv_handle) {
		log_error("can not allocate memory for receive handle");
		return -ENOMEM;
	}

	log_debug(6, "message real length is %d bytes, recv_handle %p",
		nlh->nlmsg_len, (void*)recv_handle);

	if ((rc = nlpayload_read(ctrl_fd, (void*)recv_handle,
				ev_size, 0)) < 0) {
		recvpool_put(conn, (void*)recv_handle);
		log_error("can not read from NL socket, error %d", rc);
		return rc;
	}

	if (ev->type == ISCSI_KEVENT_RECV_PDU) {
		/* produce an event, so session manager will handle */
		queue_produce(session->queue, EV_CNX_RECV_PDU, conn,
			sizeof(uintptr_t), &recv_handle);
		actor_schedule(&session->mainloop);
	} else if (ev->type == ISCSI_KEVENT_CNX_ERROR) {
		/* produce an event, so session manager will handle */
		queue_produce(session->queue, EV_CNX_ERROR, conn,
			sizeof(uintptr_t), (void*)&ev->r.cnxerror.error);
		actor_schedule(&session->mainloop);
		recvpool_put(conn, (void*)recv_handle);
	} else {
		recvpool_put(conn, (void*)recv_handle);
		log_error("unknown kernel event %d", ev->type);
		return -EEXIST;
	}

	return 0;
}

static int
ctldev_open(void)
{
	log_debug(7, "in %s", __FUNCTION__);

	nlm_sendbuf = calloc(1, NLM_BUF_DEFAULT_MAX);
	if (!nlm_sendbuf) {
		log_error("can not allocate nlm_sendbuf");
		return -1;
	}

	nlm_recvbuf = calloc(1, NLM_BUF_DEFAULT_MAX);
	if (!nlm_recvbuf) {
		free(nlm_sendbuf);
		log_error("can not allocate nlm_recvbuf");
		return -1;
	}

	pdu_sendbuf = calloc(1, PDU_SENDBUF_DEFAULT_MAX);
	if (!pdu_sendbuf) {
		free(nlm_recvbuf);
		free(nlm_sendbuf);
		log_error("can not allocate nlm_sendbuf");
		return -1;
	}

	ctrl_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ISCSI);
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

static void
ctldev_close(void)
{
	log_debug(7, "in %s", __FUNCTION__);

	free(pdu_sendbuf);
	free(nlm_recvbuf);
	free(nlm_sendbuf);
	close(ctrl_fd);
}

struct iscsi_ipc nl_ipc = {
	.name                   = "Open-iSCSI Kernel IPC/NETLINK v.1",
	.ctldev_bufmax		= NLM_BUF_DEFAULT_MAX,
	.ctldev_open		= ctldev_open,
	.ctldev_close		= ctldev_close,
	.ctldev_handle		= ctldev_handle,
	.trans_list		= ktrans_list,
	.create_session         = kcreate_session,
	.destroy_session        = kdestroy_session,
	.create_cnx             = kcreate_cnx,
	.destroy_cnx            = kdestroy_cnx,
	.bind_cnx               = kbind_cnx,
	.set_param              = kset_param,
	.get_param              = NULL,
	.start_cnx              = kstart_cnx,
	.stop_cnx               = kstop_cnx,
	.writev			= kwritev,
	.send_pdu_begin         = ksend_pdu_begin,
	.send_pdu_end           = ksend_pdu_end,
	.read			= kread,
	.recv_pdu_begin         = krecv_pdu_begin,
	.recv_pdu_end           = krecv_pdu_end,
};
struct iscsi_ipc *ipc = &nl_ipc;
