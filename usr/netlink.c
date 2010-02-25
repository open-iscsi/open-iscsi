/*
 * iSCSI Netlink/Linux Interface
 *
 * Copyright (C) 2004 Dmitry Yusupov, Alex Aizman
 * Copyright (C) 2006 Mike Christie
 * Copyright (C) 2006 Red Hat, Inc. All rights reserved.
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
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <inttypes.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/netlink.h>

#include "types.h"
#include "iscsi_if.h"
#include "iscsid.h"
#include "log.h"
#include "iscsi_ipc.h"
#include "initiator.h"
#include "iscsi_sysfs.h"
#include "transport.h"

static int ctrl_fd;
static struct sockaddr_nl src_addr, dest_addr;
static void *xmitbuf = NULL;
static int xmitlen = 0;
static void *recvbuf = NULL;
static int recvlen = 0;
static void *nlm_sendbuf;
static void *nlm_recvbuf;
static void *pdu_sendbuf;
static void *setparam_buf;

static int ctldev_handle(void);

#define NLM_BUF_DEFAULT_MAX \
	(NLMSG_SPACE(ISCSI_DEF_MAX_RECV_SEG_LEN + \
			 sizeof(struct iscsi_hdr)))

#define PDU_SENDBUF_DEFAULT_MAX \
	(ISCSI_DEF_MAX_RECV_SEG_LEN + sizeof(struct iscsi_hdr))

#define NLM_SETPARAM_DEFAULT_MAX \
	(NI_MAXHOST + 1 + sizeof(struct iscsi_uevent))

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
	 *  - iscsi_control_conn_error (should succeed)
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
 *	- session_create()
 *	- conn_create()
 *	- conn_bind()
 *	_ set_param()
 *	- conn_start()
 *	- conn_stop()
 *
 * Its OK to block for cleanup for short period of time in operatations for:
 *
 *	- conn_destroy()
 *	- session_destroy()
 *
 * FIXME: interface needs to be extended to allow longer blocking on
 *        cleanup. (Dima)
 */
static int
__kipc_call(void *iov_base, int iov_len)
{
	int rc, iferr;
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
				/*
				 * iferror is u32, but the kernel returns
				 * negative errno values for errors.
				 */
				iferr = ev->iferror;

				if (iferr == -ENOSYS)
					/* not fatal so let caller handle log */
					log_debug(1, "Received iferror %d: %s.",
						  iferr, strerror(-iferr));
				else if (iferr < 0)
					log_error("Received iferror %d: %s.",
						   iferr, strerror(-iferr));
				else
					log_error("Received iferror %d.",
						   iferr);
				return ev->iferror;
			}
			/*
			 * receive and queue async. event which as of
			 * today could be:
			 *	- CONN_ERROR
			 *	- RECV_PDU
			 */
			ctldev_handle();
		} else if (ev->type == ISCSI_UEVENT_GET_STATS) {
			/* kget_stats() will read */
			return 0;
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
ksendtargets(uint64_t transport_handle, uint32_t host_no, struct sockaddr *addr)
{
	int rc, addrlen;
	struct iscsi_uevent *ev;

	log_debug(7, "in %s", __FUNCTION__);

	memset(setparam_buf, 0, NLM_SETPARAM_DEFAULT_MAX);
	ev = (struct iscsi_uevent *)setparam_buf;
	ev->type = ISCSI_UEVENT_TGT_DSCVR;
	ev->transport_handle = transport_handle;
	ev->u.tgt_dscvr.type = ISCSI_TGT_DSCVR_SEND_TARGETS;
	ev->u.tgt_dscvr.host_no = host_no;

	if (addr->sa_family == PF_INET)
		addrlen = sizeof(struct sockaddr_in);
	else if (addr->sa_family == PF_INET6)
		addrlen = sizeof(struct sockaddr_in6);
	else {
		log_error("%s unknown addr family %d\n",
			  __FUNCTION__, addr->sa_family);
		return -EINVAL;
	}
	memcpy(setparam_buf + sizeof(*ev), addr, addrlen);

	rc = __kipc_call(ev, sizeof(*ev) + addrlen);
	if (rc < 0) {
		log_error("sendtargets failed rc%d\n", rc);
		return rc;
	}
	return 0;
}

static int
kcreate_session(uint64_t transport_handle, uint64_t ep_handle,
		uint32_t initial_cmdsn, uint16_t cmds_max, uint16_t qdepth,
		uint32_t *out_sid, uint32_t *hostno)
{
	int rc;
	struct iscsi_uevent ev;

	log_debug(7, "in %s", __FUNCTION__);

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	if (ep_handle == 0) {
		ev.type = ISCSI_UEVENT_CREATE_SESSION;
		ev.transport_handle = transport_handle;
		ev.u.c_session.initial_cmdsn = initial_cmdsn;
		ev.u.c_session.cmds_max = cmds_max;
		ev.u.c_session.queue_depth = qdepth;
	} else {
		ev.type = ISCSI_UEVENT_CREATE_BOUND_SESSION;
		ev.transport_handle = transport_handle;
		ev.u.c_bound_session.initial_cmdsn = initial_cmdsn;
		ev.u.c_bound_session.cmds_max = cmds_max;
		ev.u.c_bound_session.queue_depth = qdepth;
		ev.u.c_bound_session.ep_handle = ep_handle;
	}

	if ((rc = __kipc_call(&ev, sizeof(ev))) < 0) {
		return rc;
	}

	*hostno = ev.r.c_session_ret.host_no;
	*out_sid = ev.r.c_session_ret.sid;

	return 0;
}

static int
kdestroy_session(uint64_t transport_handle, uint32_t sid)
{
	int rc;
	struct iscsi_uevent ev;

	log_debug(7, "in %s", __FUNCTION__);

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_DESTROY_SESSION;
	ev.transport_handle = transport_handle;
	ev.u.d_session.sid = sid;

	if ((rc = __kipc_call(&ev, sizeof(ev))) < 0) {
		return rc;
	}

	return 0;
}

static int
kunbind_session(uint64_t transport_handle, uint32_t sid)
{
	int rc;
	struct iscsi_uevent ev;

	log_debug(7, "in %s", __FUNCTION__);

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_UNBIND_SESSION;
	ev.transport_handle = transport_handle;
	ev.u.d_session.sid = sid;

	if ((rc = __kipc_call(&ev, sizeof(ev))) < 0) {
		return rc;
	}

	return 0;
}

static int
kcreate_conn(uint64_t transport_handle, uint32_t sid,
	    uint32_t cid, uint32_t *out_cid)
{
	int rc;
	struct iscsi_uevent ev;

	log_debug(7, "in %s", __FUNCTION__);

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_CREATE_CONN;
	ev.transport_handle = transport_handle;
	ev.u.c_conn.cid = cid;
	ev.u.c_conn.sid = sid;

	if ((rc = __kipc_call(&ev, sizeof(ev))) < 0) {
		log_debug(7, "returned %d", rc);
		return rc;
	}

	if ((int)ev.r.c_conn_ret.cid == -1)
		return -EIO;

	*out_cid = ev.r.c_conn_ret.cid;
	return 0;
}

static int
kdestroy_conn(uint64_t transport_handle, uint32_t sid, uint32_t cid)
{
	int rc;
	struct iscsi_uevent ev;

	log_debug(7, "in %s", __FUNCTION__);

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_DESTROY_CONN;
	ev.transport_handle = transport_handle;
	ev.u.d_conn.sid = sid;
	ev.u.d_conn.cid = cid;

	if ((rc = __kipc_call(&ev, sizeof(ev))) < 0) {
		return rc;
	}

	return 0;
}

static int
kbind_conn(uint64_t transport_handle, uint32_t sid, uint32_t cid,
	  uint64_t transport_eph, int is_leading, int *retcode)
{
	int rc;
	struct iscsi_uevent ev;

	log_debug(7, "in %s", __FUNCTION__);

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_BIND_CONN;
	ev.transport_handle = transport_handle;
	ev.u.b_conn.sid = sid;
	ev.u.b_conn.cid = cid;
	ev.u.b_conn.transport_eph = transport_eph;
	ev.u.b_conn.is_leading = is_leading;

	if ((rc = __kipc_call(&ev, sizeof(ev))) < 0) {
		return rc;
	}

	*retcode = ev.r.retcode;

	return 0;
}

static void
ksend_pdu_begin(uint64_t transport_handle, uint32_t sid, uint32_t cid,
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
	ev->u.send_pdu.sid = sid;
	ev->u.send_pdu.cid = cid;
	ev->u.send_pdu.hdr_size = hdr_size;
	ev->u.send_pdu.data_size = data_size;

	log_debug(3, "send PDU began for hdr %d bytes and data %d bytes",
		hdr_size, data_size);
}

static int
ksend_pdu_end(uint64_t transport_handle, uint32_t sid, uint32_t cid,
	      int *retcode)
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
	if (ev->u.send_pdu.sid != sid || ev->u.send_pdu.cid != cid) {
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

	log_debug(3, "send PDU finished for conn %d:%d",
		  sid, cid);

	xmitbuf = NULL;
	return 0;

err:
	xmitbuf = NULL;
	xmitlen = 0;
	return rc;
}

static int
kset_host_param(uint64_t transport_handle, uint32_t host_no,
		enum iscsi_host_param param, void *value, int type)
{
	struct iscsi_uevent *ev;
	char *param_str;
	int rc, len;

	log_debug(7, "in %s", __FUNCTION__);

	memset(setparam_buf, 0, NLM_SETPARAM_DEFAULT_MAX);
	ev = (struct iscsi_uevent *)setparam_buf;
	ev->type = ISCSI_UEVENT_SET_HOST_PARAM;
	ev->transport_handle = transport_handle;
	ev->u.set_host_param.host_no = host_no;
	ev->u.set_host_param.param = param;

	param_str = setparam_buf + sizeof(*ev);
	switch (type) {
	case ISCSI_INT:
		sprintf(param_str, "%d", *((int *)value));
		break;
	case ISCSI_STRING:
		if (!strlen(value))
			return 0;
		sprintf(param_str, "%s", (char *)value);
		break;
	default:
		log_error("invalid type %d\n", type);
		return -EINVAL;
	}
	ev->u.set_host_param.len = len = strlen(param_str) + 1;

	if ((rc = __kipc_call(ev, sizeof(*ev) + len)) < 0) {
		return rc;
	}

	return 0;
}

static int
kset_param(uint64_t transport_handle, uint32_t sid, uint32_t cid,
	   enum iscsi_param param, void *value, int type)
{
	struct iscsi_uevent *ev;
	char *param_str;
	int rc, len;

	log_debug(7, "in %s", __FUNCTION__);

	memset(setparam_buf, 0, NLM_SETPARAM_DEFAULT_MAX);
	ev = (struct iscsi_uevent *)setparam_buf;
	ev->type = ISCSI_UEVENT_SET_PARAM;
	ev->transport_handle = transport_handle;
	ev->u.set_param.sid = sid;
	ev->u.set_param.cid = cid;
	ev->u.set_param.param = param;

	param_str = setparam_buf + sizeof(*ev);
	switch (type) {
	case ISCSI_INT:
		sprintf(param_str, "%d", *((int *)value));
		break;
	case ISCSI_STRING:
		if (!strlen(value))
			return 0;
		sprintf(param_str, "%s", (char *)value);
		break;
	default:
		log_error("invalid type %d\n", type);
		return -EINVAL;
	}
	ev->u.set_param.len = len = strlen(param_str) + 1;

	if ((rc = __kipc_call(ev, sizeof(*ev) + len)) < 0) {
		return rc;
	}

	return 0;
}

static int
kstop_conn(uint64_t transport_handle, uint32_t sid, uint32_t cid, int flag)
{
	int rc;
	struct iscsi_uevent ev;

	log_debug(7, "in %s", __FUNCTION__);

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_STOP_CONN;
	ev.transport_handle = transport_handle;
	ev.u.stop_conn.sid = sid;
	ev.u.stop_conn.cid = cid;
	ev.u.stop_conn.flag = flag;

	if ((rc = __kipc_call(&ev, sizeof(ev))) < 0) {
		return rc;
	}

	return 0;
}

static int
kstart_conn(uint64_t transport_handle, uint32_t sid, uint32_t cid,
	    int *retcode)
{
	int rc;
	struct iscsi_uevent ev;

	log_debug(7, "in %s", __FUNCTION__);

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_START_CONN;
	ev.transport_handle = transport_handle;
	ev.u.start_conn.sid = sid;
	ev.u.start_conn.cid = cid;

	if ((rc = __kipc_call(&ev, sizeof(ev))) < 0) {
		return rc;
	}

	*retcode = ev.r.retcode;
	return 0;
}

static int
krecv_pdu_begin(struct iscsi_conn *conn)
{
	log_debug(7, "in %s", __FUNCTION__);

	if (recvbuf) {
		log_error("recv's begin state machine bug?");
		return -EIO;
	}
	recvbuf = conn->recv_context->data + sizeof(struct iscsi_uevent);
	recvlen = 0;

	log_debug(3, "recv PDU began, pdu handle 0x%p",
		  recvbuf);

	return 0;
}

static int
krecv_pdu_end(struct iscsi_conn *conn)
{
	log_debug(7, "in %s", __FUNCTION__);

	if (!recvbuf) {
		log_error("recv's end state machine bug?");
		return -EIO;
	}

	log_debug(3, "recv PDU finished for pdu handle 0x%p",
		  recvbuf);

	iscsi_conn_context_put(conn->recv_context);
	conn->recv_context = NULL;
	recvbuf = NULL;
	return 0;
}

int
ktransport_ep_connect(iscsi_conn_t *conn, int non_blocking)
{
	int rc, addrlen;
	struct iscsi_uevent *ev;
	struct sockaddr *dst_addr = (struct sockaddr *)&conn->saddr;

	log_debug(7, "in %s", __FUNCTION__);

	memset(setparam_buf, 0, NLM_SETPARAM_DEFAULT_MAX);
	ev = (struct iscsi_uevent *)setparam_buf;
	ev->transport_handle = conn->session->t->handle;

	if (conn->bind_ep) {
		ev->type = ISCSI_UEVENT_TRANSPORT_EP_CONNECT_THROUGH_HOST;
		ev->u.ep_connect_through_host.non_blocking = non_blocking;
		ev->u.ep_connect_through_host.host_no = conn->session->hostno;
	} else {
		ev->type = ISCSI_UEVENT_TRANSPORT_EP_CONNECT;
		ev->u.ep_connect.non_blocking = non_blocking;
	}

	if (dst_addr->sa_family == PF_INET)
		addrlen = sizeof(struct sockaddr_in);
	else if (dst_addr->sa_family == PF_INET6)
		addrlen = sizeof(struct sockaddr_in6);
	else {
		log_error("%s unknown addr family %d\n",
			 __FUNCTION__, dst_addr->sa_family);
		return -EINVAL;
	}
	memcpy(setparam_buf + sizeof(*ev), dst_addr, addrlen);

	if ((rc = __kipc_call(ev, sizeof(*ev) + addrlen)) < 0)
		return rc;

	if (!ev->r.ep_connect_ret.handle)
		return -EIO;

	conn->transport_ep_handle = ev->r.ep_connect_ret.handle;

	log_debug(6, "%s got handle %llx",
		__FUNCTION__, (unsigned long long)conn->transport_ep_handle);
	return 0;
}

int
ktransport_ep_poll(iscsi_conn_t *conn, int timeout_ms)
{
	int rc;
	struct iscsi_uevent ev;

	log_debug(7, "in %s", __FUNCTION__);

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_TRANSPORT_EP_POLL;
	ev.transport_handle = conn->session->t->handle;
	ev.u.ep_poll.ep_handle  = conn->transport_ep_handle;
	ev.u.ep_poll.timeout_ms = timeout_ms;

	if ((rc = __kipc_call(&ev, sizeof(ev))) < 0)
		return rc;

	return ev.r.retcode;
}

void
ktransport_ep_disconnect(iscsi_conn_t *conn)
{
	int rc;
	struct iscsi_uevent ev;

	log_debug(7, "in %s", __FUNCTION__);

	if (conn->transport_ep_handle == -1)
		return;

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_TRANSPORT_EP_DISCONNECT;
	ev.transport_handle = conn->session->t->handle;
	ev.u.ep_disconnect.ep_handle = conn->transport_ep_handle;

	if ((rc = __kipc_call(&ev, sizeof(ev))) < 0) {
		log_error("connnection %d:%d transport disconnect failed for "
			  "ep %" PRIu64 " with error %d.", conn->session->id,
			  conn->id, conn->transport_ep_handle, rc);
	} else
		conn->transport_ep_handle = -1;
}

static int
kget_stats(uint64_t transport_handle, uint32_t sid, uint32_t cid,
	   char *statsbuf, int statsbuf_max)
{
	int rc;
	int ev_size;
	struct iscsi_uevent ev;
	char nlm_ev[NLMSG_SPACE(sizeof(struct iscsi_uevent))];
	struct nlmsghdr *nlh;

	log_debug(7, "in %s", __FUNCTION__);

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_GET_STATS;
	ev.transport_handle = transport_handle;
	ev.u.get_stats.sid = sid;
	ev.u.get_stats.cid = cid;

	if ((rc = __kipc_call(&ev, sizeof(ev))) < 0) {
		return rc;
	}

	if ((rc = nl_read(ctrl_fd, nlm_ev,
		NLMSG_SPACE(sizeof(struct iscsi_uevent)), MSG_PEEK)) < 0) {
		log_error("can not read nlm_ev, error %d", rc);
		return rc;
	}
	nlh = (struct nlmsghdr *)nlm_ev;
	ev_size = nlh->nlmsg_len - NLMSG_ALIGN(sizeof(struct nlmsghdr));

	log_debug(6, "message real length is %d bytes", nlh->nlmsg_len);

	if (ev_size > statsbuf_max) {
		log_error("destanation buffer for statistics is "
			"not big enough to fit %d bytes", statsbuf_max);
		ev_size = statsbuf_max;
	}

	if ((rc = nlpayload_read(ctrl_fd, (void*)statsbuf, ev_size, 0)) < 0) {
		log_error("can not read from NL socket, error %d", rc);
		return rc;
	}

	return 0;
}

static void drop_data(struct nlmsghdr *nlh)
{
	int ev_size;

	ev_size = nlh->nlmsg_len - NLMSG_ALIGN(sizeof(struct nlmsghdr));
	nlpayload_read(ctrl_fd, setparam_buf, ev_size, 0);
}

static int ctldev_handle(void)
{
	int rc, ev_size;
	struct iscsi_uevent *ev;
	iscsi_session_t *session = NULL;
	iscsi_conn_t *conn = NULL;
	char nlm_ev[NLMSG_SPACE(sizeof(struct iscsi_uevent))];
	struct nlmsghdr *nlh;
	struct iscsi_conn_context *conn_context;
	uint32_t sid = 0, cid = 0;

	log_debug(7, "in %s", __FUNCTION__);

	if ((rc = nl_read(ctrl_fd, nlm_ev,
		NLMSG_SPACE(sizeof(struct iscsi_uevent)), MSG_PEEK)) < 0) {
		log_error("can not read nlm_ev, error %d", rc);
		return rc;
	}
	nlh = (struct nlmsghdr *)nlm_ev;
	ev = (struct iscsi_uevent *)NLMSG_DATA(nlm_ev);

	log_debug(7, "%s got event type %u\n", __FUNCTION__, ev->type);
	/* drivers like qla4xxx can be inserted after iscsid is started */
	switch (ev->type) {
	case ISCSI_KEVENT_CREATE_SESSION:
	/* old kernels sent ISCSI_UEVENT_CREATE_SESSION on creation */
	case ISCSI_UEVENT_CREATE_SESSION:
		drop_data(nlh);
		iscsi_async_session_creation(ev->r.c_session_ret.host_no,
					     ev->r.c_session_ret.sid);
		return 0;
	case ISCSI_KEVENT_DESTROY_SESSION:
		drop_data(nlh);
		iscsi_async_session_destruction(ev->r.d_session.host_no,
						ev->r.d_session.sid);
		return 0;
	case ISCSI_KEVENT_RECV_PDU:
		sid = ev->r.recv_req.sid;
		cid = ev->r.recv_req.cid;
		break;
	case ISCSI_KEVENT_CONN_ERROR:
		sid = ev->r.connerror.sid;
		cid = ev->r.connerror.cid;
		break;
	case ISCSI_KEVENT_UNBIND_SESSION:
		sid = ev->r.unbind_session.sid;
		/* session wide event so cid is 0 */
		cid = 0;
		break;
	default:
		log_error("Unknown kernel event %d. You may want to upgrade "
			  "your iscsi tools.", ev->type);
		drop_data(nlh);
		return -EINVAL;
	}

	/* verify connection */
	session = session_find_by_sid(sid);
	if (!session) {
		log_error("Could not verify connection %d:%d. Dropping "
			   "event.\n", sid, cid);
		drop_data(nlh);
		return -ENXIO;
	}
	conn = &session->conn[0];

	ev_size = nlh->nlmsg_len - NLMSG_ALIGN(sizeof(struct nlmsghdr));
	conn_context = iscsi_conn_context_get(conn, ev_size);
	if (!conn_context) {
		/* retry later */
		log_error("Can not allocate memory for receive context.");
		return -ENOMEM;
	}

	log_debug(6, "message real length is %d bytes, recv_handle %p",
		nlh->nlmsg_len, conn_context->data);

	if ((rc = nlpayload_read(ctrl_fd, conn_context->data,
				ev_size, 0)) < 0) {
		iscsi_conn_context_put(conn_context);
		log_error("can not read from NL socket, error %d", rc);
		/* retry later */
		return rc;
	}

	/*
	 * we sched these events because the handlers could call back
	 * into ctldev_handle
	 */
	switch (ev->type) {
	case ISCSI_KEVENT_RECV_PDU:
		iscsi_sched_conn_context(conn_context, conn, 0,
					 EV_CONN_RECV_PDU);
		break;
	case ISCSI_KEVENT_CONN_ERROR:
		memcpy(conn_context->data, &ev->r.connerror.error,
			sizeof(ev->r.connerror.error));
		iscsi_sched_conn_context(conn_context, conn, 0,
					 EV_CONN_ERROR);
		break;
	case ISCSI_KEVENT_UNBIND_SESSION:
		iscsi_sched_conn_context(conn_context, conn, 0,
					 EV_CONN_STOP);
		break;
	default:
		iscsi_conn_context_put(conn_context);
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
		log_error("can not allocate nlm_recvbuf");
		goto free_nlm_sendbuf;
	}

	pdu_sendbuf = calloc(1, PDU_SENDBUF_DEFAULT_MAX);
	if (!pdu_sendbuf) {
		log_error("can not allocate nlm_sendbuf");
		goto free_nlm_recvbuf;
	}

	setparam_buf = calloc(1, NLM_SETPARAM_DEFAULT_MAX);
	if (!setparam_buf) {
		log_error("can not allocate setparam_buf");
		goto free_pdu_sendbuf;
	}

	ctrl_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ISCSI);
	if (ctrl_fd < 0) {
		log_error("can not create NETLINK_ISCSI socket");
		goto free_setparam_buf;
	}

	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();
	src_addr.nl_groups = 1;
	if (bind(ctrl_fd, (struct sockaddr *)&src_addr, sizeof(src_addr))) {
		log_error("can not bind NETLINK_ISCSI socket");
		goto close_socket;
	}

	memset(&dest_addr, 0, sizeof(dest_addr));
	dest_addr.nl_family = AF_NETLINK;
	dest_addr.nl_pid = 0; /* kernel */
	dest_addr.nl_groups = 0; /* unicast */

	log_debug(7, "created NETLINK_ISCSI socket...");

	return ctrl_fd;

close_socket:
	close(ctrl_fd);
free_setparam_buf:
	free(setparam_buf);
free_pdu_sendbuf:
	free(pdu_sendbuf);
free_nlm_recvbuf:
	free(nlm_recvbuf);
free_nlm_sendbuf:
	free(nlm_sendbuf);
	return -1;
}

static void
ctldev_close(void)
{
	log_debug(7, "in %s", __FUNCTION__);

	if (ctrl_fd >= 0)
		close(ctrl_fd);
	free(setparam_buf);
	free(pdu_sendbuf);
	free(nlm_recvbuf);
	free(nlm_sendbuf);
}

struct iscsi_ipc nl_ipc = {
	.name                   = "Open-iSCSI Kernel IPC/NETLINK v.1",
	.ctldev_bufmax		= NLM_BUF_DEFAULT_MAX,
	.ctldev_open		= ctldev_open,
	.ctldev_close		= ctldev_close,
	.ctldev_handle		= ctldev_handle,
	.sendtargets		= ksendtargets,
	.create_session         = kcreate_session,
	.destroy_session        = kdestroy_session,
	.unbind_session		= kunbind_session,
	.create_conn            = kcreate_conn,
	.destroy_conn           = kdestroy_conn,
	.bind_conn              = kbind_conn,
	.set_param              = kset_param,
	.set_host_param		= kset_host_param,
	.get_param              = NULL,
	.start_conn             = kstart_conn,
	.stop_conn              = kstop_conn,
	.get_stats		= kget_stats,
	.writev			= kwritev,
	.send_pdu_begin         = ksend_pdu_begin,
	.send_pdu_end           = ksend_pdu_end,
	.read			= kread,
	.recv_pdu_begin         = krecv_pdu_begin,
	.recv_pdu_end           = krecv_pdu_end,
};
struct iscsi_ipc *ipc = &nl_ipc;
