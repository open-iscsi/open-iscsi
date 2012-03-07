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
#include <time.h>
#include <inttypes.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/poll.h>
#include <linux/netlink.h>

#include "types.h"
#include "iscsi_if.h"
#include "log.h"
#include "iscsi_ipc.h"
#include "initiator.h"
#include "iscsi_sysfs.h"
#include "transport.h"
#include "iscsi_netlink.h"
#include "iscsi_err.h"
#include "iscsi_timer.h"

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
static struct iscsi_ipc_ev_clbk *ipc_ev_clbk;

static int ctldev_handle(void);

#define NLM_BUF_DEFAULT_MAX (NLMSG_SPACE(ISCSI_DEF_MAX_RECV_SEG_LEN +	\
					sizeof(struct iscsi_uevent) +	\
					sizeof(struct iscsi_hdr)))

#define PDU_SENDBUF_DEFAULT_MAX	(ISCSI_DEF_MAX_RECV_SEG_LEN +		\
					sizeof(struct iscsi_uevent) +	\
					sizeof(struct iscsi_hdr))

#define NLM_SETPARAM_DEFAULT_MAX (NI_MAXHOST + 1 + sizeof(struct iscsi_uevent))

struct iscsi_ping_event {
	uint32_t host_no;
	uint32_t pid;
	int32_t status;
	int active;
};

struct iscsi_ping_event ping_event;

struct nlattr *iscsi_nla_alloc(uint16_t type, uint16_t len)
{
	struct nlattr *attr;

	attr = calloc(1, ISCSI_NLA_TOTAL_LEN(len));
	if (!attr)
		return NULL; 

	attr->nla_len = ISCSI_NLA_LEN(len);
	attr->nla_type = type;
	return attr;
}

static int
kread(char *data, int count)
{
	log_debug(7, "in %s %u %u %p %p", __FUNCTION__, recvlen, count,
		  data, recvbuf);

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

	if (iov.iov_len > NLM_BUF_DEFAULT_MAX) {
		log_error("Cannot read %lu bytes. nlm_recvbuf too small.",
			  iov.iov_len);
		return -1;
	}
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

	if (data)
		memcpy(data, NLMSG_DATA(iov.iov_base), count);

	return rc;
}

static int
kwritev(enum iscsi_uevent_e type, struct iovec *iovp, int count)
{
	int i, rc;
	struct nlmsghdr *nlh;
	struct msghdr msg;
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
	memset(nlh, 0, NLMSG_SPACE(0));

	datalen = 0;
	for (i = 1; i < count; i++)
		datalen += iovp[i].iov_len;

	nlh->nlmsg_len = datalen + sizeof(*nlh);
	nlh->nlmsg_pid = getpid();
	nlh->nlmsg_flags = 0;
	nlh->nlmsg_type = type;

	iovp[0].iov_base = (void *)nlh;
	iovp[0].iov_len = sizeof(*nlh);

	memset(&msg, 0, sizeof(msg));
	msg.msg_name= (void*)&dest_addr;
	msg.msg_namelen = sizeof(dest_addr);
	msg.msg_iov = iovp;
	msg.msg_iovlen = count;

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
__kipc_call(struct iovec *iovp, int count)
{
	int rc, iferr;
	struct iscsi_uevent *ev = iovp[1].iov_base;
	enum iscsi_uevent_e type = ev->type;

	log_debug(7, "in %s", __FUNCTION__);

	rc = kwritev(type, iovp, count);

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
		} else if (ev->type == ISCSI_UEVENT_GET_CHAP) {
			/* kget_chap() will read */
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
	struct iovec iov[2];

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

	iov[1].iov_base = ev;
	iov[1].iov_len = sizeof(*ev) + addrlen;
	rc = __kipc_call(iov, 2);
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
	struct iovec iov[2];

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

	iov[1].iov_base = &ev;
	iov[1].iov_len = sizeof(ev);
	rc = __kipc_call(iov, 2);
	if (rc < 0)
		return rc;

	*hostno = ev.r.c_session_ret.host_no;
	*out_sid = ev.r.c_session_ret.sid;

	return 0;
}

static int
kdestroy_session(uint64_t transport_handle, uint32_t sid)
{
	int rc;
	struct iscsi_uevent ev;
	struct iovec iov[2];

	log_debug(7, "in %s", __FUNCTION__);

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_DESTROY_SESSION;
	ev.transport_handle = transport_handle;
	ev.u.d_session.sid = sid;

	iov[1].iov_base = &ev;
	iov[1].iov_len = sizeof(ev);
	rc = __kipc_call(iov, 2);
	if (rc < 0)
		return rc;

	return 0;
}

static int
kunbind_session(uint64_t transport_handle, uint32_t sid)
{
	int rc;
	struct iscsi_uevent ev;
	struct iovec iov[2];

	log_debug(7, "in %s", __FUNCTION__);

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_UNBIND_SESSION;
	ev.transport_handle = transport_handle;
	ev.u.d_session.sid = sid;

	iov[1].iov_base = &ev;
	iov[1].iov_len = sizeof(ev);
	rc = __kipc_call(iov, 2);
	if (rc < 0)
		return rc;

	return 0;
}

static int
kcreate_conn(uint64_t transport_handle, uint32_t sid,
	    uint32_t cid, uint32_t *out_cid)
{
	int rc;
	struct iscsi_uevent ev;
	struct iovec iov[2];

	log_debug(7, "in %s", __FUNCTION__);

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_CREATE_CONN;
	ev.transport_handle = transport_handle;
	ev.u.c_conn.cid = cid;
	ev.u.c_conn.sid = sid;

	iov[1].iov_base = &ev;
	iov[1].iov_len = sizeof(ev);
	rc = __kipc_call(iov, 2);
	if (rc < 0) {
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
	struct iovec iov[2];

	log_debug(7, "in %s", __FUNCTION__);

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_DESTROY_CONN;
	ev.transport_handle = transport_handle;
	ev.u.d_conn.sid = sid;
	ev.u.d_conn.cid = cid;

	iov[1].iov_base = &ev;
	iov[1].iov_len = sizeof(ev);
	rc = __kipc_call(iov, 2);
	if (rc < 0)
		return rc;

	return 0;
}

static int
kbind_conn(uint64_t transport_handle, uint32_t sid, uint32_t cid,
	  uint64_t transport_eph, int is_leading, int *retcode)
{
	int rc;
	struct iscsi_uevent ev;
	struct iovec iov[2];

	log_debug(7, "in %s", __FUNCTION__);

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_BIND_CONN;
	ev.transport_handle = transport_handle;
	ev.u.b_conn.sid = sid;
	ev.u.b_conn.cid = cid;
	ev.u.b_conn.transport_eph = transport_eph;
	ev.u.b_conn.is_leading = is_leading;

	iov[1].iov_base = &ev;
	iov[1].iov_len = sizeof(ev);
	rc = __kipc_call(iov, 2);
	if (rc < 0)
		return rc;

	*retcode = ev.r.retcode;

	return 0;
}

static void
ksend_pdu_begin(uint64_t transport_handle, uint32_t sid, uint32_t cid,
			int hdr_size, int data_size)
{
	struct iscsi_uevent *ev;
	int total_xmitlen = sizeof(*ev) + hdr_size + data_size;

	log_debug(7, "in %s", __FUNCTION__);

	if (xmitbuf) {
		log_error("send's begin state machine bug?");
		exit(-EIO);
	}

	if (total_xmitlen > PDU_SENDBUF_DEFAULT_MAX) {
		log_error("BUG: Cannot send %d bytes.", total_xmitlen);
		exit(-EINVAL);
	}

	xmitbuf = pdu_sendbuf;
	memset(xmitbuf, 0, total_xmitlen);
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
	struct iovec iov[2];

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

	iov[1].iov_base = xmitbuf;
	iov[1].iov_len = xmitlen;

	rc = __kipc_call(iov, 2);
	if (rc < 0)
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
	struct iovec iov[2];

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

	iov[1].iov_base = ev;
	iov[1].iov_len = sizeof(*ev) + len;
	rc = __kipc_call(iov, 2);
	if (rc < 0)
		return rc;

	return 0;
}

static int
kset_param(uint64_t transport_handle, uint32_t sid, uint32_t cid,
	   enum iscsi_param param, void *value, int type)
{
	struct iscsi_uevent *ev;
	char *param_str;
	int rc, len;
	struct iovec iov[2];

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

	iov[1].iov_base = ev;
	iov[1].iov_len = sizeof(*ev) + len;
	rc = __kipc_call(iov, 2);
	if (rc < 0)
		return rc;

	return 0;
}

static int
kstop_conn(uint64_t transport_handle, uint32_t sid, uint32_t cid, int flag)
{
	int rc;
	struct iscsi_uevent ev;
	struct iovec iov[2];

	log_debug(7, "in %s", __FUNCTION__);

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_STOP_CONN;
	ev.transport_handle = transport_handle;
	ev.u.stop_conn.sid = sid;
	ev.u.stop_conn.cid = cid;
	ev.u.stop_conn.flag = flag;

	iov[1].iov_base = &ev;
	iov[1].iov_len = sizeof(ev);
	rc = __kipc_call(iov, 2);
	if (rc < 0)
		return rc;

	return 0;
}

static int
kstart_conn(uint64_t transport_handle, uint32_t sid, uint32_t cid,
	    int *retcode)
{
	int rc;
	struct iscsi_uevent ev;
	struct iovec iov[2];

	log_debug(7, "in %s", __FUNCTION__);

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_START_CONN;
	ev.transport_handle = transport_handle;
	ev.u.start_conn.sid = sid;
	ev.u.start_conn.cid = cid;

	iov[1].iov_base = &ev;
	iov[1].iov_len = sizeof(ev);
	rc = __kipc_call(iov, 2);
	if (rc < 0)
		return rc;

	*retcode = ev.r.retcode;
	return 0;
}

static int
krecv_pdu_begin(struct iscsi_conn *conn)
{
	int rc;

	log_debug(7, "in %s", __FUNCTION__);

	if (recvbuf) {
		log_error("recv's begin state machine bug?");
		return -EIO;
	}

	if (!conn->recv_context) {
		rc = ipc->ctldev_handle();
		if (rc == -ENXIO)
			/* event for some other conn */
			return -EAGAIN;
		else if (rc < 0)
			/* fatal handling error or conn error */
			return rc;
		/*
		 * Session create/destroy event for another conn
		 */
		if (!conn->recv_context)
			return -EAGAIN;
	}

	recvbuf = conn->recv_context->data + sizeof(struct iscsi_uevent);
	recvlen = 0;

	log_debug(3, "recv PDU began, pdu handle %p", recvbuf);
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

	ipc_ev_clbk->put_ev_context(conn->recv_context);
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
	struct iovec iov[2];

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

	iov[1].iov_base = ev;
	iov[1].iov_len = sizeof(*ev) + addrlen;
	rc = __kipc_call(iov, 2);
	if (rc < 0)
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
	struct iovec iov[2];

	log_debug(7, "in %s", __FUNCTION__);

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_TRANSPORT_EP_POLL;
	ev.transport_handle = conn->session->t->handle;
	ev.u.ep_poll.ep_handle  = conn->transport_ep_handle;
	ev.u.ep_poll.timeout_ms = timeout_ms;

	iov[1].iov_base = &ev;
	iov[1].iov_len = sizeof(ev);
	rc = __kipc_call(iov, 2);
	if (rc < 0)
		return rc;

	return ev.r.retcode;
}

void
ktransport_ep_disconnect(iscsi_conn_t *conn)
{
	int rc;
	struct iscsi_uevent ev;
	struct iovec iov[2];

	log_debug(7, "in %s", __FUNCTION__);

	if (conn->transport_ep_handle == -1)
		return;

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_TRANSPORT_EP_DISCONNECT;
	ev.transport_handle = conn->session->t->handle;
	ev.u.ep_disconnect.ep_handle = conn->transport_ep_handle;

	iov[1].iov_base = &ev;
	iov[1].iov_len = sizeof(ev);
	rc = __kipc_call(iov, 2);
	if (rc < 0) {
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
	struct iovec iov[2];

	log_debug(7, "in %s", __FUNCTION__);

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_GET_STATS;
	ev.transport_handle = transport_handle;
	ev.u.get_stats.sid = sid;
	ev.u.get_stats.cid = cid;

	iov[1].iov_base = &ev;
	iov[1].iov_len = sizeof(ev);
	rc = __kipc_call(iov, 2);
	if (rc < 0)
		return rc;

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

static int
kset_net_config(uint64_t transport_handle, uint32_t host_no,
		struct iovec *iovs, uint32_t param_count)
{
	struct iscsi_uevent ev;
	int rc, ev_len;
	struct iovec *iov = iovs + 1;

	log_debug(8, "in %s", __FUNCTION__);

	ev_len = sizeof(ev);
	ev.type = ISCSI_UEVENT_SET_IFACE_PARAMS;
	ev.transport_handle = transport_handle;
	ev.u.set_iface_params.host_no = host_no;
	/* first two iovs for nlmsg hdr and ev */
	ev.u.set_iface_params.count = param_count - 2;

	iov->iov_base = &ev;
	iov->iov_len = ev_len;
	rc = __kipc_call(iovs, param_count);
	if (rc < 0)
		return rc;

	return 0;
}

static int krecv_conn_state(struct iscsi_conn *conn, uint32_t *state)
{
	int rc;

	rc = ipc->ctldev_handle();
	if (rc == -ENXIO) {
		/* event for some other conn */
		rc = -EAGAIN;
		goto exit;
	} else if (rc < 0)
		/* fatal handling error or conn error */
		goto exit;

	*state = *(enum iscsi_conn_state *)conn->recv_context->data;

	ipc_ev_clbk->put_ev_context(conn->recv_context);
	conn->recv_context = NULL;

exit:
	return rc;
}




static int
ksend_ping(uint64_t transport_handle, uint32_t host_no, struct sockaddr *addr,
	   uint32_t iface_num, uint32_t iface_type, uint32_t pid, uint32_t size)
{
	int rc, addrlen;
	struct iscsi_uevent *ev;
	struct iovec iov[2];

	log_debug(8, "in %s", __FUNCTION__);

	memset(setparam_buf, 0, NLM_SETPARAM_DEFAULT_MAX);
	ev = (struct iscsi_uevent *)setparam_buf;
	ev->type = ISCSI_UEVENT_PING;
	ev->transport_handle = transport_handle;
	ev->u.iscsi_ping.host_no = host_no;
	ev->u.iscsi_ping.iface_num = iface_num;
	ev->u.iscsi_ping.iface_type = iface_type;
	ev->u.iscsi_ping.payload_size = size;
	ev->u.iscsi_ping.pid = pid;

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

	iov[1].iov_base = ev;
	iov[1].iov_len = sizeof(*ev) + addrlen;
	rc = __kipc_call(iov, 2);
	if (rc < 0)
		return rc;

	return 0;
}

static int kexec_ping(uint64_t transport_handle, uint32_t host_no,
		      struct sockaddr *addr, uint32_t iface_num,
		      uint32_t iface_type, uint32_t size, uint32_t *status)
{
	struct pollfd pfd;
	struct timeval ping_timer;
	int timeout, fd, rc;
	uint32_t pid;

	*status = 0;

	fd = ipc->ctldev_open();
	if (fd < 0) {
		log_error("Could not open netlink socket.");
		return ISCSI_ERR;
	}

	/* prepare to poll */
	memset(&pfd, 0, sizeof(pfd));
	pfd.fd = fd;
	pfd.events = POLLIN | POLLPRI;

	/* get unique ping id */
	pid = rand();

	rc = ksend_ping(transport_handle, host_no, addr, iface_num,
			iface_type, pid, size);
	if (rc != 0) {
		switch (rc) {
		case -ENOSYS:
			rc = ISCSI_ERR_OP_NOT_SUPP;
			break;
		case -EINVAL:
			rc = ISCSI_ERR_INVAL;
			break;
		default:
			rc = ISCSI_ERR;
		}
		goto close_nl;
	}

	ping_event.host_no = -1;
	ping_event.pid = -1;
	ping_event.status = -1;
	ping_event.active = -1;

	iscsi_timer_set(&ping_timer, 30);

	timeout = iscsi_timer_msecs_until(&ping_timer);

	while (1) {
		pfd.revents = 0;
		rc = poll(&pfd, 1, timeout);

		if (iscsi_timer_expired(&ping_timer)) {
			rc = ISCSI_ERR_TRANS_TIMEOUT;
			break;
		}

		if (rc > 0) {
			if (pfd.revents & (POLLIN | POLLPRI)) {
				timeout = iscsi_timer_msecs_until(&ping_timer);
				rc = ipc->ctldev_handle();

				if (ping_event.active != 1)
					continue;

				if (pid != ping_event.pid)
					continue;

				rc = 0;
				*status = ping_event.status;
				break;
			}

			if (pfd.revents & POLLHUP) {
				rc = ISCSI_ERR_TRANS;
				break;
			}

			if (pfd.revents & POLLNVAL) {
				rc = ISCSI_ERR_INTERNAL;
				break;
			}

			if (pfd.revents & POLLERR) {
				rc = ISCSI_ERR_INTERNAL;
				break;
			}
		} else if (rc < 0) {
			rc = ISCSI_ERR_INTERNAL;
			break;
		}
	}

close_nl:
	ipc->ctldev_close();
	return rc;
}

static int kget_chap(uint64_t transport_handle, uint32_t host_no,
		     uint16_t chap_tbl_idx, uint32_t num_entries,
		     char *chap_buf, uint32_t *valid_chap_entries)
{
	int rc = 0;
	int ev_size;
	struct iscsi_uevent ev;
	struct iovec iov[2];
	char nlm_ev[NLMSG_SPACE(sizeof(struct iscsi_uevent))];
	struct nlmsghdr *nlh;

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_GET_CHAP;
	ev.transport_handle = transport_handle;
	ev.u.get_chap.host_no = host_no;
	ev.u.get_chap.chap_tbl_idx = chap_tbl_idx;
	ev.u.get_chap.num_entries = num_entries;

	iov[1].iov_base = &ev;
	iov[1].iov_len = sizeof(ev);
	rc = __kipc_call(iov, 2);
	if (rc < 0)
		return rc;

	if ((rc = nl_read(ctrl_fd, nlm_ev,
			  NLMSG_SPACE(sizeof(struct iscsi_uevent)),
			  MSG_PEEK)) < 0) {
		log_error("can not read nlm_ev, error %d", rc);
		return rc;
	}

	nlh = (struct nlmsghdr *)nlm_ev;
	ev_size = nlh->nlmsg_len - NLMSG_ALIGN(sizeof(struct nlmsghdr));

	if ((rc = nlpayload_read(ctrl_fd, (void *)chap_buf, ev_size, 0)) < 0) {
		log_error("can not read from NL socket, error %d", rc);
		return rc;
	}

	*valid_chap_entries = ev.u.get_chap.num_entries;

	return rc;
}

static int kdelete_chap(uint64_t transport_handle, uint32_t host_no,
			uint16_t chap_tbl_idx)
{
	int rc = 0;
	struct iscsi_uevent ev;
	struct iovec iov[2];

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_DELETE_CHAP;
	ev.transport_handle = transport_handle;
	ev.u.delete_chap.host_no = host_no;
	ev.u.delete_chap.chap_tbl_idx = chap_tbl_idx;

	iov[1].iov_base = &ev;
	iov[1].iov_len = sizeof(ev);

	rc = __kipc_call(iov, 2);
	if (rc < 0)
		return rc;

	return rc;
}

static void drop_data(struct nlmsghdr *nlh)
{
	int ev_size;

	ev_size = nlh->nlmsg_len - NLMSG_ALIGN(sizeof(struct nlmsghdr));
	nlpayload_read(ctrl_fd, NULL, ev_size, 0);
}

static int ctldev_handle(void)
{
	int rc, ev_size;
	struct iscsi_uevent *ev;
	iscsi_session_t *session = NULL;
	iscsi_conn_t *conn = NULL;
	char nlm_ev[NLMSG_SPACE(sizeof(struct iscsi_uevent))];
	struct nlmsghdr *nlh;
	struct iscsi_ev_context *ev_context;
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
		if (!ipc_ev_clbk)
			return 0;

		if (ipc_ev_clbk->create_session)
			ipc_ev_clbk->create_session(ev->r.c_session_ret.host_no,
						    ev->r.c_session_ret.sid);
		return 0;
	case ISCSI_KEVENT_DESTROY_SESSION:
		if (!ipc_ev_clbk)
			return 0;

		drop_data(nlh);
		if (ipc_ev_clbk->destroy_session)
			ipc_ev_clbk->destroy_session(ev->r.d_session.host_no,
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
	case ISCSI_KEVENT_CONN_LOGIN_STATE:
		sid = ev->r.conn_login.sid;
		cid = ev->r.conn_login.cid;
		break;
	case ISCSI_KEVENT_UNBIND_SESSION:
		sid = ev->r.unbind_session.sid;
		/* session wide event so cid is 0 */
		cid = 0;
		break;
	case ISCSI_KEVENT_HOST_EVENT:
		switch (ev->r.host_event.code) {
		case ISCSI_EVENT_LINKUP:
			log_warning("Host%u: Link Up.\n",
				    ev->r.host_event.host_no);
			break;
		case ISCSI_EVENT_LINKDOWN:
			log_warning("Host%u: Link Down.\n",
				    ev->r.host_event.host_no);
			break;
		default:
			log_debug(7, "Host%u: Unknwon host event: %u.\n",
				  ev->r.host_event.host_no,
				  ev->r.host_event.code);
		}

		drop_data(nlh);
		return 0;
	case ISCSI_KEVENT_PING_COMP:
		ping_event.host_no = ev->r.ping_comp.host_no;
		ping_event.pid = ev->r.ping_comp.pid;
		ping_event.status = ev->r.ping_comp.status;
		ping_event.active = 1;

		drop_data(nlh);
		return 0;
	default:
		if ((ev->type > ISCSI_UEVENT_MAX && ev->type < KEVENT_BASE) ||
		    (ev->type > ISCSI_KEVENT_MAX))
			log_error("Unknown kernel event %d. You may want to "
				  " upgrade your iscsi tools.", ev->type);
		else
			/*
			 * If another app is using the interface we might
			 * see their
			 * stuff. Just drop it.
			 */
			log_debug(7, "Got unknwon event %d. Dropping.",
				  ev->type);
		drop_data(nlh);
		return 0;
	}

	/* verify connection */
	session = session_find_by_sid(sid);
	if (!session) {
		/*
		 * this can happen normally when other apps are using the
		 * nl interface.
		 */
		log_debug(1, "Could not verify connection %d:%d. Dropping "
			   "event.\n", sid, cid);
		drop_data(nlh);
		return -ENXIO;
	}
	conn = &session->conn[0];

	ev_size = nlh->nlmsg_len - NLMSG_ALIGN(sizeof(struct nlmsghdr));

	ev_context = ipc_ev_clbk->get_ev_context(conn, ev_size);
	if (!ev_context) {
		/* retry later */
		log_error("Can not allocate memory for receive context.");
		return -ENOMEM;
	}

	log_debug(6, "message real length is %d bytes, recv_handle %p",
		nlh->nlmsg_len, ev_context->data);

	if ((rc = nlpayload_read(ctrl_fd, ev_context->data,
				ev_size, 0)) < 0) {
		ipc_ev_clbk->put_ev_context(ev_context);
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
		rc = ipc_ev_clbk->sched_ev_context(ev_context, conn, 0,
						   EV_CONN_RECV_PDU);
		break;
	case ISCSI_KEVENT_CONN_ERROR:
		memcpy(ev_context->data, &ev->r.connerror.error,
			sizeof(ev->r.connerror.error));
		rc = ipc_ev_clbk->sched_ev_context(ev_context, conn, 0,
						   EV_CONN_ERROR);
		break;
	case ISCSI_KEVENT_CONN_LOGIN_STATE:
		memcpy(ev_context->data, &ev->r.conn_login.state,
			sizeof(ev->r.conn_login.state));
		rc = ipc_ev_clbk->sched_ev_context(ev_context, conn, 0,
						   EV_CONN_LOGIN);
		break;
	case ISCSI_KEVENT_UNBIND_SESSION:
		rc = ipc_ev_clbk->sched_ev_context(ev_context, conn, 0,
						   EV_CONN_STOP);
		break;
	default:
		ipc_ev_clbk->put_ev_context(ev_context);
		log_error("unknown kernel event %d", ev->type);
		return -EEXIST;
	}

	if (rc)
		ipc_ev_clbk->put_ev_context(ev_context);
	return rc;
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
	.set_net_config         = kset_net_config,
	.recv_conn_state        = krecv_conn_state,
	.exec_ping		= kexec_ping,
	.get_chap		= kget_chap,
	.delete_chap		= kdelete_chap,
};
struct iscsi_ipc *ipc = &nl_ipc;

void ipc_register_ev_callback(struct iscsi_ipc_ev_clbk *ev_clbk)
{
	ipc_ev_clbk = ev_clbk;
}
