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
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <dirent.h>
#include <asm/types.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/netlink.h>

#include "types.h"
#include "iscsi_if.h"
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


#define ISCSI_TRANSPORT_DIR "/sys/class/iscsi_transport"

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
kdestroy_session(uint64_t transport_handle, uint64_t sessionh, uint32_t sid)
{
	int rc;
	struct iscsi_uevent ev;

	log_debug(7, "in %s", __FUNCTION__);

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_DESTROY_SESSION;
	ev.transport_handle = transport_handle;
	ev.u.d_session.session_handle = sessionh;
	ev.u.d_session.sid = sid;

	if ((rc = __kipc_call(&ev, sizeof(ev))) < 0) {
		return rc;
	}

	return 0;
}

static int
kcreate_conn(uint64_t transport_handle, uint64_t sessionh, uint32_t sid,
	    uint32_t cid, uint64_t *out_handle)
{
	int rc;
	struct iscsi_uevent ev;

	log_debug(7, "in %s", __FUNCTION__);

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_CREATE_CONN;
	ev.transport_handle = transport_handle;
	ev.u.c_conn.session_handle = sessionh;
	ev.u.c_conn.cid = cid;
	ev.u.c_conn.sid = sid;

	if ((rc = __kipc_call(&ev, sizeof(ev))) < 0) {
		return rc;
	}
	if (!ev.r.handle)
		return -EIO;

	*out_handle = ev.r.handle;
	return 0;
}

static int
kdestroy_conn(uint64_t transport_handle, uint64_t connh, int cid)
{
	int rc;
	struct iscsi_uevent ev;

	log_debug(7, "in %s", __FUNCTION__);

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_DESTROY_CONN;
	ev.transport_handle = transport_handle;
	ev.u.d_conn.conn_handle = connh;
	ev.u.d_conn.cid = cid;

	if ((rc = __kipc_call(&ev, sizeof(ev))) < 0) {
		return rc;
	}

	return 0;
}

static int
kbind_conn(uint64_t transport_handle, uint64_t sessionh, uint64_t connh,
	  uint32_t transport_fd, int is_leading, int *retcode)
{
	int rc;
	struct iscsi_uevent ev;

	log_debug(7, "in %s", __FUNCTION__);

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_BIND_CONN;
	ev.transport_handle = transport_handle;
	ev.u.b_conn.session_handle = sessionh;
	ev.u.b_conn.conn_handle = connh;
	ev.u.b_conn.transport_fd = transport_fd;
	ev.u.b_conn.is_leading = is_leading;

	if ((rc = __kipc_call(&ev, sizeof(ev))) < 0) {
		return rc;
	}

	*retcode = ev.r.retcode;

	return 0;
}

static void
ksend_pdu_begin(uint64_t transport_handle, uint64_t connh,
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
	ev->u.send_pdu.conn_handle = connh;
	ev->u.send_pdu.hdr_size = hdr_size;
	ev->u.send_pdu.data_size = data_size;

	log_debug(3, "send PDU began for hdr %d bytes and data %d bytes",
		hdr_size, data_size);
}

static int
ksend_pdu_end(uint64_t transport_handle, uint64_t connh, int *retcode)
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
	if (ev->u.send_pdu.conn_handle != connh) {
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

	log_debug(3, "send PDU finished for conn (handle %p)", iscsi_ptr(connh));

	xmitbuf = NULL;
	return 0;

err:
	xmitbuf = NULL;
	xmitlen = 0;
	return rc;
}

static int
kset_param(uint64_t transport_handle, uint64_t connh,
	       enum iscsi_param param, uint32_t value, int *retcode)
{
	int rc;
	struct iscsi_uevent ev;

	log_debug(7, "in %s", __FUNCTION__);

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_SET_PARAM;
	ev.transport_handle = transport_handle;
	ev.u.set_param.conn_handle = connh;
	ev.u.set_param.param = param;
	ev.u.set_param.value = value;

	if ((rc = __kipc_call(&ev, sizeof(ev))) < 0) {
		return rc;
	}

	*retcode = ev.r.retcode;

	return 0;
}

static int
kstop_conn(uint64_t transport_handle, uint64_t connh, int flag)
{
	int rc;
	struct iscsi_uevent ev;

	log_debug(7, "in %s", __FUNCTION__);

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_STOP_CONN;
	ev.transport_handle = transport_handle;
	ev.u.stop_conn.conn_handle = connh;
	ev.u.stop_conn.flag = flag;

	if ((rc = __kipc_call(&ev, sizeof(ev))) < 0) {
		return rc;
	}

	return 0;
}

static int
kstart_conn(uint64_t transport_handle, uint64_t connh, int *retcode)
{
	int rc;
	struct iscsi_uevent ev;

	log_debug(7, "in %s", __FUNCTION__);

	memset(&ev, 0, sizeof(struct iscsi_uevent));

	ev.type = ISCSI_UEVENT_START_CONN;
	ev.transport_handle = transport_handle;
	ev.u.start_conn.conn_handle = connh;

	if ((rc = __kipc_call(&ev, sizeof(ev))) < 0) {
		return rc;
	}

	*retcode = ev.r.retcode;
	return 0;
}

static int
krecv_pdu_begin(uint64_t transport_handle, uint64_t connh,
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
read_transport_file(char *filename, void *value, char *format)
{
	FILE *file;
	char buffer[32], *line;
	int err = 0;

	file = fopen(filename, "r");
	if (file) {
		line = fgets(buffer, sizeof(buffer), file);
		if (line)
			sscanf(buffer, format, value);
		else {
			log_error("Could not open %s.\n", filename);
			err = -EIO;
		}
		fclose(file);
	}
	return err;
}

static int
trans_filter(const struct dirent *dir)
{
	return strcmp(dir->d_name, ".") && strcmp(dir->d_name, "..");
}

static int
ktrans_list(void)
{
	struct dirent **namelist;
	char filename[64];
	int i, n, err = 0;

	log_debug(7, "in %s", __FUNCTION__);

	n = scandir(ISCSI_TRANSPORT_DIR, &namelist, trans_filter,
		    alphasort);
	if (n < 0) {
		log_error("Could not scan %s.", ISCSI_TRANSPORT_DIR);
		return n;
	}

	if (n > num_providers) {
		iscsi_provider_t *provider_arr;

		provider_arr = calloc(n,sizeof(iscsi_provider_t));
		if (provider_arr == NULL) {
			log_error("Failed to alloc %d poviders.", n);
			return -ENOMEM;
		}
		if (num_providers > 0) {
			free(provider);
		}
		provider = provider_arr;
		num_providers = n;
	}

	for (i = 0; i < n; i++) {
		strncpy(provider[i].name, namelist[i]->d_name,
			ISCSI_TRANSPORT_NAME_MAXLEN);
		free(namelist[i]);

		sprintf(filename, ISCSI_TRANSPORT_DIR"/%s/handle",
			provider[i].name);
		err = read_transport_file(filename, &provider[i].handle,
					  "%lu");
		if (err)
			break;

		sprintf(filename, ISCSI_TRANSPORT_DIR"/%s/caps",
			provider[i].name);
		err = read_transport_file(filename, &provider[i].caps,
					  "0x%x");
		if (err)
			break;

		sprintf(filename, ISCSI_TRANSPORT_DIR"/%s/af",
			provider[i].name);
		err = read_transport_file(filename, &provider[i].af,
					  "%u");
		if (err)
			break;

		sprintf(filename, ISCSI_TRANSPORT_DIR"/%s/rdma",
			provider[i].name);
		err = read_transport_file(filename, &provider[i].rdma,
					  "%u");
		if (err)
			break;
	}

	for (i++; i < n; i++)
		free(namelist[i]);
	free(namelist);

	return err;
}

static int
kget_stats(uint64_t transport_handle, uint64_t connh, char *statsbuf,
	int statsbuf_max)
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
	ev.u.get_stats.conn_handle = connh;

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
	int k;

	log_debug(7, "in %s", __FUNCTION__);

	if ((rc = nl_read(ctrl_fd, nlm_ev,
		NLMSG_SPACE(sizeof(struct iscsi_uevent)), MSG_PEEK)) < 0) {
		log_error("can not read nlm_ev, error %d", rc);
		return rc;
	}
	nlh = (struct nlmsghdr *)nlm_ev;
	ev = (struct iscsi_uevent *)NLMSG_DATA(nlm_ev);

	/* verify connection */
	for (k = 0; k < num_providers; k++) {
		item = provider[k].sessions.q_forw;
		while (item != &provider[k].sessions) {
			int i;
			session = (iscsi_session_t *)item;
			for (i=0; i<ISCSI_CONN_MAX; i++) {
				if (ev->type == ISCSI_KEVENT_RECV_PDU &&
				    ev->r.recv_req.conn_handle &&
				    session->conn[i].handle ==
						ev->r.recv_req.conn_handle) {
					conn = &session->conn[i];
					break;
				}
				if (ev->type == ISCSI_KEVENT_CONN_ERROR &&
				    ev->r.connerror.conn_handle &&
				    session->conn[i].handle ==
						ev->r.connerror.conn_handle) {
					conn = &session->conn[i];
					break;
				}
			}
			item = item->q_forw;
		}
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
		queue_produce(session->queue, EV_CONN_RECV_PDU, conn,
			sizeof(uintptr_t), &recv_handle);
		actor_schedule(&session->mainloop);
	} else if (ev->type == ISCSI_KEVENT_CONN_ERROR) {
		/* produce an event, so session manager will handle */
		queue_produce(session->queue, EV_CONN_ERROR, conn,
			sizeof(uintptr_t), (void*)&ev->r.connerror.error);
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
	.create_conn            = kcreate_conn,
	.destroy_conn           = kdestroy_conn,
	.bind_conn              = kbind_conn,
	.set_param              = kset_param,
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
