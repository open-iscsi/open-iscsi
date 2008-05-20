/*
 * User/Kernel Transport IPC API Ioctl/NETLINK/etc
 *
 * Copyright (C) 2005 Dmitry Yusupov, Alex Aizman
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
 *
 * NOTE: OSes must implement this API in terms of user's control-plane re-use.
 */

#ifndef ISCSI_IPC_H
#define ISCSI_IPC_H

#if defined(FreeBSD)
#include <sys/_iovec.h>
#endif

#include "iscsi_if.h"

enum {
	ISCSI_INT,
	ISCSI_STRING,
};

struct iscsi_conn;

/**
 * struct iscsi_ipc - Open-iSCSI Interface for Kernel IPC
 *
 * All functions allowed to return POSIX kind of error. i.e. 0 - OK, non-zero
 * means IPC error and errno set.
 */
struct iscsi_ipc {
	char *name;

	int ctldev_bufmax;

	int (*ctldev_open) (void);

	void (*ctldev_close) (void);

	int (*ctldev_handle) (void);

	int (*sendtargets) (uint64_t transport_handle, uint32_t host_no,
			    struct sockaddr *addr);

	int (*create_session) (uint64_t transport_handle, uint64_t ep_handle,
			       uint32_t initial_cmdsn, uint16_t cmds_max,
			       uint16_t qdepth, uint32_t *out_sid,
			       uint32_t *hostno);

	int (*destroy_session) (uint64_t transport_handle, uint32_t sid);

	int (*unbind_session) (uint64_t transport_handle, uint32_t sid);

	int (*create_conn) (uint64_t transport_handle,
			    uint32_t sid, uint32_t cid, uint32_t *out_cid);

	int (*destroy_conn) (uint64_t transport_handle, uint32_t sid,
			     uint32_t cid);

	int (*bind_conn) (uint64_t transport_handle, uint32_t sid,
			  uint32_t cid, uint64_t transport_eph,
			  int is_leading, int *retcode);

	int (*set_param) (uint64_t transport_handle, uint32_t sid,
			  uint32_t cid, enum iscsi_param param,
			  void *value, int type);

	int (*set_host_param) (uint64_t transport_handle, uint32_t host_no,
			       enum iscsi_host_param param,
			       void *value, int type);

	/* not implemented yet */
	int (*get_param) (uint64_t transport_handle, uint32_t sid,
			  uint32_t cid, enum iscsi_param param,
			  uint32_t *value, int *retcode);

	int (*get_stats) (uint64_t transport_handle, uint32_t sid,
			  uint32_t cid, char *statsbuf, int statsbuf_max);

	int (*start_conn) (uint64_t transport_handle, uint32_t sid,
			   uint32_t cid, int *retcode);

	int (*stop_conn) (uint64_t transport_handle, uint32_t sid,
			  uint32_t cid, int flag);

	int (*read) (char *data, int count);

	void (*send_pdu_begin) (uint64_t transport_handle, uint32_t sid,
				uint32_t cid, int hdr_size, int data_size);

	int (*send_pdu_end) (uint64_t transport_handle, uint32_t sid,
			     uint32_t cid, int *retcode);

	int (*writev) (enum iscsi_uevent_e type, struct iovec *iovp, int count);

	int (*recv_pdu_begin) (struct iscsi_conn *conn);

	int (*recv_pdu_end) (struct iscsi_conn *conn);
};

#endif /* ISCSI_IPC_H */
