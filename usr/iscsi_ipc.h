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

	/* FIXME: do not use iscsi_uevent... */
	int (*trans_list) (struct iscsi_uevent *ev);

	int (*create_session) (uint64_t transport_handle, ulong_t cp_snx,
			       uint32_t initial_cmdsn, ulong_t *out_handle,
			       int *out_sid);

	int (*destroy_session) (uint64_t transport_handle, ulong_t dp_snx,
				int sid);

	int (*create_cnx) (uint64_t transport_handle, ulong_t dp_snx,
			   ulong_t cp_cnx, uint32_t sid, uint32_t cid,
			   ulong_t *out_handle);

	int (*destroy_cnx) (uint64_t transport_handle, ulong_t dp_cnx,
			    int cid);

	int (*bind_cnx) (uint64_t transport_handle, ulong_t dp_snx,
			 ulong_t dp_cnx, uint32_t transport_fd,
			 int is_leading, int *retcode);

	int (*set_param) (uint64_t transport_handle, ulong_t dp_cnx,
			  enum iscsi_param param, uint32_t value, int *retcode);

	/* not implemented yet */
	int (*get_param) (uint64_t transport_handle, ulong_t dp_cnx,
			  enum iscsi_param param, uint32_t *value,
			  int *retcode);

	int (*start_cnx) (uint64_t transport_handle, ulong_t dp_cnx,
			  int *retcode);

	int (*stop_cnx) (uint64_t transport_handle, ulong_t dp_cnx,
			 int flag);

	int (*read) (char *data, int count);

	void (*send_pdu_begin) (uint64_t transport_handle, ulong_t dp_cnx,
				int hdr_size, int data_size);

	int (*send_pdu_end) (uint64_t transport_handle, ulong_t dp_cnx,
			     int *retcode);

	int (*writev) (enum iscsi_uevent_e type, struct iovec *iovp, int count);

	int (*recv_pdu_begin) (uint64_t transport_handle, ulong_t dp_cnx,
				ulong_t recv_handle, ulong_t *pdu_handle,
				int *pdu_size);

	int (*recv_pdu_end) (uint64_t transport_handle, ulong_t cp_cnx,
			     ulong_t pdu_handle);
};

#endif /* ISCSI_IPC_H */
