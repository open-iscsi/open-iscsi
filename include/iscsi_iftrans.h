/*
 * iSCSI Transport Interface
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
 */

#ifndef ISCSI_IFTRANS_H
#define ISCSI_IFTRANS_H

#include <iscsi_if.h>

/**
 * struct iscsi_transport - down calls
 *
 * @name: transport name
 * @caps: iSCSI Data-Path capabilities
 * @create_snx: create new iSCSI session object
 * @destroy_snx: destroy existing iSCSI session object
 * @create_cnx: create new iSCSI connection
 * @bind_cnx: associate this connection with existing iSCSI session and
 *            specified transport descriptor
 * @destroy_cnx: destroy inactive iSCSI connection
 * @set_param: set iSCSI Data-Path operational parameter
 * @start_cnx: set connection to be operational
 * @stop_cnx: suspend connection
 * @send_pdu: send iSCSI PDU, Login, Logout, NOP-Out, Reject, Text.
 *
 * API provided by generic iSCSI Data Path module
 */
struct iscsi_transport {
	struct module *owner;
	char *name;
	unsigned int caps;
	struct scsi_host_template *host_template;
	int hostdata_size;
	int max_lun;
	unsigned int max_cnx;
	unsigned int max_cmd_len;
	iscsi_snx_t (*create_session) (iscsi_snx_t cp_snx,
			uint32_t initial_cmdsn, struct Scsi_Host *shost);
	void (*destroy_session) (iscsi_snx_t dp_snx);
	iscsi_cnx_t (*create_cnx) (iscsi_snx_t dp_snx, iscsi_cnx_t cp_cnx,
			uint32_t cid);
	int (*bind_cnx) (iscsi_snx_t dp_snx, iscsi_cnx_t dp_cnx,
			uint32_t transport_fd, int is_leading);
	int (*start_cnx) (iscsi_cnx_t dp_cnx);
	void (*stop_cnx) (iscsi_cnx_t dp_cnx, int flag);
	void (*destroy_cnx) (iscsi_cnx_t dp_cnx);
	int (*set_param) (iscsi_cnx_t dp_cnx, enum iscsi_param param,
			  uint32_t value);
	int (*get_param) (iscsi_cnx_t dp_cnx, enum iscsi_param param,
			  uint32_t *value);
	int (*send_pdu) (iscsi_cnx_t dp_cnx, struct iscsi_hdr *hdr,
			 char *data, uint32_t data_size);
};

/*
 * up calls
 */
int iscsi_register_transport(struct iscsi_transport *t);
int iscsi_unregister_transport(struct iscsi_transport *t);
int iscsi_control_recv_pdu(iscsi_cnx_t cp_cnx, struct iscsi_hdr *hdr,
				char *data, uint32_t data_size);
void iscsi_control_cnx_error(iscsi_cnx_t cp_cnx, enum iscsi_err error);

#endif /* ISCSI_IFTRANS_H */
