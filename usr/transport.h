/*
 * iSCSI transport
 *
 * Copyright (C) 2006 Mike Christie
 * Copyright (C) 2006 Red Hat, Inc. All rights reserved.
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
 */
#ifndef ISCSI_TRANSPORT_H
#define ISCSI_TRANSPORT_H

#include "types.h"

struct iscsi_provider_t;
struct iscsi_conn;

struct iscsi_uspace_transport {
	const char *name;
	uint8_t rdma;
	int (*ep_connect) (iscsi_conn_t *conn, int non_blocking);
	int (*ep_poll) (iscsi_conn_t *conn, int timeout_ms);
	void (*ep_disconnect) (iscsi_conn_t *conn);
};

extern int set_uspace_transport(struct iscsi_provider_t *p);

#endif
