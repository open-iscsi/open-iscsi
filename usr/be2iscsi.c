/*
 * be2iscsi helpers
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
#include "initiator.h"

void be2iscsi_create_conn(struct iscsi_conn *conn)
{
	struct iscsi_session *session = conn->session;
	conn_rec_t *conn_rec = &session->nrec.conn[conn->id];

	if (conn->max_recv_dlength > 65536)
		conn->max_recv_dlength = 65536;

	if (session->first_burst > 8192)
		session->first_burst = 8192;

	if (session->max_burst > 262144)
		session->max_burst = 262144;

	if (conn->max_xmit_dlength > 65536)
		conn->max_xmit_dlength = 65536;

	if (!conn_rec->iscsi.MaxXmitDataSegmentLength ||
	    conn_rec->iscsi.MaxXmitDataSegmentLength > 65536)
		conn_rec->iscsi.MaxXmitDataSegmentLength = 65536;

	session->erl = 0;
	session->initial_r2t_en = 1;
}
