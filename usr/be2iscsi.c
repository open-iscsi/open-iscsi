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
	if (conn->max_recv_dlength > 65536)
		conn->max_recv_dlength = 65536;

	if (conn->session->first_burst > 8192)
		conn->session->first_burst = 8192;

	if (conn->session->max_burst > 262144)
		conn->session->max_burst = 262144;

	conn->session->erl = 0;
}
