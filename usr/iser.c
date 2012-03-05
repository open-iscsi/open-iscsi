/*
 * iser helpers
 *
 * Copyright (C) 2012 Red Hat, Inc. All rights reserved.
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

void iser_create_conn(struct iscsi_conn *conn)
{
	/* header digests not supported in iser */
	conn->hdrdgst_en = ISCSI_DIGEST_NONE;
}
