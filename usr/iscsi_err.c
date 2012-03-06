/*
 * iSCSI error helpers
 *
 * Copyright (C) 2011 Mike Christie
 * Copyright (C) 2011 Red Hat, Inc. All rights reserved.
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
#include "stdlib.h"
#include "iscsi_err.h"
#include "log.h"

static char *iscsi_err_msgs[] = {
	/* 0 */ "",
	/* 1 */ "unknown error",
	/* 2 */ "session not found",
	/* 3 */ "no available memory",
	/* 4 */ "encountered connection failure",
	/* 5 */ "encountered iSCSI login failure",
	/* 6 */ "encountered iSCSI database failure",
	/* 7 */ "invalid parameter",
	/* 8 */ "connection timed out",
	/* 9 */ "internal error",
	/* 10 */ "encountered iSCSI logout failure",
	/* 11 */ "iSCSI PDU timed out",
	/* 12 */ "iSCSI driver not found. Please make sure it is loaded, and retry the operation",
	/* 13 */ "daemon access denied",
	/* 14 */ "iSCSI driver does not support requested capability.",
	/* 15 */ "session exists",
	/* 16 */ "Unknown request",
	/* 17 */ "iSNS service not supported",
	/* 18 */ "could not communicate to iscsid",
	/* 19 */ "encountered non-retryable iSCSI login failure",
	/* 20 */ "could not connect to iscsid",
	/* 21 */ "no objects found",
	/* 22 */ "sysfs lookup failure",
	/* 23 */ "host not found",
	/* 24 */ "iSCSI login failed due to authorization failure",
	/* 25 */ "iSNS query failed",
	/* 26 */ "iSNS registration failed",
	/* 27 */ "operation not supported",
	/* 28 */ "device or resource in use",
};

char *iscsi_err_to_str(int err)
{
	if (err >= ISCSI_MAX_ERR_VAL || err < 0) {
		log_error("invalid error code %d", err);
		return NULL;
	}

	return iscsi_err_msgs[err];
}

void iscsi_err_print_msg(int err)
{
	if (err >= ISCSI_MAX_ERR_VAL || err < 0) {
		log_error("invalid error code %d", err);
		return;
	}
	log_error("initiator reported error (%d - %s)", err,
		  iscsi_err_msgs[err]);
}
