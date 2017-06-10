/*
 * iSCSI Administration library
 *
 * Copyright (C) 2008-2009 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2008-2009 Hans de Goede <hdegoede@redhat.com>
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

#include <stdio.h>
#include <stdlib.h>
#include "libiscsi.h"

int main(void)
{
	struct libiscsi_node node;
	struct libiscsi_context *context;
	int rc = 0;

	snprintf(node.name, LIBISCSI_VALUE_MAXLEN, "%s",
		 "iqn.2009-01.com.example:tgt-libiscsi");
	node.tpgt = 1;
	snprintf(node.address, NI_MAXHOST, "%s", "127.0.0.1");
	node.port = 3260;

	context = libiscsi_init();
	if (!context) {
		fprintf(stderr, "Error initializing libiscsi\n");
		return 1;
	}

	rc = libiscsi_node_logout(context, &node);
	if (rc)
		fprintf(stderr, "Error logging out: %s\n",
			libiscsi_get_error_string(context));

	libiscsi_cleanup(context);

	return rc;
}
