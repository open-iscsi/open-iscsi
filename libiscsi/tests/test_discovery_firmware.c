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
#include <string.h>
#include "libiscsi.h"

int main(void)
{
	struct libiscsi_node *found_nodes;
	struct libiscsi_context *context;
	int i, found, rc = 0;

	context = libiscsi_init();
	if (!context) {
		fprintf(stderr, "Error initializing libiscsi\n");
		return 1;
	}

	rc = libiscsi_discover_firmware(context, &found, &found_nodes);
	if (rc)
		fprintf(stderr, "Error discovering: %s\n",
			libiscsi_get_error_string(context));

	for (i = 0; i < found; i++) {
		fprintf(stdout, "Found node: %s, tpgt: %d, portal: %s:%d\n",
			found_nodes[i].name, found_nodes[i].tpgt,
			found_nodes[i].address,	found_nodes[i].port);
	}

	libiscsi_cleanup(context);
	free (found_nodes);

	return rc;
}
