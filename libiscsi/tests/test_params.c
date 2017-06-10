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
#include <errno.h>
#include <string.h>
#include "libiscsi.h"

int main(void)
{
	struct libiscsi_node node;
	struct libiscsi_context *context;
	char orig_value[LIBISCSI_VALUE_MAXLEN], value[LIBISCSI_VALUE_MAXLEN];
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

	rc = libiscsi_node_get_parameter(context, &node, "node.startup",
		orig_value);
	if (rc) {
		fprintf(stderr, "Error getting original value: %s\n",
			libiscsi_get_error_string(context));
		goto leave;
	}

	rc = libiscsi_node_set_parameter(context, &node, "node.startup",
		"automatic");
	if (rc) {
		fprintf(stderr, "Error setting node startup param: %s\n",
			libiscsi_get_error_string(context));
		goto leave;
	}

	rc = libiscsi_node_get_parameter(context, &node, "node.startup",
		value);
	if (rc) {
		fprintf(stderr, "Error getting node startup param: %s\n",
			libiscsi_get_error_string(context));
		goto leave;
	}

	if (strcmp(value, "automatic")) {
		fprintf(stderr, "Error set and get values do not match!\n");
		rc = EIO;
		goto leave;
	}

	rc = libiscsi_node_set_parameter(context, &node, "node.startup",
		orig_value);
	if (rc) {
		fprintf(stderr, "Error setting original value: %s\n",
			libiscsi_get_error_string(context));
		goto leave;
	}

	rc = libiscsi_node_get_parameter(context, &node, "node.startup",
		value);
	if (rc) {
		fprintf(stderr, "Error re-getting original value: %s\n",
			libiscsi_get_error_string(context));
		goto leave;
	}

	if (strcmp(value, orig_value)) {
		fprintf(stderr,
			"Error set and get original values do not match!\n");
		rc = EIO;
		goto leave;
	}

leave:
	libiscsi_cleanup(context);

	return rc;
}
