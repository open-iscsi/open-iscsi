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
	struct libiscsi_node node;
	struct libiscsi_context *context;
	struct libiscsi_auth_info auth_info;
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

	rc = libiscsi_node_get_auth(context, &node, &auth_info);
	if (rc) {
		fprintf(stderr, "Error setting authinfo: %s\n",
			libiscsi_get_error_string(context));
		goto leave;
	}

	switch (auth_info.method) {
		case libiscsi_auth_none:
			printf("Method:  \"None\"\n");
			break;
		case libiscsi_auth_chap:
			printf("Method:  \"CHAP\"\n");
			printf("User:    \"%s\"\n", auth_info.chap.username);
			printf("Pass:    \"%s\"\n", auth_info.chap.password);
			printf("RevUser: \"%s\"\n",
				auth_info.chap.reverse_username);
			printf("RevPass: \"%s\"\n",
				auth_info.chap.reverse_password);
			break;
	}
leave:
	libiscsi_cleanup(context);

	return rc;
}
