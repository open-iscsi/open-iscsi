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
	char initiatorname[LIBISCSI_VALUE_MAXLEN];

	if (libiscsi_get_firmware_initiator_name(initiatorname)) {
		fprintf(stderr, "No iscsi boot firmware found\n");
		return 1;
	}

	printf("iqn:\t%s\n", initiatorname);

	return 0;
}
