/*
 * iSCSI Administration Utility
 *
 * Copyright (C) 2004 Dmitry Yusupov, Alex Aizman
 * maintained by open-iscsi@@googlegroups.com
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

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include "iscsid.h"
#include "iscsiadm.h"

static char program_name[] = "iscsiadm";

static struct option const long_options[] =
{
	{"version", no_argument, 0, 'v'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0},
};

static void usage(int status)
{
	if (status != 0)
		fprintf(stderr, "Try `%s --help' for more information.\n",
			program_name);
	else {
		printf("Usage: %s [OPTION]\n", program_name);
		printf("\
iSCSI Administration Utility.\n\
  -v, --version           display version and exit\n\
  -h, --help              display this help and exit\n\
");
	}

	exit(status == 0 ? 0 : -1);
}

int
main(int argc, char **argv)
{
	int ch, longindex;

	while ((ch = getopt_long(argc, argv, "v:h:",
				 long_options, &longindex)) >= 0) {
		switch (ch) {
		case 'v':
			version();
			break;
		case 'h':
			usage(0);
			break;
		}
	}

	return 0;
}
