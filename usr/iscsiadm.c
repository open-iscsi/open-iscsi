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

#include <sys/utsname.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include "initiator.h"
#include "iscsiadm.h"
#include "config.h"
#include "log.h"

static char program_name[] = "iscsiadm";

/* global config info */
struct iscsi_daemon_config daemon_config;
struct iscsi_daemon_config *dconfig = &daemon_config;

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
	struct utsname host_info; /* will use to compound initiator alias */
	struct iscsi_config config;
	int ch, longindex;

	/* enable stdout logging */
	log_daemon = 0;
	log_init(program_name);

	/* initialize configuration defaults */
	memset(&config, 0, sizeof (config));
	iscsi_init_config_defaults(&config.defaults);

	memset(&daemon_config, 0, sizeof (daemon_config));
	daemon_config.pid_file = PID_FILE;
	daemon_config.config_file = CONFIG_FILE;
	daemon_config.initiator_name_file = INITIATOR_NAME_FILE;
	daemon_config.initiator_name =
	    get_iscsi_initiatorname(daemon_config.initiator_name_file);
	if (daemon_config.initiator_name == NULL) {
		log_warning("exiting due to configuration error");
		exit(1);
	}

	/* optional InitiatorAlias */
	memset(&host_info, 0, sizeof (host_info));
	if (uname(&host_info) >= 0) {
		daemon_config.initiator_alias = strdup(host_info.nodename);
	}


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
