/*
 * iSCSI Initiator Daemon
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
#include <sys/poll.h>
#include <sys/utsname.h>

#include "iscsi_u.h"
#include "iscsid.h"
#include "ipc.h"
#include "log.h"

#define POLL_MAX		(ISCSI_SESSION_MAX + 2)
#define POLL_CTRL		0
#define POLL_IPC		1
#define POLL_SESSION		2

/* global config info */
struct iscsi_daemon_config daemon_config;
struct iscsi_daemon_config *dconfig = &daemon_config;

static char program_name[] = "iscsid";
int ctrl_fd, ipc_fd;
static struct pollfd poll_array[POLL_MAX];

static struct option const long_options[] = {
	{"config", required_argument, 0, 'c'},
	{"foreground", no_argument, 0, 'f'},
	{"debug", required_argument, 0, 'd'},
	{"uid", required_argument, 0, 'u'},
	{"gid", required_argument, 0, 'g'},
	{"help", no_argument, 0, 'h'},
	{"version", no_argument, 0, 'v'},
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
iSCSI initiator daemon.\n\
  -c, --config=[path]     Execute in the config file (" CONFIG_FILE ").\n\
  -f, --foreground        make the program run in the foreground\n\
  -d, --debug debuglevel  print debugging information\n\
  -u, --uid=uid           run as uid, default is current user\n\
  -g, --gid=gid           run as gid, default is current user group\n\
  -h, --help              display this help and exit\n\
  -v, --version           display version and exit\n\
");
	}
	exit(status == 0 ? 0 : -1);
}

char *
get_iscsi_initiatorname(char *pathname)
{
	FILE *f = NULL;
	int c;
	char *line, buffer[1024];
	char *name = NULL;

	if (!pathname) {
		log_error("No pathname to load InitiatorName from");
		return NULL;
	}

	/* get the InitiatorName */
	if ((f = fopen(pathname, "r"))) {
		while ((line = fgets(buffer, sizeof (buffer), f))) {

			while (line && isspace(c = *line))
				line++;

			if (strncmp(line, "InitiatorName=", 14) == 0) {
				char *end = line + 14;

				/* the name is everything up to the first
				 * bit of whitespace
				 */
				while (*end && (!isspace(c = *end)))
					end++;

				if (isspace(c = *end))
					*end = '\0';

				if (end > line + 14)
					name = strdup(line + 14);
			}
		}
		fclose(f);
		if (!name) {
			log_error(
			       "an InitiatorName is required, but "
			       "was not found in %s", pathname);
			return NULL;
		} else {
			log_debug(5, "InitiatorName=%s\n", name);
		}
		return name;
	} else {
		log_error("cannot open InitiatorName configuration file %s",
			 pathname);
		return NULL;
	}
}

void
iscsi_events_handle(void)
{
	iscsi_uevent_t event;
	int res;

	while (1) {
		res = read(ctrl_fd, &event, sizeof(event));
		if (res < 0) {
			if (errno == EAGAIN)
				return;
			if (errno == EINTR)
				continue;
			log_error("read ctrl_fd (%d)", errno);
			exit(1);
		}

		log_debug(1, "event cid %u sid %d state %u",
			  event.cid, event.sid, event.state);

		switch (event.state) {
		default:
			printf("%s(%d) %u\n", __FUNCTION__, __LINE__,
			       event.state);
			exit(-1);
			break;
		}
	}
}

void
event_loop(void)
{
	int res, i;

	poll_array[POLL_CTRL].fd = ctrl_fd;
	poll_array[POLL_CTRL].events = POLLIN;
	poll_array[POLL_IPC].fd = ipc_fd;
	poll_array[POLL_IPC].events = POLLIN;

	for (i = 0; i < ISCSI_SESSION_MAX; i++) {
		poll_array[POLL_SESSION + i].fd = -1;
		poll_array[POLL_SESSION + i].events = 0;
	}

	while (1) {
		res = poll(poll_array, POLL_MAX, -1);
		if (res <= 0) {
			if (res < 0 && errno != EINTR) {
				perror("poll()");
				exit(1);
			}
			continue;
		}

		if (poll_array[POLL_CTRL].revents)
			iscsi_events_handle();

		if (poll_array[POLL_IPC].revents)
			ipc_handle(ipc_fd);
	}
}

int
main(int argc, char *argv[])
{
	struct utsname host_info; /* will use to compound initiator alias */
	char *config_file = CONFIG_FILE;
	int ch, longindex;
	uid_t uid = 0;
	gid_t gid = 0;

	while ((ch = getopt_long(argc, argv, "c:fd:u:g:vh", long_options,
				 &longindex)) >= 0) {
		switch (ch) {
		case 'c':
			config_file = optarg;
			break;
		case 'f':
			log_daemon = 0;
			break;
		case 'd':
			log_level = atoi(optarg);
			break;
		case 'u':
			uid = strtoul(optarg, NULL, 10);
			break;
		case 'g':
			gid = strtoul(optarg, NULL, 10);
			break;
		case 'v':
			printf("%s version %s\n", program_name,
				ISCSI_VERSION_STR);
			exit(0);
		case 'h':
			usage(0);
			break;
		default:
			usage(1);
			break;
		}
	}

	if ((ctrl_fd = ctldev_open()) < 0) {
		exit(-1);
	}

	if ((ipc_fd = ipc_listen()) < 0) {
		exit(-1);
	}

	log_init(program_name);
	if (log_daemon) {
		char buf[64];
		pid_t pid;
		int fd;

		fd = open(PID_FILE, O_WRONLY|O_CREAT, 0644);
		if (fd < 0) {
			log_error("unable to create pid file");
			exit(1);
		}
		pid = fork();
		if (pid < 0) {
			log_error("starting daemon failed");
			exit(1);
		} else if (pid)
			exit(0);

		chdir("/");
		if (lockf(fd, F_TLOCK, 0) < 0) {
			log_error("unable to lock pid file");
			exit(1);
		}
		ftruncate(fd, 0);
		sprintf(buf, "%d\n", getpid());
		write(fd, buf, strlen(buf));

		close(0);
		open("/dev/null", O_RDWR);
		dup2(0, 1);
		dup2(0, 2);
		setsid();
	}

	if (uid && setuid(uid) < 0)
		perror("setuid\n");

	if (gid && setgid(gid) < 0)
		perror("setgid\n");

	/* initialize configuration defaults */
//	memset(&config, 0, sizeof (config));
//	iscsi_init_config_defaults(&config.defaults);

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

	log_debug(1, "InitiatorName=%s", daemon_config.initiator_name);
	log_debug(1, "InitiatorAlias=%s", daemon_config.initiator_alias);

	/* log the version, so that we can tell if the daemon and kernel module
	 * match based on what shows up in the syslog.  Tarballs releases
	 * always install both, but Linux distributors may put the kernel module
	 * in a different RPM from the daemon and utils, and users may try to
	 * mix and match in ways that don't work.
	 */
	log_warning("version %s variant (%s)",
		ISCSI_VERSION_STR, ISCSI_DATE_STR);

//	/* load the configuration for the first time */
//	if (!update_iscsi_config(daemon_config.config_file, &config)) {
//		log_error("failed to load configuration from %s",
//		       daemon_config.config_file);
//		exit(2);
//	}

	/*
	 * Start Main Event Loop
	 */
	event_loop();

	/* we're done */
	log_debug(1, "daemon stopping");

	return 0;
}
