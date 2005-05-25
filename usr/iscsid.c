/*
 * iSCSI Initiator Daemon
 *
 * Copyright (C) 2004 Dmitry Yusupov, Alex Aizman
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
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/poll.h>
#include <sys/utsname.h>
#include <sys/signal.h>

#include "iscsid.h"
#include "actor.h"
#include "mgmt_ipc.h"
#include "iscsi_ipc.h"
#include "log.h"

#define POLL_CTRL		0
#define POLL_IPC		1
#define POLL_MAX		2

/* global config info */
struct iscsi_daemon_config daemon_config;
struct iscsi_daemon_config *dconfig = &daemon_config;
iscsi_provider_t provider[ISCSI_TRANSPORT_MAX];

static char program_name[] = "iscsid";
int control_fd, mgmt_ipc_fd;
static struct pollfd poll_array[POLL_MAX];

static struct option const long_options[] = {
	{"config", required_argument, NULL, 'c'},
	{"foreground", no_argument, NULL, 'f'},
	{"debug", required_argument, NULL, 'd'},
	{"uid", required_argument, NULL, 'u'},
	{"gid", required_argument, NULL, 'g'},
	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'v'},
	{NULL, 0, NULL, 0},
};

static void usage(int status)
{
	if (status != 0)
		fprintf(stderr, "Try `%s --help' for more information.\n",
			program_name);
	else {
		printf("Usage: %s [OPTION]\n", program_name);
		printf("\
Open-iSCSI initiator daemon.\n\
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

void event_loop(void)
{
	int res;

	poll_array[POLL_CTRL].fd = control_fd;
	poll_array[POLL_CTRL].events = POLLIN;
	poll_array[POLL_IPC].fd = mgmt_ipc_fd;
	poll_array[POLL_IPC].events = POLLIN;

	while (1) {
		res = poll(poll_array, POLL_MAX, ACTOR_RESOLUTION);
		if (res <= 0) {
			if (res == 0) {
				actor_poll();
				continue;
			}
			if (res < 0 && errno != EINTR) {
				log_error("got poll() error (%d), errno (%d), "
					  "exiting", res, errno);
				exit(1);
			}
			log_debug(6, "poll result %d", res);
			continue;
		}

		log_debug(6, "detected poll event %d", res);

		if (poll_array[POLL_CTRL].revents)
			ipc->ctldev_handle();

		if (poll_array[POLL_IPC].revents)
			mgmt_ipc_handle(mgmt_ipc_fd);
	}
}

/*
 * synchronyze registered transports and opened sessions/connections
 */
int trans_sync(void)
{
	int i, found = 0;
	struct iscsi_uevent ev;

	if (ipc->trans_list(&ev))
		return -1;

	for (i = 0; i < ISCSI_TRANSPORT_MAX; i++) {
		if (ev.r.t_list.elements[i].trans_handle) {
			provider[i].handle =
				ev.r.t_list.elements[i].trans_handle;
			strncpy(provider[i].name, ev.r.t_list.elements[i].name,
				ISCSI_TRANSPORT_NAME_MAXLEN);
			provider[i].caps_mask =
					ev.r.t_list.elements[i].caps_mask;

			/* FIXME: implement session/connection sync up logic */
			provider[i].sessions.q_forw = &provider[i].sessions;
			provider[i].sessions.q_back = &provider[i].sessions;

			found++;
		}
	}
	if (!found) {
		log_error("no registered transports found!");
		return -1;
	}
	log_debug(1, "synced %d transport(s)", found);

	return 0;
}

static void oom_adjust(void)
{
	int fd;
	char path[48];

	nice(-10);
	sprintf(path, "/proc/%d/oom_adj", getpid());
	fd = open(path, O_WRONLY);
	if (fd < 0) {
		log_debug(1, "can not adjust oom-killer's pardon");
		return;
	}
	write(fd, "-16\n", 3); /* for 2.6.11 */
	write(fd, "-17\n", 3); /* for Andrea's patch */
	close(fd);
}

static void catch_signal(int signo) {
	log_warning("caught signal -%d, ignoring...", signo);
}

int main(int argc, char *argv[])
{
	struct utsname host_info; /* will use to compound initiator alias */
	char *config_file = CONFIG_FILE;
	int ch, longindex;
	uid_t uid = 0;
	gid_t gid = 0;
	struct sigaction sa_old;
	struct sigaction sa_new;

	/* do not allow ctrl-c for now... */
	sa_new.sa_handler = catch_signal;
	sigemptyset(&sa_new.sa_mask);
	sa_new.sa_flags = 0;
	sigaction(SIGINT, &sa_new, &sa_old );
	sigaction(SIGPIPE, &sa_new, &sa_old );
	sigaction(SIGTERM, &sa_new, &sa_old );

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

	/* initialize logger */
	log_init(program_name, DEFAULT_AREA_SIZE);

	if ((mgmt_ipc_fd = mgmt_ipc_listen()) < 0) {
		exit(-1);
	}

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
		} else if (pid) {
			log_warning("iSCSI daemon with pid=%d started!", pid);
			exit(0);
		}

		if ((control_fd = ipc->ctldev_open()) < 0) {
			exit(-1);
		}

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
	} else {
		if ((control_fd = ipc->ctldev_open()) < 0) {
			exit(-1);
		}
	}

	if (uid && setuid(uid) < 0)
		perror("setuid\n");

	if (gid && setgid(gid) < 0)
		perror("setgid\n");

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

	/* oom-killer will not kill us at the night... */
	oom_adjust();

	/* in case of transports/sessions/connections been active
	 * and we've been killed or crashed. update states.
	 */
	if (trans_sync()) {
		log_error("failed to get transport list, exiting...");
		exit(-1);
	}

	/* we don't want our active sessions to be paged out... */
	if (mlockall(MCL_CURRENT | MCL_FUTURE)) {
		log_error("failed to mlockall, exiting...");
		exit(1);
	}

	/*
	 * Start Main Event Loop
	 */
	actor_init();
	event_loop();

	/* we're done */
	log_debug(1, "daemon stopping");

	return 0;
}
