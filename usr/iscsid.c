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
#include "mgmt_ipc.h"
#include "iscsi_ipc.h"
#include "log.h"
#include "util.h"
#include "initiator.h"
#include "idbm.h"

/* global config info */
struct iscsi_daemon_config daemon_config;
struct iscsi_daemon_config *dconfig = &daemon_config;
iscsi_provider_t *provider = NULL;
int num_providers = 0;

static char program_name[] = "iscsid";
int control_fd, mgmt_ipc_fd;
int mgmt_shutdown_requsted = 0;

static struct mgmt_ipc_db mgmt_ipc_db = {
	.init		= idbm_init,
	.terminate	= idbm_terminate,
	.node_read	= idbm_node_read,
};

static struct option const long_options[] = {
	{"config", required_argument, NULL, 'c'},
	{"initiatorname", required_argument, NULL, 'i'},
	{"foreground", no_argument, NULL, 'f'},
	{"debug", required_argument, NULL, 'd'},
	{"uid", required_argument, NULL, 'u'},
	{"gid", required_argument, NULL, 'g'},
	{"pid", required_argument, NULL, 'p'},
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
  -i, --initiatorname=[path]     read initiatorname from file (" INITIATOR_NAME_FILE ").\n\
  -f, --foreground        make the program run in the foreground\n\
  -d, --debug debuglevel  print debugging information\n\
  -u, --uid=uid           run as uid, default is current user\n\
  -g, --gid=gid           run as gid, default is current user group\n\
  -p, --pid=pidfile       use pid file (default " PID_FILE ").\n\
  -h, --help              display this help and exit\n\
  -v, --version           display version and exit\n\
");
	}
	exit(status == 0 ? 0 : -1);
}

/*
 * synchronyze registered transports and opened sessions/connections
 */
int trans_sync(void)
{
	int i, found = 0;

	if (ipc->trans_list())
		return -1;

	for (i = 0; i < num_providers; i++) {
		if (provider[i].handle) {
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

static void catch_signal(int signo) {
	log_warning("caught signal -%d, ignoring...", signo);
}

static void iscsid_exit(void)
{
	if (num_providers > 0) {
		free(provider);
	}
}

int main(int argc, char *argv[])
{
	struct utsname host_info; /* will use to compound initiator alias */
	char *config_file = CONFIG_FILE;
	char *initiatorname_file = INITIATOR_NAME_FILE;
	char *pid_file = PID_FILE;
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

	while ((ch = getopt_long(argc, argv, "c:i:fd:u:g:p:vh", long_options,
				 &longindex)) >= 0) {
		switch (ch) {
		case 'c':
			config_file = optarg;
			break;
		case 'i':
			initiatorname_file = optarg;
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
		case 'p':
			pid_file = optarg;
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

	/* make sure we have initiatorname config file first */
	if (access(initiatorname_file, R_OK)) {
		fprintf(stderr, "Error: initiatorname file doesn't exist!");
		fprintf(stderr, " default [%s]\n", INITIATOR_NAME_FILE);
		usage(0);
	}

	/* initialize logger */
	log_init(program_name, DEFAULT_AREA_SIZE);

	if (atexit(iscsid_exit)) {
		log_error("failed to set exit function\n");
		exit(1);
	}

	if ((mgmt_ipc_fd = mgmt_ipc_listen()) < 0) {
		exit(-1);
	}

	if (log_daemon) {
		char buf[64];
		pid_t pid;
		int fd;

		fd = open(pid_file, O_WRONLY|O_CREAT, 0644);
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

		daemon_init();
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
	daemon_config.pid_file = pid_file;
	daemon_config.config_file = config_file;
	daemon_config.initiator_name_file = initiatorname_file;
	daemon_config.initiator_name =
	    get_iscsi_initiatorname(daemon_config.initiator_name_file);
	if (daemon_config.initiator_name == NULL) {
		log_warning("exiting due to configuration error");
		exit(1);
	}

	/* optional InitiatorAlias */
	daemon_config.initiator_alias =
	    get_iscsi_initiatoralias(daemon_config.initiator_name_file);
	if (!daemon_config.initiator_alias) {
		memset(&host_info, 0, sizeof (host_info));
		if (uname(&host_info) >= 0) {
			daemon_config.initiator_alias = 
				strdup(host_info.nodename);
		}
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
	if (oom_adjust())
		log_debug(1, "can not adjust oom-killer's pardon");

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
	event_loop(ipc, control_fd, mgmt_ipc_fd, &mgmt_ipc_db);

	/* we're done */
	log_debug(1, "daemon stopping");

	return 0;
}
