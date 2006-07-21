/*
 * iSCSI Root Boot Program based on daemon code
 *
 * Copyright (C) 2004 Dmitry Yusupov, Alex Aizman
 * Copyright (C) 2006 Mike Christie
 * Copyright (C) 2006 Red Hat, Inc.  All rights reserved.
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
#include <sys/utsname.h>
#include <sys/signal.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "initiator.h"
#include "iscsi_ipc.h"
#include "transport.h"
#include "log.h"
#include "util.h"
#include "idbm.h"
#include "version.h"

/* global config info */
/* initiator needs initiator name/alias */
struct iscsi_daemon_config daemon_config;
struct iscsi_daemon_config *dconfig = &daemon_config;
/* iniitiaor and netlink need syncing transport purposes */
iscsi_provider_t *provider = NULL;
int num_providers = 0;

static node_rec_t config_rec;

static char program_name[] = "iscsistart";
static int ipc_fd;
static int mgmt_ipc_fd;

/* used by initiator */
int control_fd;
extern struct iscsi_ipc *ipc;

static struct option const long_options[] = {
	{"initiatorname", required_argument, NULL, 'i'},
	{"targetname", required_argument, NULL, 't'},
	{"tgpt", required_argument, NULL, 'g'},
	{"address", required_argument, NULL, 'a'},
	{"port", required_argument, NULL, 'p'},
	{"username", required_argument, NULL, 'u'},
	{"password", required_argument, NULL, 'w'},
	{"username_in", required_argument, NULL, 'U'},
	{"password_in", required_argument, NULL, 'W'},
	{"rec", required_argument, NULL, 'r'},
	{"debug", required_argument, NULL, 'd'},
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
Open-iSCSI initiator.\n\
  -i, --initiatorname=name set InitiatorName to name (Required)\n\
  -t, --targetname=name    set TargetName to name (Required)\n\
  -g, --tgpt=N             set target portal group tag to N (Required)\n\
  -a, --address=A.B.C.D    set IP addres to A.B.C.D (Required)\n\
  -p, --port=N             set port to N (Default 3260)\n\
  -u, --username=N         set username to N (optional)\n\
  -w, --password=N         set password to N (optional\n\
  -U, --username_in=N      set incoming username to N (optional)\n\
  -W, --password_in=N      set incoming password to N (optional\n\
  -r, --rec=N              set record id (iscsid DB recid) to N (Required)\n\
  -d, --debug debuglevel   print debugging information \n\
  -h, --help               display this help and exit\n\
  -v, --version            display version and exit\n\
");
	}
	exit(status == 0 ? 0 : -1);
}

static int db_node_read(idbm_t *db, int rec_id, node_rec_t *rec)
{
	memcpy(rec, &config_rec, sizeof(struct node_rec));
	return 0;
}

/*
 * we do not need the DB so we just return the single record
 */
static struct mgmt_ipc_db mgmt_ipc_db = {
	.node_read	= db_node_read,
};

static int stop_event_loop(void)
{
	iscsiadm_req_t req;
	iscsiadm_rsp_t rsp;
	int rc;

	memset(&req, 0, sizeof(req));
	req.command = MGMT_IPC_IMMEDIATE_STOP;
	rc = do_iscsid(&ipc_fd, &req, &rsp);
	if (rc > 0)
		iscsid_handle_error(rc);
	if (rc)
		log_error("Could not stop event_loop\n");

	return rc;
}

static int setup_session(void)
{
	iscsiadm_req_t req;
	iscsiadm_rsp_t rsp;
	int rc;

	memset(&req, 0, sizeof(req));
	req.command = MGMT_IPC_SESSION_LOGIN;
	req.u.session.rid = config_rec.id;
	rc = do_iscsid(&ipc_fd, &req, &rsp);
	if (rc > 0)
		iscsid_handle_error(rc);

	return rc;
}

static void catch_signal(int signo)
{
	log_warning("pid %d caught signal -%d", getpid(), signo);
}

static int check_params(char *initiatorname)
{
	if (!initiatorname) {
		log_error("InitiatorName not set. Exiting %s\n", program_name);
		return -EINVAL;
	}

	if (config_rec.tpgt == PORTAL_GROUP_TAG_UNKNOWN) {
		log_error("Portal Group not set. Exiting %s\n", program_name);
		return -EINVAL;
	}

	if (!strlen(config_rec.name)) {
		log_error("TargetName not set. Exiting %s\n", program_name);
		return -EINVAL;
	}
	
	if (!strlen(config_rec.conn[0].address)) {
		log_error("IP Address not set. Exiting %s\n", program_name);
		return -EINVAL;
	}

	return 0;
}

#define check_str_param_len(str, max_len, param)			\
do {									\
	if (strlen(str) > max_len) {					\
		printf("%s: invalid %s %s. Max %s length is %d.\n",	\
			program_name, param, str, param, max_len);	\
		exit(1);						\
	}								\
} while (0);

/* TODO fix leaks */
int main(int argc, char *argv[])
{
	struct utsname host_info; /* will use to compound initiator alias */
	struct iscsi_auth_config *auth;
	char *initiatorname = NULL;
	int ch, longindex;
	struct sigaction sa_old;
	struct sigaction sa_new;
	pid_t pid;
	char *end;

	idbm_node_setup_defaults(&config_rec);
	config_rec.name[0] = '\0';
	config_rec.conn[0].address[0] = '\0';
	auth = &config_rec.session.auth;

	/* do not allow ctrl-c for now... */
	sa_new.sa_handler = catch_signal;
	sigemptyset(&sa_new.sa_mask);
	sa_new.sa_flags = 0;
	sigaction(SIGINT, &sa_new, &sa_old );

	while ((ch = getopt_long(argc, argv, "i:t:g:a:p:r:d:u:w:U:W:vh",
				 long_options, &longindex)) >= 0) {
		switch (ch) {
		case 'i':
			initiatorname = optarg;
			break;
		case 't':
			check_str_param_len(optarg, TARGET_NAME_MAXLEN,
					    "targetname");
			strncpy(config_rec.name, optarg, TARGET_NAME_MAXLEN);
			break;
		case 'g':
			config_rec.tpgt = atoi(optarg);
			break;
		case 'a':
			check_str_param_len(optarg, NI_MAXHOST, "address");
			strncpy(config_rec.conn[0].address, optarg, NI_MAXHOST);
			break;
		case 'p':
			config_rec.conn[0].port = atoi(optarg);
			break;
		case 'w':
			check_str_param_len(optarg, AUTH_STR_MAX_LEN,
					   "password");
			strncpy((char *)auth->password, optarg,
				AUTH_STR_MAX_LEN);
			auth->password_length = strlen((char *)auth->password);
			break;
		case 'W':
			check_str_param_len(optarg, AUTH_STR_MAX_LEN,
					   "password_in");
			strncpy((char *)auth->password_in, optarg,
				AUTH_STR_MAX_LEN);
			auth->password_in_length =
				strlen((char *)auth->password_in);
			break;
		case 'u':
			check_str_param_len(optarg, AUTH_STR_MAX_LEN,
					    "username");
			strncpy(auth->username, optarg, AUTH_STR_MAX_LEN);
			break;
		case 'U':
			check_str_param_len(optarg, AUTH_STR_MAX_LEN,
					    "username_in");
			strncpy(auth->username_in, optarg, AUTH_STR_MAX_LEN);
			break;	
		case 'r':
			config_rec.id = strtoul(optarg, &end, 0);
			if (*end != '\0') {
				fprintf(stderr,
					"%s: invalid record number %s.\n",
					program_name, optarg);
				usage(1);
			}
			break;
		case 'd':
			log_level = atoi(optarg);
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
	log_daemon = 0;
	log_init(program_name, DEFAULT_AREA_SIZE);

	check_class_version();
	if (check_params(initiatorname))
		exit(1);

	pid = fork();
	if (pid < 0) {
		log_error("iscsiboot fork failed");
		exit(1);
	} else if (pid) {
		int status, rc, rc2;

		rc = setup_session();
		rc2 = stop_event_loop();
		/*
		 * something horrible happened. kill child and get
		 * out of here
		 */
		if (rc2)
			kill(pid, SIGTERM);

		waitpid(pid, &status, WUNTRACED);
		if (rc || rc2)
			exit(-1);

		log_debug(1, "iscsi parent done");
		exit(0);
	}

	mgmt_ipc_fd = mgmt_ipc_listen();
	if (mgmt_ipc_fd  < 0) {
		log_error("Could not setup mgmt ipc\n");
		exit(-1);
	}

	control_fd = ipc->ctldev_open();
	if (control_fd < 0)
		exit(-1);

	memset(&daemon_config, 0, sizeof (daemon_config));
	daemon_config.initiator_name = initiatorname;
	/* optional InitiatorAlias */
	memset(&host_info, 0, sizeof (host_info));
	if (uname(&host_info) >= 0)
		daemon_config.initiator_alias = host_info.nodename;

	log_debug(1, "InitiatorName=%s", daemon_config.initiator_name);
	log_debug(1, "InitiatorAlias=%s", daemon_config.initiator_alias);
	log_debug(1, "TargetName=%s", config_rec.name);
	log_debug(1, "TPGT=%d", config_rec.tpgt);
	log_debug(1, "IP Address=%s", config_rec.conn[0].address);
	log_debug(1, "recid=%x", config_rec.id);

	/* log the version, so that we can tell if the daemon and kernel module
	 * match based on what shows up in the syslog.  Tarballs releases
	 * always install both, but Linux distributors may put the kernel module
	 * in a different RPM from the daemon and utils, and users may try to
	 * mix and match in ways that don't work.
	 */
	log_error("version %s", ISCSI_VERSION_STR);

	/* oom-killer will not kill us at the night... */
	if (oom_adjust())
		log_debug(1, "can not adjust oom-killer's pardon");

	/* in case of transports/sessions/connections been active
	 * and we've been killed or crashed. update states.
	 */
	if (sync_transports()) {
		log_error("failed to get transport list, exiting...");
		exit(-1);
	}

	/*
	 * Start Main Event Loop
	 */
	actor_init();
	event_loop(ipc, control_fd, mgmt_ipc_fd, &mgmt_ipc_db);
	ipc->ctldev_close();
	mgmt_ipc_close(mgmt_ipc_fd);

	log_debug(1, "iscsi child done");
	return 0;
}
