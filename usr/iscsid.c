/*
 * iSCSI Initiator Daemon
 *
 * Copyright (C) 2004 Dmitry Yusupov, Alex Aizman
 * Copyright (C) 2006 Mike Christie
 * Copyright (C) 2006 Red Hat, Inc. All rights reserved.

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
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
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
#include "transport.h"
#include "idbm.h"
#include "version.h"
#include "iscsi_sysfs.h"
#include "iscsi_settings.h"

/* global config info */
struct iscsi_daemon_config daemon_config;
struct iscsi_daemon_config *dconfig = &daemon_config;

static char program_name[] = "iscsid";
int control_fd, mgmt_ipc_fd;
static pid_t log_pid;

extern char sysfs_file[];

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

static void
setup_rec_from_negotiated_values(idbm_t *db, node_rec_t *rec,
				struct session_info *info)
{
	struct iscsi_session_operational_config session_conf;
	struct iscsi_conn_operational_config conn_conf;
	struct iscsi_auth_config auth_conf;

	idbm_node_setup_from_conf(db, rec);
	strncpy(rec->name, info->targetname, TARGET_NAME_MAXLEN);
	rec->conn[0].port = info->persistent_port;
	strncpy(rec->conn[0].address, info->persistent_address, NI_MAXHOST);
	memcpy(&rec->iface, &info->iface, sizeof(struct iface_rec));
	rec->tpgt = info->tpgt;
	iface_copy(&rec->iface, &info->iface);

	get_negotiated_session_conf(info->sid, &session_conf);
	get_negotiated_conn_conf(info->sid, &conn_conf);
	get_auth_conf(info->sid, &auth_conf);

	if (strlen(auth_conf.username))
		strcpy(rec->session.auth.username, auth_conf.username);

	if (strlen(auth_conf.username_in))
		strcpy(rec->session.auth.username_in, auth_conf.username_in);

	if (strlen((char *)auth_conf.password)) {
		strcpy((char *)rec->session.auth.password,
			(char *)auth_conf.password);
		rec->session.auth.password_length = auth_conf.password_length;
	}

	if (strlen((char *)auth_conf.password_in)) {
		strcpy((char *)rec->session.auth.password_in,
			(char *)auth_conf.password_in);
		rec->session.auth.password_in_length =
						auth_conf.password_in_length;
	}

	if (is_valid_operational_value(conn_conf.HeaderDigest)) {
		if (conn_conf.HeaderDigest)
			rec->conn[0].iscsi.HeaderDigest =
						CONFIG_DIGEST_PREFER_ON;
		else
			rec->conn[0].iscsi.HeaderDigest =
						CONFIG_DIGEST_PREFER_OFF;
	}

	if (is_valid_operational_value(conn_conf.DataDigest)) {
		if (conn_conf.DataDigest)
			rec->conn[0].iscsi.DataDigest = CONFIG_DIGEST_PREFER_ON;
		else
			rec->conn[0].iscsi.DataDigest =
						CONFIG_DIGEST_PREFER_OFF;
	}

	if (is_valid_operational_value(conn_conf.MaxRecvDataSegmentLength))
		rec->conn[0].iscsi.MaxRecvDataSegmentLength =
					conn_conf.MaxRecvDataSegmentLength;

	if (is_valid_operational_value(conn_conf.MaxXmitDataSegmentLength))
		 rec->conn[0].iscsi.MaxXmitDataSegmentLength =
					conn_conf.MaxXmitDataSegmentLength;

	if (is_valid_operational_value(session_conf.FirstBurstLength))
		rec->session.iscsi.FirstBurstLength =
					session_conf.FirstBurstLength;

	if (is_valid_operational_value(session_conf.MaxBurstLength))
		rec->session.iscsi.MaxBurstLength =
					session_conf.MaxBurstLength;

	if (is_valid_operational_value(session_conf.ImmediateData)) {
		if (session_conf.ImmediateData)
			rec->session.iscsi.ImmediateData = 1;
		else
			rec->session.iscsi.ImmediateData = 0;
	}

	if (is_valid_operational_value(session_conf.InitialR2T)) {
		if (session_conf.InitialR2T)
			rec->session.iscsi.InitialR2T = 0;
		else
			rec->session.iscsi.InitialR2T = 1;
	}
}

static int sync_session(void *data, struct session_info *info)
{
	idbm_t *db = data;
	node_rec_t rec;
	iscsiadm_req_t req;
	iscsiadm_rsp_t rsp;
	struct iscsi_transport *t;

	log_debug(7, "sync session [%d][%s,%s.%d][%s]\n", info->sid,
		  info->targetname, info->persistent_address,
		  info->port, info->iface.hwaddress);

	t = get_transport_by_sid(info->sid);
	if (!t)
		return 0;

	/*
	 * Just rescan the device in case this is the first startup.
	 * (TODO: should do this async and check for state).
	 */
	if (t->caps & CAP_FW_DB) {
		uint32_t host_no;
		int err;

		host_no = get_host_no_from_sid(info->sid, &err);
		if (err) {
			log_error("Could not get host no from sid %u. Can not "
				  "sync session. Error %d", info->sid, err);
			return 0;
		}
		scan_host(host_no, 0);
		return 0;
	}

	memset(&rec, 0, sizeof(node_rec_t));
	iface_get_by_bind_info(db, &info->iface, &rec.iface);
	if (idbm_rec_read(db, &rec, info->targetname, info->tpgt,
			  info->persistent_address, info->persistent_port,
			  &rec.iface)) {
		log_warning("Could not read data from db. Using default and "
			    "currently negotiated values\n");
		setup_rec_from_negotiated_values(db, &rec, info);
	}

	memset(&req, 0, sizeof(req));
	req.command = MGMT_IPC_SESSION_SYNC;
	req.u.session.sid = info->sid;
	memcpy(&req.u.session.rec, &rec, sizeof(node_rec_t));

	do_iscsid(&req, &rsp);
	return 0;
}

static void sync_sessions(void)
{
	idbm_t *db;
	int nr_found = 0;

	db = idbm_init(daemon_config.config_file);
	if (!db)
		return;
	sysfs_for_each_session(db, &nr_found, sync_session);
	idbm_terminate(db);
}

static void catch_signal(int signo)
{
	log_warning("caught signal -%d, ignoring...", signo);
}

static void iscsid_exit(void)
{
	log_debug(1, "iscsid_exit");
	if (daemon_config.initiator_name)
		free(daemon_config.initiator_name);
	if (daemon_config.initiator_alias)
		free(daemon_config.initiator_alias);
	free_initiator();
	mgmt_ipc_close(mgmt_ipc_fd);
	ipc->ctldev_close();
}

int main(int argc, char *argv[])
{
	struct utsname host_info; /* will use to compound initiator alias */
	char *config_file = CONFIG_FILE;
	char *initiatorname_file = INITIATOR_NAME_FILE;
	char *pid_file = PID_FILE;
	int ch, longindex;
	int isns_fd;
	uid_t uid = 0;
	gid_t gid = 0;
	struct sigaction sa_old;
	struct sigaction sa_new;
	pid_t pid;

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
		fprintf(stderr, "Error: initiatorname file %s doesn't exist.\n",
			initiatorname_file);
		fprintf(stderr, "Please create a file %s that contains\n",
			initiatorname_file);
		fprintf(stderr, "a sting with the format: InitiatorName="
			"iqn.yyyy-mm.<reversed domain name>[:identifier].\n");
		fprintf(stderr, "Example: InitiatorName=iqn.2001-04.com.redhat:"
			"fc6\n");
		usage(0);
	}

	/* initialize logger */
	log_pid = log_init(program_name, DEFAULT_AREA_SIZE);
	if (log_pid < 0)
		exit(1);
	check_class_version();

	umask(0177);

	mgmt_ipc_fd = -1;
	control_fd = -1;
	daemon_config.initiator_name = NULL;
	daemon_config.initiator_alias = NULL;
	if (atexit(iscsid_exit)) {
		log_error("failed to set exit function\n");
		exit(1);
	}

	if ((mgmt_ipc_fd = mgmt_ipc_listen()) < 0)
		exit(-1);

	if (log_daemon) {
		char buf[64];
		int fd;

		fd = open(pid_file, O_WRONLY|O_CREAT, 0644);
		if (fd < 0) {
			log_error("Unable to create pid file");
			exit(1);
		}
		pid = fork();
		if (pid < 0) {
			log_error("Starting daemon failed");
			exit(1);
		} else if (pid) {
			log_error("iSCSI daemon with pid=%d started!", pid);
			exit(0);
		}

		if ((control_fd = ipc->ctldev_open()) < 0)
			exit(-1);

		chdir("/");
		if (lockf(fd, F_TLOCK, 0) < 0) {
			log_error("Unable to lock pid file");
			exit(1);
		}
		ftruncate(fd, 0);
		sprintf(buf, "%d\n", getpid());
		write(fd, buf, strlen(buf));

		daemon_init();
	} else {
		if ((control_fd = ipc->ctldev_open()) < 0)
			exit(-1);
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

	pid = fork();
	if (pid == 0) {
		/* child */
		sync_sessions();
		exit(0);
	} else if (pid < 0) {
		log_error("Fork failed error %d: existing sessions"
			  " will not be synced", errno);
	} else
		need_reap();

	/* oom-killer will not kill us at the night... */
	if (oom_adjust())
		log_debug(1, "can not adjust oom-killer's pardon");

	/* we don't want our active sessions to be paged out... */
	if (mlockall(MCL_CURRENT | MCL_FUTURE)) {
		log_error("failed to mlockall, exiting...");
		exit(1);
	}

	actor_init();
	isns_fd = isns_init();
	event_loop(ipc, control_fd, mgmt_ipc_fd, isns_fd);
	isns_exit();

	log_debug(1, "daemon stopping");
	return 0;
}
