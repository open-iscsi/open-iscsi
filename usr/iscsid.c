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
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "iscsid.h"
#include "mgmt_ipc.h"
#include "event_poll.h"
#include "iscsi_ipc.h"
#include "log.h"
#include "iscsi_util.h"
#include "initiator.h"
#include "transport.h"
#include "idbm.h"
#include "version.h"
#include "iscsi_sysfs.h"
#include "iface.h"
#include "session_info.h"
#include "sysdeps.h"
#include "discoveryd.h"
#include "iscsid_req.h"
#include "iscsi_err.h"

/* global config info */
struct iscsi_daemon_config daemon_config;
struct iscsi_daemon_config *dconfig = &daemon_config;

static char program_name[] = "iscsid";
static pid_t log_pid;
static gid_t gid;
static int daemonize = 1;
static int mgmt_ipc_fd;

static struct option const long_options[] = {
	{"config", required_argument, NULL, 'c'},
	{"initiatorname", required_argument, NULL, 'i'},
	{"foreground", no_argument, NULL, 'f'},
	{"debug", required_argument, NULL, 'd'},
	{"uid", required_argument, NULL, 'u'},
	{"gid", required_argument, NULL, 'g'},
	{"no-pid-file", no_argument, NULL, 'n'},
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
  -n, --no-pid-file       do not use a pid file\n\
  -p, --pid=pidfile       use pid file (default " PID_FILE ").\n\
  -h, --help              display this help and exit\n\
  -v, --version           display version and exit\n\
");
	}
	exit(status);
}

static void
setup_rec_from_negotiated_values(node_rec_t *rec, struct session_info *info)
{
	struct iscsi_session_operational_config session_conf;
	struct iscsi_conn_operational_config conn_conf;
	struct iscsi_auth_config auth_conf;

	idbm_node_setup_from_conf(rec);
	strlcpy(rec->name, info->targetname, TARGET_NAME_MAXLEN);
	rec->conn[0].port = info->persistent_port;
	strlcpy(rec->conn[0].address, info->persistent_address, NI_MAXHOST);
	memcpy(&rec->iface, &info->iface, sizeof(struct iface_rec));
	rec->tpgt = info->tpgt;
	iface_copy(&rec->iface, &info->iface);

	iscsi_sysfs_get_negotiated_session_conf(info->sid, &session_conf);
	iscsi_sysfs_get_negotiated_conn_conf(info->sid, &conn_conf);
	iscsi_sysfs_get_auth_conf(info->sid, &auth_conf);

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
	node_rec_t rec, sysfsrec;
	iscsiadm_req_t req;
	iscsiadm_rsp_t rsp;
	struct iscsi_transport *t;
	int rc, retries = 0;

	log_debug(7, "sync session [%d][%s,%s.%d][%s]\n", info->sid,
		  info->targetname, info->persistent_address,
		  info->port, info->iface.hwaddress);

	t = iscsi_sysfs_get_transport_by_sid(info->sid);
	if (!t)
		return 0;

	/*
	 * Just rescan the device in case this is the first startup.
	 * (TODO: should do this async and check for state).
	 */
	if (t->caps & CAP_FW_DB) {
		uint32_t host_no;
		int err;

		host_no = iscsi_sysfs_get_host_no_from_sid(info->sid, &err);
		if (err) {
			log_error("Could not get host no from sid %u. Can not "
				  "sync session: %s", info->sid,
				  iscsi_err_to_str(err));
			return 0;
		}
		iscsi_sysfs_scan_host(host_no, 0);
		return 0;
	}

	if (!iscsi_sysfs_session_user_created(info->sid))
		return 0;

	memset(&rec, 0, sizeof(node_rec_t));
	/*
	 * We might get the local ip address for software. We do not
	 * want to try and bind a session by ip though.
	 */
	if (!t->template->set_host_ip)
		memset(info->iface.ipaddress, 0, sizeof(info->iface.ipaddress));

	if (idbm_rec_read(&rec, info->targetname, info->tpgt,
			  info->persistent_address, info->persistent_port,
			  &info->iface)) {
		log_warning("Could not read data from db. Using default and "
			    "currently negotiated values\n");
		setup_rec_from_negotiated_values(&rec, info);
	} else {
		/*
		 * we have a valid record and iface so lets merge
		 * the values from them and sysfs to try and get
		 * the most uptodate values.
		 *
		 * Currenlty that means we will use the CHAP, target, portal
		 * and iface values from sysfs and use timer, queue depth,
		 * and segment length values from the record.
		 */
		memset(&sysfsrec, 0, sizeof(node_rec_t));
		setup_rec_from_negotiated_values(&sysfsrec, info);
		/*
		 * target, portal and iface name values have to be the same
		 * or we would not have found the record, so just copy
		 * CHAP and iface settings.
		 */
		memcpy(&rec.session.auth, &sysfsrec.session.auth,
		      sizeof(struct iscsi_auth_config));
		memcpy(&rec.iface, &info->iface, sizeof(rec.iface));
	}

	/* multiple drivers could be connected to the same portal */
	if (!iscsi_match_session(&rec, info))
		return -1;
	/*
	 * We use the initiator name from sysfs because
	 * the session could have come from our db or ibft or some other
	 * app.
	 */
	strcpy(rec.iface.iname, info->iface.iname);
	memset(&req, 0, sizeof(req));
	req.command = MGMT_IPC_SESSION_SYNC;
	req.u.session.sid = info->sid;
	memcpy(&req.u.session.rec, &rec, sizeof(node_rec_t));

retry:
	rc = iscsid_exec_req(&req, &rsp, 0);
	if (rc == ISCSI_ERR_ISCSID_NOTCONN && retries < 30) {
		retries++;
		sleep(1);
		goto retry;
	}
	return 0;
}

static char *iscsid_get_config_file(void)
{
	return daemon_config.config_file;
}

static void iscsid_shutdown(void)
{
	pid_t pid;

	killpg(gid, SIGTERM);
	while ((pid = waitpid(0, NULL, 0) > 0))
		log_debug(7, "cleaned up pid %d", pid);

	log_warning("iscsid shutting down.");
	if (daemonize && log_pid >= 0) {
		log_debug(1, "daemon stopping");
		log_close(log_pid);
	}
}

static void catch_signal(int signo)
{
	log_debug(1, "pid %d caught signal %d", getpid(), signo);

	/* In foreground mode, treat SIGINT like SIGTERM */
	if (!daemonize && signo == SIGINT)
		signo = SIGTERM;

	switch (signo) {
	case SIGTERM:
		iscsid_shutdown();
		exit(0);
		break;
	default:
		break;
	}
}

static void missing_iname_warn(char *initiatorname_file)
{
	log_error("Warning: InitiatorName file %s does not exist or does not "
		  "contain a properly formated InitiatorName. If using "
		  "software iscsi (iscsi_tcp or ib_iser) or partial offload "
		  "(bnx2i or cxgbi iscsi), you may not be able to log "
		  "into or discover targets. Please create a file %s that "
		  "contains a sting with the format: InitiatorName="
		  "iqn.yyyy-mm.<reversed domain name>[:identifier].\n\n"
		  "Example: InitiatorName=iqn.2001-04.com.redhat:fc6.\n"
		  "If using hardware iscsi like qla4xxx this message can be "
		  "ignored.\n", initiatorname_file, initiatorname_file);
}

int main(int argc, char *argv[])
{
	struct utsname host_info; /* will use to compound initiator alias */
	char *config_file = CONFIG_FILE;
	char *initiatorname_file = INITIATOR_NAME_FILE;
	char *pid_file = PID_FILE;
	int ch, longindex;
	uid_t uid = 0;
	struct sigaction sa_old;
	struct sigaction sa_new;
	int control_fd;
	pid_t pid;

	while ((ch = getopt_long(argc, argv, "c:i:fd:nu:g:p:vh", long_options,
				 &longindex)) >= 0) {
		switch (ch) {
		case 'c':
			config_file = optarg;
			break;
		case 'i':
			initiatorname_file = optarg;
			break;
		case 'f':
			daemonize = 0;
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
		case 'n':
			pid_file = NULL;
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

	/* initialize logger */
	log_pid = log_init(program_name, DEFAULT_AREA_SIZE,
		      daemonize ? log_do_log_daemon : log_do_log_std, NULL);
	if (log_pid < 0)
		exit(ISCSI_ERR);

	/* do not allow ctrl-c for now... */
	sa_new.sa_handler = catch_signal;
	sigemptyset(&sa_new.sa_mask);
	sa_new.sa_flags = 0;
	sigaction(SIGINT, &sa_new, &sa_old );
	sigaction(SIGPIPE, &sa_new, &sa_old );
	sigaction(SIGTERM, &sa_new, &sa_old );

	sysfs_init();
	if (idbm_init(iscsid_get_config_file)) {
		log_close(log_pid);
		exit(ISCSI_ERR);
	}

	umask(0177);

	mgmt_ipc_fd = -1;
	control_fd = -1;
	daemon_config.initiator_name = NULL;
	daemon_config.initiator_alias = NULL;

	if ((mgmt_ipc_fd = mgmt_ipc_listen()) < 0) {
		log_close(log_pid);
		exit(ISCSI_ERR);
	}

	if (daemonize) {
		char buf[64];
		int fd = -1;

		if (pid_file) {
			fd = open(pid_file, O_WRONLY|O_CREAT, 0644);
			if (fd < 0) {
				log_error("Unable to create pid file");
				log_close(log_pid);
				exit(ISCSI_ERR);
			}
		}
		pid = fork();
		if (pid < 0) {
			log_error("Starting daemon failed");
			log_close(log_pid);
			exit(ISCSI_ERR);
		} else if (pid) {
			log_error("iSCSI daemon with pid=%d started!", pid);
			exit(0);
		}

		if ((control_fd = ipc->ctldev_open()) < 0) {
			log_close(log_pid);
			exit(ISCSI_ERR);
		}

		if (chdir("/") < 0)
			log_debug(1, "Unable to chdir to /");
		if (fd > 0) {
			if (lockf(fd, F_TLOCK, 0) < 0) {
				log_error("Unable to lock pid file");
				log_close(log_pid);
				exit(ISCSI_ERR);
			}
			if (ftruncate(fd, 0) < 0) {
				log_error("Unable to truncate pid file");
				log_close(log_pid);
				exit(ISCSI_ERR);
			}
			sprintf(buf, "%d\n", getpid());
			if (write(fd, buf, strlen(buf)) < 0) {
				log_error("Unable to write pid file");
				log_close(log_pid);
				exit(ISCSI_ERR);
			}
		}

		daemon_init();
	} else {
		if ((control_fd = ipc->ctldev_open()) < 0) {
			log_close(log_pid);
			exit(1);
		}
	}

	if (uid && setuid(uid) < 0)
		perror("setuid\n");

	if (gid && setgid(gid) < 0)
		perror("setgid\n");

	memset(&daemon_config, 0, sizeof (daemon_config));
	daemon_config.pid_file = pid_file;
	daemon_config.config_file = config_file;
	daemon_config.initiator_name = cfg_get_string_param(initiatorname_file,
							    "InitiatorName");
	if (daemon_config.initiator_name == NULL)
		missing_iname_warn(initiatorname_file);

	/* optional InitiatorAlias */
	daemon_config.initiator_alias =
				cfg_get_string_param(initiatorname_file,
						     "InitiatorAlias");
	if (!daemon_config.initiator_alias) {
		memset(&host_info, 0, sizeof (host_info));
		if (uname(&host_info) >= 0) {
			daemon_config.initiator_alias =
				strdup(host_info.nodename);
		}
	}

	log_debug(1, "InitiatorName=%s", daemon_config.initiator_name ?
		 daemon_config.initiator_name : "NOT SET");
	log_debug(1, "InitiatorAlias=%s", daemon_config.initiator_alias);

	pid = fork();
	if (pid == 0) {
		int nr_found = 0;
		/* child */
		iscsi_sysfs_for_each_session(NULL, &nr_found, sync_session);
		exit(0);
	} else if (pid < 0) {
		log_error("Fork failed error %d: existing sessions"
			  " will not be synced", errno);
	} else
		reap_inc();

	iscsi_initiator_init();
	increase_max_files();
	discoveryd_start(daemon_config.initiator_name);

	/* oom-killer will not kill us at the night... */
	if (oom_adjust())
		log_debug(1, "can not adjust oom-killer's pardon");

	/* we don't want our active sessions to be paged out... */
	if (mlockall(MCL_CURRENT | MCL_FUTURE)) {
		log_error("failed to mlockall, exiting...");
		log_close(log_pid);
		exit(ISCSI_ERR);
	}

	actor_init();
	event_loop(ipc, control_fd, mgmt_ipc_fd);

	idbm_terminate();
	sysfs_cleanup();
	ipc->ctldev_close();
	mgmt_ipc_close(mgmt_ipc_fd);
	if (daemon_config.initiator_name)
		free(daemon_config.initiator_name);
	if (daemon_config.initiator_alias)
		free(daemon_config.initiator_alias);
	free_initiator();
	iscsid_shutdown();
	return 0;
}
