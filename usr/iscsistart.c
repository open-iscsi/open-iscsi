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
#include "event_poll.h"
#include "transport.h"
#include "log.h"
#include "iscsi_util.h"
#include "idbm.h"
#include "idbm_fields.h"
#include "version.h"
#include "iscsi_sysfs.h"
#include "iscsi_settings.h"
#include "fw_context.h"
#include "iface.h"
#include "sysdeps.h"
#include "iscsid_req.h"
#include "iscsi_err.h"
#include "iface.h"

/* global config info */
/* initiator needs initiator name/alias */
struct iscsi_daemon_config daemon_config;
struct iscsi_daemon_config *dconfig = &daemon_config;

static node_rec_t config_rec;
static LIST_HEAD(targets);
static LIST_HEAD(user_params);

static char program_name[] = "iscsistart";

/* used by initiator */
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
	{"debug", required_argument, NULL, 'd'},
	{"fwparam_connect", no_argument, NULL, 'b'},
	{"fwparam_network", no_argument, NULL, 'N'},
	{"fwparam_print", no_argument, NULL, 'f'},
	{"param", required_argument, NULL, 'P'},
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
  -W, --password_in=N      set incoming password to N (optional)\n\
  -d, --debug=debuglevel   print debugging information \n\
  -b, --fwparam_connect    create a session to the target using iBFT or OF\n\
  -N, --fwparam_network    bring up the network as specified by iBFT or OF\n\
  -f, --fwparam_print      print the iBFT or OF info to STDOUT \n\
  -P, --param=NAME=VALUE   set parameter with the name NAME to VALUE\n\
  -h, --help               display this help and exit\n\
  -v, --version            display version and exit\n\
");
	}
	exit(status);
}

static int stop_event_loop(void)
{
	iscsiadm_req_t req;
	iscsiadm_rsp_t rsp;
	int rc;

	memset(&req, 0, sizeof(req));
	req.command = MGMT_IPC_IMMEDIATE_STOP;
	rc = iscsid_exec_req(&req, &rsp, 0);
	if (rc) {
		iscsi_err_print_msg(rc);
		log_error("Could not stop event_loop\n");
	}
	return rc;
}

static int apply_params(struct node_rec *rec)
{
	struct user_param *param;
	int rc;

	/* Must init this so we can check if user overrode them */
	rec->session.initial_login_retry_max = -1;
	rec->conn[0].timeo.noop_out_interval = -1;
	rec->conn[0].timeo.noop_out_timeout = -1;

	list_for_each_entry(param, &user_params, list) {
		/*
		 * user may not have passed in all params that were set by
		 * ibft/iscsi_boot, so clear out values that might conflict
		 * with user overrides
		 */
		if (!strcmp(param->name, IFACE_NETNAME)) {
			/* overriding netname so MAC will be for old netdev */
			memset(rec->iface.hwaddress, 0,
				sizeof(rec->iface.hwaddress));
		} else if (!strcmp(param->name, IFACE_HWADDR)) {
			/* overriding MAC so netdev will be for old MAC */
			memset(rec->iface.netdev, 0, sizeof(rec->iface.netdev));
		} else if (!strcmp(param->name, IFACE_TRANSPORTNAME)) {
			/*
			 * switching drivers so all old binding info is no
			 * longer valid. Old values were either for offload
			 * and we are switching to software or the reverse,
			 * or switching types of cards (bnx2i to cxgb3i).
			 */
			memset(&rec->iface, 0, sizeof(rec->iface));
			iface_setup_defaults(&rec->iface);
		}
	}

	rc = idbm_node_set_rec_from_param(&user_params, rec, 0);
	if (rc)
		return rc;

	/*
	 * For root boot we could not change this in older versions so
	 * if user did not override then use the defaults.
	 *
	 * Increase to account for boot using static setup.
	 */
	if (rec->session.initial_login_retry_max == -1)
		rec->session.initial_login_retry_max = 30;
	/* we used to not be able to answer so turn off */
	if (rec->conn[0].timeo.noop_out_interval == -1)
		rec->conn[0].timeo.noop_out_interval = 0;
	if (rec->conn[0].timeo.noop_out_timeout == -1)
		rec->conn[0].timeo.noop_out_timeout = 0;

	return 0;
}

static int parse_param(char *param_str)
{
	struct user_param *param;
	char *name, *value;

	name = param_str;

	value = strchr(param_str, '=');
	if (!value) {
		log_error("Invalid --param %s. Missing value.", param_str);
		return ISCSI_ERR_INVAL;
	}
	*value = '\0';

	value++;
	if (!strlen(value)) {
		log_error("Invalid --param %s. Missing value.", param_str);
		return ISCSI_ERR_INVAL;
	}

	param = idbm_alloc_user_param(name, value);
	if (!param) {
		log_error("Could not allocate memory for param.");
		return ISCSI_ERR_NOMEM;
	}

	list_add(&param->list, &user_params);
	return 0;
}

static int login_session(struct node_rec *rec)
{
	iscsiadm_req_t req;
	iscsiadm_rsp_t rsp;
	int rc, retries = 0;

	rc = apply_params(rec);
	if (rc)
		return rc;

	printf("%s: Logging into %s %s:%d,%d\n", program_name, rec->name,
		rec->conn[0].address, rec->conn[0].port,
		rec->tpgt);
	memset(&req, 0, sizeof(req));
	req.command = MGMT_IPC_SESSION_LOGIN;
	memcpy(&req.u.session.rec, rec, sizeof(*rec));

retry:
	rc = iscsid_exec_req(&req, &rsp, 0);
	/*
	 * handle race where iscsid proc is starting up while we are
	 * trying to connect.
	 */
	if (rc == ISCSI_ERR_ISCSID_NOTCONN && retries < 30) {
		retries++;
		sleep(1);
		goto retry;
	} else if (rc)
		iscsi_err_print_msg(rc);
	return rc;
}

static int setup_session(void)
{
	struct boot_context *context;
	int rc = 0, rc2 = 0;

	if (list_empty(&targets))
		return login_session(&config_rec);

	list_for_each_entry(context, &targets, list) {
		struct node_rec *rec;

		rec = idbm_create_rec_from_boot_context(context);
		if (!rec) {
			log_error("Could not allocate memory. Could "
				  "not start boot session to "
				  "%s,%s,%d", context->targetname,
				  context->target_ipaddr,
				  context->target_port);
			continue;
		}

		rc2 = login_session(rec);
		if (rc2)
			rc = rc2;
		free(rec);
	}
	fw_free_targets(&targets);
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
		return EINVAL;
	}

	if (config_rec.tpgt == PORTAL_GROUP_TAG_UNKNOWN) {
		log_error("Portal Group not set. Exiting %s\n", program_name);
		return EINVAL;
	}

	if (!strlen(config_rec.name)) {
		log_error("TargetName not set. Exiting %s\n", program_name);
		return EINVAL;
	}

	if (!strlen(config_rec.conn[0].address)) {
		log_error("IP Address not set. Exiting %s\n", program_name);
		return EINVAL;
	}

	return 0;
}

#define check_str_param_len(str, max_len, param)			\
do {									\
	if (strlen(str) > max_len) {					\
		printf("%s: invalid %s %s. Max %s length is %d.\n",	\
			program_name, param, str, param, max_len);	\
		exit(ISCSI_ERR_INVAL);					\
	}								\
} while (0);

int main(int argc, char *argv[])
{
	struct utsname host_info; /* will use to compound initiator alias */
	struct iscsi_auth_config *auth;
	char *initiatorname = NULL;
	int ch, longindex, ret;
	struct boot_context *context, boot_context;
	struct sigaction sa_old;
	struct sigaction sa_new;
	int control_fd, mgmt_ipc_fd, err;
	pid_t pid;

	idbm_node_setup_defaults(&config_rec);
	config_rec.name[0] = '\0';
	config_rec.conn[0].address[0] = '\0';
	auth = &config_rec.session.auth;

	/* do not allow ctrl-c for now... */
	sa_new.sa_handler = catch_signal;
	sigemptyset(&sa_new.sa_mask);
	sa_new.sa_flags = 0;
	sigaction(SIGINT, &sa_new, &sa_old );

	/* initialize logger */
	log_init(program_name, DEFAULT_AREA_SIZE, log_do_log_std, NULL);

	sysfs_init();

	while ((ch = getopt_long(argc, argv, "P:i:t:g:a:p:d:u:w:U:W:bNfvh",
				 long_options, &longindex)) >= 0) {
		switch (ch) {
		case 'i':
			initiatorname = optarg;
			break;
		case 't':
			check_str_param_len(optarg, TARGET_NAME_MAXLEN,
					    "targetname");
			strlcpy(config_rec.name, optarg, TARGET_NAME_MAXLEN);
			break;
		case 'g':
			config_rec.tpgt = atoi(optarg);
			break;
		case 'a':
			check_str_param_len(optarg, NI_MAXHOST, "address");
			strlcpy(config_rec.conn[0].address, optarg, NI_MAXHOST);
			break;
		case 'p':
			config_rec.conn[0].port = atoi(optarg);
			break;
		case 'w':
			check_str_param_len(optarg, AUTH_STR_MAX_LEN,
					   "password");
			strlcpy((char *)auth->password, optarg,
				AUTH_STR_MAX_LEN);
			auth->password_length = strlen((char *)auth->password);
			break;
		case 'W':
			check_str_param_len(optarg, AUTH_STR_MAX_LEN,
					   "password_in");
			strlcpy((char *)auth->password_in, optarg,
				AUTH_STR_MAX_LEN);
			auth->password_in_length =
				strlen((char *)auth->password_in);
			break;
		case 'u':
			check_str_param_len(optarg, AUTH_STR_MAX_LEN,
					    "username");
			strlcpy(auth->username, optarg, AUTH_STR_MAX_LEN);
			break;
		case 'U':
			check_str_param_len(optarg, AUTH_STR_MAX_LEN,
					    "username_in");
			strlcpy(auth->username_in, optarg, AUTH_STR_MAX_LEN);
			break;
		case 'd':
			log_level = atoi(optarg);
			break;
		case 'b':
			memset(&boot_context, 0, sizeof(boot_context));
			ret = fw_get_entry(&boot_context);
			if (ret) {
				printf("Could not get boot entry.\n");
				exit(ret);
			}

			initiatorname = boot_context.initiatorname;
			ret = fw_get_targets(&targets);
			if (ret || list_empty(&targets)) {
				printf("Could not setup fw entries.\n");
				exit(ret);
			}
			break;
		case 'N':
			exit(fw_setup_nics());
		case 'f':
			ret = fw_get_targets(&targets);
			if (ret || list_empty(&targets)) {
				printf("Could not get list of targets from "
				       "firmware.\n");
				exit(ret);
			}

			list_for_each_entry(context, &targets, list)
				fw_print_entry(context);

			fw_free_targets(&targets);
			exit(0);
		case 'P':
			err = parse_param(optarg);
			if (err)
				exit(err);
			break;
		case 'v':
			printf("%s version %s\n", program_name,
				ISCSI_VERSION_STR);
			exit(0);
		case 'h':
			usage(0);
			break;
		default:
			usage(ISCSI_ERR_INVAL);
			break;
		}
	}

	if (list_empty(&targets) && check_params(initiatorname))
		exit(ISCSI_ERR_INVAL);

	pid = fork();
	if (pid < 0) {
		log_error("iscsiboot fork failed");
		exit(ISCSI_ERR_NOMEM);
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
			exit(ISCSI_ERR);

		log_debug(1, "iscsi parent done");
		exit(0);
	}

	mgmt_ipc_fd = mgmt_ipc_listen();
	if (mgmt_ipc_fd  < 0) {
		log_error("Could not setup mgmt ipc\n");
		exit(ISCSI_ERR_NOMEM);
	}

	control_fd = ipc->ctldev_open();
	if (control_fd < 0)
		exit(ISCSI_ERR_NOMEM);

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

	/*
	 * Start Main Event Loop
	 */
	iscsi_initiator_init();
	actor_init();
	event_loop(ipc, control_fd, mgmt_ipc_fd);
	ipc->ctldev_close();
	mgmt_ipc_close(mgmt_ipc_fd);
	free_initiator();
	sysfs_cleanup();

	log_debug(1, "iscsi child done");
	return 0;
}
