/*
 * iSCSI Administration Utility
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
#include <dirent.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <linux/types.h>
#include <linux/unistd.h>

#include "initiator.h"
#include "iscsiadm.h"
#include "log.h"
#include "mgmt_ipc.h"
#include "idbm.h"
#include "util.h"
#include "version.h"

struct iscsi_ipc *ipc = NULL; /* dummy */
static int ipc_fd = -1;
static char program_name[] = "iscsiadm";

char initiator_name[TARGET_NAME_MAXLEN];
char initiator_alias[TARGET_NAME_MAXLEN];
char config_file[TARGET_NAME_MAXLEN];

enum iscsiadm_mode {
	MODE_DISCOVERY,
	MODE_NODE,
	MODE_SESSION,
};

enum iscsiadm_op {
	OP_NEW,
	OP_DELETE,
	OP_UPDATE,
	OP_SHOW,
};

static struct option const long_options[] =
{
	{"mode", required_argument, NULL, 'm'},
	{"portal", required_argument, NULL, 'p'},
	{"targetname", required_argument, NULL, 'T'},
	{"op", required_argument, NULL, 'o'},
	{"type", required_argument, NULL, 't'},
	{"name", required_argument, NULL, 'n'},
	{"value", required_argument, NULL, 'v'},
	{"sid", required_argument, NULL, 'r'},
	{"login", no_argument, NULL, 'l'},
	{"logout", no_argument, NULL, 'u'},
	{"stats", no_argument, NULL, 's'},
	{"debug", required_argument, NULL, 'g'},
	{"map", required_argument, NULL, 'M'},
	{"show", no_argument, NULL, 'S'},
	{"version", no_argument, NULL, 'V'},
	{"help", no_argument, NULL, 'h'},
	{NULL, 0, NULL, 0},
};
static char *short_options = "lVhm:M:p:T:d:r:n:v:o:sSt:u";

static void usage(int status)
{
	if (status != 0)
		fprintf(stderr, "Try `%s --help' for more information.\n",
			program_name);
	else {
		printf("\
iscsiadm -m discovery [ -dhV ] [ -t type -p ip:port [ -l ] ] | [ -p ip:port ] \
[ -o operation ] [ -n name ] [ -v value ]\n\
iscsiadm -m node [ -dhV ] [ -S ] [ [ -T targetname -p ip:port | -M sysdir ] [ -l | -u ] ] \
[ [ -o  operation  ] [ -n name ] [ -v value ] [ -p ip:port ] ]\n\
iscsiadm -m session [ -dhV ] [ -r sessionid [ -u | -s ] ]\n");
	}
	exit(status == 0 ? 0 : -1);
}

static int
str_to_op(char *str)
{
	int op;

	if (!strcmp("new", str))
		op = OP_NEW;
	else if (!strcmp("delete", str))
		op = OP_DELETE;
	else if (!strcmp("update", str))
		op = OP_UPDATE;
	else if (!strcmp("show", str))
		op = OP_SHOW;
	else
		op = -1;

	return op;
}

static int
str_to_mode(char *str)
{
	int mode;

	if (!strcmp("discovery", str))
		mode = MODE_DISCOVERY;
	else if (!strcmp("node", str))
		mode = MODE_NODE;
	else if (!strcmp("session", str))
		mode = MODE_SESSION;
	else
		mode = -1;

	return mode;
}

static int
str_to_type(char *str)
{
	int type;

	if (!strcmp("sendtargets", str) ||
	    !strcmp("st", str))
		type = DISCOVERY_TYPE_SENDTARGETS;
	else if (!strcmp("slp", str))
		type = DISCOVERY_TYPE_SLP;
	else if (!strcmp("isns", str))
		type = DISCOVERY_TYPE_ISNS;
	else
		type = -1;

	return type;
}

static int
sys_to_rec(idbm_t *db, node_rec_t *rec, char *sysfs_device)
{
	char *targetname;
	char *address;
	int sid, rc, port, tpgt, len;
	struct stat statb;
	char sys_session[64], *start, *last;

	/*
	 * Given sysfs_device is a directory name of the form:
	 *
	 * /sys/devices/platform/hostH/sessionS/targetH:B:I/H:B:I:L
	 * /sys/devices/platform/hostH/sessionS/targetH:B:I
	 * /sys/devices/platform/hostH/sessionS
	 *
	 * We want to set sys_session to sessionS
	 */
	if (stat(sysfs_device, &statb)) {
		log_error("stat %s failed with %d", sysfs_device, errno);
		exit(1);
	}
	if (!S_ISDIR(statb.st_mode)) {
		log_error("%s is not a directory", sysfs_device);
		exit(1);
	}

	last = NULL;
	start = strstr(sysfs_device, "session");
	if (start && strncmp(start, "session", 7) == 0) {
		len = strlen(start);
		last = index(start, '/');
		/*
		 * If '/' not found last is NULL.
		 */
		if (last)
			len = last - start;
		strncpy(sys_session, start, len);
	} else {
		log_error("Unable to find session in %s", sysfs_device);
		exit(1);
	}

	targetname = malloc(TARGET_NAME_MAXLEN + 1);
	if (!targetname)
		return -ENOMEM;

	address = malloc(NI_MAXHOST + 1);
	if (!address) {
		rc = -ENOMEM;
		goto free_target;
	}

	log_debug(2, "%s: session %s", __FUNCTION__, sys_session);
	rc = find_sessioninfo_by_sid(&sid, targetname, address, &port, &tpgt,
				     sys_session);
	if (rc < 0) {
		log_error("Unable to find a record for iscsi %s (sys %s)",
			  sys_session, sysfs_device);
		goto free_address;
	}

	rc = idbm_node_read(db, rec, targetname, address, port);
	if (rc) {
		log_error("node [%s, %s, %d] not found!",
			  targetname, address, port);
		goto free_address;
	}

free_address:
	free(address);
free_target:
	free(targetname);
	return rc;
}

static int
session_login(node_rec_t *rec)
{
	iscsiadm_req_t req;
	iscsiadm_rsp_t rsp;

	memset(&req, 0, sizeof(iscsiadm_req_t));
	req.command = MGMT_IPC_SESSION_LOGIN;
	memcpy(&req.u.session.rec, rec, sizeof(node_rec_t));

	return do_iscsid(&ipc_fd, &req, &rsp);
}

static int
session_logout(node_rec_t *rec)
{
	iscsiadm_req_t req;
	iscsiadm_rsp_t rsp;

	memset(&req, 0, sizeof(req));
	req.command = MGMT_IPC_SESSION_LOGOUT;
	memcpy(&req.u.session.rec, rec, sizeof(node_rec_t));

	return do_iscsid(&ipc_fd, &req, &rsp);
}

static int
config_init(void)
{
	int rc;
	iscsiadm_req_t req;
	iscsiadm_rsp_t rsp;

	memset(&req, 0, sizeof(req));
	req.command = MGMT_IPC_CONFIG_INAME;

	rc = do_iscsid(&ipc_fd, &req, &rsp);
	if (rc)
		return rc;

	if (rsp.u.config.var[0] != '\0') {
		strcpy(initiator_name, rsp.u.config.var);
	}

	memset(&req, 0, sizeof(req));
	req.command = MGMT_IPC_CONFIG_IALIAS;

	rc = do_iscsid(&ipc_fd, &req, &rsp);
	if (rc)
		return rc;

	if (rsp.u.config.var[0] != '\0') {
		strcpy(initiator_alias, rsp.u.config.var);
	}

	memset(&req, 0, sizeof(req));
	req.command = MGMT_IPC_CONFIG_FILE;

	rc = do_iscsid(&ipc_fd, &req, &rsp);
	if (rc)
		return rc;

	if (rsp.u.config.var[0] != '\0') {
		strcpy(config_file, rsp.u.config.var);
	}

	return 0;
}

static int
session_activelist(idbm_t *db)
{
	DIR *dirfd;
	struct dirent *dent;
	int rc, i = 0, sid, port, tpgt;
	char *targetname, *address, *sysfs_file;

	targetname = malloc(TARGET_NAME_MAXLEN + 1);
	if (!targetname)
		return -ENOMEM;

	address = malloc(NI_MAXHOST + 1);
	if (!address) {
		rc = -ENOMEM;
		goto free_target;
	}

	sysfs_file = malloc(PATH_MAX);
	if (!sysfs_file) {
		rc = -ENOMEM;
		goto free_address;
	}

	sprintf(sysfs_file, "/sys/class/iscsi_session");
	dirfd = opendir(sysfs_file);
	if (!dirfd)
		return -EINVAL;

	/* display all active sessions */
	while ((dent = readdir(dirfd))) {
		if (!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, ".."))
			continue;

		rc = find_sessioninfo_by_sid(&sid, targetname, address, &port,
					     &tpgt, dent->d_name);
		if (rc < 0) {
			log_error("could not find session info for %s",
				   dent->d_name);
			continue;
		}

		printf("[%02d] %s:%d,%d %s\n",
		      sid, address, port, tpgt, targetname);
		i++;
	}
	rc = i;

	free(sysfs_file);
free_address:
	free(address);
free_target:
	free(targetname);
	return rc;
}

static int
session_stats(idbm_t *db, int sid)
{
	int rc, i;
	iscsiadm_req_t req;
	iscsiadm_rsp_t rsp;

	memset(&req, 0, sizeof(req));
	req.command = MGMT_IPC_SESSION_STATS;
	req.u.session.sid = sid;

	rc = do_iscsid(&ipc_fd, &req, &rsp);
	if (rc)
		return rc;

	printf("[%02d]\n", sid);
	printf( "iSCSI SNMP:\n"

		"\ttxdata_octets: %lld\n"
		"\trxdata_octets: %lld\n"

		"\tnoptx_pdus: %u\n"
		"\tscsicmd_pdus: %u\n"
		"\ttmfcmd_pdus: %u\n"
		"\tlogin_pdus: %u\n"
		"\ttext_pdus: %u\n"
		"\tdataout_pdus: %u\n"
		"\tlogout_pdus: %u\n"
		"\tsnack_pdus: %u\n"

		"\tnoprx_pdus: %u\n"
		"\tscsirsp_pdus: %u\n"
		"\ttmfrsp_pdus: %u\n"
		"\ttextrsp_pdus: %u\n"
		"\tdatain_pdus: %u\n"
		"\tlogoutrsp_pdus: %u\n"
		"\tr2t_pdus: %u\n"
		"\tasync_pdus: %u\n"
		"\trjt_pdus: %u\n"

		"\tdigest_err: %u\n"
		"\ttimeout_err: %u\n",
		(unsigned long long)rsp.u.getstats.stats.txdata_octets,
		(unsigned long long)rsp.u.getstats.stats.rxdata_octets,

		rsp.u.getstats.stats.noptx_pdus,
		rsp.u.getstats.stats.scsicmd_pdus,
		rsp.u.getstats.stats.tmfcmd_pdus,
		rsp.u.getstats.stats.login_pdus,
		rsp.u.getstats.stats.text_pdus,
		rsp.u.getstats.stats.dataout_pdus,
		rsp.u.getstats.stats.logout_pdus,
		rsp.u.getstats.stats.snack_pdus,

		rsp.u.getstats.stats.noprx_pdus,
		rsp.u.getstats.stats.scsirsp_pdus,
		rsp.u.getstats.stats.tmfrsp_pdus,
		rsp.u.getstats.stats.textrsp_pdus,
		rsp.u.getstats.stats.datain_pdus,
		rsp.u.getstats.stats.logoutrsp_pdus,
		rsp.u.getstats.stats.r2t_pdus,
		rsp.u.getstats.stats.async_pdus,
		rsp.u.getstats.stats.rjt_pdus,

		rsp.u.getstats.stats.digest_err,
		rsp.u.getstats.stats.timeout_err);

	if (rsp.u.getstats.stats.custom_length)
		printf( "iSCSI Extended:\n");

	for (i = 0; i < rsp.u.getstats.stats.custom_length; i++) {
		printf("\t%s: %llu\n", rsp.u.getstats.stats.custom[i].desc,
		      (unsigned long long)rsp.u.getstats.stats.custom[i].value);
	}

	return 0;
}

/*
 * start sendtargets discovery process based on the
 * particular config
 */
static int
do_sendtargets(idbm_t *db, struct iscsi_sendtargets_config *cfg)
{
	int rc;
	struct string_buffer info;

	init_string_buffer(&info, 8 * 1024);
	rc =  sendtargets_discovery(cfg, &info);
	if (!rc) {
		discovery_rec_t *drec;
		if ((drec = idbm_new_discovery(db, cfg->address, cfg->port,
		    DISCOVERY_TYPE_SENDTARGETS, info.buffer))) {
			idbm_print_nodes(db);
			free(drec);
		}
	}
	truncate_buffer(&info, 0);
	return rc;
}

static int
verify_mode_params(int argc, char **argv, char *allowed, int skip_m)
{
	int ch, longindex;
	int ret = 0;

	optind = 0;

	while ((ch = getopt_long(argc, argv, short_options,
				 long_options, &longindex)) >= 0) {
		if (!strchr(allowed, ch)) {
			if (ch == 'm' && skip_m)
				continue;
			ret = ch;
			break;
		}
	}

	return ret;
}

static void catch_sigint( int signo ) {
	log_warning("caught SIGINT, exiting...");
	if (ipc_fd > 0)
		close(ipc_fd);
	exit(1);
}

int
main(int argc, char **argv)
{
	char *ip = NULL, *name = NULL, *value = NULL, *sysfs_device = NULL;
	char *targetname = NULL;
	int ch, longindex, mode=-1, port=-1, do_login=0;
	int rc=0, sid=-1, op=-1, type=-1, do_logout=0, do_stats=0, do_show=0;
	idbm_t *db;
	struct sigaction sa_old;
	struct sigaction sa_new;

	/* do not allow ctrl-c for now... */
	sa_new.sa_handler = catch_sigint;
	sigemptyset(&sa_new.sa_mask);
	sa_new.sa_flags = 0;
	sigaction(SIGINT, &sa_new, &sa_old );

	umask(0177);

	/* enable stdout logging */
	log_daemon = 0;
	log_init(program_name, 1024);

	config_init();
	if (initiator_name[0] == '\0') {
		log_warning("exiting due to configuration error");
		return -1;
	}

	optopt = 0;
	while ((ch = getopt_long(argc, argv, short_options,
				 long_options, &longindex)) >= 0) {
		switch (ch) {
		case 't':
			type = str_to_type(optarg);
			break;
		case 'o':
			op = str_to_op(optarg);
			if (op < 0) {
				log_error("can not recognize operation: '%s'",
					optarg);
				return -1;
			}
			break;
		case 'n':
			name = optarg;
			break;
		case 'v':
			value = optarg;
			break;
		case 'r':
			sid = atoi(optarg);
			if (sid < 0) {
				log_error("invalid sid '%s'",
					  optarg);
				return -1;
			}
			break;
		case 'l':
			do_login = 1;
			break;
		case 'u':
			do_logout = 1;
			break;
		case 's':
			do_stats = 1;
			break;
		case 'S':
			do_show = 1;
			break;
		case 'd':
			log_level = atoi(optarg);
			break;
		case 'm':
			mode = str_to_mode(optarg);
			break;
		case 'M':
			sysfs_device = optarg;
			break;
		case 'T':
			targetname = optarg;
			break;
		case 'p':
			ip = str_to_ipport(optarg, &port, ':');
			break;
		case 'V':
			printf("%s version %s\n", program_name,
				ISCSI_VERSION_STR);
			return 0;
		case 'h':
			usage(0);
		}
	}

	if (optopt) {
		log_error("unrecognized character '%c'", optopt);
		return -1;
	}

	if (mode < 0) 
		usage(0);

	db = idbm_init(config_file);
	if (!db) {
		log_warning("exiting due to idbm configuration error");
		return -1;
	}

	if (mode == MODE_DISCOVERY) {
		if ((rc = verify_mode_params(argc, argv, "dmtplo", 0))) {
			log_error("discovery mode: option '-%c' is not "
				  "allowed/supported", rc);
			rc = -1;
			goto out;
		}
		if (type == DISCOVERY_TYPE_SENDTARGETS) {
			struct iscsi_sendtargets_config cfg;

			if (ip == NULL || port < 0) {
				log_error("please specify right portal as "
					  "<ipaddr>[:<ipport>]");
				rc = -1;
				goto out;
			}

			idbm_sendtargets_defaults(db, &cfg);
			strncpy(cfg.address, ip, sizeof(cfg.address));

			cfg.port = port;
			if (!do_sendtargets(db, &cfg) && do_login) {
				log_error("automatic login after discovery "
					  "is not fully implemented yet.");
				rc = -1;
				goto out;
			}
			goto out;
		} else if (type == DISCOVERY_TYPE_SLP) {
			log_error("SLP discovery is not fully "
				  "implemented yet.");
			rc = -1;
			goto out;
		} else if (type == DISCOVERY_TYPE_ISNS) {
			log_error("iSNS discovery is not fully "
				  "implemented yet.");
			rc = -1;
			goto out;
		} else if (type < 0) {
			if (ip) {
				discovery_rec_t rec;

				if (idbm_discovery_read(db, &rec, ip, port)) {
					log_error("discovery record [%s,%d] "
						  "not found!", ip, port);
					rc = -1;
					goto out;
				}
				if (do_login &&
				    rec.type == DISCOVERY_TYPE_SENDTARGETS) {
					do_sendtargets(db, &rec.u.sendtargets);
				} else if (do_login &&
					   rec.type == DISCOVERY_TYPE_SLP) {
					log_error("SLP discovery is not fully "
						  "implemented yet.");
					rc = -1;
					goto out;
				} else if (do_login &&
					   rec.type == DISCOVERY_TYPE_ISNS) {
					log_error("iSNS discovery is not fully "
						  "implemented yet.");
					rc = -1;
					goto out;
				} else if (op < 0 || op == OP_SHOW) {
					if (!idbm_print_discovery(db, &rec,
								  do_show)) {
						log_error("no records found!");
						rc = -1;
					}
				} else if (op == OP_DELETE) {
					if (idbm_delete_discovery(db, &rec)) {
						log_error("unable to delete "
							   "record!");
						rc = -1;
					}
				} else {
					log_error("operation is not supported.");
					rc = -1;
					goto out;
				}

			} else if (op < 0 || op == OP_SHOW) {
				if (!idbm_print_all_discovery(db)) {
					log_error("no records found!");
					rc = -1;
				}
				goto out;
			} else if (op == OP_DELETE) {
				log_error("--record required for delete operation");
				rc = -1;
				goto out;
			} else {
				log_error("Operations: new and "
					  "update for node is not fully "
					  "implemented yet.");
				rc = -1;
				goto out;
			}
		}
	} else if (mode == MODE_NODE) {
		node_rec_t rec;

		memset(&rec, 0, sizeof(node_rec_t));
		if ((rc = verify_mode_params(argc, argv, "dmMlSonvupT", 0))) {
			log_error("node mode: option '-%c' is not "
				  "allowed/supported", rc);
			rc = -1;
			goto out;
		}
		if (sysfs_device) {
			if (targetname && ip) {
				log_error("only one of map and "
					  "targetname,portal may be specified");
				rc = -1;
				goto out;
			}
			if (sys_to_rec(db, &rec, sysfs_device)) {
				rc = -1;
				goto out;
			}
			/* bleh */
			goto found_node_rec;
		}

		if (targetname && ip && op != OP_NEW) {
			log_debug(2, "%s: node [%s,%s,%d]", __FUNCTION__,
				  targetname, ip, port);
			if (idbm_node_read(db, &rec, targetname, ip, port)) {
				log_error("node [%s, %s, %d] not found!",
					  targetname, ip, port);
				rc = -1;
				goto out;
			}

found_node_rec:
			if (do_login && do_logout) {
				log_error("either login or "
					  "logout at the time allowed!");
				rc = -1;
				goto out;
			}
			if ((do_login || do_logout) && op >= 0) {
				log_error("either operation or login/logout "
					  "at the time allowed!");
				rc = -1;
				goto out;
			}
			if (!do_login && !do_logout && op < 0) {
				if (!idbm_print_node(db, &rec, do_show)) {
					log_error("no records found!");
					rc = -1;
				}
				goto out;
			}
			if (do_login) {
				if ((rc = session_login(&rec)) > 0) {
					iscsid_handle_error(rc);
					rc = -1;
				}
				goto out;
			}
			if (do_logout) {
				if ((rc = session_logout(&rec)) > 0) {
					iscsid_handle_error(rc);
					rc = -1;
				}
				goto out;
			}
			if (op == OP_UPDATE) {
				if (!name || !value) {
					log_error("update require name and "
						  "value");
					rc = -1;
					goto out;
				}
				if ((rc = idbm_node_set_param(db, &rec,
					      name, value))) {
					log_error("can not set parameter");
					goto out;
				}
			} else if (op == OP_DELETE) {
				if (idbm_delete_node(db, &rec)) {
					log_error("can not delete record");
					rc = -1;
					goto out;
				}
			} else {
				log_error("operation is not supported.");
				rc = -1;
				goto out;
			}
		} else if (op < 0 || op == OP_SHOW) {
			if (!idbm_print_nodes(db)) {
				log_error("no records found!");
				rc = -1;
				goto out;
			}
		} else if (op == OP_NEW) {
			if (!ip || !targetname) {
				log_error("portal and target required for new "
					  "node record");
				rc = -1;
				goto out;
			}
			idbm_node_setup_defaults(&rec);
			strncpy(rec.name, targetname, TARGET_NAME_MAXLEN);
			rec.conn[0].port = port;
			strncpy(rec.conn[0].address, ip, NI_MAXHOST);
			if (idbm_new_node(db, &rec)) {
				log_error("can not add new record.");
				rc = -1;
				goto out;
			}
			printf("new iSCSI node record added\n");
		} else if (op == OP_DELETE) {
			log_error("--record required for delete operation");
			rc = -1;
			goto out;
		} else {
			log_error("operation is not supported.");
			rc = -1;
			goto out;
		}
	} else if (mode == MODE_SESSION) {
		if ((rc = verify_mode_params(argc, argv, "drmus", 1))) {
			log_error("session mode: option '-%c' is not "
				  "allowed or supported", rc);
			rc = -1;
			goto out;
		}
		if (sid >= 0) {
			if (do_logout && do_stats) {
				log_error("--logout or --stats? what exactly?");
				rc = -1;
				goto out;
			}
			if (do_logout) {
				log_error("operation is not implemented yet.");
				rc = -1;
				goto out;
			}
			if (do_stats) {
				if ((rc = session_stats(db, sid)) > 0) {
					iscsid_handle_error(rc);
					log_error("can not get statistics for "
						"session with SID %d (%d)",
						sid, rc);
					rc = -1;
					goto out;
				}
			}
		} else {
			if (do_logout) {
				log_error("--logout requires target id");
				rc = -1;
				goto out;
			}
			if (do_stats) {
				log_error("--stats requires target id");
				rc = -1;
				goto out;
			}
			if ((rc = session_activelist(db)) < 0) {
				log_error("can not get list of active "
					"sessions (%d)", rc);
				rc = -1;
				goto out;
			} else if (!rc) {
				printf("no active sessions\n");
			}
		}
	} else {
		log_error("This mode is not yet supported");
	}

out:
	idbm_terminate(db);
	return rc;
}
