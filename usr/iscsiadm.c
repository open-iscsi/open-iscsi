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
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

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
	MODE_DB,
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
	{"op", required_argument, NULL, 'o'},
	{"type", required_argument, NULL, 't'},
	{"name", required_argument, NULL, 'n'},
	{"value", required_argument, NULL, 'v'},
	{"record", required_argument, NULL, 'r'},
	{"login", no_argument, NULL, 'l'},
	{"logout", no_argument, NULL, 'u'},
	{"stats", no_argument, NULL, 's'},
	{"debug", required_argument, NULL, 'g'},
	{"map", required_argument, NULL, 'M'},
	{"show", no_argument, NULL, 'S'},
	{"remove", no_argument, NULL, 'R'},
	{"version", no_argument, NULL, 'V'},
	{"help", no_argument, NULL, 'h'},
	{NULL, 0, NULL, 0},
};
static char *short_options = "lVhm:M:p:d:r:n:v:o:sSt:uR";

static void usage(int status)
{
	if (status != 0)
		fprintf(stderr, "Try `%s --help' for more information.\n",
			program_name);
	else {
		printf("\
iscsiadm -m discovery [ -dhV ] [ -t type -p ip [ -l ] ] | [ -r recid ] \
[ -o operation ] [ -n name ] [ -v value ]\n\
iscsiadm -m node [ -dhV ] [ -S ] [ [ -r recid | -M sysdir ] [ -l | -u ] ] \
[ [ -o  operation  ] [ -n name ] [ -v value ] [ -p ip ] ]\n\
iscsiadm -m session [ -dhV ] [ -r [sid:]recid [ -u | -s ] ]\n");
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
	else if (!strcmp("db", str))
		mode = MODE_DB;
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

static char*
str_to_ipport(char *str, int *port)
{
	char *sport = str;

	if (!strchr(str, '.')) {
		if (*str == '[') {
			if (!(sport = strchr(str, ']')))
				return NULL;
			*sport++ = '\0';
			str++;
		} else
			sport = NULL;
	}

	if (sport && (sport = strchr(sport, ':'))) {
		*sport = '\0';
		sport++;
		*port = strtoul(sport, NULL, 10);
	} else
		*port = DEF_ISCSI_PORT;

	return str;
}

static int
str_to_ridsid(char *str, int *sid)
{
	char *ptr, *eptr;
	int rid;

	if ((ptr = strchr(str, ':'))) {
		*ptr = '\0';
		ptr++;
		*sid = strtoul(str, &eptr, 10);
		if (eptr == str)
			*sid = -1;
	} else {
		*sid = -1;
		ptr = str;
	}

	rid = strtoul(ptr, &eptr, 16);
	if (eptr == ptr)
		rid = -1;
	return rid;
}

static int
sys_to_rid(idbm_t *db, char *sysfs_device)
{
	int sid, rec_id;
	int rc;
	int len;
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

	log_debug(2, "%s: session %s", __FUNCTION__, sys_session);
	rc = idbm_find_ids_by_session(db, &sid, &rec_id, sys_session);
	if (rc < 0) {
		log_error("Unable to find a record for iscsi %s (sys %s)",
			  sys_session, sysfs_device);
		return rc;
	}
	return rec_id;
}

static int
session_login(int rid, node_rec_t *rec)
{
	iscsiadm_req_t req;
	iscsiadm_rsp_t rsp;

	memset(&req, 0, sizeof(req));
	req.command = MGMT_IPC_SESSION_LOGIN;
	req.u.session.rid = rid;

	return do_iscsid(&ipc_fd, &req, &rsp);
}

static int
session_logout(int rid, node_rec_t *rec)
{
	iscsiadm_req_t req;
	iscsiadm_rsp_t rsp;

	memset(&req, 0, sizeof(req));
	req.command = MGMT_IPC_SESSION_LOGOUT;
	req.u.session.rid = rid;

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
	int rc, i;
	iscsiadm_req_t req;
	iscsiadm_rsp_t rsp;

	memset(&req, 0, sizeof(req));
	req.command = MGMT_IPC_SESSION_ACTIVELIST;

	rc = do_iscsid(&ipc_fd, &req, &rsp);
	if (rc)
		return rc;
	/* display all active sessions */
	for (i = 0; i < rsp.u.activelist.cnt; i++) {
		node_rec_t rec;

		if (idbm_node_read(db, rsp.u.activelist.rids[i], &rec)) {
			log_error("no record [%06x] found!",
				  rsp.u.activelist.rids[i]);
			return -1;
		}
		printf("[%02d:%06x] %s:%d,%d %s\n",
			rsp.u.activelist.sids[i], rec.id, rec.conn[0].address,
			rec.conn[0].port, rec.tpgt, rec.name);
	}

	return i;
}

static int
session_stats(idbm_t *db, int rid, int sid)
{
	int rc, i;
	iscsiadm_req_t req;
	iscsiadm_rsp_t rsp;
	node_rec_t rec;

	if (idbm_node_read(db, rid, &rec)) {
		log_error("no record [%06x] found!", rid);
		return -1;
	}

	memset(&req, 0, sizeof(req));
	req.command = MGMT_IPC_SESSION_STATS;
	req.u.session.rid = rid;
	req.u.session.sid = sid;

	rc = do_iscsid(&ipc_fd, &req, &rsp);
	if (rc)
		return rc;

	printf("[%02d:%06x] %s:%d,%d %s\n",
		sid, rid, rec.conn[0].address, rec.conn[0].port,
		rec.tpgt, rec.name);
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
			idbm_print_nodes(db, drec);
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
	int ch, longindex, mode=-1, port=-1, do_login=0;
	int rc=0, rid=-1, sid=-1, op=-1, type=-1, do_logout=0, do_stats=0;
	int do_show=0, do_remove=0;
	idbm_t *db;
	struct sigaction sa_old;
	struct sigaction sa_new;

	/* do not allow ctrl-c for now... */
	sa_new.sa_handler = catch_sigint;
	sigemptyset(&sa_new.sa_mask);
	sa_new.sa_flags = 0;
	sigaction(SIGINT, &sa_new, &sa_old );

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
			rid = str_to_ridsid(optarg, &sid);
			if (rid < 0) {
				log_error("invalid record '%s'",
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
		case 'R':
			do_remove = 1;
			break;
		case 'p':
			ip = str_to_ipport(optarg, &port);
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

	if (mode == MODE_DB) {
		if (!do_remove) {
			log_error("Try iscsiadm -m db --remove\n");
			exit(-1);
		}

		idbm_remove_all();
		exit(0);
	}

	db = idbm_init(config_file);
	if (!db) {
		log_warning("exiting due to idbm configuration error");
		return -1;
	}

	if (mode == MODE_DISCOVERY) {
		if ((rc = verify_mode_params(argc, argv, "dmtplro", 0))) {
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
			if (rid >= 0) {
				discovery_rec_t rec;

				if (idbm_discovery_read(db, rid, &rec)) {
					log_error("discovery record [%06x] "
						  "not found!", rid);
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
					if (!idbm_print_discovery(db, rid)) {
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
				if (!idbm_print_discovery(db, rid)) {
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
		if ((rc = verify_mode_params(argc, argv, "dmMlSronvup", 0))) {
			log_error("node mode: option '-%c' is not "
				  "allowed/supported", rc);
			rc = -1;
			goto out;
		}
		if (sysfs_device) {
			if (rid >= 0) {
				log_error("only one of map and recid may be"
					  " specified");
				rc = -1;
				goto out;
			}
			rid = sys_to_rid(db, sysfs_device);
			if (rid < 0) {
				rc = -1;
				goto out;
			}
			/* fall through */
		}
		if (rid >= 0) {
			node_rec_t rec;

			log_debug(2, "%s: record 0x%x", __FUNCTION__, rid);
			if (idbm_node_read(db, rid, &rec)) {
				log_error("node record [%06x] not found!", rid);
				rc = -1;
				goto out;
			}
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
				if (!idbm_print_node(db, rid, do_show)) {
					log_error("no records found!");
					rc = -1;
				}
				goto out;
			}
			if (do_login) {
				if ((rc = session_login(rid, &rec)) > 0) {
					iscsid_handle_error(rc);
					rc = -1;
				}
				goto out;
			}
			if (do_logout) {
				if ((rc = session_logout(rid, &rec)) > 0) {
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
			if (!idbm_print_node(db, rid, do_show)) {
				log_error("no records found!");
				rc = -1;
				goto out;
			}
		} else if (op == OP_NEW) {
			node_rec_t nrec;
			if (!ip) {
				log_error("--portal required for new "
					  "node record");
				rc = -1;
				goto out;
			}
			idbm_node_setup_defaults(&nrec);
			strncpy(nrec.name, "<not specified>",
				TARGET_NAME_MAXLEN);
			nrec.conn[0].port = port;
			strncpy(nrec.conn[0].address, ip, 16);
			if (idbm_new_node(db, &nrec)) {
				log_error("can not add new record.");
				rc = -1;
				goto out;
			}
			printf("new iSCSI node record added: [%06x]\n",
				nrec.id);
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
		if ((rc = verify_mode_params(argc, argv, "dmrus", 1))) {
			log_error("session mode: option '-%c' is not "
				  "allowed or supported", rc);
			rc = -1;
			goto out;
		}
		if (rid >= 0) {
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
				if ((rc = session_stats(db, rid, sid)) > 0) {
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
				log_error("--logout requires record id");
				rc = -1;
				goto out;
			}
			if (do_stats) {
				log_error("--stats requires record id");
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
