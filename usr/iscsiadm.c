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

struct iscsi_ipc *ipc = NULL; /* dummy */
static int ipc_fd = -1;
static char program_name[] = "iscsiadm";

char initiator_name[TARGET_NAME_MAXLEN];
char *initiator_alias = "temp.init.alias";

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
	{"op", required_argument, NULL, 'o'},
	{"type", required_argument, NULL, 't'},
	{"name", required_argument, NULL, 'n'},
	{"value", required_argument, NULL, 'v'},
	{"record", required_argument, NULL, 'r'},
	{"login", no_argument, NULL, 'l'},
	{"logout", no_argument, NULL, 'u'},
	{"stats", no_argument, NULL, 's'},
	{"debug", required_argument, NULL, 'g'},
	{"version", no_argument, NULL, 'V'},
	{"help", no_argument, NULL, 'h'},
	{NULL, 0, NULL, 0},
};
static char *short_options = "lVhm:p:d:r:n:v:o:t:u";

static void usage(int status)
{
	if (status != 0)
		fprintf(stderr, "Try `%s --help' for more information.\n",
			program_name);
	else {
		printf("Usage: %s [OPTION]\n", program_name);
		printf("\
iSCSI Administration Utility.\n\
\n\
  -m, --mode <op>         specify operational mode op = <discovery|node>\n\
  -m discovery --type=[type] --portal=[ip[:port]] --login\n\
                          perform [type] discovery for target portal with\n\
                          ip-address [ip] and port [port]. Initiate Login for\n\
                          each discovered target if --login is specified\n\
  -m discovery            display all discovery records from internal\n\
                          persistent discovery database\n\
  -m discovery --record=[id] --login\n\
                          perform discovery based on record [id] in database\n\
  -m discovery --record=[id] --op=[op] [--name=[name] --value=[value]]\n\
                          perform specific DB operation [op] for specific\n\
                          discovery record with [id]. It could be one of:\n\
                          [new], [delete], [update] or [show]. In case of\n\
                          [update], you have to provide [name] and [value]\n\
                          you wish to update\n\
  -m node                 display all discovered nodes from internal\n\
                          persistent discovery database\n\
  -m node --record=[id] [--login|--logout]\n\
  -m node --record=[id] --op=[op] [--name=[name] --value=[value]] [--portal]\n\
                          perform specific DB operation [op] for specific\n\
                          node with record [id]. It could be one of:\n\
                          [new], [delete], [update] or [show]. In case of\n\
                          [update], you have to provide [name] and [value]\n\
                          you wish to update. For new record portal must be\n\
		          specified\n\
  -m session              display all active sessions and connections\n\
  -m session --record=[id[:cid]] [--logout|--stats]\n\
                          perform operation for specific session with\n\
			  record [id] or display negotiated parameters if\n\
                          no operation specified. Operation will affect \n\
                          one connection only if [:cid] is specified\n\
  -d, --debug debuglevel  print debugging information\n\
  -V, --version           display version and exit\n\
  -h, --help              display this help and exit\n\
\n\
Enjoy!\n\
Open-iSCSI Team.\n");
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

static char*
str_to_ipport(char *str, int *port)
{
	char *sport;

	if ((sport = strchr(str, ':'))) {
		*sport = '\0';
		sport++;
		*port = strtoul(sport, NULL, 10);
	} else {
		*port = DEF_ISCSI_PORT;
	}
	return str;
}

static int
str_to_ridsid(char *str, int *sid)
{
	char *ptr;

	if ((ptr = strchr(str, ':'))) {
		*ptr = '\0';
		ptr++;
		*sid = strtoul(str, NULL, 10);
	} else {
		*sid = -1;
		ptr = str;
	}

	return strtoul(ptr, NULL, 16);
}

static int
iscsid_connect(void)
{
	int fd, err;
	struct sockaddr_un addr;

	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0) {
		log_error("can not create IPC socket!");
		return fd;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	memcpy((char *) &addr.sun_path + 1, ISCSIADM_NAMESPACE,
		strlen(ISCSIADM_NAMESPACE));

	if ((err = connect(fd, (struct sockaddr *) &addr, sizeof(addr))) < 0) {
		log_error("can not connect to iSCSI daemon!");
		fd = err;
	}

	return fd;
}

static int
iscsid_request(int fd, iscsiadm_req_t *req)
{
	int err;

	if ((err = write(fd, req, sizeof(*req))) != sizeof(*req)) {
		log_error("%s: got write error (%d) on cmd %d, daemon died?",
			program_name, err, req->command);
		if (err >= 0)
			err = -EIO;
	}
	return err;
}

static int
iscsid_response(int fd, iscsiadm_rsp_t *rsp)
{
	int err;

	if ((err = read(fd, rsp, sizeof(*rsp))) != sizeof(*rsp)) {
		log_error("got read error (%d), daemon died?", err);
		if (err >= 0)
			err = -EIO;
	} else
		err = rsp->err;

	return err;
}

static int
do_iscsid(iscsiadm_req_t *req, iscsiadm_rsp_t *rsp)
{
	int err;

	if ((ipc_fd = iscsid_connect()) < 0) {
		err = ipc_fd;
		goto out;
	}

	if ((err = iscsid_request(ipc_fd, req)) < 0)
		goto out;

	err = iscsid_response(ipc_fd, rsp);
	if (!err && req->command != rsp->command)
		err = -EIO;
out:
	if (ipc_fd > 0)
		close(ipc_fd);
	ipc_fd = -1;

	return err;
}

static int
session_login(int rid, node_rec_t *rec)
{
	iscsiadm_req_t req;
	iscsiadm_rsp_t rsp;

	memset(&req, 0, sizeof(req));
	req.command = MGMT_IPC_SESSION_LOGIN;
	req.u.session.rid = rid;

	return do_iscsid(&req, &rsp);
}

static int
session_logout(int rid, node_rec_t *rec)
{
	iscsiadm_req_t req;
	iscsiadm_rsp_t rsp;

	memset(&req, 0, sizeof(req));
	req.command = MGMT_IPC_SESSION_LOGOUT;
	req.u.session.rid = rid;

	return do_iscsid(&req, &rsp);
}

static int compint(const void *i1, const void *i2) {
	return *(int*)i1 >= *(int*)i2;
}

static int
session_activelist(idbm_t *db)
{
	int rc, i;
	iscsiadm_req_t req;
	iscsiadm_rsp_t rsp;

	memset(&req, 0, sizeof(req));
	req.command = MGMT_IPC_SESSION_ACTIVELIST;

	rc = do_iscsid(&req, &rsp);
	if (rc)
		return rc;
	/* display all active sessions */
	qsort(rsp.u.activelist.sids, rsp.u.activelist.cnt,
	      sizeof(int), compint);
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

	rc = do_iscsid(&req, &rsp);
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
		printf("\t%s: %llx\n", rsp.u.getstats.stats.custom[i].desc,
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

static void
iscsid_handle_error(int err)
{
	static char *err_msgs[] = {
		/* 0 */ "",
		/* 1 */ "unknown error",
		/* 2 */ "not found",
		/* 3 */ "no available memory",
		/* 4 */ "encountered connection failure",
		/* 5 */ "encountered iSCSI login failure",
		/* 6 */ "encountered iSCSI database failure",
		/* 7 */ "invalid parameter",
		/* 8 */ "connection timed out",
		/* 9 */ "internal error",
		/* 10 */ "encountered iSCSI logout failure",
		/* 11 */ "iSCSI PDU timed out",
		/* 12 */ "iSCSI transport not found",
		/* 13 */ "daemon access denied",
	};
	log_error("iscsid reported error (%d - %s)", err, err_msgs[err]);
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
	char *ip = NULL, *name = NULL, *value = NULL;
	int ch, longindex, mode=-1, port=-1, do_login=0;
	int rc=0, rid=-1, sid=-1, op=-1, type=-1, do_logout=0, do_stats=0;
	idbm_t *db;
	char *iname;
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

	iname = get_iscsi_initiatorname(INITIATOR_NAME_FILE);
	if (!iname) {
		log_warning("exiting due to configuration error");
		return -1;
	}
	strncpy(initiator_name, iname, TARGET_NAME_MAXLEN);

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
		case 'd':
			log_level = atoi(optarg);
			break;
		case 'm':
			mode = str_to_mode(optarg);
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
			break;
		}
	}

	if (optopt) {
		log_error("unrecognized character '%c'", optopt);
		return -1;
	}

	if (mode < 0) {
		mode = MODE_SESSION;
	}

	db = idbm_init(CONFIG_FILE);
	if (!db) {
		log_warning("exiting due to idbm configuration error");
		return -1;
	}

	if (mode == MODE_DISCOVERY) {
		if ((rc = verify_mode_params(argc, argv, "dmtplr", 0))) {
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
			strcpy(cfg.address, ip);
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
			if (rid >= 0 && do_login) {
				discovery_rec_t rec;

				if (idbm_discovery_read(db, rid, &rec)) {
					log_error("discovery record [%06x] "
						  "not found!", rid);
					rc = -1;
					goto out;
				}
				if (rec.type == DISCOVERY_TYPE_SENDTARGETS) {
					do_sendtargets(db, &rec.u.sendtargets);
				} else if (rec.type == DISCOVERY_TYPE_SLP) {
					log_error("SLP discovery is not fully "
						  "implemented yet.");
					rc = -1;
					goto out;
				} else if (rec.type == DISCOVERY_TYPE_ISNS) {
					log_error("iSNS discovery is not fully "
						  "implemented yet.");
					rc = -1;
					goto out;
				}
			} else if (op < 0 || op == OP_SHOW) {
				if (!idbm_print_discovery(db, rid)) {
					log_error("no records found!");
					rc = -1;
				}
				goto out;
			} else {
				log_error("Operations: insert, delete and "
					  "update for node is not fully "
					  "implemented yet.");
				rc = -1;
				goto out;
			}
		}
	} else if (mode == MODE_NODE) {
		if ((rc = verify_mode_params(argc, argv, "dmlronvu", 0))) {
			log_error("node mode: option '-%c' is not "
				  "allowed/supported", rc);
			rc = -1;
			goto out;
		}
		if (rid >= 0) {
			node_rec_t rec;

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
				if (!idbm_print_node(db, rid)) {
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
			if (!idbm_print_node(db, rid)) {
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
			printf("Active sessions:\n");
			if ((rc = session_activelist(db)) < 0) {
				log_error("can not get list of active "
					"sessions (%d)", rc);
				rc = -1;
				goto out;
			} else if (!rc) {
				printf("\tno active sessions\n");
			}
		}
	} else {
		log_error("This mode is not yet supported");
	}

out:
	idbm_terminate(db);
	return rc;
}
