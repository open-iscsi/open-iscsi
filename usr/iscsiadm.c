/*
 * iSCSI Administration Utility
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
#include "transport.h"
#include "version.h"
#include "iscsi_sysfs.h"

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
	{"rescan", no_argument, NULL, 'R'},
	{"info", no_argument, NULL, 'i'},
	{"login", no_argument, NULL, 'l'},
	{"loginall", required_argument, NULL, 'L'},
	{"logout", no_argument, NULL, 'u'},
	{"logoutall", required_argument, NULL, 'U'},
	{"stats", no_argument, NULL, 's'},
	{"debug", required_argument, NULL, 'g'},
	{"show", no_argument, NULL, 'S'},
	{"version", no_argument, NULL, 'V'},
	{"help", no_argument, NULL, 'h'},
	{NULL, 0, NULL, 0},
};
static char *short_options = "iRlVhm:p:T:U:L:d:r:n:v:o:sSt:u";

static void usage(int status)
{
	if (status != 0)
		fprintf(stderr, "Try `%s --help' for more information.\n",
			program_name);
	else {
		printf("\
iscsiadm -m discovery [ -dhV ] [ -t type -p ip:port [ -l ] ] | [ -p ip:port ] \
[ -o operation ] [ -n name ] [ -v value ]\n\
iscsiadm -m node [ -dhV ] [ -L all,manual,automatic ] [ -U all,manual,automatic ] [ -S ] [ [ -T targetname -p ip:port | -M sysdir ] [ -l | -u ] ] \
[ [ -o  operation  ] [ -n name ] [ -v value ] [ -p ip:port ] ]\n\
iscsiadm -m session [ -dhV ] [ -r sessionid [ -i | -R | -u | -s ] [ -o operation ] [ -n name ] [ -v value ] ]\n");
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
__delete_target(void *data, char *targetname, int tpgt, char *address,
	      int port, int sid)
{
	node_rec_t *rec = data;
	uint32_t host_no;
	int err;

	log_debug(6, "looking for session [%s,%s,%d]",
		  rec->name, rec->conn[0].address, rec->conn[0].port);

	if (!strcmp(rec->name, targetname) &&
	    !strcmp(rec->conn[0].address, address) &&
	    rec->conn[0].port == port) {
		host_no = get_host_no_from_sid(sid, &err);
		if (err) {
			log_error("Could not properly delete target\n");
			return 1;
		}

		sysfs_for_each_device(host_no, sid, delete_device);
		return 1;
	}

	/* keep on looking */
	return 0;
}

static int
session_logout(node_rec_t *rec)
{
	iscsiadm_req_t req;
	iscsiadm_rsp_t rsp;
	int num_found = 0;

	memset(&req, 0, sizeof(req));
	req.command = MGMT_IPC_SESSION_LOGOUT;
	memcpy(&req.u.session.rec, rec, sizeof(node_rec_t));

	sysfs_for_each_session(rec, &num_found, __delete_target);
	return do_iscsid(&ipc_fd, &req, &rsp);
}

static int
match_startup_mode(node_rec_t *rec, char *mode)
{
	/*
	 * we always skip onboot because this should be handled by
	 * something else
	 */
	if (rec->startup == ISCSI_STARTUP_ONBOOT)
		return -1;

	if ((!strcmp(mode, "automatic") &&
	    rec->startup == ISCSI_STARTUP_AUTOMATIC) ||
	    (!strcmp(mode, "manual") &&
	    rec->startup == ISCSI_STARTUP_MANUAL) ||
	    !strcmp(mode, "all"))
		return 0;

	/* support conn or session startup params */
	if ((!strcmp(mode, "automatic") &&
	    rec->conn[0].startup == ISCSI_STARTUP_AUTOMATIC) ||
	    (!strcmp(mode, "manual") &&
	    rec->conn[0].startup == ISCSI_STARTUP_MANUAL) ||
	    !strcmp(mode, "all"))
		return 0;

	return -1;
}

struct session_mgmt_fn {
	idbm_t *db;
	char *mode;
};

static int
__group_logout(void *data, char *targetname, int tpgt, char *address,
	       int port, int sid)
{
	struct session_mgmt_fn *mgmt = data;
	char *mode = mgmt->mode;
	idbm_t *db = mgmt->db;
	node_rec_t rec;
	int rc = 0;

	/* for now skip qlogic and other HW and offload drivers */
	if (!get_transport_by_sid(sid))
		return 0;

	if (idbm_node_read(db, &rec, targetname, address, port)) {
		/*
		 * this is due to a HW driver or some other driver
		 * not hooked in
		 */
		log_debug(7, "could not read data for [%s,%s.%d]\n",
			  targetname, address, port);
		return 0;
	}
	/*
	 * we always skip on boot because if the user killed this on
	 * they would not be able to do anything
	 */
	if (rec.startup == ISCSI_STARTUP_ONBOOT)
		return 0;

	if (!match_startup_mode(&rec, mode)) {
		printf("Logout session [%d][%s:%d %s]\n", sid, address, port,
			targetname);

		rc = session_logout(&rec);
		/* we raced with another app or instance of iscsiadm */
		if (rc == MGMT_IPC_ERR_NOT_FOUND)
			rc = 0;
		if (rc)
			log_error("Could not logout session (err %d).\n", rc);
		if (rc > 0) {
			iscsid_handle_error(rc);
			/* continue trying to logout the rest of them */
			rc = 0;
		}
	}

	return rc;
}

static int
group_logout(idbm_t *db, char *mode)
{
	int num_found;
	struct session_mgmt_fn mgmt;

	if (!mode || !(!strcmp(mode, "automatic") || !strcmp(mode, "all") ||
	    !strcmp(mode,"manual"))) {
		log_error("Invalid logoutall option %s.", mode);
		usage(0);
		return -EINVAL;
	}

	mgmt.mode = mode;
	mgmt.db = db;

	return sysfs_for_each_session(&mgmt, &num_found, __group_logout);
}

static int
__group_login(void *data, node_rec_t *rec)
{
	struct session_mgmt_fn *mgmt = data;
	char *mode = mgmt->mode;
	int rc;

	/*
	 * we always skip onboot because this should be handled by
	 * something else
	 */
	if (rec->startup == ISCSI_STARTUP_ONBOOT)
		return 0;

	if (!match_startup_mode(rec, mode)) {
		printf("Login session [%s:%d %s]\n", rec->conn[0].address,
			rec->conn[0].port, rec->name);

		rc = session_login(rec);
		/* we raced with another app or instance of iscsiadm */
		if (rc == MGMT_IPC_ERR_EXISTS)
			rc = 0;
		if (rc)
			log_error("Could not login session (err %d).\n", rc);
		if (rc > 0) {
			iscsid_handle_error(rc);
			/* continue trying to login the rest of them */
			rc = 0;
		}
	}

	return 0;
}

static int
group_login(idbm_t *db, char *mode)
{
	struct session_mgmt_fn mgmt;

	if (!mode || !(!strcmp(mode, "automatic") || !strcmp(mode, "all") ||
	    !strcmp(mode,"manual"))) {
		log_error("Invalid loginall option %s.", mode);
		usage(0);
		return -EINVAL;
	}

	mgmt.mode = mode;
	mgmt.db = db;

	idbm_for_each_node(db, &mgmt, __group_login);
	return 0;
}

static int
print_node_info(void *data, node_rec_t *rec)
{
	printf("%s:%d,%d %s\n", rec->conn[0].address, rec->conn[0].port,
	       rec->tpgt, rec->name);
	return 0;
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

static void print_scsi_device_info(int host_no, int target, int lun)
{
	char *blockdev, state[SCSI_MAX_STATE_VALUE];

	printf("scsi%d Channel 00 Id %d Lun: %d\n", host_no, target, lun);
	blockdev = get_blockdev_from_lun(host_no, target, lun);
	if (blockdev) {
		printf("Attached scsi disk %s\t\t", blockdev);
		free(blockdev);

		if (!get_device_state(state, host_no, target, lun))
			printf("State: %s\n", state);
		else
			printf("State: Unknown\n");
	}
}

static int is_valid_operational_value(int value)
{
	return value != -1;
}

static int print_session(void *data, char *targetname, int tpgt, char *address,
			 int port, int sid)
{
	int extended = *((int *)data), host_no = -1, err = 0;
	iscsi_provider_t *provider;
	iscsiadm_req_t req;
	iscsiadm_rsp_t rsp;
	struct iscsi_session_operational_config session_conf;
	struct iscsi_conn_operational_config conn_conf;
	char state[SCSI_MAX_STATE_VALUE];
        static char *conn_state[] = {
			"FREE",
			"TRANSPORT WAIT",
			"IN LOGIN",
			"LOGGED IN",
			"IN LOGOUT",
			"LOGOUT REQUESTED",
			"CLEANUP WAIT",
        };
	static char *session_state[] = {
			"NO CHANGE",
			"CLEANUP",
			"REPOEN",
			"REDIRECT",
	};

	provider = get_transport_by_sid(sid);

	if (!extended) {
		printf("%s: [%d] %s:%d,%d %s\n",
			provider ? provider->name : "NA",
			sid, address, port, tpgt, targetname);
		return 0;
	}

	/* TODO: how to pipe modinfo version info here */
	printf("************************************\n");
	printf("Session (sid %d) using module %s:\n", sid,
		provider ? provider->name : "NA");
	printf("************************************\n");
	printf("TargetName: %s\n", targetname);
	printf("Portal Group Tag: %d\n", tpgt);
	printf("Network Portal: %s:%d\n", address, port);  

	get_negotiated_session_conf(sid, &session_conf);
	get_negotiated_conn_conf(sid, &conn_conf);

	/*
	 * get iscsid's conn and session state. This may be slightly different
	 * the kernel's view.
	 *
	 * TODO: get kernel state and qla4xxx info
	 */
	memset(&req, 0, sizeof(iscsiadm_req_t));
	req.command = MGMT_IPC_SESSION_INFO;
	req.u.session.sid = sid;

	if (!do_iscsid(&ipc_fd, &req, &rsp)) {
		/*
		 * for drivers like qla4xxx, iscsid does not display anything
		 * here since it does not know about it.
		 */
		if (rsp.u.session_state.conn_state < 0 ||
		    rsp.u.session_state.conn_state > STATE_CLEANUP_WAIT)
			printf("Invalid iSCSI Connection State\n");
		else
			printf("iSCSI Connection State: %s\n",
				conn_state[rsp.u.session_state.conn_state]);

		if (rsp.u.session_state.session_state < 0 ||
		    rsp.u.session_state.session_state > R_STAGE_SESSION_REDIRECT)
			printf("Invalid iscsid Session State\n");
		else
			printf("Internal iscsid Session State: %s\n",
			      session_state[rsp.u.session_state.session_state]);
	}

	printf("\n");
	printf("************************\n");
	printf("Negotiated iSCSI params:\n");
	printf("************************\n");

	if (is_valid_operational_value(conn_conf.HeaderDigest))
		printf("HeaderDigest: %s\n",
			conn_conf.HeaderDigest ? "CRC32C" : "None");
	if (is_valid_operational_value(conn_conf.DataDigest))
		printf("DataDigest: %s\n",
			conn_conf.DataDigest ? "CRC32C" : "None");
	if (is_valid_operational_value(conn_conf.MaxRecvDataSegmentLength))
		printf("MaxRecvDataSegmentLength: %d\n",
			conn_conf.MaxRecvDataSegmentLength);
	if (is_valid_operational_value(conn_conf.MaxXmitDataSegmentLength))
		printf("MaxXmitDataSegmentLength: %d\n",
			conn_conf.MaxXmitDataSegmentLength);
	if (is_valid_operational_value(session_conf.FirstBurstLength))
		printf("FirstBurstLength: %d\n",
			session_conf.FirstBurstLength);
	if (is_valid_operational_value(session_conf.MaxBurstLength))
		printf("MaxBurstLength: %d\n",
			session_conf.MaxBurstLength);
	if (is_valid_operational_value(session_conf.ImmediateData))
		printf("ImmediateData: %s\n",
			session_conf.ImmediateData ? "Yes" : "No");
	if (is_valid_operational_value(session_conf.InitialR2T))
		printf("InitialR2T: %s\n",
			session_conf.InitialR2T ? "Yes" : "No");
	if (is_valid_operational_value(session_conf.MaxOutstandingR2T))
		printf("MaxOutstandingR2T: %d\n",
			session_conf.MaxOutstandingR2T);
	printf("\n");

	printf("************************\n");
	printf("Attached SCSI devices:\n");
	printf("************************\n");

	host_no = get_host_no_from_sid(sid, &err);
	if (err) {
		printf("Host No: Unknown\n");
		return err;
	}
	printf("Host Number: %d\t", host_no);
	if (!get_host_state(state, host_no))
		printf("State: %s\n", state);
	else
		printf("State: Unknown\n");
	printf("\n");

	sysfs_for_each_device(host_no, sid, print_scsi_device_info);
	printf("\n");

	return 0;
}

static int print_sessions(int extended)
{
	char version[20];
	int num_found = 0, err = 0;

	if (extended) {
		if (get_iscsi_kernel_version(version))
			printf("iSCSI Transport Class version %s\n",
				version);
		printf("%s version %s\n", program_name, ISCSI_VERSION_STR);
	}
	
	sysfs_for_each_session(&extended, &num_found, print_session);
	if (err) {
		log_error("Can not get list of active sessions (%d)", err);
		return err;
	} else if (!num_found)
		log_error("no active sessions\n");
	return 0;
}

static int rescan_session(void *data, char *targetname, int tpgt, char *address,
			  int port, int sid)
{
	int host_no, err;

	host_no = get_host_no_from_sid(sid, &err);
	if (err) {
		log_error("Could not rescan session sid %d\n", sid);
		return err;
	}

	__scan_host(host_no, 0);
	return 0;
}

static int rescan_sessions(void)
{
	int num_found = 0;

	sysfs_for_each_session(NULL, &num_found, rescan_session);
	if (num_found <= 0)
		return -ENODEV;
	else
		return 0;
}

static int
session_stats(int sid)
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
			idbm_for_each_node(db, NULL, print_node_info);
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

static int exec_node_op(idbm_t *db, int op, int do_login, int do_logout,
			int do_show, char *targetname,
			char *ip, int port, char *name, char *value)
{
	int rc = 0;
	node_rec_t rec;

	memset(&rec, 0, sizeof(node_rec_t));

	if (targetname && ip && op != OP_NEW) {
		log_debug(2, "%s: node [%s,%s,%d]", __FUNCTION__,
			  targetname, ip, port);
		if (idbm_node_read(db, &rec, targetname, ip, port)) {
			log_error("node [%s, %s, %d] not found!",
				  targetname, ip, port);
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
		if (!idbm_for_each_node(db, NULL, print_node_info)) {
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

out:
	return rc;
}

int
main(int argc, char **argv)
{
	char *ip = NULL, *name = NULL, *value = NULL;
	char *targetname = NULL, *group_session_mgmt_mode = NULL;
	int ch, longindex, mode=-1, port=-1, do_login=0, do_rescan=0, do_info=0;
	int rc=0, sid=-1, op=-1, type=-1, do_logout=0, do_stats=0, do_show=0;
	int do_login_all=0, do_logout_all=0;
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
		case 'R':
			do_rescan = 1;
			break;
		case 'i':
			do_info = 1;
			break;
		case 'l':
			do_login = 1;
			break;
		case 'u':
			do_logout = 1;
			break;
		case 'U':
			do_logout_all = 1;
			group_session_mgmt_mode= optarg;
			break;
		case 'L':
			do_login_all= 1;
			group_session_mgmt_mode= optarg;
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
		if ((rc = verify_mode_params(argc, argv, "dmlSonvupTUL",
					     0))) {
			log_error("node mode: option '-%c' is not "
				  "allowed/supported", rc);
			rc = -1;
			goto out;
		}

		if (do_login_all) {
			rc = group_login(db, group_session_mgmt_mode);
			goto out;
		}

		if (do_logout_all) {
			rc = group_logout(db, group_session_mgmt_mode);
			goto out;
		}

		rc = exec_node_op(db, op, do_login, do_logout, do_show,
				  targetname, ip, port, name, value);
		goto out;
	} else if (mode == MODE_SESSION) {
		if ((rc = verify_mode_params(argc, argv, "iRdrmusonuSv", 1))) {
			log_error("session mode: option '-%c' is not "
				  "allowed or supported", rc);
			rc = -1;
			goto out;
		}
		if (sid >= 0) {
			char session[64];
			int tmp_sid, tpgt;

			if (do_rescan) {
				rc = rescan_session(NULL, NULL, 0, NULL, 0,
						    sid);
				goto out;
			}

			if (do_stats) {
				if ((rc = session_stats(sid)) > 0) {
					iscsid_handle_error(rc);
					log_error("can not get statistics for "
						"session with SID %d (%d)",
						sid, rc);
					rc = -1;
				}
				goto out;
			}

			snprintf(session, 63, "session%d", sid);
			session[63] = '\0';

			targetname = malloc(TARGET_NAME_MAXLEN + 1);
			if (!targetname) {
				log_error("Could not allocate memory for "
					  "targetname\n");
				rc = -ENOMEM;
				goto out;
			}

			ip = malloc(NI_MAXHOST + 1);
			if (!ip) {
				rc = -ENOMEM;
				goto free_target;
			}

			rc = get_sessioninfo_by_sysfs_id(&tmp_sid, targetname,
							ip, &port, &tpgt,
							session);
			if (rc) {
				log_error("Could not get session info for sid "
					  "%d\n", sid);
				goto free_address;
			}


			if (do_info) {
				int extended = 1;

				rc = print_session(&extended, targetname,
						   tpgt, ip, port, sid);
				goto free_address;
			}

			/* drop down to node ops */
			rc = exec_node_op(db, op, do_login, do_logout,
					  do_show, targetname, ip,
					  port, name, value);
free_address:
			free(ip);
free_target:
			free(targetname);
			goto out;
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

			if (do_rescan) {
				rc = rescan_sessions();
				goto out;
			}

			if (do_info) {
				rc = print_sessions(1);
				goto out;
			}

			rc = print_sessions(0);
		}
	} else {
		log_error("This mode is not yet supported");
	}

out:
	idbm_terminate(db);
	return rc;
}
