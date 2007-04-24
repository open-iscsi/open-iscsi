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
#include "list.h"

struct iscsi_ipc *ipc = NULL; /* dummy */
static int ipc_fd = -1;
static char program_name[] = "iscsiadm";
static char node_path_buf[PATH_MAX];

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
	{"interface", required_argument, NULL, 'I'},
	{"op", required_argument, NULL, 'o'},
	{"type", required_argument, NULL, 't'},
	{"name", required_argument, NULL, 'n'},
	{"value", required_argument, NULL, 'v'},
	{"sid", required_argument, NULL, 'r'},
	{"rescan", no_argument, NULL, 'R'},
	{"print", required_argument, NULL, 'P'},
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
static char *short_options = "RlVhm:p:P:T:I:U:L:d:r:n:v:o:sSt:u";

static void usage(int status)
{
	if (status != 0)
		fprintf(stderr, "Try `%s --help' for more information.\n",
			program_name);
	else {
		printf("\
iscsiadm -m discovery [ -dhV ] [ -t type -p ip:port [ -l ] ] | [ -p ip:port ] \
[ -o operation ] [ -n name ] [ -v value ]\n\
iscsiadm -m node [ -dhV ] [ -P printlevel ] [ -L all,manual,automatic ] [ -U all,manual,automatic ] [ -S ] [ [ -T targetname -p ip:port -I HWaddress ] [ -l | -u ] ] \
[ [ -o  operation  ] [ -n name ] [ -v value ] [ -p ip:port ] ]\n\
iscsiadm -m session [ -dhV ] [ -P  printlevel] [ -r sessionid | sysfsdir [ -R | -u | -s ] [ -o operation ] [ -n name ] [ -v value ] ]\n");
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
	      int port, int sid, char *iface)
{
	node_rec_t *rec = data;
	uint32_t host_no;
	int err;

	log_debug(6, "looking for session [%s,%s,%d]",
		  rec->name, rec->conn[0].address, rec->conn[0].port);

	if (iscsi_match_session(rec, targetname, tpgt, address, port,
				sid, iface)) {
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
__logout_by_startup(void *data, char *targetname, int tpgt, char *address,
		    int port, int sid, char *iface)
{
	struct session_mgmt_fn *mgmt = data;
	char *mode = mgmt->mode;
	idbm_t *db = mgmt->db;
	node_rec_t rec;
	int rc = 0;

	if (idbm_node_read(db, &rec, targetname, address, port, iface)) {
		/*
		 * this is due to a HW driver or some other driver
		 * not hooked in
		 */
		log_debug(7, "could not read data for [%s,%s.%d]\n",
			  targetname, address, port);
		return 0;
	}

	/* multiple drivers could be connected to the same portal */
	if (!iscsi_match_session(&rec, targetname, tpgt, address, port,
				sid, iface))
		return 0;

	/*
	 * we always skip on boot because if the user killed this on
	 * they would not be able to do anything
	 */
	if (rec.startup == ISCSI_STARTUP_ONBOOT)
		return 0;

	if (!match_startup_mode(&rec, mode)) {
		printf("Logout session [%s [%d] [%s]:%d %s]\n", iface, sid,
			address, port, targetname);

		rc = session_logout(&rec);
		/* we raced with another app or instance of iscsiadm */
		if (rc == MGMT_IPC_ERR_NOT_FOUND)
			rc = 0;
		if (rc)
			log_error("Could not logout session (err %d).", rc);
		if (rc > 0) {
			iscsid_handle_error(rc);
			/* continue trying to logout the rest of them */
			rc = 0;
		}
	}

	return rc;
}

static int
logout_by_startup(idbm_t *db, char *mode)
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

	return sysfs_for_each_session(&mgmt, &num_found, __logout_by_startup);
}

static int
logout_portal(void *data, char *targetname, int tpgt, char *address,
	      int port, int sid, char *iface)
{
	node_rec_t tmprec, *rec = data;
	iscsi_provider_t *p;
	int rc;

	p = get_transport_by_sid(sid);
	if (!p)
		return 0;

	if (strlen(rec->name) && strcmp(rec->name, targetname))
		return 0;

	if (strlen(rec->conn[0].address) &&
	   strcmp(rec->conn[0].address, address))
		return 0;

	if (strlen(rec->iface.name) && strcmp(rec->iface.name, iface))
		return 0;

	if (rec->conn[0].port!= -1 && port != rec->conn[0].port)
		return 0;

	printf("Logout session [%s [%d] [%s]:%d %s]\n", iface, sid, address,
		port, targetname);

	memset(&tmprec, 0, sizeof(node_rec_t));
	idbm_node_setup_defaults(&tmprec);
	strncpy(tmprec.name, targetname, TARGET_NAME_MAXLEN);
	tmprec.conn[0].port = port;
	strncpy(tmprec.conn[0].address, address, NI_MAXHOST);
	strncpy(tmprec.iface.name, iface, ISCSI_MAX_IFACE_LEN);
	strncpy(tmprec.transport_name, p->name, ISCSI_TRANSPORT_NAME_MAXLEN);

	rc = session_logout(&tmprec);
	/* we raced with another app or instance of iscsiadm */
	if (rc == MGMT_IPC_ERR_NOT_FOUND)
		rc = 0;
	if (rc)
		log_error("Could not logout session (err %d).", rc);
	if (rc > 0) {
		iscsid_handle_error(rc);
		/* continue trying to logout the rest of them */
		rc = 0;
	}

	return rc;
}

static int
for_each_portal(idbm_t *db, char *targetname, char *ip, int port, char *iface,
		int (* fn)(void *, char *, int, char *, int, int, char *))
{
	node_rec_t rec;
	int err, num_found = 0;

	memset(&rec, 0, sizeof(node_rec_t));
	idbm_node_setup_defaults(&rec);
	if (targetname)
		strncpy(rec.name, targetname, TARGET_NAME_MAXLEN);
	rec.conn[0].port = port;
	if (ip)
		strncpy(rec.conn[0].address, ip, NI_MAXHOST);
	if (iface)
		strncpy(rec.iface.name, iface, ISCSI_MAX_IFACE_LEN);
	else
		memset(rec.iface.name, 0, ISCSI_MAX_IFACE_LEN);

	err = sysfs_for_each_session(&rec, &num_found, fn);
	if (!num_found) {
		log_error("No portal found.");
		err = ENODEV;
	}

	return err;
}

static int
login_portal(void *data, node_rec_t *rec)
{
	int rc;

	printf("Login session [%s:%s [%s]:%d %s]\n", rec->transport_name,
		rec->iface.name, rec->conn[0].address,
		rec->conn[0].port, rec->name);

	rc = session_login(rec);
	/* we raced with another app or instance of iscsiadm */
	if (rc == MGMT_IPC_ERR_EXISTS)
		rc = 0;
	if (rc)
		log_error("Could not login session (err %d).", rc);
	if (rc > 0) {
		iscsid_handle_error(rc);
		/* continue trying to login the rest of them */
		rc = 0;
	}

	return rc;
}

static int
__login_by_startup(void *data, node_rec_t *rec)
{
	struct session_mgmt_fn *mgmt = data;
	char *mode = mgmt->mode;
	int rc = 0;

	/*
	 * we always skip onboot because this should be handled by
	 * something else
	 */
	if (rec->startup == ISCSI_STARTUP_ONBOOT)
		return 0;

	if (!match_startup_mode(rec, mode))
		rc = login_portal(NULL, rec);
	return rc;
}

static int
login_by_startup(idbm_t *db, char *mode)
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

	idbm_for_each_node(db, &mgmt, __login_by_startup);
	return 0;
}

static int for_each_portal_rec(idbm_t *db, char *targetname, char *ip, int port,
			       char *iface, void *data,
			       int (* fn)(void *data, node_rec_t *rec))
{
	node_rec_t rec;
	int err;

	if (targetname && ip) {
		if (iface) {
			err = idbm_node_read(db, &rec, targetname, ip, port,
					     iface);
			if (err) {
				log_error("node [%s, %s,%d][%s] not found!",
					  targetname, ip, port, iface);
				return err;
			}

			fn(data, &rec);
			return 0;
		}


		if (!idbm_for_each_iface(node_path_buf, targetname, ip, port,
					 db, data, fn))
			goto nodev;
	} else if (targetname && !ip) {
		if (!idbm_for_each_portal(node_path_buf, targetname, db,
					 data, fn))
			goto nodev;
	} else if (!idbm_for_each_node(db, data,fn))
		goto nodev;

	return 0;
nodev:
	log_error("no records found!");
	return ENODEV;
}

/*
 * old style flat and interface unware
 */
static int print_node(void *data, node_rec_t *rec)
{
	if (strchr(rec->conn[0].address, '.'))
		printf("%s:%d,%d %s\n", rec->conn[0].address, rec->conn[0].port,
		       rec->tpgt, rec->name);
	else
		printf("[%s]:%d,%d %s\n", rec->conn[0].address,
		       rec->conn[0].port, rec->tpgt, rec->name);
	return 0;
}

static int print_node_tree(void *data, node_rec_t *rec)
{
	node_rec_t *last_rec = data;

	if (strcmp(last_rec->name, rec->name)) {
		printf("target: %s\n", rec->name);
		memset(last_rec, 0, sizeof(node_rec_t));
	}

	if ((strcmp(last_rec->conn[0].address, rec->conn[0].address) ||
	     last_rec->conn[0].port != rec->conn[0].port)) {
		if (strchr(rec->conn[0].address, '.'))
			printf("\tportal: %s:%d\n", rec->conn[0].address,
			       rec->conn[0].port);
		else
			printf("\tportal: [%s]:%d\n", rec->conn[0].address,
			       rec->conn[0].port);
	}

	printf("\t\tdriver: %s\n", rec->transport_name);
	printf("\t\thwaddress: %s\n", rec->iface.name);

	memcpy(last_rec, rec, sizeof(node_rec_t));
	return 0;
}

static int print_nodes(idbm_t *db, int info_level, char *targetname,
		       char *ip, int port, char *iface)
{
	node_rec_t tmp_rec;
	int rc = 0;

	switch (info_level) {
	case 0:
	case -1:
		if (for_each_portal_rec(db, targetname, ip, port,
					iface, NULL, print_node))
			rc = -1;
		break;
	case 1:
		memset(&tmp_rec, 0, sizeof(node_rec_t));
		if (for_each_portal_rec(db, targetname, ip, port,
					iface, &tmp_rec, print_node_tree))
			rc = -1;
		break;
	default:
		log_error("Invalid info level %d. Try 0 or 1.", info_level);
		rc = -1;
	}

	return rc;
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

static int print_session(void *data, char *targetname, int tpgt, char *address,
			 int port, int sid, char *iface)
{
	iscsi_provider_t *provider = get_transport_by_sid(sid);

	if (strchr(address, '.'))
		printf("%s: [%d] %s:%d,%d %s\n",
			provider ? provider->name : "NA",
			sid, address, port, tpgt, targetname);
	else
		printf("%s: [%d] [%s]:%d,%d %s\n",
			provider ? provider->name : "NA",
			sid, address, port, tpgt, targetname);
	return 0;
}

struct session_list_head {
	struct list_head list;
	char *targetname;
	char *address;
	char *iface;
	int port;
	int sid;
	int tpgt;
};

static int link_sessions(void *data, char *targetname, int tpgt, char *address,
			 int port, int sid, char *iface)
{
	struct list_head *list = data;
	struct session_list_head *new, *curr, *match = NULL;

	new = calloc(1, sizeof(*new));
	if (!new)
		goto fail;

	new->targetname = strdup(targetname);
	if (!new)
		goto free_new;
	new->address = strdup(address);
	if (!new->address)
		goto free_targetname;
	new->iface = strdup(iface);
	if (!new->iface)
		goto free_address;
	new->port = port;
	new->sid = sid;
	new->tpgt = tpgt;

	if (list_empty(list)) {
		list_add_tail(&new->list, list);
		return 0;
	}

	list_for_each_entry(curr, list, list) {
		if (!strcmp(curr->targetname, targetname)) {
			match = curr;

			if (!strcmp(curr->address, address)) {
				match = curr;

				if (curr->port == port) {
					match = curr;
					break;
				}
			}
		}
	}

	list_add_tail(&new->list, match ? &match->list : list);
	return 0;

free_address:
	free(new->address);
free_targetname:
	free(new->targetname);
free_new:
	free(new);
fail:
	return -ENOMEM;
}

static int print_iscsi_state(int sid)
{
	iscsiadm_req_t req;
	iscsiadm_rsp_t rsp;
	char *state = NULL;
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

	memset(&req, 0, sizeof(iscsiadm_req_t));
	req.command = MGMT_IPC_SESSION_INFO;
	req.u.session.sid = sid;

	if (do_iscsid(&ipc_fd, &req, &rsp))
		return ENODEV;

	/*
	 * for drivers like qla4xxx, iscsid does not display
	 * anything here since it does not know about it.
	 */
	if (rsp.u.session_state.conn_state >= 0 &&
	    rsp.u.session_state.conn_state <= STATE_CLEANUP_WAIT)
		state = conn_state[rsp.u.session_state.conn_state];
	printf("\t\tiSCSI Connection State: %s\n", state ? state : "Unknown");
	state = NULL;

	if (rsp.u.session_state.session_state >= 0 &&
	   rsp.u.session_state.session_state <= R_STAGE_SESSION_REDIRECT)
		state = session_state[rsp.u.session_state.session_state];
	printf("\t\tInternal iscsid Session State: %s\n",
	       state ? state : "Unknown");
	return 0;
}

static void print_iscsi_params(int sid)
{
	struct iscsi_session_operational_config session_conf;
	struct iscsi_conn_operational_config conn_conf;

	get_negotiated_session_conf(sid, &session_conf);
	get_negotiated_conn_conf(sid, &conn_conf);

	printf("\t\t************************\n");
	printf("\t\tNegotiated iSCSI params:\n");
	printf("\t\t************************\n");

	if (is_valid_operational_value(conn_conf.HeaderDigest))
		printf("\t\tHeaderDigest: %s\n",
			conn_conf.HeaderDigest ? "CRC32C" : "None");
	if (is_valid_operational_value(conn_conf.DataDigest))
		printf("\t\tDataDigest: %s\n",
			conn_conf.DataDigest ? "CRC32C" : "None");
	if (is_valid_operational_value(conn_conf.MaxRecvDataSegmentLength))
		printf("\t\tMaxRecvDataSegmentLength: %d\n",
			conn_conf.MaxRecvDataSegmentLength);
	if (is_valid_operational_value(conn_conf.MaxXmitDataSegmentLength))
		printf("\t\tMaxXmitDataSegmentLength: %d\n",
			conn_conf.MaxXmitDataSegmentLength);
	if (is_valid_operational_value(session_conf.FirstBurstLength))
		printf("\t\tFirstBurstLength: %d\n",
			session_conf.FirstBurstLength);
	if (is_valid_operational_value(session_conf.MaxBurstLength))
		printf("\t\tMaxBurstLength: %d\n",
			session_conf.MaxBurstLength);
	if (is_valid_operational_value(session_conf.ImmediateData))
		printf("\t\tImmediateData: %s\n",
			session_conf.ImmediateData ? "Yes" : "No");
	if (is_valid_operational_value(session_conf.InitialR2T))
		printf("\t\tInitialR2T: %s\n",
			session_conf.InitialR2T ? "Yes" : "No");
	if (is_valid_operational_value(session_conf.MaxOutstandingR2T))
		printf("\t\tMaxOutstandingR2T: %d\n",
			session_conf.MaxOutstandingR2T);
}

static void print_scsi_device_info(int host_no, int target, int lun)
{
	char *blockdev, state[SCSI_MAX_STATE_VALUE];

	printf("\t\tscsi%d Channel 00 Id %d Lun: %d\n", host_no, target, lun);
	blockdev = get_blockdev_from_lun(host_no, target, lun);
	if (blockdev) {
		printf("\t\t\tAttached scsi disk %s\t\t", blockdev);
		free(blockdev);

		if (!get_device_state(state, host_no, target, lun))
			printf("State: %s\n", state);
		else
			printf("State: Unknown\n");
	}
}

static int print_scsi_state(int sid)
{
	int host_no = -1, err = 0;
	char state[SCSI_MAX_STATE_VALUE];

	printf("\t\t************************\n");
	printf("\t\tAttached SCSI devices:\n");
	printf("\t\t************************\n");

	host_no = get_host_no_from_sid(sid, &err);
	if (err) {
		printf("\t\tHost No: Unknown\n");
		return err;
	}
	printf("\t\tHost Number: %d\t", host_no);
	if (!get_host_state(state, host_no))
		printf("State: %s\n", state);
	else
		printf("State: Unknown\n");

	sysfs_for_each_device(host_no, sid, print_scsi_device_info);
	return 0;
}

static void print_sessions_tree(struct list_head *list, int level)
{
	struct session_list_head *curr, *prev = NULL, *tmp;
	iscsi_provider_t *provider;

	list_for_each_entry(curr, list, list) {
		if (!prev || strcmp(prev->targetname, curr->targetname)) {
			printf("target: %s\n", curr->targetname);
			prev = NULL;
		}

		if (!prev || (strcmp(prev->address, curr->address) ||
		     prev->port != curr->port))
			printf("\tportal: %s:%d\n", curr->address, curr->port);

		provider = get_transport_by_sid(curr->sid);
		printf("\t\ttpgt: %d\n", curr->tpgt);
		printf("\t\tdriver: %s\n", provider ? provider->name : "NA");
		printf("\t\thwaddress: %s\n", curr->iface);
		printf("\t\tsid: %d\n", curr->sid);
		print_iscsi_state(curr->sid);

		if (level < 2)
			goto next;
		print_iscsi_params(curr->sid);

		if (level < 3)
			goto next;
		print_scsi_state(curr->sid);
next:
		prev = curr;
	}

	list_for_each_entry_safe(curr, tmp, list, list) {
		list_del(&curr->list);

		free(curr->targetname);
		free(curr->address);
		free(curr->iface);
		free(curr);
	}
}

static int print_sessions(int info_level)
{
	struct list_head list;
	int num_found = 0, err = 0;
	char version[20];

	switch (info_level) {
	case 0:
	case -1:
		err = sysfs_for_each_session(NULL, &num_found,
					     print_session);
		break;
	case 2:
	case 3:
		if (!get_iscsi_kernel_version(version)) {
			printf("iSCSI Transport Class version %s\n",
				version);
			printf("%s version %s\n", program_name,
			      ISCSI_VERSION_STR);
		}
		/* fall through */
	case 1:
		INIT_LIST_HEAD(&list);
		
		err = sysfs_for_each_session(&list, &num_found,
					    link_sessions);
		if (err || !num_found)
			break;

		print_sessions_tree(&list, info_level);
		break;
	default:
		log_error("Invalid info level %d. Try 0 - 2.", info_level);
		return EINVAL;
	}

	if (err) {
		log_error("Can not get list of active sessions (%d)", err);
		return err;
	} else if (!num_found)
		log_error("no active sessions.");
	return 0;
}

static int rescan_session(void *data, char *targetname, int tpgt, char *address,
			  int port, int sid, char *iface)
{
	int host_no, err;

	host_no = get_host_no_from_sid(sid, &err);
	if (err) {
		log_error("Could not rescan session sid %d.", sid);
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

	rc = sendtargets_discovery(db, cfg);
	if (!rc) {
		idbm_new_discovery(db, cfg->address, cfg->port,
				  DISCOVERY_TYPE_SENDTARGETS);
		idbm_for_each_node(db, NULL, print_node);
	}
	return rc;
}

static int isns_dev_attr_query(idbm_t *db)
{
	iscsiadm_req_t req;
	iscsiadm_rsp_t rsp;
	int err;

	memset(&req, 0, sizeof(iscsiadm_req_t));
	req.command = MGMT_IPC_ISNS_DEV_ATTR_QUERY;

	err = do_iscsid(&ipc_fd, &req, &rsp);
	if (!err)
		idbm_for_each_node(db, NULL, print_node);
	return err;
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
			int do_show, int info_level, char *targetname,
			char *ip, int port, char *iface, char *name,
			char *value)
{
	int rc = 0;
	node_rec_t rec;
	struct db_set_param set_param;

	memset(&rec, 0, sizeof(node_rec_t));

	log_debug(2, "%s: node [%s,%s,%d]", __FUNCTION__,
		  targetname, ip, port);

	if (op == OP_NEW) {
		if (!ip || !targetname) {
			log_error("portal and target required for new "
				  "node record");
			rc = -1;
			goto out;
		}

		idbm_node_setup_from_conf(db, &rec);
		strncpy(rec.name, targetname, TARGET_NAME_MAXLEN);
		rec.conn[0].port = port;
		strncpy(rec.conn[0].address, ip, NI_MAXHOST);
		if (iface)
			strncpy(rec.iface.name, iface, ISCSI_MAX_IFACE_LEN);
		if (idbm_new_node(db, &rec)) {
			log_error("can not add new record.");
			rc = -1;
			goto out;
		}
		printf("new iSCSI node record added\n");
		goto out;
	}

	if (do_login && do_logout) {
		log_error("either login or logout at the time allowed!");
		rc = -1;
		goto out;
	}

	if ((do_login || do_logout) && op >= 0) {
		log_error("either operation or login/logout "
			  "at the time allowed!");
		rc = -1;
		goto out;
	}

	if (!do_login && !do_logout && op < 0 &&
	    !targetname && !ip && !iface) {
		rc = print_nodes(db, info_level, targetname, ip, port, iface);
		goto out;
	}

	if (do_login) {
		if (for_each_portal_rec(db, targetname, ip, port,
					iface, NULL, login_portal))
			rc = -1;
		goto out;
	}

	if (do_logout) {
		if (for_each_portal(db, targetname, ip, port, iface,
				    logout_portal))
			rc = -1;
		goto out;
	}

	if (op < 0 || (!do_login && !do_logout && op == OP_SHOW)) {
		if (for_each_portal_rec(db, targetname, ip, port,
					iface, &do_show, idbm_print_node))
			rc = -1;
		goto out;
	}

	if (op == OP_UPDATE) {
		if (!name || !value) {
			log_error("update requires name and value");
			rc = -1;
			goto out;
		}

		set_param.db = db;
		set_param.name = name;
		set_param.value = value;

		if (for_each_portal_rec(db, targetname, ip, port, iface,
					&set_param, idbm_node_set_param))	
			rc = -1;
		goto out;
	} else if (op == OP_DELETE) {
		if (for_each_portal_rec(db, targetname, ip, port,
					iface, NULL, idbm_delete_node))	
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

static int parse_sid(char *session)
{
	struct stat statb;
	char sys_session[64], *start, *last;
	int sid = -1, len;

	if (stat(session, &statb)) {
		log_debug(1, "Could not stat %s failed with %d",
			  session, errno);
		if (index(session, '/')) {
			log_error("%s is an invalid session path\n", session);
			exit(1);
		}
		return atoi(session);
	}

	if (!S_ISDIR(statb.st_mode)) {
		log_error("%s is not a directory", session);
		exit(1);
	}

	/*
	 * Given sysfs_device is a directory name of the form:
	 *
	 * /sys/devices/platform/hostH/sessionS/targetH:B:I/H:B:I:L
	 * /sys/devices/platform/hostH/sessionS/targetH:B:I
	 * /sys/devices/platform/hostH/sessionS
	 *
	 * We want to set sys_session to sessionS
	 */
	last = NULL;
	start = strstr(session, "session");
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
		log_error("Unable to find session in %s", session);
		exit(1);
	}

	sscanf(sys_session, "session%d", &sid);
	return sid;
}

int
main(int argc, char **argv)
{
	char *ip = NULL, *name = NULL, *value = NULL, *iface = NULL;
	char *targetname = NULL, *group_session_mgmt_mode = NULL;
	int ch, longindex, mode=-1, port=-1, do_login=0, do_rescan=0;
	int rc=0, sid=-1, op=-1, type=-1, do_logout=0, do_stats=0, do_show=0;
	int do_login_all=0, do_logout_all=0, info_level=-1;
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
			sid = parse_sid(optarg);
			if (sid < 0) {
				log_error("invalid sid '%s'",
					  optarg);
				return -1;
			}
			break;
		case 'R':
			do_rescan = 1;
			break;
		case 'P':
			info_level = atoi(optarg);
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
		case 'I':
			iface = optarg;
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
			if ((rc = isns_dev_attr_query(db)) > 0) {
				iscsid_handle_error(rc);
				rc = -1;
			}
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
		if ((rc = verify_mode_params(argc, argv, "PdmlSonvupTIUL",
					     0))) {
			log_error("node mode: option '-%c' is not "
				  "allowed/supported", rc);
			rc = -1;
			goto out;
		}

		if (do_login_all) {
			rc = login_by_startup(db, group_session_mgmt_mode);
			goto out;
		}

		if (do_logout_all) {
			rc = logout_by_startup(db, group_session_mgmt_mode);
			goto out;
		}

		rc = exec_node_op(db, op, do_login, do_logout, do_show,
				  info_level, targetname, ip, port, iface,
				  name, value);
		goto out;
	} else if (mode == MODE_SESSION) {
		if ((rc = verify_mode_params(argc, argv, "PiRdrmusonuSv", 1))) {
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
						    sid, NULL);
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

			iface = malloc(ISCSI_MAX_IFACE_LEN);
			if (!iface) {
				rc = -ENOMEM;
				goto free_address;
			}

			rc = get_sessioninfo_by_sysfs_id(&tmp_sid, targetname,
							ip, &port, &tpgt, iface,
							session);
			if (rc) {
				log_error("Could not get session info for sid "
					  "%d", sid);
				goto free_iface;
			}

			/* drop down to node ops */
			rc = exec_node_op(db, op, do_login, do_logout,
					  do_show, info_level, targetname, ip,
					  port, iface, name, value);
free_iface:
			free(iface);
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

			rc = print_sessions(info_level);
		}
	} else {
		log_error("This mode is not yet supported");
	}

out:
	idbm_terminate(db);
	return rc;
}
