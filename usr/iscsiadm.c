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

#include <errno.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/stat.h>

#include "initiator.h"
#include "discovery.h"
#include "log.h"
#include "mgmt_ipc.h"
#include "idbm.h"
#include "iscsi_util.h"
#include "transport.h"
#include "version.h"
#include "iscsi_sysfs.h"
#include "list.h"
#include "iscsi_settings.h"
#include "fw_context.h"
#include "iface.h"
#include "session_info.h"
#include "host.h"
#include "sysdeps.h"
#include "idbm_fields.h"
#include "session_mgmt.h"
#include "iscsid_req.h"
#include "isns-proto.h"

struct iscsi_ipc *ipc = NULL; /* dummy */
static char program_name[] = "iscsiadm";
static char config_file[TARGET_NAME_MAXLEN];

enum iscsiadm_mode {
	MODE_DISCOVERY,
	MODE_NODE,
	MODE_SESSION,
	MODE_HOST,
	MODE_IFACE,
	MODE_FW,
};

enum iscsiadm_op {
	OP_NOOP			= 0x0,
	OP_NEW			= 0x1,
	OP_DELETE		= 0x2,
	OP_UPDATE		= 0x4,
	OP_SHOW			= 0x8,
	OP_NONPERSISTENT	= 0x10
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
	{"host", required_argument, NULL, 'H'},
	{"sid", required_argument, NULL, 'r'},
	{"rescan", no_argument, NULL, 'R'},
	{"print", required_argument, NULL, 'P'},
	{"login", no_argument, NULL, 'l'},
	{"loginall", required_argument, NULL, 'L'},
	{"logout", no_argument, NULL, 'u'},
	{"logoutall", required_argument, NULL, 'U'},
	{"stats", no_argument, NULL, 's'},
	{"killiscsid", required_argument, NULL, 'k'},
	{"debug", required_argument, NULL, 'd'},
	{"show", no_argument, NULL, 'S'},
	{"version", no_argument, NULL, 'V'},
	{"help", no_argument, NULL, 'h'},
	{NULL, 0, NULL, 0},
};
static char *short_options = "RlVhm:p:P:T:H:I:U:k:L:d:r:n:v:o:sSt:u";

static void usage(int status)
{
	if (status != 0)
		fprintf(stderr, "Try `%s --help' for more information.\n",
			program_name);
	else {
		printf("\
iscsiadm -m discovery [ -hV ] [ -d debug_level ] [-P printlevel] [ -t type -p ip:port -I ifaceN ... [ -l ] ] | [ -p ip:port ] \
[ -o operation ] [ -n name ] [ -v value ]\n\
iscsiadm -m node [ -hV ] [ -d debug_level ] [ -P printlevel ] [ -L all,manual,automatic ] [ -U all,manual,automatic ] [ -S ] [ [ -T targetname -p ip:port -I ifaceN ] [ -l | -u | -R | -s] ] \
[ [ -o  operation  ] [ -n name ] [ -v value ] ]\n\
iscsiadm -m session [ -hV ] [ -d debug_level ] [ -P  printlevel] [ -r sessionid | sysfsdir [ -R | -u | -s ] [ -o operation ] [ -n name ] [ -v value ] ]\n\
iscsiadm -m iface [ -hV ] [ -d debug_level ] [ -P printlevel ] [ -I ifacename ] [ [ -o  operation  ] [ -n name ] [ -v value ] ]\n\
iscsiadm -m fw [ -l ]\n\
iscsiadm -m host [ -P printlevel ] [ -H hostno ]\n\
iscsiadm -k priority\n");
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
	else if (!strcmp("nonpersistent", str))
		op = OP_NONPERSISTENT;
	else
		op = OP_NOOP;

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
	else if (!strcmp("iface", str))
		mode = MODE_IFACE;
	else if (!strcmp("fw", str))
		mode = MODE_FW;
	else if (!strcmp("host", str))
		mode = MODE_HOST;
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
	else if (!strcmp("fw", str))
		type = DISCOVERY_TYPE_FW;
	else
		type = -1;

	return type;
}

static void kill_iscsid(int priority)
{
	iscsiadm_req_t req;
	iscsiadm_rsp_t rsp;
	int rc;

	/*
	 * We only support SIGTERM like stoppage of iscsid for now.
	 * In the future we can do something where we try go finish
	 * up operations like login, error handling, etc, before
	 * iscsid is stopped, and we can add different values to indicate
	 * that the user wants iscsid to log out existing sessions before
	 * exiting.
	 */
	if (priority != 0) {
		log_error("Invalid iscsid priority %d. Priority must be 0.",
			  priority);
		return;
	}

	memset(&req, 0, sizeof(req));
	req.command = MGMT_IPC_IMMEDIATE_STOP;
	rc = iscsid_exec_req(&req, &rsp, 0);
	if (rc) {
		iscsid_handle_error(rc);
		log_error("Could not stop iscsid. Trying sending iscsid "
			  "SIGTERM or SIGKILL signals manually\n");
	}
}

/*
 * TODO: we can display how the ifaces are related to node records.
 * And we can add a scsi_host mode which would display how
 * sessions are related to hosts
 * (scsi_host and iscsi_sessions are the currently running instance of
 * a iface or node record).
 */
static int print_ifaces(struct iface_rec *iface, int info_level)
{
	int err, num_found = 0;

	switch (info_level) {
	case 0:
	case -1:
		err = iface_for_each_iface(NULL, 0, &num_found,
					   iface_print_flat);
		break;
	case 1:
		if (iface) {
			err = iface_conf_read(iface);
			if (err) {
				log_error("Could not read iface %s.\n",
					  iface->name);
				return err;
			}
			iface_print_tree(NULL, iface);
			num_found = 1;
		} else
			err = iface_for_each_iface(NULL, 0, &num_found,
						   iface_print_tree);
		break;
	default:
		log_error("Invalid info level %d. Try 0 - 1.", info_level);
		return EINVAL;
	}

	if (!num_found) {
		log_error("No interfaces found.");
		err = ENODEV;
	}
	return err;
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

static int
for_each_session(struct node_rec *rec, iscsi_sysfs_session_op_fn *fn)
{
	int err, num_found = 0;

	err = iscsi_sysfs_for_each_session(rec, &num_found, fn);
	if (err)
		log_error("Could not execute operation on all sessions. Err "
			  "%d.", err);
	else if (!num_found) {
		log_error("No portal found.");
		err = ENODEV;
	}

	return err;
}

static int link_recs(void *data, struct node_rec *rec)
{
	struct list_head *list = data;
	struct node_rec *rec_copy;

	rec_copy = calloc(1, sizeof(*rec_copy));
	if (!rec_copy)
		return ENOMEM;
	memcpy(rec_copy, rec, sizeof(*rec_copy));
	INIT_LIST_HEAD(&rec_copy->list);
	list_add_tail(&rec_copy->list, list);
	return 0;
}

static int
__logout_by_startup(void *data, struct list_head *list,
		    struct session_info *info)
{
	char *mode = data;
	node_rec_t rec;
	int rc = 0;

	memset(&rec, 0, sizeof(node_rec_t));
	if (idbm_rec_read(&rec, info->targetname, info->tpgt,
			  info->persistent_address,
			  info->persistent_port, &info->iface)) {
		/*
		 * this is due to a HW driver or some other driver
		 * not hooked in
		 */
		log_debug(7, "could not read data for [%s,%s.%d]\n",
			  info->targetname, info->persistent_address,
			  info->persistent_port);
		return -1;
	}

	/* multiple drivers could be connected to the same portal */
	if (strcmp(rec.iface.transport_name, info->iface.transport_name))
		return -1;
	/*
	 * we always skip on boot because if the user killed this on
	 * they would not be able to do anything
	 */
	if (rec.startup == ISCSI_STARTUP_ONBOOT)
		return -1;

	if (!match_startup_mode(&rec, mode))
		rc = iscsi_logout_portal(info, list);
	return rc;
}

static int
logout_by_startup(char *mode)
{
	int nr_found;

	if (!mode || !(!strcmp(mode, "automatic") || !strcmp(mode, "all") ||
	    !strcmp(mode,"manual"))) {
		log_error("Invalid logoutall option %s.", mode);
		usage(0);
		return EINVAL;
	}

	return iscsi_logout_portals(mode, &nr_found, 1, __logout_by_startup);
}

/*
 * TODO: merged this and logout into the common for_each_rec by making
 * the matching more generic
 */
static int
__login_by_startup(void *data, struct list_head *list, struct node_rec *rec)
{
	char *mode = data;
	/*
	 * we always skip onboot because this should be handled by
	 * something else
	 */
	if (rec->startup == ISCSI_STARTUP_ONBOOT)
		return -1;

	if (match_startup_mode(rec, mode))
		return -1;

	iscsi_login_portal(NULL, list, rec);
	return 0;
}

static int
login_by_startup(char *mode)
{
	int nr_found = 0, rc, err;
	struct list_head rec_list;

	if (!mode || !(!strcmp(mode, "automatic") || !strcmp(mode, "all") ||
	    !strcmp(mode,"manual"))) {
		log_error("Invalid loginall option %s.", mode);
		usage(0);
		return EINVAL;
	}

	INIT_LIST_HEAD(&rec_list);
	rc = idbm_for_each_rec(&nr_found, &rec_list, link_recs);
	err = iscsi_login_portals(mode, &nr_found, 1, &rec_list,
				  __login_by_startup);
	if (err && !rc)
		rc = err;

	if (rc)
		log_error("Could not log into all portals. Err %d.", rc);
	else if (!nr_found) {
		log_error("No records found!");
		rc = ENODEV;
	}
	return rc;
}

/**
 * iscsi_logout_matched_portal - logout of targets matching the rec info
 * @data: record to session with
 * @list: list to add logout rec to
 * @info: session to match with rec
 */
static int iscsi_logout_matched_portal(void *data, struct list_head *list,
				       struct session_info *info)
{
	struct node_rec *pattern_rec = data;
	struct iscsi_transport *t;

	t = iscsi_sysfs_get_transport_by_sid(info->sid);
	if (!t)
		return -1;

	if (!iscsi_match_session(pattern_rec, info))
		return -1;

	/* we do not support this yet */
	if (t->caps & CAP_FW_DB) {
		log_error("Could not logout session of [sid: %d, "
			  "target: %s, portal: %s,%d].", info->sid,
			  info->targetname, info->persistent_address,
			  info->port);
		log_error("Logout not supported for driver: %s.", t->name);
		return -1;
	}
	return iscsi_logout_portal(info, list);
}

static int iface_fn(void *data, node_rec_t *rec)
{
	struct rec_op_data *op_data = data;

	if (!__iscsi_match_session(op_data->match_rec, rec->name,
				   rec->conn[0].address, rec->conn[0].port,
				   &rec->iface))
		return -1;
	return op_data->fn(op_data->data, rec);
}

static int __for_each_rec(int verbose, struct node_rec *rec,
			  void *data, idbm_iface_op_fn *fn)
{
	struct rec_op_data op_data;
	int nr_found = 0, rc;

	memset(&op_data, 0, sizeof(struct rec_op_data));
	op_data.data = data;
	op_data.match_rec = rec;
	op_data.fn = fn;

	rc = idbm_for_each_rec(&nr_found, &op_data, iface_fn);
	if (rc) {
		if (verbose)
			log_error("Could not execute operation on all "
				  "records. Err %d.", rc);
	} else if (!nr_found) {
		if (verbose)
			log_error("no records found!");
		rc = ENODEV;
	}

	return rc;
}

static int for_each_rec(struct node_rec *rec, void *data,
			idbm_iface_op_fn *fn)
{
	return __for_each_rec(1, rec, data, fn);
}


static int login_portals(struct node_rec *pattern_rec)
{
	struct list_head rec_list;
	int err, ret, nr_found;

	INIT_LIST_HEAD(&rec_list);
	ret = for_each_rec(pattern_rec, &rec_list, link_recs);
	err = iscsi_login_portals(NULL, &nr_found, 1, &rec_list,
				  iscsi_login_portal);
	if (err && !ret)
		ret = err;
	return ret;
}

static int print_nodes(int info_level, struct node_rec *rec)
{
	struct node_rec tmp_rec;
	int rc = 0;

	switch (info_level) {
	case 0:
	case -1:
		if (for_each_rec(rec, NULL, idbm_print_node_flat))
			rc = -1;
		break;
	case 1:
		memset(&tmp_rec, 0, sizeof(node_rec_t));
		if (for_each_rec(rec, &tmp_rec, idbm_print_node_and_iface_tree))
			rc = -1;
		break;
	default:
		log_error("Invalid info level %d. Try 0 or 1.", info_level);
		rc = -1;
	}

	return rc;
}

static char *get_config_file(void)
{
	int rc;
	iscsiadm_req_t req;
	iscsiadm_rsp_t rsp;

	memset(&req, 0, sizeof(req));
	req.command = MGMT_IPC_CONFIG_FILE;

	rc = iscsid_exec_req(&req, &rsp, 1);
	if (rc)
		return NULL;

	if (rsp.u.config.var[0] != '\0') {
		strcpy(config_file, rsp.u.config.var);
		return config_file;
	}

	return NULL;
}

static int rescan_portal(void *data, struct session_info *info)
{
	int host_no, err;

	if (!iscsi_match_session(data, info))
		return -1;

	printf("Rescanning session [sid: %d, target: %s, portal: "
		"%s,%d]\n", info->sid, info->targetname,
		info->persistent_address, info->port);

	host_no = iscsi_sysfs_get_host_no_from_sid(info->sid, &err);
	if (err) {
		log_error("Could not rescan session sid %d.", info->sid);
		return err;
	}
	/* rescan each device to pick up size changes */
	iscsi_sysfs_for_each_device(NULL, host_no, info->sid,
				    iscsi_sysfs_rescan_device);
	/* now scan for new devices */
	iscsi_sysfs_scan_host(host_no, 0);
	return 0;
}

static int
session_stats(void *data, struct session_info *info)
{
	int rc, i;
	iscsiadm_req_t req;
	iscsiadm_rsp_t rsp;

	if (!iscsi_match_session(data, info))
		return -1;

	memset(&req, 0, sizeof(req));
	req.command = MGMT_IPC_SESSION_STATS;
	req.u.session.sid = info->sid;

	rc = iscsid_exec_req(&req, &rsp, 1);
	if (rc)
		return EIO;

	printf("Stats for session [sid: %d, target: %s, portal: "
		"%s,%d]\n",
		info->sid, info->targetname, info->persistent_address,
		info->port);

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

static int add_static_rec(int *found, char *targetname, int tpgt,
			  char *ip, int port, struct iface_rec *iface)
{
	node_rec_t *rec;
	discovery_rec_t *drec;
	int rc;

	rec = calloc(1, sizeof(*rec));
	if (!rec) {
		log_error("Could not allocate memory for node addition");
		rc = ENOMEM;
		goto done;
	}

	drec = calloc(1, sizeof(*drec));
	if (!drec) {
		log_error("Could not allocate memory for node addition");
		rc = ENOMEM;
		goto free_rec;
	}
	drec->type = DISCOVERY_TYPE_STATIC;

	idbm_node_setup_from_conf(rec);
	strlcpy(rec->name, targetname, TARGET_NAME_MAXLEN);
	rec->tpgt = tpgt;
	rec->conn[0].port = port;
	strlcpy(rec->conn[0].address, ip, NI_MAXHOST);

	if (iface) {
		rc = iface_conf_read(iface);
		if (rc) {
			log_error("Could not read iface %s. Error %d",
				  iface->name, rc);
			return rc;
		}

		iface_copy(&rec->iface, iface);
	}

	rc = idbm_add_node(rec, drec, 1);
	if (!rc) {
		(*found)++;
		printf("New iSCSI node [%s:" iface_fmt " %s,%d,%d %s] added\n",
			rec->iface.transport_name, iface_str(&rec->iface),
			ip, port, tpgt, targetname);
	}
	free(drec);
free_rec:
	free(rec);
done:
	return rc;
}

static int add_static_portal(int *found, void *data,
			     char *targetname, int tpgt, char *ip, int port)
{
	node_rec_t *rec = data;

	if (strlen(rec->conn[0].address) &&
	    strcmp(rec->conn[0].address, ip))
		return 0;

	if (rec->conn[0].port != -1 && rec->conn[0].port != port)
		return 0;

	return add_static_rec(found, targetname, tpgt, ip, port,
			      &rec->iface);
}

static int add_static_node(int *found, void *data,
			  char *targetname)
{
	node_rec_t *rec = data;

	if (!strlen(rec->name))
		goto search;

	if (strcmp(rec->name, targetname))
		return 0;

	if (!strlen(rec->conn[0].address))
		goto search;

	return add_static_rec(found, targetname, rec->tpgt,
			      rec->conn[0].address,
			      rec->conn[0].port, &rec->iface);
search:
	return idbm_for_each_portal(found, data, add_static_portal,
				    targetname);
}

static int add_static_recs(struct node_rec *rec)
{
	int rc, nr_found = 0;

	rc = idbm_for_each_node(&nr_found, rec, add_static_node);
	if (rc) {
		log_error("Error while adding records. DB may be in an "
			  "inconsistent state. Err %d", rc);
		return rc;
	}
	/* success */
	if (nr_found > 0)
		return 0;

	/* brand new target */
	if (strlen(rec->name) && strlen(rec->conn[0].address)) {
		rc = add_static_rec(&nr_found, rec->name, rec->tpgt,
				    rec->conn[0].address, rec->conn[0].port,
				    &rec->iface);
		if (rc)
			goto done;
		return 0;
	}
done:
	printf("No records added.\n");
	return ENODEV;
}

/*
 * start sendtargets discovery process based on the
 * particular config
 */
static int
do_offload_sendtargets(discovery_rec_t *drec, int host_no, int do_login)
{
	drec->type = DISCOVERY_TYPE_OFFLOAD_SENDTARGETS;
	return discovery_offload_sendtargets(host_no, do_login, drec);
}

static int delete_node(void *data, struct node_rec *rec)
{
	if (iscsi_check_for_running_session(rec)) {
		/*
 		 * We could log out the session for the user, but if
 		 * the session is being used the user may get something
 		 * they were not expecting (FS errors and a read only
 		 * remount).
		 */
		log_error("This command will remove the record [iface: %s, "
			  "target: %s, portal: %s,%d], but a session is "
			  "using it. Logout session then rerun command to "
			  "remove record.", rec->iface.name, rec->name,
			  rec->conn[0].address, rec->conn[0].port);
		return EINVAL;
	}

	return idbm_delete_node(rec);
}

static int delete_stale_rec(void *data, struct node_rec *rec)
{
	struct list_head *new_rec_list = data;
	struct node_rec *new_rec;

	list_for_each_entry(new_rec, new_rec_list, list) {
		/*
		 * We could also move this to idbm.c and instead of looping
		 * over every node just loop over disc to node links.
		 */
		if (rec->disc_type != new_rec->disc_type ||
		    rec->disc_port != new_rec->disc_port ||
		    strcmp(rec->disc_address, new_rec->disc_address))
			/*
			 * if we are not from the same discovery source
			 * ignore it
			 */
			return 0;

		if (__iscsi_match_session(rec,
					  new_rec->name,
					  new_rec->conn[0].address,
					  new_rec->conn[0].port,
					  &new_rec->iface))
			return 0;
	}
	/* if there is a error we can continue on */
	delete_node(NULL, rec);
	return 0;
}

static int
exec_disc_op_on_recs(discovery_rec_t *drec, struct list_head *rec_list,
		     int info_level, int do_login, int op)
{
	int rc = 0, err, found = 0;
	struct node_rec *new_rec, tmp_rec;

	/* clean up node db */
	if (op & OP_DELETE)
		idbm_for_each_rec(&found, rec_list, delete_stale_rec);

	if (op & OP_NEW || op & OP_UPDATE) {
		/* now add/update records */
		list_for_each_entry(new_rec, rec_list, list) {
			rc = idbm_add_node(new_rec, drec, op & OP_UPDATE);
			if (rc)
				log_error("Could not add/update "
					  "[%s:" iface_fmt " %s,%d,%d %s]",
					   new_rec->iface.transport_name,
					   iface_str(&new_rec->iface),
					   new_rec->conn[0].address,
					   new_rec->conn[0].port,
					   new_rec->tpgt, new_rec->name);
		}
	}

	memset(&tmp_rec, 0, sizeof(node_rec_t));
	list_for_each_entry(new_rec, rec_list, list) {
		switch (info_level) {
		case 0:
		case -1:
			idbm_print_node_flat(NULL, new_rec);
			break;
		case 1:
			idbm_print_node_and_iface_tree(&tmp_rec, new_rec);
		}

	}

	if (!do_login)
		return 0;

	err = iscsi_login_portals(NULL, &found, 1, rec_list,
				  iscsi_login_portal);
	if (err && !rc)
		rc = err;
	return rc;
}

static int
do_software_sendtargets(discovery_rec_t *drec, struct list_head *ifaces,
		        int info_level, int do_login, int op)
{
	struct list_head rec_list;
	struct node_rec *rec, *tmp;
	int rc;

	INIT_LIST_HEAD(&rec_list);
	/*
	 * compat: if the user did not pass any op then we do all
	 * ops for them
	 */
	if (!op)
		op = OP_NEW | OP_DELETE | OP_UPDATE;

	drec->type = DISCOVERY_TYPE_SENDTARGETS;
	/*
	 * we will probably want to know how a specific iface and discovery
	 * DB lined up, but for now just put all the targets found from
	 * a discovery portal in one place
	 */
	if (!(op & OP_NONPERSISTENT)) {
		rc = idbm_add_discovery(drec);
		if (rc) {
			log_error("Could not add new discovery record.");
			return rc;
		}
	}

	rc = idbm_bind_ifaces_to_nodes(discovery_sendtargets, drec, ifaces,
				       &rec_list);
	if (rc) {
		log_error("Could not perform SendTargets discovery.");
		return rc;
	}

	rc = exec_disc_op_on_recs(drec, &rec_list, info_level, do_login, op);

	list_for_each_entry_safe(rec, tmp, &rec_list, list) {
		list_del(&rec->list);
		free(rec);
	}

	return rc;
}

static int
do_sendtargets(discovery_rec_t *drec, struct list_head *ifaces,
	       int info_level, int do_login, int op)
{
	struct iface_rec *tmp, *iface;
	int rc, host_no;
	struct iscsi_transport *t;

	if (list_empty(ifaces)) {
		ifaces = NULL;
		goto sw_st;
	}

	/* we allow users to mix hw and sw iscsi so we have to sort it out */
	list_for_each_entry_safe(iface, tmp, ifaces, list) {
		rc = iface_conf_read(iface);
		if (rc) {
			log_error("Could not read iface info for %s. "
				  "Make sure a iface config with the file "
				  "name and iface.iscsi_ifacename %s is in %s.",
				  iface->name, iface->name, IFACE_CONFIG_DIR);
			list_del(&iface->list);
			free(iface);
			continue;
		}

		host_no = iscsi_sysfs_get_host_no_from_hwinfo(iface, &rc);
		if (rc || host_no == -1) {
			log_debug(1, "Could not match iface" iface_fmt " to "
				  "host.", iface_str(iface)); 
			/* try software iscsi */
			continue;
		}

		t = iscsi_sysfs_get_transport_by_hba(host_no);
		if (!t) {
			log_error("Could not match hostno %d to "
				  "transport. Dropping interface %s,"
				   iface_fmt " ,%s.",
				   host_no, iface->transport_name,
				   iface_str(iface), iface->ipaddress);
			list_del(&iface->list);
			free(iface);
			continue;
		}

		if (t->caps & CAP_SENDTARGETS_OFFLOAD) {
			do_offload_sendtargets(drec, host_no, do_login);
			list_del(&iface->list);
			free(iface);
		}
	}

	if (list_empty(ifaces))
		return ENODEV;

sw_st:
	return do_software_sendtargets(drec, ifaces, info_level, do_login,
				       op);
}

static int do_isns(discovery_rec_t *drec, struct list_head *ifaces,
		   int info_level, int do_login, int op)
{
	struct list_head rec_list;
	struct node_rec *rec, *tmp;
	int rc;

	INIT_LIST_HEAD(&rec_list);
	/*
	 * compat: if the user did not pass any op then we do all
	 * ops for them
	 */
	if (!op)
		op = OP_NEW | OP_DELETE | OP_UPDATE;

	drec->type = DISCOVERY_TYPE_ISNS;

	rc = idbm_bind_ifaces_to_nodes(discovery_isns, drec, ifaces,
				       &rec_list);
	if (rc) {
		log_error("Could not perform iSNS discovery.");
		return rc;
	}

	rc = exec_disc_op_on_recs(drec, &rec_list, info_level, do_login, op);

	list_for_each_entry_safe(rec, tmp, &rec_list, list) {
		list_del(&rec->list);
		free(rec);
	}

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
	exit(1);
}

/* TODO: merge iter helpers and clean them up, so we can use them here */
static int exec_iface_op(int op, int do_show, int info_level,
			 struct iface_rec *iface, char *name, char *value)
{
	struct db_set_param set_param;
	struct node_rec *rec = NULL;
	int rc = 0;

	switch (op) {
	case OP_NEW:
		if (!iface) {
			log_error("Could not add interface. No interface "
				  "passed in.");
			return EINVAL;
		}

		rec = idbm_create_rec(NULL, -1, NULL, -1, iface, 0);
		if (rec && iscsi_check_for_running_session(rec)) {
			rc = EBUSY;
			goto new_fail;
		}

		iface_setup_defaults(iface);
		rc = iface_conf_write(iface);
		if (rc)
			goto new_fail;
		printf("New interface %s added\n", iface->name);
		break;
new_fail:
		log_error("Could not create new interface %s.", iface->name);
		break;
	case OP_DELETE:
		if (!iface) {
			log_error("Could not delete interface. No interface "
				  "passed in.");
			return EINVAL;
		}

		rec = idbm_create_rec(NULL, -1, NULL, -1, iface, 1);
		if (!rec) {
			rc = EINVAL;
			goto delete_fail;
		}

		/* logout and delete records using it first */
		rc = __for_each_rec(0, rec, NULL, delete_node);
		if (rc && rc != ENODEV)
			goto delete_fail;

		rc = iface_conf_delete(iface);
		if (rc)
			goto delete_fail;

		printf("%s unbound and deleted.\n", iface->name);
		break;
delete_fail:
		log_error("Could not delete iface %s. A session is "
			  "is using it or it could not be found.",
			   iface->name);
		break;
	case OP_UPDATE:
		if (!iface || !name || !value) {
			log_error("Update requires name, value, and iface.");
			rc = EINVAL;
			break;
		}

		rec = idbm_create_rec(NULL, -1, NULL, -1, iface, 1);
		if (!rec) {
			rc = EINVAL;
			goto update_fail;
		}

		if (iscsi_check_for_running_session(rec))
			log_warning("Updating iface while iscsi sessions "
				    "are using it. You must logout the running "
				    "sessions then log back in for the "
				    "new settings to take affect.");

		if (!strcmp(name, IFACE_ISCSINAME)) {
			log_error("Can not update "
				  "iface.iscsi_ifacename. Delete it, "
				  "and then create a new one.");
			rc = EINVAL;
			break;
		}

		if (iface_is_bound_by_hwaddr(&rec->iface) &&
		    !strcmp(name, IFACE_NETNAME)) {
			log_error("Can not update interface binding "
				  "from hwaddress to net_ifacename. ");
			log_error("You must delete the interface and "
				  "create a new one");
			rc = EINVAL;
			break;
		}

		if (iface_is_bound_by_netdev(&rec->iface) &&
		    !strcmp(name, IFACE_HWADDR)) {
			log_error("Can not update interface binding "
				  "from net_ifacename to hwaddress. ");
			log_error("You must delete the interface and "
				  "create a new one");
			rc = EINVAL;
			break;
		}
		set_param.name = name;
		set_param.value = value;

		/* pass rec's iface because it has the db values */
		rc = iface_conf_update(&set_param, &rec->iface);
		if (rc)
			goto update_fail;

		rc = __for_each_rec(0, rec, &set_param, idbm_node_set_param);
		if (rc && rc != ENODEV)
			goto update_fail;

		printf("%s updated.\n", iface->name);
		break;
update_fail:
		log_error("Could not update iface %s. A session is "
			  "is using it or it could not be found.",
			  iface->name);
		break;
	default:
		if (!iface || (iface && info_level > 0)) {
			if (op == OP_NOOP || op == OP_SHOW)
				rc = print_ifaces(iface, info_level);
			else
				rc = EINVAL;
		} else {
			rc = iface_conf_read(iface);
			if (!rc)
				idbm_print_iface_info(&do_show, iface);
			else
				log_error("Could not read iface %s (%d).",
					  iface->name, rc);
		}
	}

	if (rec)
		free(rec);
	return rc;
}

/* TODO cleanup arguments */
static int exec_node_op(int op, int do_login, int do_logout,
			int do_show, int do_rescan, int do_stats,
			int info_level, struct node_rec *rec,
			char *name, char *value)
{
	int rc = 0;
	struct db_set_param set_param;

	if (rec)
		log_debug(2, "%s: %s:%s node [%s,%s,%d]", __FUNCTION__,
			  rec->iface.transport_name, rec->iface.name,
			  rec->name, rec->conn[0].address, rec->conn[0].port);

	if (op == OP_NEW) {
		if (add_static_recs(rec))
			rc = -1;
		goto out;
	}

	if (do_rescan) {
		if (for_each_session(rec, rescan_portal))
			rc = -1;
		goto out;
	}

	if (do_stats) {
		if (for_each_session(rec, session_stats))
			rc = -1;
		goto out;
	}

	if (do_login && do_logout) {
		log_error("either login or logout at the time allowed!");
		rc = -1;
		goto out;
	}

	if ((do_login || do_logout) && op > OP_NOOP) {
		log_error("either operation or login/logout "
			  "at the time allowed!");
		rc = -1;
		goto out;
	}

	if ((!do_login && !do_logout && op == OP_NOOP) &&
	    (!strlen(rec->name) && !strlen(rec->conn[0].address) &&
	     !strlen(rec->iface.name))) {
		rc = print_nodes(info_level, rec);
		goto out;
	}

	if (do_login) {
		if (login_portals(rec))
			rc = -1;
		goto out;
	}

	if (do_logout) {
		int nr_found;

		if (iscsi_logout_portals(rec, &nr_found, 1,
					 iscsi_logout_matched_portal))
			rc = -1;
		goto out;
	}

	if (op == OP_NOOP || (!do_login && !do_logout && op == OP_SHOW)) {
		if (for_each_rec(rec, &do_show, idbm_print_node_info))
			rc = -1;
		goto out;
	}

	if (op == OP_UPDATE) {
		if (!name || !value) {
			log_error("update requires name and value");
			rc = -1;
			goto out;
		}

		/* compat - old tools used node and iface transport name */
		if (!strncmp(name, "iface.", 6) &&
		     strcmp(name, "iface.transport_name")) {
			log_error("Cannot modify %s. Use iface mode to update "
				  "this value.", name);
			rc = -1;
			goto out;
		}

		if (!strcmp(name, "node.transport_name"))
			name = "iface.transport_name";
		/*
		 * tmp hack - we added compat crap above for the transport,
		 * but want to fix Doran's issue in this release too. However
		 * his patch is too harsh on many settings and we do not have
		 * time to update apps so we have this tmp hack until we
		 * can settle on a good interface that distros can use
		 * and we can mark stable.
		 */
		if (!strcmp(name, "iface.transport_name")) {
			if (iscsi_check_for_running_session(rec)) {
				log_warning("Cannot modify node/iface "
					    "transport name while a session "
					    "is using it. Log out the session "
					    "then update record.");
				rc = -1;
				goto out;
			}
		}

		set_param.name = name;
		set_param.value = value;

		if (for_each_rec(rec, &set_param, idbm_node_set_param))	
			rc = -1;
		goto out;
	} else if (op == OP_DELETE) {
		if (for_each_rec(rec, NULL, delete_node))
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

static int exec_fw_disc_op(discovery_rec_t *drec, struct list_head *ifaces,
			   int info_level, int do_login, int op)
{
	struct list_head targets, rec_list, new_ifaces;
	struct iface_rec *iface, *tmp_iface;
	struct node_rec *rec, *tmp_rec;
	int rc = 0;

	INIT_LIST_HEAD(&targets);
	INIT_LIST_HEAD(&rec_list);
	INIT_LIST_HEAD(&new_ifaces);
	/*
	 * compat: if the user did not pass any op then we do all
	 * ops for them
	 */
	if (!op)
		op = OP_NEW | OP_DELETE | OP_UPDATE;

	/*
	 * if a user passed in ifaces then we use them and ignore the ibft
	 * net info
	 */
	if (!list_empty(ifaces)) {
		list_for_each_entry_safe(iface, tmp_iface, ifaces, list) {
			rc = iface_conf_read(iface);
			if (rc) {
				log_error("Could not read iface info for %s. "
					  "Make sure a iface config with the "
					  "file name and iface.iscsi_ifacename "
					  "%s is in %s.", iface->name,
					  iface->name, IFACE_CONFIG_DIR);
				list_del_init(&iface->list);
				free(iface);
				continue;
			}
		}
		goto discover_fw_tgts;
	}

	/*
	 * Next, check if we see any offload cards. If we do then
	 * we make a iface if needed.
	 *
	 * Note1: if there is not a offload card we do not setup
	 * software iscsi binding with the nic used for booting,
	 * because we do not know if that was intended.
	 *
	 * Note2: we assume that the user probably wanted to access
	 * all targets through all the ifaces instead of being limited
	 * to what you can export in ibft.
	 */
	rc = fw_get_targets(&targets);
	if (rc) {
		log_error("Could not get list of targets from firmware. "
			  "(err %d)\n", rc);
		return rc;
	}
	rc = iface_create_ifaces_from_boot_contexts(&new_ifaces, &targets);
	if (rc)
		goto done;
	if (!list_empty(&new_ifaces))
		ifaces = &new_ifaces;

discover_fw_tgts:
	rc = idbm_bind_ifaces_to_nodes(discovery_fw, drec,
				       ifaces, &rec_list);
	if (rc)
		log_error("Could not perform fw discovery.\n");
	else
		rc = exec_disc_op_on_recs(drec, &rec_list, info_level,
					   do_login, op);

done:
	fw_free_targets(&targets);

	list_for_each_entry_safe(iface, tmp_iface, &new_ifaces, list) {
		list_del(&iface->list);
		free(iface);
	}

	list_for_each_entry_safe(rec, tmp_rec, &rec_list, list) {
		list_del(&rec->list);
		free(rec);
	}
	return rc;
}

static int exec_fw_op(discovery_rec_t *drec, struct list_head *ifaces,
		      int info_level, int do_login, int op)
{
	struct boot_context *context;
	struct list_head targets, rec_list;
	struct node_rec *rec;
	int rc = 0;

	INIT_LIST_HEAD(&targets);
	INIT_LIST_HEAD(&rec_list);

	if (drec)
		return exec_fw_disc_op(drec, ifaces, info_level, do_login, op);

	/* The following ops do not interact with the DB */
	rc = fw_get_targets(&targets);
	if (rc) {
		log_error("Could not get list of targets from firmware. "
			  "(err %d)\n", rc);
		return rc;
	}

	if (do_login) {
		list_for_each_entry(context, &targets, list) {
			rec = idbm_create_rec_from_boot_context(context);
			if (!rec) {
				log_error("Could not convert firmware info to "
					  "node record.\n");
				rc = ENOMEM;
				break;
			}

			iscsi_login_portal(NULL, NULL, rec);
			free(rec);
		}
	} else {
		list_for_each_entry(context, &targets, list)
			fw_print_entry(context);
	}

	fw_free_targets(&targets);
	return rc;
}

int
main(int argc, char **argv)
{
	char *ip = NULL, *name = NULL, *value = NULL;
	char *targetname = NULL, *group_session_mgmt_mode = NULL;
	int ch, longindex, mode=-1, port=-1, do_login=0, do_rescan=0;
	int rc=0, sid=-1, op=OP_NOOP, type=-1, do_logout=0, do_stats=0;
	int do_login_all=0, do_logout_all=0, info_level=-1, num_ifaces = 0;
	int tpgt = PORTAL_GROUP_TAG_UNKNOWN, killiscsid=-1, do_show=0;
	struct sigaction sa_old;
	struct sigaction sa_new;
	discovery_rec_t drec;
	struct list_head ifaces;
	struct iface_rec *iface = NULL, *tmp;
	struct node_rec *rec = NULL;
	uint32_t host_no = -1;

	memset(&drec, 0, sizeof(discovery_rec_t));
	INIT_LIST_HEAD(&ifaces);
	/* do not allow ctrl-c for now... */
	memset(&sa_old, 0, sizeof(struct sigaction));
	memset(&sa_new, 0, sizeof(struct sigaction));

	sa_new.sa_handler = catch_sigint;
	sigemptyset(&sa_new.sa_mask);
	sa_new.sa_flags = 0;
	sigaction(SIGINT, &sa_new, &sa_old );

	umask(0177);

	/* enable stdout logging */
	log_init(program_name, 1024, log_do_log_stderr, NULL);
	sysfs_init();

	optopt = 0;
	while ((ch = getopt_long(argc, argv, short_options,
				 long_options, &longindex)) >= 0) {
		switch (ch) {
		case 'k':
			killiscsid = atoi(optarg);
			if (killiscsid < 0) {
				log_error("Invalid killiscsid priority %d "
					  "Priority must be greater than or "
					  "equal to zero.", killiscsid);
				rc = -1;
				goto free_ifaces;
			}
			break;
		case 't':
			type = str_to_type(optarg);
			break;
		case 'o':
			op |= str_to_op(optarg);
			if (op == OP_NOOP) {
				log_error("can not recognize operation: '%s'",
					optarg);
				rc = -1;
				goto free_ifaces;
			}
			break;
		case 'n':
			name = optarg;
			break;
		case 'v':
			value = optarg;
			break;
		case 'H':
			errno = 0;
			host_no = strtoul(optarg, NULL, 10);
			if (errno) {
				log_error("invalid host no %s. %s.",
					  optarg, strerror(errno));
				rc = -1;
				goto free_ifaces;
			}
			break;
		case 'r':
			sid = iscsi_sysfs_get_sid_from_path(optarg);
			if (sid < 0) {
				log_error("invalid sid '%s'",
					  optarg);
				rc = -1;
				goto free_ifaces;
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
			ip = str_to_ipport(optarg, &port, &tpgt);
			break;
		case 'I':
			iface = iface_alloc(optarg, &rc);
			if (rc == EINVAL) {
				printf("Invalid iface name %s. Must be from "
					"1 to %d characters.\n",
					optarg, ISCSI_MAX_IFACE_LEN - 1);
				rc = -1;
				goto free_ifaces;
			} else if (!iface || rc) {
				printf("Could not add iface %s.", optarg);
				rc = -1;
				goto free_ifaces;
			}

			list_add_tail(&iface->list, &ifaces);
			num_ifaces++;
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
		rc = -1;
		goto free_ifaces;
	}

	if (killiscsid >= 0) {
		kill_iscsid(killiscsid);
		goto free_ifaces;
	}

	if (mode < 0)
		usage(0);

	if (mode == MODE_FW) {
		if ((rc = verify_mode_params(argc, argv, "ml", 0))) {
			log_error("fw mode: option '-%c' is not "
				  "allowed/supported", rc);
			rc = -1;
			goto free_ifaces;
		}

		rc = exec_fw_op(NULL, NULL, info_level, do_login, op);
		goto free_ifaces;
	}

	increase_max_files();
	if (idbm_init(get_config_file)) {
		log_warning("exiting due to idbm configuration error");
		rc = -1;
		goto free_ifaces;
	}

	if (mode != MODE_DISCOVERY && ip)
		port = ISCSI_LISTEN_PORT;

	switch (mode) {
	case MODE_HOST:
		if ((rc = verify_mode_params(argc, argv, "HdmP", 0))) {
			log_error("host mode: option '-%c' is not "
				  "allowed/supported", rc);
			rc = -1;
			goto out;
		}

		rc = host_info_print(info_level, host_no);
		break;
	case MODE_IFACE:
		iface_setup_host_bindings();

		if ((rc = verify_mode_params(argc, argv, "IdnvmPo", 0))) {
			log_error("iface mode: option '-%c' is not "
				  "allowed/supported", rc);
			rc = -1;
			goto out;
		}

		if (!list_empty(&ifaces)) {
			iface = list_entry(ifaces.next, struct iface_rec,
					   list);
			if (num_ifaces > 1)
				log_error("iface mode only accepts one "
					  "interface. Using the first one "
					  "%s.", iface->name);
		}
		rc = exec_iface_op(op, do_show, info_level, iface,
				   name, value);
		break;
	case MODE_DISCOVERY:
		if ((rc = verify_mode_params(argc, argv, "SIPdmntplov", 0))) {
			log_error("discovery mode: option '-%c' is not "
				  "allowed/supported", rc);
			rc = -1;
			goto out;
		}
		switch (type) {
		case DISCOVERY_TYPE_SENDTARGETS:
			if (port < 0)
				port = ISCSI_LISTEN_PORT;

			if (ip == NULL) {
				log_error("please specify right portal as "
					  "<ipaddr>[:<ipport>]");
				rc = -1;
				goto out;
			}

			if (idbm_discovery_read(&drec, ip, port)) {
				idbm_sendtargets_defaults(&drec.u.sendtargets);
				strlcpy(drec.address, ip, sizeof(drec.address));
				drec.port = port;
			}

			if (do_sendtargets(&drec, &ifaces, info_level,
					   do_login, op)) {
				rc = -1;
				goto out;
			}
			break;
		case DISCOVERY_TYPE_SLP:
			log_error("SLP discovery is not fully "
				  "implemented yet.");
			rc = -1;
			break;
		case DISCOVERY_TYPE_ISNS:
			if (!ip) {
				log_error("please specify right portal as "
					  "<ipaddr>:[<ipport>]");
				rc = -1;
				goto out;
			}

			strlcpy(drec.address, ip, sizeof(drec.address));
			if (port < 0)
				drec.port = ISNS_DEFAULT_PORT;
			else
				drec.port = port;

			if (do_isns(&drec, &ifaces, info_level, do_login, op)) {
				rc = -1;
				goto out;
			}
			break;
		case DISCOVERY_TYPE_FW:
			drec.type = DISCOVERY_TYPE_FW;
			if (exec_fw_op(&drec, &ifaces, info_level, do_login,
					op))
				rc = -1;
			break;
		default:
			if (ip) {
				if (idbm_discovery_read(&drec, ip, port)) {
					log_error("discovery record [%s,%d] "
						  "not found!", ip, port);
					rc = -1;
					goto out;
				}
				if (do_login &&
				    drec.type == DISCOVERY_TYPE_SENDTARGETS) {
					do_sendtargets(&drec, &ifaces,
							info_level, do_login,
							op);
				} else if (do_login &&
					   drec.type == DISCOVERY_TYPE_SLP) {
					log_error("SLP discovery is not fully "
						  "implemented yet.");
					rc = -1;
					goto out;
				} else if (do_login &&
					   drec.type == DISCOVERY_TYPE_ISNS) {
					log_error("iSNS discovery is not fully "
						  "implemented yet.");
					rc = -1;
					goto out;
				} else if (op == OP_NOOP || op == OP_SHOW) {
					if (!idbm_print_discovery_info(&drec,
								do_show)) {
						log_error("no records found!");
						rc = -1;
					}
				} else if (op == OP_DELETE) {
					if (idbm_delete_discovery(&drec)) {
						log_error("unable to delete "
							   "record!");
						rc = -1;
					}
				} else if (op == OP_UPDATE) {
					struct db_set_param set_param;

					if (!name || !value) {
						log_error("Update requires "
							  "name and value");
						rc = -1;
						goto out;
					}
					set_param.name = name;
					set_param.value = value;
					if (idbm_discovery_set_param(&set_param,
								     &drec))
						rc = -1;
				} else {
					log_error("operation is not supported.");
					rc = -1;
					goto out;
				}

			} else if (op == OP_NOOP || op == OP_SHOW) {
				if (!idbm_print_all_discovery(info_level))
					rc = -1;
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
			/* fall through */
		}
		break;
	case MODE_NODE:
		if ((rc = verify_mode_params(argc, argv, "RsPIdmlSonvupTUL",
					     0))) {
			log_error("node mode: option '-%c' is not "
				  "allowed/supported", rc);
			rc = -1;
			goto out;
		}

		if (do_login_all) {
			rc = login_by_startup(group_session_mgmt_mode);
			goto out;
		}

		if (do_logout_all) {
			rc = logout_by_startup(group_session_mgmt_mode);
			goto out;
		}

		if (!list_empty(&ifaces)) {
			iface = list_entry(ifaces.next, struct iface_rec,
					   list);
			if (num_ifaces > 1)
				log_error("NODE mode only accepts one "
					  "interface. Using the first one "
					  "driver %s hwaddress %s ipaddress "
					  "%s.", iface->transport_name,
					  iface->hwaddress, iface->ipaddress);
		}

		rec = idbm_create_rec(targetname, tpgt, ip, port, iface, 1);
		if (!rec) {
			rc = -1;
			goto out;
		}

		rc = exec_node_op(op, do_login, do_logout, do_show,
				  do_rescan, do_stats, info_level, rec,
				  name, value);
		break;
	case MODE_SESSION:
		if ((rc = verify_mode_params(argc, argv,
					      "PiRdrmusonuSv", 1))) {
			log_error("session mode: option '-%c' is not "
				  "allowed or supported", rc);
			rc = -1;
			goto out;
		}
		if (sid >= 0) {
			char session[64];
			struct session_info *info;

			snprintf(session, 63, "session%d", sid);
			session[63] = '\0';

			info = calloc(1, sizeof(*info));
			if (!info) {
				rc = ENOMEM;
				goto out;
			}

			rc = iscsi_sysfs_get_sessioninfo_by_id(info, session);
			if (rc) {
				log_error("Could not get session info for sid "
					  "%d", sid);
				goto free_info;
			}

			/*
			 * We should be able to go on, but for now
			 * we only support session mode ops if the module
			 * is loaded and we support that module.
			 */
			if (!iscsi_sysfs_get_transport_by_sid(sid))
				goto free_info;

			if (!do_logout && !do_rescan && !do_stats &&
			    op == OP_NOOP && info_level > 0) {
				rc = session_info_print(info_level, info);
				if (rc)
					rc = -1;
				goto free_info;
			}

			rec = idbm_create_rec(info->targetname,
					      info->tpgt,
					      info->persistent_address,
					      info->persistent_port,
					      &info->iface, 1);
			if (!rec) {
				rc = -1;
				goto free_info;
			}

			/* drop down to node ops */
			rc = exec_node_op(op, do_login, do_logout, do_show,
					  do_rescan, do_stats, info_level,
					  rec, name, value);
free_info:
			free(info);
			goto out;
		} else {
			if (do_logout || do_rescan || do_stats) {
				rc = exec_node_op(op, do_login, do_logout,
						 do_show, do_rescan, do_stats,
						 info_level, NULL, name, value);
				goto out;
			}

			rc = session_info_print(info_level, NULL);
		}
		break;
	default:
		log_error("This mode is not yet supported");
		/* fall through */
	}

out:
	if (rec)
		free(rec);
	idbm_terminate();
free_ifaces:
	list_for_each_entry_safe(iface, tmp, &ifaces, list) {
		list_del(&iface->list);
		free(iface);
	}
	free_transports();
	sysfs_cleanup();
	return rc;
}
