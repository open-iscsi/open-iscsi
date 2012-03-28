/*
 * iSCSI Administration Utility
 *
 * Copyright (C) 2004 Dmitry Yusupov, Alex Aizman
 * Copyright (C) 2006 Mike Christie
 * Copyright (C) 2006 Red Hat, Inc. All rights reserved.
 * Copyright (C) 2011 Dell Inc.
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
#include <time.h>
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
#include "iscsi_err.h"
#include "iscsi_ipc.h"
#include "iscsi_timer.h"

static char program_name[] = "iscsiadm";
static char config_file[TARGET_NAME_MAXLEN];
extern struct iscsi_ipc *ipc;

enum iscsiadm_mode {
	MODE_DISCOVERY,
	MODE_DISCOVERYDB,
	MODE_NODE,
	MODE_SESSION,
	MODE_HOST,
	MODE_IFACE,
	MODE_FW,
	MODE_PING,
	MODE_CHAP
};

enum iscsiadm_op {
	OP_NOOP			= 0x0,
	OP_NEW			= 0x1,
	OP_DELETE		= 0x2,
	OP_UPDATE		= 0x4,
	OP_SHOW			= 0x8,
	OP_NONPERSISTENT	= 0x10,
	OP_APPLY		= 0x20,
	OP_APPLY_ALL		= 0x40
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
	{"discover", no_argument, NULL, 'D'},
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
	{"submode", required_argument, NULL, 'C'},
	{"ip", required_argument, NULL, 'a'},
	{"packetsize", required_argument, NULL, 'b'},
	{"count", required_argument, NULL, 'c'},
	{"interval", required_argument, NULL, 'i'},
	{NULL, 0, NULL, 0},
};
static char *short_options = "RlDVhm:a:b:c:C:p:P:T:H:i:I:U:k:L:d:r:n:v:o:sSt:u";

static void usage(int status)
{
	if (status != 0)
		fprintf(stderr, "Try `%s --help' for more information.\n",
			program_name);
	else {
		printf("\
iscsiadm -m discoverydb [ -hV ] [ -d debug_level ] [-P printlevel] [ -t type -p ip:port -I ifaceN ... [ -Dl ] ] | [ [ -p ip:port -t type] \
[ -o operation ] [ -n name ] [ -v value ] [ -lD ] ] \n\
iscsiadm -m discovery [ -hV ] [ -d debug_level ] [-P printlevel] [ -t type -p ip:port -I ifaceN ... [ -l ] ] | [ [ -p ip:port ] [ -l | -D ] ] \n\
iscsiadm -m node [ -hV ] [ -d debug_level ] [ -P printlevel ] [ -L all,manual,automatic ] [ -U all,manual,automatic ] [ -S ] [ [ -T targetname -p ip:port -I ifaceN ] [ -l | -u | -R | -s] ] \
[ [ -o  operation  ] [ -n name ] [ -v value ] ]\n\
iscsiadm -m session [ -hV ] [ -d debug_level ] [ -P  printlevel] [ -r sessionid | sysfsdir [ -R | -u | -s ] [ -o operation ] [ -n name ] [ -v value ] ]\n\
iscsiadm -m iface [ -hV ] [ -d debug_level ] [ -P printlevel ] [ -I ifacename | -H hostno|MAC ] [ [ -o  operation  ] [ -n name ] [ -v value ] ] [ -C ping [ -a ip ] [ -b packetsize ] [ -c count ] [ -i interval ] ]\n\
iscsiadm -m fw [ -l ]\n\
iscsiadm -m host [ -P printlevel ] [ -H hostno|MAC ] [ -C chap [ -o operation ] [ -v chap_tbl_idx ] ]\n\
iscsiadm -k priority\n");
	}
	exit(status);
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
	else if (!strcmp("apply", str))
		op = OP_APPLY;
	else if (!strcmp("applyall", str))
		op = OP_APPLY_ALL;
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
	else if (!strcmp("discoverydb", str))
		mode = MODE_DISCOVERYDB;
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
str_to_submode(char *str)
{
	int sub_mode;

	if (!strcmp("ping", str))
		sub_mode = MODE_PING;
	else if (!strcmp("chap", str))
		sub_mode = MODE_CHAP;
	else
		sub_mode = -1;

	return sub_mode;
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
		iscsi_err_print_msg(rc);
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
		return ISCSI_ERR_INVAL;
	}

	if (!num_found) {
		log_error("No interfaces found.");
		err = ISCSI_ERR_NO_OBJS_FOUND;
	}
	return err;
}

static int
match_startup_mode(node_rec_t *rec, char *mode)
{
	if ((!strcmp(mode, "automatic") &&
	    rec->startup == ISCSI_STARTUP_AUTOMATIC) ||
	    (!strcmp(mode, "onboot") &&
	    rec->startup == ISCSI_STARTUP_ONBOOT) ||
	    (!strcmp(mode, "manual") &&
	    rec->startup == ISCSI_STARTUP_MANUAL) ||
	    !strcmp(mode, "all"))
		return 0;

	/* support conn or session startup params */
	if ((!strcmp(mode, "automatic") &&
	    rec->conn[0].startup == ISCSI_STARTUP_AUTOMATIC) ||
	    (!strcmp(mode, "onboot") &&
	    rec->conn[0].startup == ISCSI_STARTUP_ONBOOT) ||
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

	if (rec && rec->session.info) {
		num_found = 1;
		err = fn(rec, rec->session.info);
	} else {
		err = iscsi_sysfs_for_each_session(rec, &num_found, fn);
	}
	if (err)
		log_error("Could not execute operation on all sessions: %s",
			  iscsi_err_to_str(err));
	else if (!num_found) {
		log_error("No session found.");
		err = ISCSI_ERR_NO_OBJS_FOUND;
	}

	return err;
}

static int link_recs(void *data, struct node_rec *rec)
{
	struct list_head *list = data;
	struct node_rec *rec_copy;

	rec_copy = calloc(1, sizeof(*rec_copy));
	if (!rec_copy)
		return ISCSI_ERR_NOMEM;
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

	if (match_startup_mode(&rec, mode))
		return -1;

	return iscsi_logout_portal(info, list);
}

static int
logout_by_startup(char *mode)
{
	int nr_found;
	int rc;

	if (!mode || !(!strcmp(mode, "automatic") || !strcmp(mode, "all") ||
	    !strcmp(mode,"manual"))) {
		log_error("Invalid logoutall option %s.", mode);
		usage(ISCSI_ERR_INVAL);
		return ISCSI_ERR_INVAL;
	}

	rc = iscsi_logout_portals(mode, &nr_found, 1, __logout_by_startup);
	if (rc == ISCSI_ERR_NO_OBJS_FOUND)
		log_error("No matching sessions found");
	return rc; 
}

struct startup_data {
	char *mode;
	struct list_head all_logins;
	struct list_head leading_logins;
};

static int link_startup_recs(void *data, struct node_rec *rec)
{
	struct startup_data *startup = data;
	struct node_rec *rec_copy;

	if (match_startup_mode(rec, startup->mode))
		return -1;

	rec_copy = calloc(1, sizeof(*rec_copy));
	if (!rec_copy)
		return ISCSI_ERR_NOMEM;
	memcpy(rec_copy, rec, sizeof(*rec_copy));
	INIT_LIST_HEAD(&rec_copy->list);

	if (rec_copy->leading_login)
		list_add_tail(&rec_copy->list, &startup->leading_logins);
	else
		list_add_tail(&rec_copy->list, &startup->all_logins);
	return 0;
}

static int
__do_leading_login(void *data, struct list_head *list, struct node_rec *rec)
{
	struct iface_rec *pattern_iface = data;
	int nr_found;

	/* Skip any records that do not match the pattern iface */
	if (!iface_match(pattern_iface, &rec->iface))
		return -1;

	/*
	 * If there is an existing session that matcthes the target,
	 * the leading login is complete.
	 */
	if (iscsi_sysfs_for_each_session(rec, &nr_found, iscsi_match_target)) {
		log_debug(1, "Skipping %s: Already a session for that target",
			  rec->name);
		return -1;
	}

	/* No existing session: Attempt a login. */
	return iscsi_login_portal(NULL, list, rec);
}

static int
login_by_startup(char *mode)
{
	int nr_found = 0, err, rc;
	struct startup_data startup;

	if (!mode || !(!strcmp(mode, "automatic") || !strcmp(mode, "all") ||
		       !strcmp(mode,"manual") || !strcmp(mode, "onboot"))) {
		log_error("Invalid loginall option %s.", mode);
		usage(ISCSI_ERR_INVAL);
		return ISCSI_ERR_INVAL;
	}

	/*
	 * Filter all node records that match the given 'mode' into 2 lists:
	 * Those with leading_login enabled, and those without.
	 */
	startup.mode = mode;
	INIT_LIST_HEAD(&startup.all_logins);
	INIT_LIST_HEAD(&startup.leading_logins);
	err = idbm_for_each_rec(&nr_found, &startup, link_startup_recs);
	if (err && (!list_empty(&startup.all_logins) ||
		    !list_empty(&startup.leading_logins)))
		/* log msg and try to log into what we found */
		log_error("Could not read all records: %s",
			  iscsi_err_to_str(err));
	else if (list_empty(&startup.all_logins) &&
		 list_empty(&startup.leading_logins)) {
		if (err) {
			log_error("Could not read node DB: %s.",
				  iscsi_err_to_str(err));
		} else {
			log_error("No records found");
			err = ISCSI_ERR_NO_OBJS_FOUND;
		}
		return err;
	}
	rc = err;

	if (!list_empty(&startup.all_logins)) {
		log_debug(1, "Logging into normal (non-leading-login) portals");
		/* Login all regular (non-leading-login) portals first */
		err = iscsi_login_portals(NULL, &nr_found, 1,
				&startup.all_logins, iscsi_login_portal);
		if (err)
			log_error("Could not log into all portals");
		if (err && !rc)
			rc = err;
	}

	if (!list_empty(&startup.leading_logins)) {
		/*
		 * For each iface in turn, try to login all portals on that
		 * iface that do not already have a session present.
		 */
		struct iface_rec *pattern_iface, *tmp_iface;
		struct node_rec *rec, *tmp_rec;
		struct list_head iface_list;
		int missed_leading_login = 0;
		log_debug(1, "Logging into leading-login portals");
		INIT_LIST_HEAD(&iface_list);
		iface_link_ifaces(&iface_list);
		list_for_each_entry_safe(pattern_iface, tmp_iface, &iface_list,
					 list) {
			log_debug(1, "Establishing leading-logins via iface %s",
				  pattern_iface->name);
			err = iscsi_login_portals_safe(pattern_iface, &nr_found,
						       1,
						       &startup.leading_logins,
						       __do_leading_login);
			if (err)
				log_error("Could not log into all portals on "
					  "%s, trying next interface",
					  pattern_iface->name);

			/*
			 * Note: We always try all iface records in case there
			 * are targets that are associated with only a subset
			 * of iface records.  __do_leading_login already
			 * prevents duplicate sessions if an iface has succeded
			 * for a particular target.
			 */
		}
		/*
		 * Double-check that all leading-login portals have at least
		 * one session
		 */
		list_for_each_entry_safe(rec, tmp_rec, &startup.leading_logins,
					 list) {
			if (!iscsi_sysfs_for_each_session(rec, &nr_found,
							  iscsi_match_target))
				missed_leading_login++;
			/*
			 * Cleanup the list, since 'iscsi_login_portals_safe'
			 * does not
			 */
			list_del(&rec->list);
			free(rec);
		}
		if (missed_leading_login) {
			log_error("Could not login all leading-login portals");
			if (!rc)
				rc = ISCSI_ERR_FATAL_LOGIN;
		}
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

	return iscsi_logout_portal(info, list);
}

static int rec_match_fn(void *data, node_rec_t *rec)
{
	struct rec_op_data *op_data = data;

	if (!__iscsi_match_session(op_data->match_rec, rec->name,
				   rec->conn[0].address, rec->conn[0].port,
				   &rec->iface, rec->session.sid))
		return -1;
	return op_data->fn(op_data->data, rec);
}

static int __for_each_matched_rec(int verbose, struct node_rec *rec,
				  void *data, idbm_iface_op_fn *fn)
{
	struct rec_op_data op_data;
	int nr_found = 0, rc;

	memset(&op_data, 0, sizeof(struct rec_op_data));
	op_data.data = data;
	op_data.match_rec = rec;
	op_data.fn = fn;

	rc = idbm_for_each_rec(&nr_found, &op_data, rec_match_fn);
	if (rc) {
		if (verbose)
			log_error("Could not execute operation on all "
				  "records: %s", iscsi_err_to_str(rc));
	} else if (!nr_found) {
		if (verbose)
			log_error("No records found");
		rc = ISCSI_ERR_NO_OBJS_FOUND;
	}

	return rc;
}

static int for_each_matched_rec(struct node_rec *rec, void *data,
			        idbm_iface_op_fn *fn)
{
	return __for_each_matched_rec(1, rec, data, fn);
}


static int login_portals(struct node_rec *pattern_rec)
{
	struct list_head rec_list;
	int nr_found, rc, err;

	INIT_LIST_HEAD(&rec_list);
	err = for_each_matched_rec(pattern_rec, &rec_list, link_recs);
	if (err == ISCSI_ERR_NO_OBJS_FOUND)
		return err;
	else if (err && list_empty(&rec_list))
		return err;

	rc = err;
	/* if there is an err but some recs then try to login to what we have */

	err = iscsi_login_portals(pattern_rec, &nr_found, 1, &rec_list,
				  iscsi_login_portal);
	if (err)
		log_error("Could not log into all portals");

	if (err && !rc)
		rc = err;

	return rc;
}

static int print_nodes(int info_level, struct node_rec *rec)
{
	struct node_rec tmp_rec;
	int rc = 0;

	switch (info_level) {
	case 0:
	case -1:
		rc = for_each_matched_rec(rec, NULL, idbm_print_node_flat);
		break;
	case 1:
		memset(&tmp_rec, 0, sizeof(node_rec_t));
		rc = for_each_matched_rec(rec, &tmp_rec,
					  idbm_print_node_and_iface_tree);
		break;
	default:
		log_error("Invalid info level %d. Try 0 or 1.", info_level);
		rc = ISCSI_ERR_INVAL;
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
		return rc;

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
		rc = ISCSI_ERR_NOMEM;
		goto done;
	}

	drec = calloc(1, sizeof(*drec));
	if (!drec) {
		log_error("Could not allocate memory for node addition");
		rc = ISCSI_ERR_NOMEM;
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
		return -1;

	if (rec->conn[0].port != -1 && rec->conn[0].port != port)
		return -1;

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
		return -1;

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
	if (rc)
		goto done;
	/* success */
	if (nr_found > 0)
		return 0;

	/* brand new target */
	if (strlen(rec->name) && strlen(rec->conn[0].address)) {
		rc = add_static_rec(&nr_found, rec->name, rec->tpgt,
				    rec->conn[0].address, rec->conn[0].port,
				    &rec->iface);
		if (!rc)
			return 0;
	}
done:
	log_error("Error while adding record: %s", iscsi_err_to_str(rc));
	return rc;
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
		return ISCSI_ERR_SESS_EXISTS;
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
			return -1;

		if (__iscsi_match_session(rec,
					  new_rec->name,
					  new_rec->conn[0].address,
					  new_rec->conn[0].port,
					  &new_rec->iface,
					  new_rec->session.sid))
			return -1;
	}
	/* if there is a error we can continue on */
	return delete_node(NULL, rec);
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
		        int info_level, int do_login, int op, int sync_drec)
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
	if ((!(op & OP_NONPERSISTENT)) && sync_drec) {
		rc = idbm_add_discovery(drec);
		if (rc) {
			log_error("Could not add new discovery record.");
			return rc;
		}
	}

	rc = idbm_bind_ifaces_to_nodes(discovery_sendtargets, drec, ifaces,
				       &rec_list);
	if (rc) {
		log_error("Could not perform SendTargets discovery: %s",
			  iscsi_err_to_str(rc));
		return rc;
	} else if (list_empty(&rec_list)) {
		log_error("No portals found");
		return ISCSI_ERR_NO_OBJS_FOUND;
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
	       int info_level, int do_login, int op, int sync_drec)
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
		/* check for transport name first to make sure it is loaded */
		t = iscsi_sysfs_get_transport_by_name(iface->transport_name);
		if (!t) {
			log_error("Could not load transport %s."
				  "Dropping interface %s.",
				   iface->transport_name, iface->name);
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

		if (t->caps & CAP_SENDTARGETS_OFFLOAD) {
			do_offload_sendtargets(drec, host_no, do_login);
			list_del(&iface->list);
			free(iface);
		}
	}

	if (list_empty(ifaces))
		return ISCSI_ERR_NO_OBJS_FOUND;

sw_st:
	return do_software_sendtargets(drec, ifaces, info_level, do_login,
				       op, sync_drec);
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
		log_error("Could not perform iSNS discovery: %s",
			  iscsi_err_to_str(rc));
		return rc;
	} else if (list_empty(&rec_list)) {
		log_error("No portals found");
		return ISCSI_ERR_NO_OBJS_FOUND;
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

static int iface_apply_net_config(struct iface_rec *iface, int op)
{
	int rc = ISCSI_ERR;
	uint32_t host_no;
	int param_count;
	int param_used;
	int iface_all = 0;
	int i;
	struct iovec *iovs = NULL;
	struct iovec *iov = NULL;
	struct iscsi_transport *t = NULL;
	int fd;

	log_debug(8, "Calling iscsid, to apply net config for"
		  "iface.name = %s\n", iface->name);

	if (op == OP_APPLY_ALL)
		iface_all = 1;

	param_count = iface_get_param_count(iface, iface_all);
	if (!param_count) {
		log_error("Nothing to configure.");
		return ISCSI_SUCCESS;
	}

	/*
	 * TODO: create a nicer interface where the caller does not have
	 * know the packet/hdr details
	 */

	/* +2 for event and nlmsghdr */
	param_count += 2;
	iovs = calloc((param_count * sizeof(struct iovec)),
		       sizeof(char));
	if (!iovs) {
		log_error("Out of Memory.");
		return ISCSI_ERR_NOMEM;
	}

	/* param_used gives actual number of iovecs used for netconfig */
	param_used = iface_build_net_config(iface, iface_all, iovs);
	if (!param_used) {
		log_error("Build netconfig failed.");
		goto free_buf;
	}

	t = iscsi_sysfs_get_transport_by_name(iface->transport_name);
	if (!t) {
		log_error("Can't find transport.");
		goto free_buf;
	}

	host_no = iscsi_sysfs_get_host_no_from_hwinfo(iface, &rc);
	if (host_no == -1) {
		log_error("Can't find host_no.");
		goto free_buf;
	}
	rc = ISCSI_ERR;

	fd = ipc->ctldev_open();
	if (fd < 0) {
		log_error("Netlink open failed.");
		goto free_buf;
	}

	rc = ipc->set_net_config(t->handle, host_no, iovs, param_count);
	if (rc < 0)
		log_error("Set net_config failed. errno=%d", errno);

	ipc->ctldev_close();

free_buf:
	/* start at 2, because 0 is for nlmsghdr and 1 for event */
	iov = iovs + 2;
	for (i = 0; i < param_used; i++, iov++) {
		if (iov->iov_base)
			free(iov->iov_base);
	}

	free(iovs);
	if (rc)
		return ISCSI_ERR;
	return ISCSI_SUCCESS;
}

static int get_host_chap_info(uint32_t host_no)
{
	struct iscsi_transport *t = NULL;
	struct iscsi_chap_rec *crec = NULL;
	char *req_buf = NULL;
	uint32_t valid_chap_entries;
	uint32_t num_entries;
	uint16_t chap_tbl_idx = 0;
	int rc = 0;
	int fd, i = 0;

	t = iscsi_sysfs_get_transport_by_hba(host_no);
	if (!t) {
		log_error("Could not match hostno %d to "
			  "transport.", host_no);
		rc = ISCSI_ERR_TRANS_NOT_FOUND;
		goto exit_chap_info;
	}

	num_entries = MAX_CHAP_BUF_SZ / sizeof(*crec);

	req_buf = calloc(1, REQ_CHAP_BUF_SZ);
	if (!req_buf) {
		log_error("Could not allocate memory for CHAP request.");
		rc = ISCSI_ERR_NOMEM;
		goto exit_chap_info;
	}

	fd = ipc->ctldev_open();
	if (fd < 0) {
		rc = ISCSI_ERR_INTERNAL;
		log_error("Netlink open failed.");
		goto exit_chap_info;
	}

get_chap:
	memset(req_buf, 0, REQ_CHAP_BUF_SZ);

	rc = ipc->get_chap(t->handle, host_no, chap_tbl_idx, num_entries,
			   req_buf, &valid_chap_entries);
	if (rc < 0) {
		log_error("get_chap_info failed. errno=%d", errno);
		rc = ISCSI_ERR;
		goto exit_chap_info;
	}

	crec = (struct iscsi_chap_rec *) (req_buf +
					  sizeof(struct iscsi_uevent));

	if (valid_chap_entries)
		chap_tbl_idx =
		(crec + (valid_chap_entries - 1))->chap_tbl_idx + 1;

	/* print chap info */
	for (i = 0; i < valid_chap_entries; i++) {
		idbm_print_host_chap_info(crec);
		crec++;
	}

	if (valid_chap_entries != num_entries)
		goto exit_chap_info;
	else
		goto get_chap;

	ipc->ctldev_close();

exit_chap_info:
	if (req_buf)
		free(req_buf);

	return rc;
}

static int delete_host_chap_info(uint32_t host_no, char *value)
{
	struct iscsi_transport *t = NULL;
	int fd, rc = 0;
	uint16_t chap_tbl_idx;

	if (!value) {
		log_error("CHAP deletion requires --value=table_index.");
		return ISCSI_ERR_INVAL;
	}

	chap_tbl_idx = (uint16_t)atoi(value);

	t = iscsi_sysfs_get_transport_by_hba(host_no);
	if (!t) {
		log_error("Could not match hostno %d to "
			  "transport.", host_no);
		rc = ISCSI_ERR_TRANS_NOT_FOUND;
		goto exit_delete_chap;
	}

	fd = ipc->ctldev_open();
	if (fd < 0) {
		log_error("Netlink open failed.");
		rc = ISCSI_ERR_INTERNAL;
		goto exit_delete_chap;
	}

	log_info("Deleteing CHAP index: %d\n", chap_tbl_idx);
	rc = ipc->delete_chap(t->handle, host_no, chap_tbl_idx);
	if (rc < 0) {
		log_error("CHAP Delete failed.");
		if (rc == -EBUSY) {
			rc = ISCSI_ERR_BUSY;
			log_error("CHAP index %d is in use.", chap_tbl_idx);
		} else
			rc = ISCSI_ERR;
	}

	ipc->ctldev_close();

exit_delete_chap:
	return rc;
}

static int exec_host_chap_op(int op, int info_level, uint32_t host_no,
			     char *value)
{
	int rc = ISCSI_ERR_INVAL;

	switch (op) {
	case OP_SHOW:
		rc = get_host_chap_info(host_no);
		break;
	case OP_DELETE:
		rc = delete_host_chap_info(host_no, value);
		break;
	default:
		log_error("Invalid operation.");
		break;
	}

	return rc;
}

static int verify_iface_params(struct list_head *params, struct node_rec *rec)
{
	struct user_param *param;

	list_for_each_entry(param, params, list) {
		if (!strcmp(param->name, IFACE_ISCSINAME)) {
			log_error("Can not update "
				  "iface.iscsi_ifacename. Delete it, "
				  "and then create a new one.");
			return ISCSI_ERR_INVAL;
		}

		if (iface_is_bound_by_hwaddr(&rec->iface) &&
		    !strcmp(param->name, IFACE_NETNAME)) {
			log_error("Can not update interface binding "
				  "from hwaddress to net_ifacename. "
				  "You must delete the interface and "
				  "create a new one");
			return ISCSI_ERR_INVAL;
		}

		if (iface_is_bound_by_netdev(&rec->iface) &&
		    !strcmp(param->name, IFACE_HWADDR)) {
			log_error("Can not update interface binding "
				  "from net_ifacename to hwaddress. "
				  "You must delete the interface and "
				  "create a new one");
			return ISCSI_ERR_INVAL;
		}
	}
	return 0;
}

/* TODO: merge iter helpers and clean them up, so we can use them here */
static int exec_iface_op(int op, int do_show, int info_level,
			 struct iface_rec *iface, uint32_t host_no,
			 struct list_head *params)
{
	struct host_info hinfo;
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
			rc = ISCSI_ERR_SESS_EXISTS;
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
			return ISCSI_ERR_INVAL;
		}

		rec = idbm_create_rec(NULL, -1, NULL, -1, iface, 1);
		if (!rec) {
			rc = ISCSI_ERR_INVAL;
			goto delete_fail;
		}

		/* logout and delete records using it first */
		rc = __for_each_matched_rec(0, rec, NULL, delete_node);
		if (rc && rc != ISCSI_ERR_NO_OBJS_FOUND)
			goto delete_fail;

		rc = iface_conf_delete(iface);
		if (rc)
			goto delete_fail;

		printf("%s unbound and deleted.\n", iface->name);
		break;
delete_fail:
		log_error("Could not delete iface %s: %s", iface->name,
			  iscsi_err_to_str(rc));
		break;
	case OP_UPDATE:
		if (!iface || list_empty(params)) {
			log_error("Update requires name, value, and iface.");
			rc = ISCSI_ERR_INVAL;
			break;
		}

		rec = idbm_create_rec(NULL, -1, NULL, -1, iface, 1);
		if (!rec) {
			rc = ISCSI_ERR_INVAL;
			goto update_fail;
		}

		if (iscsi_check_for_running_session(rec))
			log_warning("Updating iface while iscsi sessions "
				    "are using it. You must logout the running "
				    "sessions then log back in for the "
				    "new settings to take affect.");

		rc = verify_iface_params(params, rec);
		if (rc)
			break;

		/* pass rec's iface because it has the db values */
		rc = iface_conf_update(params, &rec->iface);
		if (rc)
			goto update_fail;

		rc = __for_each_matched_rec(0, rec, params,
					    idbm_node_set_param);
		if (rc == ISCSI_ERR_NO_OBJS_FOUND)
			rc = 0;
		else if (rc)
			goto update_fail;

		printf("%s updated.\n", iface->name);
		break;
update_fail:
		log_error("Could not update iface %s: %s",
			  iface->name, iscsi_err_to_str(rc));
		break;
	case OP_APPLY:
		if (!iface) {
			log_error("Apply requires iface.");
			rc = ISCSI_ERR_INVAL;
			break;
		}
		rc = iface_conf_read(iface);
		if (rc) {
			log_error("Could not read iface %s (%d).",
				  iface->name, rc);
			break;
		}

		rc = iface_apply_net_config(iface, op);
		if (rc) {
			log_error("Could not apply net configuration: %s",
				  iscsi_err_to_str(rc));
			break;
		}
		printf("%s applied.\n", iface->name);
		break;
	case OP_APPLY_ALL:
		if (host_no == -1) {
			log_error("Applyall requires a host number or MAC "
				  "passed in with the --host argument.");
			rc = ISCSI_ERR_INVAL;
			break;
		}

		/*
		 * Need to get other iface info like transport.
		 */
		memset(&hinfo, 0, sizeof(struct host_info));
		hinfo.host_no = host_no;
		if (iscsi_sysfs_get_hostinfo_by_host_no(&hinfo)) {
			log_error("Could not match host%u to ifaces.", host_no);
			rc = ISCSI_ERR_INVAL;
			break;
		}
		rc = iface_apply_net_config(&hinfo.iface, op);
		if (rc) {
			log_error("Could not apply net configuration: %s",
				  iscsi_err_to_str(rc));
			break;
		}

		printf("Applied settings to ifaces attached to host%u.\n",
		       host_no);
		break;
	default:
		if (!iface || (iface && info_level > 0)) {
			if (op == OP_NOOP || op == OP_SHOW)
				rc = print_ifaces(iface, info_level);
			else
				rc = ISCSI_ERR_INVAL;
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

static int verify_node_params(struct list_head *params, struct node_rec *rec)
{
	struct user_param *param;

	if (list_empty(params)) {
		log_error("update requires name and value");
		return ISCSI_ERR_INVAL;
	}

	list_for_each_entry(param, params, list) {
		/* compat - old tools used node and iface transport name */
		if (!strncmp(param->name, "iface.", 6) &&
		     strcmp(param->name, "iface.transport_name")) {
			log_error("Cannot modify %s. Use iface mode to update "
				  "this value.", param->name);
			return ISCSI_ERR_INVAL;
		}

		if (!strcmp(param->name, "node.transport_name")) {
			free(param->name);
			param->name = strdup("iface.transport_name");
			if (!param->name) {
				log_error("Could not allocate memory for "
					  "param.");
				return ISCSI_ERR_NOMEM;
			}
		}
		/*
		 * tmp hack - we added compat crap above for the transport,
		 * but want to fix Doran's issue in this release too. However
		 * his patch is too harsh on many settings and we do not have
		 * time to update apps so we have this tmp hack until we
		 * can settle on a good interface that distros can use
		 * and we can mark stable.
		 */
		if (!strcmp(param->name, "iface.transport_name")) {
			if (iscsi_check_for_running_session(rec)) {
				log_warning("Cannot modify node/iface "
					    "transport name while a session "
					    "is using it. Log out the session "
					    "then update record.");
				return ISCSI_ERR_SESS_EXISTS;
			}
		}
	}

	return 0;
}

/* TODO cleanup arguments */
static int exec_node_op(int op, int do_login, int do_logout,
			int do_show, int do_rescan, int do_stats,
			int info_level, struct node_rec *rec,
			struct list_head *params)
{
	int rc = 0;

	if (rec)
		log_debug(2, "%s: %s:%s node [%s,%s,%d] sid %u", __FUNCTION__,
			  rec->iface.transport_name, rec->iface.name,
			  rec->name, rec->conn[0].address, rec->conn[0].port,
			  rec->session.sid);

	if (op == OP_NEW) {
		rc = add_static_recs(rec);
		goto out;
	}

	if (do_rescan) {
		rc = for_each_session(rec, rescan_portal);
		goto out;
	}

	if (do_stats) {
		rc = for_each_session(rec, session_stats);
		goto out;
	}

	if (do_login && do_logout) {
		log_error("Invalid parameters. Both login and logout passed in");
		rc = ISCSI_ERR_INVAL;
		goto out;
	}

	if ((do_login || do_logout) && op > OP_NOOP) {
		log_error("Invalid parameters. Login/logout and op passed in");
		rc = ISCSI_ERR_INVAL;
		goto out;
	}

	if ((!do_login && !do_logout && op == OP_NOOP) &&
	    (!strlen(rec->name) && !strlen(rec->conn[0].address) &&
	     !strlen(rec->iface.name))) {
		rc = print_nodes(info_level, rec);
		goto out;
	}

	if (do_login) {
		rc = login_portals(rec);
		goto out;
	}

	if (do_logout) {
		int nr_found;

		rc = iscsi_logout_portals(rec, &nr_found, 1,
					  iscsi_logout_matched_portal);
		if (rc == ISCSI_ERR_NO_OBJS_FOUND)
			log_error("No matching sessions found");
		goto out;
	}

	if (op == OP_NOOP || (!do_login && !do_logout && op == OP_SHOW)) {
		rc = for_each_matched_rec(rec, &do_show, idbm_print_node_info);
		goto out;
	}

	if (op == OP_UPDATE) {
		rc = verify_node_params(params, rec);
		if (rc)
			goto out;

		rc = for_each_matched_rec(rec, params, idbm_node_set_param);
		goto out;
	} else if (op == OP_DELETE) {
		rc = for_each_matched_rec(rec, NULL, delete_node);
		goto out;
	} else {
		log_error("operation is not supported.");
		rc = ISCSI_ERR_INVAL;
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
				rc = ISCSI_ERR_NOMEM;
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

static void setup_drec_defaults(int type, char *ip, int port,
				struct discovery_rec *drec)
{
	switch (type) {
	case DISCOVERY_TYPE_ISNS:
		idbm_isns_defaults(&drec->u.isns);
		break;
	case DISCOVERY_TYPE_SENDTARGETS:
		idbm_sendtargets_defaults(&drec->u.sendtargets);
		break;
	default:
		log_error("Invalid disc type.");
	}
	strlcpy(drec->address, ip, sizeof(drec->address));
	drec->port = port;
	drec->type = type;
}

/**
 * exec_discover - prep, add, read and exec discovery on drec
 * @type: discovery type
 * @ip: IP address
 * @port: port
 * @ifaces: list of ifaces to bind to
 * @info_level: print level
 * @do_login: set to 1 if discovery function should also log into portals found
 * @do_discover: set to 1 if discovery was requested
 * @op: ops passed in by user
 * @drec: discovery rec struct
 *
 * This function determines what type of op needs to be executed
 * and will read and add a drec, and perform discovery if needed.
 *
 * returns:
 * 	Greater than 0 - error
 * 	0 - op/discovery completed
 * 	-1 - exec db op
 */
static int exec_discover(int disc_type, char *ip, int port,
			 struct list_head *ifaces, int info_level,
			 int do_login, int do_discover, int op,
			 struct discovery_rec *drec)
{
	int rc;

	if (ip == NULL) {
		log_error("Please specify portal as <ipaddr>[:<ipport>]");
		return ISCSI_ERR_INVAL;
	}

	if (op & OP_NEW && !do_discover) {
		setup_drec_defaults(disc_type, ip, port, drec);

		rc = idbm_add_discovery(drec);
		if (rc) {
			log_error("Could not add new discovery record.");
			return rc;
		} else {
			printf("New discovery record for [%s,%d] added.\n", ip,
			       port);
			return 0;
		}
	}

	rc = idbm_discovery_read(drec, disc_type, ip, port);
	if (rc) {
		if (!do_discover) {
			log_error("Discovery record [%s,%d] not found.",
				  ip, port);
			return rc;
		}

		/* Just add default rec for user */
		log_debug(1, "Discovery record [%s,%d] not found!",
			  ip, port);
		setup_drec_defaults(disc_type, ip, port, drec);
		if (!(op & OP_NONPERSISTENT)) {
			rc = idbm_add_discovery(drec);
			if (rc) {
				log_error("Could not add new discovery "
					  "record.");
				return rc;
			}
		}
	} else if (!do_discover)
		return -1;

	rc = 0;
	switch (disc_type) {
	case DISCOVERY_TYPE_SENDTARGETS:
		/*
		 * idbm_add_discovery call above handles drec syncing so
		 * we always pass in 0 here.
		 */
		rc = do_sendtargets(drec, ifaces, info_level, do_login, op,
				    0);
		break;
	case DISCOVERY_TYPE_ISNS:
		rc = do_isns(drec, ifaces, info_level, do_login, op);
		break;
	default:
		log_error("Unsupported discovery type.");
		break;
	}

	return rc;
}

static int exec_disc2_op(int disc_type, char *ip, int port,
			 struct list_head *ifaces, int info_level, int do_login,
			 int do_discover, int op, struct list_head *params,
			 int do_show)
{
	struct discovery_rec drec;
	int rc = 0;

	memset(&drec, 0, sizeof(struct discovery_rec));
	if (disc_type != -1)
		drec.type = disc_type;

	switch (disc_type) {
	case DISCOVERY_TYPE_SENDTARGETS:
		if (port < 0)
			port = ISCSI_LISTEN_PORT;

		rc = exec_discover(disc_type, ip, port, ifaces, info_level,
				   do_login, do_discover, op, &drec);
		if (rc < 0)
			goto do_db_op;
		goto done;
	case DISCOVERY_TYPE_SLP:
		log_error("SLP discovery is not fully implemented yet.");
		rc = ISCSI_ERR_INVAL;
		goto done;
	case DISCOVERY_TYPE_ISNS:
		if (port < 0)
			port = ISNS_DEFAULT_PORT;

		rc = exec_discover(disc_type, ip, port, ifaces, info_level,
				   do_login, do_discover, op, &drec);
		if (rc < 0)
			goto do_db_op;
		goto done;
	case DISCOVERY_TYPE_FW:
		if (!do_discover) {
			log_error("Invalid command. Possibly missing "
				  "--discover argument.");
			rc = ISCSI_ERR_INVAL;
			goto done;
		}

		drec.type = DISCOVERY_TYPE_FW;
		rc = exec_fw_op(&drec, ifaces, info_level, do_login, op);
		goto done;
	default:
		rc = ISCSI_ERR_INVAL;

		if (!ip) {
			 if (op == OP_NOOP || op == OP_SHOW) {
				if (idbm_print_all_discovery(info_level))
					/* successfully found some recs */
					rc = 0;
				else
					rc = ISCSI_ERR_NO_OBJS_FOUND;
			} else
				log_error("Invalid operation. Operation not "
					  "supported.");
		} else if (op)
			log_error("Invalid command. Possibly missing discovery "
				  "--type.");
		else
			log_error("Invalid command. Portal not needed or "
				  "Possibly missing discovery --type.");
		goto done;
	}

do_db_op:
	rc = 0;

	if (op == OP_NOOP || op == OP_SHOW) {
		if (!idbm_print_discovery_info(&drec, do_show)) {
			log_error("No records found");
			rc = ISCSI_ERR_NO_OBJS_FOUND;
		}
	} else if (op == OP_DELETE) {
		rc = idbm_delete_discovery(&drec);
		if (rc)
			log_error("Unable to delete record!");
	} else if (op == OP_UPDATE) {
		if (list_empty(params)) {
			log_error("Update requires name and value.");
			rc = ISCSI_ERR_INVAL;
			goto done;
		}
		rc = idbm_discovery_set_param(params, &drec);
	} else {
		log_error("Operation is not supported.");
		rc = ISCSI_ERR_INVAL;
		goto done;
	}
done:
	return rc;
}

static int exec_disc_op(int disc_type, char *ip, int port,
			struct list_head *ifaces, int info_level, int do_login,
			int do_discover, int op, struct list_head *params,
			int do_show)
{
	struct discovery_rec drec;
	int rc = 0;

	memset(&drec, 0, sizeof(struct discovery_rec));

	switch (disc_type) {
	case DISCOVERY_TYPE_SENDTARGETS:
		drec.type = DISCOVERY_TYPE_SENDTARGETS;

		if (port < 0)
			port = ISCSI_LISTEN_PORT;

		if (ip == NULL) {
			log_error("Please specify portal as "
				  "<ipaddr>[:<ipport>]");
			rc = ISCSI_ERR_INVAL;
			goto done;
		}

		idbm_sendtargets_defaults(&drec.u.sendtargets);
		strlcpy(drec.address, ip, sizeof(drec.address));
		drec.port = port;

		rc = do_sendtargets(&drec, ifaces, info_level,
				    do_login, op, 1);
		if (rc)
			goto done;
		break;
	case DISCOVERY_TYPE_SLP:
		log_error("SLP discovery is not fully implemented yet.");
		rc = ISCSI_ERR_INVAL;
		break;
	case DISCOVERY_TYPE_ISNS:
		if (!ip) {
			log_error("Please specify portal as "
				  "<ipaddr>:[<ipport>]");
			rc = ISCSI_ERR_INVAL;
			goto done;
		}

		strlcpy(drec.address, ip, sizeof(drec.address));
		if (port < 0)
			drec.port = ISNS_DEFAULT_PORT;
		else
			drec.port = port;

		rc = do_isns(&drec, ifaces, info_level, do_login, op);
		if (rc)
			goto done;
		break;
	case DISCOVERY_TYPE_FW:
		drec.type = DISCOVERY_TYPE_FW;
		rc = exec_fw_op(&drec, ifaces, info_level, do_login, op);
		break;
	default:
		if (ip) {
			/*
			 * We only have sendtargets disc recs in discovery
			 * mode, so we can hardcode the port check to the
			 * iscsi default here.
			 *
			 * For isns or slp recs then discovery db mode
			 * must be used.
			 */
			if (port < 0)
				port = ISCSI_LISTEN_PORT;

			if (idbm_discovery_read(&drec,
						DISCOVERY_TYPE_SENDTARGETS,
						ip, port)) {
				log_error("Discovery record [%s,%d] "
					  "not found!", ip, port);
				rc = ISCSI_ERR_INVAL;
				goto done;
			}
			if ((do_discover || do_login) &&
			    drec.type == DISCOVERY_TYPE_SENDTARGETS) {
				rc = do_sendtargets(&drec, ifaces, info_level,
						    do_login, op, 0);
			} else if (op == OP_NOOP || op == OP_SHOW) {
				if (!idbm_print_discovery_info(&drec,
							       do_show)) {
					log_error("No records found");
					rc = ISCSI_ERR_NO_OBJS_FOUND;
				}
			} else if (op == OP_DELETE) {
				rc = idbm_delete_discovery(&drec);
				if (rc)
					log_error("Unable to delete record!");
			} else if (op == OP_UPDATE || op == OP_NEW) {
				log_error("Operations new and update for "
					  "discovery mode is not supported. "
					  "Use discoverydb mode.");
				rc = ISCSI_ERR_INVAL;
				goto done;
			} else {
				log_error("Invalid operation.");
				rc = ISCSI_ERR_INVAL;
				goto done;
			}
		} else if (op == OP_NOOP || op == OP_SHOW) {
			if (!idbm_print_all_discovery(info_level))
				rc = ISCSI_ERR_NO_OBJS_FOUND;
			goto done;
		} else {
			log_error("Invalid operation.");
			rc = ISCSI_ERR_INVAL;
			goto done;
		}
		/* fall through */
	}

done:
	return rc;
}

static uint32_t parse_host_info(char *optarg, int *rc)
{
	int err = 0;
	uint32_t host_no = -1;

	*rc = 0;
	if (strstr(optarg, ":")) {
		transport_probe_for_offload();

		host_no = iscsi_sysfs_get_host_no_from_hwaddress(optarg,
								 &err);
		if (err) {
			log_error("Could not match MAC to host.");
			*rc = ISCSI_ERR_INVAL;
		}
	} else {
		host_no = strtoul(optarg, NULL, 10);
		if (errno) {
			log_error("Invalid host no %s. %s.",
				  optarg, strerror(errno));
			*rc = ISCSI_ERR_INVAL;
		}
	}
	return host_no;
}

static char *iscsi_ping_stat_strs[] = {
	/* ISCSI_PING_SUCCESS */
	"success",
	/* ISCSI_PING_FW_DISABLED */
	"firmware disabled",
	/* ISCSI_PING_IPADDR_INVALID */
	"invalid IP address",
	/* ISCSI_PING_LINKLOCAL_IPV6_ADDR_INVALID */
	"invalid link local IPv6 address",
	/* ISCSI_PING_TIMEOUT */
	"timed out",
	/* ISCSI_PING_INVALID_DEST_ADDR */
	"invalid destination address",
	/* ISCSI_PING_OVERSIZE_PACKET */
	"oversized packet",
	/* ISCSI_PING_ICMP_ERROR */
	"ICMP error",
	/* ISCSI_PING_MAX_REQ_EXCEEDED */
	"Max request exceeded",
	/* ISCSI_PING_NO_ARP_RECEIVED */
	"No ARP response received",
};

static char *iscsi_ping_stat_to_str(uint32_t status)
{
	if (status < 0 || status > ISCSI_PING_NO_ARP_RECEIVED) {
		log_error("Invalid ping status %u\n", status);
		return NULL;
	}

	return iscsi_ping_stat_strs[status];
}

static int exec_ping_op(struct iface_rec *iface, char *ip, int size, int count,
			int interval)
{
	int rc = ISCSI_ERR;
	uint32_t iface_type = ISCSI_IFACE_TYPE_IPV4;
	struct iscsi_transport *t = NULL;
	uint32_t host_no, status = 0;
	struct sockaddr_storage addr;
	int i;

	if (!iface) {
		log_error("Ping requires iface.");
		rc = ISCSI_ERR_INVAL;
		goto ping_exit;
	}

	if (!ip) {
		log_error("Ping requires destination ipaddress.");
		rc = ISCSI_ERR_INVAL;
		goto ping_exit;
	}

	if (size <= 0) {
		log_error("Invalid packet size: %d.", size);
		rc = ISCSI_ERR_INVAL;
		goto ping_exit;
	}

	if (count <= 0) {
		log_error("Invalid number of packets to transmit: %d.", count);
		rc = ISCSI_ERR_INVAL;
		goto ping_exit;
	}

	if (interval < 0) {
		log_error("Invalid timing interval: %d.", interval);
		rc = ISCSI_ERR_INVAL;
		goto ping_exit;
	}

	rc = iface_conf_read(iface);
	if (rc) {
		log_error("Could not read iface %s (%d).", iface->name, rc);
		goto ping_exit;
	}


	iface_type = iface_get_iptype(iface);

	t = iscsi_sysfs_get_transport_by_name(iface->transport_name);
	if (!t) {
		log_error("Can't find transport.");
		rc = ISCSI_ERR_INVAL;
		goto ping_exit;
	}

	host_no = iscsi_sysfs_get_host_no_from_hwinfo(iface, &rc);
	if (host_no == -1) {
		log_error("Can't find host_no.");
		rc = ISCSI_ERR_INVAL;
		goto ping_exit;
	}

	rc = resolve_address(ip, NULL, &addr);
	if (rc) {
		log_error("Invalid IP address.");
		rc = ISCSI_ERR_INVAL;
		goto ping_exit;
	}

	/* TODO: move this. It is needed by interface for pid */
	srand(time(NULL));

	for (i = 1; i <= count; i++) {
		/*
		 * To support drivers like bnx2i that do not use
		 * the iscsi if to send a ping, we can add a transport
		 * callout here.
		 */
		status = 0;
		rc = ipc->exec_ping(t->handle, host_no,
				    (struct sockaddr *)&addr, iface->iface_num,
				    iface_type, size, &status);
		if (!rc && !status)
			printf("Ping %d completed\n", i);
		else if (status)
			printf("Ping %d failed: %s\n", i,
				iscsi_ping_stat_to_str(status));
		else
			printf("Ping %d failed: %s\n", i, iscsi_err_to_str(rc));

		if (i < count)
			sleep(interval);
	}

ping_exit:
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
	int packet_size=32, ping_count=1, ping_interval=0;
	int do_discover = 0, sub_mode = -1;
	struct sigaction sa_old;
	struct sigaction sa_new;
	struct list_head ifaces;
	struct iface_rec *iface = NULL, *tmp;
	struct node_rec *rec = NULL;
	uint32_t host_no = -1;
	struct user_param *param;
	struct list_head params;

	INIT_LIST_HEAD(&params);
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
	log_init(program_name, 1024, log_do_log_std, NULL);
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
				rc = ISCSI_ERR_INVAL;
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
				rc = ISCSI_ERR_INVAL;
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
			host_no = parse_host_info(optarg, &rc);
			if (rc)
				goto free_ifaces;
			break;
		case 'r':
			sid = iscsi_sysfs_get_sid_from_path(optarg);
			if (sid < 0) {
				log_error("invalid sid '%s'",
					  optarg);
				rc = ISCSI_ERR_INVAL;
				goto free_ifaces;
			}
			break;
		case 'R':
			do_rescan = 1;
			break;
		case 'P':
			info_level = atoi(optarg);
			break;
		case 'D':
			do_discover = 1;
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
		case 'C':
			sub_mode = str_to_submode(optarg);
			break;
		case 'T':
			targetname = optarg;
			break;
		case 'p':
			ip = str_to_ipport(optarg, &port, &tpgt);
			break;
		case 'a':
			ip = optarg;
			break;
		case 'b':
			packet_size = atoi(optarg);
			break;
		case 'c':
			ping_count = atoi(optarg);
			break;
		case 'i':
			ping_interval = atoi(optarg);
			break;
		case 'I':
			iface = iface_alloc(optarg, &rc);
			if (rc == ISCSI_ERR_INVAL) {
				printf("Invalid iface name %s. Must be from "
					"1 to %d characters.\n",
					optarg, ISCSI_MAX_IFACE_LEN - 1);
				goto free_ifaces;
			} else if (!iface || rc) {
				printf("Could not add iface %s.", optarg);
				rc = ISCSI_ERR_INVAL;
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

		if (name && value) {
			param = idbm_alloc_user_param(name, value);
			if (!param) {
				log_error("Cannot allocate memory for params.");
				rc = ISCSI_ERR_NOMEM;
				goto free_ifaces;
			}
			list_add_tail(&param->list, &params);
			name = NULL;
			value = NULL;
		}
	}

	if (optopt) {
		log_error("unrecognized character '%c'", optopt);
		rc = ISCSI_ERR_INVAL;
		goto free_ifaces;
	}

	if (killiscsid >= 0) {
		kill_iscsid(killiscsid);
		goto free_ifaces;
	}

	if (mode < 0)
		usage(ISCSI_ERR_INVAL);

	if (mode == MODE_FW) {
		if ((rc = verify_mode_params(argc, argv, "ml", 0))) {
			log_error("fw mode: option '-%c' is not "
				  "allowed/supported", rc);
			rc = ISCSI_ERR_INVAL;
			goto free_ifaces;
		}

		rc = exec_fw_op(NULL, NULL, info_level, do_login, op);
		goto free_ifaces;
	}

	increase_max_files();
	if (idbm_init(get_config_file)) {
		log_warning("exiting due to idbm configuration error");
		rc = ISCSI_ERR_IDBM;
		goto free_ifaces;
	}

	switch (mode) {
	case MODE_HOST:
		if ((rc = verify_mode_params(argc, argv, "CHdmPov", 0))) {
			log_error("host mode: option '-%c' is not "
				  "allowed/supported", rc);
			rc = ISCSI_ERR_INVAL;
			goto out;
		}
		if (sub_mode != -1) {
			switch (sub_mode) {
			case MODE_CHAP:
				if (!op || !host_no) {
					log_error("CHAP mode requires host "
						"no and valid operation");
					rc = ISCSI_ERR_INVAL;
					break;
				}
				rc = exec_host_chap_op(op, info_level, host_no,
						       value);
				break;
			default:
				log_error("Invalid Sub Mode");
				break;
			}
		} else
			rc = host_info_print(info_level, host_no);
		break;
	case MODE_IFACE:
		iface_setup_host_bindings();

		if ((rc = verify_mode_params(argc, argv, "HIdnvmPoCabci", 0))) {
			log_error("iface mode: option '-%c' is not "
				  "allowed/supported", rc);
			rc = ISCSI_ERR_INVAL;
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

		if (sub_mode == MODE_PING)
			rc = exec_ping_op(iface, ip, packet_size, ping_count,
					  ping_interval);
		else
			rc = exec_iface_op(op, do_show, info_level, iface,
					   host_no, &params);

		break;
	case MODE_DISCOVERYDB:
		if ((rc = verify_mode_params(argc, argv, "DSIPdmntplov", 0))) {
			log_error("discovery mode: option '-%c' is not "
				  "allowed/supported", rc);
			rc = ISCSI_ERR_INVAL;
			goto out;
		}

		rc = exec_disc2_op(type, ip, port, &ifaces, info_level,
				   do_login, do_discover, op, &params,
				   do_show);
		break;
	case MODE_DISCOVERY:
		if ((rc = verify_mode_params(argc, argv, "DSIPdmntplov", 0))) {
			log_error("discovery mode: option '-%c' is not "
				  "allowed/supported", rc);
			rc = ISCSI_ERR_INVAL;
			goto out;
		}

		rc = exec_disc_op(type, ip, port, &ifaces, info_level,
				  do_login, do_discover, op, &params,
				  do_show);
		break;
	case MODE_NODE:
		if ((rc = verify_mode_params(argc, argv, "RsPIdmlSonvupTUL",
					     0))) {
			log_error("node mode: option '-%c' is not "
				  "allowed/supported", rc);
			rc = ISCSI_ERR_INVAL;
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

		if (ip && port == -1)
			port = ISCSI_LISTEN_PORT;

		rec = idbm_create_rec(targetname, tpgt, ip, port, iface, 1);
		if (!rec) {
			rc = ISCSI_ERR_NOMEM;
			goto out;
		}

		rc = exec_node_op(op, do_login, do_logout, do_show,
				  do_rescan, do_stats, info_level, rec,
				  &params);
		break;
	case MODE_SESSION:
		if ((rc = verify_mode_params(argc, argv,
					      "PiRdrmusonuSv", 1))) {
			log_error("session mode: option '-%c' is not "
				  "allowed or supported", rc);
			rc = ISCSI_ERR_INVAL;
			goto out;
		}
		if (sid >= 0) {
			char session[64];
			struct session_info *info;

			snprintf(session, 63, "session%d", sid);
			session[63] = '\0';

			info = calloc(1, sizeof(*info));
			if (!info) {
				rc = ISCSI_ERR_NOMEM;
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
				rc = session_info_print(info_level, info,
							do_show);
				goto free_info;
			}

			rec = idbm_create_rec(info->targetname,
					      info->tpgt,
					      info->persistent_address,
					      info->persistent_port,
					      &info->iface, 1);
			if (!rec) {
				rc = ISCSI_ERR_NOMEM;
				goto free_info;
			}
			rec->session.info = info;
			rec->session.sid = sid;

			/*
			 * A "new" session means to login a multiple of the
			 * currently-detected session.
			 */
			if (op == OP_NEW) {
				op = OP_NOOP;
				do_login = 1;
				rec->session.multiple = 1;
			}

			/* drop down to node ops */
			rc = exec_node_op(op, do_login, do_logout, do_show,
					  do_rescan, do_stats, info_level,
					  rec, &params);
free_info:
			free(info);
			goto out;
		} else {
			if (op == OP_NEW) {
				log_error("session mode: Operation 'new' only "
					  "allowed with specific session IDs");
				rc = ISCSI_ERR_INVAL;
				goto out;
			}
			if (do_logout || do_rescan || do_stats) {
				rc = exec_node_op(op, do_login, do_logout,
						 do_show, do_rescan, do_stats,
						 info_level, NULL, &params);
				goto out;
			}

			rc = session_info_print(info_level, NULL, do_show);
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
