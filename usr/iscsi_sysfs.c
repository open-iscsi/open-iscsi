/*
 * iSCSI sysfs
 *
 * Copyright (C) 2006 Mike Christie
 * Copyright (C) 2006 Red Hat, Inc. All rights reserved.
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
 */
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include "log.h"
#include "initiator.h"
#include "transport.h"
#include "idbm.h"
#include "idbm_fields.h"
#include "version.h"
#include "iscsi_sysfs.h"
#include "sysdeps.h"
#include "iscsi_settings.h"
#include "iface.h"
#include "session_info.h"
#include "host.h"
#include "iscsi_err.h"
#include "flashnode.h"

/*
 * TODO: remove the _DIR defines and search for subsys dirs like
 *  is done in sysfs.c.
 */
#define ISCSI_TRANSPORT_DIR	"/sys/class/iscsi_transport"
#define ISCSI_SESSION_DIR	"/sys/class/iscsi_session"
#define ISCSI_HOST_DIR		"/sys/class/iscsi_host"
#define ISCSI_FLASHNODE_DIR	"/sys/bus/iscsi_flashnode/devices"

#define ISCSI_SESSION_SUBSYS		"iscsi_session"
#define ISCSI_CONN_SUBSYS		"iscsi_connection"
#define ISCSI_HOST_SUBSYS		"iscsi_host"
#define ISCSI_TRANSPORT_SUBSYS		"iscsi_transport"
#define ISCSI_IFACE_SUBSYS		"iscsi_iface"
#define ISCSI_FLASHNODE_SUBSYS		"iscsi_flashnode"
#define SCSI_HOST_SUBSYS		"scsi_host"
#define SCSI_SUBSYS			"scsi"

#define ISCSI_SESSION_ID		"session%d"
#define ISCSI_CONN_ID			"connection%d:0"
#define ISCSI_HOST_ID			"host%d"
#define ISCSI_FLASHNODE_SESS		"flashnode_sess-%d:%d"
#define ISCSI_FLASHNODE_CONN		"flashnode_conn-%d:%d:0"

/*
 * TODO: make this into a real API and check inputs better and add doc.
 */

static int num_transports;
LIST_HEAD(transports);

void free_transports(void)
{
	struct iscsi_transport *t, *tmp;

	list_for_each_entry_safe(t, tmp, &transports, list) {
		list_del(&t->list);
		free(t);
	}
}

static int trans_filter(const struct dirent *dir)
{
	return strcmp(dir->d_name, ".") && strcmp(dir->d_name, "..");
}

static int read_transports(void)
{
	struct dirent **namelist;
	int i, n, found;
	struct iscsi_transport *t;

	log_debug(7, "in %s", __FUNCTION__);

	n = scandir(ISCSI_TRANSPORT_DIR, &namelist, trans_filter,
		    alphasort);
	if (n < 0) {
		log_error("Could not scan %s.", ISCSI_TRANSPORT_DIR);
		return n;
	}

	for (i = 0; i < n; i++) {
		found = 0;

		list_for_each_entry(t, &transports, list) {
			if (!strcmp(t->name, namelist[i]->d_name)) {
				found = 1;
				break;
			}
		}

		if (!found) {
			/* copy new transport */
			t = malloc(sizeof(*t));
			if (!t)
				continue;
			log_debug(7, "Adding new transport %s",
				  namelist[i]->d_name);

			INIT_LIST_HEAD(&t->sessions);
			INIT_LIST_HEAD(&t->list);
			strlcpy(t->name, namelist[i]->d_name,
				ISCSI_TRANSPORT_NAME_MAXLEN);
			if (set_transport_template(t)) {
				free(t);
				return -1;
			}
		} else
			log_debug(7, "Updating transport %s",
				  namelist[i]->d_name);

		if (sysfs_get_uint64(t->name, ISCSI_TRANSPORT_SUBSYS,
				     "handle", &t->handle)) {
			if (list_empty(&t->list))
				free(t);
			else
				log_error("Could not update %s.",
					  t->name);
			continue;
		}

		if (sysfs_get_uint(t->name, ISCSI_TRANSPORT_SUBSYS,
				  "caps", &t->caps)) {
			if (list_empty(&t->list))
				free(t);
			else
				log_error("Could not update %s.",
					  t->name);
			continue;
		}
		/*
		 * tmp hack for qla4xx compat
		 */
		if (!strcmp(t->name, "qla4xxx")) {
			t->caps |= CAP_DATA_PATH_OFFLOAD;
		}

		if (list_empty(&t->list))
			list_add_tail(&t->list, &transports);
	}

	for (i = 0; i < n; i++)
		free(namelist[i]);
	free(namelist);
	num_transports = n;

	return 0;
}

/* caller must check lengths */
void iscsi_sysfs_get_auth_conf(int sid, struct iscsi_auth_config *conf)
{
	char id[NAME_SIZE];

	memset(conf, 0, sizeof(*conf));
	snprintf(id, sizeof(id), ISCSI_SESSION_ID, sid);

	sysfs_get_str(id, ISCSI_SESSION_SUBSYS, "username", conf->username,
		      sizeof(conf->username));
	sysfs_get_str(id, ISCSI_SESSION_SUBSYS, "username_in",
		      conf->username_in, sizeof(conf->username_in));

	sysfs_get_str(id, ISCSI_SESSION_SUBSYS, "password",
		      (char *)conf->password, sizeof(conf->password));
	if (strlen((char *)conf->password))
		conf->password_length = strlen((char *)conf->password);

	sysfs_get_str(id, ISCSI_SESSION_SUBSYS, "password_in",
		      (char *)conf->password_in, sizeof(conf->password_in));
	if (strlen((char *)conf->password_in))
		conf->password_in_length = strlen((char *)conf->password_in);
}

/* called must check for -1=invalid value */
void iscsi_sysfs_get_negotiated_conn_conf(int sid,
				struct iscsi_conn_operational_config *conf)
{
	char id[NAME_SIZE];

	memset(conf, 0, sizeof(*conf));
	snprintf(id, sizeof(id), ISCSI_CONN_ID, sid);

	sysfs_get_int(id, ISCSI_CONN_SUBSYS, "data_digest", &conf->DataDigest);
	sysfs_get_int(id, ISCSI_CONN_SUBSYS, "header_digest",
		      &conf->HeaderDigest);
	sysfs_get_int(id, ISCSI_CONN_SUBSYS, "max_xmit_dlength",
		      &conf->MaxXmitDataSegmentLength);
	sysfs_get_int(id, ISCSI_CONN_SUBSYS, "max_recv_dlength",
		       &conf->MaxRecvDataSegmentLength);
}

/* called must check for -1=invalid value */
void iscsi_sysfs_get_negotiated_session_conf(int sid,
				struct iscsi_session_operational_config *conf)
{
	char id[NAME_SIZE];

	memset(conf, 0, sizeof(*conf));
	snprintf(id, sizeof(id), ISCSI_SESSION_ID, sid);

	sysfs_get_int(id, ISCSI_SESSION_SUBSYS, "data_pdu_in_order",
		      &conf->DataPDUInOrder);
	sysfs_get_int(id, ISCSI_SESSION_SUBSYS, "data_seq_in_order",
		      &conf->DataSequenceInOrder);
	sysfs_get_int(id, ISCSI_SESSION_SUBSYS, "erl", &conf->ERL);
	sysfs_get_int(id, ISCSI_SESSION_SUBSYS, "first_burst_len",
		       &conf->FirstBurstLength);
	sysfs_get_int(id, ISCSI_SESSION_SUBSYS, "max_burst_len",
		      &conf->MaxBurstLength);
	sysfs_get_int(id, ISCSI_SESSION_SUBSYS, "immediate_data",
		      &conf->ImmediateData);
	sysfs_get_int(id, ISCSI_SESSION_SUBSYS, "initial_r2t",
		      &conf->InitialR2T);
	sysfs_get_int(id, ISCSI_SESSION_SUBSYS, "max_outstanding_r2t",
		      &conf->MaxOutstandingR2T);
}

/*
 * iscsi_sysfs_session_user_created - return if session was setup by userspace
 * @sid: id of session to test
 *
 * Returns -1 if we could not tell due to kernel not supporting the
 * feature. 0 is returned if kernel created it. And 1 is returned
 * if userspace created it.
 */
int iscsi_sysfs_session_user_created(int sid)
{
	char id[NAME_SIZE];
	pid_t pid;

	snprintf(id, sizeof(id), ISCSI_SESSION_ID, sid);
	if (sysfs_get_int(id, ISCSI_SESSION_SUBSYS, "creator", &pid))
		return -1;

	if (pid == -1)
		return 0;
	else
		return 1;
}

uint32_t iscsi_sysfs_get_host_no_from_sid(uint32_t sid, int *err)
{
	struct sysfs_device *session_dev, *host_dev;
	char devpath[PATH_SIZE];
	char id[NAME_SIZE];

	*err = 0;
	snprintf(id, sizeof(id), "session%u", sid);
	if (!sysfs_lookup_devpath_by_subsys_id(devpath, sizeof(devpath),
					       ISCSI_SESSION_SUBSYS, id)) {
		log_error("Could not lookup devpath for %s. Possible sysfs "
			  "incompatibility.", id);
		*err = ISCSI_ERR_SYSFS_LOOKUP;
		return 0;
	}

	session_dev = sysfs_device_get(devpath);
	if (!session_dev) {
		log_error("Could not get dev for %s. Possible sysfs "
			  "incompatibility.", id);
		*err = ISCSI_ERR_SYSFS_LOOKUP;
		return 0;
	}

	/*
	 * 2.6.27 moved from scsi_host to scsi for the subsys when
	 * sysfs compat is not on.
	 */
	host_dev = sysfs_device_get_parent_with_subsystem(session_dev,
							  SCSI_SUBSYS);
	if (!host_dev) {
		struct sysfs_device *dev_parent;

		dev_parent = sysfs_device_get_parent(session_dev);
		while (dev_parent != NULL) {
			if (strncmp(dev_parent->kernel, "host", 4) == 0) {
				host_dev = dev_parent;
				break;
			}
			dev_parent = sysfs_device_get_parent(dev_parent);
		}

		if (!host_dev) {
			log_error("Could not get host dev for %s. Possible "
				  "sysfs incompatibility.", id);
			*err = ISCSI_ERR_SYSFS_LOOKUP;
			return 0;
		}
	}

	return atol(host_dev->kernel_number);
}

/* TODO: merge and make macro */
static int __get_host_no_from_netdev(void *data, struct host_info *info)
{
	struct host_info *ret_info = data;

	if (!strcmp(ret_info->iface.netdev, info->iface.netdev)) {
		ret_info->host_no = info->host_no;
		return 1;
	}
	return 0;
}

static uint32_t get_host_no_from_netdev(char *netdev, int *rc)
{
	uint32_t host_no = -1;
	struct host_info *info;
	int nr_found, local_rc;

	*rc = 0;

	info = calloc(1, sizeof(*info));
	if (!info) {
		*rc = ISCSI_ERR_NOMEM;
		return -1;
	}
	strcpy(info->iface.netdev, netdev);

	local_rc = iscsi_sysfs_for_each_host(info, &nr_found,
					     __get_host_no_from_netdev);
	if (local_rc == 1)
		host_no = info->host_no;
	else
		*rc = ISCSI_ERR_HOST_NOT_FOUND;
	free(info);
	return host_no;
}

static int __get_host_no_from_hwaddress(void *data, struct host_info *info)
{
	struct host_info *ret_info = data;

	if (!strcasecmp(ret_info->iface.hwaddress, info->iface.hwaddress)) {
		ret_info->host_no = info->host_no;
		return 1;
	}
	return 0;
}

uint32_t iscsi_sysfs_get_host_no_from_hwaddress(char *hwaddress, int *rc)
{
	uint32_t host_no = -1;
	struct host_info *info;
	int nr_found, local_rc;

	*rc = 0;

	info = calloc(1, sizeof(*info));
	if (!info) {
		log_debug(4, "No memory for host info");
		*rc = ISCSI_ERR_NOMEM;
		return -1;
	}
	/* make sure there is room for the MAC address plus NULL terminator */
	if (strlen(hwaddress) > (ISCSI_HWADDRESS_BUF_SIZE - 1)) {
		log_debug(4, "HW Address \"%s\" too long (%d max)",
				hwaddress, ISCSI_HWADDRESS_BUF_SIZE-1);
		*rc = ISCSI_ERR_INVAL;
		goto dun;
	}
	strncpy(info->iface.hwaddress, hwaddress, ISCSI_HWADDRESS_BUF_SIZE-1);

	local_rc = iscsi_sysfs_for_each_host(info, &nr_found,
					__get_host_no_from_hwaddress);
	if (local_rc == 1)
		host_no = info->host_no;
	else {
		log_debug(4, "Host not found from HW Address \"%s\"",
				hwaddress);
		*rc = ISCSI_ERR_HOST_NOT_FOUND;
	}
dun:
	free(info);
	return host_no;
}

static int __get_host_no_from_ipaddress(void *data, struct host_info *info)
{
	struct host_info *ret_info = data;

	if (!strcmp(ret_info->iface.ipaddress, info->iface.ipaddress)) {
		ret_info->host_no = info->host_no;
		return 1;
	}
	return 0;
}

static uint32_t get_host_no_from_ipaddress(char *address, int *rc)
{
	uint32_t host_no = -1;
	struct host_info *info;
	int nr_found;
	int local_rc;

	*rc = 0;

	info = calloc(1, sizeof(*info));
	if (!info) {
		*rc = ISCSI_ERR_NOMEM;
		return -1;
	}
	strcpy(info->iface.ipaddress, address);

	local_rc = iscsi_sysfs_for_each_host(info, &nr_found,
					     __get_host_no_from_ipaddress);
	if (local_rc == 1)
		host_no = info->host_no;
	else
		*rc = ISCSI_ERR_HOST_NOT_FOUND;
	free(info);
	return host_no;
}

uint32_t iscsi_sysfs_get_host_no_from_hwinfo(struct iface_rec *iface, int *rc)
{
	int tmp_rc;
	uint32_t host_no = -1;

	if (strlen(iface->hwaddress) &&
	    strcasecmp(iface->hwaddress, DEFAULT_HWADDRESS))
		host_no = iscsi_sysfs_get_host_no_from_hwaddress(
						iface->hwaddress, &tmp_rc);
	else if (strlen(iface->netdev) &&
		strcasecmp(iface->netdev, DEFAULT_NETDEV))
		host_no = get_host_no_from_netdev(iface->netdev, &tmp_rc);
	else if (strlen(iface->ipaddress) &&
		 strcasecmp(iface->ipaddress, DEFAULT_IPADDRESS))
		host_no = get_host_no_from_ipaddress(iface->ipaddress, &tmp_rc);
	else
		tmp_rc = ISCSI_ERR_INVAL;

	*rc = tmp_rc;
	return host_no;
}

/*
 * Read the flash node attributes based on host and flash node index.
 */
int iscsi_sysfs_get_flashnode_info(struct flashnode_rec *fnode,
				   uint32_t host_no,
				   uint32_t flashnode_idx)
{
	char sess_id[NAME_SIZE] = {'\0'};
	char conn_id[NAME_SIZE] = {'\0'};
	char fnode_path[PATH_SIZE] = {'\0'};
	struct iscsi_transport *t;
	int ret = 0;

	t = iscsi_sysfs_get_transport_by_hba(host_no);
	if (!t)
		log_debug(7, "could not get transport name for host%d",
			  host_no);
	else
		strlcpy(fnode->transport_name, t->name,
			ISCSI_TRANSPORT_NAME_MAXLEN);

	snprintf(sess_id, sizeof(sess_id), ISCSI_FLASHNODE_SESS, host_no,
		 flashnode_idx);

	snprintf(fnode_path, sizeof(fnode_path), ISCSI_FLASHNODE_DIR"/%s",
		 sess_id);
	if (access(fnode_path, F_OK) != 0)
		return errno;

	snprintf(conn_id, sizeof(conn_id), ISCSI_FLASHNODE_CONN, host_no,
		 flashnode_idx);

	snprintf(fnode_path, sizeof(fnode_path), ISCSI_FLASHNODE_DIR"/%s",
		 conn_id);
	if (access(fnode_path, F_OK) != 0)
		return errno;


	sysfs_get_uint8(conn_id, ISCSI_FLASHNODE_SUBSYS, "is_fw_assigned_ipv6",
			&((fnode->conn[0]).is_fw_assigned_ipv6));
	sysfs_get_str(sess_id, ISCSI_FLASHNODE_SUBSYS, "portal_type",
		      (fnode->sess).portal_type,
		      sizeof((fnode->sess).portal_type));
	sysfs_get_uint8(sess_id, ISCSI_FLASHNODE_SUBSYS, "auto_snd_tgt_disable",
			&((fnode->sess).auto_snd_tgt_disable));
	sysfs_get_uint8(sess_id, ISCSI_FLASHNODE_SUBSYS, "discovery_session",
			&((fnode->sess).discovery_session));
	sysfs_get_uint8(sess_id, ISCSI_FLASHNODE_SUBSYS, "entry_enable",
			&((fnode->sess).entry_enable));
	sysfs_get_uint8(conn_id, ISCSI_FLASHNODE_SUBSYS, "header_digest",
			&((fnode->conn[0]).header_digest_en));
	sysfs_get_uint8(conn_id, ISCSI_FLASHNODE_SUBSYS, "data_digest",
			&((fnode->conn[0]).data_digest_en));
	sysfs_get_uint8(sess_id, ISCSI_FLASHNODE_SUBSYS, "immediate_data",
			&((fnode->sess).immediate_data));
	sysfs_get_uint8(sess_id, ISCSI_FLASHNODE_SUBSYS, "initial_r2t",
			&((fnode->sess).initial_r2t));
	sysfs_get_uint8(sess_id, ISCSI_FLASHNODE_SUBSYS, "data_seq_in_order",
			&((fnode->sess).data_seq_in_order));
	sysfs_get_uint8(sess_id, ISCSI_FLASHNODE_SUBSYS, "data_pdu_in_order",
			&((fnode->sess).data_pdu_in_order));
	sysfs_get_uint8(sess_id, ISCSI_FLASHNODE_SUBSYS, "chap_auth",
			&((fnode->sess).chap_auth_en));
	sysfs_get_uint8(conn_id, ISCSI_FLASHNODE_SUBSYS, "snack_req",
			&((fnode->conn[0]).snack_req_en));
	sysfs_get_uint8(sess_id, ISCSI_FLASHNODE_SUBSYS, "discovery_logout",
			&((fnode->sess).discovery_logout_en));
	sysfs_get_uint8(sess_id, ISCSI_FLASHNODE_SUBSYS, "bidi_chap",
			&((fnode->sess).bidi_chap_en));
	sysfs_get_uint8(sess_id, ISCSI_FLASHNODE_SUBSYS,
			"discovery_auth_optional",
			&((fnode->sess).discovery_auth_optional));
	sysfs_get_uint8(sess_id, ISCSI_FLASHNODE_SUBSYS, "erl",
			&((fnode->sess).erl));
	sysfs_get_uint8(conn_id, ISCSI_FLASHNODE_SUBSYS, "tcp_timestamp_stat",
			&((fnode->conn[0]).tcp_timestamp_stat));
	sysfs_get_uint8(conn_id, ISCSI_FLASHNODE_SUBSYS, "tcp_nagle_disable",
			&((fnode->conn[0]).tcp_nagle_disable));
	sysfs_get_uint8(conn_id, ISCSI_FLASHNODE_SUBSYS, "tcp_wsf_disable",
			&((fnode->conn[0]).tcp_wsf_disable));
	sysfs_get_uint8(conn_id, ISCSI_FLASHNODE_SUBSYS, "tcp_timer_scale",
			&((fnode->conn[0]).tcp_timer_scale));
	sysfs_get_uint8(conn_id, ISCSI_FLASHNODE_SUBSYS, "tcp_timestamp_enable",
			&((fnode->conn[0]).tcp_timestamp_en));
	sysfs_get_uint8(conn_id, ISCSI_FLASHNODE_SUBSYS, "fragment_disable",
			&((fnode->conn[0]).fragment_disable));
	sysfs_get_uint(conn_id, ISCSI_FLASHNODE_SUBSYS, "max_recv_dlength",
		       &((fnode->conn[0]).max_recv_dlength));
	sysfs_get_uint(conn_id, ISCSI_FLASHNODE_SUBSYS, "max_xmit_dlength",
		       &((fnode->conn[0]).max_xmit_dlength));
	sysfs_get_uint(sess_id, ISCSI_FLASHNODE_SUBSYS, "first_burst_len",
		       &((fnode->sess).first_burst_len));
	sysfs_get_uint16(sess_id, ISCSI_FLASHNODE_SUBSYS, "def_time2wait",
			 &((fnode->sess).def_time2wait));
	sysfs_get_uint16(sess_id, ISCSI_FLASHNODE_SUBSYS, "def_time2retain",
			 &((fnode->sess).def_time2retain));
	sysfs_get_uint16(sess_id, ISCSI_FLASHNODE_SUBSYS, "max_outstanding_r2t",
			 &((fnode->sess).max_outstanding_r2t));
	sysfs_get_uint16(conn_id, ISCSI_FLASHNODE_SUBSYS, "keepalive_tmo",
			 &((fnode->conn[0]).keepalive_tmo));
	sysfs_get_str(sess_id, ISCSI_FLASHNODE_SUBSYS, "isid",
		      (fnode->sess).isid, sizeof((fnode->sess).isid));
	sysfs_get_uint16(sess_id, ISCSI_FLASHNODE_SUBSYS, "tsid",
			 &((fnode->sess).tsid));
	sysfs_get_uint16(conn_id, ISCSI_FLASHNODE_SUBSYS, "port",
			 &((fnode->conn[0]).port));
	sysfs_get_uint(sess_id, ISCSI_FLASHNODE_SUBSYS, "max_burst_len",
		       &((fnode->sess).max_burst_len));
	sysfs_get_uint16(sess_id, ISCSI_FLASHNODE_SUBSYS, "def_taskmgmt_tmo",
			 &((fnode->sess).def_taskmgmt_tmo));
	sysfs_get_str(sess_id, ISCSI_FLASHNODE_SUBSYS, "targetalias",
		      (fnode->sess).targetalias,
		      sizeof((fnode->sess).targetalias));
	sysfs_get_str(conn_id, ISCSI_FLASHNODE_SUBSYS, "ipaddress",
		      (fnode->conn[0]).ipaddress,
		      sizeof((fnode->conn[0]).ipaddress));
	sysfs_get_str(conn_id, ISCSI_FLASHNODE_SUBSYS, "redirect_ipaddr",
		      (fnode->conn[0]).redirect_ipaddr,
		      sizeof((fnode->conn[0]).redirect_ipaddr));
	sysfs_get_uint(conn_id, ISCSI_FLASHNODE_SUBSYS, "max_segment_size",
		       &((fnode->conn[0]).max_segment_size));
	sysfs_get_uint16(conn_id, ISCSI_FLASHNODE_SUBSYS, "local_port",
			 &((fnode->conn[0]).local_port));
	sysfs_get_uint8(conn_id, ISCSI_FLASHNODE_SUBSYS, "ipv4_tos",
			&((fnode->conn[0]).ipv4_tos));
	sysfs_get_uint8(conn_id, ISCSI_FLASHNODE_SUBSYS, "ipv6_traffic_class",
			&((fnode->conn[0]).ipv6_traffic_class));
	sysfs_get_uint16(conn_id, ISCSI_FLASHNODE_SUBSYS, "ipv6_flow_label",
			 &((fnode->conn[0]).ipv6_flow_lbl));
	sysfs_get_str(sess_id, ISCSI_FLASHNODE_SUBSYS, "targetname",
		      (fnode->sess).targetname,
		      sizeof((fnode->sess).targetname));
	sysfs_get_str(conn_id, ISCSI_FLASHNODE_SUBSYS, "link_local_ipv6",
		      (fnode->conn[0]).link_local_ipv6,
		      sizeof((fnode->conn[0]).link_local_ipv6));
	sysfs_get_uint16(sess_id, ISCSI_FLASHNODE_SUBSYS,
			 "discovery_parent_idx",
			 &((fnode->sess).discovery_parent_idx));
	sysfs_get_str(sess_id, ISCSI_FLASHNODE_SUBSYS,
		      "discovery_parent_type",
		      (fnode->sess).discovery_parent_type,
		      sizeof((fnode->sess).discovery_parent_type));
	sysfs_get_uint16(sess_id, ISCSI_FLASHNODE_SUBSYS, "tpgt",
			 &((fnode->sess).tpgt));
	sysfs_get_uint(conn_id, ISCSI_FLASHNODE_SUBSYS, "tcp_xmit_wsf",
		       &((fnode->conn[0]).tcp_xmit_wsf));
	sysfs_get_uint(conn_id, ISCSI_FLASHNODE_SUBSYS, "tcp_recv_wsf",
		       &((fnode->conn[0]).tcp_recv_wsf));
	sysfs_get_uint16(sess_id, ISCSI_FLASHNODE_SUBSYS, "chap_out_idx",
			 &((fnode->sess).chap_out_idx));
	sysfs_get_uint16(sess_id, ISCSI_FLASHNODE_SUBSYS, "chap_in_idx",
			 &((fnode->sess).chap_in_idx));
	sysfs_get_str(sess_id, ISCSI_FLASHNODE_SUBSYS, "username",
		      (fnode->sess).username, sizeof((fnode->sess).username));
	sysfs_get_str(sess_id, ISCSI_FLASHNODE_SUBSYS, "username_in",
		      (fnode->sess).username_in,
		      sizeof((fnode->sess).username_in));
	sysfs_get_str(sess_id, ISCSI_FLASHNODE_SUBSYS, "password",
		      (fnode->sess).password, sizeof((fnode->sess).password));
	sysfs_get_str(sess_id, ISCSI_FLASHNODE_SUBSYS, "password_in",
		      (fnode->sess).password_in,
		      sizeof((fnode->sess).password_in));
	sysfs_get_uint(conn_id, ISCSI_FLASHNODE_SUBSYS, "statsn",
		       &((fnode->conn[0]).stat_sn));
	sysfs_get_uint(conn_id, ISCSI_FLASHNODE_SUBSYS, "exp_statsn",
		       &((fnode->conn[0]).exp_stat_sn));
	sysfs_get_uint8(sess_id, ISCSI_FLASHNODE_SUBSYS, "is_boot_target",
			&((fnode->sess).is_boot_target));
	return ret;
}

/*
 * For each flash node of the given host, perform operation specified in fn.
 */
int iscsi_sysfs_for_each_flashnode(void *data, uint32_t host_no, int *nr_found,
				   iscsi_sysfs_flashnode_op_fn *fn)
{
	struct dirent **namelist;
	int rc = 0, i, n;
	struct flashnode_rec *fnode;
	uint32_t flashnode_idx;
	uint32_t hostno;

	fnode = malloc(sizeof(*fnode));
	if (!fnode)
		return ISCSI_ERR_NOMEM;

	n = scandir(ISCSI_FLASHNODE_DIR, &namelist, trans_filter, alphasort);
	if (n <= 0)
		goto free_fnode;

	for (i = 0; i < n; i++) {
		memset(fnode, 0, sizeof(*fnode));

		if (!strncmp(namelist[i]->d_name, "flashnode_conn",
			     strlen("flashnode_conn")))
			continue;

		if (sscanf(namelist[i]->d_name, ISCSI_FLASHNODE_SESS,
			   &hostno, &flashnode_idx) != 2) {
			log_error("Invalid iscsi target dir: %s",
				  namelist[i]->d_name);
			break;
		}

		if (host_no != hostno)
			continue;

		rc = iscsi_sysfs_get_flashnode_info(fnode, host_no,
						    flashnode_idx);
		if (rc)
			break;

		rc = fn(data, fnode, host_no, flashnode_idx);
		if (rc != 0)
			break;
		(*nr_found)++;
	}

	for (i = 0; i < n; i++)
		free(namelist[i]);
	free(namelist);

free_fnode:
	free(fnode);
	return rc;
}

static int iscsi_sysfs_read_boot(struct iface_rec *iface, char *session)
{
	char boot_root[BOOT_NAME_MAXLEN], boot_nic[BOOT_NAME_MAXLEN];
	char boot_name[BOOT_NAME_MAXLEN], boot_content[BOOT_NAME_MAXLEN];

	/* Extract boot info */
	strlcpy(boot_name, "boot_target", sizeof(boot_name));
	if (sysfs_get_str(session, ISCSI_SESSION_SUBSYS, boot_name,
			  boot_content, BOOT_NAME_MAXLEN))
		return -1;
	strlcpy(boot_name, "boot_nic", sizeof(boot_name));
	if (sysfs_get_str(session, ISCSI_SESSION_SUBSYS, boot_name, boot_nic,
			  BOOT_NAME_MAXLEN))
		return -1;
	strlcpy(boot_name, "boot_root", sizeof(boot_name));
	if (sysfs_get_str(session, ISCSI_SESSION_SUBSYS, boot_name, boot_root,
			  BOOT_NAME_MAXLEN))
		return -1;

	/* If all boot_root/boot_target/boot_nic exist, then extract the
	   info from the boot nic */
	if (sysfs_get_str(boot_nic, boot_root, "vlan", boot_content,
			  BOOT_NAME_MAXLEN))
		log_debug(5, "could not read %s/%s/vlan", boot_root, boot_nic);
	else
		iface->vlan_id = atoi(boot_content);

	if (sysfs_get_str(boot_nic, boot_root, "subnet-mask",
			  iface->subnet_mask, NI_MAXHOST))
		log_debug(5, "could not read %s/%s/subnet", boot_root,
			  boot_nic);

	if (sysfs_get_str(boot_nic, boot_root, "gateway",
			  iface->gateway, NI_MAXHOST))
		log_debug(5, "could not read %s/%s/gateway", boot_root,
			  boot_nic);

	log_debug(5, "sysfs read boot returns %s/%s/ vlan = %d subnet = %s",
		  boot_root, boot_nic, iface->vlan_id, iface->subnet_mask);
	return 0;
}

/*
 * Read in iface settings based on host and session values. If
 * session is not passed in, then the ifacename will not be set. And
 * if the session is not passed in then iname will only be set for
 * qla4xxx.
 */
static int iscsi_sysfs_read_iface(struct iface_rec *iface, int host_no,
				  char *session, char *iface_kern_id)
{
	uint32_t tmp_host_no, iface_num;
	char host_id[NAME_SIZE];
	struct iscsi_transport *t;
	int ret, iface_type;

	t = iscsi_sysfs_get_transport_by_hba(host_no);
	if (!t)
		log_debug(7, "could not get transport name for host%d",
			  host_no);
	else
		strcpy(iface->transport_name, t->name);

	snprintf(host_id, sizeof(host_id), ISCSI_HOST_ID, host_no);
	/*
	 * backward compat
	 * If we cannot get the address we assume we are doing the old
	 * style and use default.
	 */
	ret = sysfs_get_str(host_id, ISCSI_HOST_SUBSYS, "hwaddress",
			    iface->hwaddress, sizeof(iface->hwaddress));
	if (ret)
		log_debug(7, "could not read hwaddress for host%d", host_no);

	if (iface_kern_id)
		ret = sysfs_get_str(iface_kern_id, ISCSI_IFACE_SUBSYS,
				    "ipaddress",
				    iface->ipaddress, sizeof(iface->ipaddress));
	else
		/* if not found just print out default */
		ret = sysfs_get_str(host_id, ISCSI_HOST_SUBSYS, "ipaddress",
				    iface->ipaddress, sizeof(iface->ipaddress));
	if (ret)
		log_debug(7, "could not read local address for host%d",
			  host_no);

	/* if not found just print out default */
	ret = sysfs_get_str(host_id, ISCSI_HOST_SUBSYS, "netdev",
			    iface->netdev, sizeof(iface->netdev));
	if (ret)
		log_debug(7, "could not read netdev for host%d", host_no);

	/*
	 * For drivers like qla4xxx we can only set the iname at the
	 * host level because we cannot create different initiator ports
	 * (cannot set isid either). The LLD also exports the iname at the
	 * hba level so apps can see it, but we no longer set the iname for
	 * each iscsid controlled host since bnx2i cxgbi can support multiple
	 * initiator names and of course software iscsi can support anything.
	 */
	ret = 1;
	memset(iface->iname, 0, sizeof(iface->iname));
	if (session) {
		ret = sysfs_get_str(session, ISCSI_SESSION_SUBSYS,
				    "initiatorname",
				    iface->iname, sizeof(iface->iname));
		/*
		 * qlaxxx will not set this at the session level so we
		 * always drop down for it.
		 *
		 * And.
		 *
		 * For older kernels/tools (2.6.26 and below and 2.0.870)
		 * we will not have a session level initiator name, so
		 * we will drop down.
		 */
	}

	if (ret) {
		ret = sysfs_get_str(host_id, ISCSI_HOST_SUBSYS, "initiatorname",
				    iface->iname, sizeof(iface->iname));
		if (ret)
			/*
			 * default iname is picked up later from
			 * initiatorname.iscsi if software/partial-offload.
			 *
			 * TODO: we should make it easier to get the
			 * global iname so we can just fill it in here.
			 */
			log_debug(7, "Could not read initiatorname for "
				  "host%d", host_no);
		/* optional so do not return error */
		ret = 0;
	}

	sysfs_get_str(host_id, ISCSI_HOST_SUBSYS, "port_state",
		      iface->port_state, sizeof(iface->port_state));

	sysfs_get_str(host_id, ISCSI_HOST_SUBSYS, "port_speed",
		      iface->port_speed, sizeof(iface->port_speed));

	/*
	 * this is on the session, because we support multiple bindings
	 * per device.
	 */
	memset(iface->name, 0, sizeof(iface->name));
	if (session) {
		/*
		 * this was added after 2.0.869 so we could be doing iscsi_tcp
		 * session binding, but there may not be an ifacename set
		 * if binding is not used.
		 */
		ret = sysfs_get_str(session, ISCSI_SESSION_SUBSYS, "ifacename",
				    iface->name, sizeof(iface->name));
		if (ret) {
			log_debug(7, "could not read iface name for "
				  "session %s", session);
			/*
			 * if the ifacename file is not there then we are
			 * using a older kernel and can try to find the
			 * binding by the net info which was used on these
			 * older kernels.
			 */
			if (iface_get_by_net_binding(iface, iface))
				log_debug(7, "Could not find iface for session "
					  "bound to:" iface_fmt "",
					  iface_str(iface));
		}
	}

	if (session && t && t->template->use_boot_info)
		iscsi_sysfs_read_boot(iface, session);

	if (!iface_kern_id)
		goto done;

	strlcpy(iface->name, iface_kern_id, sizeof(iface->name));

	if (!strncmp(iface_kern_id, "ipv4", 4)) {
		sysfs_get_str(iface_kern_id, ISCSI_IFACE_SUBSYS, "bootproto",
			      iface->bootproto, sizeof(iface->bootproto));

		sysfs_get_str(iface_kern_id, ISCSI_IFACE_SUBSYS, "gateway",
			      iface->gateway, sizeof(iface->gateway));

		sysfs_get_str(iface_kern_id, ISCSI_IFACE_SUBSYS, "subnet",
			      iface->subnet_mask, sizeof(iface->subnet_mask));

		sysfs_get_str(iface_kern_id, ISCSI_IFACE_SUBSYS,
			      "dhcp_alt_client_id_en",
			      iface->dhcp_alt_client_id_state,
			      sizeof(iface->dhcp_alt_client_id_state));

		sysfs_get_str(iface_kern_id, ISCSI_IFACE_SUBSYS,
			      "dhcp_alt_client_id",
			      iface->dhcp_alt_client_id,
			      sizeof(iface->dhcp_alt_client_id));

		sysfs_get_str(iface_kern_id, ISCSI_IFACE_SUBSYS,
			      "dhcp_dns_address_en",
			      iface->dhcp_dns, sizeof(iface->dhcp_dns));

		sysfs_get_str(iface_kern_id, ISCSI_IFACE_SUBSYS,
			      "dhcp_learn_iqn_en",
			      iface->dhcp_learn_iqn,
			      sizeof(iface->dhcp_learn_iqn));

		sysfs_get_str(iface_kern_id, ISCSI_IFACE_SUBSYS,
			      "dhcp_req_vendor_id_en",
			      iface->dhcp_req_vendor_id_state,
			      sizeof(iface->dhcp_req_vendor_id_state));

		sysfs_get_str(iface_kern_id, ISCSI_IFACE_SUBSYS,
			      "dhcp_use_vendor_id_en",
			      iface->dhcp_vendor_id_state,
			      sizeof(iface->dhcp_vendor_id_state));

		sysfs_get_str(iface_kern_id, ISCSI_IFACE_SUBSYS,
			      "dhcp_vendor_id",
			      iface->dhcp_vendor_id,
			      sizeof(iface->dhcp_vendor_id));

		sysfs_get_str(iface_kern_id, ISCSI_IFACE_SUBSYS,
			      "dhcp_slp_da_info_en",
			      iface->dhcp_slp_da, sizeof(iface->dhcp_slp_da));

		sysfs_get_str(iface_kern_id, ISCSI_IFACE_SUBSYS,
			      "fragment_disable",
			      iface->fragmentation,
			      sizeof(iface->fragmentation));

		sysfs_get_str(iface_kern_id, ISCSI_IFACE_SUBSYS,
			      "grat_arp_en",
			      iface->gratuitous_arp,
			      sizeof(iface->gratuitous_arp));

		sysfs_get_str(iface_kern_id, ISCSI_IFACE_SUBSYS,
			      "incoming_forwarding_en",
			      iface->incoming_forwarding,
			      sizeof(iface->incoming_forwarding));

		sysfs_get_str(iface_kern_id, ISCSI_IFACE_SUBSYS,
			      "tos_en",
			      iface->tos_state, sizeof(iface->tos_state));

		if (sysfs_get_uint8(iface_kern_id, ISCSI_IFACE_SUBSYS,
				    "tos", &iface->tos))
			iface->tos = 0;

		if (sysfs_get_uint8(iface_kern_id, ISCSI_IFACE_SUBSYS,
				    "ttl", &iface->ttl))
			iface->ttl = 0;
	} else {
		sysfs_get_str(iface_kern_id, ISCSI_IFACE_SUBSYS,
			      "ipaddr_autocfg",
			      iface->ipv6_autocfg, sizeof(iface->ipv6_autocfg));

		sysfs_get_str(iface_kern_id, ISCSI_IFACE_SUBSYS,
			      "link_local_addr", iface->ipv6_linklocal,
			      sizeof(iface->ipv6_linklocal));

		sysfs_get_str(iface_kern_id, ISCSI_IFACE_SUBSYS,
			      "link_local_autocfg", iface->linklocal_autocfg,
			      sizeof(iface->linklocal_autocfg));

		sysfs_get_str(iface_kern_id, ISCSI_IFACE_SUBSYS, "router_addr",
			      iface->ipv6_router,
			      sizeof(iface->ipv6_router));

		sysfs_get_str(iface_kern_id, ISCSI_IFACE_SUBSYS, "router_state",
			      iface->router_autocfg,
			      sizeof(iface->router_autocfg));

		if (sysfs_get_uint8(iface_kern_id, ISCSI_IFACE_SUBSYS,
				    "dup_addr_detect_cnt",
				    &iface->dup_addr_detect_cnt))
			iface->dup_addr_detect_cnt = 0;

		if (sysfs_get_uint(iface_kern_id, ISCSI_IFACE_SUBSYS,
				   "flow_label", &iface->flow_label))
			iface->flow_label = 0;

		sysfs_get_str(iface_kern_id, ISCSI_IFACE_SUBSYS,
			      "grat_neighbor_adv_en",
			      iface->gratuitous_neighbor_adv,
			      sizeof(iface->gratuitous_neighbor_adv));

		if (sysfs_get_uint8(iface_kern_id, ISCSI_IFACE_SUBSYS,
				    "hop_limit", &iface->hop_limit))
			iface->hop_limit = 0;

		sysfs_get_str(iface_kern_id, ISCSI_IFACE_SUBSYS, "mld_en",
			      iface->mld, sizeof(iface->mld));

		if (sysfs_get_uint(iface_kern_id, ISCSI_IFACE_SUBSYS,
				   "nd_reachable_tmo",
				   &iface->nd_reachable_tmo))
			iface->nd_reachable_tmo = 0;

		if (sysfs_get_uint(iface_kern_id, ISCSI_IFACE_SUBSYS,
				   "nd_rexmit_time", &iface->nd_rexmit_time))
			iface->nd_rexmit_time = 0;

		if (sysfs_get_uint(iface_kern_id, ISCSI_IFACE_SUBSYS,
				   "nd_stale_tmo", &iface->nd_stale_tmo))
			iface->nd_stale_tmo = 0;

		if (sysfs_get_uint(iface_kern_id, ISCSI_IFACE_SUBSYS,
				   "router_adv_link_mtu",
				   &iface->router_adv_link_mtu))
			iface->router_adv_link_mtu = 0;

		if (sysfs_get_uint(iface_kern_id, ISCSI_IFACE_SUBSYS,
				   "traffic_class", &iface->traffic_class))
			iface->traffic_class = 0;
	}

	if (sysfs_get_uint16(iface_kern_id, ISCSI_IFACE_SUBSYS, "port",
			     &iface->port))
		iface->port = 0;
	if (sysfs_get_uint16(iface_kern_id, ISCSI_IFACE_SUBSYS, "mtu",
			     &iface->mtu))
		iface->mtu = 0;
	if (sysfs_get_uint16(iface_kern_id, ISCSI_IFACE_SUBSYS, "vlan_id",
			     &iface->vlan_id))
		iface->vlan_id = UINT16_MAX;

	if (sysfs_get_uint8(iface_kern_id, ISCSI_IFACE_SUBSYS, "vlan_priority",
			    &iface->vlan_priority))
		iface->vlan_priority = UINT8_MAX;

	sysfs_get_str(iface_kern_id, ISCSI_IFACE_SUBSYS, "vlan_enabled",
		      iface->vlan_state, sizeof(iface->vlan_state));

	sysfs_get_str(iface_kern_id, ISCSI_IFACE_SUBSYS, "enabled",
		      iface->state, sizeof(iface->state));

	sysfs_get_str(iface_kern_id, ISCSI_IFACE_SUBSYS, "delayed_ack_en",
		      iface->delayed_ack, sizeof(iface->delayed_ack));

	sysfs_get_str(iface_kern_id, ISCSI_IFACE_SUBSYS, "tcp_nagle_disable",
		      iface->nagle, sizeof(iface->nagle));

	sysfs_get_str(iface_kern_id, ISCSI_IFACE_SUBSYS, "tcp_wsf_disable",
		      iface->tcp_wsf_state, sizeof(iface->tcp_wsf_state));

	if (sysfs_get_uint8(iface_kern_id, ISCSI_IFACE_SUBSYS, "tcp_wsf",
			    &iface->tcp_wsf))
		iface->tcp_wsf = 0;

	if (sysfs_get_uint8(iface_kern_id, ISCSI_IFACE_SUBSYS,
			    "tcp_timer_scale", &iface->tcp_timer_scale))
		iface->tcp_timer_scale = 0;

	sysfs_get_str(iface_kern_id, ISCSI_IFACE_SUBSYS, "tcp_timestamp_en",
		      iface->tcp_timestamp, sizeof(iface->tcp_timestamp));

	sysfs_get_str(iface_kern_id, ISCSI_IFACE_SUBSYS, "redirect_en",
		      iface->redirect, sizeof(iface->redirect));

	if (sysfs_get_uint16(iface_kern_id, ISCSI_IFACE_SUBSYS,
			     "def_taskmgmt_tmo", &iface->def_task_mgmt_tmo))
		iface->def_task_mgmt_tmo = 0;

	sysfs_get_str(iface_kern_id, ISCSI_IFACE_SUBSYS, "header_digest",
		      iface->header_digest, sizeof(iface->header_digest));

	sysfs_get_str(iface_kern_id, ISCSI_IFACE_SUBSYS, "data_digest",
		      iface->data_digest, sizeof(iface->data_digest));

	sysfs_get_str(iface_kern_id, ISCSI_IFACE_SUBSYS, "immediate_data",
		      iface->immediate_data, sizeof(iface->immediate_data));

	sysfs_get_str(iface_kern_id, ISCSI_IFACE_SUBSYS, "initial_r2t",
		      iface->initial_r2t, sizeof(iface->initial_r2t));

	sysfs_get_str(iface_kern_id, ISCSI_IFACE_SUBSYS, "data_seq_in_order",
		      iface->data_seq_inorder, sizeof(iface->data_seq_inorder));

	sysfs_get_str(iface_kern_id, ISCSI_IFACE_SUBSYS, "data_pdu_in_order",
		      iface->data_pdu_inorder, sizeof(iface->data_pdu_inorder));

	if (sysfs_get_uint8(iface_kern_id, ISCSI_IFACE_SUBSYS, "erl",
			    &iface->erl))
		iface->erl = 0;

	if (sysfs_get_uint(iface_kern_id, ISCSI_IFACE_SUBSYS,
			   "max_recv_dlength", &iface->max_recv_dlength))
		iface->max_recv_dlength = 0;

	if (sysfs_get_uint(iface_kern_id, ISCSI_IFACE_SUBSYS,
			   "first_burst_len", &iface->first_burst_len))
		iface->first_burst_len = 0;

	if (sysfs_get_uint16(iface_kern_id, ISCSI_IFACE_SUBSYS,
			     "max_outstanding_r2t", &iface->max_out_r2t))
		iface->max_out_r2t = 0;

	if (sysfs_get_uint(iface_kern_id, ISCSI_IFACE_SUBSYS,
			   "max_burst_len", &iface->max_burst_len))
		iface->max_burst_len = 0;

	sysfs_get_str(iface_kern_id, ISCSI_IFACE_SUBSYS, "chap_auth",
		      iface->chap_auth, sizeof(iface->chap_auth));

	sysfs_get_str(iface_kern_id, ISCSI_IFACE_SUBSYS, "bidi_chap",
		      iface->bidi_chap, sizeof(iface->bidi_chap));

	sysfs_get_str(iface_kern_id, ISCSI_IFACE_SUBSYS, "strict_login_comp_en",
		      iface->strict_login_comp,
		      sizeof(iface->strict_login_comp));

	sysfs_get_str(iface_kern_id, ISCSI_IFACE_SUBSYS,
		      "discovery_auth_optional",
		      iface->discovery_auth, sizeof(iface->discovery_auth));

	sysfs_get_str(iface_kern_id, ISCSI_IFACE_SUBSYS, "discovery_logout",
		      iface->discovery_logout, sizeof(iface->discovery_logout));

	if (sscanf(iface_kern_id, "ipv%d-iface-%u-%u", &iface_type,
		   &tmp_host_no, &iface_num) == 3)
		iface->iface_num = iface_num;

done:
	if (ret)
		return ISCSI_ERR_SYSFS_LOOKUP;
	else
		return 0;
}

int iscsi_sysfs_get_hostinfo_by_host_no(struct host_info *hinfo)
{
	return iscsi_sysfs_read_iface(&hinfo->iface, hinfo->host_no, NULL,
				      NULL);
}

int iscsi_sysfs_for_each_host(void *data, int *nr_found,
			      iscsi_sysfs_host_op_fn *fn)
{
	struct dirent **namelist;
	int rc = 0, i, n;
	struct host_info *info;

	info = malloc(sizeof(*info));
	if (!info)
		return ISCSI_ERR_NOMEM;

	n = scandir(ISCSI_HOST_DIR, &namelist, trans_filter,
		    alphasort);
	if (n <= 0)
		goto free_info;

	for (i = 0; i < n; i++) {
		memset(info, 0, sizeof(*info));
		if (sscanf(namelist[i]->d_name, "host%u", &info->host_no) !=
			   1) {
			log_error("Invalid iscsi host dir: %s",
				  namelist[i]->d_name);
			break;
		}

		iscsi_sysfs_get_hostinfo_by_host_no(info);
		rc = fn(data, info);
		if (rc != 0)
			break;
		(*nr_found)++;
	}

	for (i = 0; i < n; i++)
		free(namelist[i]);
	free(namelist);

free_info:
	free(info);
	return rc;
}

int iscsi_sysfs_for_each_iface_on_host(void *data, uint32_t host_no,
				       int *nr_found,
				       iscsi_sysfs_iface_op_fn *fn)
{
	struct dirent **namelist;
	int rc = 0, i, n;
	struct iface_rec iface;
        char devpath[PATH_SIZE];
        char sysfs_dev_iscsi_iface_path[PATH_SIZE];
        char id[NAME_SIZE];

        snprintf(id, sizeof(id), "host%u", host_no);
        if (!sysfs_lookup_devpath_by_subsys_id(devpath, sizeof(devpath),
                                               SCSI_SUBSYS, id)) {
                log_error("Could not look up host's ifaces via scsi bus.");
                return ISCSI_ERR_SYSFS_LOOKUP;
        }

	sprintf(sysfs_dev_iscsi_iface_path, "/sys");
	strlcat(sysfs_dev_iscsi_iface_path, devpath, sizeof(sysfs_dev_iscsi_iface_path));
	strlcat(sysfs_dev_iscsi_iface_path, "/iscsi_iface", sizeof(sysfs_dev_iscsi_iface_path));

	n = scandir(sysfs_dev_iscsi_iface_path, &namelist, trans_filter, alphasort);
	if (n <= 0)
		/* older kernels or some drivers will not have ifaces */
		return 0;

	for (i = 0; i < n; i++) {
		memset(&iface, 0, sizeof(iface));

		iscsi_sysfs_read_iface(&iface, host_no, NULL,
				       namelist[i]->d_name);
		rc = fn(data, &iface);
		if (rc != 0)
			break;
		(*nr_found)++;
	}

	for (i = 0; i < n; i++)
		free(namelist[i]);
	free(namelist);
	return rc;
}

/**
 * sysfs_session_has_leadconn - checks if session has lead conn in kernel
 * @sid: session id
 *
 * return 1 if session has lead conn and 0 if not.
 */
int iscsi_sysfs_session_has_leadconn(uint32_t sid)
{
	char devpath[PATH_SIZE];
	char id[NAME_SIZE];

	snprintf(id, sizeof(id), "connection%u:0", sid);
	return sysfs_lookup_devpath_by_subsys_id(devpath, sizeof(devpath),
						 ISCSI_CONN_SUBSYS, id);
}

/*
 * iscsi_sysfs_get_sid_from_path - parse a string for the sid
 * @session: session path
 *
 * Given sysfs_device is a directory name of the form:
 *
 * /sys/devices/platform/hostH/sessionS/targetH:B:I/H:B:I:L
 * /sys/devices/platform/hostH/sessionS/targetH:B:I
 * /sys/devices/platform/hostH/sessionS
 *
 * return the sid S. If just the sid is passed in it will be converted
 * to an int.
 */
int iscsi_sysfs_get_sid_from_path(char *session)
{
	struct sysfs_device *dev_parent, *dev;
	struct stat statb;
	char devpath[PATH_SIZE];
	char *end;
	int sid;

	sid = strtol(session, &end, 10);
	if (sid > 0 && *session != '\0' && *end == '\0')
		return sid;

	if (lstat(session, &statb)) {
		log_error("%s is an invalid session ID or path", session);
		exit(1);
	}

	if (!S_ISDIR(statb.st_mode) && !S_ISLNK(statb.st_mode)) {
		log_error("%s is not a directory", session);
		exit(1);
	}

	if (!strncmp(session, "/sys", 4))
		strlcpy(devpath, session + 4, sizeof(devpath));
	else
		strlcpy(devpath, session, sizeof(devpath));

	dev = sysfs_device_get(devpath);
	if (!dev) {
		log_error("Could not get dev for %s. Possible sysfs "
			  "incompatibility.", devpath);
		return -1;
	}

	if (!strncmp(dev->kernel, "session", 7))
		return atoi(dev->kernel_number);

	dev_parent = sysfs_device_get_parent(dev);
	while (dev_parent != NULL) {
		if (strncmp(dev_parent->kernel, "session", 7) == 0)
			return atoi(dev_parent->kernel_number);
		dev_parent = sysfs_device_get_parent(dev_parent);
	}

	log_error("Unable to find sid in path %s", session);
	return -1;
}

int iscsi_sysfs_get_sessioninfo_by_id(struct session_info *info, char *session)
{
	char id[NAME_SIZE];
	int ret, pers_failed = 0;
	uint32_t host_no;

	if (sscanf(session, "session%d", &info->sid) != 1) {
		log_error("invalid session '%s'", session);
		return ISCSI_ERR_INVAL;
	}

	ret = sysfs_get_str(session, ISCSI_SESSION_SUBSYS, "targetname",
			    info->targetname, sizeof(info->targetname));
	if (ret) {
		log_error("could not read session targetname: %d", ret);
		return ISCSI_ERR_SYSFS_LOOKUP;
	}

	ret = sysfs_get_str(session, ISCSI_SESSION_SUBSYS, "username",
				(info->chap).username,
				sizeof((info->chap).username));
	if (ret)
		log_debug(5, "could not read username: %d", ret);

	ret = sysfs_get_str(session, ISCSI_SESSION_SUBSYS, "password",
				(info->chap).password,
				sizeof((info->chap).password));
	if (ret)
		log_debug(5, "could not read password: %d", ret);

	ret = sysfs_get_str(session, ISCSI_SESSION_SUBSYS, "username_in",
				(info->chap).username_in,
				sizeof((info->chap).username_in));
	if (ret)
		log_debug(5, "could not read username in: %d", ret);

	ret = sysfs_get_str(session, ISCSI_SESSION_SUBSYS, "password_in",
				(info->chap).password_in,
				sizeof((info->chap).password_in));
	if (ret)
		log_debug(5, "could not read password in: %d", ret);

	ret = sysfs_get_int(session, ISCSI_SESSION_SUBSYS, "recovery_tmo",
				&((info->tmo).recovery_tmo));
	if (ret)
		(info->tmo).recovery_tmo = -1;

	ret = sysfs_get_int(session, ISCSI_SESSION_SUBSYS, "lu_reset_tmo",
				&((info->tmo).lu_reset_tmo));
	if (ret)
		(info->tmo).lu_reset_tmo = -1;

	ret = sysfs_get_int(session, ISCSI_SESSION_SUBSYS, "tgt_reset_tmo",
				&((info->tmo).tgt_reset_tmo));
	if (ret)
		(info->tmo).lu_reset_tmo = -1;

	sysfs_get_int(session, ISCSI_SESSION_SUBSYS, "abort_tmo",
				&((info->tmo).abort_tmo));
	if (ret)
		(info->tmo).abort_tmo = -1;

	ret = sysfs_get_int(session, ISCSI_SESSION_SUBSYS, "tpgt",
			    &info->tpgt);
	if (ret) {
		log_error("could not read session tpgt: %d", ret);
		return ISCSI_ERR_SYSFS_LOOKUP;
	}

	snprintf(id, sizeof(id), ISCSI_CONN_ID, info->sid);
	/* some HW drivers do not export addr and port */
	memset(info->persistent_address, 0, NI_MAXHOST);
	ret = sysfs_get_str(id, ISCSI_CONN_SUBSYS, "persistent_address",
			    info->persistent_address,
			    sizeof(info->persistent_address));
	if (ret) {
		pers_failed = 1;
		/* older qlogic does not support this */
		log_debug(5, "could not read pers conn addr: %d", ret);
	}

	memset(info->address, 0, NI_MAXHOST);
	ret = sysfs_get_str(id, ISCSI_CONN_SUBSYS, "address",
			    info->address, sizeof(info->address));
	if (ret) {
		log_debug(5, "could not read curr addr: %d", ret);
		/* iser did not export this */
		if (!pers_failed)
			strcpy(info->address, info->persistent_address);
	} else if (pers_failed)
		/*
		 * for qla if we could not get the persistent addr
		 * we will use the current for both addrs
		 */
		strcpy(info->persistent_address, info->address);
	pers_failed = 0;

	info->persistent_port = -1;
	ret = sysfs_get_int(id, ISCSI_CONN_SUBSYS, "persistent_port",
			    &info->persistent_port);
	if (ret) {
		pers_failed = 1;
		log_debug(5, "Could not read pers conn port %d", ret);
	}

	info->port = -1;
	ret = sysfs_get_int(id, ISCSI_CONN_SUBSYS, "port", &info->port);
	if (ret) {
		/* iser did not export this */
		if (!pers_failed)
			info->port = info->persistent_port;
		log_debug(5, "Could not read curr conn port %d", ret);
	} else if (pers_failed)
		/*
		 * for qla if we could not get the persistent addr
		 * we will use the current for both addrs
		 */
		info->persistent_port = info->port;

	ret = 0;
	host_no = iscsi_sysfs_get_host_no_from_sid(info->sid, &ret);
	if (ret) {
		log_error("could not get host_no for session%d: %s.",
			  info->sid, iscsi_err_to_str(ret));
		return ret;
	}

	iscsi_sysfs_read_iface(&info->iface, host_no, session, NULL);

	log_debug(7, "found targetname %s address %s pers address %s port %d "
		 "pers port %d driver %s iface name %s ipaddress %s "
		 "netdev %s hwaddress %s iname %s",
		  info->targetname, info->address[0] ? info->address : "NA",
		  info->persistent_address[0] ? info->persistent_address : "NA",
		  info->port, info->persistent_port, info->iface.transport_name,
		  info->iface.name, info->iface.ipaddress,
		  info->iface.netdev, info->iface.hwaddress,
		  info->iface.iname);
	return 0;
}

int iscsi_sysfs_for_each_session(void *data, int *nr_found,
				 iscsi_sysfs_session_op_fn *fn,
				 int in_parallel)
{
	struct dirent **namelist;
	int rc = 0, n, i, chldrc = 0;
	struct session_info *info;
	pid_t pid = 0;

	info = calloc(1, sizeof(*info));
	if (!info)
		return ISCSI_ERR_NOMEM;

	info->iscsid_req_tmo = ISCSID_RESP_POLL_TIMEOUT;
	n = scandir(ISCSI_SESSION_DIR, &namelist, trans_filter,
		    alphasort);
	if (n <= 0)
		goto free_info;

	for (i = 0; i < n; i++) {
		rc = iscsi_sysfs_get_sessioninfo_by_id(info,
						       namelist[i]->d_name);
		if (rc) {
			log_error("could not find session info for %s",
				   namelist[i]->d_name);
			/* raced. session was shutdown while looping */
			rc = 0;
			continue;
		}

		if (in_parallel) {
			pid = fork();
		}
		if (pid == 0) {
			rc = fn(data, info);
			if (in_parallel) {
				exit(rc);
			} else {
				if (rc > 0) {
					break;
				} else if (rc == 0) {
					(*nr_found)++;
				} else {
					/* if less than zero it means it was not a match */
					rc = 0;
				}
			}
		} else if (pid < 0) {
			log_error("could not fork() for session %s, err %d",
				   namelist[i]->d_name, errno);
		}
	}

	if (in_parallel) {
		while (1) {
			if (wait(&chldrc) < 0) {
				/*
				 * ECHILD means no more children which is
				 * expected to happen sooner or later.
				 */
				if (errno != ECHILD) {
					rc = errno;
				}
				break;
			}

			if (!WIFEXITED(chldrc)) {
				/*
				 * abnormal termination (signal, exception, etc.)
				 *
				 * The non-parallel code path returns the first
				 * error so this keeps the same semantics.
				 */
				if (rc == 0)
					rc = ISCSI_ERR_CHILD_TERMINATED;
			} else if ((WEXITSTATUS(chldrc) != 0) &&
			           (WEXITSTATUS(chldrc) != 255)) {
				/*
				 * 0 is success
				 * 255 is a truncated return code from exit(-1)
				 *     and means no match
				 * anything else (this case) is an error
				 */
				if (rc == 0)
					rc = WEXITSTATUS(chldrc);
			} else if (WEXITSTATUS(chldrc) == 0) {
				/* success */
				(*nr_found)++;
			}
		}
	}

	for (i = 0; i < n; i++)
		free(namelist[i]);
	free(namelist);

free_info:
	free(info);
	return rc;
}

/*
 * count the number of sessions -- a much-simplified
 * version of iscsi_sysfs_for_each_session
 *
 * TODO: return an array of the session info we find, for use
 * by iscsi_sysfs_for_each_session(), so it doesn't have to
 * do it all over again
 */
int iscsi_sysfs_count_sessions(void)
{
	struct dirent **namelist = NULL;
	int n, i;
	struct session_info *info;


	info = calloc(1, sizeof(*info));
	if (!info)
		/* no sessions found */
		return 0;
	info->iscsid_req_tmo = -1;

	n = scandir(ISCSI_SESSION_DIR, &namelist, trans_filter, alphasort);
	if (n <= 0)
		/* no sessions found */
		goto free_info;

	/*
	 * try to get session info for each session found, but ignore
	 * errors if any since it may be a race condition
	 */
	for (i = 0; i < n; i++)
		if (iscsi_sysfs_get_sessioninfo_by_id(info,
					namelist[i]->d_name) != 0)
			log_warning("could not find session info for %s",
					namelist[i]->d_name);

	for (i = 0; i < n; i++)
		free(namelist[i]);
	free(namelist);

free_info:
	free(info);
	return n;
}

int iscsi_sysfs_get_session_state(char *state, int sid)
{
	char id[NAME_SIZE];

	snprintf(id, sizeof(id), ISCSI_SESSION_ID, sid);
	if (sysfs_get_str(id, ISCSI_SESSION_SUBSYS, "state", state,
			  SCSI_MAX_STATE_VALUE))
		return ISCSI_ERR_SYSFS_LOOKUP;
	return 0;
}

int iscsi_sysfs_get_host_state(char *state, int host_no)
{
	char id[NAME_SIZE];

	snprintf(id, sizeof(id), ISCSI_HOST_ID, host_no);
	if (sysfs_get_str(id, SCSI_HOST_SUBSYS, "state", state,
			  SCSI_MAX_STATE_VALUE))
		return ISCSI_ERR_SYSFS_LOOKUP;
	return 0;
}

int iscsi_sysfs_get_device_state(char *state, int host_no, int target, int lun)
{
	char id[NAME_SIZE];

	snprintf(id, sizeof(id), "%d:0:%d:%d", host_no, target, lun);
	if (sysfs_get_str(id, SCSI_SUBSYS, "state", state,
			  SCSI_MAX_STATE_VALUE)) {
		log_debug(3, "Could not read attr state for %s", id);
		return ISCSI_ERR_SYSFS_LOOKUP;
	}

	return 0;
}

char *iscsi_sysfs_get_blockdev_from_lun(int host_no, int target, int lun)
{
	char devpath[PATH_SIZE];
	char path_full[PATH_SIZE];
	char id[NAME_SIZE];
	DIR *dirfd;
	struct dirent *dent;
	size_t sysfs_len;
	struct stat statbuf;
	char *blockdev, *blockdup = NULL;

	snprintf(id, sizeof(id), "%d:0:%d:%d", host_no, target, lun);
	if (!sysfs_lookup_devpath_by_subsys_id(devpath, sizeof(devpath),
					       SCSI_SUBSYS, id)) {
		log_debug(3, "Could not lookup devpath for %s %s",
			  SCSI_SUBSYS, id);
		return NULL;
	}

	sysfs_len = strlcpy(path_full, sysfs_path, sizeof(path_full));
	if (sysfs_len >= sizeof(path_full))
		sysfs_len = sizeof(path_full) - 1;
	strlcat(path_full, devpath, sizeof(path_full));

	dirfd = opendir(path_full);
	if (!dirfd)
		return NULL;

	while ((dent = readdir(dirfd))) {
		if (!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, ".."))
			continue;

		/* not sure what tape looks like */
		if (strncmp(dent->d_name, "block:", 5))
			continue;

		strlcat(path_full, "/", sizeof(path_full));
		strlcat(path_full, dent->d_name, sizeof(path_full));
		/*
		 * 2.6.25 dropped the symlink and now block is a dir.
		 */
		if (lstat(path_full, &statbuf)) {
			log_error("Could not stat block path %s err %d",
				  path_full, errno);
			break;
		}

		if (S_ISLNK(statbuf.st_mode)) {
			blockdev = strchr(dent->d_name, ':');
			if (!blockdev)
				break;
			/* increment past colon */
			blockdev++;
			blockdup = strdup(blockdev);
		} else if (S_ISDIR(statbuf.st_mode)) {
			DIR *blk_dirfd;
			struct dirent *blk_dent;

			/* it should not be this hard should it? :) */
			blk_dirfd = opendir(path_full);
			if (!blk_dirfd) {
				log_debug(3, "Could not open blk path %s",
					  path_full);
				break;
			}

			while ((blk_dent = readdir(blk_dirfd))) {
				if (!strcmp(blk_dent->d_name, ".") ||
				    !strcmp(blk_dent->d_name, ".."))
					continue;
				blockdup = strdup(blk_dent->d_name);
				break;
			}
			closedir(blk_dirfd);
		}

		break;
	}
	closedir(dirfd);
	return blockdup;
}

static uint32_t get_target_no_from_sid(uint32_t sid, int *err)
{
	char devpath[PATH_SIZE];
	char path_full[PATH_SIZE];
	char id[NAME_SIZE];
	DIR *dirfd;
	struct dirent *dent;
	uint32_t host, bus, target = 0;
	size_t sysfs_len;

	*err = ISCSI_ERR_SESS_NOT_FOUND;

	snprintf(id, sizeof(id), "session%u", sid);
	if (!sysfs_lookup_devpath_by_subsys_id(devpath, sizeof(devpath),
					       ISCSI_SESSION_SUBSYS, id)) {
		log_debug(3, "Could not lookup devpath for %s %s",
			  ISCSI_SESSION_SUBSYS, id);
		return 0;
	}

	/*
	 * This does not seem safe from future changes, but we currently
	 * want /devices/platform/hostY/sessionX, but we come from the
	 * /class/iscsi_session/sessionX/device.
	 */
	sysfs_len = strlcpy(path_full, sysfs_path, sizeof(path_full));
	if (sysfs_len >= sizeof(path_full))
		sysfs_len = sizeof(path_full) - 1;
	strlcat(path_full, devpath, sizeof(path_full));
	strlcat(path_full, "/device", sizeof(devpath));

	dirfd = opendir(path_full);
	if (!dirfd)
		return 0;

	while ((dent = readdir(dirfd))) {
		if (!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, ".."))
			continue;

		if (strncmp(dent->d_name, "target", 6))
			continue;

		if (sscanf(dent->d_name, "target%u:%u:%u",
			   &host, &bus, &target) != 3)
			break;

		*err = 0;
		break;

	}
	closedir(dirfd);
	return target;

}

int iscsi_sysfs_is_transport_loaded(char *transport_name)
{
	struct iscsi_transport *t;

	/* sync up kernel and userspace */
	read_transports();

	/* check if the transport is loaded and matches */
	list_for_each_entry(t, &transports, list) {
		if (t->handle && !strncmp(t->name, transport_name,
					  ISCSI_TRANSPORT_NAME_MAXLEN))
			return 1;
	}

	return 0;
}

struct iscsi_transport *iscsi_sysfs_get_transport_by_name(char *transport_name)
{
	struct iscsi_transport *t;
	int retry = 0;

retry:
	/* sync up kernel and userspace */
	read_transports();

	/* check if the transport is loaded and matches */
	list_for_each_entry(t, &transports, list) {
		if (t->handle && !strncmp(t->name, transport_name,
					  ISCSI_TRANSPORT_NAME_MAXLEN))
			return t;
	}

	if (retry < 1) {
		retry++;
		if (!transport_load_kmod(transport_name))
			goto retry;
	}

	return NULL;
}

/* TODO: replace the following functions with some decent sysfs links */
struct iscsi_transport *iscsi_sysfs_get_transport_by_hba(uint32_t host_no)
{
	char name[ISCSI_TRANSPORT_NAME_MAXLEN];
	char id[NAME_SIZE];
	int rc;

	if (host_no > MAX_HOST_NO)
		return NULL;	/* not set? */

	snprintf(id, sizeof(id), ISCSI_HOST_ID, host_no);
	rc = sysfs_get_str(id, SCSI_HOST_SUBSYS, "proc_name", name,
			   ISCSI_TRANSPORT_NAME_MAXLEN);
	if (rc) {
		log_error("Could not read proc_name for host%u rc %d.",
			  host_no, rc);
		return NULL;
	}

	/*
	 * stupid, stupid. We named the transports tcp or iser, but the
	 * the modules are named iscsi_tcp and iscsi_iser
	 */
	if (strstr(name, "iscsi_"))
		return iscsi_sysfs_get_transport_by_name(name + 6);
	else
		return iscsi_sysfs_get_transport_by_name(name);
}

struct iscsi_transport *iscsi_sysfs_get_transport_by_sid(uint32_t sid)
{
	uint32_t host_no;
	int err;

	host_no = iscsi_sysfs_get_host_no_from_sid(sid, &err);
	if (err)
		return NULL;
	return iscsi_sysfs_get_transport_by_hba(host_no);
}

/*
 * For connection reinstatement we need to send the exp_statsn from
 * the previous connection
 *
 * This is only called when the connection is halted so exp_statsn is safe
 * to read without racing.
 */
int iscsi_sysfs_get_exp_statsn(int sid)
{
	char id[NAME_SIZE];
	uint32_t exp_statsn = 0;

	snprintf(id, sizeof(id), ISCSI_CONN_ID, sid);
	if (sysfs_get_uint(id, ISCSI_CONN_SUBSYS, "exp_statsn",
			   &exp_statsn)) {
		log_error("Could not read expstatsn for sid %d. "
			  "Using zero for exp_statsn.", sid);
		exp_statsn = 0;
	}
	return exp_statsn;
}

int iscsi_sysfs_session_supports_nop(int sid)
{
	char id[NAME_SIZE];
	uint32_t ping_tmo = 0;

	snprintf(id, sizeof(id), ISCSI_CONN_ID, sid);
	if (sysfs_get_uint(id, ISCSI_CONN_SUBSYS, "ping_tmo",
			   &ping_tmo)) {
		return 0;
	}
	return 1;
}

int iscsi_sysfs_for_each_device(void *data, int host_no, uint32_t sid,
				void (* fn)(void *data, int host_no,
					    int target, int lun))
{
	struct dirent **namelist;
	int h, b, t, l, i, n, err = 0, target;
	char devpath[PATH_SIZE];
	char id[NAME_SIZE];
	char path_full[3*PATH_SIZE];

	target = get_target_no_from_sid(sid, &err);
	if (err)
		return err;
	snprintf(id, sizeof(id), "session%u", sid);
	if (!sysfs_lookup_devpath_by_subsys_id(devpath, sizeof(devpath),
					       ISCSI_SESSION_SUBSYS, id)) {
		log_debug(3, "Could not lookup devpath for %s %s",
			  ISCSI_SESSION_SUBSYS, id);
		return ISCSI_ERR_SYSFS_LOOKUP;
	}

	snprintf(path_full, sizeof(path_full), "%s%s/device/target%d:0:%d",
		 sysfs_path, devpath, host_no, target);

	if (strlen(path_full) > PATH_SIZE) {
		log_debug(3, "Could not lookup devpath for %s %s (too long)",
			  ISCSI_SESSION_SUBSYS, id);
		return ISCSI_ERR_SYSFS_LOOKUP;
	}

	n = scandir(path_full, &namelist, trans_filter,
		    alphasort);
	if (n <= 0)
		return 0;

	for (i = 0; i < n; i++) {
		if (sscanf(namelist[i]->d_name, "%d:%d:%d:%d\n",
			   &h, &b, &t, &l) != 4)
			continue;
		fn(data, h, t, l);
	}

	for (i = 0; i < n; i++)
		free(namelist[i]);
	free(namelist);

	return 0;
}

void iscsi_sysfs_set_queue_depth(void *data, int hostno, int target, int lun)
{
	char id[NAME_SIZE];
	char write_buf[20];
	int err, qdepth = *((int *)data);

	snprintf(id, sizeof(id), "%d:0:%d:%d", hostno, target, lun);
	snprintf(write_buf, sizeof(write_buf), "%d", qdepth);
	log_debug(4, "set queue depth for %s to %s", id, write_buf);

	err = sysfs_set_param(id, SCSI_SUBSYS, "queue_depth", write_buf,
			      strlen(write_buf));
	if (err && err != EINVAL)
		log_error("Could not queue depth for LUN %d err %d.", lun, err);
}

void iscsi_sysfs_set_device_online(__attribute__((unused))void *data,
				   int hostno, int target, int lun)
{
	char *write_buf = "running\n", *state;
	char id[NAME_SIZE];
	int err;

	snprintf(id, sizeof(id), "%d:0:%d:%d", hostno, target, lun);
	log_debug(4, "online device %s", id);

	state = sysfs_get_value(id, SCSI_SUBSYS, "state");
	if (!state) {
		log_error("Could not read state for LUN %s\n", id);
		goto set_state;
	}

	if (!strcmp(state, "running"))
		goto done;
	/*
	 * The kernel can start to perform session level recovery cleanup
	 * any time after the conn start call, so we only want to change the
	 * state if we are in one of the offline states.
	 */
	if (strcmp(state, "offline") && strcmp(state, "transport-offline")) {
		log_debug(4, "Dev not offline. Skip onlining %s", id);
		goto done;
	}

set_state:
	err = sysfs_set_param(id, SCSI_SUBSYS, "state", write_buf,
			      strlen(write_buf));
	if (err && err != EINVAL)
		/* we should read the state */
		log_error("Could not online LUN %d err %d.", lun, err);

done:
	if (state)
		free(state);
}

void iscsi_sysfs_rescan_device(__attribute__((unused))void *data,
			       int hostno, int target, int lun)
{
	char *write_buf = "1";
	char id[NAME_SIZE];

	snprintf(id, sizeof(id), "%d:0:%d:%d", hostno, target, lun);
	log_debug(4, "rescanning device %s", id);
	sysfs_set_param(id, SCSI_SUBSYS, "rescan", write_buf,
			strlen(write_buf));
}

pid_t iscsi_sysfs_scan_host(int hostno, int async, int autoscan)
{
	char id[NAME_SIZE];
	char *write_buf = "- - -";
	pid_t pid = 0;

	if (async)
		pid = fork();

	if (pid >= 0 && !autoscan) {
		if (pid)
			log_debug(4, "host%d in manual scan mode, skipping scan", hostno);
	} else if (pid == 0) {
		/* child */
		log_debug(4, "scanning host%d", hostno);

		snprintf(id, sizeof(id), ISCSI_HOST_ID, hostno);
		sysfs_set_param(id, SCSI_HOST_SUBSYS, "scan", write_buf,
				strlen(write_buf));
		log_debug(4, "scanning host%d completed", hostno);
	} else if (pid > 0) {
		log_debug(4, "scanning host%d from pid %d", hostno, pid);
	} else
		/*
		 * Session is fine, so log the error and let the user
		 * scan by hand
		  */
		log_error("Could not start scanning process for host %d "
			  "err %d. Try scanning through sysfs.", hostno,
			  errno);
	return pid;
}

struct iscsi_transport *iscsi_sysfs_get_transport_by_session(char *sys_session)
{
	uint32_t sid;

        if (sscanf(sys_session, "session%u", &sid) != 1) {
                log_error("invalid session '%s'.", sys_session);
                return NULL;
        }

	return iscsi_sysfs_get_transport_by_sid(sid);
}

char *iscsi_sysfs_get_iscsi_kernel_version(void)
{
	return sysfs_attr_get_value("/module/scsi_transport_iscsi", "version");
}
