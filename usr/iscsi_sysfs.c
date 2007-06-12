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
#include <search.h>
#include <dirent.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <linux/types.h>
#include <linux/unistd.h>

#include "log.h"
#include "initiator.h"
#include "transport.h"
#include "version.h"
#include "iscsi_sysfs.h"
#include "list.h"
#include "iscsi_settings.h"

#define ISCSI_TRANSPORT_DIR	"/sys/class/iscsi_transport"
#define ISCSI_SESSION_DIR	"/sys/class/iscsi_session"
#define ISCSI_CONN_DIR		"/sys/class/iscsi_connection"
#define ISCSI_HOST_DIR		"/sys/class/iscsi_host"

#define ISCSI_MAX_SYSFS_BUFFER NI_MAXHOST

/* tmp buffer used by sysfs functions */
static char sysfs_file[PATH_MAX];
int num_transports = 0;
LIST_HEAD(transports);

int read_sysfs_file(char *filename, void *value, char *format)
{
	FILE *file;
	char buffer[ISCSI_MAX_SYSFS_BUFFER + 1], *line;
	int err = 0;

	file = fopen(filename, "r");
	if (file) {
		line = fgets(buffer, sizeof(buffer), file);
		if (line)
			sscanf(buffer, format, value);
		else {
			log_debug(5, "Could not read %s.\n", filename);
			err = ENODATA;
		}
		fclose(file);
	} else {
		log_debug(5, "Could not open %s.\n", filename);
		err = errno;
	}
	return err;
}

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
	char filename[64];
	int i, n, found, err = 0;
	struct iscsi_transport *t;

	log_debug(7, "in %s", __FUNCTION__);

	n = scandir(ISCSI_TRANSPORT_DIR, &namelist, trans_filter,
		    versionsort);
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

		if (found)
			continue;

		/* copy new transport */
		t = malloc(sizeof(*t));
		if (!t)
			continue;
		log_debug(7, "Adding new transport %s", namelist[i]->d_name);

		INIT_LIST_HEAD(&t->sessions);
		INIT_LIST_HEAD(&t->list);
		strncpy(t->name, namelist[i]->d_name,
			ISCSI_TRANSPORT_NAME_MAXLEN);

		sprintf(filename, ISCSI_TRANSPORT_DIR"/%s/handle", t->name);
		err = read_sysfs_file(filename, &t->handle, "%llu\n");
		if (err)
			continue;

		sprintf(filename, ISCSI_TRANSPORT_DIR"/%s/caps", t->name);
		err = read_sysfs_file(filename, &t->caps, "0x%x");
		if (err)
			continue;

		list_add_tail(&t->list, &transports);
	}

	for (i = 0; i < n; i++)
		free(namelist[i]);
	free(namelist);
	num_transports = n;

	return 0;
}

static void get_session_param(int sid, char *param, void *value, char *format)
{
	/* set to invalid */
	if (!strcmp(format, "%s\n"))
		((char *)value)[0] = '\0';
	else
		*((int *)value) = -1;

	memset(sysfs_file, 0, PATH_MAX);
	sprintf(sysfs_file, ISCSI_SESSION_DIR"/session%d/%s", sid, param);
	read_sysfs_file(sysfs_file, value, format);
}

static void get_negotiated_conn_param(int sid, char *param, int *value)
{
	/* set to invalid */
	*value = -1;

	memset(sysfs_file, 0, PATH_MAX);
	sprintf(sysfs_file, ISCSI_CONN_DIR"/connection%d:0/%s", sid, param);
	read_sysfs_file(sysfs_file, value, "%d\n");
}

/* caller must check lengths */
void get_auth_conf(int sid, struct iscsi_auth_config *conf)
{
	memset(conf, 0, sizeof(*conf));

	get_session_param(sid, "username", conf->username, "%s\n");
	get_session_param(sid, "username_in", conf->username_in, "%s\n");
	get_session_param(sid, "password", conf->password, "%s\n");
	if (strlen((char *)conf->password))
		conf->password_length = strlen((char *)conf->password);
	get_session_param(sid, "password_in", conf->password_in, "%s\n");
	if (strlen((char *)conf->password_in))
		conf->password_in_length = strlen((char *)conf->password_in);
}

/* called must check for -1=invalid value */
void get_negotiated_conn_conf(int sid,
			      struct iscsi_conn_operational_config *conf)
{
	memset(conf, 0, sizeof(*conf));

	get_negotiated_conn_param(sid, "data_digest",
				  &conf->DataDigest);
	get_negotiated_conn_param(sid, "header_digest",
				  &conf->HeaderDigest);
	get_negotiated_conn_param(sid, "max_xmit_dlength",
				  &conf->MaxXmitDataSegmentLength);
	get_negotiated_conn_param(sid, "max_recv_dlength",
				  &conf->MaxRecvDataSegmentLength);
}

/* called must check for -1=invalid value */
void get_negotiated_session_conf(int sid,
				 struct iscsi_session_operational_config *conf)
{
	memset(conf, 0, sizeof(*conf));

	get_session_param(sid, "data_pdu_in_order",
			  &conf->DataPDUInOrder, "%d\n");
	get_session_param(sid, "data_seq_in_order",
			  &conf->DataSequenceInOrder, "%d\n");
	get_session_param(sid, "erl",
			  &conf->ERL, "%d\n");
	get_session_param(sid, "first_burst_len",
			  &conf->FirstBurstLength, "%d\n");
	get_session_param(sid, "max_burst_len",
			  &conf->MaxBurstLength, "%d\n");
	get_session_param(sid, "immediate_data",
			  &conf->ImmediateData, "%d\n");
	get_session_param(sid, "initial_r2t",
			  &conf->InitialR2T, "%d\n");
	get_session_param(sid, "max_outstanding_r2t",
			  &conf->MaxOutstandingR2T, "%d\n");
}

uint32_t get_host_no_from_sid(uint32_t sid, int *err)
{
	char *buf, *path, *tmp;
	uint32_t host_no;

	*err = 0;

	buf = calloc(2, PATH_MAX);
	if (!buf) {
		*err = ENOMEM;
		return 0;
	}
	path = buf + PATH_MAX;

	sprintf(path, ISCSI_SESSION_DIR"/session%d/device", sid);
	if (readlink(path, buf, PATH_MAX) < 0) {
		log_error("Could not get link for %s.", path);
		*err = errno;
		goto free_buf;
	}

	/* buf will be .....bus_info/hostX/sessionY */

	/* find hostX */
	tmp = strrchr(buf, '/');
	*tmp = '\0';

	/* find bus and increment past it */
	tmp = strrchr(buf, '/');
	tmp++;

	if (sscanf(tmp, "host%u", &host_no) != 1) {
		log_error("Could not get host for sid %u.", sid);
		*err = ENXIO;
		goto free_buf;
	}

free_buf:
	free(buf);
	return host_no;
}

static int __get_host_no_from_hwaddress(void *data, struct host_info *info)
{
	struct host_info *ret_info = data;

	if (!strcmp(ret_info->iface.hwaddress, info->iface.hwaddress)) {
		ret_info->host_no = info->host_no;
		return 1;
	}
	return 0;
}

static uint32_t get_host_no_from_hwaddress(char *address, int *rc)
{
	uint32_t host_no = -1;
	struct host_info *info;
	int nr_found, local_rc;

	*rc = 0;

	info = calloc(1, sizeof(*info));
	if (!info) {
		*rc = ENOMEM;
		return -1;
	}
	strcpy(info->iface.hwaddress, address);

	local_rc = sysfs_for_each_host(info, &nr_found,
					__get_host_no_from_hwaddress);
	if (local_rc == 1)
		host_no = info->host_no;
	else
		*rc = ENODEV;
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
		*rc = ENOMEM;
		return -1;
	}
	strcpy(info->iface.ipaddress, address);

	local_rc = sysfs_for_each_host(info, &nr_found,
					__get_host_no_from_ipaddress);
	if (local_rc == 1)
		host_no = info->host_no;
	else
		*rc = ENODEV;
	free(info);
	return host_no;
}

uint32_t get_host_no_from_iface(struct iface_rec *iface, int *rc)
{
	int tmp_rc;
	uint32_t host_no = -1;

	if (strlen(iface->hwaddress) &&
	    strcasecmp(iface->hwaddress, DEFAULT_HWADDRESS))
		host_no = get_host_no_from_hwaddress(iface->hwaddress, &tmp_rc);
	else if (strlen(iface->ipaddress) &&
		 strcasecmp(iface->ipaddress, DEFAULT_IPADDRESS))
		host_no = get_host_no_from_ipaddress(iface->ipaddress, &tmp_rc);
	else
		tmp_rc = EINVAL;

	*rc = tmp_rc;
	return host_no;
}

int sysfs_for_each_host(void *data, int *nr_found, sysfs_host_op_fn *fn)
{
	struct dirent **namelist;
	int rc = 0, i, n;
	struct host_info *info;
	struct iscsi_transport *t;

	info = calloc(1, sizeof(*info));
	if (!info)
		return ENOMEM;

	n = scandir(ISCSI_HOST_DIR, &namelist, trans_filter,
		    versionsort);
	if (n <= 0)
		goto free_info;

	for (i = 0; i < n; i++) {
		if (sscanf(namelist[i]->d_name, "host%u", &info->host_no) !=
			   1) {
			log_error("Invalid iscsi host dir: %s",
				  namelist[i]->d_name);
			break;
		}

		memset(sysfs_file, 0, PATH_MAX);
		sprintf(sysfs_file, ISCSI_HOST_DIR"/%s/initiatorname",
			namelist[i]->d_name);
		rc = read_sysfs_file(sysfs_file, info->iname, "%s\n");
		if (rc)
			log_debug(4, "Could not read initiatorname for host "
				  "%u. Error %d\n", info->host_no, rc);

		memset(sysfs_file, 0, PATH_MAX);
		sprintf(sysfs_file, ISCSI_HOST_DIR"/%s/ipaddress",
			namelist[i]->d_name);
		rc = read_sysfs_file(sysfs_file, info->iface.ipaddress, "%s\n");
		if (rc)
			log_debug(4, "Could not read ipaddress for host %u. "
				  "Error %d\n", info->host_no, rc);

		memset(sysfs_file, 0, PATH_MAX);
		sprintf(sysfs_file, ISCSI_HOST_DIR"/%s/hwaddress",
			namelist[i]->d_name);
		rc = read_sysfs_file(sysfs_file, info->iface.hwaddress, "%s\n");
		if (rc)
			log_debug(4, "Could not read hwaddress for host %u. "
				  "Error %d\n", info->host_no, rc);

		memset(sysfs_file, 0, PATH_MAX);
		sprintf(sysfs_file, ISCSI_HOST_DIR"/%s/netdev",
			namelist[i]->d_name);
		rc = read_sysfs_file(sysfs_file, info->iface.netdev, "%s\n");
		if (rc)
			log_debug(4, "Could not read netdev for host %u. "
				  "Error %d\n", info->host_no, rc);

		t = get_transport_by_hba(info->host_no);
		if (!t)
			log_debug(4, "could not get transport name for host %d",
				  info->host_no);
		else
			strcpy(info->iface.transport_name, t->name);

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

int get_sessioninfo_by_sysfs_id(struct session_info *info, char *session)
{
	int ret, pers_failed = 0;
	uint32_t host_no;
	struct iscsi_transport *t;

	if (sscanf(session, "session%d", &info->sid) != 1) {
		log_error("invalid session '%s'", session);
		return EINVAL;
	}

	memset(sysfs_file, 0, PATH_MAX);
	sprintf(sysfs_file, ISCSI_SESSION_DIR"/%s/targetname", session);
	ret = read_sysfs_file(sysfs_file, info->targetname, "%s\n");
	if (ret) {
		log_error("could not read session targetname: %d", ret);
		return ret;
	}

	memset(sysfs_file, 0, PATH_MAX);
	sprintf(sysfs_file, ISCSI_SESSION_DIR"/%s/tpgt", session);
	ret = read_sysfs_file(sysfs_file, &info->tpgt, "%u\n");
	if (ret) {
		log_error("could not read session tpgt: %d", ret);
		return ret;
	}

	/* some HW drivers do not export addr and port */
	memset(sysfs_file, 0, PATH_MAX);
	sprintf(sysfs_file, ISCSI_CONN_DIR"/connection%d:0/"
		"persistent_address", info->sid);
	memset(info->persistent_address, 0, NI_MAXHOST);
	ret = read_sysfs_file(sysfs_file, info->persistent_address, "%s\n");
	if (ret) {
		pers_failed = 1;
		/* older qlogic does not support this */
		log_debug(5, "could not read pers conn addr: %d", ret);
	}

	memset(sysfs_file, 0, PATH_MAX);
	sprintf(sysfs_file, ISCSI_CONN_DIR"/connection%d:0/address",
		 info->sid);
	memset(info->address, 0, NI_MAXHOST);
	ret = read_sysfs_file(sysfs_file, info->address, "%s\n");
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

	memset(sysfs_file, 0, PATH_MAX);
	sprintf(sysfs_file, ISCSI_CONN_DIR"/connection%d:0/"
		"persistent_port", info->sid);
	info->persistent_port = -1;
	ret = read_sysfs_file(sysfs_file, &info->persistent_port, "%u\n");
	if (ret) {
		pers_failed = 1;
		log_debug(5, "Could not read pers conn port %d", ret);
	}

	memset(sysfs_file, 0, PATH_MAX);
	sprintf(sysfs_file, ISCSI_CONN_DIR"/connection%d:0/port",
		info->sid);
	info->port = -1;
	ret = read_sysfs_file(sysfs_file, &info->port, "%u\n");
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
	host_no = get_host_no_from_sid(info->sid, &ret);
	if (ret) {
		log_error("could not get host_no for session %d.", ret);
		return ret;
	}

	memset(sysfs_file, 0, PATH_MAX);
	sprintf(sysfs_file, ISCSI_HOST_DIR"/host%u/hwaddress", host_no);
	/*
	 * backward compat
	 * If we cannot get the address we assume we are doing the old
	 * style and use default.
	 */
	sprintf(info->iface.hwaddress, DEFAULT_HWADDRESS);
	ret = read_sysfs_file(sysfs_file, info->iface.hwaddress, "%s\n");
	if (ret)
		log_debug(7, "could not read hwaddress for %s", sysfs_file);

	t = get_transport_by_sid(info->sid);
	if (!t)
		log_debug(7, "could not get transport name for session %d",
			  info->sid);
	else
		strcpy(info->iface.transport_name, t->name);

	memset(sysfs_file, 0, PATH_MAX);
	sprintf(sysfs_file, ISCSI_HOST_DIR"/host%u/ipaddress", host_no);
	/* if not found just print out default */
	sprintf(info->iface.ipaddress, DEFAULT_IPADDRESS);
	ret = read_sysfs_file(sysfs_file, info->iface.ipaddress, "%s\n");
	if (ret)
		log_debug(7, "could not read local address for %s",
			 sysfs_file);

	memset(sysfs_file, 0, PATH_MAX);
	sprintf(sysfs_file, ISCSI_HOST_DIR"/host%u/netdev", host_no);
	/* if not found just print out default */
	sprintf(info->iface.netdev, DEFAULT_NETDEV);
	ret = read_sysfs_file(sysfs_file, info->iface.netdev, "%s\n");
	if (ret)
		log_debug(7, "could not read netdev for %s",
			 sysfs_file);

	log_debug(7, "found targetname %s address %s pers address %s port %d "
		 "pers port %d driver %s iface ipaddress %s "
		 "netdev %s hwaddress %s",
		  info->targetname, info->address ? info->address : "NA",
		  info->persistent_address ? info->persistent_address : "NA",
		  info->port, info->persistent_port,
		  info->iface.transport_name, info->iface.ipaddress,
		  info->iface.netdev, info->iface.hwaddress);
	return 0;
}
 
int sysfs_for_each_session(void *data, int *nr_found, sysfs_session_op_fn *fn)
{
	struct dirent **namelist;
	int rc = 0, n, i;
	struct session_info *info;

	info = calloc(1, sizeof(*info));
	if (!info)
		return ENOMEM;

	sprintf(sysfs_file, ISCSI_SESSION_DIR);
	n = scandir(sysfs_file, &namelist, trans_filter,
		    versionsort);
	if (n <= 0)
		goto free_info;

	for (i = 0; i < n; i++) {
		rc = get_sessioninfo_by_sysfs_id(info, namelist[i]->d_name);
		if (rc) {
			log_error("could not find session info for %s",
				   namelist[i]->d_name);
			continue;
		}

		rc = fn(data, info);
		if (rc > 0)
			break;
		else if (rc == 0)
			(*nr_found)++;
		else
			/* if less than zero it means it was not a match */
			rc = 0;
	}

	for (i = 0; i < n; i++)
		free(namelist[i]);
	free(namelist);

free_info:
	free(info);
	return rc;
}

int get_host_state(char *state, int host_no)
{
	memset(sysfs_file, 0, PATH_MAX);
	sprintf(sysfs_file, "/sys/class/scsi_host/host%d/state", host_no);
	return read_sysfs_file(sysfs_file, state, "%s\n");
}

int get_device_state(char *state, int host_no, int target, int lun)
{
	memset(sysfs_file, 0, PATH_MAX);
	sprintf(sysfs_file, "/sys/bus/scsi/devices/%d:0:%d:%d/state",
		host_no, target, lun);
	return read_sysfs_file(sysfs_file, state, "%s\n");
}

char *get_blockdev_from_lun(int host_no, int target, int lun)
{
	DIR *dirfd;
	struct dirent *dent;
	char *blockdev, *blockdup = NULL;

	sprintf(sysfs_file, "/sys/bus/scsi/devices/%d:0:%d:%d",
		host_no, target, lun);
	dirfd = opendir(sysfs_file);
	if (!dirfd)
		return NULL;

	while ((dent = readdir(dirfd))) {
		if (!strcmp(dent->d_name, ".") || !strcmp(dent->d_name, ".."))
			continue;

		/* not sure what tape looks like */
		if (strncmp(dent->d_name, "block:", 5))
			continue;

		blockdev = strchr(dent->d_name, ':');
		if (!blockdev)
			break;
		/* increment past colon */
		blockdev++;

		blockdup = strdup(blockdev);
		break;

	}
	closedir(dirfd);
	return blockdup;
}

static uint32_t get_target_no_from_sid(uint32_t sid, int *err)
{
	DIR *dirfd;
	struct dirent *dent;
	uint32_t host, bus, target = 0;

	*err = ENODEV;

	sprintf(sysfs_file, ISCSI_SESSION_DIR"/session%u/device/", sid);
	dirfd = opendir(sysfs_file);
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

struct iscsi_transport *get_transport_by_name(char *transport_name)
{
	struct iscsi_transport *t;

	/* sync up kernel and userspace */
	read_transports();

	/* check if the transport is loaded and matches */
	list_for_each_entry(t, &transports, list) {
		if (t->handle && !strncmp(t->name, transport_name,
					  ISCSI_TRANSPORT_NAME_MAXLEN))
			return t;
	}
	return NULL;
}

/* TODO: replace the following functions with some decent sysfs links */
struct iscsi_transport *get_transport_by_hba(long host_no)
{
	char name[ISCSI_TRANSPORT_NAME_MAXLEN];
	int rc;

	if (host_no == -1)
		return NULL;

	memset(sysfs_file, 0, PATH_MAX);
	sprintf(sysfs_file, "/sys/class/scsi_host/host%lu/proc_name", host_no);
	rc = read_sysfs_file(sysfs_file, name, "%s\n");
	if (rc) {
		log_error("Could not read %s rc %d.", sysfs_file, rc);
		return NULL;
	}

	/*
	 * stupid, stupid. We named the transports tcp or iser, but the
	 * the modules are named iscsi_tcp and iscsi_iser
	 */
	if (strstr(name, "iscsi_"))
		return get_transport_by_name(name + 6);
	else
		return get_transport_by_name(name);
}

struct iscsi_transport *get_transport_by_sid(uint32_t sid)
{
	uint32_t host_no;
	int err;

	host_no = get_host_no_from_sid(sid, &err);
	if (err)
		return NULL;
	return get_transport_by_hba(host_no);
}

/*
 * For connection reinstatement we need to send the exp_statsn from
 * the previous connection
 *
 * This is only called when the connection is halted so exp_statsn is safe
 * to read without racing.
 */
int set_exp_statsn(iscsi_conn_t *conn)
{
	sprintf(sysfs_file,
		ISCSI_CONN_DIR"/connection%d:%d/exp_statsn",
		conn->session->id, conn->id);
	if (read_sysfs_file(sysfs_file, &conn->exp_statsn, "%u\n")) {
		log_error("Could not read %s. Using zero fpr exp_statsn.",
			  sysfs_file);
		conn->exp_statsn = 0;
	}
	return 0;
}

int sysfs_for_each_device(int host_no, uint32_t sid,
			  void (* fn)(int host_no, int target, int lun))
{
	struct dirent **namelist;
	int h, b, t, l, i, n, err = 0, target;

	target = get_target_no_from_sid(sid, &err);
	if (err)
		return err;

	sprintf(sysfs_file, ISCSI_SESSION_DIR"/session%d/device/target%d:0:%d",
		sid, host_no, target);
	n = scandir(sysfs_file, &namelist, trans_filter,
		    versionsort);
	if (n <= 0)
		return 0;

	for (i = 0; i < n; i++) {
		if (sscanf(namelist[i]->d_name, "%d:%d:%d:%d\n",
			   &h, &b, &t, &l) != 4)
			continue;
		fn(h, t, l);
	}

	for (i = 0; i < n; i++)
		free(namelist[i]);
	free(namelist);

	return 0;
}

void set_device_online(int hostno, int target, int lun)
{
	int fd;

	sprintf(sysfs_file, "/sys/bus/scsi/devices/%d:0:%d:%d/state",
		hostno, target, lun);
	fd = open(sysfs_file, O_WRONLY);
	if (fd < 0)
		return;
	log_debug(4, "online device using %s", sysfs_file);
	if (write(fd, "running\n", 8) == -1 && errno != EINVAL)
		/* we should read the state */
		log_error("Could not online LUN %d err %d.", lun, errno);
	close(fd);
}

/* TODO: remove this when we fix shutdown */
void delete_device(int hostno, int target, int lun)
{
	int fd;

	sprintf(sysfs_file, "/sys/bus/scsi/devices/%d:0:%d:%d/delete",
		hostno, target, lun);
	fd = open(sysfs_file, O_WRONLY);
	if (fd < 0)
		return;
	log_debug(4, "deleting device using %s", sysfs_file);
	write(fd, "1", 1);
	close(fd);
}

pid_t scan_host(int hostno, int async)
{
	pid_t pid = 0;
	int fd;

	sprintf(sysfs_file, "/sys/class/scsi_host/host%d/scan",
		hostno);
	fd = open(sysfs_file, O_WRONLY);
	if (fd < 0) {
		log_error("could not scan scsi host%d.", hostno);
		return -1;
	}

	if (async)
		pid = fork();
	if (pid == 0) {
		/* child */
		log_debug(4, "scanning host%d using %s", hostno,
			  sysfs_file);
		write(fd, "- - -", 5);
		log_debug(4, "scanning host%d completed\n", hostno);
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

	close(fd);
	return pid;
}

struct iscsi_transport *get_transport_by_session(char *sys_session)
{
	uint32_t sid;

        if (sscanf(sys_session, "session%u", &sid) != 1) {
                log_error("invalid session '%s'.", sys_session);
                return NULL;
        }

	return get_transport_by_sid(sid);
}

int get_iscsi_kernel_version(char *buf)
{
	if (read_sysfs_file(ISCSI_VERSION_FILE, buf, "%s\n"))
		return ENODATA;
	else
		return 0;
}

void check_class_version(void)
{
	char version[20];
	int i;

	if (get_iscsi_kernel_version(version))
		goto fail;

	log_warning("transport class version %s. iscsid version %s",
		    version, ISCSI_VERSION_STR);

	for (i = 0; i < strlen(version); i++) {
		if (version[i] == '-')
			break;
	}

	if (i == strlen(version))
		goto fail;

	/*
	 * We want to make sure the release and interface are the same.
	 * It is ok for the svn versions to be different.
	 */
	if (!strncmp(version, ISCSI_VERSION_STR, i) ||
	   /* support 2.6.18 */
	    !strncmp(version, "1.1", 3))
		return;

fail:
	log_error( "Missing or Invalid version from %s. Make sure a up "
		"to date scsi_transport_iscsi module is loaded and a up to"
		"date version of iscsid is running. Exiting...",
		ISCSI_VERSION_FILE);
	exit(1);
}
