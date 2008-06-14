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

#include "log.h"
#include "initiator.h"
#include "transport.h"
#include "idbm.h"
#include "version.h"
#include "iscsi_sysfs.h"
#include "sysdeps.h"
#include "iscsi_settings.h"
#include "iface.h"

/*
 * TODO: remove the _DIR defines and search for subsys dirs like
 *  is done in sysfs.c.
 */
#define ISCSI_TRANSPORT_DIR	"/sys/class/iscsi_transport"
#define ISCSI_SESSION_DIR	"/sys/class/iscsi_session"
#define ISCSI_HOST_DIR		"/sys/class/iscsi_host"

#define ISCSI_SYSFS_INVALID_VALUE	"<NULL>"
#define ISCSI_SESSION_SUBSYS		"iscsi_session"
#define ISCSI_CONN_SUBSYS		"iscsi_connection"
#define ISCSI_HOST_SUBSYS		"iscsi_host"
#define ISCSI_TRANSPORT_SUBSYS		"iscsi_transport"
#define SCSI_HOST_SUBSYS		"scsi_host"
#define SCSI_DEVICE_SUBSYS		"scsi_device"
#define SCSI_SUBSYS			"scsi"

#define ISCSI_MAX_SYSFS_BUFFER NI_MAXHOST

/*
 * TODO: make this into a real API and check inputs better and add doc.
 */

static int num_transports;
LIST_HEAD(transports);

static int iscsi_sysfs_get_param(char *id, char *subsys, char *param,
				 void *ret_value, char *format)
{
	char devpath[PATH_SIZE];
	char *sysfs_value;

	/* set to invalid */
	if (!strcmp(format, "%s\n"))
		((char *)ret_value)[0] = '\0';
	else
		*((int *)ret_value) = -1;

	if (!sysfs_lookup_devpath_by_subsys_id(devpath, sizeof(devpath),
					       subsys, id)) {
		log_debug(3, "Could not lookup devpath for %s %s\n",
			  subsys, id);
		return EIO;
	}

	sysfs_value = sysfs_attr_get_value(devpath, param);
	if (!sysfs_value) {
		log_debug(3, "Could not read attr %s on path %s\n",
			  param, devpath);
		return EIO;
	}

	if (!strncmp(sysfs_value, ISCSI_SYSFS_INVALID_VALUE, 6))
		return ENODATA;

	sscanf(sysfs_value, format, ret_value);
	return 0;
}

#define iscsi_sysfs_get_param_by_str(name, subsys)			\
static int iscsi_sysfs_get_##name##_param(char *tag, char *param,	\
					  void *ret_value,		\
					  char *format)			\
{									\
	char id[NAME_SIZE];						\
									\
	snprintf(id, sizeof(id), "%s", tag);				\
	return iscsi_sysfs_get_param(id, subsys, param, ret_value, format);\
}

#define iscsi_sysfs_get_param_by_int(name, id_format, subsys)		\
static int iscsi_sysfs_get_##name##_param(int tag, char *param,		\
					  void *ret_value,		\
					  char *format)			\
{									\
	char id[NAME_SIZE];						\
									\
	snprintf(id, sizeof(id), id_format, tag);			\
	return iscsi_sysfs_get_param(id, subsys, param, ret_value, format);\
}

iscsi_sysfs_get_param_by_int(session, "session%d", ISCSI_SESSION_SUBSYS);
iscsi_sysfs_get_param_by_int(conn, "connection%d:0", ISCSI_CONN_SUBSYS);
iscsi_sysfs_get_param_by_int(iscsi_host, "host%d", ISCSI_HOST_SUBSYS);
iscsi_sysfs_get_param_by_int(scsi_host, "host%d", SCSI_HOST_SUBSYS);

iscsi_sysfs_get_param_by_str(transport, ISCSI_TRANSPORT_SUBSYS);
iscsi_sysfs_get_param_by_str(scsi_dev, SCSI_SUBSYS);

static int iscsi_sysfs_set_param(char *id, char *subsys, char *attr_name,
				 char *write_buf, ssize_t buf_size)
{
	struct stat statbuf;
	char devpath[PATH_SIZE];
	size_t sysfs_len;
	char path_full[PATH_SIZE];
	const char *path;
	int rc = 0, fd;

	if (!sysfs_lookup_devpath_by_subsys_id(devpath, sizeof(devpath),
					       subsys, id)) {
		log_debug(3, "Could not lookup devpath for %s %s\n",
			  subsys, id);
		return EIO;
	}

	sysfs_len = strlcpy(path_full, sysfs_path, sizeof(path_full));
	if(sysfs_len >= sizeof(path_full))
		sysfs_len = sizeof(path_full) - 1;
	path = &path_full[sysfs_len];
	strlcat(path_full, devpath, sizeof(path_full));
	strlcat(path_full, "/", sizeof(path_full));
	strlcat(path_full, attr_name, sizeof(path_full));

	if (lstat(path_full, &statbuf)) {
		log_debug(3, "Could not stat %s\n", path_full);
		return errno;
	}

	if ((statbuf.st_mode & S_IWUSR) == 0) {
		log_error("Could not write to %s. Invalid permissions.\n",
			  path_full);
		return EACCES;
	}

	fd = open(path_full, O_WRONLY);
	if (fd < 0) {
		log_error("Could not open %s err %d\n", path_full, errno);
		return errno;
	}

	if (write(fd, write_buf, buf_size) == -1)
		rc = errno;
	close(fd);
	return rc;
}

#define iscsi_sysfs_set_param_by_str(name, subsys)			\
static int iscsi_sysfs_set_##name##_param(char *tag, char *attr_name,	\
					  char *write_buf,		\
					  ssize_t buf_size)		\
{									\
	char id[NAME_SIZE];						\
									\
	snprintf(id, sizeof(id), "%s", tag);				\
	return iscsi_sysfs_set_param(id, subsys, attr_name, write_buf,	\
				     buf_size);				\
}

#define iscsi_sysfs_set_param_by_int(name, id_format, subsys)		\
static int iscsi_sysfs_set_##name##_param(int tag, char *attr_name,	\
					  char *write_buf,		\
					  ssize_t buf_size)		\
{									\
	char id[NAME_SIZE];						\
									\
	snprintf(id, sizeof(id), id_format, tag);			\
	return iscsi_sysfs_set_param(id, subsys, attr_name, write_buf,	\
				     buf_size);				\
}

iscsi_sysfs_set_param_by_int(scsi_host, "host%d", SCSI_HOST_SUBSYS);
iscsi_sysfs_set_param_by_str(scsi_dev, SCSI_SUBSYS);

/* mini implementation of versionsort for uclibc compatility */
int direntcmp(const void *d1, const void *d2)
{
	const char *a = (*(const struct dirent **)d1)->d_name;
	const char *b = (*(const struct dirent **)d2)->d_name;
	while (*a && *b) {
		int mask = (isdigit(*a) != 0) |  ((isdigit(*b) != 0) << 1);
		switch (mask) {
		case 0: /* none are digit */
			if (*a == *b)
				break;
			return (*a - *b);
		case 1: /* a is digit but not b */
			return -1;
		case 2: /* b is digit but not a */
			return 1;
		case 3: /* both ar digits */
			return atoi(a) - atoi(b);
		}
		a++; b++;
	}
	return *a - *b;
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
	int i, n, found;
	struct iscsi_transport *t;

	log_debug(7, "in %s", __FUNCTION__);

	n = scandir(ISCSI_TRANSPORT_DIR, &namelist, trans_filter,
		    direntcmp);
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

		if (iscsi_sysfs_get_transport_param(t->name, "handle",
						    &t->handle, "%llu\n"))
			continue;

		if (iscsi_sysfs_get_transport_param(t->name, "caps",
						    &t->caps, "0x%x"))
			continue;
		/*
		 * tmp hack for qla4xx compat
		 */
		if (!strcmp(t->name, "qla4xxx")) {
			t->caps |= CAP_DATA_PATH_OFFLOAD;
			t->caps |= CAP_FW_DB;
		}

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
	memset(conf, 0, sizeof(*conf));

	iscsi_sysfs_get_session_param(sid, "username", conf->username, "%s\n");
	iscsi_sysfs_get_session_param(sid, "username_in", conf->username_in,
				      "%s\n");
	iscsi_sysfs_get_session_param(sid, "password", conf->password, "%s\n");
	if (strlen((char *)conf->password))
		conf->password_length = strlen((char *)conf->password);
	iscsi_sysfs_get_session_param(sid, "password_in", conf->password_in,
				      "%s\n");
	if (strlen((char *)conf->password_in))
		conf->password_in_length = strlen((char *)conf->password_in);
}

/* called must check for -1=invalid value */
void iscsi_sysfs_get_negotiated_conn_conf(int sid,
				struct iscsi_conn_operational_config *conf)
{
	memset(conf, 0, sizeof(*conf));

	iscsi_sysfs_get_conn_param(sid, "data_digest", &conf->DataDigest,
				   "%d\n");
	iscsi_sysfs_get_conn_param(sid, "header_digest", &conf->HeaderDigest,
				   "%d\n");
	iscsi_sysfs_get_conn_param(sid, "max_xmit_dlength",
				   &conf->MaxXmitDataSegmentLength, "%d\n");
	iscsi_sysfs_get_conn_param(sid, "max_recv_dlength",
				   &conf->MaxRecvDataSegmentLength, "%d\n");
}

/* called must check for -1=invalid value */
void iscsi_sysfs_get_negotiated_session_conf(int sid,
				struct iscsi_session_operational_config *conf)
{
	memset(conf, 0, sizeof(*conf));

	iscsi_sysfs_get_session_param(sid, "data_pdu_in_order",
				      &conf->DataPDUInOrder, "%d\n");
	iscsi_sysfs_get_session_param(sid, "data_seq_in_order",
				      &conf->DataSequenceInOrder, "%d\n");
	iscsi_sysfs_get_session_param(sid, "erl", &conf->ERL, "%d\n");
	iscsi_sysfs_get_session_param(sid, "first_burst_len",
				      &conf->FirstBurstLength, "%d\n");
	iscsi_sysfs_get_session_param(sid, "max_burst_len",
				      &conf->MaxBurstLength, "%d\n");
	iscsi_sysfs_get_session_param(sid, "immediate_data",
				      &conf->ImmediateData, "%d\n");
	iscsi_sysfs_get_session_param(sid, "initial_r2t",
				      &conf->InitialR2T, "%d\n");
	iscsi_sysfs_get_session_param(sid, "max_outstanding_r2t",
				      &conf->MaxOutstandingR2T, "%d\n");
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
			  "incompatibility.\n", id);
		*err = EIO;
		return 0;
	}

	session_dev = sysfs_device_get(devpath);
	if (!session_dev) {
		log_error("Could not get dev for %s. Possible sysfs "
			  "incompatibility.\n", id);
		*err = EIO;
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
				  "sysfs incompatibility.\n", id);
			*err = EIO;
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
		*rc = ENOMEM;
		return -1;
	}
	strcpy(info->iface.netdev, netdev);

	local_rc = iscsi_sysfs_for_each_host(info, &nr_found,
					     __get_host_no_from_netdev);
	if (local_rc == 1)
		host_no = info->host_no;
	else
		*rc = ENODEV;
	free(info);
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

	local_rc = iscsi_sysfs_for_each_host(info, &nr_found,
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

	local_rc = iscsi_sysfs_for_each_host(info, &nr_found,
					     __get_host_no_from_ipaddress);
	if (local_rc == 1)
		host_no = info->host_no;
	else
		*rc = ENODEV;
	free(info);
	return host_no;
}

uint32_t iscsi_sysfs_get_host_no_from_iface(struct iface_rec *iface, int *rc)
{
	int tmp_rc;
	uint32_t host_no = -1;

	if (strlen(iface->hwaddress) &&
	    strcasecmp(iface->hwaddress, DEFAULT_HWADDRESS))
		host_no = get_host_no_from_hwaddress(iface->hwaddress, &tmp_rc);
	else if (strlen(iface->ipaddress) &&
		 strcasecmp(iface->ipaddress, DEFAULT_IPADDRESS))
		host_no = get_host_no_from_ipaddress(iface->ipaddress, &tmp_rc);
	else if(strlen(iface->netdev) &&
		strcasecmp(iface->netdev, DEFAULT_NETDEV))
		host_no = get_host_no_from_netdev(iface->netdev, &tmp_rc);
	else
		tmp_rc = EINVAL;

	*rc = tmp_rc;
	return host_no;
}

static int sysfs_read_iface(struct iface_rec *iface, int host_no, int sid)
{
	struct iscsi_transport *t;
	int ret;

	/*
	 * backward compat
	 * If we cannot get the address we assume we are doing the old
	 * style and use default.
	 */
	ret = iscsi_sysfs_get_iscsi_host_param(host_no, "hwaddress",
					       iface->hwaddress, "%s\n");
	if (ret) {
		sprintf(iface->hwaddress, DEFAULT_HWADDRESS);
		log_debug(7, "could not read hwaddress for host%d\n", host_no);
	}

	t = iscsi_sysfs_get_transport_by_hba(host_no);
	if (!t)
		log_debug(7, "could not get transport name for host%d",
			  host_no);
	else
		strcpy(iface->transport_name, t->name);

	/* if not found just print out default */
	ret = iscsi_sysfs_get_iscsi_host_param(host_no, "ipaddress",
					       iface->ipaddress, "%s\n");
	if (ret) {
		sprintf(iface->ipaddress, DEFAULT_IPADDRESS);
		log_debug(7, "could not read local address for host%d\n",
			  host_no);
	}

	/* if not found just print out default */
	ret = iscsi_sysfs_get_iscsi_host_param(host_no, "netdev",
					       iface->netdev, "%s\n");
	if (ret) {
		sprintf(iface->netdev, DEFAULT_NETDEV);
		log_debug(7, "could not read netdev for host%d\n", host_no);
	}

	ret = iscsi_sysfs_get_iscsi_host_param(host_no, "initiatorname",
					       iface->iname, "%s\n");
	if (ret)
		/* default iname is picked up later from initiatorname.iscsi */
		log_debug(7, "Could not read initiatorname for host%d\n",
			  host_no);

	/*
	 * this is on the session, because we support multiple bindings
	 * per device.
	 */
	memset(iface->name, 0, sizeof(iface->name));
	/*
	 * this was added after 2.0.869 so we could be doing iscsi_tcp
	 * session binding, but there may not be a ifacename set
	 */
	ret = iscsi_sysfs_get_session_param(sid, "ifacename", iface->name,
					    "%s\n");
	if (ret) {
		log_debug(7, "could not read iface name for sid %u\n", sid);
		/*
 		 * if the ifacename file is not there then we are using a older
 		 * kernel and can try to find the binding by the net info
 		 * which was used on these older kernels.
 		 */
		if (iface_get_by_net_binding(iface, iface))
			log_debug(7, "Could not find iface for session bound "
				  "to:" iface_fmt "\n", iface_str(iface));
	}
	return ret;
}

int iscsi_sysfs_for_each_host(void *data, int *nr_found,
			      iscsi_sysfs_host_op_fn *fn)
{
	struct dirent **namelist;
	int rc = 0, i, n;
	struct host_info *info;

	info = calloc(1, sizeof(*info));
	if (!info)
		return ENOMEM;

	n = scandir(ISCSI_HOST_DIR, &namelist, trans_filter,
		    direntcmp);
	if (n <= 0)
		goto free_info;

	for (i = 0; i < n; i++) {
		if (sscanf(namelist[i]->d_name, "host%u", &info->host_no) !=
			   1) {
			log_error("Invalid iscsi host dir: %s",
				  namelist[i]->d_name);
			break;
		}

		sysfs_read_iface(&info->iface, info->host_no, -1);

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
 * return the sid S. If just the sid is passed in it will be covnerted
 * to a int.
 */
int iscsi_sysfs_get_sid_from_path(char *session)
{
	struct sysfs_device *dev_parent, *dev;
	struct stat statb;
	char devpath[PATH_SIZE];

	if (lstat(session, &statb)) {
		log_debug(1, "Could not stat %s failed with %d",
			  session, errno);
		if (index(session, '/')) {
			log_error("%s is an invalid session path\n", session);
			exit(1);
		}
		return atoi(session);
	}

	if (!S_ISDIR(statb.st_mode) && !S_ISLNK(statb.st_mode)) {
		log_error("%s is not a directory", session);
		exit(1);
	}

	if (!strncmp(session, "/sys", 4))
		strncpy(devpath, session + 4, sizeof(devpath));
	else
		strncpy(devpath, session, sizeof(devpath));

	dev = sysfs_device_get(devpath);
	if (!dev) {
		log_error("Could not get dev for %s. Possible sysfs "
			  "incompatibility.\n", devpath);
		exit(1);
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
	exit(1);
	return 0;
}

int iscsi_sysfs_get_sessioninfo_by_id(struct session_info *info, char *session)
{
	int ret, pers_failed = 0;
	uint32_t host_no;

	if (sscanf(session, "session%d", &info->sid) != 1) {
		log_error("invalid session '%s'", session);
		return EINVAL;
	}

	ret = iscsi_sysfs_get_session_param(info->sid, "targetname",
					    info->targetname, "%s\n");
	if (ret) {
		log_error("could not read session targetname: %d", ret);
		return ret;
	}

	ret = iscsi_sysfs_get_session_param(info->sid, "tpgt", &info->tpgt,
					    "%u\n");
	if (ret) {
		log_error("could not read session tpgt: %u", ret);
		return ret;
	}

	/* some HW drivers do not export addr and port */
	memset(info->persistent_address, 0, NI_MAXHOST);
	ret = iscsi_sysfs_get_conn_param(info->sid, "persistent_address",
					 info->persistent_address, "%s\n");
	if (ret) {
		pers_failed = 1;
		/* older qlogic does not support this */
		log_debug(5, "could not read pers conn addr: %d", ret);
	}

	memset(info->address, 0, NI_MAXHOST);
	ret = iscsi_sysfs_get_conn_param(info->sid, "address",
					 info->address, "%s\n");
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
	ret = iscsi_sysfs_get_conn_param(info->sid, "persistent_port",
					 &info->persistent_port, "%u\n");
	if (ret) {
		pers_failed = 1;
		log_debug(5, "Could not read pers conn port %d", ret);
	}

	info->port = -1;
	ret = iscsi_sysfs_get_conn_param(info->sid, "port", &info->port,
					 "%u\n");
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
		log_error("could not get host_no for session%d err %d.",
			  info->sid, ret);
		return ret;
	}

	sysfs_read_iface(&info->iface, host_no, info->sid);
 
	log_debug(7, "found targetname %s address %s pers address %s port %d "
		 "pers port %d driver %s iface name %s ipaddress %s "
		 "netdev %s hwaddress %s iname %s",
		  info->targetname, info->address ? info->address : "NA",
		  info->persistent_address ? info->persistent_address : "NA",
		  info->port, info->persistent_port, info->iface.transport_name,
		  info->iface.name, info->iface.ipaddress,
		  info->iface.netdev, info->iface.hwaddress,
		  info->iface.iname);
	return 0;
}
 
int iscsi_sysfs_for_each_session(void *data, int *nr_found,
				 iscsi_sysfs_session_op_fn *fn)
{
	struct dirent **namelist;
	int rc = 0, n, i;
	struct session_info *info;

	info = calloc(1, sizeof(*info));
	if (!info)
		return ENOMEM;

	n = scandir(ISCSI_SESSION_DIR, &namelist, trans_filter,
		    direntcmp);
	if (n <= 0)
		goto free_info;

	for (i = 0; i < n; i++) {
		rc = iscsi_sysfs_get_sessioninfo_by_id(info,
						       namelist[i]->d_name);
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

int iscsi_sysfs_get_session_state(char *state, int sid)
{
	return iscsi_sysfs_get_session_param(sid, "state", state, "%s\n");
}

int iscsi_sysfs_get_host_state(char *state, int host_no)
{
	return iscsi_sysfs_get_scsi_host_param(host_no, "state", state, "%s\n");
}

int iscsi_sysfs_get_device_state(char *state, int host_no, int target, int lun)
{
	char id[NAME_SIZE];

	snprintf(id, sizeof(id), "%d:0:%d:%d", host_no, target, lun);
	if (iscsi_sysfs_get_scsi_dev_param(id, "state", state, "%s\n")) {
		log_debug(3, "Could not read attr state for %s\n", id);
		return EIO;
	}

	return 0;
}

char *iscsi_sysfs_get_blockdev_from_lun(int host_no, int target, int lun)
{
	char devpath[PATH_SIZE];
	char path_full[PATH_SIZE];
	char *path;
	char id[NAME_SIZE];
	DIR *dirfd;
	struct dirent *dent;
	size_t sysfs_len;
	struct stat statbuf;
	char *blockdev, *blockdup = NULL;

	snprintf(id, sizeof(id), "%d:0:%d:%d", host_no, target, lun);
	if (!sysfs_lookup_devpath_by_subsys_id(devpath, sizeof(devpath),
					       SCSI_SUBSYS, id)) {
		log_debug(3, "Could not lookup devpath for %s %s\n",
			  SCSI_SUBSYS, id);
		return NULL;
	}

	sysfs_len = strlcpy(path_full, sysfs_path, sizeof(path_full));
	if(sysfs_len >= sizeof(path_full))
		sysfs_len = sizeof(path_full) - 1;
	path = &path_full[sysfs_len];
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
			log_error("Could not stat block path %s err %d\n",
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
				log_debug(3, "Could not open blk path %s\n",
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
	char *path;
	char id[NAME_SIZE];
	DIR *dirfd;
	struct dirent *dent;
	uint32_t host, bus, target = 0;
	size_t sysfs_len;

	*err = ENODEV;

	snprintf(id, sizeof(id), "session%u", sid);
	if (!sysfs_lookup_devpath_by_subsys_id(devpath, sizeof(devpath),
					       ISCSI_SESSION_SUBSYS, id)) {
		log_debug(3, "Could not lookup devpath for %s %s\n",
			  ISCSI_SESSION_SUBSYS, id);
		return 0;
	}

	/*
	 * This does not seem safe from future changes, but we currently
	 * want /devices/platform/hostY/sessionX, but we come from the
	 * /class/iscsi_session/sessionX/device.
	 */
	sysfs_len = strlcpy(path_full, sysfs_path, sizeof(path_full));
	if(sysfs_len >= sizeof(path_full))
		sysfs_len = sizeof(path_full) - 1;
	path = &path_full[sysfs_len];
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

struct iscsi_transport *iscsi_sysfs_get_transport_by_name(char *transport_name)
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
struct iscsi_transport *iscsi_sysfs_get_transport_by_hba(long host_no)
{
	char name[ISCSI_TRANSPORT_NAME_MAXLEN];
	int rc;

	if (host_no == -1)
		return NULL;

	rc = iscsi_sysfs_get_scsi_host_param(host_no, "proc_name", name,
					     "%s\n");
	if (rc) {
		log_error("Could not read proc_name for host%ld rc %d.",
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
	uint32_t exp_statsn = 0;

	if (iscsi_sysfs_get_conn_param(sid, "exp_statsn", &exp_statsn,
				      "%u\n")) {
		log_error("Could not read expstatsn for sid %d. "
			  "Using zero for exp_statsn.", sid);
		exp_statsn = 0;
	}
	return exp_statsn;
}

int iscsi_sysfs_for_each_device(int host_no, uint32_t sid,
				void (* fn)(int host_no, int target, int lun))
{
	struct dirent **namelist;
	int h, b, t, l, i, n, err = 0, target;
	char devpath[PATH_SIZE];
	char id[NAME_SIZE];
	char path_full[PATH_SIZE];

	target = get_target_no_from_sid(sid, &err);
	if (err)
		return err;
	snprintf(id, sizeof(id), "session%u", sid);
	if (!sysfs_lookup_devpath_by_subsys_id(devpath, sizeof(devpath),
					       ISCSI_SESSION_SUBSYS, id)) {
		log_debug(3, "Could not lookup devpath for %s %s\n",
			  ISCSI_SESSION_SUBSYS, id);
		return EIO;
	}

	snprintf(path_full, sizeof(path_full), "%s%s/device/target%d:0:%d",
		 sysfs_path, devpath, host_no, target);
	n = scandir(path_full, &namelist, trans_filter,
		    direntcmp);
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

void iscsi_sysfs_set_device_online(int hostno, int target, int lun)
{
	char *write_buf = "running\n";
	char id[NAME_SIZE];
	int err;

	snprintf(id, sizeof(id), "%d:0:%d:%d", hostno, target, lun);
	log_debug(4, "online device %s", id);

	err = iscsi_sysfs_set_scsi_dev_param(id, "state", write_buf,
					     strlen(write_buf));
	if (err && err != EINVAL)
		/* we should read the state */
		log_error("Could not online LUN %d err %d.", lun, err);
}

void iscsi_sysfs_rescan_device(int hostno, int target, int lun)
{
	char *write_buf = "1";
	char id[NAME_SIZE];

	snprintf(id, sizeof(id), "%d:0:%d:%d", hostno, target, lun);
	log_debug(4, "rescanning device %s", id);
	iscsi_sysfs_set_scsi_dev_param(id, "rescan", write_buf,
				       strlen(write_buf));
}

pid_t iscsi_sysfs_scan_host(int hostno, int async)
{
	char *write_buf = "- - -";
	pid_t pid = 0;

	if (async)
		pid = fork();
	if (pid == 0) {
		/* child */
		log_debug(4, "scanning host%d", hostno);

		iscsi_sysfs_set_scsi_host_param(hostno, "scan", write_buf,
					        strlen(write_buf));
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

int iscsi_sysfs_check_class_version(void)
{
	char *version;
	int i;

	version = iscsi_sysfs_get_iscsi_kernel_version();
	if (!version)
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
		return 0;

fail:
	log_error( "Missing or Invalid version from %s. Make sure a up "
		"to date scsi_transport_iscsi module is loaded and a up to"
		"date version of iscsid is running. Exiting...",
		ISCSI_VERSION_FILE);
	return -1;
}
