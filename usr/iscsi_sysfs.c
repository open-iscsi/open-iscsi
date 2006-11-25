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
#include <linux/types.h>
#include <linux/unistd.h>

#include "log.h"
#include "initiator.h"
#include "transport.h"
#include "version.h"

#define ISCSI_TRANSPORT_DIR "/sys/class/iscsi_transport"
#define ISCSI_SESSION_DIR "/sys/class/iscsi_session"
#define ISCSI_CONN_DIR "/sys/class/iscsi_connection"

#define ISCSI_MAX_SYSFS_BUFFER NI_MAXHOST

/* tmp buffer used by sysfs functions */
static char sysfs_file[PATH_MAX];
int num_providers = 0;
struct qelem providers;

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

void init_providers(void)
{
	providers.q_forw = &providers;
	providers.q_back = &providers;
}

static int trans_filter(const struct dirent *dir)
{
	return strcmp(dir->d_name, ".") && strcmp(dir->d_name, "..");
}

static int read_transports(void)
{
	struct qelem *item;
	struct dirent **namelist;
	char filename[64];
	int i, n, found, err = 0;
	iscsi_provider_t *p;

	log_debug(7, "in %s", __FUNCTION__);

	if (num_providers == 0)
		init_providers();

	n = scandir(ISCSI_TRANSPORT_DIR, &namelist, trans_filter,
		    versionsort);
	if (n < 0) {
		log_error("Could not scan %s.", ISCSI_TRANSPORT_DIR);
		return n;
	}

	for (i = 0; i < n; i++) {
		found = 0;

		/* copy existing pr vider to new array */
		item = providers.q_forw;
		while (item != &providers) {
			p = (iscsi_provider_t *)item;

			if (!strcmp(p->name, namelist[i]->d_name)) {
				found = 1;
				break;
			}
			item = item->q_forw;
		}

		if (found)
			continue;

		/* copy new provider */
		p = malloc(sizeof(iscsi_provider_t));
		if (!p)
			continue;

		p->sessions.q_forw = &p->sessions;
		p->sessions.q_back = &p->sessions;

		strncpy(p->name, namelist[i]->d_name,
			ISCSI_TRANSPORT_NAME_MAXLEN);

		sprintf(filename, ISCSI_TRANSPORT_DIR"/%s/handle", p->name);
		err = read_sysfs_file(filename, &p->handle, "%llu\n");
		if (err)
			continue;

		sprintf(filename, ISCSI_TRANSPORT_DIR"/%s/caps", p->name);
		err = read_sysfs_file(filename, &p->caps, "0x%x");
		if (err)
			continue;

		insque(&p->list, &providers);
	}

	for (i = 0; i < n; i++)
		free(namelist[i]);
	free(namelist);
	num_providers = n;

	return 0;
}

static void get_negotiated_session_param(int sid, char *param, int *value)
{
	/* set to invalid */
	*value = -1;

	memset(sysfs_file, 0, PATH_MAX);
	sprintf(sysfs_file, ISCSI_SESSION_DIR"/session%d/%s", sid, param);
	read_sysfs_file(sysfs_file, value, "%d\n");
}

static void get_negotiated_conn_param(int sid, char *param, int *value)
{
	/* set to invalid */
	*value = -1;

	memset(sysfs_file, 0, PATH_MAX);
	sprintf(sysfs_file, ISCSI_CONN_DIR"/connection%d:0/%s", sid, param);
	read_sysfs_file(sysfs_file, value, "%d\n");
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

	get_negotiated_session_param(sid, "data_pdu_in_order",
				     &conf->DataPDUInOrder);
	get_negotiated_session_param(sid, "data_seq_in_order",
				     &conf->DataSequenceInOrder);
	get_negotiated_session_param(sid, "erl",
				     &conf->ERL);
	get_negotiated_session_param(sid, "first_burst_len",
				     &conf->FirstBurstLength);
	get_negotiated_session_param(sid, "max_burst_len",
				     &conf->MaxBurstLength);
	get_negotiated_session_param(sid, "immediate_data",
				     &conf->ImmediateData);
	get_negotiated_session_param(sid, "initial_r2t",
				     &conf->InitialR2T);
	get_negotiated_session_param(sid, "max_outstanding_r2t",
				     &conf->MaxOutstandingR2T);
}

int get_sessioninfo_by_sysfs_id(int *sid, char *targetname, char *addr,
				int *port, int *tpgt, char *session)
{
	int ret;

	if (sscanf(session, "session%d", sid) != 1) {
		log_error("invalid session '%s'", session);
		return EINVAL;
	}

	memset(sysfs_file, 0, PATH_MAX);
	sprintf(sysfs_file, ISCSI_SESSION_DIR"/%s/targetname", session);
	ret = read_sysfs_file(sysfs_file, targetname, "%s\n");
	if (ret) {
		log_error("could not read session targetname: %d", ret);
		return ret;
	}

	memset(sysfs_file, 0, PATH_MAX);
	sprintf(sysfs_file, ISCSI_SESSION_DIR"/%s/tpgt", session);
	ret = read_sysfs_file(sysfs_file, tpgt, "%u\n");
	if (ret) {
		log_error("could not read session tpgt: %d", ret);
		return ret;
	}

	/* some HW drivers do not export addr and port */
	memset(sysfs_file, 0, PATH_MAX);
	sprintf(sysfs_file, ISCSI_CONN_DIR"/connection%d:0/"
		"persistent_address", *sid);
	memset(addr, 0, NI_MAXHOST);
	ret = read_sysfs_file(sysfs_file, addr, "%s\n");
	if (ret) {
		/* fall back to current address */
		log_debug(5, "could not read pers conn addr: %d", ret);
		memset(sysfs_file, 0, PATH_MAX);
		sprintf(sysfs_file, ISCSI_CONN_DIR"/connection%d:0/address",
			 *sid);
		memset(addr, 0, NI_MAXHOST);
		ret = read_sysfs_file(sysfs_file, addr, "%s\n");
		if (ret)
			log_debug(5, "could not read curr addr: %d", ret);
	}

	memset(sysfs_file, 0, PATH_MAX);
	sprintf(sysfs_file, ISCSI_CONN_DIR"/connection%d:0/"
		"persistent_port", *sid);
	*port = -1;
	ret = read_sysfs_file(sysfs_file, port, "%u\n");
	if (ret) {
		/* fall back to current port */
		log_debug(5, "Could not read pers conn port %d\n", ret);
		memset(sysfs_file, 0, PATH_MAX);
		sprintf(sysfs_file, ISCSI_CONN_DIR"/connection%d:0/port",
			*sid);
		*port = -1;
		ret = read_sysfs_file(sysfs_file, port, "%u\n");
		if (ret)
			log_debug(5, "Could not read curr conn port %d\n", ret);
	}

	log_debug(7, "found targetname %s address %s port %d\n",
		  targetname, addr ? addr : "NA", *port);
	return 0;
}

int sysfs_for_each_session(void *data, int *nr_found,
			   int (* fn)(void *, char *, int, char *, int, int))
{
	struct dirent **namelist;
	int rc = 0, sid, port, tpgt, n, i;
	char *targetname, *address;

	targetname = malloc(TARGET_NAME_MAXLEN + 1);
	if (!targetname)
		return ENOMEM;

	address = malloc(NI_MAXHOST + 1);
	if (!address) {
		rc = ENOMEM;
		goto free_target;
	}

	sprintf(sysfs_file, ISCSI_SESSION_DIR);
	n = scandir(sysfs_file, &namelist, trans_filter,
		    versionsort);
	if (n <= 0)
		goto free_address;

	for (i = 0; i < n; i++) {
		rc = get_sessioninfo_by_sysfs_id(&sid, targetname, address,
						 &port, &tpgt,
						 namelist[i]->d_name);
		if (rc) {
			log_error("could not find session info for %s",
				   namelist[i]->d_name);
			continue;
		}

		rc = fn(data, targetname, tpgt, address, port, sid);
		if (rc != 0)
			break;
		(*nr_found)++;
	}

	for (i = 0; i < n; i++)
		free(namelist[i]);
	free(namelist);

free_address:
	free(address);
free_target:
	free(targetname);
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

uint32_t get_host_no_from_sid(uint32_t sid, int *err)
{
	char buf[PATH_MAX], path[PATH_MAX], *tmp;
	uint32_t host_no;

	*err = 0;

	memset(buf, 0, PATH_MAX);
	memset(path, 0, PATH_MAX);
	sprintf(path, ISCSI_SESSION_DIR"/session%d/device", sid);
	if (readlink(path, buf, PATH_MAX) < 0) {
		log_error("Could not get link for %s\n", path);
		*err = errno;
		return 0;
	}

	/* buf will be .....bus_info/hostX/sessionY */

	/* find hostX */
	tmp = strrchr(buf, '/');
	*tmp = '\0';

	/* find bus and increment past it */
	tmp = strrchr(buf, '/');
	tmp++;

	if (sscanf(tmp, "host%u", &host_no) != 1) {
		log_error("Could not get host for sid %u\n", sid);
		*err = ENXIO;
		return 0;
	}

	return host_no;
}

iscsi_provider_t *get_transport_by_name(char *transport_name)
{
	struct qelem *pitem;
	iscsi_provider_t *p;

	/* sync up kernel and userspace */
	read_transports();

	/* check if the transport is loaded */
	pitem = providers.q_forw;
	while (pitem != &providers) {
		p = (iscsi_provider_t *)pitem;

		if (p->handle && !strncmp(p->name, transport_name,
					  ISCSI_TRANSPORT_NAME_MAXLEN))
			return p;
		pitem = pitem->q_forw;
	}
	return NULL;
}

/* TODO: replace the following functions with some decent sysfs links */
iscsi_provider_t *get_transport_by_hba(long host_no)
{
	char name[ISCSI_TRANSPORT_NAME_MAXLEN];
	int rc;

	if (host_no == -1)
		return NULL;

	memset(sysfs_file, 0, PATH_MAX);
	sprintf(sysfs_file, "/sys/class/scsi_host/host%lu/proc_name", host_no);
	rc = read_sysfs_file(sysfs_file, name, "%s\n");
	if (rc) {
		log_error("Could not read %s rc %d\n", sysfs_file, rc);
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

iscsi_provider_t *get_transport_by_sid(uint32_t sid)
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
		log_error("Could not read %s. Using zero fpr exp_statsn\n",
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
		log_error("Could not online LUN %d err %d\n",
			  lun, errno);
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

pid_t __scan_host(int hostno, int async)
{
	pid_t pid = 0;
	int fd;

	sprintf(sysfs_file, "/sys/class/scsi_host/host%d/scan",
		hostno);
	fd = open(sysfs_file, O_WRONLY);
	if (fd < 0) {
		log_error("could not scan scsi host%d\n", hostno);
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
			  "err %d. Try scanning through sysfs\n", hostno,
			  errno);

	close(fd);
	return pid;
}

/*
 * Scan a session from usersapce using sysfs
 */
pid_t scan_host(iscsi_session_t *session, int async)
{
	return __scan_host(session->hostno, 1);
}

iscsi_provider_t *get_transport_by_session(char *sys_session)
{
	uint32_t sid;

        if (sscanf(sys_session, "session%u", &sid) != 1) {
                log_error("invalid session '%s'", sys_session);
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

	log_warning("transport class version %s. iscsid version %s\n",
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
	log_error("Invalid version from %s. Make sure a up to date "
		  "scsi_transport_iscsi module is loaded and a up to"
		  "date version of iscsid is running. Exiting...\n",
		  ISCSI_VERSION_FILE);
	exit(1);
}
