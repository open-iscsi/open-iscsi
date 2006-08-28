#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/un.h>

#include "log.h"
#include "actor.h"
#include "iscsi_ipc.h"
#include "mgmt_ipc.h"
#include "config.h"
#include "initiator.h"
#include "version.h"

void daemon_init(void)
{
	int fd;

	fd = open("/dev/null", O_RDWR);
	if (fd == -1) {
		exit(-1);
	}

	dup2(fd, 0);
	dup2(fd, 1);
	dup2(fd, 2);
	setsid();
	chdir("/");
}

int oom_adjust(void)
{
	int fd;
	char path[48];

	nice(-10);
	sprintf(path, "/proc/%d/oom_adj", getpid());
	fd = open(path, O_WRONLY);
	if (fd < 0) {
		return -1;
	}
	write(fd, "-16\n", 3); /* for 2.6.11 */
	write(fd, "-17\n", 3); /* for Andrea's patch */
	close(fd);

	return 0;
}

char*
str_to_ipport(char *str, int *port, int delim)
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

	if (sport && (sport = strchr(sport, delim))) {
		*sport = '\0';
		sport++;
		*port = strtoul(sport, NULL, 10);
	} else
		*port = DEF_ISCSI_PORT;

	return str;
}

static int iscsid_connect(void)
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

static int iscsid_request(int fd, iscsiadm_req_t *req)
{
	int err;

	if ((err = write(fd, req, sizeof(*req))) != sizeof(*req)) {
		log_error("got write error (%d/%d) on cmd %d, daemon died?",
			err, errno, req->command);
		if (err >= 0)
			err = -EIO;
	}
	return err;
}

static int iscsid_response(int fd, iscsiadm_rsp_t *rsp)
{
	int err;

	if ((err = recv(fd, rsp, sizeof(*rsp), MSG_WAITALL)) != sizeof(*rsp)) {
		log_error("got read error (%d/%d), daemon died?", err, errno);
		if (err >= 0)
			err = -EIO;
	} else
		err = rsp->err;

	return err;
}

int do_iscsid(int *ipc_fd, iscsiadm_req_t *req, iscsiadm_rsp_t *rsp)
{
	int err;

	if ((*ipc_fd = iscsid_connect()) < 0) {
		err = *ipc_fd;
		goto out;
	}

	if ((err = iscsid_request(*ipc_fd, req)) < 0)
		goto out;

	err = iscsid_response(*ipc_fd, rsp);
	if (!err && req->command != rsp->command)
		err = -EIO;
out:
	if (*ipc_fd > 0)
		close(*ipc_fd);
	*ipc_fd = -1;

	return err;
}

void idbm_node_setup_defaults(node_rec_t *rec)
{
	int i;

	memset(rec, 0, sizeof(node_rec_t));

	strcpy(rec->transport_name, "tcp");
	rec->dbversion = IDBM_VERSION;
	rec->active_conn = 1; /* at least one connection must exist */
	rec->tpgt = PORTAL_GROUP_TAG_UNKNOWN;
	rec->session.initial_cmdsn = 0;
	rec->session.reopen_max = 32;
	rec->session.auth.authmethod = 0;
	rec->session.auth.password_length = 0;
	rec->session.auth.password_in_length = 0;
	rec->session.err_timeo.abort_timeout = 10;
	rec->session.err_timeo.reset_timeout = 30;
	rec->session.timeo.replacement_timeout = 120;
	rec->session.iscsi.InitialR2T = 0;
	rec->session.iscsi.ImmediateData = 1;
	rec->session.iscsi.FirstBurstLength = 256 * 1024;
	rec->session.iscsi.MaxBurstLength = (16 * 1024 * 1024) - 1024;
	rec->session.iscsi.DefaultTime2Wait = 0;
	rec->session.iscsi.DefaultTime2Retain = 0;
	rec->session.iscsi.MaxConnections = 1;
	rec->session.iscsi.MaxOutstandingR2T = 1;
	rec->session.iscsi.ERL = 0;

	for (i=0; i<ISCSI_CONN_MAX; i++) {
		rec->conn[i].startup = 0;
		rec->conn[i].port = DEF_ISCSI_PORT;
		rec->conn[i].tcp.window_size = 512 * 1024;
		rec->conn[i].tcp.type_of_service = 0;
		rec->conn[i].timeo.login_timeout=15;
		rec->conn[i].timeo.auth_timeout = 45;
		rec->conn[i].timeo.active_timeout=5;
		rec->conn[i].timeo.idle_timeout = 60;
		rec->conn[i].timeo.ping_timeout = 5;

		rec->conn[i].timeo.noop_out_interval = 0;
		rec->conn[i].timeo.noop_out_timeout = 0;

		rec->conn[i].iscsi.MaxRecvDataSegmentLength = 128 * 1024;
		rec->conn[i].iscsi.HeaderDigest = CONFIG_DIGEST_PREFER_OFF;
		rec->conn[i].iscsi.DataDigest = CONFIG_DIGEST_NEVER;
		rec->conn[i].iscsi.IFMarker = 0;
		rec->conn[i].iscsi.OFMarker = 0;
	}

}

void iscsid_handle_error(int err)
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
		/* 14 */ "iSCSI transport capability failure",
		/* 15 */ "already exists",
	};
	log_error("initiator reported error (%d - %s)", err, err_msgs[err]);
}


/*
 * SYSFS helpers
 */
int read_sysfs_int_attr(char *path, uint32_t *retval)
{
	int fd, err = 0;
	char intbuf[20];

	*retval = 0;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		log_error("could not open '%s': %d", path, errno);
		return errno;
	}

	if (read(fd, &intbuf, 20) < 0) {
		log_error("could not read attribute %s: %d", path, errno);
		err = errno;
		goto done;
	} else
		*retval = strtol(intbuf, NULL, 10);

done:
	close(fd);
	return err;
}

int read_sysfs_str_attr(char *path, char *retval, int buflen)
{
	int fd, err = 0, len;

	*retval = 0;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		log_error("could not open '%s': %d", path, errno);
		return errno;
	}

	memset(retval, 0, buflen);
	if (read(fd, retval, buflen) < 0) {
		log_error("could not read attribute %s: %d", path, errno);
		err = errno;
	}

	len = strlen(retval);
	if (len > 2)
		/* add null where the newline is */
		retval[len - 1] = '\0';

	close(fd);
	return err;
}

int find_sessioninfo_by_sid(int *sid, char *targetname, char *addr,
			    int *port, int *tpgt, char *session)
{
	int ret;
	char *sysfs_file;

	sysfs_file = malloc(PATH_MAX);
	if (!sysfs_file)
		return -ENOMEM;

	if (sscanf(session, "session%d", sid) != 1) {
		log_error("invalid session '%s'", session);
		ret = errno;
		goto free_file;
	}

	memset(sysfs_file, 0, PATH_MAX);
	sprintf(sysfs_file, "/sys/class/iscsi_session/%s/targetname", session);
	ret = read_sysfs_str_attr(sysfs_file, targetname, TARGET_NAME_MAXLEN);
	if (ret) {
		log_error("could not read session targetname: %d", ret);
		goto free_file;
	}

	memset(sysfs_file, 0, PATH_MAX);
	sprintf(sysfs_file, "/sys/class/iscsi_session/%s/tpgt", session);
	ret = read_sysfs_int_attr(sysfs_file, (uint32_t *)tpgt);
	if (ret) {
		log_error("could not read session tpgt: %d", ret);
		goto free_file;
	}

	memset(sysfs_file, 0, PATH_MAX);
	sprintf(sysfs_file, "/sys/class/iscsi_connection/connection%d:0/"
		"persistent_address", *sid);
	ret = read_sysfs_str_attr(sysfs_file, addr, NI_MAXHOST);
	if (ret) {
		log_error("could not read conn addr: %d", ret);
		goto free_file;
	}

	memset(sysfs_file, 0, PATH_MAX);
	sprintf(sysfs_file, "/sys/class/iscsi_connection/connection%d:0/"
		"persistent_port", *sid);
	ret = read_sysfs_int_attr(sysfs_file, (uint32_t *)port);
	if (ret) {
		log_error("Could not read conn port %d\n", ret);
		goto free_file;
	}

	log_debug(7, "found targetname %s address %s port %d\n",
		  targetname, addr, *port);
	return 0;

free_file:
	free(sysfs_file);
	return ret;
}

void check_class_version(void)
{
	char version[20];
	int i;

	if (read_sysfs_str_attr(ISCSI_VERSION_FILE, version, 20))
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
	if (!strncmp(version, ISCSI_VERSION_STR, i))
		return;

fail:
		log_error("Invalid version from %s. Make sure a up to date "
			  "scsi_transport_iscsi module is loaded and a up to"
			  "date version of iscsid is running. Exiting...\n",
			  ISCSI_VERSION_FILE);
		exit(1);
	}
