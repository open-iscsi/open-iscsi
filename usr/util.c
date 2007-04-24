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
#include <linux/types.h>
#include <linux/unistd.h>

#include "log.h"
#include "actor.h"
#include "iscsi_ipc.h"
#include "mgmt_ipc.h"
#include "config.h"
#include "initiator.h"
#include "version.h"
#include "iscsi_settings.h"
#include "iscsi_sysfs.h"

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

	rec->tpgt = PORTAL_GROUP_TAG_UNKNOWN;
	rec->disc_type = DISCOVERY_TYPE_STATIC;
	rec->session.initial_cmdsn = 0;
	rec->session.cmds_max = CMDS_MAX;
	rec->session.queue_depth = QUEUE_DEPTH;
	rec->session.reopen_max = 32;
	rec->session.auth.authmethod = 0;
	rec->session.auth.password_length = 0;
	rec->session.auth.password_in_length = 0;
	rec->session.err_timeo.abort_timeout = 10;
	rec->session.err_timeo.reset_timeout = 30;
	rec->session.timeo.replacement_timeout = DEF_REPLACEMENT_TIMEO;
	rec->session.iscsi.InitialR2T = 0;
	rec->session.iscsi.ImmediateData = 1;
	rec->session.iscsi.FirstBurstLength = DEF_INI_FIRST_BURST_LEN;
	rec->session.iscsi.MaxBurstLength = DEF_INI_MAX_BURST_LEN;
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
		rec->conn[i].timeo.login_timeout= DEF_LOGIN_TIMEO;
		rec->conn[i].timeo.logout_timeout= DEF_LOGOUT_TIMEO;
		rec->conn[i].timeo.auth_timeout = 45;
		rec->conn[i].timeo.active_timeout=5;
		rec->conn[i].timeo.idle_timeout = 60;
		rec->conn[i].timeo.ping_timeout = 5;

		rec->conn[i].timeo.noop_out_interval = DEF_NOOP_OUT_INTERVAL;
		rec->conn[i].timeo.noop_out_timeout = DEF_NOOP_OUT_TIMEO;

		rec->conn[i].iscsi.MaxRecvDataSegmentLength =
						DEF_INI_MAX_RECV_SEG_LEN;
		rec->conn[i].iscsi.HeaderDigest = CONFIG_DIGEST_PREFER_OFF;
		rec->conn[i].iscsi.DataDigest = CONFIG_DIGEST_NEVER;
		rec->conn[i].iscsi.IFMarker = 0;
		rec->conn[i].iscsi.OFMarker = 0;
	}

	/*
	 * default is to use tcp through whatever the network layer
	 * selects for us
	 */
	sprintf(rec->iface.name, "default");
	sprintf(rec->iface.transport_name, "tcp");
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
		/* 16 */ "Unknown request",
		/* 17 */ "encountered iSNS failure",
	};
	log_error("initiator reported error (%d - %s)", err, err_msgs[err]);
}

int iscsi_match_session(void *data, char *targetname, int tpgt,
			char *address, int port, int sid, char *iface)
{
	node_rec_t *rec = data;
	struct iscsi_transport *t;

	log_debug(6, "looking for session [%d][%s,%s,%d][%s]", sid,
		  rec->name, rec->conn[0].address, rec->conn[0].port,
		  iface);

	t = get_transport_by_sid(sid);
	if (!t)
		return 0;

	if (!strcmp(rec->iface.transport_name, t->name) &&
	    !strcmp(rec->name, targetname) &&
	    !strcmp(rec->conn[0].address, address) &&
	    !strcmp(rec->iface.name, iface) &&
	    rec->conn[0].port == port)
		return 1;

	/* keep on looking */
	return 0;
}
