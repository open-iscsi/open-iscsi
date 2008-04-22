#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "log.h"
#include "actor.h"
#include "iscsi_ipc.h"
#include "mgmt_ipc.h"
#include "config.h"
#include "initiator.h"
#include "version.h"
#include "iscsi_settings.h"
#include "iscsi_sysfs.h"
#include "iscsi_proto.h"
#include "transport.h"
#include "idbm.h"
#include "iface.h"

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
str_to_ipport(char *str, int *port, int *tpgt)
{
	char *stpgt, *sport = str, *ip = str;

	if (!strchr(ip, '.')) {
		if (*ip == '[') {
			if (!(sport = strchr(ip, ']')))
				return NULL;
			*sport++ = '\0';
			ip++;
			str = sport;
		} else
			sport = NULL;
	}

	if (sport && (sport = strchr(str, ':'))) {
		*sport++ = '\0';
		*port = strtoul(sport, NULL, 10);
		str = sport;
	} else
		*port = ISCSI_LISTEN_PORT;

	if ((stpgt = strchr(str, ','))) {
		*stpgt++ = '\0';
		*tpgt = strtoul(stpgt, NULL, 10);
	} else
		*tpgt = PORTAL_GROUP_TAG_UNKNOWN;

	log_debug(2, "ip %s, port %d, tgpt %d", ip, *port, *tpgt);
	return ip;
}

#define ISCSI_MAX_FILES 16384

int increase_max_files(void)
{
	struct rlimit rl;
	int err;

	err = getrlimit(RLIMIT_NOFILE, &rl);
	if (err) {
		log_debug(1, "Could not get file limit (err %d)\n", errno);
		return errno;
	}
	log_debug(1, "Max file limits %lu %lu\n", rl.rlim_cur, rl.rlim_max);

	if (rl.rlim_cur < ISCSI_MAX_FILES)
		rl.rlim_cur = ISCSI_MAX_FILES;
	if (rl.rlim_max < ISCSI_MAX_FILES)
		rl.rlim_max = ISCSI_MAX_FILES;

	err = setrlimit(RLIMIT_NOFILE, &rl);
	if (err) {
		log_debug(1, "Could not set file limit to %lu/%lu (err %d)\n",
			  rl.rlim_cur, rl.rlim_max, errno);
		return errno;
	}

	return 0;
}

#define MAXSLEEP 128

static mgmt_ipc_err_e iscsid_connect(int *fd)
{
	int nsec;
	struct sockaddr_un addr;

	*fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (*fd < 0) {
		log_error("can not create IPC socket (%d)!", errno);
		return MGMT_IPC_ERR_ISCSID_COMM_ERR;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	memcpy((char *) &addr.sun_path + 1, ISCSIADM_NAMESPACE,
		strlen(ISCSIADM_NAMESPACE));
	/*
	 * Trying to connect with exponential backoff
	 */
	for (nsec = 1; nsec <= MAXSLEEP; nsec <<= 1) {
		if (connect(*fd, (struct sockaddr *) &addr, sizeof(addr)) == 0)
			/* Connection established */
			return MGMT_IPC_OK;

		/* If iscsid isn't there, there's no sense
		 * in retrying. */
		if (errno == ECONNREFUSED)
			break;

		/*
		 * Delay before trying again
		 */
		if (nsec <= MAXSLEEP/2)
			sleep(nsec);
	}
	log_error("can not connect to iSCSI daemon (%d)!", errno);
	return MGMT_IPC_ERR_ISCSID_COMM_ERR;
}

mgmt_ipc_err_e iscsid_request(int *fd, iscsiadm_req_t *req)
{
	int err;

	err = iscsid_connect(fd);
	if (err)
		return err;

	if ((err = write(*fd, req, sizeof(*req))) != sizeof(*req)) {
		log_error("got write error (%d/%d) on cmd %d, daemon died?",
			err, errno, req->command);
		close(*fd);
		return MGMT_IPC_ERR_ISCSID_COMM_ERR;
	}
	return MGMT_IPC_OK;
}

mgmt_ipc_err_e iscsid_response(int fd, iscsiadm_cmd_e cmd, iscsiadm_rsp_t *rsp)
{
	mgmt_ipc_err_e iscsi_err;
	int err;

	if ((err = recv(fd, rsp, sizeof(*rsp), MSG_WAITALL)) != sizeof(*rsp)) {
		log_error("got read error (%d/%d), daemon died?", err, errno);
		iscsi_err = MGMT_IPC_ERR_ISCSID_COMM_ERR;
	} else
		iscsi_err = rsp->err;
	close(fd);

	if (!iscsi_err && cmd != rsp->command)
		iscsi_err = MGMT_IPC_ERR_ISCSID_COMM_ERR;
	return iscsi_err;
}

mgmt_ipc_err_e do_iscsid(iscsiadm_req_t *req, iscsiadm_rsp_t *rsp)
{
	int fd;
	mgmt_ipc_err_e err;

	err = iscsid_request(&fd, req);
	if (err)
		return err;

	return iscsid_response(fd, req->command, rsp);
}

int iscsid_req_wait(iscsiadm_cmd_e cmd, int fd)
{
	iscsiadm_rsp_t rsp;

	memset(&rsp, 0, sizeof(iscsiadm_rsp_t));
	return iscsid_response(fd, cmd, &rsp);
}

int iscsid_req_by_rec_async(iscsiadm_cmd_e cmd, node_rec_t *rec, int *fd)
{
	iscsiadm_req_t req;

	memset(&req, 0, sizeof(iscsiadm_req_t));
	req.command = cmd;
	memcpy(&req.u.session.rec, rec, sizeof(node_rec_t));

	return iscsid_request(fd, &req);
}

int iscsid_req_by_rec(iscsiadm_cmd_e cmd, node_rec_t *rec)
{
	int err, fd;

	err = iscsid_req_by_rec_async(cmd, rec, &fd);
	if (err)
		return err;
	return iscsid_req_wait(cmd, fd);
}

int iscsid_req_by_sid_async(iscsiadm_cmd_e cmd, int sid, int *fd)
{
	iscsiadm_req_t req;

	memset(&req, 0, sizeof(iscsiadm_req_t));
	req.command = cmd;
	req.u.session.sid = sid;

	return iscsid_request(fd, &req);
}

int iscsid_req_by_sid(iscsiadm_cmd_e cmd, int sid)
{
	int err, fd;

	err = iscsid_req_by_sid_async(cmd, sid, &fd);
	if (err)
		return err;
	return iscsid_req_wait(cmd, fd);
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
	rec->session.initial_login_retry_max = DEF_INITIAL_LOGIN_RETRIES_MAX;
	rec->session.reopen_max = 32;
	rec->session.auth.authmethod = 0;
	rec->session.auth.password_length = 0;
	rec->session.auth.password_in_length = 0;
	rec->session.err_timeo.abort_timeout = DEF_ABORT_TIMEO;
	rec->session.err_timeo.lu_reset_timeout = DEF_LU_RESET_TIMEO;
	rec->session.err_timeo.host_reset_timeout = DEF_HOST_RESET_TIMEO;
	rec->session.timeo.replacement_timeout = DEF_REPLACEMENT_TIMEO;
	rec->session.iscsi.InitialR2T = 0;
	rec->session.iscsi.ImmediateData = 1;
	rec->session.iscsi.FirstBurstLength = DEF_INI_FIRST_BURST_LEN;
	rec->session.iscsi.MaxBurstLength = DEF_INI_MAX_BURST_LEN;
	rec->session.iscsi.DefaultTime2Wait = ISCSI_DEF_TIME2WAIT;
	rec->session.iscsi.DefaultTime2Retain = 0;
	rec->session.iscsi.MaxConnections = 1;
	rec->session.iscsi.MaxOutstandingR2T = 1;
	rec->session.iscsi.ERL = 0;
	rec->session.iscsi.FastAbort = 1;

	for (i=0; i<ISCSI_CONN_MAX; i++) {
		rec->conn[i].startup = ISCSI_STARTUP_MANUAL;
		rec->conn[i].port = ISCSI_LISTEN_PORT;
		rec->conn[i].tcp.window_size = TCP_WINDOW_SIZE;
		rec->conn[i].tcp.type_of_service = 0;
		rec->conn[i].timeo.login_timeout= DEF_LOGIN_TIMEO;
		rec->conn[i].timeo.logout_timeout= DEF_LOGOUT_TIMEO;
		rec->conn[i].timeo.auth_timeout = 45;

		rec->conn[i].timeo.noop_out_interval = DEF_NOOP_OUT_INTERVAL;
		rec->conn[i].timeo.noop_out_timeout = DEF_NOOP_OUT_TIMEO;

		rec->conn[i].iscsi.MaxRecvDataSegmentLength =
						DEF_INI_MAX_RECV_SEG_LEN;
		rec->conn[i].iscsi.HeaderDigest = CONFIG_DIGEST_NEVER;
		rec->conn[i].iscsi.DataDigest = CONFIG_DIGEST_NEVER;
		rec->conn[i].iscsi.IFMarker = 0;
		rec->conn[i].iscsi.OFMarker = 0;
	}

	iface_setup_defaults(&rec->iface);
}

void iscsid_handle_error(mgmt_ipc_err_e err)
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
		/* 12 */ "iSCSI driver not found. Please make sure it is loaded, and retry the operation",
		/* 13 */ "daemon access denied",
		/* 14 */ "iSCSI driver does not support requested capability.",
		/* 15 */ "already exists",
		/* 16 */ "Unknown request",
		/* 17 */ "encountered iSNS failure",
		/* 18 */ "could not communicate to iscsid",
	};
	log_error("initiator reported error (%d - %s)", err, err_msgs[err]);
}

int __iscsi_match_session(node_rec_t *rec, char *targetname,
			  char *address, int port, struct iface_rec *iface)
{
	if (!rec) {
		log_debug(6, "no rec info to match\n");
		return 1;
	}

	log_debug(6, "match session [%s,%s,%d][%s %s,%s,%s]",
		  rec->name, rec->conn[0].address, rec->conn[0].port,
		  rec->iface.name, rec->iface.transport_name,
		  rec->iface.hwaddress, rec->iface.ipaddress);

	if (iface)
		log_debug(6, "to [%s,%s,%d][%s %s,%s,%s]",
			  targetname, address, port, iface->name,
			  iface->transport_name, iface->hwaddress,
			  iface->ipaddress);


	if (strlen(rec->name) && strcmp(rec->name, targetname))
		return 0;

	if (strlen(rec->conn[0].address) &&
	    strcmp(rec->conn[0].address, address))
		return 0;

	if (rec->conn[0].port != -1 && port != rec->conn[0].port)
		return 0;

	if (!iface_match(&rec->iface, iface))
		return 0;

	return 1;
}

int iscsi_match_session(void *data, struct session_info *info)
{
	return __iscsi_match_session(data, info->targetname,
				     info->persistent_address,
				     info->persistent_port, &info->iface);
}
