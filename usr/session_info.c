#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <inttypes.h>

#include <libopeniscsiusr/libopeniscsiusr.h>

#include "list.h"
#include "log.h"
#include "iscsi_sysfs.h"
#include "version.h"
#include "iscsi_settings.h"
#include "mgmt_ipc.h"
#include "session_info.h"
#include "transport.h"
#include "initiator.h"
#include "iface.h"
#include "iscsid_req.h"
#include "iscsi_err.h"

static int session_info_print_flat(struct iscsi_session *se);

int session_info_create_list(void *data, struct session_info *info)
{
	struct session_link_info *link_info = data;
	struct list_head *list = link_info->list;
	struct session_info *new, *curr, *match = NULL;

	if (link_info->match_fn && !link_info->match_fn(link_info->data, info))
		return -1;

	new = calloc(1, sizeof(*new));
	if (!new)
		return ISCSI_ERR_NOMEM;
	memcpy(new, info, sizeof(*new));
	INIT_LIST_HEAD(&new->list);

	if (list_empty(list)) {
		list_add_tail(&new->list, list);
		return 0;
	}

	list_for_each_entry(curr, list, list) {
		if (!strcmp(curr->targetname, info->targetname)) {
			match = curr;

			if (!strcmp(curr->address, info->address)) {
				match = curr;

				if (curr->port == info->port) {
					match = curr;
					break;
				}
			}
		}
	}

	list_add_tail(&new->list, match ? match->list.next : list);
	return 0;
}

void session_info_free_list(struct list_head *list)
{
	struct session_info *curr, *tmp;

	list_for_each_entry_safe(curr, tmp, list, list) {
		list_del(&curr->list);
		free(curr);
	}
}

static char *get_iscsi_node_type(uint32_t sid)
{
	int pid = iscsi_sysfs_session_user_created((int) sid);

	if (!pid)
		return "flash";
	else
		return "non-flash";
}

static int session_info_print_flat(struct iscsi_session *se)
{
	uint32_t sid = 0;
	struct iscsi_transport *t = NULL;

	sid = iscsi_session_sid_get(se);
	t = iscsi_sysfs_get_transport_by_sid((int) sid);

	if (strchr(iscsi_session_persistent_address_get(se), '.'))
		printf("%s: [%" PRIu32 "] %s:%" PRIi32 ",%"PRIi32 " %s (%s)\n",
			t ? t->name : UNKNOWN_VALUE,
			sid, iscsi_session_persistent_address_get(se),
			iscsi_session_persistent_port_get(se),
			iscsi_session_tpgt_get(se),
			iscsi_session_target_name_get(se),
			get_iscsi_node_type(sid));
	else
		printf("%s: [%" PRIu32 "] [%s]:%" PRIi32 ",%" PRIi32
		       " %s (%s)\n",
			t ? t->name : UNKNOWN_VALUE,
			sid, iscsi_session_persistent_address_get(se),
			iscsi_session_persistent_port_get(se),
			iscsi_session_tpgt_get(se),
			iscsi_session_target_name_get(se),
			get_iscsi_node_type(sid));
	return 0;
}

static int print_iscsi_state(int sid, char *prefix, int tmo)
{
	iscsiadm_req_t req;
	iscsiadm_rsp_t rsp;
	int err;
	char *state = NULL;
	char state_buff[SCSI_MAX_STATE_VALUE];
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
		"REOPEN",
		"REDIRECT",
	};

	memset(&req, 0, sizeof(iscsiadm_req_t));
	req.command = MGMT_IPC_SESSION_INFO;
	req.u.session.sid = sid;

	err = iscsid_exec_req(&req, &rsp, 1, tmo);
	/*
	 * for drivers like qla4xxx, iscsid does not display
	 * anything here since it does not know about it.
	 */
	if (!err && rsp.u.session_state.conn_state >= 0 &&
	    rsp.u.session_state.conn_state <= ISCSI_CONN_STATE_CLEANUP_WAIT)
		state = conn_state[rsp.u.session_state.conn_state];
	printf("%s\t\tiSCSI Connection State: %s\n", prefix,
	       state ? state : "Unknown");
	state = NULL;

	memset(state_buff, 0, SCSI_MAX_STATE_VALUE);
	if (!iscsi_sysfs_get_session_state(state_buff, sid))
		printf("%s\t\tiSCSI Session State: %s\n", prefix, state_buff);
	else
		printf("%s\t\tiSCSI Session State: Unknown\n", prefix);

	if (!err && rsp.u.session_state.session_state >= 0 &&
	   rsp.u.session_state.session_state <= R_STAGE_SESSION_REDIRECT)
		state = session_state[rsp.u.session_state.session_state];
	printf("%s\t\tInternal iscsid Session State: %s\n", prefix,
	       state ? state : "Unknown");
	return 0;
}

static void print_iscsi_params(int sid, char *prefix)
{
	struct iscsi_session_operational_config session_conf;
	struct iscsi_conn_operational_config conn_conf;

	iscsi_sysfs_get_negotiated_session_conf(sid, &session_conf);
	iscsi_sysfs_get_negotiated_conn_conf(sid, &conn_conf);

	printf("%s\t\t************************\n", prefix);
	printf("%s\t\tNegotiated iSCSI params:\n", prefix);
	printf("%s\t\t************************\n", prefix);

	if (is_valid_operational_value(conn_conf.HeaderDigest))
		printf("%s\t\tHeaderDigest: %s\n", prefix,
			conn_conf.HeaderDigest ? "CRC32C" : "None");
	if (is_valid_operational_value(conn_conf.DataDigest))
		printf("%s\t\tDataDigest: %s\n", prefix,
			conn_conf.DataDigest ? "CRC32C" : "None");
	if (is_valid_operational_value(conn_conf.MaxRecvDataSegmentLength))
		printf("%s\t\tMaxRecvDataSegmentLength: %d\n", prefix,
			conn_conf.MaxRecvDataSegmentLength);
	if (is_valid_operational_value(conn_conf.MaxXmitDataSegmentLength))
		printf("%s\t\tMaxXmitDataSegmentLength: %d\n", prefix,
			conn_conf.MaxXmitDataSegmentLength);
	if (is_valid_operational_value(session_conf.FirstBurstLength))
		printf("%s\t\tFirstBurstLength: %d\n", prefix,
			session_conf.FirstBurstLength);
	if (is_valid_operational_value(session_conf.MaxBurstLength))
		printf("%s\t\tMaxBurstLength: %d\n", prefix,
			session_conf.MaxBurstLength);
	if (is_valid_operational_value(session_conf.ImmediateData))
		printf("%s\t\tImmediateData: %s\n", prefix,
			session_conf.ImmediateData ? "Yes" : "No");
	if (is_valid_operational_value(session_conf.InitialR2T))
		printf("%s\t\tInitialR2T: %s\n", prefix,
			session_conf.InitialR2T ? "Yes" : "No");
	if (is_valid_operational_value(session_conf.MaxOutstandingR2T))
		printf("%s\t\tMaxOutstandingR2T: %d\n", prefix,
			session_conf.MaxOutstandingR2T);
}

static void print_scsi_device_info(void *data, int host_no, int target, int lun)
{
	char *prefix = data;
	char *blockdev, state[SCSI_MAX_STATE_VALUE];

	printf("%s\t\tscsi%d Channel 00 Id %d Lun: %d\n", prefix, host_no,
	       target, lun);
	blockdev = iscsi_sysfs_get_blockdev_from_lun(host_no, target, lun);
	if (blockdev) {
		printf("%s\t\t\tAttached scsi disk %s\t\t", prefix, blockdev);
		free(blockdev);

		if (!iscsi_sysfs_get_device_state(state, host_no, target, lun))
			printf("State: %s\n", state);
		else
			printf("State: Unknown\n");
	}
}

static int print_scsi_state(int sid, char *prefix, unsigned int flags)
{
	int host_no = -1, err = 0;
	char state[SCSI_MAX_STATE_VALUE];

	printf("%s\t\t************************\n", prefix);
	printf("%s\t\tAttached SCSI devices:\n", prefix);
	printf("%s\t\t************************\n", prefix);

	host_no = iscsi_sysfs_get_host_no_from_sid(sid, &err);
	if (err) {
		printf("%s\t\tUnavailable\n", prefix);
		return err;
	}

	if (flags & SESSION_INFO_HOST_DEVS) {
		printf("%s\t\tHost Number: %d\t", prefix, host_no);
		if (!iscsi_sysfs_get_host_state(state, host_no))
			printf("State: %s\n", state);
		else
			printf("State: Unknown\n");
	}

	if (flags & SESSION_INFO_SCSI_DEVS)
		iscsi_sysfs_for_each_device(prefix, host_no, sid,
					    print_scsi_device_info);
	return 0;
}

void session_info_print_tree(struct iscsi_session **ses, uint32_t se_count,
			     char *prefix, unsigned int flags, int do_show)
{
	struct iscsi_session *curr = NULL;
	struct iscsi_session *prev = NULL;
	const char *curr_targetname = NULL;
	const char *curr_address = NULL;
	const char *persistent_address = NULL;
	const char *prev_targetname = NULL;
	const char *prev_address = NULL;
	int32_t curr_port = 0;
	int32_t prev_port = 0;
	uint32_t i = 0;
	uint32_t sid = 0;
	char *new_prefix = NULL;
	int32_t tgt_reset_tmo = -1;
	int32_t lu_reset_tmo = -1;
	int32_t abort_tmo = -1;
	const char *pass = NULL;

	for (i = 0; i < se_count; ++i) {
		curr = ses[i];
		curr_targetname = iscsi_session_target_name_get(curr);
		sid = iscsi_session_sid_get(curr);
		if (prev != NULL)
			prev_targetname = iscsi_session_target_name_get(prev);
		else
			prev_targetname = NULL;

		if (! ((prev_targetname != NULL) &&
		       (curr_targetname != NULL) &&
		       (strcmp(prev_targetname, curr_targetname) == 0))) {
			printf("%sTarget: %s (%s)\n", prefix, curr_targetname,
				get_iscsi_node_type(sid));
			prev = NULL;
		}
		curr_address = iscsi_session_address_get(curr);
		curr_port = iscsi_session_port_get(curr);

		if (prev != NULL) {
			prev_address = iscsi_session_address_get(prev);
			prev_port = iscsi_session_port_get(prev);
		} else {
			prev_address = NULL;
			prev_port = 0;
		}
		if (! ((prev_address != NULL) &&
		       (curr_address != NULL) &&
		       (prev_port != 0) &&
		       (curr_port != 0) &&
		       (strcmp(prev_address, curr_address) == 0) &&
		       (curr_port == prev_port))) {
			if (strchr(curr_address, '.'))
				printf("%s\tCurrent Portal: %s:%" PRIi32
				       ",%" PRIi32 "\n",
				       prefix, curr_address, curr_port,
				       iscsi_session_tpgt_get(curr));
			else
				printf("%s\tCurrent Portal: [%s]:%" PRIi32
				       ",%" PRIi32 "\n",
				       prefix, curr_address, curr_port,
				       iscsi_session_tpgt_get(curr));
			persistent_address =
				iscsi_session_persistent_address_get(curr);

			if (strchr(persistent_address, '.'))
				printf("%s\tPersistent Portal: %s:%" PRIi32
				       ",%" PRIi32 "\n",
				       prefix, persistent_address,
				       iscsi_session_persistent_port_get(curr),
				       iscsi_session_tpgt_get(curr));
			else
				printf("%s\tPersistent Portal: [%s]:%" PRIi32
				       ",%" PRIi32 "\n",
				       prefix, persistent_address,
				       iscsi_session_persistent_port_get(curr),
				       iscsi_session_tpgt_get(curr));
		} else
			printf("\n");

		if (flags & SESSION_INFO_IFACE) {
			printf("%s\t\t**********\n", prefix);
			printf("%s\t\tInterface:\n", prefix);
			printf("%s\t\t**********\n", prefix);

			new_prefix = calloc(1, 1 + strlen(prefix) +
					    strlen("\t\t"));
			if (new_prefix == NULL) {
				printf("Could not print interface info. "
					"Out of Memory.\n");
				return;
			} else {
				sprintf(new_prefix, "%s%s", prefix, "\t\t");
				iface_print(iscsi_session_iface_get(curr),
					    new_prefix);
			}
			free(new_prefix);
		}

		if (flags & SESSION_INFO_ISCSI_STATE) {
			printf("%s\t\tSID: %" PRIu32 "\n", prefix, sid);
			print_iscsi_state((int) sid, prefix, -1 /* tmo */);
			/* TODO(Gris Ge): It seems in the whole project,
			 *		  tmo is always -1, correct?
			 */
		}

		if (flags & SESSION_INFO_ISCSI_TIM) {
			printf("%s\t\t*********\n", prefix);
			printf("%s\t\tTimeouts:\n", prefix);
			printf("%s\t\t*********\n", prefix);

			printf("%s\t\tRecovery Timeout: %" PRIi32 "\n", prefix,
			       iscsi_session_recovery_tmo_get(curr));

			tgt_reset_tmo = iscsi_session_tgt_reset_tmo_get(curr);
			lu_reset_tmo = iscsi_session_lu_reset_tmo_get(curr);
			abort_tmo = iscsi_session_abort_tmo_get(curr);

			if (tgt_reset_tmo >= 0)
				printf("%s\t\tTarget Reset Timeout: %" PRIi32
				       "\n", prefix, tgt_reset_tmo);
			else
				printf("%s\t\tTarget Reset Timeout: %s\n",
					prefix, UNKNOWN_VALUE);

			if (lu_reset_tmo >= 0)
				printf("%s\t\tLUN Reset Timeout: %" PRIi32 "\n",
				       prefix, lu_reset_tmo);
			else
				printf("%s\t\tLUN Reset Timeout: %s\n", prefix,
					UNKNOWN_VALUE);

			if (abort_tmo >= 0)
				printf("%s\t\tAbort Timeout: %" PRIi32 "\n",
				       prefix, abort_tmo);
			else
				printf("%s\t\tAbort Timeout: %s\n", prefix,
					UNKNOWN_VALUE);

		}
		if (flags & SESSION_INFO_ISCSI_AUTH) {
			printf("%s\t\t*****\n", prefix);
			printf("%s\t\tCHAP:\n", prefix);
			printf("%s\t\t*****\n", prefix);
			printf("%s\t\tusername: %s\n", prefix,
			       strlen(iscsi_session_username_get(curr)) ?
			       iscsi_session_username_get(curr) :
			       UNKNOWN_VALUE);

			if (!do_show)
				printf("%s\t\tpassword: %s\n", prefix,
					"********");
			else {
				pass = iscsi_session_password_get(curr);
				printf("%s\t\tpassword: %s\n", prefix,
				       strlen(pass) ?  pass : UNKNOWN_VALUE);
			}

			printf("%s\t\tusername_in: %s\n", prefix,
			       strlen(iscsi_session_username_in_get(curr)) ?
			       iscsi_session_username_in_get(curr) :
			       UNKNOWN_VALUE);
			if (!do_show)
				printf("%s\t\tpassword_in: %s\n", prefix,
					"********");
			else {
				pass = iscsi_session_password_in_get(curr);
				printf("%s\t\tpassword: %s\n", prefix,
				       strlen(pass) ?  pass : UNKNOWN_VALUE);
			}
		}

		if (flags & SESSION_INFO_ISCSI_PARAMS)
			print_iscsi_params((int) sid, prefix);

		if (flags & (SESSION_INFO_SCSI_DEVS | SESSION_INFO_HOST_DEVS))
			print_scsi_state((int) sid, prefix, flags);

		prev = curr;
	}
}

int session_info_print(int info_level, struct iscsi_session **ses,
		       uint32_t se_count, int do_show)
{
	int err = 0;
	char *version;
	unsigned int flags = 0;
	uint32_t i = 0;

	switch (info_level) {
	case 0:
	case -1:
		for (i = 0; i < se_count; ++i) {
			err = session_info_print_flat(ses[i]);
			if (err != 0)
				break;
		}
		break;
	case 3:
		version = iscsi_sysfs_get_iscsi_kernel_version();
		if (version) {
			printf("iSCSI Transport Class version %s\n",
				version);
			printf("version %s\n", ISCSI_VERSION_STR);
			free(version);
		}

		flags |= (SESSION_INFO_SCSI_DEVS | SESSION_INFO_HOST_DEVS);
		/* fall through */
	case 2:
		flags |= (SESSION_INFO_ISCSI_PARAMS | SESSION_INFO_ISCSI_TIM
				| SESSION_INFO_ISCSI_AUTH);
		/* fall through */
	case 1:
		flags |= (SESSION_INFO_ISCSI_STATE | SESSION_INFO_IFACE);
		session_info_print_tree(ses, se_count, "", flags, do_show);
		break;
	default:
		log_error("Invalid info level %d. Try 0 - 3.", info_level);
		return ISCSI_ERR_INVAL;
	}

	if (err) {
		log_error("Can not get list of active sessions (%d)", err);
		return err;
	}
	return 0;
}
