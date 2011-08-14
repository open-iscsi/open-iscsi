#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

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

static int session_info_print_flat(void *data, struct session_info *info)
{
	struct iscsi_transport *t = iscsi_sysfs_get_transport_by_sid(info->sid);

	if (strchr(info->persistent_address, '.'))
		printf("%s: [%d] %s:%d,%d %s\n",
			t ? t->name : UNKNOWN_VALUE,
			info->sid, info->persistent_address,
			info->persistent_port, info->tpgt, info->targetname);
	else
		printf("%s: [%d] [%s]:%d,%d %s\n",
			t ? t->name : UNKNOWN_VALUE,
			info->sid, info->persistent_address,
			info->persistent_port, info->tpgt, info->targetname);
	return 0;
}

static int print_iscsi_state(int sid, char *prefix)
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

	err = iscsid_exec_req(&req, &rsp, 1);
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

void session_info_print_tree(struct list_head *list, char *prefix,
			     unsigned int flags, int do_show)
{
	struct session_info *curr, *prev = NULL;

	list_for_each_entry(curr, list, list) {
		if (!prev || strcmp(prev->targetname, curr->targetname)) {
			printf("%sTarget: %s\n", prefix, curr->targetname);
			prev = NULL;
		}

		if (!prev || (strcmp(prev->address, curr->address) ||
		     prev->port != curr->port)) {
			if (strchr(curr->address, '.'))
				printf("%s\tCurrent Portal: %s:%d,%d\n",
				       prefix, curr->address, curr->port,
				       curr->tpgt);
			else
				printf("%s\tCurrent Portal: [%s]:%d,%d\n",
				       prefix, curr->address, curr->port,
				       curr->tpgt);

			if (strchr(curr->persistent_address, '.'))
				printf("%s\tPersistent Portal: %s:%d,%d\n",
				       prefix, curr->persistent_address,
				       curr->persistent_port, curr->tpgt);
			else
				printf("%s\tPersistent Portal: [%s]:%d,%d\n",
				       prefix, curr->persistent_address,
				       curr->persistent_port, curr->tpgt);
		} else
			printf("\n");

		if (flags & SESSION_INFO_IFACE) {
			char *new_prefix;

			printf("%s\t\t**********\n", prefix);
			printf("%s\t\tInterface:\n", prefix);
			printf("%s\t\t**********\n", prefix);

			new_prefix = calloc(1, 1 + strlen(prefix) +
					    strlen("\t\t"));
			if (!new_prefix)
				printf("Could not print interface info. "
					"Out of Memory.\n");
			else {
				sprintf(new_prefix, "%s%s", prefix, "\t\t");
				iface_print(&curr->iface, new_prefix);
			}
		}

		if (flags & SESSION_INFO_ISCSI_STATE) {
			printf("%s\t\tSID: %d\n", prefix, curr->sid);
			print_iscsi_state(curr->sid, prefix);
		}
		if (flags & SESSION_INFO_ISCSI_TIM) {
			printf("%s\t\t*********\n", prefix);
			printf("%s\t\tTimeouts:\n", prefix);
			printf("%s\t\t*********\n", prefix);

			printf("%s\t\tRecovery Timeout: %d\n", prefix,
			      ((curr->tmo).recovery_tmo));

			if ((curr->tmo).tgt_reset_tmo >= 0)
				printf("%s\t\tTarget Reset Timeout: %d\n",
					prefix,
					((curr->tmo).tgt_reset_tmo));
			else
				printf("%s\t\tTarget Reset Timeout: %s\n",
					prefix, UNKNOWN_VALUE);

			if ((curr->tmo).lu_reset_tmo >= 0)
				printf("%s\t\tLUN Reset Timeout: %d\n", prefix,
					((curr->tmo).lu_reset_tmo));
			else
				printf("%s\t\tLUN Reset Timeout: %s\n", prefix,
					UNKNOWN_VALUE);

			if ((curr->tmo).lu_reset_tmo >= 0)
				printf("%s\t\tAbort Timeout: %d\n", prefix,
					((curr->tmo).abort_tmo));
			else
				printf("%s\t\tAbort Timeout: %s\n", prefix,
					UNKNOWN_VALUE);

		}
		if (flags & SESSION_INFO_ISCSI_AUTH) {
			printf("%s\t\t*****\n", prefix);
			printf("%s\t\tCHAP:\n", prefix);
			printf("%s\t\t*****\n", prefix);
			if (!do_show) {
				strcpy(curr->chap.password, "********");
				strcpy(curr->chap.password_in, "********");
			}
			if (strlen((curr->chap).username))
				printf("%s\t\tusername: %s\n", prefix,
					(curr->chap).username);
			else
				printf("%s\t\tusername: %s\n", prefix,
					UNKNOWN_VALUE);
			if (strlen((curr->chap).password))
				printf("%s\t\tpassword: %s\n", prefix,
					(curr->chap).password);
			else
				printf("%s\t\tpassword: %s\n", prefix,
					UNKNOWN_VALUE);
			if (strlen((curr->chap).username_in))
				printf("%s\t\tusername_in: %s\n", prefix,
					(curr->chap).username_in);
			else
				printf("%s\t\tusername_in: %s\n", prefix,
					UNKNOWN_VALUE);
			if (strlen((curr->chap).password_in))
				printf("%s\t\tpassword_in: %s\n", prefix,
					(curr->chap).password_in);
			else
				printf("%s\t\tpassword_in: %s\n", prefix,
					UNKNOWN_VALUE);
		}

		if (flags & SESSION_INFO_ISCSI_PARAMS)
			print_iscsi_params(curr->sid, prefix);

		if (flags & (SESSION_INFO_SCSI_DEVS | SESSION_INFO_HOST_DEVS))
			print_scsi_state(curr->sid, prefix, flags);

		prev = curr;
	}
}

int session_info_print(int info_level, struct session_info *info, int do_show)
{
	struct list_head list;
	int num_found = 0, err = 0;
	char *version;
	unsigned int flags = 0;

	switch (info_level) {
	case 0:
	case -1:
		if (info) {
			session_info_print_flat(NULL, info);
			num_found = 1;
		} else
			err = iscsi_sysfs_for_each_session(info, &num_found,
						   session_info_print_flat);
		break;
	case 3:
		version = iscsi_sysfs_get_iscsi_kernel_version();
		if (version) {
			printf("iSCSI Transport Class version %s\n",
				version);
			printf("version %s\n", ISCSI_VERSION_STR);
		}

		flags |= (SESSION_INFO_SCSI_DEVS | SESSION_INFO_HOST_DEVS);
		/* fall through */
	case 2:
		flags |= (SESSION_INFO_ISCSI_PARAMS | SESSION_INFO_ISCSI_TIM
				| SESSION_INFO_ISCSI_AUTH);
		/* fall through */
	case 1:
		INIT_LIST_HEAD(&list);
		struct session_link_info link_info;

		flags |= (SESSION_INFO_ISCSI_STATE | SESSION_INFO_IFACE);
		if (info) {
			INIT_LIST_HEAD(&info->list);
			list_add_tail(&list, &info->list);
			session_info_print_tree(&list, "", flags, do_show);
			num_found = 1;
			break;
		}

		memset(&link_info, 0, sizeof(link_info));
		link_info.list = &list;
		link_info.data = NULL;
		link_info.match_fn = NULL;

		err = iscsi_sysfs_for_each_session(&link_info, &num_found,
						   session_info_create_list);
		if (err || !num_found)
			break;

		session_info_print_tree(&list, "", flags, do_show);
		session_info_free_list(&list);
		break;
	default:
		log_error("Invalid info level %d. Try 0 - 3.", info_level);
		return ISCSI_ERR_INVAL;
	}

	if (err) {
		log_error("Can not get list of active sessions (%d)", err);
		return err;
	} else if (!num_found) {
		log_error("No active sessions.");
		return ISCSI_ERR_NO_OBJS_FOUND;
	}
	return 0;
}
