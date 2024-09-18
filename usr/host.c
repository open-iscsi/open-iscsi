/*
 * iSCSI host helpers
 *
 * Copyright (C) 2008 Mike Christie
 * Copyright (C) 2008 Red Hat, Inc. All rights reserved.
 * maintained by open-iscsi@@googlegroups.com
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
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "iface.h"
#include "list.h"
#include "iscsi_util.h"
#include "log.h"
#include "iscsi_sysfs.h"
#include "version.h"
#include "iscsi_settings.h"
#include "mgmt_ipc.h"
#include "host.h"
#include "session_info.h"
#include "transport.h"
#include "initiator.h"
#include "iscsi_err.h"
#include "iscsi_netlink.h"

struct _host_info_print_tree_arg {
	unsigned int flags;
	struct iscsi_session **ses;
	uint32_t se_count;
};

static int match_host_to_session(uint32_t host_no, struct iscsi_session *se)
{
	uint32_t sid = 0;
	uint32_t info_host_no;
	int rc;

	sid = iscsi_session_sid_get(se);

	info_host_no = iscsi_sysfs_get_host_no_from_sid(sid, &rc);
	if (rc) {
		log_error("could not get host_no for session%d err %d.",
			  sid, rc);
		return 0;
	}

	return host_no == info_host_no;
}

static void print_host_info(struct iface_rec *iface, char *prefix)
{
	if (strlen(iface->transport_name))
		printf("%sTransport: %s\n", prefix,
		      iface->transport_name);
	else
		printf("%sTransport: %s\n", prefix, UNKNOWN_VALUE);

	if (strlen(iface->iname))
		printf("%sInitiatorname: %s\n", prefix,
		      iface->iname);
	else
		printf("%sInitiatorname: %s\n", prefix, UNKNOWN_VALUE);

	if (!strlen(iface->ipaddress))
		printf("%sIPaddress: %s\n", prefix, UNKNOWN_VALUE);
	else if (strchr(iface->ipaddress, '.'))
		printf("%sIPaddress: %s\n", prefix, iface->ipaddress);
	else
		printf("%sIPaddress: [%s]\n", prefix, iface->ipaddress);

	if (strlen(iface->hwaddress))
		printf("%sHWaddress: %s\n", prefix, iface->hwaddress);
	else
		printf("%sHWaddress: %s\n", prefix, UNKNOWN_VALUE);

	if (strlen(iface->netdev))
		printf("%sNetdev: %s\n", prefix, iface->netdev);
	else
		printf("%sNetdev: %s\n", prefix, UNKNOWN_VALUE);
}

static int host_info_print_flat(__attribute__((unused))void *data,
				struct host_info *hinfo)
{
	struct iface_rec *iface = &hinfo->iface;

	if (strlen(iface->transport_name))
		printf("%s: ", iface->transport_name);
	else
		printf("%s: ", UNKNOWN_VALUE);

	printf("[%u] ", hinfo->host_no);

	if (!strlen(iface->ipaddress))
		printf("%s,", UNKNOWN_VALUE);
	else if (strchr(iface->ipaddress, '.'))
		printf("%s,", iface->ipaddress);
	else
		printf("[%s],", iface->ipaddress);

	if (strlen(iface->hwaddress))
		printf("[%s],", iface->hwaddress);
	else
		printf("[%s],", UNKNOWN_VALUE);

	if (strlen(iface->netdev))
		printf("%s ", iface->netdev);
	else
		printf("%s ", UNKNOWN_VALUE);

	if (strlen(iface->iname))
		printf("%s\n", iface->iname);
	else
		printf("%s\n", UNKNOWN_VALUE);
	return 0;
}

static int print_host_iface(void *data, struct iface_rec *iface)
{
	char *prefix = data;

	printf("%s**********\n", prefix);
	printf("%sInterface:\n", prefix);
	printf("%s**********\n", prefix);

	printf("%sKernel Name: %s\n", prefix, iface->name);

	if (!strlen(iface->ipaddress))
		printf("%sIPaddress: %s\n", prefix, UNKNOWN_VALUE);
	else if (strchr(iface->ipaddress, '.')) {
		printf("%sIPaddress: %s\n", prefix, iface->ipaddress);

		if (!strlen(iface->gateway))
			printf("%sGateway: %s\n", prefix, UNKNOWN_VALUE);
		else
			printf("%sGateway: %s\n", prefix, iface->gateway);
		if (!strlen(iface->subnet_mask))
			printf("%sSubnet: %s\n", prefix, UNKNOWN_VALUE);
		else
			printf("%sSubnet: %s\n", prefix, iface->subnet_mask);
		if (!strlen(iface->bootproto))
			printf("%sBootProto: %s\n", prefix, UNKNOWN_VALUE);
		else
			printf("%sBootProto: %s\n", prefix, iface->bootproto);
	} else {
		printf("%sIPaddress: [%s]\n", prefix, iface->ipaddress);

		if (!strlen(iface->ipv6_autocfg))
			printf("%sIPaddress Autocfg: %s\n", prefix,
			       UNKNOWN_VALUE);
		else
			printf("%sIPaddress Autocfg: %s\n", prefix,
			       iface->ipv6_autocfg);
		if (!strlen(iface->ipv6_linklocal))
			printf("%sLink Local Address: %s\n", prefix,
			       UNKNOWN_VALUE);
		else
			printf("%sLink Local Address: [%s]\n", prefix,
			       iface->ipv6_linklocal);
		if (!strlen(iface->linklocal_autocfg))
			printf("%sLink Local Autocfg: %s\n", prefix,
			       UNKNOWN_VALUE);
		else
			printf("%sLink Local Autocfg: %s\n", prefix,
			       iface->linklocal_autocfg);
		if (!strlen(iface->ipv6_router))
			printf("%sRouter Address: %s\n", prefix,
			      UNKNOWN_VALUE);
		else
			printf("%sRouter Address: [%s]\n", prefix,
			       iface->ipv6_router);
	}

	if (!strlen(iface->port_state))
		printf("%sPort State: %s\n", prefix, UNKNOWN_VALUE);
	else
		printf("%sPort State: %s\n", prefix, iface->port_state);

	if (!strlen(iface->port_speed))
		printf("%sPort Speed: %s\n", prefix, UNKNOWN_VALUE);
	else
		printf("%sPort Speed: %s\n", prefix, iface->port_speed);

	if (!iface->port)
		printf("%sPort: %s\n", prefix, UNKNOWN_VALUE);
	else
		printf("%sPort: %u\n", prefix, iface->port);

	if (!iface->mtu)
		printf("%sMTU: %s\n", prefix, UNKNOWN_VALUE);
	else
		printf("%sMTU: %u\n", prefix, iface->mtu);

	if (iface->vlan_id == UINT16_MAX)
		printf("%sVLAN ID: %s\n", prefix, UNKNOWN_VALUE);
	else
		printf("%sVLAN ID: %u\n", prefix, iface->vlan_id);

	if (iface->vlan_priority == UINT8_MAX)
		printf("%sVLAN priority: %s\n", prefix, UNKNOWN_VALUE);
	else
		printf("%sVLAN priority: %u\n", prefix, iface->vlan_priority);
	return 0;
}

static void print_host_ifaces(struct host_info *hinfo, char *prefix)
{
	int nr_found = 0;

	iscsi_sysfs_for_each_iface_on_host(prefix, hinfo->host_no, &nr_found,
					   print_host_iface);
}

static int host_info_print_tree(void *data, struct host_info *hinfo)
{
	unsigned int session_info_flags = 0;
	struct _host_info_print_tree_arg *arg = data;
	struct iscsi_session **ses = NULL;
	struct iscsi_session **matched_ses = NULL;
	uint32_t se_count = 0;
	uint32_t matched_se_count = 0;
	uint32_t i = 0;
	char state[SCSI_MAX_STATE_VALUE];

	if (arg == NULL)
		return -EINVAL;

	session_info_flags = arg->flags;
	ses = arg->ses;
	se_count = arg->se_count;

	printf("Host Number: %u\n", hinfo->host_no);
	if (!iscsi_sysfs_get_host_state(state, hinfo->host_no))
		printf("\tState: %s\n", state);
	else
		printf("\tState: Unknown\n");
	print_host_info(&hinfo->iface, "\t");

	print_host_ifaces(hinfo, "\t");

	if ((!session_info_flags) || (!se_count))
		return 0;

	matched_ses = calloc(se_count, sizeof(struct iscsi_session *));
	if (matched_ses == NULL)
		return -ENOMEM;

	for (i = 0; i < se_count; ++i)
		if (match_host_to_session(hinfo->host_no, ses[i]))
			matched_ses[matched_se_count++] = ses[i];

	if (!matched_se_count)
		goto out;

	printf("\t*********\n");
	printf("\tSessions:\n");
	printf("\t*********\n");
	session_info_print_tree(matched_ses, matched_se_count, "\t",
				session_info_flags, 0/* don't show password */);
out:
	free(matched_ses);
	return 0;
}

int host_info_print(int info_level, uint32_t host_no,
		    struct iscsi_session **ses, uint32_t se_count)

{
	int num_found = 0, err = 0;
	char *version;
	unsigned int flags = 0;
	struct _host_info_print_tree_arg arg;

	switch (info_level) {
	case 0:
	case -1:
		err = iscsi_sysfs_for_each_host(NULL, &num_found,
						host_info_print_flat);
		break;
	case 4:
		version = iscsi_sysfs_get_iscsi_kernel_version();
		if (version) {
			printf("iSCSI Transport Class version %s\n",
			       version);
			printf("version %s\n", ISCSI_VERSION_STR);
			free(version);
		}

		flags |= SESSION_INFO_SCSI_DEVS;
		/* fall through */
	case 3:
		flags |= SESSION_INFO_ISCSI_PARAMS;
		/* fall through */
	case 2:
		flags |= SESSION_INFO_ISCSI_STATE | SESSION_INFO_IFACE;
		/* fall through */
	case 1:
		arg.flags = flags;
		arg.ses = ses;
		arg.se_count = se_count;
		/* set host_no if not yet done */
		if (host_no > MAX_HOST_NO) {
			struct host_info hinfo;

			memset(&hinfo, 0, sizeof(struct host_info));
			hinfo.host_no = host_no;
			iscsi_sysfs_get_hostinfo_by_host_no(&hinfo);
			host_info_print_tree(&arg, &hinfo);
			num_found = 1;
			break;
		}

		transport_probe_for_offload();
		err = iscsi_sysfs_for_each_host(&arg, &num_found,
						host_info_print_tree);
		break;
	default:
		log_error("Invalid info level %d. Try 0 - 4.", info_level);
		return ISCSI_ERR_INVAL;
	}

	if (err) {
		log_error("Can not get list of iSCSI hosts: %s",
			  iscsi_err_to_str(err));
		return err;
	} else if (!num_found) {
		log_error("No iSCSI hosts.");
		return ISCSI_ERR_NO_OBJS_FOUND;
	}
	return 0;
}

static int chap_fill_param_uint(struct iovec *iov, int param,
				uint32_t param_val, int param_len)
{
	struct iscsi_param_info *param_info;
	struct nlattr *attr;
	int len;
	uint8_t val8 = 0;
	uint16_t val16 = 0;
	uint32_t val32 = 0;
	char *val = NULL;

	len = sizeof(struct iscsi_param_info) + param_len;
	iov->iov_base = iscsi_nla_alloc(param, len);
	if (!iov->iov_base)
		return 1;

	attr = iov->iov_base;
	iov->iov_len = NLA_ALIGN(attr->nla_len);

	param_info = (struct iscsi_param_info *)ISCSI_NLA_DATA(attr);
	param_info->param = param;
	param_info->len = param_len;

	switch (param_len) {
	case 1:
		val8 = (uint8_t)param_val;
		val = (char *)&val8;
		break;

	case 2:
		val16 = (uint16_t)param_val;
		val = (char *)&val16;
		break;

	case 4:
		val32 = (uint32_t)param_val;
		val = (char *)&val32;
		break;

	default:
		goto free;
	}
	memcpy(param_info->value, val, param_len);

	return 0;

free:
	free(iov->iov_base);
	iov->iov_base = NULL;
	iov->iov_len = 0;
	return 1;
}

static int chap_fill_param_str(struct iovec *iov, int param, char *param_val,
			       int param_len)
{
	struct iscsi_param_info *param_info;
	struct nlattr *attr;
	int len;

	len = sizeof(struct iscsi_param_info) + param_len;
	iov->iov_base = iscsi_nla_alloc(param, len);
	if (!iov->iov_base)
		return 1;

	attr = iov->iov_base;
	iov->iov_len = NLA_ALIGN(attr->nla_len);

	param_info = (struct iscsi_param_info *)ISCSI_NLA_DATA(attr);
	param_info->param = param;
	param_info->len = param_len;
	memcpy(param_info->value, param_val, param_len);
	return 0;
}

int chap_build_config(struct iscsi_chap_rec *crec, struct iovec *iovs)
{
	struct iovec *iov = NULL;
	int count = 0;

	/* start at 2, because 0 is for nlmsghdr and 1 for event */
	iov = iovs + 2;

	if (!chap_fill_param_uint(&iov[count], ISCSI_CHAP_PARAM_INDEX,
				  crec->chap_tbl_idx,
				  sizeof(crec->chap_tbl_idx)))
		count++;

	if (!chap_fill_param_uint(&iov[count], ISCSI_CHAP_PARAM_CHAP_TYPE,
				  crec->chap_type, sizeof(crec->chap_type)))
		count++;

	if (!chap_fill_param_str(&iov[count], ISCSI_CHAP_PARAM_USERNAME,
				 crec->username, strlen(crec->username)))
		count++;

	if (!chap_fill_param_str(&iov[count], ISCSI_CHAP_PARAM_PASSWORD,
				 (char *)crec->password,
				 strlen((char *)crec->password)))
		count++;

	if (!chap_fill_param_uint(&iov[count], ISCSI_CHAP_PARAM_PASSWORD_LEN,
				  crec->password_length,
				  sizeof(crec->password_length)))
		count++;

	return count;
}
