/*
 * iSCSI flashnode helpers
 *
 * Copyright (C) 2013 QLogic Corporation.
 * Maintained by open-iscsi@googlegroups.com
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
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#include "log.h"
#include "idbm.h"
#include "iscsi_util.h"
#include "transport.h"
#include "iscsi_sysfs.h"
#include "list.h"
#include "sysdeps.h"
#include "idbm_fields.h"
#include "iscsi_err.h"
#include "iscsi_ipc.h"
#include "iscsi_netlink.h"
#include "flashnode.h"
#include "iscsi_settings.h"

char key[NAME_MAXVAL];

char *to_key(const char *fmt)
{
	int i = 0;
	memset(key, 0, sizeof(key));
	sprintf(key, fmt, i);
	return key;
}

int flashnode_info_print_flat(void *data, struct flashnode_rec *fnode,
			      uint32_t host_no, uint32_t flashnode_idx)
{
	printf("%s: [%d] ", fnode->transport_name, flashnode_idx);
	if (!strlen((char *)fnode->conn[0].ipaddress))
		printf("%s:", UNKNOWN_VALUE);
	else if (strchr((char *)fnode->conn[0].ipaddress, '.'))
		printf("%s:", fnode->conn[0].ipaddress);
	else
		printf("[%s]:", fnode->conn[0].ipaddress);

	if (!fnode->conn[0].port)
		printf("%s,", UNKNOWN_VALUE);
	else
		printf("%u,", fnode->conn[0].port);

	printf("%u ", fnode->sess.tpgt);

	if (!strlen(fnode->sess.targetname))
		printf("%s\n", UNKNOWN_VALUE);
	else
		printf("%s\n", fnode->sess.targetname);

	return 0;
}

static int flashnode_fill_isid(struct flashnode_rec *fnode, struct iovec *iov)
{
	struct iscsi_flashnode_param_info *fnode_param;
	struct nlattr *attr;
	int len;
	uint8_t isid[6];

	len = sizeof(struct iscsi_flashnode_param_info) + 6;
	iov->iov_base = iscsi_nla_alloc(ISCSI_FLASHNODE_ISID, len);
	if (!iov->iov_base)
		return 1;

	attr = iov->iov_base;
	iov->iov_len = NLA_ALIGN(attr->nla_len);

	fnode_param = (struct iscsi_flashnode_param_info *)ISCSI_NLA_DATA(attr);
	fnode_param->param = ISCSI_FLASHNODE_ISID;
	fnode_param->len = 6;

	sscanf(fnode->sess.isid, "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
	       &isid[0], &isid[1], &isid[2], &isid[3], &isid[4], &isid[5]);

	memcpy(fnode_param->value, isid, fnode_param->len);
	return 0;
}

static int flashnode_fill_ipv4_addr(struct flashnode_rec *fnode,
				    struct iovec *iov, int param_type)
{
	struct iscsi_flashnode_param_info *fnode_param;
	struct nlattr *attr;
	int len;
	int rc;

	len = sizeof(struct iscsi_flashnode_param_info) + 4;
	iov->iov_base = iscsi_nla_alloc(param_type, len);
	if (!iov->iov_base)
		return 1;

	attr = iov->iov_base;
	iov->iov_len = NLA_ALIGN(attr->nla_len);

	fnode_param = (struct iscsi_flashnode_param_info *)ISCSI_NLA_DATA(attr);
	fnode_param->param = param_type;
	fnode_param->len = 4;

	switch (param_type) {
	case ISCSI_FLASHNODE_IPADDR:
		rc = inet_pton(AF_INET, (char *)fnode->conn[0].ipaddress,
			       fnode_param->value);
		break;
	case ISCSI_FLASHNODE_REDIRECT_IPADDR:
		rc = inet_pton(AF_INET, (char *)fnode->conn[0].redirect_ipaddr,
			       fnode_param->value);
		break;
	default:
		goto free;
	}

	if (rc <= 0)
		goto free;

	return 0;

free:
	free(iov->iov_base);
	iov->iov_base = NULL;
	iov->iov_len = 0;
	return 1;
}

static int flashnode_fill_ipv6_addr(struct flashnode_rec *fnode,
				    struct iovec *iov, int param_type)
{
	struct iscsi_flashnode_param_info *fnode_param;
	struct nlattr *attr;
	int len;
	int rc;

	len = sizeof(struct iscsi_flashnode_param_info) + 16;
	iov->iov_base = iscsi_nla_alloc(param_type, len);
	if (!iov->iov_base)
		return 1;

	attr = iov->iov_base;
	iov->iov_len = NLA_ALIGN(attr->nla_len);

	fnode_param = (struct iscsi_flashnode_param_info *)ISCSI_NLA_DATA(attr);
	fnode_param->param = param_type;
	fnode_param->len = 16;

	switch (param_type) {
	case ISCSI_FLASHNODE_IPADDR:
		rc = inet_pton(AF_INET6, (char *)fnode->conn[0].ipaddress,
			       fnode_param->value);
		break;
	case ISCSI_FLASHNODE_REDIRECT_IPADDR:
		rc = inet_pton(AF_INET6, (char *)fnode->conn[0].redirect_ipaddr,
			       fnode_param->value);
		break;
	case ISCSI_FLASHNODE_LINK_LOCAL_IPV6:
		rc = inet_pton(AF_INET6, (char *)fnode->conn[0].link_local_ipv6,
			       fnode_param->value);
		break;
	default:
		goto free;
	}

	if (rc <= 0)
		goto free;

	return 0;

free:
	free(iov->iov_base);
	iov->iov_base = NULL;
	iov->iov_len = 0;
	return 1;
}

static int flashnode_fill_ipaddr(struct flashnode_rec *fnode, struct iovec *iov,
				 int param_type)
{
	int rc = 0;

	if (!strncmp(fnode->sess.portal_type, "ipv4", 4))
		rc = flashnode_fill_ipv4_addr(fnode, iov, param_type);
	else
		rc = flashnode_fill_ipv6_addr(fnode, iov, param_type);

	return rc;
}

static int flashnode_fill_uint8(struct flashnode_rec *fnode, struct iovec *iov,
				int param_type, uint8_t val)
{
	struct iscsi_flashnode_param_info *fnode_param;
	struct nlattr *attr;
	int len;

	len = sizeof(struct iscsi_flashnode_param_info) + 1;
	iov->iov_base = iscsi_nla_alloc(param_type, len);
	if (!iov->iov_base)
		return 1;

	attr = iov->iov_base;
	iov->iov_len = NLA_ALIGN(attr->nla_len);

	fnode_param = (struct iscsi_flashnode_param_info *)ISCSI_NLA_DATA(attr);
	fnode_param->param = param_type;
	fnode_param->len = 1;
	fnode_param->value[0] = val;
	return 0;
}

static int flashnode_fill_uint16(struct flashnode_rec *fnode, struct iovec *iov,
				 int param_type, uint16_t val)
{
	struct iscsi_flashnode_param_info *fnode_param;
	struct nlattr *attr;
	int len;

	len = sizeof(struct iscsi_flashnode_param_info) + 2;
	iov->iov_base = iscsi_nla_alloc(param_type, len);
	if (!iov->iov_base)
		return 1;

	attr = iov->iov_base;
	iov->iov_len = NLA_ALIGN(attr->nla_len);

	fnode_param = (struct iscsi_flashnode_param_info *)ISCSI_NLA_DATA(attr);
	fnode_param->param = param_type;
	fnode_param->len = 2;
	memcpy(fnode_param->value, &val, fnode_param->len);
	return 0;
}

static int flashnode_fill_uint32(struct flashnode_rec *fnode, struct iovec *iov,
				 int param_type, uint32_t val)
{
	struct iscsi_flashnode_param_info *fnode_param;
	struct nlattr *attr;
	int len;

	len = sizeof(struct iscsi_flashnode_param_info) + 4;
	iov->iov_base = iscsi_nla_alloc(param_type, len);
	if (!iov->iov_base)
		return 1;

	attr = iov->iov_base;
	iov->iov_len = NLA_ALIGN(attr->nla_len);

	fnode_param = (struct iscsi_flashnode_param_info *)ISCSI_NLA_DATA(attr);
	fnode_param->param = param_type;
	fnode_param->len = 4;
	memcpy(fnode_param->value, &val, fnode_param->len);
	return 0;
}

static int flashnode_fill_str(struct flashnode_rec *fnode, struct iovec *iov,
			      int param_type, char *buf, int buflen)
{
	struct iscsi_flashnode_param_info *fnode_param;
	struct nlattr *attr;
	int len;

	len = sizeof(struct iscsi_flashnode_param_info) + buflen;
	iov->iov_base = iscsi_nla_alloc(param_type, len);
	if (!iov->iov_base)
		return 1;

	attr = iov->iov_base;
	iov->iov_len = NLA_ALIGN(attr->nla_len);

	fnode_param = (struct iscsi_flashnode_param_info *)ISCSI_NLA_DATA(attr);
	fnode_param->param = param_type;
	fnode_param->len = buflen;
	memcpy(fnode_param->value, buf, fnode_param->len);
	return 0;
}

int flashnode_build_config(struct list_head *params,
			   struct flashnode_rec *fnode, struct iovec *iovs)
{
	struct user_param *param;
	struct iovec *iov = NULL;
	int count = 0;
	int port = 3260;

	/* start at 2, because 0 is for nlmsghdr and 1 for event */
	iov = iovs + 2;

	list_for_each_entry(param, params, list) {
		if (!strcmp(param->name, FLASHNODE_SESS_AUTO_SND_TGT_DISABLE)) {
			if (!flashnode_fill_uint8(fnode, &iov[count],
			    ISCSI_FLASHNODE_AUTO_SND_TGT_DISABLE,
			    fnode->sess.auto_snd_tgt_disable))
				count++;
		} else if (!strcmp(param->name,
				   FLASHNODE_SESS_DISCOVERY_SESS)) {
			if (!flashnode_fill_uint8(fnode, &iov[count],
			    ISCSI_FLASHNODE_DISCOVERY_SESS,
			    fnode->sess.discovery_session))
				count++;
		} else if (!strcmp(param->name, FLASHNODE_SESS_ENTRY_EN)) {
			if (!flashnode_fill_uint8(fnode, &iov[count],
			    ISCSI_FLASHNODE_ENTRY_EN,
			    fnode->sess.entry_enable))
				count++;
		} else if (!strcmp(param->name, FLASHNODE_SESS_IMM_DATA_EN)) {
			if (!flashnode_fill_uint8(fnode, &iov[count],
			    ISCSI_FLASHNODE_IMM_DATA_EN,
			    fnode->sess.immediate_data))
				count++;
		} else if (!strcmp(param->name,
				   FLASHNODE_SESS_INITIAL_R2T_EN)) {
			if (!flashnode_fill_uint8(fnode, &iov[count],
			    ISCSI_FLASHNODE_INITIAL_R2T_EN,
			    fnode->sess.initial_r2t))
				count++;
		} else if (!strcmp(param->name,
				  FLASHNODE_SESS_DATASEQ_INORDER)) {
			if (!flashnode_fill_uint8(fnode, &iov[count],
			    ISCSI_FLASHNODE_DATASEQ_INORDER,
			    fnode->sess.data_seq_in_order))
				count++;
		} else if (!strcmp(param->name, FLASHNODE_SESS_PDU_INORDER)) {
			if (!flashnode_fill_uint8(fnode, &iov[count],
			    ISCSI_FLASHNODE_PDU_INORDER,
			    fnode->sess.data_pdu_in_order))
				count++;
		} else if (!strcmp(param->name, FLASHNODE_SESS_CHAP_AUTH_EN)) {
			if (!flashnode_fill_uint8(fnode, &iov[count],
			    ISCSI_FLASHNODE_CHAP_AUTH_EN,
			    fnode->sess.chap_auth_en))
				count++;
		} else if (!strcmp(param->name,
				  FLASHNODE_SESS_DISCOVERY_LOGOUT_EN)) {
			if (!flashnode_fill_uint8(fnode, &iov[count],
			    ISCSI_FLASHNODE_DISCOVERY_LOGOUT_EN,
			    fnode->sess.discovery_logout_en))
				count++;
		} else if (!strcmp(param->name, FLASHNODE_SESS_BIDI_CHAP_EN )) {
			if (!flashnode_fill_uint8(fnode, &iov[count],
			    ISCSI_FLASHNODE_BIDI_CHAP_EN,
			    fnode->sess.bidi_chap_en))
				count++;
		} else if (!strcmp(param->name,
				  FLASHNODE_SESS_DISCOVERY_AUTH_OPTIONAL)) {
			if (!flashnode_fill_uint8(fnode, &iov[count],
			    ISCSI_FLASHNODE_DISCOVERY_AUTH_OPTIONAL,
			    fnode->sess.discovery_auth_optional))
				count++;
		} else if (!strcmp(param->name, FLASHNODE_SESS_ERL)) {
			if (!flashnode_fill_uint8(fnode, &iov[count],
			    ISCSI_FLASHNODE_ERL,
			    fnode->sess.erl))
				count++;
		} else if (!strcmp(param->name,
				  FLASHNODE_SESS_DEF_TIME2WAIT)) {
			if (!flashnode_fill_uint16(fnode, &iov[count],
			    ISCSI_FLASHNODE_DEF_TIME2WAIT,
			    fnode->sess.def_time2wait))
				count++;
		} else if (!strcmp(param->name,
				  FLASHNODE_SESS_DEF_TIME2RETAIN)) {
			if (!flashnode_fill_uint16(fnode, &iov[count],
			    ISCSI_FLASHNODE_DEF_TIME2RETAIN,
			    fnode->sess.def_time2retain))
				count++;
		} else if (!strcmp(param->name, FLASHNODE_SESS_MAX_R2T)) {
			if (!flashnode_fill_uint16(fnode, &iov[count],
			    ISCSI_FLASHNODE_MAX_R2T,
			    fnode->sess.max_outstanding_r2t))
				count++;
		} else if (!strcmp(param->name, FLASHNODE_SESS_TSID)) {
			if (!flashnode_fill_uint16(fnode, &iov[count],
			    ISCSI_FLASHNODE_TSID,
			    fnode->sess.tsid))
				count++;
		} else if (!strcmp(param->name, FLASHNODE_SESS_MAX_BURST)) {
			if (!flashnode_fill_uint32(fnode, &iov[count],
			    ISCSI_FLASHNODE_MAX_BURST,
			    fnode->sess.max_burst_len))
				count++;
		} else if (!strcmp(param->name,
				  FLASHNODE_SESS_DEF_TASKMGMT_TMO)) {
			if (!flashnode_fill_uint16(fnode, &iov[count],
			    ISCSI_FLASHNODE_DEF_TASKMGMT_TMO,
			    fnode->sess.def_taskmgmt_tmo))
				count++;
		} else if (!strcmp(param->name, FLASHNODE_SESS_NAME)) {
			if (!flashnode_fill_str(fnode, &iov[count],
			    ISCSI_FLASHNODE_NAME,
			    fnode->sess.targetname,
			    sizeof(fnode->sess.targetname)))
				count++;
		} else if (!strcmp(param->name, FLASHNODE_SESS_FIRST_BURST)) {
			if (!flashnode_fill_uint32(fnode, &iov[count],
			    ISCSI_FLASHNODE_FIRST_BURST,
			    fnode->sess.first_burst_len))
				count++;
		} else if (!strcmp(param->name, FLASHNODE_SESS_ISID)) {
			if (!flashnode_fill_isid(fnode, &iov[count]))
				count++;
		} else if (!strcmp(param->name, FLASHNODE_SESS_ALIAS)) {
			if (!flashnode_fill_str(fnode, &iov[count],
			    ISCSI_FLASHNODE_ALIAS,
			    fnode->sess.targetalias,
			    sizeof(fnode->sess.targetalias)))
				count++;
		} else if (!strcmp(param->name, FLASHNODE_SESS_TPGT)) {
			if (!flashnode_fill_uint16(fnode, &iov[count],
			    ISCSI_FLASHNODE_TPGT,
			    fnode->sess.tpgt))
				count++;
		} else if (!strcmp(param->name,
			  FLASHNODE_SESS_DISCOVERY_PARENT_IDX)) {
			if (!flashnode_fill_uint16(fnode, &iov[count],
			    ISCSI_FLASHNODE_DISCOVERY_PARENT_IDX,
			    fnode->sess.discovery_parent_idx))
				count++;
		} else if (!strcmp(param->name,
			  FLASHNODE_SESS_DISCOVERY_PARENT_TYPE)) {
			if (!flashnode_fill_str(fnode, &iov[count],
			    ISCSI_FLASHNODE_DISCOVERY_PARENT_TYPE,
			    fnode->sess.discovery_parent_type,
			    sizeof(fnode->sess.discovery_parent_type)))
				count++;
		} else if (!strcmp(param->name, FLASHNODE_SESS_PORTAL_TYPE)) {
			if (!flashnode_fill_str(fnode, &iov[count],
			    ISCSI_FLASHNODE_PORTAL_TYPE,
			    fnode->sess.portal_type,
			    sizeof(fnode->sess.portal_type)))
				count++;
		} else if (!strcmp(param->name,
			  to_key(FLASHNODE_SESS_CHAP_OUT_IDX))) {
			if (!flashnode_fill_uint32(fnode, &iov[count],
			    ISCSI_FLASHNODE_CHAP_OUT_IDX,
			    fnode->sess.chap_out_idx))
				count++;
		} else if (!strcmp(param->name, to_key(FLASHNODE_CONN_PORT))) {
			if (fnode->conn[0].port)
				port = fnode->conn[0].port;
			if (!flashnode_fill_uint16(fnode, &iov[count],
			    ISCSI_FLASHNODE_PORT, port))
				count++;
		} else if (!strcmp(param->name,
			  to_key(FLASHNODE_CONN_IPADDR))) {
			if (!flashnode_fill_ipaddr(fnode, &iov[count],
						   ISCSI_FLASHNODE_IPADDR))
					count++;
		} else if (!strcmp(param->name,
			  to_key(FLASHNODE_CONN_MAX_RECV_DLENGTH))) {
			if (!flashnode_fill_uint32(fnode, &iov[count],
			    ISCSI_FLASHNODE_MAX_RECV_DLENGTH,
			    fnode->conn[0].max_recv_dlength))
				count++;
		} else if (!strcmp(param->name,
			  to_key(FLASHNODE_CONN_IS_FW_ASSIGNED_IPV6))) {
			if (!flashnode_fill_uint8(fnode, &iov[count],
			    ISCSI_FLASHNODE_IS_FW_ASSIGNED_IPV6,
			    fnode->conn[0].is_fw_assigned_ipv6))
				count++;
		} else if (!strcmp(param->name,
			  to_key(FLASHNODE_CONN_HDR_DGST_EN))) {
			if (!flashnode_fill_uint8(fnode, &iov[count],
			    ISCSI_FLASHNODE_HDR_DGST_EN,
			    fnode->conn[0].header_digest_en))
				count++;
		} else if (!strcmp(param->name,
			  to_key(FLASHNODE_CONN_DATA_DGST_EN))) {
			if (!flashnode_fill_uint8(fnode, &iov[count],
			    ISCSI_FLASHNODE_DATA_DGST_EN,
			    fnode->conn[0].data_digest_en))
				count++;
		} else if (!strcmp(param->name,
			  to_key(FLASHNODE_CONN_SNACK_REQ_EN))) {
			if (!flashnode_fill_uint8(fnode, &iov[count],
			    ISCSI_FLASHNODE_SNACK_REQ_EN,
			    fnode->conn[0].snack_req_en))
				count++;
		} else if (!strcmp(param->name,
			  to_key(FLASHNODE_CONN_TCP_TIMESTAMP_STAT))) {
			if (!flashnode_fill_uint8(fnode, &iov[count],
			    ISCSI_FLASHNODE_TCP_TIMESTAMP_STAT,
			    fnode->conn[0].tcp_timestamp_stat))
				count++;
		} else if (!strcmp(param->name,
			  to_key(FLASHNODE_CONN_TCP_NAGLE_DISABLE))) {
			if (!flashnode_fill_uint8(fnode, &iov[count],
			    ISCSI_FLASHNODE_TCP_NAGLE_DISABLE,
			    fnode->conn[0].tcp_nagle_disable))
				count++;
		} else if (!strcmp(param->name,
			  to_key(FLASHNODE_CONN_TCP_WSF_DISABLE))) {
			if (!flashnode_fill_uint8(fnode, &iov[count],
			    ISCSI_FLASHNODE_TCP_WSF_DISABLE,
			    fnode->conn[0].tcp_wsf_disable))
				count++;
		} else if (!strcmp(param->name,
			  to_key(FLASHNODE_CONN_TCP_TIMER_SCALE))) {
			if (!flashnode_fill_uint8(fnode, &iov[count],
			    ISCSI_FLASHNODE_TCP_TIMER_SCALE,
			    fnode->conn[0].tcp_timer_scale))
				count++;
		} else if (!strcmp(param->name,
			  to_key(FLASHNODE_CONN_TCP_TIMESTAMP_EN))) {
			if (!flashnode_fill_uint8(fnode, &iov[count],
			    ISCSI_FLASHNODE_TCP_TIMESTAMP_EN,
			    fnode->conn[0].tcp_timestamp_en))
				count++;
		} else if (!strcmp(param->name,
			  to_key(FLASHNODE_CONN_IP_FRAG_DISABLE))) {
			if (!flashnode_fill_uint8(fnode, &iov[count],
			    ISCSI_FLASHNODE_IP_FRAG_DISABLE,
			    fnode->conn[0].fragment_disable))
				count++;
		} else if (!strcmp(param->name,
			  to_key(FLASHNODE_CONN_MAX_XMIT_DLENGTH))) {
			if (!flashnode_fill_uint32(fnode, &iov[count],
			    ISCSI_FLASHNODE_MAX_XMIT_DLENGTH,
			    fnode->conn[0].max_xmit_dlength))
				count++;
		} else if (!strcmp(param->name,
			  to_key(FLASHNODE_CONN_KEEPALIVE_TMO))) {
			if (!flashnode_fill_uint16(fnode, &iov[count],
			    ISCSI_FLASHNODE_KEEPALIVE_TMO,
			    fnode->conn[0].keepalive_tmo))
				count++;
		} else if (!strcmp(param->name,
			  to_key(FLASHNODE_CONN_REDIRECT_IPADDR))) {
			if (!flashnode_fill_ipaddr(fnode, &iov[count],
					ISCSI_FLASHNODE_REDIRECT_IPADDR))
					count++;
		} else if (!strcmp(param->name,
			  to_key(FLASHNODE_CONN_MAX_SEGMENT_SIZE))) {
			if (!flashnode_fill_uint32(fnode, &iov[count],
			    ISCSI_FLASHNODE_MAX_SEGMENT_SIZE,
			    fnode->conn[0].max_segment_size))
				count++;
		} else if (!strcmp(param->name,
			  to_key(FLASHNODE_CONN_LOCAL_PORT))) {
			if (!flashnode_fill_uint16(fnode, &iov[count],
			    ISCSI_FLASHNODE_LOCAL_PORT,
			    fnode->conn[0].local_port))
				count++;
		} else if (!strcmp(param->name,
			  to_key(FLASHNODE_CONN_IPV4_TOS))) {
			if (!flashnode_fill_uint8(fnode, &iov[count],
			    ISCSI_FLASHNODE_IPV4_TOS,
			    fnode->conn[0].ipv4_tos))
				count++;
		} else if (!strcmp(param->name,
			  to_key(FLASHNODE_CONN_IPV6_TC))) {
			if (!flashnode_fill_uint8(fnode, &iov[count],
			    ISCSI_FLASHNODE_IPV6_TC,
			    fnode->conn[0].ipv6_traffic_class))
				count++;
		} else if (!strcmp(param->name,
			  to_key(FLASHNODE_CONN_IPV6_FLOW_LABEL))) {
			if (!flashnode_fill_uint16(fnode, &iov[count],
			    ISCSI_FLASHNODE_IPV6_FLOW_LABEL,
			    fnode->conn[0].ipv6_flow_lbl))
				count++;
		} else if (!strcmp(param->name,
			  to_key(FLASHNODE_CONN_LINK_LOCAL_IPV6))) {
			if (!flashnode_fill_ipv6_addr(fnode, &iov[count],
					ISCSI_FLASHNODE_LINK_LOCAL_IPV6))
					count++;
		} else if (!strcmp(param->name,
			  to_key(FLASHNODE_CONN_TCP_XMIT_WSF))) {
			if (!flashnode_fill_uint32(fnode, &iov[count],
			    ISCSI_FLASHNODE_TCP_XMIT_WSF,
			    fnode->conn[0].tcp_xmit_wsf))
				count++;
		} else if (!strcmp(param->name,
			  to_key(FLASHNODE_CONN_TCP_RECV_WSF))) {
			if (!flashnode_fill_uint32(fnode, &iov[count],
			    ISCSI_FLASHNODE_TCP_RECV_WSF,
			    fnode->conn[0].tcp_recv_wsf))
				count++;
		} else if (!strcmp(param->name,
			  to_key(FLASHNODE_CONN_STATSN))) {
			if (!flashnode_fill_uint32(fnode, &iov[count],
			    ISCSI_FLASHNODE_STATSN,
			    fnode->conn[0].stat_sn))
				count++;
		} else if (!strcmp(param->name,
			  to_key(FLASHNODE_CONN_EXP_STATSN))) {
			if (!flashnode_fill_uint32(fnode, &iov[count],
			    ISCSI_FLASHNODE_EXP_STATSN,
			    fnode->conn[0].exp_stat_sn))
				count++;
		}
	}

	return count;
}
