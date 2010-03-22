/*
 * iSCSI Discovery
 *
 * Copyright (C) 2002 Cisco Systems, Inc.
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

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <netdb.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "strings.h"
#include "types.h"
#include "iscsi_proto.h"
#include "initiator.h"
#include "log.h"
#include "idbm.h"
#include "iscsi_settings.h"
#include "sysdeps.h"
#include "fw_context.h"
#include "iscsid_req.h"
#include "iscsi_util.h"
/* libisns includes */
#include "isns.h"
#include "paths.h"
#include "message.h"

#ifdef SLP_ENABLE
#include "iscsi-slp-discovery.h"
#endif

#define DISCOVERY_NEED_RECONNECT 0xdead0001

static int rediscover = 0;

static char initiator_name[TARGET_NAME_MAXLEN + 1];
static char initiator_alias[TARGET_NAME_MAXLEN + 1];

static int request_initiator_name(void)
{
	int rc;
	iscsiadm_req_t req;
	iscsiadm_rsp_t rsp;

	memset(initiator_name, 0, sizeof(initiator_name));
	initiator_name[0] = '\0';
	memset(initiator_alias, 0, sizeof(initiator_alias));
	initiator_alias[0] = '\0';

	memset(&req, 0, sizeof(req));
	req.command = MGMT_IPC_CONFIG_INAME;

	rc = iscsid_exec_req(&req, &rsp, 1);
	if (rc)
		return EIO;

	if (rsp.u.config.var[0] != '\0')
		strcpy(initiator_name, rsp.u.config.var);

	memset(&req, 0, sizeof(req));
	req.command = MGMT_IPC_CONFIG_IALIAS;

	rc = iscsid_exec_req(&req, &rsp, 0);
	if (rc)
		/* alias is optional so return ok */
		return 0;

	if (rsp.u.config.var[0] != '\0')
		strcpy(initiator_alias, rsp.u.config.var);
	return 0;
}

void discovery_isns_free_servername(void)
{
	if (isns_config.ic_server_name)
		free(isns_config.ic_server_name);
	isns_config.ic_server_name = NULL;
}

int discovery_isns_set_servername(char *address, int port)
{
	char *server;
	int len;

	if (port > USHRT_MAX) {
		log_error("Invalid port %d\n", port);
		return EINVAL;
	}

	/* 5 for port and 1 for colon and 1 for null */
	len = strlen(address) + 7;
	server = calloc(1, len);
	if (!server)
		return ENOMEM;

	snprintf(server, len, "%s:%d", address, port);
	isns_assign_string(&isns_config.ic_server_name, server);
	free(server);
	return 0;
}

int discovery_isns_query(struct discovery_rec *drec, const char *iname,
			 const char *targetname, struct list_head *rec_list)
{
	isns_attr_list_t key_attrs = ISNS_ATTR_LIST_INIT;
	isns_object_list_t objects = ISNS_OBJECT_LIST_INIT;
	isns_source_t *source;
	isns_simple_t *qry;
	isns_client_t *clnt;
	uint32_t status;
	int rc, i;

	isns_config.ic_security = 0;
	source = isns_source_create_iscsi(iname);
	if (!source)
		return ENOMEM;

	clnt = isns_create_client(NULL, iname); 
	if (!clnt) {
		rc = ENOMEM;
		goto free_src;
	}

	/* do not retry forever */
	isns_socket_set_disconnect_fatal(clnt->ic_socket);

	if (targetname)
		isns_attr_list_append_string(&key_attrs, ISNS_TAG_ISCSI_NAME,
					     targetname);
	else
		/* Query for all visible targets */
		isns_attr_list_append_uint32(&key_attrs,
					     ISNS_TAG_ISCSI_NODE_TYPE,
					     ISNS_ISCSI_TARGET_MASK);

	qry = isns_create_query2(clnt, &key_attrs, source);
	if (!qry) {
		rc = ENOMEM;
		goto free_clnt;
	}

	isns_query_request_attr_tag(qry, ISNS_TAG_ISCSI_NAME);
	isns_query_request_attr_tag(qry, ISNS_TAG_ISCSI_NODE_TYPE);
	isns_query_request_attr_tag(qry, ISNS_TAG_PORTAL_IP_ADDRESS);
	isns_query_request_attr_tag(qry, ISNS_TAG_PORTAL_TCP_UDP_PORT);
	isns_query_request_attr_tag(qry, ISNS_TAG_PG_ISCSI_NAME);
	isns_query_request_attr_tag(qry, ISNS_TAG_PG_PORTAL_IP_ADDR);
	isns_query_request_attr_tag(qry, ISNS_TAG_PG_PORTAL_TCP_UDP_PORT);
	isns_query_request_attr_tag(qry, ISNS_TAG_PG_TAG);

	status = isns_client_call(clnt, &qry);
	switch (status) {
	case ISNS_SUCCESS:
		break;
	case ISNS_SOURCE_UNKNOWN:
		/* server requires that we are registered but we are not */
		rc = ENOENT;
		goto free_query;
	default:
		log_error("iSNS discovery failed: %s", isns_strerror(status));
		rc = EIO;
		goto free_query;
	}

	status = isns_query_response_get_objects(qry, &objects);
	if (status) {
		log_error("Unable to extract object list from query "
			  "response: %s\n", isns_strerror(status));
		rc = EIO;
		goto free_query;
	}

	for (i = 0; i < objects.iol_count; ++i) {
		isns_object_t *obj = objects.iol_data[i];
		const char *pg_tgt = NULL;
		struct in6_addr in_addr;
		uint32_t pg_port = ISCSI_LISTEN_PORT;
		uint32_t pg_tag = PORTAL_GROUP_TAG_UNKNOWN;
		char pg_addr[INET6_ADDRSTRLEN + 1];
		struct node_rec *rec;

		if (!isns_object_is_pg(obj))
			continue;

		if (!isns_object_get_string(obj, ISNS_TAG_PG_ISCSI_NAME,
					    &pg_tgt)) {
			log_debug(1, "Missing target name");
			continue;
		}

		if (!isns_object_get_ipaddr(obj, ISNS_TAG_PG_PORTAL_IP_ADDR,
					    &in_addr)) {
			log_debug(1, "Missing addr");
			continue;
		}
		if (IN6_IS_ADDR_V4MAPPED(&in_addr) ||
		    IN6_IS_ADDR_V4COMPAT(&in_addr)) {
			struct in_addr ipv4;

			ipv4.s_addr = in_addr.s6_addr32[3];
			inet_ntop(AF_INET, &ipv4, pg_addr, sizeof(pg_addr));
		} else
			inet_ntop(AF_INET6, &in_addr, pg_addr, sizeof(pg_addr));

		if (!isns_object_get_uint32(obj,
					    ISNS_TAG_PG_PORTAL_TCP_UDP_PORT,
					    &pg_port)) {
			log_debug(1, "Missing port");
			continue;
		}

		if (!isns_object_get_uint32(obj, ISNS_TAG_PG_TAG, &pg_tag)) {
			log_debug(1, "Missing tag");
			continue;
		}

		rec = calloc(1, sizeof(*rec));
		if (!rec) {
			rc = ENOMEM;
			goto destroy_list;
		}

		idbm_node_setup_from_conf(rec);
		if (drec) {
			rec->disc_type = drec->type;
			rec->disc_port = drec->port;
			strcpy(rec->disc_address, drec->address);
		}

		strlcpy(rec->name, pg_tgt, TARGET_NAME_MAXLEN);
		rec->tpgt = pg_tag;
		rec->conn[0].port = pg_port;
		strlcpy(rec->conn[0].address, pg_addr, NI_MAXHOST);
		list_add_tail(&rec->list, rec_list);
	}
	rc = 0;

	isns_flush_events();
destroy_list:
	isns_object_list_destroy(&objects);
free_query:
	isns_simple_free(qry);
free_clnt:
	isns_client_destroy(clnt);
free_src:
	isns_source_release(source);
	return rc;
}

/*
 * discovery_isns_reg_node - register/deregister node
 * @iname: initiator name
 * @reg: bool indicating if we are supposed to register or deregister node.
 *
 * We do a very simple registration just so we can query.
 */
static int discovery_isns_reg_node(const char *iname, int op_reg)
{
	isns_simple_t *reg;
	isns_client_t *clnt;
	isns_source_t *source;
	int rc = 0, status;

	isns_config.ic_security = 0;

	log_debug(1, "trying to %s %s with iSNS server.",
		  op_reg ? "register" : "deregister", iname);

	source = isns_source_create_iscsi(iname);
	if (!source)
		return ENOMEM;

	clnt = isns_create_client(NULL, iname); 
	if (!clnt) {
		rc = ENOMEM;
		goto free_src;
	}

	reg = isns_simple_create(op_reg ? ISNS_DEVICE_ATTRIBUTE_REGISTER :
				 ISNS_DEVICE_DEREGISTER,
				 source, NULL);
	if (!reg) {
		rc = ENOMEM;
		goto free_clnt;
	}

	isns_attr_list_append_string(&reg->is_operating_attrs,
				     ISNS_TAG_ISCSI_NAME, iname);
	if (op_reg)
		isns_attr_list_append_uint32(&reg->is_operating_attrs,
					     ISNS_TAG_ISCSI_NODE_TYPE,
					     ISNS_ISCSI_INITIATOR_MASK);
	status = isns_client_call(clnt, &reg);
	if (status != ISNS_SUCCESS) {
		log_error("Could not %s %s with iSNS server: %s.",
			  reg ? "register" : "deregister", iname,
			  isns_strerror(status));
		rc = EIO;
	} else
		log_debug(1, "%s %s with iSNS server successful.",
			  op_reg ? "register" : "deregister", iname);
free_clnt:
	isns_client_destroy(clnt);
free_src:
	isns_source_release(source);
	return rc;
}

int discovery_isns(void *data, struct iface_rec *iface,
		   struct list_head *rec_list)
{
	struct discovery_rec *drec = data;
	char *iname;
	int rc, registered = 0;

	if (iface && strlen(iface->iname))
		iname = iface->iname;
	else {
		if (request_initiator_name() || initiator_name[0] == '\0') {
			log_error("Cannot perform discovery. Initiatorname "
				  "required.");
			return EINVAL;
		}
		iname = initiator_name;
	}

	rc = discovery_isns_set_servername(drec->address, drec->port);
	if (rc)
		return rc;
retry:
	rc = discovery_isns_query(drec, iname, NULL, rec_list);
	if (!registered && rc == ENOENT) {
		rc = discovery_isns_reg_node(iname, 1);
		if (!rc) {
			registered = 1;
			goto retry;
		}
	}

	if (registered)
		discovery_isns_reg_node(iname, 0);

	discovery_isns_free_servername();
	return rc;
}

int discovery_fw(void *data, struct iface_rec *iface,
		 struct list_head *rec_list)
{
	struct discovery_rec *drec = data;
	struct boot_context *bcontext;
	struct list_head targets;
	struct node_rec *rec;
	int rc;

	INIT_LIST_HEAD(&targets);
	rc = fw_get_targets(&targets);
	if (rc) {
		log_error("Could not get list of targets from firmware. "
			  "(err %d)\n", rc);
		return rc;
	}
	if (list_empty(&targets))
		return 0;
	/*
	 * TODO: Do we want to match the iface MAC/netdev with what is in
	 * the firmware or could the user want to bind based on what is
	 * in passed in or in the default ifaces?
	 */

	list_for_each_entry(bcontext, &targets, list) {
		rec = idbm_create_rec_from_boot_context(bcontext);
		if (!rec) {
			log_error("Could not convert firmware info to "
				  "node record.\n");
			rc = ENOMEM;
			goto free_targets;
		}
		rec->disc_type = drec->type;

		list_add_tail(&rec->list, rec_list);
	}

free_targets:
	fw_free_targets(&targets);
	return rc;
}

int discovery_offload_sendtargets(int host_no, int do_login,
				  discovery_rec_t *drec)
{
	struct sockaddr_storage ss;
	char default_port[NI_MAXSERV];
	iscsiadm_req_t req;
	iscsiadm_rsp_t rsp;
	int rc;

	log_debug(4, "offload st though host %d to %s", host_no,
		  drec->address);

	memset(&req, 0, sizeof(req));
	req.command = MGMT_IPC_SEND_TARGETS;
	req.u.st.host_no = host_no;
	req.u.st.do_login = do_login;

	/* resolve the DiscoveryAddress to an IP address */
	sprintf(default_port, "%d", drec->port);
	if (resolve_address(drec->address, default_port, &ss)) {
		log_error("Cannot resolve host name %s.", drec->address);
		return EIO;
	}       
	req.u.st.ss = ss;

	/*
	 * We only know how ask qla4xxx to do discovery and login
	 * to what it finds. We are not able to get what it finds or
	 * is able to log into so we just send the command and proceed.
	 *
	 * There is a way to just use the hw to send a sendtargets command
	 * and get back the results. We should do this since it would
	 * allows us to then process the results like software iscsi.
	 */
	rc = iscsid_exec_req(&req, &rsp, 1);
	if (rc) {
		log_error("Could not offload sendtargets to %s.\n",
			  drec->address);
		iscsid_handle_error(rc);
		return EIO;
	}

	return 0;
}

static int
iscsi_make_text_pdu(iscsi_session_t *session, struct iscsi_hdr *hdr,
		    char *data, int max_data_length)
{
	struct iscsi_text *text_pdu = (struct iscsi_text *)hdr;

	/* initialize the PDU header */
	memset(text_pdu, 0, sizeof (*text_pdu));

	text_pdu->opcode = ISCSI_OP_TEXT;
	text_pdu->itt = htonl(session->itt);
	text_pdu->ttt = ISCSI_RESERVED_TAG;
	text_pdu->cmdsn = htonl(session->cmdsn++);
	text_pdu->exp_statsn = htonl(session->conn[0].exp_statsn);

	return 1;
}

static int
request_targets(iscsi_session_t *session)
{
	char data[64];
	struct iscsi_text text;
	struct iscsi_hdr *hdr = (struct iscsi_hdr *) &text;

	memset(&text, 0, sizeof (text));
	memset(data, 0, sizeof (data));

	/* make a text PDU with SendTargets=All */
	if (!iscsi_make_text_pdu(session, hdr, data, sizeof (data))) {
		log_error("failed to make a SendTargets PDU");
		return 0;
	}

	if (!iscsi_add_text(hdr, data, sizeof (data), "SendTargets", "All")) {
		log_error("failed to add SendTargets text key");
		exit(1);
	}

	text.ttt = ISCSI_RESERVED_TAG;
	text.flags = ISCSI_FLAG_CMD_FINAL;

	if (++session->itt == ISCSI_RESERVED_TAG)
		session->itt = 1;

	if (!iscsi_io_send_pdu(&session->conn[0], hdr, ISCSI_DIGEST_NONE, data,
		    ISCSI_DIGEST_NONE, session->conn[0].active_timeout)) {
		log_error("failed to send SendTargets PDU");
		return 0;
	}

	return 1;
}

static int
iterate_targets(iscsi_session_t *session, uint32_t ttt)
{
	char data[64];
	struct iscsi_text text;
	struct iscsi_hdr *pdu = (struct iscsi_hdr *) &text;

	memset(&text, 0, sizeof (text));
	memset(data, 0, sizeof (data));

	/* make an empty text PDU */
	if (!iscsi_make_text_pdu(session, pdu, data, sizeof (data))) {
		log_error("failed to make an empty text PDU");
		return 0;
	}

	text.ttt = ttt;
	text.flags = ISCSI_FLAG_CMD_FINAL;

	if (++session->itt == ISCSI_RESERVED_TAG)
		session->itt = 1;

	if (!iscsi_io_send_pdu(&session->conn[0], pdu, ISCSI_DIGEST_NONE, data,
		    ISCSI_DIGEST_NONE, session->conn[0].active_timeout)) {
		log_error("failed to send empty text PDU");
		return 0;
	}

	return 1;
}

static int add_portal(struct list_head *rec_list, discovery_rec_t *drec,
		      char *targetname, char *address, char *port, char *tag)
{
	struct sockaddr_storage ss;
	char host[NI_MAXHOST];
	struct node_rec *rec;

	/* resolve the address, in case it was a DNS name */
	if (resolve_address(address, port, &ss)) {
		log_error("cannot resolve %s", address);
		return 0;
	}

	/* convert the resolved name to text */
	getnameinfo((struct sockaddr *) &ss, sizeof(ss),
		    host, sizeof(host), NULL, 0, NI_NUMERICHOST);

	rec = calloc(1, sizeof(*rec));
	if (!rec)
		return 0;

	idbm_node_setup_from_conf(rec);
	rec->disc_type = drec->type;
	rec->disc_port = drec->port;
	strcpy(rec->disc_address, drec->address);

	strlcpy(rec->name, targetname, TARGET_NAME_MAXLEN);
	if (tag && *tag)
		rec->tpgt = atoi(tag);
	else
		rec->tpgt = PORTAL_GROUP_TAG_UNKNOWN;
	if (port && *port)
		rec->conn[0].port = atoi(port);
	else
		rec->conn[0].port = ISCSI_LISTEN_PORT;
	strlcpy(rec->conn[0].address, address, NI_MAXHOST);

	list_add_tail(&rec->list, rec_list);
	return 1;
}

static int
add_target_record(char *name, char *end, discovery_rec_t *drec,
		  struct list_head *rec_list, char *default_port)
{
	char *text = NULL;
	char *nul = name;
	size_t length;

	/* address = IPv4
	 * address = [IPv6]
	 * address = DNSname
	 * address = IPv4:port
	 * address = [IPv6]:port
	 * address = DNSname:port
	 * address = IPv4,tag
	 * address = [IPv6],tag
	 * address = DNSname,tag
	 * address = IPv4:port,tag
	 * address = [IPv6]:port,tag
	 * address = DNSname:port,tag
	 */

	log_debug(7, "adding target record %p, end %p", name, end);

	/* find the end of the name */
	while ((nul < end) && (*nul != '\0'))
		nul++;

	length = nul - name;
	if (length > TARGET_NAME_MAXLEN) {
		log_error("TargetName %s too long, ignoring", name);
		return 0;
	}
	text = name + length;

	/* skip NULs after the name */
	while ((text < end) && (*text == '\0'))
		text++;

	/* if no address is provided, use the default */
	if (text >= end) {
		if (drec->address == NULL) {
			log_error("no default address known for target %s",
				  name);
			return 0;
		} else if (!add_portal(rec_list, drec, name, drec->address,
				       default_port, NULL)) {
			log_error("failed to add default portal, ignoring "
				  "target %s", name);
			return 0;
		}
		/* finished adding the default */
		return 1;
	}

	/* process TargetAddresses */
	while (text < end) {
		char *next = text + strlen(text) + 1;

		log_debug(7, "text %p, next %p, end %p, %s", text, next, end,
			 text);

		if (strncmp(text, "TargetAddress=", 14) == 0) {
			char *port = NULL;
			char *tag = NULL;
			char *address = text + 14;
			char *temp;

			if ((tag = strrchr(text, ','))) {
				*tag = '\0';
				tag++;
			}
			if ((port = strrchr(text, ':'))) {
				*port = '\0';
				port++;
			}

			if (*address == '[') {
				address++;
				if ((temp = strrchr(text, ']')))
					*temp = '\0';
			}

			if (!add_portal(rec_list, drec, name, address, port,
					tag)) {
				log_error("failed to add default portal, "
					 "ignoring target %s", name);
				return 0;
			}
		} else
			log_error("unexpected SendTargets data: %s",
			       text);
		text = next;
	}

	return 1;
}

static int
process_sendtargets_response(struct str_buffer *sendtargets,
			     int final, discovery_rec_t *drec,
			     struct list_head *rec_list,
			     char *default_port)
{
	char *start = str_buffer_data(sendtargets);
	char *text = start;
	char *end = text + str_data_length(sendtargets);
	char *nul = end - 1;
	char *record = NULL;
	int num_targets = 0;

	if (start == end) {
		/* no SendTargets data */
		goto done;
	}

	/* scan backwards to find the last NUL in the data, to ensure we
	 * don't walk off the end.  Since key=value pairs can span PDU
	 * boundaries, we're not guaranteed that the end of the data has a
	 * NUL.
	 */
	while ((nul > start) && *nul)
		nul--;

	if (nul == start) {
		/* couldn't find anything we can process now,
		 * it's one big partial string
		 */
		goto done;
	}

	/* find the boundaries between target records (TargetName or final PDU)
	 */
	for (;;) {
		/* skip NULs */
		while ((text < nul) && (*text == '\0'))
			text++;

		if (text == nul)
			break;

		log_debug(7,
			 "processing sendtargets record %p, text %p, line %s",
			 record, text, text);

		/* look for the start of a new target record */
		if (strncmp(text, "TargetName=", 11) == 0) {
			if (record) {
				/* send the last record, which we just found
				 * the end of. don't bother passing the
				 * "TargetName=" prefix.
				 */
				if (!add_target_record(record + 11, text,
							drec, rec_list,
							default_port)) {
					log_error(
					       "failed to add target record");
					str_truncate_buffer(sendtargets, 0);
					goto done;
				}
				num_targets++;
			}
			record = text;
		}

		/* everything up til the next NUL must be part of the
		 * current target record
		 */
		while ((text < nul) && (*text != '\0'))
			text++;
	}

	if (record) {
		if (final) {
			/* if this is the last PDU of the text sequence,
			 * it also ends a target record
			 */
			log_debug(7,
				 "processing final sendtargets record %p, "
				 "line %s",
				 record, record);
			if (add_target_record (record + 11, text,
					       drec, rec_list, default_port)) {
				num_targets++;
				record = NULL;
				str_truncate_buffer(sendtargets, 0);
			} else {
				log_error("failed to add target record");
				str_truncate_buffer(sendtargets, 0);
				goto done;
			}
		} else {
			/* remove the parts of the sendtargets buffer we've
			 * processed, and move the parts we haven't to the
			 * beginning of the buffer.
			 */
			log_debug(7,
				 "processed %d bytes of sendtargets data, "
				 "%d remaining",
				 (int)(record - str_buffer_data(sendtargets)),
				 (int)(str_buffer_data(sendtargets) +
				 str_data_length(sendtargets) - record));
			str_remove_initial(sendtargets,
					   record - str_buffer_data(sendtargets));
		}
	}

      done:

	return 1;
}

static void
clear_timer(struct timeval *timer)
{
	memset(timer, 0, sizeof (*timer));
}

/* set timer to now + seconds */
static void
set_timer(struct timeval *timer, int seconds)
{
	if (timer) {
		memset(timer, 0, sizeof (*timer));
		gettimeofday(timer, NULL);

		timer->tv_sec += seconds;
	}
}

static int
timer_expired(struct timeval *timer)
{
	struct timeval now;

	/* no timer, can't have expired */
	if ((timer == NULL) || ((timer->tv_sec == 0) && (timer->tv_usec == 0)))
		return 0;

	memset(&now, 0, sizeof (now));
	gettimeofday(&now, NULL);

	if (now.tv_sec > timer->tv_sec)
		return 1;
	if ((now.tv_sec == timer->tv_sec) && (now.tv_usec >= timer->tv_usec))
		return 1;
	return 0;
}

static int
msecs_until(struct timeval *timer)
{
	struct timeval now;
	int msecs;
	long partial;

	/* no timer, can't have expired, infinite time til it expires */
	if ((timer == NULL) || ((timer->tv_sec == 0) && (timer->tv_usec == 0)))
		return -1;

	memset(&now, 0, sizeof (now));
	gettimeofday(&now, NULL);

	/* already expired? */
	if (now.tv_sec > timer->tv_sec)
		return 0;
	if ((now.tv_sec == timer->tv_sec) && (now.tv_usec >= timer->tv_usec))
		return 0;

	/* not expired yet, do the math */
	partial = timer->tv_usec - now.tv_usec;
	if (partial < 0) {
		partial += 1000 * 1000;
		msecs = (partial + 500) / 1000;
		msecs += (timer->tv_sec - now.tv_sec - 1) * 1000;
	} else {
		msecs = (partial + 500) / 1000;
		msecs += (timer->tv_sec - now.tv_sec) * 1000;
	}

	return msecs;
}

static iscsi_session_t *
init_new_session(struct iscsi_sendtargets_config *config,
		 struct iface_rec *iface)
{
	iscsi_session_t *session;

	session = calloc(1, sizeof (*session));
	if (session == NULL)
		goto done;

	/* initialize the session's leading connection */
	session->conn[0].socket_fd = -1;
	session->conn[0].login_timeout = config->conn_timeo.login_timeout;
	session->conn[0].auth_timeout = config->conn_timeo.auth_timeout;
	session->conn[0].active_timeout = config->conn_timeo.active_timeout;
	session->conn[0].hdrdgst_en = ISCSI_DIGEST_NONE;
	session->conn[0].datadgst_en = ISCSI_DIGEST_NONE;

	session->conn[0].max_recv_dlength =
					config->iscsi.MaxRecvDataSegmentLength;
	if (session->conn[0].max_recv_dlength < ISCSI_MIN_MAX_RECV_SEG_LEN ||
	    session->conn[0].max_recv_dlength > ISCSI_MAX_MAX_RECV_SEG_LEN) {
		log_error("Invalid iscsi.MaxRecvDataSegmentLength. Must be "
			  "within %u and %u. Setting to %u.",
			  ISCSI_MIN_MAX_RECV_SEG_LEN,
			  ISCSI_MAX_MAX_RECV_SEG_LEN,
			  DEF_INI_DISC_MAX_RECV_SEG_LEN);
		session->conn[0].max_recv_dlength =
						DEF_INI_DISC_MAX_RECV_SEG_LEN;
	}
	session->conn[0].max_xmit_dlength = ISCSI_DEF_MAX_RECV_SEG_LEN;

	session->reopen_cnt = config->reopen_max + 1;

	/* OUI and uniqifying number */
	session->isid[0] = DRIVER_ISID_0;
	session->isid[1] = DRIVER_ISID_1;
	session->isid[2] = DRIVER_ISID_2;
	session->isid[3] = 0;
	session->isid[4] = 0;
	session->isid[5] = 0;

	request_initiator_name();

	if (iface && strlen(iface->iname)) {
		strcpy(initiator_name, iface->iname);
		/* MNC TODO add iface alias */
	} else {
		if (initiator_name[0] == '\0') {
			log_error("Cannot perform discovery. Initiatorname "
				  "required.");
			free(session);
			return NULL;
		}
	}

	session->initiator_name = initiator_name;
	session->initiator_alias = initiator_alias;
	session->portal_group_tag = PORTAL_GROUP_TAG_UNKNOWN;
	session->type = ISCSI_SESSION_TYPE_DISCOVERY;
done:
	return session;
}


static int
setup_authentication(iscsi_session_t *session,
		     discovery_rec_t *drec,
		     struct iscsi_sendtargets_config *config)
{
	int rc;

	rc = 1;

	/* if we have any incoming credentials, we insist on authenticating
	 * the target or not logging in at all
	 */
	if (config->auth.username_in[0]
	    || config->auth.password_in_length) {
		session->bidirectional_auth = 1;

		/* sanity check the config */
		if (config->auth.password_length == 0) {
			log_error(
			       "discovery process to %s:%d has incoming "
			       "authentication credentials but has no outgoing "
			       "credentials configured",
			       drec->address, drec->port);
			log_error(
			       "discovery process to %s:%d exiting, bad "
			       "configuration",
			       drec->address, drec->port);
			rc = 0;
			goto done;
		}
	} else {
		/* no or 1-way authentication */
		session->bidirectional_auth = 0;
	}

	/* copy in whatever credentials we have */
	strlcpy(session->username, config->auth.username,
		sizeof (session->username));
	session->username[sizeof (session->username) - 1] = '\0';
	if ((session->password_length = config->auth.password_length))
		memcpy(session->password, config->auth.password,
		       session->password_length);

	strlcpy(session->username_in, config->auth.username_in,
		sizeof (session->username_in));
	session->username_in[sizeof (session->username_in) - 1] = '\0';
	if ((session->password_in_length =
	     config->auth.password_in_length))
		memcpy(session->password_in, config->auth.password_in,
		       session->password_in_length);

	if (session->password_length || session->password_in_length) {
		/* setup the auth buffers */
		session->auth_buffers[0].address = &session->auth_client_block;
		session->auth_buffers[0].length =
		    sizeof (session->auth_client_block);
		session->auth_buffers[1].address =
		    &session->auth_recv_string_block;
		session->auth_buffers[1].length =
		    sizeof (session->auth_recv_string_block);

		session->auth_buffers[2].address =
		    &session->auth_send_string_block;
		session->auth_buffers[2].length =
		    sizeof (session->auth_send_string_block);

		session->auth_buffers[3].address =
		    &session->auth_recv_binary_block;
		session->auth_buffers[3].length =
		    sizeof (session->auth_recv_binary_block);

		session->auth_buffers[4].address =
		    &session->auth_send_binary_block;
		session->auth_buffers[4].length =
		    sizeof (session->auth_send_binary_block);

		session->num_auth_buffers = 5;
	} else {
		session->num_auth_buffers = 0;
	}
 done:
	return(rc);
}

static int
process_recvd_pdu(struct iscsi_hdr *pdu,
		  discovery_rec_t *drec,
		  struct list_head *rec_list,
		  iscsi_session_t *session,
		  struct str_buffer *sendtargets,
		  char *default_port,
		  int *active,
		  int *valid_text,
		  char *data)
{
	int rc=0;

	switch (pdu->opcode) {
		case ISCSI_OP_TEXT_RSP:{
			struct iscsi_text_rsp *text_response =
				(struct iscsi_text_rsp *) pdu;
			int dlength = ntoh24(pdu->dlength);
			int final =
				(text_response->flags & ISCSI_FLAG_CMD_FINAL) ||
				(text_response-> ttt == ISCSI_RESERVED_TAG);
			size_t curr_data_length;

			log_debug(4, "discovery session to %s:%d received text"
				 " response, %d data bytes, ttt 0x%x, "
				 "final 0x%x",
				 drec->address,
				 drec->port,
				 dlength,
				 ntohl(text_response->ttt),
				 text_response->flags & ISCSI_FLAG_CMD_FINAL);

			/* mark how much more data in the sendtargets
			 * buffer is now valid
			 */
			curr_data_length = str_data_length(sendtargets);
			if (str_enlarge_data(sendtargets, dlength)) {
				log_error("Could not allocate memory to "
					  "process SendTargets response.");
				rc = 0;
				goto done;
			}

			memcpy(str_buffer_data(sendtargets) + curr_data_length,
			       data, dlength);

			*valid_text = 1;
			/* process as much as we can right now */
			process_sendtargets_response(sendtargets,
						     final,
						     drec,
						     rec_list,
						     default_port);

			if (final) {
				/* SendTargets exchange is now complete
				 */
				*active = 0;
				/* from now on, after any reconnect,
				 * assume LUNs may have changed
				 */
			} else {
				/* ask for more targets */
				if (!iterate_targets(session,
						     text_response->ttt)) {
					rc = DISCOVERY_NEED_RECONNECT;
					goto done;
				}
			}
			break;
		}
		default:
			log_warning(
			       "discovery session to %s:%d received "
			       "unexpected opcode 0x%x",
			       drec->address, drec->port, pdu->opcode);
			rc = DISCOVERY_NEED_RECONNECT;
			goto done;
	}
 done:
	return(rc);
}

/*
 * Make a best effort to logout the session, then disconnect the
 * socket.
 */
static void
iscsi_logout_and_disconnect(iscsi_session_t * session)
{
	struct iscsi_logout logout_req;
	struct iscsi_logout_rsp logout_resp;
	int rc;

	/*
	 * Build logout request header
	 */
	memset(&logout_req, 0, sizeof (logout_req));
	logout_req.opcode = ISCSI_OP_LOGOUT | ISCSI_OP_IMMEDIATE;
	logout_req.flags = ISCSI_FLAG_CMD_FINAL |
		(ISCSI_LOGOUT_REASON_CLOSE_SESSION &
				ISCSI_FLAG_LOGOUT_REASON_MASK);
	logout_req.itt = htonl(session->itt);
	if (++session->itt == ISCSI_RESERVED_TAG)
		session->itt = 1;
	logout_req.cmdsn = htonl(session->cmdsn);
	logout_req.exp_statsn = htonl(++session->conn[0].exp_statsn);

	/*
	 * Send the logout request
	 */
	rc = iscsi_io_send_pdu(&session->conn[0],(struct iscsi_hdr *)&logout_req,
			    ISCSI_DIGEST_NONE, NULL, ISCSI_DIGEST_NONE, 3);
	if (!rc) {
		log_error(
		       "iscsid: iscsi_logout - failed to send logout PDU.");
		goto done;
	}

	/*
	 * Read the logout response
	 */
	memset(&logout_resp, 0, sizeof(logout_resp));
	rc = iscsi_io_recv_pdu(&session->conn[0],
		(struct iscsi_hdr *)&logout_resp, ISCSI_DIGEST_NONE, NULL,
		0, ISCSI_DIGEST_NONE, 1);
	if (!rc) {
		log_error("iscsid: logout - failed to receive logout resp");
		goto done;
	}
	if (logout_resp.response != ISCSI_LOGOUT_SUCCESS) {
		log_error("iscsid: logout failed - response = 0x%x",
		       logout_resp.response);
	}

done:
	/*
	 * Close the socket.
	 */
	iscsi_io_disconnect(&session->conn[0]);
}

int discovery_sendtargets(void *fndata, struct iface_rec *iface,
			  struct list_head *rec_list)
{
	discovery_rec_t *drec = fndata;
	iscsi_session_t *session;
	struct pollfd pfd;
	struct iscsi_hdr pdu_buffer;
	struct iscsi_hdr *pdu = &pdu_buffer;
	char *data = NULL;
	int active = 0, valid_text = 0;
	struct timeval connection_timer;
	int timeout;
	int rc;
	struct str_buffer sendtargets;
	uint8_t status_class = 0, status_detail = 0;
	unsigned int login_failures = 0, data_len;
	int login_delay = 0;
	struct sockaddr_storage ss;
	char host[NI_MAXHOST], serv[NI_MAXSERV], default_port[NI_MAXSERV];
	struct iscsi_sendtargets_config *config = &drec->u.sendtargets;

	/* initial setup */
	log_debug(1, "starting sendtargets discovery, address %s:%d, ",
		 drec->address, drec->port);
	memset(&pdu_buffer, 0, sizeof (pdu_buffer));
	clear_timer(&connection_timer);

	/* allocate a new session, and initialize default values */
	session = init_new_session(config, iface);
	if (session == NULL) {
		log_error("Discovery process to %s:%d failed to "
			  "create a discovery session.",
			  drec->address, drec->port);
		return 1;
	}

	log_debug(4, "sendtargets discovery to %s:%d using "
		 "isid 0x%02x%02x%02x%02x%02x%02x",
		 drec->address, drec->port, session->isid[0],
		 session->isid[1], session->isid[2], session->isid[3],
		 session->isid[4], session->isid[5]);

	/* allocate data buffers for SendTargets data */
	data = malloc(session->conn[0].max_recv_dlength);
	if (!data) {
		rc = 1;
		goto free_session;
	}
	data_len = session->conn[0].max_recv_dlength;

	str_init_buffer(&sendtargets, 0);

	sprintf(default_port, "%d", drec->port);
	/* resolve the DiscoveryAddress to an IP address */
	if (resolve_address(drec->address, default_port, &ss)) {
		log_error("cannot resolve host name %s", drec->address);
		rc = 1;
		goto free_sendtargets;
	}

	log_debug(4, "discovery timeouts: login %d, reopen_cnt %d, auth %d.",
		 session->conn[0].login_timeout, session->reopen_cnt,
		 session->conn[0].auth_timeout);

	/* setup authentication variables for the session*/
	rc = setup_authentication(session, drec, config);
	if (rc == 0) {
		rc = 1;
		goto free_sendtargets;
	}

set_address:
	/*
	 * copy the saved address to the session,
	 * undoing any temporary redirect
	 */
	session->conn[0].saddr = ss;

reconnect:

	if (--session->reopen_cnt < 0) {
		log_error("connection login retries (reopen_max %d) exceeded",
			  config->reopen_max);
		rc = 1;
		goto free_sendtargets;
	}

redirect_reconnect:

	iscsi_io_disconnect(&session->conn[0]);

	session->cmdsn = 1;
	session->itt = 1;
	session->portal_group_tag = PORTAL_GROUP_TAG_UNKNOWN;

	/* slowly back off the frequency of login attempts */
	if (login_failures == 0)
		login_delay = 0;
	else if (login_failures < 10)
		login_delay = 1;	/* 10 seconds at 1 sec each */
	else if (login_failures < 20)
		login_delay = 2;	/* 20 seconds at 2 sec each */
	else if (login_failures < 26)
		login_delay = 5;	/* 30 seconds at 5 sec each */
	else if (login_failures < 34)
		login_delay = 15;	/* 60 seconds at 15 sec each */
	else
		login_delay = 60;	/* after 2 minutes, try once a minute */

	if (login_delay) {
		log_debug(4, "discovery session to %s:%d sleeping for %d "
			 "seconds before next login attempt",
			 drec->address, drec->port, login_delay);
		sleep(login_delay);
	}

	getnameinfo((struct sockaddr *) &session->conn[0].saddr,
		    sizeof(session->conn[0].saddr), host,
		    sizeof(host), serv, sizeof(serv),
		    NI_NUMERICHOST|NI_NUMERICSERV);

	if (!iscsi_io_connect(&session->conn[0])) {
		log_error("connection to discovery address %s "
			  "failed", host);

		login_failures++;
		/* If a temporary redirect sent us to something unreachable,
		 * we want to go back to the original IP address, so make sure
		 * we reset the session's IP.
		 */
		goto set_address;
	}

	log_debug(1, "connected to discovery address %s", host);

	log_debug(4, "discovery session to %s:%d starting iSCSI login on fd %d",
		 drec->address, drec->port, session->conn[0].socket_fd);

	/* In case of discovery, we using socket's descriptor as ctrl. */
	session->ctrl_fd = session->conn[0].socket_fd;
	session->conn[0].session = session;

	status_class = 0;
	status_detail = 0;

	memset(data, 0, data_len);
	rc = iscsi_login(session, 0, data, data_len,
			 &status_class, &status_detail);

	switch (rc) {
	case LOGIN_OK:
	case LOGIN_REDIRECT:
		break;

	case LOGIN_IO_ERROR:
	case LOGIN_REDIRECTION_FAILED:
		/* try again */
		log_warning("retrying discovery login to %s", host);
		iscsi_io_disconnect(&session->conn[0]);
		login_failures++;
		goto set_address;

	default:
	case LOGIN_FAILED:
	case LOGIN_NEGOTIATION_FAILED:
	case LOGIN_AUTHENTICATION_FAILED:
	case LOGIN_VERSION_MISMATCH:
	case LOGIN_INVALID_PDU:
		log_error("discovery login to %s failed, giving up", host);
		iscsi_io_disconnect(&session->conn[0]);
		rc = 1;
		goto free_sendtargets;
	}

	/* check the login status */
	switch (status_class) {
	case ISCSI_STATUS_CLS_SUCCESS:
		log_debug(4, "discovery login success to %s", host);
		login_failures = 0;
		break;
	case ISCSI_STATUS_CLS_REDIRECT:
		switch (status_detail) {
			/* the session IP address was changed by the login
			 * library, so just try again with this portal
			 * config but the new address.
			 */
		case ISCSI_LOGIN_STATUS_TGT_MOVED_TEMP:
			log_warning(
				"discovery login temporarily redirected to "
				"%s port %s", host, serv);
			goto redirect_reconnect;
		case ISCSI_LOGIN_STATUS_TGT_MOVED_PERM:
			log_warning(
				"discovery login permanently redirected to "
				"%s port %s", host, serv);
			/* make the new address permanent */
			ss = session->conn[0].saddr;
			goto redirect_reconnect;
		default:
			log_error(
			       "discovery login rejected: redirection type "
			       "0x%x not supported",
			       status_detail);
			goto set_address;
		}
		break;
	case ISCSI_STATUS_CLS_INITIATOR_ERR:
		log_error(
			"discovery login to %s rejected: "
			"initiator error (%02x/%02x), non-retryable, giving up",
			host, status_class, status_detail);
		iscsi_io_disconnect(&session->conn[0]);
		rc = 1;
		goto free_sendtargets;
	case ISCSI_STATUS_CLS_TARGET_ERR:
		log_error(
			"discovery login to %s rejected: "
			"target error (%02x/%02x)",
			host, status_class, status_detail);
		iscsi_io_disconnect(&session->conn[0]);
		login_failures++;
		goto reconnect;
	default:
		log_error(
			"discovery login to %s failed, response "
			"with unknown status class 0x%x, detail 0x%x",
			host,
			status_class, status_detail);
		iscsi_io_disconnect(&session->conn[0]);
		login_failures++;
		goto reconnect;
	}

	/* reinitialize */
	str_truncate_buffer(&sendtargets, 0);

	/* ask for targets */
	if (!request_targets(session)) {
		goto reconnect;
	}
	active = 1;

	/* set timeouts */
	set_timer(&connection_timer, session->conn[0].active_timeout);

	/* prepare to poll */
	memset(&pfd, 0, sizeof (pfd));
	pfd.fd = session->conn[0].socket_fd;
	pfd.events = POLLIN | POLLPRI;

repoll:
	timeout = msecs_until(&connection_timer);
	/* block until we receive a PDU, a TCP FIN, a TCP RST,
	 * or a timeout
	 */
	log_debug(4,
		 "discovery process  %s:%d polling fd %d, "
		 "timeout in %f seconds",
		 drec->address, drec->port, pfd.fd,
		 timeout / 1000.0);

	pfd.revents = 0;
	rc = poll(&pfd, 1, timeout);

	log_debug(7,
		 "discovery process to %s:%d returned from poll, rc %d",
		 drec->address, drec->port, rc);

	if (timer_expired(&connection_timer)) {
		log_warning("discovery session to %s:%d session "
			    "logout, connection timer expired",
			    drec->address, drec->port);
			    iscsi_logout_and_disconnect(session);
		rc = 1;
		goto free_sendtargets;
	}

	if (rc > 0) {
		if (pfd.revents & (POLLIN | POLLPRI)) {
			timeout = msecs_until(&connection_timer);

			memset(data, 0, data_len);
			if (!iscsi_io_recv_pdu(&session->conn[0],
					       pdu, ISCSI_DIGEST_NONE, data,
			     		       data_len, ISCSI_DIGEST_NONE,
					       timeout)) {
				log_debug(1, "discovery session to "
					  "%s:%d failed to recv a PDU "
					  "response, terminating",
					   drec->address,
					   drec->port);
				iscsi_io_disconnect(&session->conn[0]);
				rc = 1;
				goto free_sendtargets;
			}

			/*
			 * process iSCSI PDU received
			 */
			rc = process_recvd_pdu(pdu, drec, rec_list,
					       session, &sendtargets,
					       default_port,
					       &active, &valid_text, data);
			if (rc == DISCOVERY_NEED_RECONNECT)
				goto reconnect;

			/* reset timers after receiving a PDU */
			if (active) {
				set_timer(&connection_timer,
				       session->conn[0].active_timeout);
				goto repoll;
			}
		}

		if (pfd.revents & POLLHUP) {
			log_warning("discovery session to %s:%d "
				    "terminating after hangup",
				     drec->address, drec->port);
			iscsi_io_disconnect(&session->conn[0]);
			rc = 1;
			goto free_sendtargets;
		}

		if (pfd.revents & POLLNVAL) {
			log_warning("discovery POLLNVAL");
			sleep(1);
			goto reconnect;
		}

		if (pfd.revents & POLLERR) {
			log_warning("discovery POLLERR");
			sleep(1);
			goto reconnect;
		}
	} else if (rc < 0) {
		if (errno == EINTR) {
			/* if we got SIGHUP, reconnect and rediscover */
			if (rediscover) {
				rediscover = 0;
				log_debug(1, "rediscovery requested");
				goto reconnect;
			}
		} else {
			log_error("poll error");
			rc = 1;
			goto free_sendtargets;
		}
	}

	log_debug(1, "discovery process to %s:%d exiting",
		 drec->address, drec->port);
	rc = 0;

free_sendtargets:
	str_free_buffer(&sendtargets);
	free(data);
free_session:
	free(session);
	return rc;
}

#ifdef SLP_ENABLE
int
slp_discovery(struct iscsi_slp_config *config)
{
	struct sigaction action;
	char *pl;
	unsigned short flag = 0;

	memset(&action, 0, sizeof (struct sigaction));
	action.sa_sigaction = NULL;
	action.sa_flags = 0;
	action.sa_handler = SIG_DFL;
	sigaction(SIGTERM, &action, NULL);
	sigaction(SIGINT, &action, NULL);
	sigaction(SIGPIPE, &action, NULL);

	action.sa_handler = sighup_handler;
	sigaction(SIGHUP, &action, NULL);

	if (iscsi_process_should_exit()) {
		log_debug(1, "slp discovery process %p exiting", discovery);
		exit(0);
	}

	discovery->pid = getpid();

	pl = generate_predicate_list(discovery, &flag);

	while (1) {
		if (flag == SLP_MULTICAST_ENABLED) {
			discovery->flag = SLP_MULTICAST_ENABLED;
			slp_multicast_srv_query(discovery, pl, GENERIC_QUERY);
		}

		if (flag == SLP_UNICAST_ENABLED) {
			discovery->flag = SLP_UNICAST_ENABLED;
			slp_unicast_srv_query(discovery, pl, GENERIC_QUERY);
		}

		sleep(config->poll_interval);
	}

	exit(0);
}

#endif
