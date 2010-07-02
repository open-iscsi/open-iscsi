/*
 * iSCSI Initiator discovery daemon
 *
 * Copyright (C) 2010 Mike Christie
 * Copyright (C) 2010 Red Hat, Inc. All rights reserved.

 * maintained by open-iscsi@googlegroups.com
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
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "discovery.h"
#include "idbm.h"
#include "list.h"
#include "iscsi_proto.h"
#include "sysdeps.h"
#include "log.h"
#include "session_mgmt.h"
#include "iscsi_util.h"
#include "event_poll.h"
#include "iface.h"
#include "session_mgmt.h"
#include "session_info.h"
#include "isns-proto.h"
#include "isns.h"
#include "paths.h"
#include "message.h"

#define DISC_DEF_POLL_INVL	30

static LIST_HEAD(iscsi_targets);
static int stop_discoveryd;

static LIST_HEAD(isns_initiators);
static LIST_HEAD(isns_refresh_list);
static char *isns_entity_id = NULL;
static uint32_t isns_refresh_interval;
static int isns_register_nodes = 1;

static void isns_reg_refresh_by_eid_qry(void *data);

typedef void (do_disc_and_login_fn)(const char *def_iname,
				    struct discovery_rec *drec, int poll_inval);

static int logout_session(void *data, struct list_head *list,
			  struct session_info *info)
{
	struct list_head *rec_list = data;
	struct node_rec *rec;

	list_for_each_entry(rec, rec_list, list) {
		if (iscsi_match_session(rec, info))
			return iscsi_logout_portal(info, list);
	}
	return -1;
}

static void discoveryd_stop(void)
{
	struct node_rec *rec, *tmp_rec;
	int nr_found = 0;

	if (list_empty(&iscsi_targets))
		goto done;

	/*
	 * User requested to just login and exit.
	 */
	if (!stop_discoveryd)
		goto done;

	iscsi_logout_portals(&iscsi_targets, &nr_found, 1, logout_session);
	list_for_each_entry_safe(rec, tmp_rec, &iscsi_targets, list) {
		list_del(&rec->list);
		free(rec);
	}

done:
	exit(0);
}

static void catch_signal(int signo)
{
	log_debug(1, "%d caught signal -%d...", signo, getpid());
	switch (signo) {
	case SIGTERM:
		stop_discoveryd = 1;
		break;
	default:
		break;
	}
}

static void setup_signal_handler(void)
{
	struct sigaction sa_old;
	struct sigaction sa_new;

	sa_new.sa_handler = catch_signal;
	sigemptyset(&sa_new.sa_mask);
	sa_new.sa_flags = 0;
	sigaction(SIGTERM, &sa_new, &sa_old );
}

/*
 * update_sessions - login/logout sessions
 * @new_rec_list: new target portals recs bound to ifaces
 * @targetname: if set we only update sessions for this target
 * @iname: if set we only update session for that initiator
 *
 * This will login/logout of portals. When it returns the recs on
 * new_rec_list will be freed or put on the iscsi_targets list.
 *
 * FIXME: if we are hitting a per problem this may be it. With targets
 * that do a target per lun this could get ugly.
 */
static void update_sessions(struct list_head *new_rec_list,
			    const char *targetname, const char *iname)
{
	struct node_rec *rec, *tmp_rec;
	struct list_head stale_rec_list;
	int nr_found;

	INIT_LIST_HEAD(&stale_rec_list);
	/*
 	 * Check if a target portal is no longer being sent.
 	 * Note: Due to how we reread ifaces this will also detect
 	 * changes in ifaces being access through portals.
 	 */
	list_for_each_entry_safe(rec, tmp_rec, &iscsi_targets, list) {
		log_debug(7, "Trying to match %s %s to %s %s %s",
	 		   targetname, iname, rec->name, rec->conn[0].address,
			    rec->iface.name);
		if (targetname && strcmp(rec->name, targetname))
			continue;

		if (iname) {
			if (strlen(rec->iface.iname) &&
			    strcmp(rec->iface.iname, iname))
				continue;
			else if (strcmp(iname, isns_config.ic_source_name))
				continue;
		}

		log_debug(5, "Matched %s %s, checking if in new targets.",
			  targetname, iname);
		if (!idbm_find_rec_in_list(new_rec_list, rec->name,
					   rec->conn[0].address,
					   rec->conn[0].port, &rec->iface)) {
			log_debug(5, "Not found. Marking for logout");
			list_move_tail(&rec->list, &stale_rec_list);
		}
	}

	list_for_each_entry_safe(rec, tmp_rec, new_rec_list, list) {
		if (!iscsi_check_for_running_session(rec))
			iscsi_login_portal_nowait(rec);

		if (!idbm_find_rec_in_list(&iscsi_targets, rec->name,
					   rec->conn[0].address,
					   rec->conn[0].port, &rec->iface)) {
			log_debug(5, "%s %s %s %s not on curr target list. "
				 "Adding.", rec->name, rec->conn[0].address,
				 rec->iface.name, rec->iface.iname);
			list_move_tail(&rec->list, &iscsi_targets);
		} else {
			list_del(&rec->list);
			free(rec);
		}
	}

	if (!list_empty(&stale_rec_list)) {
		iscsi_logout_portals(&stale_rec_list, &nr_found, 0,
				     logout_session);
		list_for_each_entry_safe(rec, tmp_rec, &stale_rec_list, list) {
			list_del(&rec->list);
			free(rec);
		}
	}
}

static void fork_disc(const char *def_iname, struct discovery_rec *drec,
		      int poll_inval, do_disc_and_login_fn *do_disc_and_login)
{
	pid_t pid;

	pid = fork();
	if (pid == 0) {
		setup_signal_handler();
		do_disc_and_login(def_iname, drec, poll_inval);
		exit(0);
	} else if (pid < 0)
		log_error("Fork failed (err %d - %s). Will not be able "
			   "to perform discovery to %s.\n",
			   errno, strerror(errno), drec->address);
	else {
		shutdown_callback(pid);
		log_debug(1, "iSCSI disc and login helper pid=%d", pid);
		reap_inc();
	}
}

struct isns_node_list {
	isns_source_t *source;
	struct list_head list;
};

/* iSNS */
static int isns_build_objs(isns_portal_info_t *portal_info,
			   isns_object_list_t *objs)
{
	struct isns_node_list *node;
	isns_object_t *inode, *entity;
	unsigned int i, nportals = 1; 
	int rc = 0;

	log_debug(7, "isns_build_objs");

	/* we currently just use all portals */
	if (isns_portal_is_wildcard(portal_info)) {
		static isns_portal_info_t *iflist;

		nportals = isns_get_nr_portals();
		log_debug(4, "got %d portals", nportals);
		if (!nportals)
			return ENODEV;

		iflist = calloc(nportals, sizeof(isns_portal_info_t));
		if (!iflist) {
			log_error("Unable to allocate %d portals.", nportals);
			return ENOMEM;
		}

		nportals = isns_enumerate_portals(iflist, nportals);
		if (nportals == 0) {
			log_error("Unable to enumerate portals - "
				  "no usable interfaces found\n");
			free(iflist);
			return ENODEV;
		}
		for (i = 0; i < nportals; ++i) {
			iflist[i].addr.sin6_port = portal_info->addr.sin6_port;
			iflist[i].proto = portal_info->proto;
		}
		portal_info = iflist;
	}

	if (!isns_entity_id) {
		isns_entity_id = calloc(1, 256);
		if (!isns_entity_id)
			return ENOMEM;

		rc = getnameinfo((struct sockaddr *) &portal_info->addr,
				 sizeof(portal_info->addr),
				 isns_entity_id, 256, NULL, 0, 0);
		if (rc) {
			free(isns_entity_id);
			isns_entity_id = NULL;

			log_error("Could not get hostname for EID.");
			return EIO;
		}
	}

	entity = isns_create_entity(ISNS_ENTITY_PROTOCOL_ISCSI, isns_entity_id);
	if (!entity) {
		log_error("Could not create iSNS entity.");
		return ENOMEM;
	}
	isns_object_list_append(objs, entity);

	for (i = 0; i < nportals; ++i, ++portal_info) { 
		isns_object_t *portal;

		portal = isns_create_portal(portal_info, entity);
		if (!portal) {
			rc = ENOMEM;
			goto fail;
		}
		isns_object_list_append(objs, portal);

		if (!isns_object_set_uint32(portal, ISNS_TAG_SCN_PORT,
				isns_portal_tcpudp_port(portal_info))) {
			rc = EINVAL;
			goto fail;
		}
	}

	list_for_each_entry(node, &isns_initiators, list) {
		inode = isns_create_storage_node2(node->source,
						  ISNS_ISCSI_INITIATOR_MASK,
						  NULL);
		if (!inode) {
			rc = ENOMEM;
			goto fail;
		}
		isns_object_list_append(objs, inode);		
	}

	return 0;
fail:
	isns_object_list_destroy(objs);
	return rc;
}

struct isns_qry_data {
	const char *iname;
	const char *targetname;
};

static int isns_query_node(void *data, struct iface_rec *iface,
			   struct list_head *recs)
{
	struct isns_qry_data *qry_data = data;
	int is_def_iname = 0;
	const char *iname;

	if (qry_data->iname) {
		if (!strcmp(qry_data->iname, isns_config.ic_source_name))
			is_def_iname = 1;

		if ((!is_def_iname || strlen(iface->iname)) &&
		    strcmp(iface->iname, qry_data->iname))
			return 0;

		iname = qry_data->iname;
	} else {
		if (strlen(iface->iname))
			iname = iface->iname;
		else
			iname = isns_config.ic_source_name;
	}

	return discovery_isns_query(NULL, iname, qry_data->targetname, recs);
}

static int isns_disc_new_portals(const char *targetname, const char *iname)
{
	struct list_head ifaces, rec_list;
	struct iface_rec *iface, *tmp_iface;
	struct isns_qry_data qry_data;
	int rc;

	INIT_LIST_HEAD(&rec_list);
	INIT_LIST_HEAD(&ifaces);

	qry_data.targetname = targetname;
	qry_data.iname = iname;

log_error("isns_disc_new_portals");
	iface_link_ifaces(&ifaces);
	rc = idbm_bind_ifaces_to_nodes(isns_query_node, &qry_data, &ifaces,
				       &rec_list);
	if (rc) {
		log_error("Could not perform iSNS DevAttrQuery for node %s.",
			  targetname);
		goto free_ifaces;
	}
	update_sessions(&rec_list, targetname, iname);
	rc = 0;

free_ifaces:
	list_for_each_entry_safe(iface, tmp_iface, &ifaces, list) {
		list_del(&iface->list);
		free(iface);
	}

	return rc;
}

static void isns_reg_refresh_with_disc(void *data)
{
	int retries = 0, rc;

	log_debug(1, "Refresh registration using DevAttrQuery");

	/*
	 * it is ok to block here since we are not expecting SCNs
	 * from the server.
	 */
	do {
		/*
		 * Some servers do not support SCNs so we ping
		 * the server by doing discovery.
		 */
		rc = isns_disc_new_portals(NULL, NULL);
		if (rc) {
			log_debug(4, "Registration refresh using DevAttrQuery "
				  "failed (retires %d) err %d", retries, rc);
			sleep(1);
			retries++;
			continue;
		}
	} while (rc && retries < 3);

	if (rc)
		/*
		 * Try to reregister from scratch.
		 */
		 isns_register_nodes = 1;
}

struct isns_refresh_data {
	isns_client_t *clnt;
	isns_simple_t *qry;
	uint32_t xid;
	uint32_t interval;
	time_t start_time;
	struct list_head list;
};

static void isns_free_refresh_data(struct isns_refresh_data *refresh_data)
{
	list_del(&refresh_data->list);
	if (refresh_data->qry)
		isns_simple_free(refresh_data->qry);
	if (refresh_data->clnt)
		isns_client_destroy(refresh_data->clnt);
	free(refresh_data);
}

static struct isns_refresh_data *isns_find_refresh_data(uint32_t xid)
{
	struct isns_refresh_data *refresh_data;

	list_for_each_entry(refresh_data, &isns_refresh_list, list) {
		if (refresh_data->xid == xid)
			return refresh_data;
	}
	return NULL;
}

static void isns_eid_qry_rsp(uint32_t xid, int status, isns_simple_t *rsp)
{
	struct isns_refresh_data *refresh_data;

	refresh_data = isns_find_refresh_data(xid);
	if (!refresh_data) {
		log_error("EID Query respond could not match xid");
		return;
	}

	if (refresh_data->clnt) {
		isns_client_destroy(refresh_data->clnt);
		refresh_data->clnt = NULL;
	}

	if (!rsp || status != ISNS_SUCCESS) {
		log_debug(1, "Registration refresh using eid qry failed: %s",
			  isns_strerror(status));
		
		isns_add_oneshot_timer(2, isns_reg_refresh_by_eid_qry,
				       refresh_data);
		return;
	}

	log_debug(1, "eid qry successful");
	refresh_data->start_time = time(NULL);
	isns_add_oneshot_timer(isns_refresh_interval,
	       		       isns_reg_refresh_by_eid_qry, refresh_data);
}

static void isns_reg_refresh_by_eid_qry(void *data)
{
	struct isns_refresh_data *refresh_data = data;
	isns_attr_list_t qry_key = ISNS_ATTR_LIST_INIT;
	isns_simple_t *qry;
	isns_client_t *clnt;
	int status, timeout;

	log_debug(1, "Refresh registration using eid qry");
	if (refresh_data->start_time + refresh_data->interval <= time(NULL)) {
		log_error("Could not refresh registration with server "
			  "before registration period. Starting new "
			  "registration.");
		isns_free_refresh_data(refresh_data);
		isns_register_nodes = 1;
		return;
	}

	clnt = isns_create_default_client(NULL);
	if (!clnt) {
		log_error("iSNS registration refresh failed. Could not "
			  "connect to server.");
		goto rearm;
	}
	refresh_data->clnt = clnt;
	/*
	 * if a operation has failed we will want to adjust timers
	 * and possibly reregister.
	 */
	isns_socket_set_report_failure(clnt->ic_socket);

	/*
	 * if this is a retry or re-refresh then there will be a qry
	 */
	qry = refresh_data->qry;
	if (qry)
		goto send;

	isns_attr_list_append_string(&qry_key, ISNS_TAG_ENTITY_IDENTIFIER,
				     isns_entity_id);
	qry = isns_create_query(clnt, &qry_key);
	isns_attr_list_destroy(&qry_key);
	if (!qry)
		goto rearm;
	isns_query_request_attr_tag(qry, ISNS_TAG_ENTITY_PROTOCOL);
	refresh_data->qry = qry;

send:
	timeout = (refresh_data->start_time + refresh_data->interval) -
								time(NULL);

	status = isns_simple_transmit(clnt->ic_socket, qry, NULL,
				      timeout, isns_eid_qry_rsp);
	if (status == ISNS_SUCCESS) {
		log_debug(7, "sent eid qry with xid %u", qry->is_xid);

		refresh_data->xid = qry->is_xid;
		return;
	}
rearm:
	if (refresh_data->clnt) {
		isns_client_destroy(refresh_data->clnt);
		refresh_data->clnt = NULL;
	}
	log_debug(1, "Could not send eid qry to refresh registration.");
	isns_add_oneshot_timer(2, isns_reg_refresh_by_eid_qry, refresh_data);
}

static int isns_setup_registration_refresh(isns_simple_t *rsp, int poll_inval)
{
	isns_object_list_t objs = ISNS_OBJECT_LIST_INIT;
	struct isns_refresh_data *refresh_data;
	int status, i, rc = 0;
	uint32_t interval = 0;

	status = isns_query_response_get_objects(rsp, &objs);
	if (status) {
		log_error("Unable to extract object list from "
                           "registration response: %s\n",
                           isns_strerror(status));
		return EIO;
	}

	for (i = 0; i < objs.iol_count; ++i) {
		isns_object_t *obj = objs.iol_data[i]; 

		if (!isns_object_is_entity(obj))
			continue;

		if (isns_object_get_uint32(obj, ISNS_TAG_REGISTRATION_PERIOD,
					   &interval))
			break;
	}

	if (!interval)
		goto free_objs;

	refresh_data = calloc(1, sizeof(*refresh_data));
	if (!refresh_data) {
		rc = ENOMEM;
		goto free_objs;
	}
	INIT_LIST_HEAD(&refresh_data->list);
	list_add_tail(&refresh_data->list, &isns_refresh_list);
	refresh_data->start_time = time(NULL);

	/*
	 * Several servers do not support SCNs properly, so for the
	 * registration period refresh we do a DevAttrQuery for all targets
	 * if the poll_inval is greater than 0.
	 *
	 * If the target does support SCNs then we just send a query
	 * for our entity's protocol.
	 */

	/* we cut in half to give us time to handle errors */
	isns_refresh_interval = interval / 2;
	if (!isns_refresh_interval) {
		log_warning("iSNS Registration Period only %d seconds.",
			    interval);
		isns_refresh_interval = interval;
	}
	refresh_data->interval = interval;

	if (poll_inval > 0) {
		/* user wants to override server and do disc */
		if (isns_refresh_interval > poll_inval)
			isns_refresh_interval = poll_inval;
		isns_add_timer(isns_refresh_interval,
			       isns_reg_refresh_with_disc,
			       refresh_data);
	} else
		/*
		 * user wants to use server value so we just ping
		 * with a simple qry
		 */
		isns_add_oneshot_timer(isns_refresh_interval,
				       isns_reg_refresh_by_eid_qry,
				       refresh_data);
	log_debug(5, "Got registration period of %u "
		  "internval. Using interval of %u",
		  interval, isns_refresh_interval);

free_objs:
	isns_flush_events();
	isns_object_list_destroy(&objs);
	return rc;
}

static void isns_cancel_refresh_timers(void)
{
	isns_cancel_timer(isns_reg_refresh_with_disc, NULL);
	isns_cancel_timer(isns_reg_refresh_by_eid_qry, NULL);
}

static int isns_register_objs(isns_client_t *clnt, isns_object_list_t *objs,
			      int poll_inval)
{
	struct isns_node_list *node;
	isns_object_t *entity = NULL;
	isns_simple_t *reg;
	unsigned int i;
	int status, rc = 0;

	log_debug(7, "isns_register_objs");

	for (i = 0; i < objs->iol_count; ++i) {
		if (isns_object_is_entity(objs->iol_data[i])) {
			entity = objs->iol_data[i];
			break;
		}
	}

	reg = isns_create_registration(clnt, entity);
	if (!reg)
		return ENOMEM;

	for (i = 0; i < objs->iol_count; ++i)
		isns_registration_add_object(reg, objs->iol_data[i]);
	isns_registration_set_replace(reg, 1);

	status = isns_simple_call(clnt->ic_socket, &reg);
	if (status != ISNS_SUCCESS) {
		log_error("Could not register with iSNS server: %s",
			  isns_strerror(status));
		rc = EIO;
		goto free_reg;
	}
	log_debug(4, "Registered objs");

	if (!poll_inval)
		goto free_reg;

	rc = isns_setup_registration_refresh(reg, poll_inval);
	if (rc)
		goto free_reg;

	list_for_each_entry(node, &isns_initiators, list) {
		isns_simple_free(reg);
		reg = isns_create_scn_registration2(clnt,
					   ISNS_SCN_OBJECT_UPDATED_MASK |
					   ISNS_SCN_OBJECT_ADDED_MASK |
					   ISNS_SCN_OBJECT_REMOVED_MASK |
					   ISNS_SCN_TARGET_AND_SELF_ONLY_MASK,
					   node->source);

		if (!reg) {
			isns_cancel_refresh_timers();
			rc = ENOMEM;
			goto done;
		}

		status = isns_simple_call(clnt->ic_socket, &reg);
		if (status != ISNS_SUCCESS) {
			log_error("SCN registration for node %s failed: %s\n",
				  isns_source_name(node->source),
				  isns_strerror(status));
			/*
			 * if the user was going to poll then ignore error
			 * since user was probably using polling because SCNs
			 * were not supported by server 
			 */
			if (poll_inval < 0) {
				isns_cancel_refresh_timers();
				rc = EIO;
				break;
			}
		}
		log_debug(4, "Registered %s for SCNs",
			  isns_source_name(node->source));
	}

free_reg:
	isns_simple_free(reg);
done:
	return rc;
}

static int isns_scn_register(isns_socket_t *svr_sock, int poll_inval)
{
	isns_object_list_t objs = ISNS_OBJECT_LIST_INIT;
	isns_portal_info_t portal_info;
	isns_client_t *clnt;
	int rc;

	clnt = isns_create_default_client(NULL);
	if (!clnt) {
		log_error("iSNS setup failed. Could not connect to server.");
		return ENOTCONN;
	}
	isns_socket_set_disconnect_fatal(clnt->ic_socket);

	log_debug(7, "isns_scn_register");

	if (!isns_socket_get_portal_info(svr_sock, &portal_info)) {
		log_error("Could not get portal info for iSNS registration.");
		rc = ENODEV;
		goto destroy_clnt;
	}

	rc = isns_build_objs(&portal_info, &objs);
	if (rc)
		goto destroy_clnt;

	rc = isns_register_objs(clnt, &objs, poll_inval);
	isns_object_list_destroy(&objs);
	if (!rc)
		log_warning("iSNS: Registered network entity with EID %s with "
			     "server.",  isns_entity_id);

destroy_clnt:
	isns_client_destroy(clnt);
	return rc;
}

static isns_source_t *isns_lookup_node(char *iname)
{
	struct isns_node_list *node;

	list_for_each_entry(node, &isns_initiators, list) {
		if (!strcmp(iname, isns_source_name(node->source)))
			return node->source;
	}
	return NULL;
}

static struct isns_node_list *isns_create_node(const char *iname)
{
	isns_source_t *source;
	struct isns_node_list *node;

	source = isns_source_create_iscsi(iname);
	if (!source)
		return NULL;

	node = calloc(1, sizeof(*node));
	if (!node) {
		isns_source_release(source);
		return NULL;
	}
	INIT_LIST_HEAD(&node->list);
	node->source = source;
	return node;
}

static int isns_create_node_list(const char *def_iname)
{
	struct iface_rec *iface, *tmp_iface;
	struct list_head ifaces;
	struct isns_node_list *node, *tmp_node;
	int rc = 0;

	INIT_LIST_HEAD(&ifaces);
	iface_link_ifaces(&ifaces);

	if (def_iname) {
		node = isns_create_node(def_iname);
		if (!node) {
			rc = ENOMEM;
			goto fail;
		}
		list_add_tail(&node->list, &isns_initiators);
	}

	list_for_each_entry(iface, &ifaces, list) {
		if (strlen(iface->iname) &&
		    !isns_lookup_node(iface->iname)) {
			node = isns_create_node(iface->iname);
			if (!node) {
				rc = ENOMEM;
				goto fail;
			}
			list_add_tail(&node->list, &isns_initiators);
		}
	}
	/* fix me */
	rc = 0;
	goto done;
fail:
	list_for_each_entry_safe(node, tmp_node, &isns_initiators, list) {
		list_del(&node->list);
		free(node);
	}

done:
	list_for_each_entry_safe(iface, tmp_iface, &ifaces, list) {
		list_del(&iface->list);
		free(iface);
	}
	return rc;
}

static void isns_scn_callback(isns_db_t *db, uint32_t bitmap,
			      isns_object_template_t *node_type,
			      const char *node_name, const char *dst_name)
{
	log_error("SCN for initiator: %s (Target: %s, Event: %s.)",
		    dst_name, node_name, isns_event_string(bitmap));
	isns_disc_new_portals(node_name, dst_name);
}

static void isns_clear_refresh_list(void)
{
	struct isns_refresh_data *refresh_data, *tmp_refresh;

	list_for_each_entry_safe(refresh_data, tmp_refresh, &isns_refresh_list,
				 list)
		isns_free_refresh_data(refresh_data);
}

static int isns_scn_recv(isns_server_t *svr, isns_socket_t *svr_sock,
			 int poll_inval)
{
	isns_message_t *msg, *rsp;
	struct timeval timeout = { 0, 0 };
	time_t now, then, next_timeout;
	unsigned int function;
	int rc = 0;

	log_debug(1, "isns_scn_recv");

	while (!stop_discoveryd) {
		/* reap disc/login procs */
		reap_proc();
		/*
		 * timer func could force a scn registration so check timers
		 * first
		 */
		then = isns_run_timers();
		now = time(NULL);
		next_timeout = now + 3600;
		if (then && then < next_timeout)
			next_timeout = then;

		if (isns_register_nodes) {
			isns_clear_refresh_list();
			/*
			 * it is ok to block here, because the server
			 * should have unregistered us or this is our
			 * first time registerting.
			 */
			rc = isns_scn_register(svr_sock, poll_inval);
			if (rc) {
				sleep(5);
				continue;
			}

			isns_disc_new_portals(NULL, NULL);
			if (!poll_inval)
				break;
			isns_register_nodes = 0;
			/*
			 * the scn reg may have added timers or changed
			 * timeout values so recheck.
			 */
			continue;
		}

		/* Determine how long we can sleep */
		if (next_timeout <= now)
			continue;
		timeout.tv_sec = next_timeout - now;

		if ((msg = isns_recv_message(&timeout)) == NULL)
			continue;

		function = isns_message_function(msg);
		if (function != ISNS_STATE_CHANGE_NOTIFICATION) {
			log_warning("Discarding unexpected %s message\n",
				    isns_function_name(function));
			isns_message_release(msg);
			continue;
		}

		if ((rsp = isns_process_message(svr, msg)) != NULL) {
			isns_socket_t *sock = isns_message_socket(msg);

			isns_socket_send(sock, rsp);
			isns_message_release(rsp);
		}

		isns_message_release(msg);
	}

	log_debug(1, "isns_scn_recv done");
	reap_proc();
	return rc;
}

#define ISNS_EVENTD_PIDFILE	ISNS_RUNDIR"/iscsid.isns.pid"
#define ISNS_EVENTD_CTL		ISNS_RUNDIR"/iscsid.isns.isnsctl"

static int isns_eventd(const char *def_iname, char *disc_addr, int port,
		       int poll_inval)
{
	static isns_socket_t *svr_sock;
	isns_server_t *svr;
	isns_db_t *db;
	struct isns_node_list *tmp_node, *node;
	int rc = 0;

	isns_create_node_list(def_iname);
	if (list_empty(&isns_initiators)) {
		log_error("iSNS registration failed. Initiatorname not set.");
		return EINVAL;
	}

	/* use def_iname or if not set the first iface's iname for the src */
	node = list_entry(isns_initiators.next, struct isns_node_list, list);
	isns_assign_string(&isns_config.ic_source_name,
			   isns_source_name(node->source));
	isns_config.ic_security = 0;
	isns_config.ic_pidfile = ISNS_EVENTD_PIDFILE;
	isns_config.ic_control_socket = ISNS_EVENTD_CTL;

	if (discovery_isns_set_servername(disc_addr, port)) {
		rc = ENOMEM;
		goto fail;
	}

	isns_write_pidfile(isns_config.ic_pidfile);

	db = isns_db_open(NULL);
	if (!db) {
		log_error("iSNS setup failed. Could not create db.");
		rc = ENOMEM;
		goto fail;
	}
	svr = isns_create_server(node->source, db, &isns_callback_service_ops);
	if (!svr) {
		log_error("iSNS setup failed. Could not create server.");
		rc = ENOTCONN;
		goto fail;
	}
	isns_server_set_scn_callback(svr, isns_scn_callback);

	svr_sock = isns_create_server_socket(NULL, NULL, AF_INET6, SOCK_DGRAM);
	if (!svr_sock) {
		log_error("iSNS setup failed. Could not create server socket.");
		rc = ENOTCONN;
		goto fail;
	}

	rc = isns_scn_recv(svr, svr_sock, poll_inval);
	isns_cancel_refresh_timers();
fail:
	isns_clear_refresh_list();

	list_for_each_entry_safe(node, tmp_node, &isns_initiators, list) {
		list_del(&node->list);
		free(node);
	}

	if (isns_entity_id)
		free(isns_entity_id);
	isns_entity_id = NULL;

	discovery_isns_free_servername();

	if (isns_config.ic_source_name)
		free(isns_config.ic_source_name);
	isns_config.ic_source_name = NULL;
	return rc;
}

static void start_isns(const char *def_iname, struct discovery_rec *drec,
		       int poll_inval)
{
	int rc, port = drec->port;

	if (port < 0)
		port = ISNS_DEFAULT_PORT;

	rc = isns_eventd(def_iname, drec->address, port, poll_inval);
	log_debug(1, "start isns done %d.", rc);
	discoveryd_stop();
}

/* SendTargets */
static void __do_st_disc_and_login(struct discovery_rec *drec)
{
	struct list_head rec_list, setup_ifaces;
	struct iface_rec *iface, *tmp_iface;
	int rc;

	INIT_LIST_HEAD(&rec_list);
	INIT_LIST_HEAD(&setup_ifaces);

	/*
	 * The disc daemon will try again in poll_interval secs
	 * so no need to retry here
	 */
	drec->u.sendtargets.reopen_max = 0;

	iface_link_ifaces(&setup_ifaces);
	/*
	 * disc code assumes this is not set and wants to use
	 * the userspace IO code.
	 */
	ipc = NULL;

	rc = idbm_bind_ifaces_to_nodes(discovery_sendtargets, drec,
					&setup_ifaces, &rec_list);
	if (rc) {
		log_error("Could not perform SendTargets to %s:%d.",
			   drec->address, drec->port);
		goto free_ifaces;
	}

	update_sessions(&rec_list, NULL, NULL);

free_ifaces:
	list_for_each_entry_safe(iface, tmp_iface, &setup_ifaces, list) {
		list_del(&iface->list);
		free(iface);
	}
}

static void do_st_disc_and_login(const char *def_iname,
				 struct discovery_rec *drec, int poll_inval)
{
	if (poll_inval < 0)
		poll_inval = DISC_DEF_POLL_INVL;

	do {
		__do_st_disc_and_login(drec);
		if (!poll_inval)
			break;
	} while (!stop_discoveryd && !sleep(poll_inval));

	discoveryd_stop();
}

static int st_start(void *data, struct discovery_rec *drec)
{
	log_debug(1, "st_start %s:%d %d", drec->address, drec->port,
		  drec->u.sendtargets.use_discoveryd);
	if (!drec->u.sendtargets.use_discoveryd)
		return ENOSYS;

	fork_disc(NULL, drec, drec->u.sendtargets.discoveryd_poll_inval,
		  do_st_disc_and_login);
	return 0;
}

static void discoveryd_st_start(void)
{
	idbm_for_each_st_drec(NULL, st_start);
}

static int isns_start(void *data, struct discovery_rec *drec)
{
	log_debug(1, "isns_start %s:%d %d", drec->address, drec->port,
		  drec->u.isns.use_discoveryd);
	if (!drec->u.isns.use_discoveryd)
		return ENOSYS;

	fork_disc(data, drec, drec->u.isns.discoveryd_poll_inval, start_isns);
	return 0;
}

static void discoveryd_isns_start(const char *def_iname)
{
	idbm_for_each_isns_drec((void *)def_iname, isns_start);
}

void discoveryd_start(const char *def_iname)
{
	discoveryd_isns_start(def_iname);
	discoveryd_st_start();
}
