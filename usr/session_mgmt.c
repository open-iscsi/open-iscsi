/*
 * iSCSI session management helpers
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

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>

#include "idbm.h"
#include "list.h"
#include "iscsi_util.h"
#include "mgmt_ipc.h"
#include "session_info.h"
#include "iscsi_sysfs.h"
#include "log.h"
#include "iscsid_req.h"

static void log_login_msg(struct node_rec *rec, int rc)
{
	if (rc) {
		log_error("Could not login to [iface: %s, target: %s, "
			  "portal: %s,%d].", rec->iface.name,
			  rec->name, rec->conn[0].address,
			  rec->conn[0].port);
		iscsid_handle_error(rc);
	} else
		log_info("Login to [iface: %s, target: %s, portal: "
			 "%s,%d] successful.", rec->iface.name,
			 rec->name, rec->conn[0].address,
			 rec->conn[0].port);
}

struct iscsid_async_req {
	struct list_head list;
	void *data;
	int fd;
};

/**
 * iscsid_reqs_close - close open async requests
 * @list: list of async reqs
 *
 * This just closes the socket to the daemon.
 */
static void iscsid_reqs_close(struct list_head *list)
{
	struct iscsid_async_req *tmp, *curr;

	list_for_each_entry_safe(curr, tmp, list, list) {
		close(curr->fd);
		list_del(&curr->list);
		free(curr);
	}
}

static int iscsid_login_reqs_wait(struct list_head *list)
{
	struct iscsid_async_req *tmp, *curr;
	struct node_rec *rec;
	int ret = 0;

	list_for_each_entry_safe(curr, tmp, list, list) {
		int err;

		rec = curr->data;
		err = iscsid_req_wait(MGMT_IPC_SESSION_LOGIN, curr->fd);
		log_login_msg(rec, err);
		list_del(&curr->list);
		free(curr);
	}
	return ret;
}

/**
 * iscsi_login_portal - request iscsid to login to portal
 * @data: Unused. Only needed so this can be used in iscsi_login_portals
 * @list: If async, list to add session to
 * @rec: portal rec to log into
 */
int iscsi_login_portal(void *data, struct list_head *list, struct node_rec *rec)
{
	struct iscsid_async_req *async_req = NULL;
	int rc = 0, fd;

	log_info("Logging in to [iface: %s, target: %s, portal: %s,%d]",
		 rec->iface.name, rec->name, rec->conn[0].address,
		 rec->conn[0].port);

	if (list) {
		async_req = calloc(1, sizeof(*async_req));
		if (!async_req)
			log_info("Could not allocate memory for async login "
				 "handling. Using sequential login instead.");
		else
			INIT_LIST_HEAD(&async_req->list);
	}

	if (async_req)
		rc = iscsid_req_by_rec_async(MGMT_IPC_SESSION_LOGIN,
					     rec, &fd);
	else
		rc = iscsid_req_by_rec(MGMT_IPC_SESSION_LOGIN, rec);

	if (rc) {
		log_login_msg(rec, rc);
		if (async_req)
			free(async_req);
		/* we raced with another app or instance of iscsiadm */
		if (rc == MGMT_IPC_ERR_EXISTS)
			return 0;

		return ENOTCONN;
	}

	if (async_req) {
		list_add_tail(&async_req->list, list);
		async_req->fd = fd;
		async_req->data = rec;
	} else
		log_login_msg(rec, rc);

	return 0;
}

/**
 * iscsi_login_portal_nowait - request iscsid to login to portal
 * @rec: portal rec to log into
 *
 * This sends the login request, but does not wait for the result.
 */
int iscsi_login_portal_nowait(struct node_rec *rec)
{
	struct list_head list;
	int err;

	INIT_LIST_HEAD(&list);

	err = iscsi_login_portal(NULL, &list, rec);
	if (err > 0)
		return err;
	iscsid_reqs_close(&list);
	return 0;
}

/**
 * iscsi_login_portals - login into portals on @rec_list,
 * @data: data to pass to login_fn
 * @nr_found: returned with number of portals logged into
 * @wait: bool indicating if the fn should wait for the result
 * @rec_list: list of portals to log into
 * @login_fn: list iter function
 *
 * This will loop over the list of portals and login. It
 * will attempt to login asynchronously, and then wait for
 * them to complete if wait is set.
 */
int iscsi_login_portals(void *data, int *nr_found, int wait,
			struct list_head *rec_list,
			int (* login_fn)(void *, struct list_head *,
					 struct node_rec *))
{
	struct node_rec *curr_rec, *tmp;
	struct list_head login_list;
	int ret = 0, err;

	*nr_found = 0;
	INIT_LIST_HEAD(&login_list);

	list_for_each_entry(curr_rec, rec_list, list) {
		err = login_fn(data, &login_list, curr_rec);
		if (err > 0 && !ret)
			ret = err;
		if (!err)
			(*nr_found)++;
	}

	if (wait) {
		err = iscsid_login_reqs_wait(&login_list);
		if (err && !ret)
			ret = err;
	} else
		iscsid_reqs_close(&login_list);

	list_for_each_entry_safe(curr_rec, tmp, rec_list, list) {
		list_del(&curr_rec->list);
		free(curr_rec);
	}
	return ret;
}

static void log_logout_msg(struct session_info *info, int rc)
{
	if (rc) {
		log_error("Could not logout of [sid: %d, target: %s, "
			  "portal: %s,%d].", info->sid,
			  info->targetname,
			  info->persistent_address, info->port);
		iscsid_handle_error(rc);
	} else
		log_info("Logout of [sid: %d, target: %s, "
			 "portal: %s,%d] successful.",
			 info->sid, info->targetname,
			 info->persistent_address, info->port);
}

static int iscsid_logout_reqs_wait(struct list_head *list)
{
	struct iscsid_async_req *tmp, *curr;
	struct session_info *info;
	int ret = 0;

	list_for_each_entry_safe(curr, tmp, list, list) {
		int err;

		info  = curr->data;
		err = iscsid_req_wait(MGMT_IPC_SESSION_LOGOUT, curr->fd);
		log_logout_msg(info, err);
		if (err)
			ret = err;
		list_del(&curr->list);
		free(curr);
	}
	return ret;
}

/**
 * iscsi_logout_portal - logou tof portal
 * @info: session to log out of
 * @list: if async, this is the list to add the logout req to
 */
int iscsi_logout_portal(struct session_info *info, struct list_head *list)
{
	struct iscsid_async_req *async_req = NULL;
	int fd, rc;

	/* TODO: add fn to add session prefix info like dev_printk */
	log_info("Logging out of session [sid: %d, target: %s, portal: "
		 "%s,%d]",
		 info->sid, info->targetname, info->persistent_address,
		 info->port);

	if (list) {
		async_req = calloc(1, sizeof(*async_req));
		if (!async_req)
			log_info("Could not allocate memory for async logout "
				 "handling. Using sequential logout instead.");
	}

	if (!async_req)
		rc = iscsid_req_by_sid(MGMT_IPC_SESSION_LOGOUT, info->sid);
	else {
		INIT_LIST_HEAD(&async_req->list);
		rc = iscsid_req_by_sid_async(MGMT_IPC_SESSION_LOGOUT,
					     info->sid, &fd);
	}

	/* we raced with another app or instance of iscsiadm */
	if (rc) {
		log_logout_msg(info, rc);
		if (async_req)
			free(async_req);

		if (rc == MGMT_IPC_ERR_NOT_FOUND)
			return 0;

		return EIO;
	}

	if (async_req) {
		list_add_tail(&async_req->list, list);
		async_req->fd = fd;
		async_req->data = info;
	} else
		log_logout_msg(info, rc);

	return 0;
}

/**
 * iscsi_logout_portals - logout portals
 * @data: data to pass to iter logout_fn
 * @nr_found: number of sessions logged out
 * @wait: bool indicating if the fn should wait for the result
 * @logout_fn: logout iter function
 *
 * This will loop over the list of sessions and run the logout fn
 * on them. It will attempt to logout asynchronously, and then wait for
 * them to complete if wait is set.
 */
int iscsi_logout_portals(void *data, int *nr_found, int wait,
			 int (*logout_fn)(void *, struct list_head *,
					  struct session_info *))
{
	struct session_info *curr_info;
	struct session_link_info link_info;
	struct list_head session_list, logout_list;
	int ret = 0, err;

	INIT_LIST_HEAD(&session_list);
	INIT_LIST_HEAD(&logout_list);

	memset(&link_info, 0, sizeof(link_info));
	link_info.list = &session_list;
	link_info.data = NULL;
	link_info.match_fn = NULL;
	*nr_found = 0;

	err = iscsi_sysfs_for_each_session(&link_info, nr_found,
					   session_info_create_list);
	if (err || !*nr_found)
		return err;

	*nr_found = 0;
	list_for_each_entry(curr_info, &session_list, list) {
		err = logout_fn(data, &logout_list, curr_info);
		if (err > 0 && !ret)
			ret = err;
		if (!err)
			(*nr_found)++;
	}

	if (wait) {
		err = iscsid_logout_reqs_wait(&logout_list);
		if (err)
			ret = err;
	} else
		iscsid_reqs_close(&logout_list);

	session_info_free_list(&session_list);
	return ret;
}

/* TODO merge with initiator.c implementation */
/* And add locking */
int iscsi_check_for_running_session(struct node_rec *rec)
{
	int nr_found = 0;
	if (iscsi_sysfs_for_each_session(rec, &nr_found, iscsi_match_session))
		return 1;
	return 0;
}
