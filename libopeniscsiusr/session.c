/*
 * Copyright (C) 2017 Red Hat, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Author: Gris Ge <fge@redhat.com>
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE			/* For NI_MAXHOST */
#endif

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <dirent.h>
#include <limits.h>
#include <stdint.h>
#include <inttypes.h>
#include <netdb.h>
#include <string.h>
#include <errno.h>

#include "libopeniscsiusr/libopeniscsiusr.h"
#include "misc.h"
#include "sysfs.h"
#include "iface.h"

#define _ISCSI_NAME_MAX_LEN		223
/* ^ RFC 3720:
 *	Each iSCSI node, whether an initiator or target, MUST have an iSCSI
 *	name.
 *
 *	Initiators and targets MUST support the receipt of iSCSI names of up
 *	to the maximum length of 223 bytes.
 */

#define _ISCSI_CHAP_AUTH_STR_MAX_LEN	256
/* ^ No official document found for this value, just copy from usr/auth.h
 */

struct iscsi_session {
	uint32_t sid;
	/* ^ It's actually a int according to Linux kernel code but
	 * the dev_set_name() in iscsi_add_session() of scsi_transport_iscsi.c
	 * are using %u to output this.
	 */
	char persistent_address[NI_MAXHOST + 1];
	int32_t persistent_port;
	char target_name[_ISCSI_NAME_MAX_LEN + 1];
	char username[_ISCSI_CHAP_AUTH_STR_MAX_LEN];
	char password[_ISCSI_CHAP_AUTH_STR_MAX_LEN];
	char username_in[_ISCSI_CHAP_AUTH_STR_MAX_LEN];
	char password_in[_ISCSI_CHAP_AUTH_STR_MAX_LEN];
	int32_t recovery_tmo;
	/* ^ It's actually a int according to Linux kernel code.
	 */
	int32_t lu_reset_tmo;
	/* ^ It's actually a int according to Linux kernel code.
	 */
	int32_t tgt_reset_tmo;
	/* ^ It's actually a int according to Linux kernel code.
	 */
	int32_t abort_tmo;
	/* ^ It's actually a int according to Linux kernel code.
	 */
	int32_t tpgt;
	/* ^ It's actually a int according to Linux kernel code.
	 */
	char address[NI_MAXHOST + 1];

	int32_t port;
	struct iscsi_iface *iface;
};

static uint32_t session_str_to_sid(const char *session_str);

_iscsi_getter_func_gen(iscsi_session, sid, uint32_t);
_iscsi_getter_func_gen(iscsi_session, persistent_address, const char *);
_iscsi_getter_func_gen(iscsi_session, persistent_port, int32_t);
_iscsi_getter_func_gen(iscsi_session, target_name, const char *);
_iscsi_getter_func_gen(iscsi_session, username, const char *);
_iscsi_getter_func_gen(iscsi_session, password, const char *);
_iscsi_getter_func_gen(iscsi_session, username_in, const char *);
_iscsi_getter_func_gen(iscsi_session, password_in, const char *);
_iscsi_getter_func_gen(iscsi_session, recovery_tmo, int32_t);
_iscsi_getter_func_gen(iscsi_session, lu_reset_tmo, int32_t);
_iscsi_getter_func_gen(iscsi_session, tgt_reset_tmo, int32_t);
_iscsi_getter_func_gen(iscsi_session, abort_tmo, int32_t);
_iscsi_getter_func_gen(iscsi_session, tpgt, int32_t);
_iscsi_getter_func_gen(iscsi_session, address, const char *);
_iscsi_getter_func_gen(iscsi_session, port, int32_t);
_iscsi_getter_func_gen(iscsi_session, iface, struct iscsi_iface *);

/*
 * The session string is "session%u" used by /sys/class/iscsi_session/session%u.
 * Return 0 if error parsing session string.
 */
static uint32_t session_str_to_sid(const char *session_str)
{
	uint32_t sid = 0;

	if (sscanf(session_str, "session%" SCNu32, &sid) != 1)
		return 0; /* error */
	return sid;
}

int iscsi_session_get(struct iscsi_context *ctx, uint32_t sid,
		      struct iscsi_session **se)
{
	int rc = LIBISCSI_OK;
	char sysfs_se_dir_path[PATH_MAX];
	char sysfs_con_dir_path[PATH_MAX];
	uint32_t host_id = 0;

	assert(ctx != NULL);
	assert(se != NULL);

	_debug(ctx, "Querying iSCSI session for sid %" PRIu32, sid);

	snprintf(sysfs_se_dir_path, PATH_MAX, "%s/session%" PRIu32,
		 _ISCSI_SYS_SESSION_DIR, sid);
	snprintf(sysfs_con_dir_path, PATH_MAX, "%s/connection%" PRIu32 ":0",
		 _ISCSI_SYS_CONNECTION_DIR, sid);
	/* ^ BUG(Gris Ge): ':0' here in kernel is referred as connection id.
	 *		   but the open-iscsi assuming it's always 0, need
	 *		   investigation.
	 */

	*se = (struct iscsi_session *)
		calloc(sizeof(struct iscsi_session), 1);
	_alloc_null_check(ctx, *se , rc, out);

	if (! _file_exists(sysfs_se_dir_path)) {
		_info(ctx, "Sysfs path '%s' does not exists",
		      sysfs_se_dir_path);
		rc = LIBISCSI_ERR_SESS_NOT_FOUND;
	}
	if (! _file_exists(sysfs_con_dir_path)) {
		_info(ctx, "Sysfs path '%s' does not exists",
		      sysfs_se_dir_path);
		rc = LIBISCSI_ERR_SESS_NOT_FOUND;
	}
	if (rc == LIBISCSI_ERR_SESS_NOT_FOUND) {
		_error(ctx, "Specified SID %" PRIu32, "does not exists",
		       sid);
		goto out;
	}

	(*se)->sid = sid;
	_good(_sysfs_prop_get_str(ctx, sysfs_se_dir_path, "targetname",
				 (*se)->target_name,
				 sizeof((*se)->target_name) / sizeof(char),
				 NULL), rc, out);

	_good(_sysfs_prop_get_str(ctx, sysfs_se_dir_path, "username",
				  (*se)->username,
				  sizeof((*se)->username) / sizeof(char),
				  ""),
	      rc, out);

	_good(_sysfs_prop_get_str(ctx, sysfs_se_dir_path, "password",
				  (*se)->password,
				  sizeof((*se)->password) / sizeof(char),
				  ""),
	      rc, out);

	_good(_sysfs_prop_get_str(ctx, sysfs_se_dir_path, "username_in",
				  (*se)->username_in,
				  sizeof((*se)->username_in) / sizeof(char),
				  ""),
	      rc, out);

	_good(_sysfs_prop_get_str(ctx, sysfs_se_dir_path, "password_in",
				  (*se)->password_in,
				  sizeof((*se)->password_in) / sizeof(char),
				  ""),
	      rc, out);

	_good(_sysfs_prop_get_i32(ctx, sysfs_se_dir_path, "recovery_tmo",
				  &((*se)->recovery_tmo),
				  -1),
	      rc, out);

	_good(_sysfs_prop_get_i32(ctx, sysfs_se_dir_path, "lu_reset_tmo",
				  &((*se)->lu_reset_tmo), -1),
	      rc, out);

	_good(_sysfs_prop_get_i32(ctx, sysfs_se_dir_path,
				  "tgt_reset_tmo", &((*se)->tgt_reset_tmo), -1),
	      rc, out);

	_good(_sysfs_prop_get_i32(ctx, sysfs_se_dir_path, "abort_tmo",
				  &((*se)->abort_tmo), -1),
	      rc, out);

	_good(_sysfs_prop_get_i32(ctx, sysfs_se_dir_path, "tpgt",
				  &((*se)->tpgt),
				  INT32_MAX /* raise error if not found */),
	      rc, out);

	_good(_sysfs_prop_get_str(ctx, sysfs_con_dir_path, "persistent_address",
				  (*se)->persistent_address,
				  sizeof((*se)->persistent_address) /
				  sizeof(char), ""),
	      rc, out);

	_good(_sysfs_prop_get_i32(ctx, sysfs_con_dir_path, "persistent_port",
				  &((*se)->persistent_port), -1),
	      rc, out);

	_good(_sysfs_prop_get_str(ctx, sysfs_con_dir_path, "address",
				  (*se)->address,
				  sizeof((*se)->address) / sizeof(char),
				  ""),
	      rc, out);

	_good(_sysfs_prop_get_i32(ctx, sysfs_con_dir_path, "port",
				  &((*se)->port), -1), rc, out);

	if ((strcmp((*se)->address, "") == 0) &&
	    (strcmp((*se)->persistent_address, "") != 0))
		strncpy((*se)->persistent_address, (*se)->address,
			sizeof((*se)->persistent_address) / sizeof(char));

	if ((strcmp((*se)->address, "") != 0) &&
	    (strcmp((*se)->persistent_address, "") == 0))
		strncpy((*se)->address, (*se)->persistent_address,
			sizeof((*se)->address) / sizeof(char));

	if (((*se)->persistent_port != -1) &&
	    ((*se)->port == -1))
		(*se)->persistent_port = (*se)->port;

	if (((*se)->persistent_port != -1) &&
	    ((*se)->port == -1))
		(*se)->port = (*se)->persistent_port;

	_good(_iscsi_host_id_of_session(ctx, sid, &host_id), rc, out);

	_good(_iscsi_iface_get(ctx, host_id, sid, NULL /*iface kernel id */,
			       &((*se)->iface)),
	      rc, out);

out:
	if (rc != LIBISCSI_OK) {
		iscsi_session_free(*se);
		*se = NULL;
	}
	return rc;
}

int iscsi_sessions_get(struct iscsi_context *ctx,
		       struct iscsi_session ***sessions,
		       uint32_t *session_count)
{
	struct dirent **namelist = NULL;
	int n = 0;
	int rc = LIBISCSI_OK;
	int errno_save = 0;
	uint32_t i = 0;
	uint32_t sid = 0;
	int j = 0;

	assert(ctx != NULL);
	assert(sessions != NULL);
	assert(session_count != NULL);

	*sessions = NULL;
	*session_count = 0;

	n = scandir(_ISCSI_SYS_SESSION_DIR, &namelist, _scan_filter_skip_dot,
		    alphasort);
	if (n < 0) {
		errno_save = errno;
		if (errno_save == ENOENT)
			goto out;
		if (errno_save == ENOMEM) {
			rc = LIBISCSI_ERR_NOMEM;
			goto out;
		}
		if (errno_save == ENOTDIR) {
			rc = LIBISCSI_ERR_BUG;
			_error(ctx, "Got ENOTDIR error when scandir %s",
			       _ISCSI_SYS_SESSION_DIR);
			goto out;
		}
		rc = LIBISCSI_ERR_BUG;
		_error(ctx, "Got unexpected error %d when scandir %s",
		       errno_save, _ISCSI_SYS_SESSION_DIR);
		goto out;
	}
	_info(ctx, "Got %d iSCSI sessions", n);
	*sessions = (struct iscsi_session **)
		calloc (sizeof(struct iscsi_session *), n);
	_alloc_null_check(ctx, *sessions, rc, out);

	*session_count = n & UINT32_MAX;

	for (i = 0; i < *session_count; ++i) {
		sid = session_str_to_sid(namelist[i]->d_name);
		if (sid == 0) {
			_error(ctx, "Got illegal iscsi session string %s",
			       namelist[i]->d_name);
			rc = LIBISCSI_ERR_BUG;
			goto out;
		}
		_good(iscsi_session_get(ctx, sid, &((*sessions)[i])), rc, out);
	}

out:
	for (j = n - 1; j >= 0; --j)
		free(namelist[j]);
	free(namelist);
	if (rc != LIBISCSI_OK) {
		iscsi_sessions_free(*sessions, *session_count);
		*sessions = NULL;
		*session_count = 0;
	}
	return rc;
}

void iscsi_session_free(struct iscsi_session *se)
{
	if (se != NULL)
		_iscsi_iface_free(se->iface);
	free(se);
}

void iscsi_sessions_free(struct iscsi_session **ses, uint32_t se_count)
{
	uint32_t i = 0;

	if ((ses == NULL) || (se_count == 0))
		return;

	for (i = 0; i < se_count; ++i)
		iscsi_session_free(ses[i]);
	free (ses);
}
