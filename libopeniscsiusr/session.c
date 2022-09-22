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

int _iscsi_session_get(struct iscsi_context *ctx, uint32_t sid,
		      struct iscsi_session **se, bool verbose)
{
	int rc = LIBISCSI_OK;
	char *sysfs_se_dir_path = NULL;
	char *sysfs_con_dir_path = NULL;
	uint32_t host_id = 0;

	assert(ctx != NULL);
	assert(se != NULL);

	_debug(ctx, "Querying iSCSI session for sid %" PRIu32, sid);

	_good(_asprintf(&sysfs_se_dir_path, "%s/session%" PRIu32,
			_ISCSI_SYS_SESSION_DIR, sid), rc, out);
	_good(_asprintf(&sysfs_con_dir_path, "%s/connection%" PRIu32 ":0",
			_ISCSI_SYS_CONNECTION_DIR, sid), rc, out);
	/* ^ BUG(Gris Ge): ':0' here in kernel is referred as connection id.
	 *		   but the open-iscsi assuming it's always 0, need
	 *		   investigation.
	 */

	*se = (struct iscsi_session *) calloc(1, sizeof(struct iscsi_session));
	_alloc_null_check(ctx, *se , rc, out);

	if (! _file_exists(sysfs_se_dir_path)) {
		_info(ctx, "Sysfs path '%s' does not exist",
		      sysfs_se_dir_path);
		rc = LIBISCSI_ERR_SESS_NOT_FOUND;
	}
	if (! _file_exists(sysfs_con_dir_path)) {
		_info(ctx, "Sysfs path '%s' does not exist",
		      sysfs_se_dir_path);
		rc = LIBISCSI_ERR_SESS_NOT_FOUND;
	}
	if (rc == LIBISCSI_ERR_SESS_NOT_FOUND) {
		/* don't complain loudly if called through iscsi_sessions_get()
		 * the caller is not looking for a specific session,
		 * and the list could be changing as we work through it
		 */
		if (verbose) {
			_error(ctx, "Specified SID %" PRIu32 " does not exist",
			       sid);
		}
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
				  &((*se)->recovery_tmo), -1, true),
	      rc, out);

	_good(_sysfs_prop_get_i32(ctx, sysfs_se_dir_path, "lu_reset_tmo",
				  &((*se)->lu_reset_tmo), -1, true),
	      rc, out);

	_good(_sysfs_prop_get_i32(ctx, sysfs_se_dir_path, "tgt_reset_tmo",
				  &((*se)->tgt_reset_tmo), -1, true),
	      rc, out);

	_good(_sysfs_prop_get_i32(ctx, sysfs_se_dir_path, "abort_tmo",
				  &((*se)->abort_tmo), -1, true),
	      rc, out);

	_good(_sysfs_prop_get_i32(ctx, sysfs_se_dir_path, "tpgt",
				  &((*se)->tpgt), -1, true),
	      rc, out);

	_good(_sysfs_prop_get_str(ctx, sysfs_con_dir_path, "persistent_address",
				  (*se)->persistent_address,
				  sizeof((*se)->persistent_address) /
				  sizeof(char), ""),
	      rc, out);

	_good(_sysfs_prop_get_i32(ctx, sysfs_con_dir_path, "persistent_port",
				  &((*se)->persistent_port), -1, true),
	      rc, out);

	_sysfs_prop_get_str(ctx, sysfs_con_dir_path, "address", (*se)->address,
			    sizeof((*se)->address) / sizeof(char), "");

	_sysfs_prop_get_i32(ctx, sysfs_con_dir_path, "port",
			    &((*se)->port), -1, true);

	if ((strcmp((*se)->address, "") != 0) &&
	    (strcmp((*se)->persistent_address, "") == 0))
		_strncpy((*se)->persistent_address, (*se)->address,
			 sizeof((*se)->persistent_address) / sizeof(char));
	else if ((strcmp((*se)->address, "") == 0) &&
	    (strcmp((*se)->persistent_address, "") != 0))
		_strncpy((*se)->address, (*se)->persistent_address,
			 sizeof((*se)->address) / sizeof(char));

	if (((*se)->persistent_port == -1) &&
	    ((*se)->port != -1))
		(*se)->persistent_port = (*se)->port;
	else if (((*se)->persistent_port != -1) &&
		 ((*se)->port == -1))
		(*se)->port = (*se)->persistent_port;

	_good(_iscsi_host_id_of_session(ctx, sid, &host_id), rc, out);

	/* does this need to the correct iface_kern_id for the session? */
	_good(_iscsi_iface_get_from_sysfs(ctx, host_id, sid, NULL, &((*se)->iface)),
	      rc, out);

out:
	if (rc != LIBISCSI_OK) {
		iscsi_session_free(*se);
		*se = NULL;
	}
	free(sysfs_se_dir_path);
	free(sysfs_con_dir_path);
	return rc;
}

int iscsi_session_get(struct iscsi_context *ctx, uint32_t sid,
		      struct iscsi_session **se) {
	return _iscsi_session_get(ctx, sid, se, true);
}

int iscsi_sessions_get(struct iscsi_context *ctx,
		       struct iscsi_session ***sessions,
		       uint32_t *session_count)
{
	int rc = LIBISCSI_OK;
	uint32_t i = 0;
	uint32_t j = 0;
	uint32_t *sids = NULL;

	assert(ctx != NULL);
	assert(sessions != NULL);
	assert(session_count != NULL);

	*sessions = NULL;
	*session_count = 0;

	_good(_iscsi_sids_get(ctx, &sids, session_count), rc ,out);
	if (!*session_count)
		goto out;

	*sessions = calloc (*session_count, sizeof(struct iscsi_session *));
	_alloc_null_check(ctx, *sessions, rc, out);

	for (i = 0; i < *session_count; ++i) {
		_debug(ctx, "sid %" PRIu32, sids[i]);
		rc = _iscsi_session_get(ctx, sids[i], &((*sessions)[j]), false);
		if (rc == LIBISCSI_OK) {
			/* if session info was successfully read from sysfs, advance the sessions pointer */
			j++;
		} else {
			/* if not, just ignore the issue and keep trying with the next session ID,
			 * there's always going to be an inherent race against session removal when collecting
			 * attribute data from sysfs
			 */
			_debug(ctx, "Problem reading session %" PRIu32 ", skipping.", sids[i]);
			rc = LIBISCSI_OK;
		}
	}
	/*
	 * reset session count and sessions array length to what we were able to read from sysfs
	 *
	 * do not use reallocarray() for the sessions array, since not all platforms
	 * have that function call
	 */
	*session_count = j;
	/* assert that there is no integer overflow in the realloc call */
	assert(!(*session_count > (UINT_MAX / sizeof(struct iscsi_session *))));
	*sessions =
	    realloc(*sessions, *session_count * sizeof(struct iscsi_session *));

out:
	free(sids);
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
		iscsi_iface_free(se->iface);
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
