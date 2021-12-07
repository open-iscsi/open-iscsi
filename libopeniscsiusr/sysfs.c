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
#define _GNU_SOURCE
#endif

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <assert.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include <regex.h>
#include <dirent.h>
#include <errno.h>

#include "libopeniscsiusr/libopeniscsiusr_common.h"
#include "sysfs.h"
#include "misc.h"

#define _INT32_STR_MAX_LEN		12
/* ^ The max uint32_t is 4294967296 which requires 11 bytes for string.
 *   The max/min in32_t is 2147483647 or -2147483646 which requires 12 bytes.
 */

#define _SYS_NULL_STR			"(null)"

#define _sysfs_prop_get_uint_func_gen(func_name, out_type, type_max_value) \
	int func_name(struct iscsi_context *ctx, const char *dir_path, \
		      const char *prop_name, out_type *val, \
		      out_type default_value, bool ignore_error) \
	{ \
		long long int tmp_val = 0; \
		int rc = LIBISCSI_OK; \
		long long int dv = default_value; \
		rc = iscsi_sysfs_prop_get_ll(ctx, dir_path, prop_name, \
					     &tmp_val, (long long int) dv, \
					     ignore_error); \
		if (rc == LIBISCSI_OK) \
			*val = tmp_val & type_max_value; \
		return rc; \
	}

#define _sysfs_prop_get_int_func_gen(func_name, out_type, type_min_value, type_max_value) \
	int func_name(struct iscsi_context *ctx, const char *dir_path, \
		      const char *prop_name, out_type *val, \
		      out_type default_value, bool ignore_error) \
	{ \
		long long int tmp_val = 0; \
		int rc = LIBISCSI_OK; \
		long long int dv = default_value; \
		rc = iscsi_sysfs_prop_get_ll(ctx, dir_path, prop_name, \
					     &tmp_val, (long long int) dv, \
					     ignore_error); \
		if (rc == LIBISCSI_OK) { \
			if (tmp_val > type_max_value) \
				*val = type_max_value; \
			else if (tmp_val < type_min_value) \
				*val = type_min_value; \
			else \
				*val = tmp_val; \
		} \
		return rc; \
	}


enum _sysfs_dev_class {
	_SYSFS_DEV_CLASS_ISCSI_SESSION,
	_SYSFS_DEV_CLASS_ISCSI_HOST,
};

static int sysfs_read_file(const char *path, uint8_t *buff, size_t buff_size);
static int iscsi_sysfs_prop_get_ll(struct iscsi_context *ctx,
				   const char *dir_path, const char *prop_name,
				   long long int *val,
				   long long int default_value,
				   bool ignore_error);

/*
 * dev_path needs to be freed by the caller on success
 */
static int sysfs_get_dev_path(struct iscsi_context *ctx, const char *path,
			      enum _sysfs_dev_class class, char **dev_path);

_sysfs_prop_get_uint_func_gen(_sysfs_prop_get_u8, uint8_t, UINT8_MAX);
_sysfs_prop_get_uint_func_gen(_sysfs_prop_get_u16, uint16_t, UINT16_MAX);
_sysfs_prop_get_int_func_gen(_sysfs_prop_get_i32, int32_t, INT32_MIN, INT32_MAX);
_sysfs_prop_get_uint_func_gen(_sysfs_prop_get_u32, uint32_t, UINT32_MAX);

static int sysfs_read_file(const char *path, uint8_t *buff, size_t buff_size)
{
	int fd = -1;
	int errno_save = 0;
	ssize_t readed = 0;
	ssize_t i = 0;

	assert(path != NULL);
	assert(buff != NULL);
	assert(buff_size != 0);

	memset(buff, 0, buff_size);

	fd = open(path, O_RDONLY);
	if (fd < 0)
		return errno;
	readed = read(fd, buff, buff_size);
	errno_save = errno;
	close(fd);

	if (readed < 0) {
		buff[0] = '\0';
		return errno_save;
	}

	buff[buff_size - 1] = '\0';
	/* Remove the trailing \n */
	for (i = readed - 1; i >= 0; --i) {
		if (buff[i] == '\n') {
			buff[i] = '\0';
			break;
		}
	}

	if (strcmp((char *) buff, _SYS_NULL_STR) == 0)
		buff[0] = '\0';

	return 0;
}

int _sysfs_prop_get_str(struct iscsi_context *ctx, const char *dir_path,
			const char *prop_name, char *buff, size_t buff_size,
			const char *default_value)
{
	char *file_path = NULL;
	int rc = LIBISCSI_OK;
	int errno_save = 0;

	assert(dir_path != NULL);
	assert(prop_name != NULL);
	assert(buff != NULL);

	_good(_asprintf(&file_path, "%s/%s", dir_path, prop_name), rc, out);

	errno_save = sysfs_read_file(file_path, (uint8_t *) buff, buff_size);
	if (errno_save != 0) {
		if (errno_save == ENOENT) {
			if (default_value == NULL) {
				rc = LIBISCSI_ERR_SYSFS_LOOKUP;
				_error(ctx, "Failed to read '%s': "
				       "file '%s' does not exist", prop_name,
				       file_path);
			} else {
				_info(ctx, "Failed to read '%s': "
				      "file '%s' does not exist, "
				      "using default value %s", prop_name,
				      file_path, default_value);
				memcpy(buff, (void *) default_value,
				       strlen(default_value) + 1);
			}
		} else if (errno_save == EACCES) {
			rc = LIBISCSI_ERR_ACCESS;
			_error(ctx, "Failed to read '%s': "
			       "permission deny when reading '%s'", prop_name,
			       file_path);
		} else if (errno_save == ENOTCONN) {
			if (default_value == NULL) {
				rc = LIBISCSI_ERR_SYSFS_LOOKUP;
				_error(ctx, "Failed to read '%s': "
				       "error when reading '%s': "
				       "Target unavailable",
				       prop_name, file_path);
			} else {
				_info(ctx, "Failed to read '%s': "
				       "error when reading '%s': "
				       "Target unavailable, using default value '%s'",
				       prop_name, file_path, default_value);
				memcpy(buff, (void *) default_value,
				       strlen(default_value) + 1);
			}
		} else {
			rc = LIBISCSI_ERR_BUG;
			_error(ctx, "Failed to read '%s': "
			       "error when reading '%s': %d", prop_name,
			       file_path, errno_save);
		}
	} else {
		if ((buff[0] == '\0') && (default_value != NULL)) {
			memcpy(buff, (void *) default_value,
			       strlen(default_value) + 1);
			_debug(ctx, "Open '%s', got NULL, using default value",
			       file_path, default_value);
		} else
			_debug(ctx, "Open '%s', got '%s'", file_path, buff);
	}
out:
	free(file_path);
	return rc;
}

static int iscsi_sysfs_prop_get_ll(struct iscsi_context *ctx,
				 const char *dir_path, const char *prop_name,
				 long long int *val,
				 long long int default_value, bool ignore_error)
{
	char *file_path = NULL;
	int rc = LIBISCSI_OK;
	int errno_save = 0;
	uint8_t buff[_INT32_STR_MAX_LEN];
	long long int tmp_val = 0;

	assert(dir_path != NULL);
	assert(prop_name != NULL);
	assert(val != NULL);

	*val = 0;

	_good(_asprintf(&file_path, "%s/%s", dir_path, prop_name), rc, out);

	errno_save = sysfs_read_file(file_path, buff, _INT32_STR_MAX_LEN);
	if (errno_save != 0) {
		if (errno_save == ENOENT || errno_save == EINVAL) {
			if (! ignore_error) {
				rc = LIBISCSI_ERR_SYSFS_LOOKUP;
				_error(ctx, "Failed to read '%s': "
				       "file '%s' does not exist",
				       prop_name, file_path);
				goto out;
			} else {
				_info(ctx,
				       "Failed to read '%s': "
				      "File '%s' does not exist, using ",
				      "default value %lld",
				      prop_name, file_path, default_value);
				*val = default_value;
				goto out;
			}
		} else if (errno_save == EACCES) {
			rc = LIBISCSI_ERR_ACCESS;
			_error(ctx, "Permission deny when reading '%s'",
			       file_path);
			goto out;
		} else if (errno_save == ENOTCONN) {
			if (!ignore_error) {
				rc = LIBISCSI_ERR_SYSFS_LOOKUP;
				_error(ctx, "Failed to read '%s': "
					"error when reading '%s': "
					"Target unavailable",
					prop_name, file_path);
				goto out;
			} else {
				_info(ctx, "Failed to read '%s': "
					"error when reading '%s': "
					"Target unavailable, using default value %lld",
					prop_name, file_path, default_value);
				*val = default_value;
				goto out;
			}
		} else {
			rc = LIBISCSI_ERR_BUG;
			_error(ctx, "Error when reading '%s': %d", file_path,
			       errno_save);
			goto out;
		}
	}

	errno = 0;
	tmp_val = strtoll((const char *) buff, NULL, 10 /* base */);
	errno_save = errno;
	if ((errno_save != 0) && (! ignore_error)) {
		rc = LIBISCSI_ERR_BUG;
		_error(ctx, "Sysfs: %s: Error when converting '%s' "
		       "to number", file_path,  (char *) buff, errno_save);
		goto out;
	}

	*val = tmp_val;

	_debug(ctx, "Open '%s', got %lld", file_path, tmp_val);
out:
	free(file_path);
	return rc;
}

static int sysfs_get_dev_path(struct iscsi_context *ctx, const char *path,
			      enum _sysfs_dev_class class, char **dev_path)
{
	int rc = LIBISCSI_OK;
	int errno_save = 0;
	regex_t regex;
	regmatch_t reg_match[2];
	int reg_rc = 0;
	int need_free_reg = 0;

	assert(ctx != NULL);
	assert(path != NULL);
	assert(dev_path != NULL);

	*dev_path = realpath(path, NULL);
	if (*dev_path == NULL) {
		errno_save = errno;
		rc = LIBISCSI_ERR_SYSFS_LOOKUP;
		_error(ctx, "realpath() failed on %s with error %d", path,
		       errno_save);
		goto out;
	}

	switch (class) {
	case _SYSFS_DEV_CLASS_ISCSI_SESSION:
		reg_rc = regcomp(&regex,
				 "\\(.\\{1,\\}/devices/.\\{1,\\}/"
				 "host[0-9]\\{1,\\}\\)/"
				 "session[0-9]\\{1,\\}/iscsi_session/",
				 0 /* no flag */);
		break;
	case _SYSFS_DEV_CLASS_ISCSI_HOST:
		reg_rc = regcomp(&regex,
				 "\\(.\\{1,\\}/devices/.\\{1,\\}/"
				 "host[0-9]\\{1,\\}\\)/"
				 "iscsi_host/",
				 0 /* no flag */);
		break;
	default:
		rc = LIBISCSI_ERR_BUG;
		_error(ctx, "BUG: sysfs_get_dev_path(): got unknown class %d",
		       class);
		goto out;
	}
	if (reg_rc != 0) {
		rc = LIBISCSI_ERR_SYSFS_LOOKUP;
		_error(ctx, "regcomp() failed %d", reg_rc);
		goto out;
	}
	need_free_reg = 1;
	if (regexec(&regex, *dev_path, 2 /* count of max matches */,
		    reg_match, 0 /* no flags */) != 0) {
		rc = LIBISCSI_ERR_SYSFS_LOOKUP;
		_error(ctx, "regexec() not match for %s", *dev_path);
		goto out;
	}

	*(*dev_path + reg_match[1].rm_eo ) = '\0';

	_debug(ctx, "Got dev path of '%s': '%s'", path, *dev_path);

out:
	if (need_free_reg)
		regfree(&regex);
	if (rc != LIBISCSI_OK) {
		free(*dev_path);
		*dev_path = NULL;
	}
	return rc;
}

int _iscsi_host_id_of_session(struct iscsi_context *ctx, uint32_t sid,
			      uint32_t *host_id)
{
	int rc = LIBISCSI_OK;
	char *sys_se_dir_path = NULL;
	char *sys_dev_path = NULL;
	char *sys_scsi_host_dir_path = NULL;
	struct dirent **namelist = NULL;
	int n = 0;
	const char *host_id_str = NULL;
	const char iscsi_host_dir_str[] = "/iscsi_host/";

	assert(ctx != NULL);
	assert(sid != 0);
	assert(host_id != NULL);

	_good(_asprintf(&sys_se_dir_path, "%s/session%" PRIu32,
			_ISCSI_SYS_SESSION_DIR, sid), rc, out);

	*host_id = 0;

	_good(sysfs_get_dev_path(ctx, sys_se_dir_path,
				 _SYSFS_DEV_CLASS_ISCSI_SESSION, &sys_dev_path),
	      rc, out);

	_good(_asprintf(&sys_scsi_host_dir_path, "%s%s",
			sys_dev_path, iscsi_host_dir_str), rc, out);

	_good(_scandir(ctx, sys_scsi_host_dir_path, &namelist, &n), rc, out);

	if (n != 1) {
		rc = LIBISCSI_ERR_SYSFS_LOOKUP;
		_error(ctx, "Got unexpected(should be 1) file in folder %s",
		       sys_scsi_host_dir_path);
		goto out;
	}
	host_id_str = namelist[0]->d_name;

	if (sscanf(host_id_str, "host%" SCNu32, host_id) != 1) {
		rc = LIBISCSI_ERR_SYSFS_LOOKUP;
		_error(ctx, "sscanf() failed on string %s", host_id_str);
		goto out;
	}

out:
	_scandir_free(namelist, n);
	free(sys_se_dir_path);
	free(sys_dev_path);
	free(sys_scsi_host_dir_path);
	return rc;
}

static int _iscsi_ids_get(struct iscsi_context *ctx,
			  uint32_t **ids, uint32_t *id_count,
			  const char *dir_path, const char *file_prefix)
{
	int rc = LIBISCSI_OK;
	struct dirent **namelist = NULL;
	int n = 0;
	uint32_t i = 0;
	const char *id_str = NULL;
	char fmt_buff[128];

	assert(ctx != NULL);
	assert(ids != 0);
	assert(id_count != NULL);

	*ids = NULL;
	*id_count = 0;

	_good(_scandir(ctx, dir_path, &namelist, &n), rc, out);
	_debug(ctx, "Got %d iSCSI %s", n, file_prefix);

	*id_count = n & UINT32_MAX;

	*ids = calloc(*id_count, sizeof(uint32_t));
	_alloc_null_check(ctx, *ids, rc, out);

	snprintf(fmt_buff, sizeof(fmt_buff)/sizeof(char), "%s%%" SCNu32,
		 file_prefix);

	for (i = 0; i < *id_count; ++i) {
		id_str = namelist[i]->d_name;
		if (sscanf(id_str, fmt_buff, &((*ids)[i])) != 1) {
			rc = LIBISCSI_ERR_SYSFS_LOOKUP;
			_error(ctx, "sscanf() failed on string %s",
			       id_str);
			goto out;
		}
		_debug(ctx, "Got iSCSI %s id %" PRIu32, file_prefix, (*ids)[i]);
	}

out:
	_scandir_free(namelist, n);
	if (rc != LIBISCSI_OK) {
		free(*ids);
		*ids = NULL;
		*id_count = 0;
	}
	return rc;
}

int _iscsi_sids_get(struct iscsi_context *ctx, uint32_t **sids,
		    uint32_t *sid_count)
{
	return _iscsi_ids_get(ctx, sids, sid_count, _ISCSI_SYS_SESSION_DIR,
			      "session");
}

int _iscsi_hids_get(struct iscsi_context *ctx, uint32_t **hids,
		    uint32_t *hid_count)
{
	return _iscsi_ids_get(ctx, hids, hid_count, _ISCSI_SYS_HOST_DIR,
			      "host");
}

bool _iscsi_transport_is_loaded(const char *transport_name)
{
	int rc = LIBISCSI_OK;
	char *path = NULL;

	if (transport_name == NULL)
		return false;

	_good(_asprintf(&path, "%s/%s", _ISCSI_SYS_TRANSPORT_DIR,
			transport_name), rc, out);

	if (access(path, F_OK) == 0) {
		free(path);
		return true;
	}
out:
	free(path);
	return false;
}

int _iscsi_iface_kern_ids_of_host_id(struct iscsi_context *ctx,
				    uint32_t host_id,
				    char ***iface_kern_ids,
				    uint32_t *iface_count)
{
	char *sysfs_sh_path = NULL;
	char *dev_path = NULL;
	char *sysfs_iface_path = NULL;
	int rc = LIBISCSI_OK;
	struct dirent **namelist = NULL;
	int n = 0;
	uint32_t i = 0;

	_good(_asprintf(&sysfs_sh_path, "%s/host%" PRIu32,
			_ISCSI_SYS_HOST_DIR, host_id), rc, out);

	_good(sysfs_get_dev_path(ctx, sysfs_sh_path,
				 _SYSFS_DEV_CLASS_ISCSI_HOST, &dev_path),
	      rc, out);

	_good(_asprintf(&sysfs_iface_path, "%s/iscsi_iface", dev_path),
	      rc, out);

	_good(_scandir(ctx, sysfs_iface_path, &namelist, &n), rc, out);

	if (n == 0) {
		/* this is OK, and needed for transport drivers like
		 * bnx2i and qedi */
		rc = LIBISCSI_OK;
		_debug(ctx, "No iSCSI interface for iSCSI host %" PRIu32,
		       host_id);
		goto out;
	}

	*iface_count = n;
	*iface_kern_ids = calloc(*iface_count, sizeof(char *));
	_alloc_null_check(ctx, *iface_kern_ids, rc, out);
	for (i = 0; i < *iface_count; i++) {
		(*iface_kern_ids)[i] = strdup(namelist[i]->d_name);
		_alloc_null_check(ctx, (*iface_kern_ids)[i], rc, out);
		_debug(ctx, "Found iSCSI iface '%s' for iSCSI host %" PRIu32,
		       (*iface_kern_ids)[i], host_id);
	}
out:
	if (rc != LIBISCSI_OK) {
		for (i = 0; i < *iface_count; i++ ) {
			free((*iface_kern_ids)[i]);
		}
		free(*iface_kern_ids);
		*iface_kern_ids = NULL;
		*iface_count = 0;
	}
	_scandir_free(namelist, n);
	free(sysfs_sh_path);
	free(dev_path);
	free(sysfs_iface_path);
	return rc;
}
