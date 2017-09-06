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

#include "libiscsiusr/libiscsiusr.h"
#include "private.h"

#define _UINT32_STR_MAX_LEN		11
/* ^ The max uint32_t is 4294967296 which requires 11 bytes for string. */

#define _SYS_NULL_STR			"(null)"

static int sys_read_file(const char *path, uint8_t *buff, size_t buff_size);
static int iscsi_sys_prop_get_ll(struct iscsi_context *ctx,
				 const char *dir_path, const char *prop_name,
				 long long int *val);
/*
 * dev_path should be char[PATH_MAX].
 */
static int sysfs_get_dev_path(struct iscsi_context *ctx, const char *path,
			      char *dev_path);

static int sys_read_file(const char *path, uint8_t *buff, size_t buff_size)
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

int _sys_prop_get_str(struct iscsi_context *ctx, const char *dir_path,
		      const char *prop_name, char *buff, size_t buff_size)
{
	char file_path[PATH_MAX];
	int rc = LIBISCSI_OK;
	int errno_save = 0;

	assert(dir_path != NULL);
	assert(prop_name != NULL);
	assert(buff != NULL);

	snprintf(file_path, PATH_MAX, "%s/%s", dir_path, prop_name);

	errno_save = sys_read_file(file_path, (uint8_t *) buff, buff_size);
	if (errno_save != 0) {
		if (errno_save == EACCES) {
			rc = LIBISCSI_ERR_PERMISSION_DENY;
			_error(ctx, "Permission deny when reading '%s'",
			       file_path);
		} else {
			rc = LIBISCSI_ERR_BUG;
			_error(ctx, "Error when reading '%s': %d", file_path,
			       errno_save);
		}
	}
	_debug(ctx, "Open %s, got '%s'", file_path, buff);
	return rc;
}

static int iscsi_sys_prop_get_ll(struct iscsi_context *ctx,
				 const char *dir_path, const char *prop_name,
				 long long int *val)
{
	char file_path[PATH_MAX];
	int rc = LIBISCSI_OK;
	int errno_save = 0;
	uint8_t buff[_UINT32_STR_MAX_LEN];
	long long int tmp_val = 0;

	assert(dir_path != NULL);
	assert(prop_name != NULL);
	assert(val != NULL);

	*val = 0;

	snprintf(file_path, PATH_MAX, "%s/%s", dir_path, prop_name);

	errno_save = sys_read_file(file_path, buff, _UINT32_STR_MAX_LEN);
	if (errno_save != 0) {
		rc = LIBISCSI_ERR_BUG;
		_error(ctx, "Error when reading '%s': %d", file_path,
		       errno_save);
		return rc;
	}

	tmp_val = strtoll((const char *) buff, NULL, 10 /* base */);
	errno_save = errno;
	if ((errno_save != 0) && (tmp_val == LONG_MAX)) {
		rc = LIBISCSI_ERR_BUG;
		_error(ctx, "Sysfs: %s: Error when converting '%s' "
		       "to number", file_path,  (char *) buff, errno_save);
		return rc;
	}

	*val = tmp_val;

	_debug(ctx, "Open %s, got %lld", file_path, tmp_val);

	return rc;
}

int _sys_prop_get_u32(struct iscsi_context *ctx, const char *dir_path,
			    const char *prop_name, uint32_t *val)
{
	long long int tmp_val = 0;
	int rc = LIBISCSI_OK;

	rc = iscsi_sys_prop_get_ll(ctx, dir_path, prop_name, &tmp_val);
	if (rc == LIBISCSI_OK)
		*val = tmp_val & UINT32_MAX;
	return rc;
}

int _sys_prop_get_i32(struct iscsi_context *ctx, const char *dir_path,
			    const char *prop_name, int32_t *val)
{
	long long int tmp_val = 0;
	int rc = LIBISCSI_OK;

	rc = iscsi_sys_prop_get_ll(ctx, dir_path, prop_name, &tmp_val);

	if (rc == LIBISCSI_OK)
		*val = tmp_val & INT32_MAX;
	return rc;
}

static int sysfs_get_dev_path(struct iscsi_context *ctx, const char *path,
			      char *dev_path)
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

	memset(dev_path, 0, PATH_MAX);

	if (realpath(path, dev_path) == NULL) {
		errno_save = errno;
		rc = LIBISCSI_ERR_BUG;
		_error(ctx, "realpath() failed on %s with error %d", path,
		       errno_save);
		goto out;
	}

	reg_rc = regcomp(&regex,
			 "\\(.\\{1,\\}/devices/.\\{1,\\}/host[0-9]\\{1,\\}\\)/"
			 "session[0-9]\\{1,\\}/iscsi_session/",
			 0 /* no flag */);
	/* ^ BUG(Gris Ge): This is based on GUESS, should check linux kernel
	 *		   code on this
	 */
	if (reg_rc != 0) {
		rc = LIBISCSI_ERR_BUG;
		_error(ctx, "regcomp() failed %d", reg_rc);
		goto out;
	}
	need_free_reg = 1;
	if (regexec(&regex, dev_path, 2 /* count of max matches */,
		    reg_match, 0 /* no flags */) != 0) {
		rc = LIBISCSI_ERR_BUG;
		_error(ctx, "regexec() not match for %s", dev_path);
		goto out;
	}

	*(dev_path + reg_match[1].rm_eo ) = '\0';

	_debug(ctx, "Got dev path of '%s': '%s'", path, dev_path);

out:
	if (need_free_reg)
		regfree(&regex);
	if (rc != LIBISCSI_OK)
		memset(dev_path, 0, PATH_MAX);
	return rc;
}

int _iscsi_host_id_of_session(struct iscsi_context *ctx, uint32_t sid,
			      uint32_t *host_id)
{
	int rc = LIBISCSI_OK;
	char sys_se_dir_path[PATH_MAX];
	char sys_dev_path[PATH_MAX];
	char sys_scsi_host_dir_path[PATH_MAX];
	struct dirent **namelist = NULL;
	int n = 0;
	const char *host_id_str = NULL;
	int i = 0;

	assert(ctx != NULL);
	assert(sid != 0);
	assert(host_id != NULL);

	snprintf(sys_se_dir_path, PATH_MAX, "%s/session%" PRIu32,
		 _ISCSI_SYS_SESSION_DIR, sid);

	*host_id = 0;

	_good(sysfs_get_dev_path(ctx, sys_se_dir_path, sys_dev_path), rc, out);

	snprintf(sys_scsi_host_dir_path, PATH_MAX, "%s/iscsi_host/",
		 sys_dev_path);

	n = scandir(sys_scsi_host_dir_path, &namelist, _scan_filter_skip_dot,
		    alphasort);
	if (n != 1) {
		rc = LIBISCSI_ERR_BUG;
		_error(ctx, "Got unexpected(should be 1) file in folder %s",
		       sys_scsi_host_dir_path);
		goto out;
	}
	host_id_str = namelist[0]->d_name;

	if (sscanf(host_id_str, "host%" SCNu32, host_id) != 1) {
		rc = LIBISCSI_ERR_BUG;
		_error(ctx, "sscanf() failed on string %s", host_id_str);
		goto out;
	}

out:
	for (i = n - 1; i >= 0; --i)
		free(namelist[i]);
	free(namelist);

	return rc;
}
