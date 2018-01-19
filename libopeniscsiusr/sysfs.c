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
#include <errno.h>

#include "libopeniscsiusr/libopeniscsiusr_common.h"
#include "sysfs.h"
#include "misc.h"

#define _INT32_STR_MAX_LEN		12
/* ^ The max uint32_t is 4294967296 which requires 11 bytes for string.
 *   The max/min in32_t is 2147483647 or -2147483646 which requires 12 bytes.
 */

#define _SYS_NULL_STR			"(null)"

static int sysfs_read_file(const char *path, uint8_t *buff, size_t buff_size);
static int iscsi_sysfs_prop_get_ll(struct iscsi_context *ctx,
				   const char *dir_path, const char *prop_name,
				   long long int *val,
				   long long int default_value);
/*
 * dev_path should be char[PATH_MAX].
 */
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
	char file_path[PATH_MAX];
	int rc = LIBISCSI_OK;
	int errno_save = 0;

	assert(dir_path != NULL);
	assert(prop_name != NULL);
	assert(buff != NULL);

	snprintf(file_path, PATH_MAX, "%s/%s", dir_path, prop_name);

	errno_save = sysfs_read_file(file_path, (uint8_t *) buff, buff_size);
	if (errno_save != 0) {
		if (errno_save == ENOENT) {
			if (default_value == NULL) {
				rc = LIBISCSI_ERR_SYSFS_LOOKUP;
				_error(ctx, "Failed to read '%s': "
				       "file '%s' does not exists", prop_name,
				       file_path);
			} else {
				_info(ctx, "Failed to read '%s': "
				      "file '%s' does not exists, "
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
		} else {
			rc = LIBISCSI_ERR_BUG;
			_error(ctx, "Failed to read '%s': "
			       "error when reading '%s': %d", prop_name,
			       file_path, errno_save);
		}
	} else {
		_debug(ctx, "Open '%s', got '%s'", file_path, buff);
	}
	return rc;
}

static int iscsi_sysfs_prop_get_ll(struct iscsi_context *ctx,
				 const char *dir_path, const char *prop_name,
				 long long int *val,
				 long long int default_value)
{
	char file_path[PATH_MAX];
	int rc = LIBISCSI_OK;
	int errno_save = 0;
	uint8_t buff[_INT32_STR_MAX_LEN];
	long long int tmp_val = 0;

	assert(dir_path != NULL);
	assert(prop_name != NULL);
	assert(val != NULL);

	*val = 0;

	snprintf(file_path, PATH_MAX, "%s/%s", dir_path, prop_name);

	errno_save = sysfs_read_file(file_path, buff, _INT32_STR_MAX_LEN);
	if (errno_save != 0) {
		if (errno_save == ENOENT) {
			if (default_value == LLONG_MAX) {
				rc = LIBISCSI_ERR_SYSFS_LOOKUP;
				_error(ctx, "Failed to read '%s': "
				       "file '%s' does not exists",
				       prop_name, file_path);
				return rc;
			} else {
				_info(ctx,
				       "Failed to read '%s': "
				      "File '%s' does not exists, using ",
				      "default value %lld",
				      file_path, default_value);
				*val = default_value;
				return rc;
			}
		} else if (errno_save == EACCES) {
			rc = LIBISCSI_ERR_ACCESS;
			_error(ctx, "Permission deny when reading '%s'",
			       file_path);
			return rc;
		} else {
			rc = LIBISCSI_ERR_BUG;
			_error(ctx, "Error when reading '%s': %d", file_path,
			       errno_save);
			return rc;
		}
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

	_debug(ctx, "Open '%s', got %lld", file_path, tmp_val);

	return rc;
}

int _sysfs_prop_get_u32(struct iscsi_context *ctx, const char *dir_path,
			const char *prop_name, uint32_t *val,
			uint32_t default_value)
{
	long long int tmp_val = 0;
	int rc = LIBISCSI_OK;
	long long int dv = default_value;

	if (default_value == UINT32_MAX)
		dv = LLONG_MAX;

	rc = iscsi_sysfs_prop_get_ll(ctx, dir_path, prop_name, &tmp_val,
				     (long long int) dv);
	if (rc == LIBISCSI_OK)
		*val = tmp_val & UINT32_MAX;
	return rc;
}

int _sysfs_prop_get_i32(struct iscsi_context *ctx, const char *dir_path,
			const char *prop_name, int32_t *val,
			int32_t default_value)
{
	long long int tmp_val = 0;
	int rc = LIBISCSI_OK;
	long long int dv = default_value;

	if (default_value == INT32_MAX)
		dv = LLONG_MAX;

	rc = iscsi_sysfs_prop_get_ll(ctx, dir_path, prop_name, &tmp_val,
				     (long long int) dv);

	if (rc == LIBISCSI_OK)
		*val = tmp_val & INT32_MAX;
	return rc;
}
