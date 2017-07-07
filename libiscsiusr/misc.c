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
#include <errno.h>
#include <dirent.h>
#include <string.h>

#include "libiscsiusr/libiscsiusr.h"

struct _num_str_conv {
	const uint32_t value;
	const char *str;
};

#define _iscsi_str_func_gen(func_name, var_type, var, conv_array) \
const char *func_name(var_type var) { \
	size_t i = 0; \
	uint32_t tmp_var = var & UINT32_MAX; \
	errno = 0; \
	/* In the whole libiscsi, we don't have negative value */ \
	for (; i < sizeof(conv_array)/sizeof(conv_array[0]); ++i) { \
		if ((conv_array[i].value) == tmp_var) \
			return conv_array[i].str; \
	} \
	errno = EINVAL; \
	return "Invalid argument"; \
}

static const struct _num_str_conv _ISCSI_RC_MSG_CONV[] = {
	{LIBISCSI_OK, "OK"},
	{LIBISCSI_ERR_BUG, "BUG of libiscsiusr library"},
	{LIBISCSI_ERR_NO_MEMORY, "Out of memory"},
	{LIBISCSI_ERR_PERMISSION_DENY, "Permission deny"},
};

_iscsi_str_func_gen(iscsi_strerror, int, rc, _ISCSI_RC_MSG_CONV);

static const struct _num_str_conv _ISCSI_PRI_CONV[] = {
	{LIBISCSI_LOG_PRIORITY_DEBUG, "DEBUG"},
	{LIBISCSI_LOG_PRIORITY_INFO, "INFO"},
	{LIBISCSI_LOG_PRIORITY_WARNING, "WARNING"},
	{LIBISCSI_LOG_PRIORITY_ERROR, "ERROR"},
};

_iscsi_str_func_gen(iscsi_log_priority_str, int, priority, _ISCSI_PRI_CONV);


int _scan_filter_skip_dot(const struct dirent *dir)
{
	return strcmp(dir->d_name, ".") && strcmp(dir->d_name, "..");
}
