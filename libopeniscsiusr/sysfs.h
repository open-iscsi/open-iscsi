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
#ifndef __ISCSI_USR_SYSFS_H__
#define __ISCSI_USR_SYSFS_H__

#include <stdint.h>

#include "libopeniscsiusr/libopeniscsiusr_common.h"

#define _ISCSI_SYS_SESSION_DIR		"/sys/class/iscsi_session"
#define _ISCSI_SYS_CONNECTION_DIR	"/sys/class/iscsi_connection"

/*
 * When default_value == NULL, treat no such file as LIB_BUG.
 */
__DLL_LOCAL int _sysfs_prop_get_str(struct iscsi_context *ctx,
				    const char *dir_path, const char *prop_name,
				    char *buff, size_t buff_size,
				    const char *default_value);

/*
 * When default_value == UINT32_MAX, treat no such file as LIB_BUG.
 */
__DLL_LOCAL int _sysfs_prop_get_u32(struct iscsi_context *ctx,
				    const char *dir_path, const char *prop_name,
				    uint32_t *val, uint32_t default_value);

/*
 * When default_value == INT32_MAX, treat no such file as LIB_BUG.
 */
__DLL_LOCAL int _sysfs_prop_get_i32(struct iscsi_context *ctx,
				    const char *dir_path, const char *prop_name,
				    int32_t *val, int32_t default_value);

#endif /* End of __ISCSI_USR_SYSFS_H__ */
