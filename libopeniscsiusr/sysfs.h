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
#include <stdbool.h>

#include "libopeniscsiusr/libopeniscsiusr_common.h"

#define _ISCSI_SYS_SESSION_DIR		"/sys/class/iscsi_session"
#define _ISCSI_SYS_CONNECTION_DIR	"/sys/class/iscsi_connection"
#define _ISCSI_SYS_HOST_DIR		"/sys/class/iscsi_host"
#define _ISCSI_SYS_IFACE_DIR		"/sys/class/iscsi_iface"
#define _ISCSI_SYS_TRANSPORT_DIR	"/sys/class/iscsi_transport"
#define _SCSI_SYS_HOST_DIR		"/sys/class/scsi_host"

/*
 * When default_value == NULL, treat no such file as LIB_BUG.
 */
__DLL_LOCAL int _sysfs_prop_get_str(struct iscsi_context *ctx,
				    const char *dir_path, const char *prop_name,
				    char *buff, size_t buff_size,
				    const char *default_value);

int _sysfs_prop_get_u8(struct iscsi_context *ctx, const char *dir_path,
		       const char *prop_name, uint8_t *val,
		       uint8_t default_value, bool ignore_error);

int _sysfs_prop_get_u16(struct iscsi_context *ctx, const char *dir_path,
			const char *prop_name, uint16_t *val,
			uint16_t default_value, bool ignore_error);

/*
 * When default_value == UINT32_MAX, treat no such file as LIB_BUG.
 */
__DLL_LOCAL int _sysfs_prop_get_u32(struct iscsi_context *ctx,
				    const char *dir_path, const char *prop_name,
				    uint32_t *val, uint32_t default_value,
				    bool ignore_error);

/*
 * When default_value == INT32_MAX, treat no such file as LIB_BUG.
 */
__DLL_LOCAL int _sysfs_prop_get_i32(struct iscsi_context *ctx,
				    const char *dir_path, const char *prop_name,
				    int32_t *val, int32_t default_value,
				    bool ignore_error);

__DLL_LOCAL int _iscsi_host_id_of_session(struct iscsi_context *ctx,
					  uint32_t sid, uint32_t *host_id);

/*
 * iface_kern_id returns an allocated (char *)[iface_count]
 * that needs to be freed by the caller
 */
__DLL_LOCAL int _iscsi_iface_kern_ids_of_host_id(struct iscsi_context *ctx,
						 uint32_t host_id,
						 char ***iface_kern_ids,
						 uint32_t *iface_count);

/*
 * The memory of (uint32_t *sids) should be freed by free().
 */
__DLL_LOCAL int _iscsi_sids_get(struct iscsi_context *ctx,
				uint32_t **sids, uint32_t *sid_count);

/*
 * The memory of (uint32_t *hids) should be freed by free().
 */
__DLL_LOCAL int _iscsi_hids_get(struct iscsi_context *ctx, uint32_t **hids,
				uint32_t *hid_count);

__DLL_LOCAL bool _iscsi_transport_is_loaded(const char *transport_name);

#endif /* End of __ISCSI_USR_SYSFS_H__ */
