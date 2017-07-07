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
#ifndef __PRIVATE_H_
#define __PRIVATE_H_

/*
 * Notes:
 *	Internal/Private functions does not check input argument but using
 *	assert() to abort if NULL pointer found in argument.
 */

#include <stdint.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <dirent.h>

#include "libiscsiusr/libiscsiusr.h"

#define _ISCSI_SYS_SESSION_DIR		"/sys/class/iscsi_session"
#define _ISCSI_SYS_HOST_DIR		"/sys/class/iscsi_host"
#define _ISCSI_SYS_IFACE_DIR		"/sys/class/iscsi_iface"
#define _ISCSI_SYS_CONNECTION_DIR	"/sys/class/iscsi_connection"
#define _SCSI_SYS_HOST_DIR		"/sys/class/scsi_host"

#define _good(rc, rc_val, out) \
	do { \
		rc_val = rc; \
		if (rc_val != LIBISCSI_OK) \
			goto out; \
	} while(0)

__DLL_LOCAL void _iscsi_log(struct iscsi_context *ctx, int priority,
			    const char *file, int line, const char *func_name,
			    const char *format, ...);
__DLL_LOCAL void _iscsi_log_err_str(struct iscsi_context *ctx, int rc);
__DLL_LOCAL void _iscsi_log_stderr(struct iscsi_context *ctx, int priority,
				   const char *file, int line,
				   const char *func_name, const char *format,
				   va_list args);

#define _iscsi_log_cond(ctx, prio, arg...) \
	do { \
		if ((ctx != NULL) && \
		    (iscsi_context_log_priority_get(ctx) >= prio)) \
			_iscsi_log(ctx, prio, __FILE__, __LINE__, \
				   __FUNCTION__, ## arg); \
	} while (0)

#define _debug(ctx, arg...) \
	_iscsi_log_cond(ctx, LIBISCSI_LOG_PRIORITY_DEBUG, ## arg)
#define _info(ctx, arg...) \
	_iscsi_log_cond(ctx, LIBISCSI_LOG_PRIORITY_INFO, ## arg)
#define _warn(ctx, arg...) \
	_iscsi_log_cond(ctx, LIBISCSI_LOG_PRIORITY_WARNING, ## arg)
#define _error(ctx, arg...) \
	_iscsi_log_cond(ctx, LIBISCSI_LOG_PRIORITY_ERROR, ## arg)

/*
 * Check pointer returned by malloc() or strdup() or calloc(), if NULL, set
 * rc as LIBISCSI_ERR_NO_MEMORY, report error and goto goto_out.
 */
#define _alloc_null_check(ctx, ptr, rc, goto_out) \
	do { \
		if (ptr == NULL) { \
			rc = LIBISCSI_ERR_NO_MEMORY; \
			_error(ctx, iscsi_strerror(rc)); \
			goto goto_out; \
		} \
	} while(0)

#define _iscsi_getter_func_gen(struct_name, prop_name, prop_type) \
	prop_type struct_name##_##prop_name##_get(struct struct_name *d) \
	{ \
		assert(d != NULL); \
		return d->prop_name; \
	}

__DLL_LOCAL int _sys_prop_get_str(struct iscsi_context *ctx,
					const char *dir_path,
					const char *prop_name, char *buff,
					size_t buff_size);

__DLL_LOCAL int _sys_prop_get_u32(struct iscsi_context *ctx,
					const char *dir_path,
					const char *prop_name, uint32_t *val);

__DLL_LOCAL int _sys_prop_get_i32(struct iscsi_context *ctx,
					const char *dir_path,
					const char *prop_name, int32_t *val);

__DLL_LOCAL int _iscsi_host_id_of_session(struct iscsi_context *ctx,
					  uint32_t sid, uint32_t *host_id);

/*
 * BUG(Gris Ge): Should include 'iface_kern_id' parameter.
 */
__DLL_LOCAL int _iscsi_iface_get(struct iscsi_context *ctx, uint32_t host_id,
				 uint32_t sid, const char *iface_kern_id,
				 struct iscsi_iface **iface);

__DLL_LOCAL void _iscsi_iface_free(struct iscsi_iface *iface);

__DLL_LOCAL int _scan_filter_skip_dot(const struct dirent *dir);


#endif /* End of __PRIVATE_H_ */
