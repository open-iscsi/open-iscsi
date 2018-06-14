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
#ifndef __ISCSI_USR_MISC_H__
#define __ISCSI_USR_MISC_H__

#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <stdarg.h>
#include <dirent.h>
#include <net/if.h>

#include "libopeniscsiusr/libopeniscsiusr.h"

#define _good(rc, rc_val, out) \
	do { \
		rc_val = rc; \
		if (rc_val != LIBISCSI_OK) \
			goto out; \
	} while(0)

#define _asprintf(...) \
	(asprintf(__VA_ARGS__) == -1 ? LIBISCSI_ERR_NOMEM : LIBISCSI_OK)

__DLL_LOCAL void _iscsi_log(struct iscsi_context *ctx, int priority,
			    const char *file, int line, const char *func_name,
			    const char *format, ...);
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

#define _iscsi_getter_func_gen(struct_name, prop_name, prop_type) \
	prop_type struct_name##_##prop_name##_get(struct struct_name *d) \
	{ \
		assert(d != NULL); \
		return d->prop_name; \
	}

/*
 * Check pointer returned by malloc() or strdup() or calloc(), if NULL, set
 * rc as LIBISCSI_ERR_NO_MEMORY, report error and goto goto_out.
 */
#define _alloc_null_check(ctx, ptr, rc, goto_out) \
	do { \
		if (ptr == NULL) { \
			rc = LIBISCSI_ERR_NOMEM; \
			_error(ctx, iscsi_strerror(rc)); \
			goto goto_out; \
		} \
	} while(0)

#define _STRERR_BUFF_LEN	1024
#define _strerror(err_no, buff) \
	strerror_r(err_no, buff, _STRERR_BUFF_LEN)

/* Workaround for suppress GCC 8 `stringop-truncation` warnings. */
#define _strncpy(dst, src, size) \
	do { \
		memcpy(dst, src, \
		       (size_t) size > strlen(src) ? \
		       strlen(src) : (size_t) size); \
		* (char *) (dst + \
			    ((size_t) size - 1 > strlen(src) ? \
			     strlen(src) : (size_t) (size - 1))) = '\0'; \
	} while(0)

__DLL_LOCAL int _scan_filter_skip_dot(const struct dirent *dir);

__DLL_LOCAL bool _file_exists(const char *path);


#define _ETH_DRIVER_NAME_MAX_LEN	32
/* ^ Defined in linux/ethtool.h `struct ethtool_drvinfo`. */

struct _eth_if {
	char driver_name[_ETH_DRIVER_NAME_MAX_LEN];
	char if_name[IF_NAMESIZE];
};

__DLL_LOCAL int _eth_ifs_get(struct iscsi_context *ctx,
			     struct _eth_if ***eifs, uint32_t *eif_count);

__DLL_LOCAL void _eth_ifs_free(struct _eth_if **eifs, uint32_t eif_count);

__DLL_LOCAL int _scandir(struct iscsi_context *ctx, const char *dir_path,
			 struct dirent ***namelist, int *count);
__DLL_LOCAL void _scandir_free(struct dirent **namelist, int count);

#endif /* End of __ISCSI_USR_MISC_H__ */
