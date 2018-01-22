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
#ifndef _LIB_OPEN_ISCSI_USR_H_
#define _LIB_OPEN_ISCSI_USR_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdarg.h>

#include "libopeniscsiusr_common.h"

/**
 * iscsi_log_priority_str() - Convert log priority to string.
 *
 * Convert log priority to string (const char *).
 *
 * @priority:
 *	int. Log priority.
 *
 * Return:
 *	const char *. Please don't free returned pointer. Valid string are:
 *
 *	* "ERROR" for LIBISCSI_LOG_PRIORITY_ERROR
 *
 *	* "WARN"  for LIBISCSI_LOG_PRIORITY_WARNING
 *
 *	* "INFO"  for LIBISCSI_LOG_PRIORITY_INFO
 *
 *	* "DEBUG" for LIBISCSI_LOG_PRIORITY_DEBUG
 *
 *	* "Invalid argument" for invalid log priority.
 */
__DLL_EXPORT const char *iscsi_log_priority_str(int priority);

/**
 * iscsi_strerror() - Convert error code to string.
 *
 * Convert error code (int) to string (const char *):
 *
 *	* LIBISCSI_OK -- "OK"
 *
 *	* Other invalid error number -- "Invalid argument"
 *
 * @rc:
 *	int. Return code by libiscsiur functions. When provided error code is
 *	not a valid error code, return "Invalid argument".
 *
 * Return:
 *	const char *. The meaning of provided error code. Don't free returned
 *	pointer.
 */
__DLL_EXPORT const char *iscsi_strerror(int rc);

/**
 * iscsi_context_new() - Create struct iscsi_context.
 *
 * The default logging level (LIBISCSI_LOG_PRIORITY_DEFAULT) is
 * LIBISCSI_LOG_PRIORITY_WARNING which means only warning and error message will
 * be forward to log handler function.  The default log handler function will
 * print log message to STDERR, to change so, please use
 * iscsi_context_log_func_set() to set your own log handler, check manpage
 * libopeniscsiusr.h(3) for detail.
 *
 * Return:
 *	Pointer of 'struct iscsi_context'. Should be freed by
 *	iscsi_context_free().
 */
__DLL_EXPORT struct iscsi_context *iscsi_context_new(void);

/**
 * iscsi_context_free() - Release the memory of struct iscsi_context.
 *
 * Release the memory of struct iscsi_context, but the userdata memory defined
 * via iscsi_context_userdata_set() will not be touched.
 *
 * @ctx:
 *	Pointer of 'struct iscsi_context'.
 * Return:
 *	void
 */
__DLL_EXPORT void iscsi_context_free(struct iscsi_context *ctx);

/**
 * iscsi_context_log_priority_set() - Set log priority.
 *
 *
 * When library generates log message, only equal or more important(less value)
 * message will be forwarded to log handler function. Valid log priority values
 * are:
 *
 *	* LIBISCSI_LOG_PRIORITY_ERROR -- 3
 *
 *	* LIBISCSI_LOG_PRIORITY_WARNING -- 4
 *
 *	* LIBISCSI_LOG_PRIORITY_INFO -- 6
 *
 *	* LIBISCSI_LOG_PRIORITY_DEBUG -- 7
 *
 * @ctx:
 *	Pointer of 'struct iscsi_context'.
 *	If this pointer is NULL, your program will be terminated by assert.
 *
 * @priority:
 *	int, log priority.
 *
 * Return:
 *	void
 */
__DLL_EXPORT void iscsi_context_log_priority_set(struct iscsi_context *ctx,
						 int priority);

/**
 * iscsi_context_log_priority_get() - Get log priority.
 *
 * Retrieve current log priority. Valid log priority values are:
 *
 *	* LIBISCSI_LOG_PRIORITY_ERROR -- 3
 *
 *	* LIBISCSI_LOG_PRIORITY_WARNING -- 4
 *
 *	* LIBISCSI_LOG_PRIORITY_INFO -- 5
 *
 *	* LIBISCSI_LOG_PRIORITY_DEBUG -- 7
 *
 * @ctx:
 *	Pointer of 'struct iscsi_context'.
 *	If this pointer is NULL, your program will be terminated by assert.
 *
 * Return:
 *	int, log priority.
 */
__DLL_EXPORT int iscsi_context_log_priority_get(struct iscsi_context *ctx);

/**
 * iscsi_context_log_func_set() - Set log handler function.
 *
 * Set custom log handler. The log handler will be invoked when log message
 * is equal or more important(less value) than log priority setting.
 * Please check manpage libopeniscsiusr.h(3) for detail usage.
 *
 * @ctx:
 *	Pointer of 'struct iscsi_context'.
 *	If this pointer is NULL, your program will be terminated by assert.
 * @log_func:
 *	Pointer of log handler function.
 *
 * Return:
 *	void
 */
__DLL_EXPORT void iscsi_context_log_func_set
	(struct iscsi_context *ctx,
	 void (*log_func) (struct iscsi_context *ctx, int priority,
			   const char *file, int line, const char *func_name,
			   const char *format, va_list args));

/**
 * iscsi_context_userdata_set() - Set user data pointer.
 *
 * Store user data pointer into 'struct iscsi_context'.
 *
 * @ctx:
 *	Pointer of 'struct iscsi_context'.
 *	If this pointer is NULL, your program will be terminated by assert.
 * @userdata:
 *	Pointer of user defined data.
 *
 * Return:
 *	void
 */
__DLL_EXPORT void iscsi_context_userdata_set(struct iscsi_context *ctx,
					     void *userdata);

/**
 * iscsi_context_userdata_get() - Get user data pointer.
 *
 * Retrieve user data pointer from 'struct iscsi_context'.
 *
 * @ctx:
 *	Pointer of 'struct iscsi_context'.
 *	If this pointer is NULL, your program will be terminated by assert.
 *
 * Return:
 *	void *. Pointer of user defined data.
 */
__DLL_EXPORT void *iscsi_context_userdata_get(struct iscsi_context *ctx);

#ifdef __cplusplus
} /* End of extern "C" */
#endif

#endif /* End of _LIB_OPEN_ISCSI_USR_H_ */
