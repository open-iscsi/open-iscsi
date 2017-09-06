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


#ifndef _LIB_ISCSI_USR_H_
#define _LIB_ISCSI_USR_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdarg.h>
#include <errno.h>

/* TODO(Gris Ge): Documentation */

#define __DLL_EXPORT	__attribute__ ((visibility ("default")))
/* ^ Mark function or struct as external use.
 *   Check https://gcc.gnu.org/wiki/Visibility for detail
 */
#define __DLL_LOCAL	__attribute__ ((visibility ("hidden")))
/* ^ Mark function or struct as internal use only.
 *   Check https://gcc.gnu.org/wiki/Visibility for detail
 */

#define LIBISCSI_OK			0
#define LIBISCSI_ERR_BUG		-1
#define LIBISCSI_ERR_NO_MEMORY		ENOMEM
#define LIBISCSI_ERR_NO_SUPPORT		ENOTSUP
#define LIBISCSI_ERR_PERMISSION_DENY	EACCES

/*
 * Use the syslog severity level as log priority
 */
#define LIBISCSI_LOG_PRIORITY_ERROR	3
#define LIBISCSI_LOG_PRIORITY_WARNING	4
#define LIBISCSI_LOG_PRIORITY_INFO	6
#define LIBISCSI_LOG_PRIORITY_DEBUG	7

#define LIBISCSI_LOG_PRIORITY_DEFAULT	LIBISCSI_LOG_PRIORITY_WARNING

struct __DLL_EXPORT iscsi_context;
struct __DLL_EXPORT iscsi_session;
struct __DLL_EXPORT iscsi_iface;

/*
 * Don't free returned pointer.
 */
__DLL_EXPORT const char *iscsi_log_priority_str(int priority);

/*
 * Don't free returned pointer.
 */
__DLL_EXPORT const char *iscsi_strerror(int rc);

__DLL_EXPORT struct iscsi_context *iscsi_context_new(void);
__DLL_EXPORT void iscsi_context_free(struct iscsi_context *ctx);
__DLL_EXPORT void iscsi_context_log_priority_set(struct iscsi_context *ctx,
						 int priority);
__DLL_EXPORT int iscsi_context_log_priority_get(struct iscsi_context *ctx);
__DLL_EXPORT void iscsi_context_log_func_set
	(struct iscsi_context *ctx,
	 void (*log_func) (struct iscsi_context *ctx, int priority,
			   const char *file, int line, const char *func_name,
			   const char *format, va_list args));
__DLL_EXPORT void iscsi_context_userdata_set(struct iscsi_context *ctx,
					     void *userdata);
__DLL_EXPORT void *iscsi_context_userdata_get(struct iscsi_context *ctx);

__DLL_EXPORT int iscsi_session_get(struct iscsi_context *ctx, uint32_t sid,
				   struct iscsi_session **se);
__DLL_EXPORT void iscsi_session_free(struct iscsi_session *se);
__DLL_EXPORT int iscsi_sessions_get(struct iscsi_context *ctx,
				    struct iscsi_session ***ses,
				    uint32_t *se_count);
__DLL_EXPORT void iscsi_sessions_free(struct iscsi_session **ses,
				      uint32_t session_count);

__DLL_EXPORT uint32_t iscsi_session_sid_get(struct iscsi_session *se);

/*
 * Don't free the returned pointer
 */
__DLL_EXPORT const char *iscsi_session_persistent_address_get
	(struct iscsi_session *se);

__DLL_EXPORT int32_t iscsi_session_persistent_port_get
	(struct iscsi_session *se);

/*
 * Don't free the returned pointer
 */
__DLL_EXPORT const char *iscsi_session_targetname_get(struct iscsi_session *se);

/*
 * Don't free the returned pointer
 */
__DLL_EXPORT const char *iscsi_session_username_get(struct iscsi_session *se);

/*
 * Don't free the returned pointer
 */
__DLL_EXPORT const char *iscsi_session_password_get(struct iscsi_session *se);

/*
 * Don't free the returned pointer
 */
__DLL_EXPORT const char *iscsi_session_username_in_get
	(struct iscsi_session *se);

/*
 * Don't free the returned pointer
 */
__DLL_EXPORT const char *iscsi_session_password_in_get
	(struct iscsi_session *se);

__DLL_EXPORT int32_t iscsi_session_recovery_tmo_get(struct iscsi_session *se);

__DLL_EXPORT int32_t iscsi_session_lu_reset_tmo_get(struct iscsi_session *se);
__DLL_EXPORT int32_t iscsi_session_tgt_reset_tmo_get(struct iscsi_session *se);
__DLL_EXPORT int32_t iscsi_session_abort_tmo_get(struct iscsi_session *se);
__DLL_EXPORT int32_t iscsi_session_tpgt_get(struct iscsi_session *se);

/*
 * Don't free the returned pointer
 */
__DLL_EXPORT const char *iscsi_session_address_get
	(struct iscsi_session *se);

__DLL_EXPORT int32_t iscsi_session_port_get(struct iscsi_session *se);

/*
 * Don't free the returned pointer
 */
__DLL_EXPORT struct iscsi_iface *iscsi_session_iface_get
	(struct iscsi_session *se);

__DLL_EXPORT const char *iscsi_iface_ipaddress_get(struct iscsi_iface *iface);
__DLL_EXPORT const char *iscsi_iface_hwaddress_get(struct iscsi_iface *iface);
__DLL_EXPORT const char *iscsi_iface_netdev_get(struct iscsi_iface *iface);
__DLL_EXPORT const char *iscsi_iface_transport_name_get
	(struct iscsi_iface *iface);
__DLL_EXPORT const char *iscsi_iface_netdev_get(struct iscsi_iface *iface);
__DLL_EXPORT const char *iscsi_iface_iname_get(struct iscsi_iface *iface);
__DLL_EXPORT const char *iscsi_iface_port_state_get(struct iscsi_iface *iface);
__DLL_EXPORT const char *iscsi_iface_port_speed_get(struct iscsi_iface *iface);
__DLL_EXPORT const char *iscsi_iface_name_get(struct iscsi_iface *iface);

#ifdef __cplusplus
} /* End of extern "C" */
#endif

#endif /* End of _LIB_ISCSI_USR_H_ */
