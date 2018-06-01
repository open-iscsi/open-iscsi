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


#ifndef _LIB_OPEN_ISCSI_USR_COMMON_H_
#define _LIB_OPEN_ISCSI_USR_COMMON_H_

#include <errno.h>

/* Below error numbers should align with 'open-iscsi/include/iscsi_err.h' */
#define LIBISCSI_OK			0
/* ^ No error */

#define LIBISCSI_ERR_BUG		1
/* ^ Bug of library */

#define LIBISCSI_ERR_SESS_NOT_FOUND	2
/* ^ session could not be found */

#define LIBISCSI_ERR_NOMEM		3
/* ^ Could not allocate resource for operation */

#define LIBISCSI_ERR_IDBM		6
/* ^ Error accessing/managing iSCSI DB */

#define LIBISCSI_ERR_INVAL		7
/* ^ Invalid argument */

#define LIBISCSI_ERR_TRANS_NOT_FOUND	12
/* ^ iSCSI transport module not loaded in kernel or iscsid */

#define LIBISCSI_ERR_ACCESS		13
/* ^ Permission denied */

#define LIBISCSI_ERR_SYSFS_LOOKUP	22
/* ^ Could not lookup object in sysfs */

/*
 * Use the syslog severity level as log priority
 */
#define LIBISCSI_LOG_PRIORITY_ERROR	3
#define LIBISCSI_LOG_PRIORITY_WARNING	4
#define LIBISCSI_LOG_PRIORITY_INFO	6
#define LIBISCSI_LOG_PRIORITY_DEBUG	7

#define LIBISCSI_LOG_PRIORITY_DEFAULT	LIBISCSI_LOG_PRIORITY_WARNING

#define __DLL_EXPORT	__attribute__ ((visibility ("default")))
/* ^ Mark function or struct as external use.
 *   Check https://gcc.gnu.org/wiki/Visibility for detail
 */
#define __DLL_LOCAL	__attribute__ ((visibility ("hidden")))
/* ^ Mark function or struct as internal use only.
 *   Check https://gcc.gnu.org/wiki/Visibility for detail
 */

struct __DLL_EXPORT iscsi_context;

struct __DLL_EXPORT iscsi_session;

struct __DLL_EXPORT iscsi_iface;

struct __DLL_EXPORT iscsi_node;

#endif /* End of _LIB_OPEN_ISCSI_USR_COMMON_H_ */
