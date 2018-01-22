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

#define LIBISCSI_OK			0

/*
 * Use the syslog severity level as log priority
 */
#define LIBISCSI_LOG_PRIORITY_ERROR	3
#define LIBISCSI_LOG_PRIORITY_WARNING	4
#define LIBISCSI_LOG_PRIORITY_INFO	6
#define LIBISCSI_LOG_PRIORITY_DEBUG	7

#define LIBISCSI_LOG_PRIORITY_DEFAULT	LIBISCSI_LOG_PRIORITY_WARNING

/* TODO(Gris Ge): Documentation */

#define __DLL_EXPORT	__attribute__ ((visibility ("default")))
/* ^ Mark function or struct as external use.
 *   Check https://gcc.gnu.org/wiki/Visibility for detail
 */
#define __DLL_LOCAL	__attribute__ ((visibility ("hidden")))
/* ^ Mark function or struct as internal use only.
 *   Check https://gcc.gnu.org/wiki/Visibility for detail
 */

struct __DLL_EXPORT iscsi_context;

#endif /* End of _LIB_OPEN_ISCSI_USR_COMMON_H_ */
