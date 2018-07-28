/*
 * Copyright (C) 2017-2018 Red Hat, Inc.
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
#ifndef __ISCSI_USR_CONTEXT_H__
#define __ISCSI_USR_CONTEXT_H__

#include "idbm.h"
#include <stdarg.h>

struct iscsi_context {
	void (*log_func)(struct iscsi_context *ctx, int priority,
			 const char *file, int line, const char *func_name,
			 const char *format, va_list args);
	int log_priority;
	void *userdata;
	struct idbm *db;
};


#endif /* End of __ISCSI_USR_CONTEXT_H__ */
