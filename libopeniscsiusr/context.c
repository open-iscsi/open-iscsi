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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <assert.h>

#include "libopeniscsiusr/libopeniscsiusr.h"
#include "misc.h"
#include "context.h"

_iscsi_getter_func_gen(iscsi_context, log_priority, int);

_iscsi_getter_func_gen(iscsi_context, userdata, void *);

struct iscsi_context *iscsi_context_new(void)
{
	struct iscsi_context *ctx = NULL;

	ctx = (struct iscsi_context *) malloc(sizeof(struct iscsi_context));

	if (ctx == NULL)
		return NULL;

	ctx->log_func = _iscsi_log_stderr;
	ctx->log_priority = LIBISCSI_LOG_PRIORITY_DEFAULT;
	ctx->userdata = NULL;
	ctx->db = _idbm_new();
	if (ctx->db == NULL) {
		free(ctx);
		return NULL;
	}

	return ctx;
}

void iscsi_context_free(struct iscsi_context *ctx)
{
	if (ctx == NULL)
		return;

	if (ctx->db)
		_idbm_free(ctx->db);

	free(ctx);
}

void iscsi_context_log_priority_set(struct iscsi_context *ctx, int priority)
{
	assert(ctx != NULL);
	ctx->log_priority = priority;
}

void iscsi_context_log_func_set
	(struct iscsi_context *ctx,
	 void (*log_func)(struct iscsi_context *ctx, int priority,
			  const char *file, int line, const char *func_name,
			  const char *format, va_list args))
{
	assert(ctx != NULL);
	ctx->log_func = log_func;
}

void iscsi_context_userdata_set(struct iscsi_context *ctx, void *userdata)
{
	assert(ctx != NULL);
	ctx->userdata = userdata;
}
