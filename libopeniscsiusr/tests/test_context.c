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
#include <assert.h>

#include <libopeniscsiusr/libopeniscsiusr.h>

int main(void)
{
	struct iscsi_context *ctx = NULL;
	int rc = EXIT_SUCCESS;
	int i = 0;

	ctx = iscsi_context_new();
	assert(ctx != NULL);
	iscsi_context_log_priority_set(ctx, LIBISCSI_LOG_PRIORITY_DEBUG);
	assert(iscsi_context_log_priority_get(ctx) ==
	       LIBISCSI_LOG_PRIORITY_DEBUG);
	iscsi_context_log_func_set(ctx, NULL);
	iscsi_context_userdata_set(ctx, (void *) &i);
	assert(* (int *) iscsi_context_userdata_get(ctx) == 0);

	iscsi_context_free(ctx);
	exit(rc);
}
