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
#include <stdlib.h>
#include <stdio.h>
#include <assert.h>
#include <inttypes.h>

#include <libopeniscsiusr/libopeniscsiusr.h>

int main()
{
	struct iscsi_context *ctx = NULL;
	struct iscsi_node **nodes = NULL;
	uint32_t node_count = 0;
	uint32_t i = 0;
	const char *dump = NULL;
	int rc = EXIT_SUCCESS;

	ctx = iscsi_context_new();
	iscsi_context_log_priority_set(ctx, LIBISCSI_LOG_PRIORITY_DEBUG);

	if (iscsi_nodes_get(ctx, &nodes, &node_count) != LIBISCSI_OK) {
		printf("FAILED\n");
		rc = EXIT_FAILURE;
	} else {
		printf("\nGot %" PRIu32 " iSCSI nodes\n", node_count);
		for (i = 0; i < node_count; ++i) {
			dump = iscsi_node_dump_config(nodes[i], true);
			assert(dump != NULL);
			free((void *) dump);
			iscsi_node_print_config(nodes[i], true);
		}
		iscsi_nodes_free(nodes, node_count);
	}
	iscsi_context_free(ctx);
	exit(rc);
}
