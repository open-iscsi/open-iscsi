/*
 * Copyright (C) 2018 Red Hat, Inc.
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
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
/* ^ For strerror_r() */
#endif

#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "libopeniscsiusr/libopeniscsiusr.h"
#include "misc.h"
#include "node.h"

/* ptr is both input and output pointer.
 * count is both input and output pointer.
 * When success, both count and ptr will be updated.
 * If fail, return LIBISCSI_ERR_NOMEM and no touch to old memory.
 */
static int _grow_node_array(struct iscsi_context *ctx,
			    struct iscsi_node ***nodes, uint32_t *count)
{
	int rc = LIBISCSI_OK;
	struct iscsi_node **tmp = NULL;
	uint32_t i = 0;

	_debug(ctx, "Growing node array from size %" PRIu32 " to %" PRIu32,
	       *count, *count * 2);

	tmp = realloc(*nodes, *count * 2 * sizeof(struct iscsi_node *));
	_alloc_null_check(ctx, tmp, rc, out);
	for (i = *count; i < *count * 2; ++i)
		tmp[i] = NULL;

	*count *= 2;
	*nodes = tmp;

out:
	return rc;
}

static int nodes_append(struct iscsi_context *ctx, struct iscsi_node ***nodes,
			uint32_t *real_node_count, uint32_t *array_size,
			struct iscsi_node *node)
{
	int rc = LIBISCSI_OK;
	if (*real_node_count >= *array_size)
		_good(_grow_node_array(ctx, nodes, array_size), rc, out);

	(*nodes)[(*real_node_count)++] = node;

out:
	return rc;
}

int iscsi_nodes_get(struct iscsi_context *ctx, struct iscsi_node ***nodes,
		    uint32_t *node_count)
{
	int rc = LIBISCSI_OK;
	struct dirent **namelist = NULL;
	int n = 0;
	int i = 0;
	int j = 0;
	int k = 0;
	struct iscsi_node *node = NULL;
	uint32_t real_node_count = 0;
	const char *target_name = NULL;
	const char *portal = NULL;
	const char *iface_name = NULL;
	struct dirent **namelist_portals = NULL;
	int p = 0;
	struct dirent **namelist_ifaces = NULL;
	int f = 0;
	char *target_path = NULL;
	char *path = NULL;
	struct stat path_stat;
	char strerr_buff[_STRERR_BUFF_LEN];

	assert(ctx != NULL);
	assert(nodes != NULL);
	assert(node_count != NULL);

	*nodes = NULL;
	*node_count = 0;

	_good(_idbm_lock(ctx), rc, out);

	_good(_scandir(ctx, NODE_CONFIG_DIR, &namelist, &n), rc, out);
	_debug(ctx, "Got %d target from %s nodes folder", n, NODE_CONFIG_DIR);
	/*
	 * If continue with n == 0, calloc() might return a memory which failed
	 * to be freed in iscsi_nodes_free()
	 *
	 * So here just goto out to exit if n == 0
	 */
	if (n == 0)
		goto out;

	*node_count = n & UINT32_MAX;
	*nodes = (struct iscsi_node **) calloc(*node_count,
					       sizeof(struct iscsi_node *));
	_alloc_null_check(ctx, *nodes, rc, out);

	// New style of nodes folder:
	//	<target_name>/<address>,<port>,<tpgt>/<iface_name>
	// Old style of nodes folder:
	//	<target_name>/<address>,<port>

	for (i = 0; i < n; ++i) {
		target_name = namelist[i]->d_name;
		_good(_asprintf(&target_path, "%s/%s", NODE_CONFIG_DIR,
				target_name), rc, out);
		_good(_scandir(ctx, target_path, &namelist_portals, &p),
		      rc, out);
		_debug(ctx, "Got %d portals from %s folder", p, target_path);
		free(target_path);
		target_path = NULL;
		for (j = 0; j < p; ++j) {
			portal = namelist_portals[j]->d_name;
			_good(_asprintf(&path, "%s/%s/%s", NODE_CONFIG_DIR,
					target_name, portal), rc, out);
			if (stat(path, &path_stat) != 0) {
				_warn(ctx, "Cannot stat path '%s': %d, %s",
				      path, errno,
				      _strerror(errno, strerr_buff));
				continue;
			}
			if (S_ISREG(path_stat.st_mode)) {
				// Old style of node
				_good(_idbm_node_get(ctx, target_name, portal,
						     NULL, &node),
				      rc, out);
				_good(nodes_append(ctx, nodes,
						   &real_node_count,
						   node_count, node),
				      rc, out);
				continue;
			}
			if (! S_ISDIR(path_stat.st_mode)) {
				_warn(ctx, "Invalid iSCSI node configuration "
				      "file %s, it should be a file or "
				      "directory.", path);
				rc = LIBISCSI_ERR_IDBM;
				goto out;
			}
			_good(_scandir(ctx, path, &namelist_ifaces, &f), rc,
			      out);
			_debug(ctx, "Got %d ifaces from %s folder", f, path);
			for (k = 0; k < f; ++k) {
				iface_name = namelist_ifaces[k]->d_name;
				_good(_idbm_node_get(ctx, target_name, portal,
						     iface_name, &node),
				      rc, out);
				_good(nodes_append(ctx, nodes,
						   &real_node_count,
						   node_count, node),
				      rc, out);
			}
			free(path);
			path = NULL;
			_scandir_free(namelist_ifaces, f);
			namelist_ifaces = NULL;
			f = 0;
		}
		_scandir_free(namelist_portals, p);
		namelist_portals = NULL;
		p = 0;
	}

	*node_count = real_node_count;

out:
	free(path);
	free(target_path);
	_scandir_free(namelist, n);
	_scandir_free(namelist_portals, p);
	_scandir_free(namelist_ifaces, f);
	_idbm_unlock(ctx);
	if (rc != LIBISCSI_OK) {
		iscsi_nodes_free(*nodes, *node_count);
		*nodes = NULL;
		*node_count = 0;
	}
	return rc;
}

void iscsi_nodes_free(struct iscsi_node **nodes, uint32_t node_count)
{
	uint32_t i = 0;

	if ((nodes == NULL) || (node_count == 0))
		return;

	for (i = 0; i < node_count; ++i)
		iscsi_node_free(nodes[i]);
	free (nodes);
}

void iscsi_node_free(struct iscsi_node *node)
{
	free(node);
}

const char *iscsi_node_dump_config(struct iscsi_node *node, bool show_secret)
{
	FILE *f = NULL;
	char *buff = NULL;

	assert(node != NULL);

	buff = calloc(1, IDBM_DUMP_SIZE);
	if (buff == NULL)
		return NULL;

	f = fmemopen(buff, IDBM_DUMP_SIZE - 1, "w");
	if (f == NULL) {
		free(buff);
		return NULL;
	}

	_idbm_node_print(node, f, show_secret);

	fclose(f);

	return buff;
}

void iscsi_node_print_config(struct iscsi_node *node, bool show_secret)
{
	assert(node != NULL);
	_idbm_node_print(node, stdout, show_secret);
}

// TODO(Gris Ge): Convert below duplicated codes to macros.
bool iscsi_node_conn_is_ipv6(struct iscsi_node *node)
{
	assert(node != NULL);
	return node->conn.is_ipv6;
}

const char *iscsi_node_conn_address_get(struct iscsi_node *node)
{
	assert(node != NULL);
	return node->conn.address;
}

uint32_t iscsi_node_conn_port_get(struct iscsi_node *node)
{
	assert(node != NULL);
	return node->conn.port;
}

int32_t iscsi_node_tpgt_get(struct iscsi_node *node)
{
	assert(node != NULL);
	return node->tpgt;
}

const char *iscsi_node_target_name_get(struct iscsi_node *node)
{
	assert(node != NULL);
	return node->target_name;
}

const char *iscsi_node_iface_name_get(struct iscsi_node *node)
{
	assert(node != NULL);
	return node->iface.name;
}

const char *iscsi_node_portal_get(struct iscsi_node *node)
{
	assert(node != NULL);
	return node->portal;
}
