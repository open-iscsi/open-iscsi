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
#define _GNU_SOURCE			/* For NI_MAXHOST */
#endif

#ifndef __ISCSI_USR_NODE_H__
#define __ISCSI_USR_NODE_H__

#include <netdb.h>
#include <stdint.h>

#include "idbm.h"
#include "iface.h"

struct iscsi_node {
	char					target_name[TARGET_NAME_MAXLEN];
	int32_t					tpgt;
	enum iscsi_startup_type			startup;
	enum leading_login_type			leading_login;
	struct iscsi_session_idbm		session;
	struct iscsi_conn			conn;
	struct iscsi_iface			iface;
	enum discovery_type			disc_type;
	char					disc_address[NI_MAXHOST];
	int32_t					disc_port;
	char					portal[NI_MAXHOST * 2];
};

#define NODE_CONFIG_DIR		ISCSI_DB_ROOT"/nodes"

/* Might be public in the future */
__DLL_LOCAL void iscsi_node_free(struct iscsi_node *node);

#endif /* End of __ISCSI_USR_NODE_H__ */
