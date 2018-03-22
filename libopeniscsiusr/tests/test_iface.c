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
 * along with this program.  If not, see <http://www.gnu.org/licenifaces/>.
 *
 * Author: Gris Ge <fge@redhat.com>
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <assert.h>

#include <libopeniscsiusr/libopeniscsiusr.h>

#define _assert_print_prop_str_can_empty(struct_name, obj, prop_name) \
	do { \
		assert(struct_name##_##prop_name##_get(obj) != NULL); \
		printf("\t" # prop_name ": '%s'\n", \
		       struct_name##_##prop_name##_get(obj)); \
	} while(0)

#define _assert_print_prop_str_not_empty(struct_name, obj, prop_name) \
	do { \
		assert(struct_name##_##prop_name##_get(obj) != NULL); \
		assert(strlen(struct_name##_##prop_name##_get(obj)) != 0); \
		printf("\t" # prop_name ": '%s'\n", \
		       struct_name##_##prop_name##_get(obj)); \
	} while(0)

static void test_iface(struct iscsi_context *ctx, struct iscsi_iface *iface)
{
	struct iscsi_iface *tmp_iface = NULL;
	const char *conf = NULL;

	assert(iface != NULL);
	printf("\t#### Interface info ####\n");
	_assert_print_prop_str_not_empty(iscsi_iface, iface, name);
	if (! iscsi_is_default_iface(iface)) {
		assert(iscsi_iface_get(ctx, iscsi_iface_name_get(iface),
				       &tmp_iface) == LIBISCSI_OK);
		_assert_print_prop_str_can_empty(iscsi_iface, tmp_iface,
						 ipaddress);
		_assert_print_prop_str_can_empty(iscsi_iface, tmp_iface,
						 transport_name);
		_assert_print_prop_str_can_empty(iscsi_iface, tmp_iface, iname);
		_assert_print_prop_str_can_empty(iscsi_iface, tmp_iface,
						 hwaddress);
		_assert_print_prop_str_can_empty(iscsi_iface, tmp_iface,
						 netdev);
		_assert_print_prop_str_can_empty(iscsi_iface, tmp_iface,
						 port_state);
		_assert_print_prop_str_can_empty(iscsi_iface, tmp_iface,
						 port_speed);
		iscsi_iface_free(tmp_iface);
	}
	printf("\t########################\n");

	conf = iscsi_iface_dump_config(iface);
	assert(conf != NULL);
	free((char *) conf);
	iscsi_iface_print_config(iface);
}

int main()
{
	struct iscsi_context *ctx = NULL;
	struct iscsi_iface **ifaces = NULL;
	uint32_t iface_count = 0;
	uint32_t i = 0;
	int rc = EXIT_SUCCESS;

	ctx = iscsi_context_new();
	iscsi_context_log_priority_set(ctx, LIBISCSI_LOG_PRIORITY_DEBUG);

	if (iscsi_default_iface_setup(ctx) != LIBISCSI_OK) {
		printf("FAILED\n");
		rc = EXIT_FAILURE;
	}

	if (iscsi_ifaces_get(ctx, &ifaces, &iface_count) != LIBISCSI_OK) {
		printf("FAILED\n");
		rc = EXIT_FAILURE;
	} else {
		assert(iface_count >= 2);
		/* we will have at least the default ifaces:
		 * iser and iscsi_tcp
		 */
		printf("\nGot %" PRIu32 " iSCSI ifaces\n", iface_count);
		for (i = 0; i < iface_count; ++i) {
			test_iface(ctx, ifaces[i]);
		}
		iscsi_ifaces_free(ifaces, iface_count);
	}
	iscsi_context_free(ctx);
	exit(rc);
}
