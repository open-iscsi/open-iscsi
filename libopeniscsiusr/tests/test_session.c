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

#define _assert_print_prop_u32_not_zero(struct_name, obj, prop_name) \
	do { \
		assert(struct_name##_##prop_name##_get(obj) != 0); \
		printf("\t" # prop_name ": %" PRIu32 "\n", \
		       struct_name##_##prop_name##_get(obj)); \
	} while(0)

#define _assert_print_prop_i32_not_zero(struct_name, obj, prop_name) \
	do { \
		assert(struct_name##_##prop_name##_get(obj) != 0); \
		printf("\t" # prop_name ": %" PRIi32 "\n", \
		       struct_name##_##prop_name##_get(obj)); \
	} while(0)

static void test_session(struct iscsi_session *se);
static void test_iface(struct iscsi_iface *iface);

static void test_iface(struct iscsi_iface *iface)
{
	assert(iface != NULL);
	printf("\t#### Interface info ####\n");
	_assert_print_prop_str_not_empty(iscsi_iface, iface, name);
	_assert_print_prop_str_not_empty(iscsi_iface, iface, ipaddress);
	_assert_print_prop_str_not_empty(iscsi_iface, iface, transport_name);
	_assert_print_prop_str_not_empty(iscsi_iface, iface, iname);
	_assert_print_prop_str_can_empty(iscsi_iface, iface, hwaddress);
	_assert_print_prop_str_can_empty(iscsi_iface, iface, netdev);
	_assert_print_prop_str_can_empty(iscsi_iface, iface, port_state);
	_assert_print_prop_str_can_empty(iscsi_iface, iface, port_speed);
	printf("\t########################\n");
}

static void test_session(struct iscsi_session *se)
{
	assert(se != NULL);
	printf("Session %" PRIu32 ":\n", iscsi_session_sid_get(se));

	_assert_print_prop_u32_not_zero(iscsi_session, se, sid);
	_assert_print_prop_str_not_empty(iscsi_session, se, persistent_address);
	_assert_print_prop_i32_not_zero(iscsi_session, se, persistent_port);
	_assert_print_prop_str_not_empty(iscsi_session, se, target_name);
	_assert_print_prop_str_can_empty(iscsi_session, se, username);
	_assert_print_prop_str_can_empty(iscsi_session, se, password);
	_assert_print_prop_str_can_empty(iscsi_session, se, username_in);
	_assert_print_prop_str_can_empty(iscsi_session, se, password_in);
	_assert_print_prop_u32_not_zero(iscsi_session, se, recovery_tmo);
	_assert_print_prop_u32_not_zero(iscsi_session, se, lu_reset_tmo);
	_assert_print_prop_u32_not_zero(iscsi_session, se, tgt_reset_tmo);
	_assert_print_prop_u32_not_zero(iscsi_session, se, abort_tmo);
	_assert_print_prop_u32_not_zero(iscsi_session, se, tpgt);
	_assert_print_prop_str_not_empty(iscsi_session, se, address);
	_assert_print_prop_i32_not_zero(iscsi_session, se, port);
}

int main()
{
	struct iscsi_context *ctx = NULL;
	struct iscsi_session **ses = NULL;
	uint32_t se_count = 0;
	uint32_t i = 0;
	int rc = EXIT_SUCCESS;

	ctx = iscsi_context_new();
	iscsi_context_log_priority_set(ctx, LIBISCSI_LOG_PRIORITY_DEBUG);

	if (iscsi_sessions_get(ctx, &ses, &se_count) != LIBISCSI_OK) {
		printf("FAILED\n");
		rc = EXIT_FAILURE;
	} else {
		printf("\nGot %" PRIu32 " iSCSI sessions\n", se_count);
		for (i = 0; i < se_count; ++i) {
			test_session(ses[i]);
			test_iface(iscsi_session_iface_get(ses[i]));
		}
		iscsi_sessions_free(ses, se_count);
	}
	iscsi_context_free(ctx);
	exit(rc);
}
