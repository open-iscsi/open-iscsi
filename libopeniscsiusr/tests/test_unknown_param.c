/*
 * Copyright (C) 2026 Chris Stosgale
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * Regression test for node record forward compatibility.
 *
 * A node record may have been written by a newer open-iscsi than the
 * libopeniscsiusr reading it, so it can contain parameter names this
 * version does not know yet.  Such a parameter must be warned about and
 * skipped; it must not invalidate the whole record.  Otherwise every node
 * disappears from "iscsiadm -m node" (which then reports
 * ISCSI_ERR_NO_OBJS_FOUND, exit 21) even though the record is perfectly
 * usable.
 *
 * This is not theoretical: node.session.login_redirect_max and
 * node.session.sess_reopen_log_freq were added after 2.1.9, and a 2.1.9
 * library rejected every record written by a newer binary, which took 15
 * volumes offline.  Commit 8112cdd ("Fix reopen log freq change") made
 * unknown parameter names non-fatal; this test makes sure that behaviour
 * stays.
 *
 * A known parameter carrying an invalid value must still be rejected, or
 * typos would silently fall back to defaults.
 *
 * The library linked into this test is built with ISCSI_DB_ROOT pointing
 * into the build directory (see meson.build and Makefile), so the test can
 * write its own node record without touching the system database.  Like the
 * other libopeniscsiusr tests, it needs a writable LOCK_DIR
 * (/run/lock/iscsi), i.e. it normally runs as root.
 */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <libopeniscsiusr/libopeniscsiusr.h>

#define TEST_TARGET	"iqn.2026-10.com.example:unknown-param"
#define TEST_ADDRESS	"192.168.0.90"
#define TEST_PORT	3260
#define TEST_TPGT	1
#define TEST_IFACE	"default"
#define TEST_FIRST_BURST_LENGTH	65536

/* mkdir -p */
static int mkdir_p(const char *path)
{
	char buff[4096];
	char *p = NULL;
	size_t len = 0;

	len = strlen(path);
	if ((len == 0) || (len >= sizeof(buff))) {
		fprintf(stderr, "invalid path '%s'\n", path);
		return -1;
	}
	memcpy(buff, path, len + 1);

	for (p = buff + 1; *p != '\0'; p++) {
		if (*p != '/')
			continue;
		*p = '\0';
		if ((mkdir(buff, 0755) != 0) && (errno != EEXIST)) {
			fprintf(stderr, "mkdir '%s': %s\n", buff,
				strerror(errno));
			return -1;
		}
		*p = '/';
	}
	if ((mkdir(buff, 0755) != 0) && (errno != EEXIST)) {
		fprintf(stderr, "mkdir '%s': %s\n", buff, strerror(errno));
		return -1;
	}
	return 0;
}

static void record_path(char *path, size_t path_size, const char *dbroot)
{
	snprintf(path, path_size, "%s/nodes/%s/%s,%d,%d/%s", dbroot,
		 TEST_TARGET, TEST_ADDRESS, TEST_PORT, TEST_TPGT,
		 TEST_IFACE);
}

/*
 * Write <dbroot>/nodes/<target>/<address>,<port>,<tpgt>/<iface>, i.e. the
 * layout iscsiadm uses, with the given extra lines inserted in the middle
 * of the record.
 */
static int write_record(const char *dbroot, const char *extra)
{
	char dir[4096];
	char path[4096];
	FILE *f = NULL;

	snprintf(dir, sizeof(dir), "%s/nodes/%s/%s,%d,%d", dbroot,
		 TEST_TARGET, TEST_ADDRESS, TEST_PORT, TEST_TPGT);
	if (mkdir_p(dir) != 0)
		return -1;

	record_path(path, sizeof(path), dbroot);
	f = fopen(path, "w");
	if (f == NULL) {
		fprintf(stderr, "fopen '%s': %s\n", path, strerror(errno));
		return -1;
	}

	fprintf(f,
		"# BEGIN RECORD 2.1.13\n"
		"node.name = %s\n"
		"node.tpgt = %d\n"
		"node.startup = manual\n"
		"node.discovery_type = static\n"
		"iface.iscsi_ifacename = %s\n"
		"iface.transport_name = tcp\n"
		"node.session.timeo.replacement_timeout = 120\n"
		"node.session.login_redirect_max = 3\n"
		"%s"
		"node.session.iscsi.FirstBurstLength = %d\n"
		"node.conn[0].address = %s\n"
		"node.conn[0].port = %d\n"
		"# END RECORD\n",
		TEST_TARGET, TEST_TPGT, TEST_IFACE, extra,
		TEST_FIRST_BURST_LENGTH, TEST_ADDRESS, TEST_PORT);

	if (fclose(f) != 0) {
		fprintf(stderr, "fclose '%s': %s\n", path, strerror(errno));
		return -1;
	}
	return 0;
}

static void remove_record(const char *dbroot)
{
	char path[4096];

	record_path(path, sizeof(path), dbroot);
	unlink(path);
	snprintf(path, sizeof(path), "%s/nodes/%s/%s,%d,%d", dbroot,
		 TEST_TARGET, TEST_ADDRESS, TEST_PORT, TEST_TPGT);
	rmdir(path);
	snprintf(path, sizeof(path), "%s/nodes/%s", dbroot, TEST_TARGET);
	rmdir(path);
}

/*
 * Read back the record and make sure it survived intact.
 *
 * The parameter set on the line after the unknown one (FirstBurstLength) is
 * checked explicitly: it proves that parsing continued instead of stopping
 * at the unknown parameter.
 */
static int check_forward_compatible_record(struct iscsi_context *ctx)
{
	struct iscsi_node **nodes = NULL;
	uint32_t node_count = 0;
	const char *dump = NULL;
	int rc = EXIT_FAILURE;

	if (iscsi_nodes_get(ctx, &nodes, &node_count) != LIBISCSI_OK) {
		fprintf(stderr, "FAIL: iscsi_nodes_get() rejected a record "
			"containing an unknown parameter\n");
		return EXIT_FAILURE;
	}
	if (node_count != 1) {
		fprintf(stderr, "FAIL: expected 1 node, got %u\n", node_count);
		goto out;
	}
	if (strcmp(iscsi_node_target_name_get(nodes[0]), TEST_TARGET) != 0) {
		fprintf(stderr, "FAIL: unexpected target name '%s'\n",
			iscsi_node_target_name_get(nodes[0]));
		goto out;
	}
	if (iscsi_node_tpgt_get(nodes[0]) != TEST_TPGT) {
		fprintf(stderr, "FAIL: expected tpgt %d, got %d\n", TEST_TPGT,
			iscsi_node_tpgt_get(nodes[0]));
		goto out;
	}
	if (iscsi_node_conn_port_get(nodes[0]) != TEST_PORT) {
		fprintf(stderr, "FAIL: expected port %d, got %u\n", TEST_PORT,
			iscsi_node_conn_port_get(nodes[0]));
		goto out;
	}
	if (strcmp(iscsi_node_conn_address_get(nodes[0]), TEST_ADDRESS) != 0) {
		fprintf(stderr, "FAIL: unexpected address '%s'\n",
			iscsi_node_conn_address_get(nodes[0]));
		goto out;
	}

	dump = iscsi_node_dump_config(nodes[0], true);
	if (dump == NULL) {
		fprintf(stderr, "FAIL: iscsi_node_dump_config() failed\n");
		goto out;
	}
	if (strstr(dump,
		   "node.session.timeo.replacement_timeout = 120") == NULL) {
		fprintf(stderr, "FAIL: known parameter before the unknown one "
			"was not parsed\n");
		goto out;
	}
	if (strstr(dump, "node.session.login_redirect_max = 3") == NULL) {
		fprintf(stderr, "FAIL: node.session.login_redirect_max was not "
			"parsed\n");
		goto out;
	}
	if (strstr(dump,
		   "node.session.iscsi.FirstBurstLength = 65536") == NULL) {
		fprintf(stderr, "FAIL: parameter after the unknown one was not "
			"parsed\n");
		goto out;
	}
	if (strstr(dump, "not_a_real_key") != NULL) {
		fprintf(stderr, "FAIL: unknown parameter was kept in the "
			"record\n");
		goto out;
	}

	rc = EXIT_SUCCESS;

out:
	free((void *)dump);
	iscsi_nodes_free(nodes, node_count);
	return rc;
}

/* A known parameter with a value we do not understand is still an error. */
static int check_invalid_value_rejected(struct iscsi_context *ctx)
{
	struct iscsi_node **nodes = NULL;
	uint32_t node_count = 0;
	int rc = EXIT_SUCCESS;

	if (iscsi_nodes_get(ctx, &nodes, &node_count) == LIBISCSI_OK) {
		fprintf(stderr, "FAIL: invalid value for a known parameter was "
			"accepted\n");
		rc = EXIT_FAILURE;
	} else if (node_count != 0) {
		fprintf(stderr, "FAIL: expected 0 nodes after an invalid "
			"record, got %u\n", node_count);
		rc = EXIT_FAILURE;
	}

	iscsi_nodes_free(nodes, node_count);
	return rc;
}

int main(void)
{
	const char *dbroot = getenv("ISCSI_TEST_DBROOT");
	struct iscsi_context *ctx = NULL;
	int rc = EXIT_FAILURE;

	if (dbroot == NULL) {
		fprintf(stderr, "ISCSI_TEST_DBROOT is not set\n");
		return EXIT_FAILURE;
	}

	ctx = iscsi_context_new();
	if (ctx == NULL) {
		fprintf(stderr, "FAIL: iscsi_context_new() failed\n");
		return EXIT_FAILURE;
	}
	iscsi_context_log_priority_set(ctx, LIBISCSI_LOG_PRIORITY_WARNING);

	if (write_record(dbroot, "node.session.not_a_real_key = 7\n") != 0)
		goto out;
	if (check_forward_compatible_record(ctx) != EXIT_SUCCESS)
		goto out;
	if (write_record(dbroot, "node.startup = not_a_valid_startup\n") != 0)
		goto out;
	if (check_invalid_value_rejected(ctx) != EXIT_SUCCESS)
		goto out;

	printf("PASS: unknown parameter names are skipped, known parameters "
	       "with invalid values are still rejected\n");
	rc = EXIT_SUCCESS;

out:
	remove_record(dbroot);
	iscsi_context_free(ctx);
	return rc;
}
