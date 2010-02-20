/*
 * Local iSNS registration
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 *
 * The way isnsdd communicates with local services (initiator,
 * target) is via a file and signals. That sounds rather
 * awkward, but it's a lot simpler to add to these services
 * than another socket based communication mechanism I guess.
 *
 * The file format is simple:
 *  <object> owner=<owner>
 *  <object> owner=<owner>
 *  ...
 *
 * <owner> identifies the service owning these entries.
 * This is a service name, such as iscsid, tgtd, isnsdd,
 * optionally followed by a colon and a PID. This allows
 * removal of all entries created by one service in one go.
 *
 * <object> is the description of one iSNS object, using the
 * syntax used by all other open-isns apps.
 */

#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <limits.h>

#include <isns.h>
#include "security.h"
#include "util.h"
#include "isns-proto.h"
#include "paths.h"
#include "attrs.h"
#include "util.h"

typedef int __isns_local_registry_cb_fn_t(const char *line,
			int argc, char **argv,
			void *user_data);

/*
 * Build the owner=<svcname>:<pid> tag
 */
static const char *
__isns_local_registry_make_owner(const char *svcname, pid_t pid)
{
	static char owner[128];

	if (pid == 0) {
		return svcname;
	}
	snprintf(owner, sizeof(owner), "%s:%u", svcname, pid);
	return owner;
}

/*
 * Read the registry file, match each entry against the given owner=<foo> tag,
 * and invoke the callback function.
 * This is used for both reading the registry, and rewriting it.
 */
static int
__isns_local_registry_read(const char *match_owner,
			__isns_local_registry_cb_fn_t handle_matching,
			__isns_local_registry_cb_fn_t handle_nonmatching,
			void *user_data)
{
	const char	*filename = isns_config.ic_local_registry_file;
	char		*line, *copy = NULL;
	FILE		*fp;
	int		rv = 0, owner_len;

	if (!(fp = fopen(filename, "r"))) {
		if (errno == ENOENT) {
			isns_debug_state("Unable to open %s: %m\n", filename);
			return 1;
		}
		isns_error("Unable to open %s: %m\n", filename);
		return 0;
	}

	owner_len = match_owner? strlen(match_owner) : 0;
	while ((line = parser_get_next_line(fp)) != NULL) {
		__isns_local_registry_cb_fn_t *cb;
		char	*argv[256], *owner;
		int	argc = 0;

		isns_assign_string(&copy, line);

		argc = isns_attr_list_split(line, argv, 255);
		if (argc <= 0)
			continue;

		/* Last attr should be owner */
		if (strncasecmp(argv[argc-1], "owner=", 6)) {
			isns_error("%s: syntax error (missing owner field)\n",
					filename);
			goto out;
		}
		owner = argv[argc-1] + 6;

		if (!strncasecmp(owner, match_owner, owner_len)
		 && (owner[owner_len] == '\0' || owner[owner_len] == ':'))
			cb = handle_matching;
		else
			cb = handle_nonmatching;

		if (cb && !cb(copy, argc, argv, user_data))
			goto out;

	}
	rv = 1;

out:
	free(copy);
	fclose(fp);
	return rv;
}

/*
 * Open and lock the registry file for writing. Returns an
 * open stream and the name of the lock file.
 * Follow up with _finish_write when done.
 */
static FILE *
__isns_local_registry_open_write(char **lock_name)
{
	char	lock_path[PATH_MAX];
	FILE	*fp;
	int	fd, retry;

	snprintf(lock_path, sizeof(lock_path), "%s.lock",
			isns_config.ic_local_registry_file);

	for (retry = 0; retry < 5; ++retry) {
		fd = open(lock_path, O_RDWR|O_CREAT|O_EXCL, 0644);
		if (fd >= 0)
			break;
		if (errno != EEXIST) {
			isns_error("Unable to create %s: %m\n",
					lock_path);
			return NULL;
		}
		isns_error("Cannot lock %s - retry in 1 sec\n",
					isns_config.ic_local_registry_file);
		sleep(1);
	}

	if (!(fp = fdopen(fd, "w"))) {
		isns_error("fdopen failed: %m\n");
		close(fd);
		return NULL;
	}
	isns_assign_string(lock_name, lock_path);
	return fp;
}

/*
 * We're done with (re)writing the registry. Commit the changes,
 * or discard them.
 * Also frees the lock_name returned by registry_open_write.
 */
static int
__isns_local_registry_finish_write(FILE *fp, char *lock_name, int commit)
{
	int	rv = 1;

	fclose(fp);
	if (!commit) {
		if (unlink(lock_name))
			isns_error("Failed to unlink %s: %m\n", lock_name);
	} else
	if (rename(lock_name, isns_config.ic_local_registry_file)) {
		isns_error("Failed to rename %s to %s: %m\n",
				lock_name, isns_config.ic_local_registry_file);
		rv = 0;
	}

	free(lock_name);
	return rv;
}

/*
 * Get the entity name for this service
 */
static char *
__isns_local_registry_entity_name(const char *owner)
{
	static char	namebuf[1024];

	snprintf(namebuf, sizeof(namebuf), "%s:%s",
			isns_config.ic_entity_name,
			owner);
	return namebuf;
}

/*
 * Callback function which builds an iSNS object from the
 * list of attr=tag values.
 */
static int
__isns_local_registry_load_object(const char *line,
		int argc, char **argv, void *user_data)
{
	isns_attr_list_t attrs = ISNS_ATTR_LIST_INIT;
	struct isns_attr_list_parser state;
	isns_object_list_t *list = user_data;
	isns_object_t *obj, *entity = NULL;

	for (; argc > 0; --argc) {
		char	*attr = argv[argc-1];

		if (!strncasecmp(attr, "owner=", 6)) {
			char *eid = __isns_local_registry_entity_name(attr + 6);
			ISNS_QUICK_ATTR_LIST_DECLARE(key_attrs,
					ISNS_TAG_ENTITY_IDENTIFIER,
					string, eid);

			if (entity) {
				isns_error("Duplicate owner entry in registry\n");
				continue;
			}
			isns_attr_print(&key_attrs.iqa_attr, isns_print_stdout);
			entity = isns_object_list_lookup(list,
					&isns_entity_template,
					&key_attrs.iqa_list);
			if (entity != NULL)
				continue;

			isns_debug_state("Creating fake entity %s\n", eid);
			entity = isns_create_entity(ISNS_ENTITY_PROTOCOL_ISCSI, eid);
			isns_object_list_append(list, entity);
		} else {
			break;
		}
	}

	isns_attr_list_parser_init(&state, NULL);
	if (!isns_parse_attrs(argc, argv, &attrs, &state)) {
		isns_error("Unable to parse attrs\n");
		isns_attr_list_destroy(&attrs);
		return 0;
	}

	obj = isns_create_object(isns_attr_list_parser_context(&state),
					&attrs, entity);
	isns_attr_list_destroy(&attrs);

	if (obj == NULL) {
		isns_error("Unable to create object\n");
		return 0;
	}

	isns_object_list_append(list, obj);
	return 1;
}

/*
 * Callback function that simply writes out the line as-is
 */
static int
__isns_local_registry_rewrite_object(const char *line,
		int argc, char **argv, void *user_data)
{
	FILE	*ofp = user_data;

	fprintf(ofp, "%s\n", line);
	return 1;
}

/*
 * Load all objects owner by a specific service from the local registry.
 * If the svcname starts with "!", all entries except those matching this
 * particular service are returned.
 */
int
isns_local_registry_load(const char *svcname, pid_t pid, isns_object_list_t *objs)
{
	__isns_local_registry_cb_fn_t *if_matching = NULL, *if_nonmatching = NULL;

	if (svcname == NULL) {
		isns_error("%s: no svcname given\n", __FUNCTION__);
		return 0;
	}
	if (*svcname == '!') {
		if_nonmatching = __isns_local_registry_load_object;
		svcname++;
	} else {
		if_matching = __isns_local_registry_load_object;
	}

	return __isns_local_registry_read(
			__isns_local_registry_make_owner(svcname, pid),
			if_matching, if_nonmatching, objs);
}

/*
 * Store the given list of objects in the registry.
 * This replaces all objects previously registered by this service.
 */
int
isns_local_registry_store(const char *svcname, pid_t pid, const isns_object_list_t *objs)
{
	const char *owner = __isns_local_registry_make_owner(svcname, pid);
	char	*lock_name = NULL;
	FILE	*ofp;

	if (!(ofp = __isns_local_registry_open_write(&lock_name))) {
		isns_error("%s: could not open registry for writing\n", __FUNCTION__);
		return 0;
	}

	/* First, purge all entries previously belonging to this owner */
	if (!__isns_local_registry_read(owner, NULL, __isns_local_registry_rewrite_object, ofp))
		goto failed;

	if (objs) {
		unsigned int	i;

		for (i = 0; i < objs->iol_count; ++i) {
			isns_object_t *obj = objs->iol_data[i];
			char *argv[256];
			int i, argc;

			argc = isns_print_attrs(obj, argv, 256);
			for (i = 0; i < argc; ++i)
				fprintf(ofp, "%s ", argv[i]);
			fprintf(ofp, "owner=%s\n", owner);
		}
	}

	return __isns_local_registry_finish_write(ofp, lock_name, 1);

failed:
	isns_error("%s: error rewriting registry file\n", __FUNCTION__);
	__isns_local_registry_finish_write(ofp, lock_name, 0);
	return 0;
}

/*
 * Purge the local registry of all objects owned by the
 * given service.
 */
int
isns_local_registry_purge(const char *svcname, pid_t pid)
{
	return isns_local_registry_store(svcname, pid, NULL);
}
