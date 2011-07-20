/*
 * iSNS object database
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

#include "isns.h"
#include "objects.h"
#include "message.h"
#include "util.h"
#include "db.h"

#define DBE_FILE_VERSION	1

struct isns_db_file_info {
	uint32_t	db_version;
	uint32_t	db_last_eid;
	uint32_t	db_last_index;
};

struct isns_db_object_info {
	uint32_t	db_version;
	char		db_type[64];
	uint32_t	db_parent;
	uint32_t	db_state;
	uint32_t	db_flags;
	uint32_t	db_scn_mask;
	/* reserved bytes */
	uint32_t	__db_reserved[15];
};

static int	isns_dbe_file_sync(isns_db_t *);
static int	isns_dbe_file_reload(isns_db_t *);
static int	isns_dbe_file_store(isns_db_t *,
				const isns_object_t *);
static int	isns_dbe_file_remove(isns_db_t *,
				const isns_object_t *);
static int	__dbe_file_load_all(const char *,
				isns_object_list_t *);

/*
 * Helper functions
 */
static const char *
__path_concat(const char *dirname, const char *basename)
{
	static char	pathname[PATH_MAX];

	snprintf(pathname, sizeof(pathname), "%s/%s",
			dirname, basename);
	return pathname;
}

static const char *
__print_index(uint32_t index)
{
	static char	namebuf[32];

	snprintf(namebuf, sizeof(namebuf), "%08x", index);
	return namebuf;
}

static int
__get_index(const char *name, uint32_t *result)
{
	char	*end;

	*result = strtoul(name, &end, 16);
	if (*end)
		return ISNS_INTERNAL_ERROR;
	return ISNS_SUCCESS;
}

/*
 * Build path names for an object
 */
static const char *
__dbe_file_object_path(const char *dirname, const isns_object_t *obj)
{
	return __path_concat(dirname, __print_index(obj->ie_index));
}

/*
 * Build a path name for a temporary file.
 * Cannot use __path_concat, because we need both names
 * when storing objects
 */
static const char *
__dbe_file_object_temp(const char *dirname, const isns_object_t *obj)
{
	static char	pathname[PATH_MAX];

	snprintf(pathname, sizeof(pathname), "%s/.%s",
			dirname, __print_index(obj->ie_index));
	return pathname;
}

/*
 * Recursively create a directory
 */
static int
__dbe_mkdir_path(const char *dirname)
{
	unsigned int true_len = strlen(dirname);
	char	*copy, *s;

	copy = isns_strdup(dirname);
	
	/* Walk up until we find a directory that exists */
	while (1) {
		s = strrchr(copy, '/');
		if (s == NULL)
			break;

		*s = '\0';
		if (access(copy, F_OK) == 0)
			break;
	}

	while (strcmp(dirname, copy)) {
		unsigned int len = strlen(copy);

		/* Better safe than sorry */
		isns_assert(len < true_len);

		/* Put the next slash back in */
		copy[len] = '/';

		/* and try to create the directory */
		if (mkdir(copy, 0700) < 0)
			return -1;
	}

	return 0;
}

/*
 * Write an object to a file
 */
static int
__dbe_file_store_object(const char *dirname, const isns_object_t *obj)
{
	struct isns_db_object_info info;
	const char	*path = __dbe_file_object_path(dirname, obj);
	const char	*temp = __dbe_file_object_temp(dirname, obj);
	buf_t		*bp = NULL;
	int		status = ISNS_INTERNAL_ERROR;

	isns_debug_state("DB: Storing object %u -> %s\n", obj->ie_index, path);
	if (access(dirname, F_OK) < 0
	 && (errno != ENOENT || __dbe_mkdir_path(dirname) < 0)) {
		isns_error("DB: Unable to create %s: %m\n",
				dirname);
		goto out;
	}

	bp = buf_open(temp, O_CREAT|O_TRUNC|O_WRONLY);
	if (bp == NULL) {
		isns_error("Unable to open %s: %m\n", temp);
		goto out;
	}

	/* Encode the header info ... */
	memset(&info, 0, sizeof(info));
	info.db_version = htonl(DBE_FILE_VERSION);
	info.db_state = htonl(obj->ie_state);
	info.db_flags = htonl(obj->ie_flags);
	info.db_scn_mask = htonl(obj->ie_scn_mask);
	strcpy(info.db_type, obj->ie_template->iot_name);
	if (obj->ie_container)
		info.db_parent = htonl(obj->ie_container->ie_index);

	if (!buf_put(bp, &info, sizeof(info)))
		goto out;

	/* ... and attributes */
	status = isns_attr_list_encode(bp, &obj->ie_attrs);
	if (status != ISNS_SUCCESS)
		goto out;

	/* Renaming an open file. NFS will hate this */
	if (rename(temp, path) < 0) {
		isns_error("Cannot rename %s -> %s: %m\n",
				temp, path);
		unlink(temp);
		status = ISNS_INTERNAL_ERROR;
	}

out:
	if (bp)
		buf_close(bp);
	return status;
}

/*
 * Store all children of an object
 */
static int
__dbe_file_store_children(const char *dirname, const isns_object_t *obj)
{
	int		status = ISNS_SUCCESS;
	unsigned int	i;

	for (i = 0; i < obj->ie_children.iol_count; ++i) {
		isns_object_t	*child;

		child = obj->ie_children.iol_data[i];
		status = __dbe_file_store_object(dirname, child);
		if (status)
			break;
		status = __dbe_file_store_children(dirname, child);
		if (status)
			break;
	}

	return status;
}

/*
 * Remove object and children
 */
static int
__dbe_file_remove_object(const char *dirname, const isns_object_t *obj)
{
	const char	*path = __dbe_file_object_path(dirname, obj);

	isns_debug_state("DB: Purging object %u (%s)\n", obj->ie_index, path);
	if (unlink(path) < 0)
		isns_error("DB: Cannot remove %s: %m\n", path);
	return ISNS_SUCCESS;
}

static int
__dbe_file_remove_children(const char *dirname, const isns_object_t *obj)
{
	const isns_object_list_t *list = &obj->ie_children;
	unsigned int	i;

	for (i = 0; i < list->iol_count; ++i)
		__dbe_file_remove_object(dirname, list->iol_data[i]);

	return ISNS_SUCCESS;
}

/*
 * Load an object from file
 */
static int
__dbe_file_load_object(const char *filename, const char *basename,
		isns_object_list_t *result)
{
	struct isns_db_object_info info;
	isns_attr_list_t attrs = ISNS_ATTR_LIST_INIT;
	isns_object_template_t *tmpl;
	isns_object_t	*obj = NULL;
	buf_t		*bp = NULL;
	uint32_t	index;
	int		status;

	bp = buf_open(filename, O_RDONLY);
	if (bp == NULL) {
		isns_error("Unable to open %s: %m\n", filename);
		goto internal_error;
	}

	/* Decode the header ... */
	if (!buf_get(bp, &info, sizeof(info)))
		goto internal_error;
	if (info.db_version != htonl(DBE_FILE_VERSION)) {
		/* If we ever have to deal with a DB version
		 * upgrade, we could do it here. */
		isns_fatal("Found iSNS database version %u; not supported\n",
				ntohl(info.db_version));
	}

	/* ... and attributes */
	status = isns_attr_list_decode(bp, &attrs);
	if (status != ISNS_SUCCESS)
		goto out;

	/* Get the index from the file name */
	status = __get_index(basename, &index);
	if (status != ISNS_SUCCESS)
		goto out;

	tmpl = isns_object_template_by_name(info.db_type);
	if (tmpl == NULL) {
		isns_error("DB: Bad type name \"%s\" in object file\n",
				info.db_type);
		goto internal_error;
	}

	obj = isns_create_object(tmpl, &attrs, NULL);
	if (obj == NULL)
		goto internal_error;

	obj->ie_state = ntohl(info.db_state);
	obj->ie_flags = ntohl(info.db_flags) & ~(ISNS_OBJECT_DIRTY);
	obj->ie_scn_mask = ntohl(info.db_scn_mask);
	obj->ie_index = index;

	/* Stash away the parent's index; we resolve them later on
	 * once we've loaded all objects */
	obj->ie_container_idx = ntohl(info.db_parent);

	isns_object_list_append(result, obj);

out:
	if (bp)
		buf_close(bp);
	if (obj)
		isns_object_release(obj);
	isns_attr_list_destroy(&attrs);
	return status;

internal_error:
	isns_error("Unable to load %s: Internal error\n",
			filename);
	status = ISNS_INTERNAL_ERROR;
	goto out;
}

/*
 * Load contents of directory into our database.
 *
 * We take two passes over the directory. In the first pass, we load
 * all regular files containing objects. The file names correspond to
 * the DB index.
 *
 * In the second pass, we load all directories, containing children of
 * an object. The directories names are formed by the object's index,
 * with ".d" appended to it.
 */
static int
__dbe_file_load_all(const char *dirpath, isns_object_list_t *result)
{
	struct dirent *dp;
	DIR	*dir;
	int	status = ISNS_SUCCESS;

	if ((dir = opendir(dirpath)) == NULL) {
		isns_error("DB: cannot open %s: %m\n", dirpath);
		return ISNS_INTERNAL_ERROR;
	}

	while ((dp = readdir(dir)) != NULL) {
		struct stat	stb;
		const char	*path;

		if (dp->d_name[0] == '.'
		 || !strcmp(dp->d_name, "DB"))
			continue;

		path = __path_concat(dirpath, dp->d_name);
		if (lstat(path, &stb) < 0) {
			isns_error("DB: cannot stat %s: %m\n", path);
			status = ISNS_INTERNAL_ERROR;
		} else
		if (S_ISREG(stb.st_mode)) {
			status = __dbe_file_load_object(path,
					dp->d_name, result);
		} else {
			isns_debug_state("DB: ignoring %s\n", path);
		}

		if (status != ISNS_SUCCESS)
			break;
	}

	closedir(dir);
	return status;
}

/*
 * Load and store DB metadata
 */
static int
__dbe_file_write_info(isns_db_t *db)
{
	isns_db_backend_t *back = db->id_backend;
	const char	*path;
	buf_t		*bp;
	int		status = ISNS_INTERNAL_ERROR;

	path = __path_concat(back->idb_name, "DB");
	if ((bp = buf_open(path, O_CREAT|O_TRUNC|O_WRONLY)) == NULL) {
		isns_error("Unable to write %s: %m\n", path);
		goto out;
	}

	if (buf_put32(bp, DBE_FILE_VERSION)
	 && buf_put32(bp, db->id_last_eid)
	 && buf_put32(bp, db->id_last_index))
		status = ISNS_SUCCESS;

out:
	if (bp)
		buf_close(bp);
	return status;
}

static int
__dbe_file_load_info(isns_db_t *db)
{
	isns_db_backend_t *back = db->id_backend;
	struct isns_db_file_info info;
	const char	*path;
	buf_t		*bp = NULL;
	int		status;

	path = __path_concat(back->idb_name, "DB");
	if ((bp = buf_open(path, O_RDONLY)) == NULL) {
		status = ISNS_NO_SUCH_ENTRY;
		goto out;
	}

	status = ISNS_INTERNAL_ERROR;
	if (!buf_get32(bp, &info.db_version))
		goto out;

	if (info.db_version != DBE_FILE_VERSION) {
		isns_error("DB file from unsupported version %04x\n",
				info.db_version);
		goto out;
	}

	if (buf_get32(bp, &info.db_last_eid)
	 && buf_get32(bp, &info.db_last_index)) {
		db->id_last_eid = info.db_last_eid;
		db->id_last_index = info.db_last_index;
		status = ISNS_SUCCESS;
	}

out:
	if (bp)
		buf_close(bp);
	return status;
}

/*
 * Find object with the given index.
 */
static isns_object_t *
__dbe_find_object(isns_object_list_t *list, uint32_t index)
{
	unsigned int	i;

	for (i = 0; i < list->iol_count; ++i) {
		isns_object_t	*obj = list->iol_data[i];

		if (obj->ie_index == index)
			return obj;
	}
	return NULL;
}

int
isns_dbe_file_reload(isns_db_t *db)
{
	isns_db_backend_t *back = db->id_backend;
	int		status;
	unsigned int	i;

	isns_debug_state("DB: loading all objects from %s\n",
			back->idb_name);

	if (access(back->idb_name, R_OK) < 0) {
		if (errno == ENOENT) {
			/* Empty database is okay */
			return ISNS_NO_SUCH_ENTRY;
		}
		isns_error("Cannot open database %s: %m\n", back->idb_name);
		return ISNS_INTERNAL_ERROR;
	}

	status = __dbe_file_load_info(db);
	if (status)
		return status;

	status = __dbe_file_load_all(back->idb_name, db->id_objects);
	if (status)
		return status;

	/* Resolve parent/child relationship for all nodes */
	for (i = 0; i < db->id_objects->iol_count; ++i) {
		isns_object_t	*obj = db->id_objects->iol_data[i];
		uint32_t	index = obj->ie_container_idx;
		isns_object_t	*parent;

		if (index == 0)
			continue;

		obj->ie_container = NULL;

		parent = __dbe_find_object(db->id_objects, index);
		if (parent == NULL) {
			isns_warning("DB: object %u references "
					"unknown container %u\n",
					obj->ie_index,
					index);
		} else {
			isns_object_attach(obj, parent);
		}
	}

	/* Add objects to the appropriate lists */
	for (i = 0; i < db->id_objects->iol_count; ++i) {
		isns_object_template_t *tmpl;
		isns_object_t	*obj = db->id_objects->iol_data[i];

		switch (obj->ie_state) {
		case ISNS_OBJECT_STATE_MATURE:
			isns_scope_add(db->id_global_scope, obj);
			obj->ie_references++;

			tmpl = obj->ie_template;
			if (tmpl->iot_build_relation
			 && !tmpl->iot_build_relation(db, obj, NULL))
				isns_warning("DB: cannot build relation for "
						"object %u\n",
						obj->ie_index);

			if (obj->ie_relation)
				isns_relation_add(db->id_relations,
						obj->ie_relation);

			if (ISNS_IS_ENTITY(obj))
				isns_esi_register(obj);
			break;

		case ISNS_OBJECT_STATE_LIMBO:
			isns_object_list_append(&db->id_limbo, obj);
			break;

		default:
			isns_error("Unexpected object state %d in object %u "
				"loaded from %s\n",
				obj->ie_state, obj->ie_index,
				back->idb_name);
		}

		/* Clear the dirty flag, which will be set when the
		   object is created. */
		obj->ie_flags &= ~ISNS_OBJECT_DIRTY;
	}

	return ISNS_SUCCESS;
}

int
isns_dbe_file_sync(isns_db_t *db)
{
	return __dbe_file_write_info(db);
}

int
isns_dbe_file_store(isns_db_t *db, const isns_object_t *obj)
{
	isns_db_backend_t *back = db->id_backend;
	int		status;

	if (obj->ie_index == 0) {
		isns_error("DB: Refusing to store object with index 0\n");
		return ISNS_INTERNAL_ERROR;
	}

	status = __dbe_file_store_object(back->idb_name, obj);
	if (status == ISNS_SUCCESS)
		status = __dbe_file_store_children(back->idb_name, obj);

	return status;
}

int
isns_dbe_file_remove(isns_db_t *db, const isns_object_t *obj)
{
	isns_db_backend_t *back = db->id_backend;
	int		status;

	status = __dbe_file_remove_object(back->idb_name, obj);
	if (status == ISNS_SUCCESS)
		status = __dbe_file_remove_children(back->idb_name, obj);

	return status;
}

/*
 * Create the file backend
 */
isns_db_backend_t *
isns_create_file_db_backend(const char *pathname)
{
	isns_db_backend_t *back;

	isns_debug_state("Creating file DB backend (%s)\n", pathname);

	back = isns_calloc(1, sizeof(*back));
	back->idb_name = isns_strdup(pathname);
	back->idb_reload = isns_dbe_file_reload;
	back->idb_sync = isns_dbe_file_sync;
	back->idb_store = isns_dbe_file_store;
	back->idb_remove = isns_dbe_file_remove;

	return back;
}

