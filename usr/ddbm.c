/*
 * iSCSI Discovery Database Library
 *
 * Copyright (C) 2004 Dmitry Yusupov, Alex Aizman
 * maintained by open-iscsi@@googlegroups.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * See the file COPYING included with this distribution for more details.
 */

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "ddbm.h"
#include "log.h"

extern char*
ddbm_hash(discovery_rec_t *rec)
{
	char *hash = malloc(HASH_MAXLEN);

	if (!hash) {
		log_error("out of memory on hash allocation");
		return NULL;
	}

	if (rec->type == DISCOVERY_TYPE_SENDTARGETS) {
		snprintf(hash, HASH_MAXLEN, "%s:%5d#%s:%5d,%d",
			rec->u.sendtargets.address,
			rec->u.sendtargets.port,
			rec->address,
			rec->port,
			rec->tpgt);
		return hash;
	} else {
		log_error("unsupported discovery type");
		return NULL;
	}
}

DBM*
ddbm_open(char *filename, int flags)
{
	DBM *dbm;

	if (flags & O_CREAT) {
		char *dirname, *ptr;

		dirname = strdup(filename);
		if (dirname && (ptr = strrchr(dirname, '/'))) {
			*ptr = '\0';
		} else if (!dirname)
			return NULL;

		if (access(dirname, F_OK) != 0) {
			if (mkdir(dirname, 0755) != 0) {
				free(dirname);
				log_error("mkdir '%s' error", dirname);
				return NULL;
			}
		}
		free(dirname);
	}

	/* Now open the database */
	dbm = dbm_open(filename, flags, 0666);
	if (!dbm) {
		log_error("discovery DB '%s' open failed", filename);
		return NULL;
	}

	return dbm;
}

void
ddbm_delete(DBM *dbm, char *hash)
{
}

discovery_rec_t*
ddbm_read(DBM *dbm, char *hash)
{
	datum key, data;

	key.dptr = hash;
	key.dsize = HASH_MAXLEN;

	data = dbm_fetch(dbm, key);
	if (data.dsize > 0) {
		return (discovery_rec_t*)data.dptr;
	}

	log_error("key '%s' not found", hash);
	return NULL;
}

int
ddbm_write(DBM *dbm, discovery_rec_t *rec)
{
	return 0;
}

void
ddbm_close(DBM *dbm)
{
	dbm_close(dbm);
}

int
ddbm_update_info(DBM *dbm, struct string_buffer *info)
{
	return 0;
}
