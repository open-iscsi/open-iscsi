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
#include <sys/stat.h>

#include "db.h"
#include "log.h"

DB*
discoverydb_open(char *filename, uint32_t openflags)
{
	char *dirname, *ptr;
	DB *dbp;
	int ret;

	dirname = strdup(filename);
	if (dirname && (ptr = strrchr(dirname, '/'))) {
		*ptr = '\0';
	} else if (!dirname)
		return NULL;

	/* Initialize the DB handle */
	ret = db_create(&dbp, NULL, 0);
	if (ret != 0) {
		free(dirname);
		log_error("%s", db_strerror(ret));
		return NULL;
	}

	if (openflags & DB_CREATE) {
		if (access(dirname, F_OK) != 0) {
			if (mkdir(dirname, 0755) != 0) {
				free(dirname);
				log_error("mkdir '%s' error", dirname);
				return NULL;
			}
		}
	}

	/* Now open the database */
	ret = dbp->open(dbp,         /* Pointer to the database */
			NULL,        /* Txn pointer */
			filename,   /* File name */
			NULL,        /* Logical db name (unneeded) */
			DB_BTREE,    /* Database type (using btree) */
			openflags,  /* Open flags */
			0);          /* File mode. Using defaults */
	if (ret != 0) {
		free(dirname);
		log_error("discovery DB '%s' open failed", filename);
		return NULL;
	}

	free(dirname);

	return dbp;
}

discovery_rec_t*
discoverydb_read(DB *dbp)
{
	discovery_rec_t *rec;

	return rec;
}

int
discoverydb_write(DB *dbp, discovery_rec_t *rec)
{
	return 0;
}

void
discoverydb_close(DB *dbp)
{
	dbp->close(dbp, 0);
}
