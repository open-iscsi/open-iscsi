/*
 * iSNS object database
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#ifndef ISNS_DB_H
#define ISNS_DB_H

#include "attrs.h"

typedef struct isns_db_backend	isns_db_backend_t;

/*
 * In-memory portion of object database.
 * Stable storage is provided by different
 * backends.
 */
struct isns_db {
	isns_object_list_t *	id_objects;
	isns_object_list_t	__id_objects;

	isns_relation_soup_t *	id_relations;

	uint32_t		id_last_eid;
	uint32_t		id_last_index;

	isns_scope_t *		id_global_scope;
	isns_scope_t *		id_default_scope;

	isns_db_backend_t *	id_backend;

	unsigned int		id_in_transaction : 1;
	struct isns_db_trans *	id_transact;

	/* This is for objects in limbo. When a client
	 * calls DevAttrDereg, the object will first be
	 * placed on the id_deferred list.
	 * When we're done processing the message, we
	 * invoke isns_db_purge, which looks at these
	 * objects.
	 *  -	if the reference count is 1, the object
	 *	is deleted.
	 *  -	otherwise, we assume the object is referenced
	 *	by a discovery domain. In this case, we prune
	 *	the attribute list down to the key attr(s)
	 *	plus the index attribute, and move it to
	 *	the id_limbo list.
	 */
	isns_object_list_t	id_deferred;
	isns_object_list_t	id_limbo;
};


struct isns_db_backend {
	char *		idb_name;

	int		(*idb_reload)(isns_db_t *);
	int		(*idb_sync)(isns_db_t *);
	int		(*idb_store)(isns_db_t *,
					const isns_object_t *);
	int		(*idb_remove)(isns_db_t *,
					const isns_object_t *);
};

extern isns_db_backend_t *isns_create_file_db_backend(const char *);
extern isns_object_t *	__isns_db_get_next(const isns_object_list_t *,
					isns_object_template_t *,
					const isns_attr_list_t *,
					const isns_attr_list_t *);

extern isns_relation_soup_t *isns_relation_soup_alloc(void);
extern isns_relation_t *isns_create_relation(isns_object_t *relating_object,
					unsigned int relation_type,
					isns_object_t *subordinate_object1,
					isns_object_t *subordinate_object2);
extern void		isns_relation_sever(isns_relation_t *);
extern void		isns_relation_release(isns_relation_t *);
extern void		isns_relation_add(isns_relation_soup_t *,
					isns_relation_t *);
extern void		isns_relation_remove(isns_relation_soup_t *,
					isns_relation_t *);
extern isns_object_t *	isns_relation_get_other(const isns_relation_t *,
					const isns_object_t *);
extern isns_relation_t *isns_relation_find_edge(isns_relation_soup_t *,
					const isns_object_t *,
					const isns_object_t *,
					unsigned int);
extern void		isns_relation_halfspace(isns_relation_soup_t *,
					const isns_object_t *,
					unsigned int,
					isns_object_list_t *);
extern void		isns_relation_get_edge_objects(isns_relation_soup_t *,
					const isns_object_t *,
					unsigned int,
					isns_object_list_t *);
extern int		isns_relation_exists(isns_relation_soup_t *,
					const isns_object_t *relating_object,
					const isns_object_t *left,
					const isns_object_t *right,
					unsigned int relation_type);
extern int		isns_relation_is_dead(const isns_relation_t *);

extern void		isns_db_create_relation(isns_db_t *db,
					isns_object_t *relating_object,
					unsigned int relation_type,
					isns_object_t *subordinate_object1,
					isns_object_t *subordinate_object2);
extern void		isns_db_get_relationship_objects(isns_db_t *,
					const isns_object_t *,
					unsigned int relation_type,
					isns_object_list_t *);
extern isns_object_t *	isns_db_get_relationship_object(isns_db_t *,
					const isns_object_t *,
					const isns_object_t *,
					unsigned int relation_type);
extern int		isns_db_relation_exists(isns_db_t *db,
					const isns_object_t *relating_object,
					const isns_object_t *left,
					const isns_object_t *right,
					unsigned int relation_type);
extern int		isns_db_create_pg_relation(isns_db_t *,
					isns_object_t *);

extern isns_scope_t *	isns_scope_for_call(isns_db_t *, const isns_simple_t *);
extern isns_scope_t *	isns_scope_alloc(isns_db_t *);
extern void		isns_scope_release(isns_scope_t *);
extern void		isns_scope_add(isns_scope_t *,
				isns_object_t *);
extern int		isns_scope_remove(isns_scope_t *,
				isns_object_t *);
extern int		isns_scope_gang_lookup(isns_scope_t *,
				isns_object_template_t *,
				const isns_attr_list_t *,
				isns_object_list_t *);
extern isns_object_t *	isns_scope_get_next(isns_scope_t *,
				isns_object_template_t *,
				const isns_attr_list_t *current,
				const isns_attr_list_t *scope);
extern void		isns_scope_get_related(isns_scope_t *,
				const isns_object_t *,
				unsigned int,
				isns_object_list_t *);
extern isns_db_t *	isns_scope_get_db(const isns_scope_t *);


#endif /* ISNS_DB_H */
