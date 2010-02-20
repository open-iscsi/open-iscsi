/*
 * iSNS object database
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>

#include "isns.h"
#include "objects.h"
#include "db.h"
#include "util.h"

enum {
	IDT_INSERT,
	IDT_REMOVE,
	IDT_UPDATE
};
struct isns_db_trans {
	struct isns_db_trans *	idt_next;
	int			idt_action;
	isns_object_t *		idt_object;
};

/* Internal helpers */
static int	isns_db_sanity_check(isns_db_t *);
static int	isns_db_get_key_tags(const isns_attr_list_t *,
			uint32_t *, unsigned int);
static int	isns_db_keyed_compare(const isns_object_t *,
			const isns_attr_list_t *,
			const uint32_t *, unsigned int);

/*
 * Open a database
 */
static isns_db_t *
isns_db_create(isns_db_backend_t *backend)
{
	isns_db_t *db;

	db = isns_calloc(1, sizeof(*db));
	db->id_last_index = 1;
	db->id_last_eid = 1;
	db->id_backend = backend;
	db->id_global_scope = isns_scope_alloc(db);
	db->id_relations = isns_relation_soup_alloc();
	db->id_objects = &db->__id_objects;

	if (backend && backend->idb_reload) {
		int	status;

		status = backend->idb_reload(db);
		/* "No such entry" is returned when the DB
		 * is still empty. */
		if (status != ISNS_SUCCESS
		 && status != ISNS_NO_SUCH_ENTRY) {
			isns_error("Error loading database: %s\n",
					isns_strerror(status));
			/* FIXME: isns_db_free(db); */
			return NULL;
		}

		isns_db_sanity_check(db);
	}

	return db;
}

isns_db_t *
isns_db_open(const char *location)
{
	isns_db_backend_t *backend;

	if (location == NULL) {
		isns_debug_state("Using in-memory DB\n");
		return isns_db_create(NULL);
	}

	if (location[0] == '/') {
		backend = isns_create_file_db_backend(location);
	} else
	if (!strncmp(location, "file:", 5)) {
		backend = isns_create_file_db_backend(location + 5);
	} else {
		isns_error("Unsupported database type \"%s\"\n",
				location);
		return NULL;
	}

	return isns_db_create(backend);
}

isns_db_t *
isns_db_open_shadow(isns_object_list_t *list)
{
	isns_db_t	*db;

	if ((db = isns_db_create(NULL)) != NULL)
		db->id_objects = list;
	return db;
}

int
isns_db_sanity_check(isns_db_t *db)
{
	unsigned int	i;

	i = 0;
	while (i < db->id_objects->iol_count) {
		isns_object_t *obj = db->id_objects->iol_data[i];

		switch (obj->ie_state) {
		case ISNS_OBJECT_STATE_MATURE:
			/* Nothing yet. */
			break;

		case ISNS_OBJECT_STATE_LIMBO:
			if (!ISNS_IS_ISCSI_NODE(obj)
			 && !ISNS_IS_PORTAL(obj)) {
				isns_error("Unexpected object %u (%s) in limbo\n",
						obj->ie_index,
						obj->ie_template->iot_name);
				isns_db_remove(db, obj);
			}
			break;

		default:
			isns_error("Unexpected object state %d in object %u (%s)\n",
				obj->ie_state, obj->ie_index,
				obj->ie_template->iot_name);
			isns_db_remove(db, obj);
			break;
		}

		i += 1;
	}

	return 1;
}

isns_object_t *
isns_db_lookup(isns_db_t *db,
		isns_object_template_t *tmpl,
		const isns_attr_list_t *keys)
{
	return isns_object_list_lookup(db->id_objects, tmpl, keys);
}

int
isns_db_gang_lookup(isns_db_t *db,
		isns_object_template_t *tmpl,
		const isns_attr_list_t *keys,
		isns_object_list_t *result)
{
	return isns_object_list_gang_lookup(db->id_objects,
			tmpl, keys, result);
}

/*
 * Look up the storage node for the given source.
 */
isns_object_t *
isns_db_lookup_source_node(isns_db_t *db,
		const isns_source_t *source)
{
	isns_attr_list_t attrs = ISNS_ATTR_LIST_INIT;
	isns_object_t	*node;

	isns_attr_list_append_attr(&attrs, isns_source_attr(source));
	node = isns_db_lookup(db, NULL, &attrs);
	isns_attr_list_destroy(&attrs);

	return node;
}

isns_object_t *
isns_db_vlookup(isns_db_t *db,
		isns_object_template_t *tmpl,
		...)
{
	isns_attr_list_t keys = ISNS_ATTR_LIST_INIT;
	isns_object_t *obj = NULL;
	va_list	ap;

	va_start(ap, tmpl);
	while (1) {
		const isns_tag_type_t *tag_type;
		isns_value_t	value;
		uint32_t	tag;

		tag = va_arg(ap, unsigned int);
		if (tag == 0)
			break;

		tag_type = isns_tag_type_by_id(tag);
		if (tag_type == NULL) {
			isns_error("isns_db_vlookup: unknown tag %u\n", tag);
			goto out;
		}

		memset(&value, 0, sizeof(value));
		value.iv_type = tag_type->it_type;
		switch (tag_type->it_type->it_id) {
		case ISNS_ATTR_TYPE_STRING:
			value.iv_string = va_arg(ap, char *);
			break;

		case ISNS_ATTR_TYPE_INT32:
			value.iv_int32 = va_arg(ap, int32_t);
			break;

		case ISNS_ATTR_TYPE_UINT32:
			value.iv_int32 = va_arg(ap, uint32_t);
			break;

		case ISNS_ATTR_TYPE_IPADDR:
			value.iv_ipaddr = *va_arg(ap, struct in6_addr *);
			break;

		default:
			isns_error("isns_db_vlookup: unsupported tag type %s\n",
					value.iv_type->it_name);
			goto out;
		}

		isns_attr_list_append_value(&keys, tag, tag_type, &value);
	}

	obj = isns_db_lookup(db, tmpl, &keys);

out:
	isns_attr_list_destroy(&keys);
	va_end(ap);
	return obj;
}

/*
 * Find the next matching object
 *
 * This implementation could be a lot simpler if the
 * RFC didn't make things so awfully complicated.
 * It could simply have mandated the use of the object
 * index attribute, period.
 */
isns_object_t *
__isns_db_get_next(const isns_object_list_t *list,
		isns_object_template_t *tmpl,
		const isns_attr_list_t *current,
		const isns_attr_list_t *scope)
{
	isns_object_t	*next = NULL;
	uint32_t	tags[16];
	unsigned int	i;
	int		num_tags;

	if (!tmpl)
		return NULL;

	/* Get the search attribute tags, and sort them.
	 * Note, these don't have to be the standard key
	 * attributes for a given object type; the RFC
	 * also permits index attributes.
	 */
	num_tags = isns_db_get_key_tags(current, tags, 16);
	if (num_tags < 0)
		return NULL;

	/*
	 * 5.6.5.3.
	 * If the TLV length of the Message Key Attribute(s) is zero,
	 * then the first object entry in the iSNS database matching the
	 * Message Key type SHALL be returned in the Message Key of the
	 * corresponding DevGetNextRsp message.
	 */
	for (i = 0; i < current->ial_count; ++i) {
		isns_attr_t *attr = current->ial_data[i];

		if (!ISNS_ATTR_IS_NIL(attr))
			goto non_nil;
	}
	current = NULL;
non_nil:

	for (i = 0; i < list->iol_count; ++i) {
		isns_object_t	*obj = list->iol_data[i];

		if (obj->ie_template != tmpl)
			continue;
		if (scope && !isns_object_match(obj, scope))
			continue;

		/* compare returns -1 if the first list
		 * is "before" the second list, in terms of
		 * implicit ordering. */
		if (current
		 && isns_db_keyed_compare(obj, current, tags, num_tags) <= 0) {
			/* obj less than or equal to current */
			continue;
		}

		if (next == NULL
		 || isns_db_keyed_compare(obj, &next->ie_attrs, tags, num_tags) < 0)
			next = obj;
	}

	if (next)
		isns_object_get(next);
	return next;
}

isns_object_t *
isns_db_get_next(isns_db_t *db,
		isns_object_template_t *tmpl,
		const isns_attr_list_t *current,
		const isns_attr_list_t *scope,
		const isns_source_t *source)
{
	return __isns_db_get_next(db->id_objects,
			tmpl, current, scope);
}

/*
 * Get the search key tags
 */
static int
isns_db_get_key_tags(const isns_attr_list_t *keys,
		uint32_t *tags, unsigned int max_tags)
{
	unsigned int	i;

	/* Get the search attribute tags, and sort them */
	for (i = 0; i < keys->ial_count; ++i) {
		if (i >= 16)
			return -1;
		tags[i] = keys->ial_data[i]->ia_tag_id;
	}

	/* FIXME: qsort the list */
	return i;
}

/*
 * Helper function for GetNext
 */
static int
isns_db_keyed_compare(const isns_object_t *obj,
		const isns_attr_list_t *attrs,
		const uint32_t *tags, unsigned int num_tags)
{
	int		ind = 0;
	unsigned int	i;

	for (i = 0; i < num_tags; ++i) {
		isns_attr_t	*attr1, *attr2;
		uint32_t	tag = tags[i];

		if (!isns_attr_list_get_attr(&obj->ie_attrs, tag, &attr1))
			attr1 = NULL;
		if (!isns_attr_list_get_attr(attrs, tag, &attr2))
			attr2 = NULL;
		if (attr1 == attr2) {
			ind = 0;
		} else if (attr1 && attr2) {
			ind = isns_attr_compare(attr1, attr2);
		} else if (attr1 == NULL) {
			ind = -1;
		} else {
			ind = 1;
		}
		if (ind)
			break;
	}
	return ind;
}

uint32_t
isns_db_allocate_index(isns_db_t *db)
{
	return db->id_last_index++;
}

/*
 * Insert an object into the database.
 */
void
__isns_db_insert(isns_db_t *db, isns_object_t *obj, unsigned int state)
{
	uint32_t	idx_tag = obj->ie_template->iot_index;

	switch (obj->ie_state) {
	case ISNS_OBJECT_STATE_LIMBO:
		/* The object was in limbo; now it goes
		 * live (again). It should have an index,
		 * and it should be on the global id_objects
		 * list too.
		 */
		isns_assert(state == ISNS_OBJECT_STATE_MATURE);
		isns_assert(obj->ie_index);
		isns_assert(obj->ie_users > 1);
		isns_object_list_remove(&db->id_limbo, obj);
		break;

	case ISNS_OBJECT_STATE_DEAD:
		/* A DevAttrReg with the F_REPLACE bit set will cause
		 * the key object to be removed from the DB, which may
		 * kill it for good.
		 * The subsequent call to db_insert will assign a new
		 * index, and re-add it to the database.
		 */

	case ISNS_OBJECT_STATE_LARVAL:
		/* Larval objects can go either to mature or
		 * limbo state. */
		obj->ie_index = db->id_last_index++;

		if (idx_tag)
			isns_object_set_uint32(obj,
				idx_tag,
				obj->ie_index);

		isns_object_list_append(db->id_objects, obj);
		break;

	case ISNS_OBJECT_STATE_MATURE:
		/* If we call db_insert on a mature object, treat
		   this as a NOP. */
		isns_assert(state == ISNS_OBJECT_STATE_MATURE);
		return;

	default:
		isns_error("Internal error: unexpected object %u (%s) "
				"state %u in db_insert\n",
				obj->ie_index,
				obj->ie_template->iot_name,
				obj->ie_state);
		return;
	}

	obj->ie_state = state;

	/* Add it to the global scope */
	if (state == ISNS_OBJECT_STATE_MATURE) {
		isns_scope_add(db->id_global_scope, obj);
		obj->ie_references++;

		/* See if this object represents a relationship
		 * (eg a portal group). */
		if (obj->ie_template->iot_relation_type) {
			if (!obj->ie_relation) {
				isns_warning("DB: inserting %s object "
						"without relation\n",
						obj->ie_template->iot_name);
			} else {
				isns_relation_add(db->id_relations,
						obj->ie_relation);
			}
		}

		isns_mark_object(obj, ISNS_SCN_OBJECT_ADDED);
	}

	isns_debug_state("DB: added object %u (%s) state %u\n",
			obj->ie_index,
			obj->ie_template->iot_name,
			obj->ie_state);

	if (db->id_backend) {
		db->id_backend->idb_store(db, obj);
		db->id_backend->idb_sync(db);
	}
}

void
isns_db_insert(isns_db_t *db, isns_object_t *obj)
{
	__isns_db_insert(db, obj, ISNS_OBJECT_STATE_MATURE);
}

void
isns_db_insert_limbo(isns_db_t *db, isns_object_t *obj)
{
	isns_assert(obj->ie_state == ISNS_OBJECT_STATE_LARVAL);
	__isns_db_insert(db, obj, ISNS_OBJECT_STATE_LIMBO);
}

/*
 * Save an object after updating it
 */
void
isns_db_sync(isns_db_t *db)
{
	isns_object_list_t *list = db->id_objects;
	unsigned int	i, saved = 0;

	if (!db->id_backend)
		return;

	for (i = 0; i < list->iol_count; ++i) {
		isns_object_t	*obj = list->iol_data[i];

		if (obj->ie_flags & ISNS_OBJECT_DIRTY) {
			db->id_backend->idb_store(db, obj);
			obj->ie_flags &= ~ISNS_OBJECT_DIRTY;
			saved++;
		}
	}
	if (saved)
		db->id_backend->idb_sync(db);
}

/*
 * Remove an object from the database.
 * This is slow and inefficient, due to the use
 * of an object array. We should at least use
 * a linked list, or maybe even a hash one day.
 */
static void
__isns_db_prepare_removal(isns_db_t *db, isns_object_t *obj)
{
	isns_object_t	*child;

	obj->ie_flags |= ISNS_OBJECT_DEAD;
	isns_object_get(obj);

	/* The node is dead; it's no longer interested in SCNs */
	obj->ie_scn_mask = 0;

	/* Trigger an SCN event. */
	if (obj->ie_state == ISNS_OBJECT_STATE_MATURE)
		isns_mark_object(obj, ISNS_SCN_OBJECT_REMOVED);

	/* If the object represents a relation between
	 * two other objects, sever that relationship.
	 */
	if (obj->ie_relation) {
		isns_relation_remove(db->id_relations,
				obj->ie_relation);
		isns_relation_sever(obj->ie_relation);
		isns_relation_release(obj->ie_relation);
		obj->ie_relation = NULL;
	}

	/* Detach the object from its container */
	isns_object_detach(obj);

	/* Remove it from the database */
	if (isns_scope_remove(db->id_global_scope, obj)) {
		obj->ie_references--;
	} else {
		isns_warning("Unable to remove object from scope\n");
	}

	/* Recursively remove all children */
	while (obj->ie_children.iol_count) {
		child = obj->ie_children.iol_data[0];
		__isns_db_prepare_removal(db, child);
	}

	isns_debug_state("DB: removed object %u (%s)\n",
			obj->ie_index,
			obj->ie_template->iot_name);

	isns_object_list_append(&db->id_deferred, obj);
	isns_object_release(obj);
}

int
isns_db_remove(isns_db_t *db, isns_object_t *obj)
{
	isns_object_t	*entity;
	unsigned int	i;

	/* Don't even bother if the object was never added */
	if (obj->ie_index == 0)
		goto out;

	/* Obtain the containing entity before removal */
	entity = isns_object_get_entity(obj);

	/* We don't remove the object for real yet; 
	 * this will happen later during db_purge */
	__isns_db_prepare_removal(db, obj);

	/*
	 * 5.6.5.4.
	 * If all Nodes and Portals associated with a Network Entity are
	 * deregistered, then the Network Entity SHALL also be removed.
	 *
	 * If both the Portal and iSCSI Storage Node objects associated
	 * with a Portal Group object are removed, then that Portal Group
	 * object SHALL also be removed.  The Portal Group object SHALL
	 * remain registered as long as either of its associated Portal
	 * or iSCSI Storage Node objects remain registered.  If a deleted
	 * Storage Node or Portal object is subsequently re-registered,
	 * then a relationship between the re- registered object and
	 * an existing Portal or Storage Node object registration,
	 * indicated by the PG object, SHALL be restored.
	 */
	if (ISNS_IS_ENTITY(obj))
		goto out;

	if (entity == NULL || !ISNS_IS_ENTITY(entity))
		goto out;

	/* Don't do this for the CONTROL entity. */
	if (entity->ie_flags & ISNS_OBJECT_PRIVATE)
		goto out;

	/* Step 1: Purge all relationship objects (read: portal groups)
	 * where both referenced objects are dead.
	 */
	for (i = 0; i < entity->ie_children.iol_count; ) {
		isns_object_t *child = entity->ie_children.iol_data[i];

		if (child->ie_relation
		 && isns_relation_is_dead(child->ie_relation)) {
			__isns_db_prepare_removal(db, child);
			continue;
		}

		i += 1;
	}

	/* Step 2: If all portals, nodes and PGs have been unregistered,
	 * the list of children should be empty. */
	if (entity->ie_children.iol_count == 0) {
		isns_debug_state("Last portal/node unregistered, removing entity\n");
		__isns_db_prepare_removal(db, entity);
	}

out:
	return ISNS_SUCCESS;
}

/*
 * Purge deregistered objects.
 * If we find they're still part of some discovery
 * domain, they're moved to id_limbo; otherwise we'll
 * destroy them for good.
 */
void
isns_db_purge(isns_db_t *db)
{
	isns_object_list_t *list = &db->id_deferred;
	unsigned int	i;

	while (list->iol_count) {
		isns_object_t *obj = list->iol_data[0];

		if (obj->ie_references == 0) {
			isns_debug_state("DB: destroying object %u (%s)\n",
					obj->ie_index,
					obj->ie_template->iot_name);

			if (db->id_backend) {
				db->id_backend->idb_remove(db, obj);
				/* db->id_backend->idb_sync(db); */
			}

			isns_object_list_remove(db->id_objects, obj);
			obj->ie_state = ISNS_OBJECT_STATE_DEAD;
		} else if (obj->ie_state != ISNS_OBJECT_STATE_LIMBO) {
			isns_debug_state("DB: moving object %u (%s) to purgatory - "
					"%u references left\n",
					obj->ie_index,
					obj->ie_template->iot_name,
					obj->ie_references);

			isns_object_list_append(&db->id_limbo, obj);
			obj->ie_state = ISNS_OBJECT_STATE_LIMBO;
			isns_object_prune_attrs(obj);

			if (db->id_backend) {
				db->id_backend->idb_store(db, obj);
				db->id_backend->idb_sync(db);
			}
		}

		isns_object_list_remove(list, obj);
	}

	/* Brute force - look at all objects in limbo and kill those
	 * that went out of scope */
	for (i = 0; i < db->id_limbo.iol_count; ) {
		isns_object_t *obj = db->id_limbo.iol_data[i];

		if (obj->ie_references == 0) {
			isns_debug_state("DB: destroying object %u (%s)\n",
					obj->ie_index,
					obj->ie_template->iot_name);

			if (db->id_backend) {
				db->id_backend->idb_remove(db, obj);
				/* db->id_backend->idb_sync(db); */
			}

			obj->ie_state = ISNS_OBJECT_STATE_DEAD;
			isns_object_list_remove(&db->id_limbo, obj);
			isns_object_list_remove(db->id_objects, obj);
			continue;
		}

		i += 1;
	}
}

/*
 * Expire old entities
 *
 * This code is still rather simple, but once we start
 * using ESI things get rather complex quickly.
 */
time_t
isns_db_expire(isns_db_t *db)
{
	isns_object_list_t *list = db->id_objects;
	time_t		now = time(NULL), next_timeout;
	unsigned int	i = 0;

	next_timeout = now + 3600;
	if (isns_config.ic_registration_period == 0)
		return next_timeout;

	while (i < list->iol_count) {
		isns_object_t	*obj;
		uint64_t	stamp;
		uint32_t	period;

		obj = list->iol_data[i];
		if (!ISNS_IS_ENTITY(obj))
			goto next;

		if (!isns_object_get_uint32(obj,
					ISNS_TAG_REGISTRATION_PERIOD,
					&period)) {
			isns_debug_state("No registration period for entity %u\n",
					obj->ie_index);
			goto next;
		}

		if (!isns_object_get_uint64(obj,
					ISNS_TAG_TIMESTAMP,
					&stamp)) {
			isns_debug_state("No timestamp for entity %u\n",
					obj->ie_index);
			goto next;
		}

		stamp += period;
		if (stamp <= now) {
			/* removing the object will move one
			 * object from the tail to the free
			 * slot in the list. So don't increment
			 * the index here. */
			isns_debug_state("Expiring entity %u\n", obj->ie_index);
			isns_db_remove(db, obj);
			goto next;
		} else {
			isns_debug_state("Entity %u will expire in %u sec\n",
					obj->ie_index, (int) (stamp - now));
			if (stamp < next_timeout)
				next_timeout = stamp;
		}

next:
		i += 1;
	}

	/* Send out SCN notifications.
	 * This makes sure we won't have extraneous references
	 * on expired objects when we reach db_purge. */
	isns_flush_events();

	return next_timeout;
}

/*
 * Very special function to make sure we always have a
 * CONTROL entity.
 */
isns_object_t *
isns_db_get_control(isns_db_t *db)
{
	isns_attr_list_t keys = ISNS_ATTR_LIST_INIT;
	isns_object_list_t *list = db->id_objects;
	isns_object_t	*found = NULL;
	unsigned int	i;

	isns_attr_list_append_string(&keys,
			ISNS_TAG_ENTITY_IDENTIFIER,
			ISNS_ENTITY_CONTROL);

	for (i = 0; i < list->iol_count; ++i) {
		isns_object_t	*obj;

		obj = list->iol_data[i];
		if (!ISNS_IS_ENTITY(obj))
			continue;
		if (isns_object_match(obj, &keys)) {
			obj->ie_users++;
			found = obj;
			goto done;
		}
	}

	found = isns_create_object(&isns_entity_template,
			&keys, NULL);
	found->ie_flags |= ISNS_OBJECT_PRIVATE;
	isns_db_insert(db, found);
	isns_db_sync(db);

done:
	return found;
}

void
isns_db_get_domainless(isns_db_t *db,
		isns_object_template_t *tmpl,
		isns_object_list_t *result)
{
	isns_object_list_t *list = db->id_objects;
	unsigned int	i;

	if (!tmpl)
		return;

	for (i = 0; i < list->iol_count; ++i) {
		isns_object_t	*obj = list->iol_data[i];

		if (obj->ie_template == tmpl
		 && isns_bitvector_is_empty(obj->ie_membership))
			isns_object_list_append(result, obj);
	}
}

/*
 * Create a relationship and store it in the DB
 */
void
isns_db_create_relation(isns_db_t *db,
		isns_object_t *relating_object,
		unsigned int relation_type,
		isns_object_t *subordinate_object1,
		isns_object_t *subordinate_object2)
{
	isns_relation_t *rel;

	rel = isns_create_relation(relating_object,
			relation_type,
			subordinate_object1,
			subordinate_object2);
	if (rel) {
		isns_relation_add(db->id_relations, rel);
		isns_relation_release(rel);
	}
}

/*
 * Get all objects related to @left through a relation
 * of type @type.
 */
void
isns_db_get_relationship_objects(isns_db_t *db,
		const isns_object_t *left,
		unsigned int relation_type,
		isns_object_list_t *result)
{
	isns_relation_get_edge_objects(db->id_relations,
			left, relation_type,
			result);
}

/*
 * Get the object relating left and right.
 * Usually called to find the portal group connecting
 * a portal and a storage node, or a DD connecting
 * two storage nodes.
 */
isns_object_t *
isns_db_get_relationship_object(isns_db_t *db,
		const isns_object_t *left,
		const isns_object_t *right,
		unsigned int relation_type)
{
	isns_relation_t *rel;

	/* Find a relation of the given type, connecting
	 * the two objects. */
	rel = isns_relation_find_edge(db->id_relations,
			left, right, relation_type);

	if (rel == NULL)
		return NULL;

	return isns_object_get(rel->ir_object);
}

/*
 * See if a relationship exists
 */
int
isns_db_relation_exists(isns_db_t *db,
		const isns_object_t *relating_object,
		const isns_object_t *left,
		const isns_object_t *right,
		unsigned int relation_type)
{
	return isns_relation_exists(db->id_relations,
			relating_object,
			left, right, relation_type);
}

/*
 * Debug helper
 */
void
isns_db_print(isns_db_t *db, isns_print_fn_t *fn)
{
	const isns_object_list_t *list = db->id_objects;
	unsigned int	i;

	fn("Dumping database contents\n"
	   "Backend:     %s\n"
	   "Last EID:    %u\n"
	   "Last Index:  %u\n"
	   ,
	   db->id_backend->idb_name,
	   db->id_last_eid,
	   db->id_last_index);

	for (i = 0; i < list->iol_count; ++i) {
		isns_object_t *obj = list->iol_data[i];

		fn("--------------\n"
		   "Object:      index=%u type=<%s> state=%s",
		   obj->ie_index,
		   obj->ie_template->iot_name,
		   isns_object_state_string(obj->ie_state));
		if (obj->ie_container)
			fn(" parent=%u", obj->ie_container->ie_index);
		if (obj->ie_flags & ISNS_OBJECT_DIRTY)
			fn(" DIRTY");
		if (obj->ie_flags & ISNS_OBJECT_PRIVATE)
			fn(" PRIVATE");
		fn("\n");
		isns_attr_list_print(&obj->ie_attrs, fn);
	}
}

/*
 * Generate a "random" entity identifier. This is used when
 * a DevAttrReg request does not specify an entity, and the
 * client's policy doesn't specify one either.
 */
const char *
isns_db_generate_eid(isns_db_t *db, char *buf, size_t size)
{
	snprintf(buf, size, "isns.entity.%04d", db->id_last_eid);
	db->id_last_eid++;
	return buf;
}

/*
 * Highly primitive transaction handling.
 * This is really just a hack for the iSNS server code,
 * which wants to go along creating objects, and back out
 * if something goes wrong.
 */
void
isns_db_begin_transaction(isns_db_t *db)
{
	if (db->id_in_transaction) {
		isns_error("isns_db_begin_transaction: running into pending transaction\n");
		isns_db_rollback(db);
	}
	db->id_in_transaction = 1;
}

void
isns_db_commit(isns_db_t *db)
{
	/* Nothing yet */
	db->id_in_transaction = 0;
}

void
isns_db_rollback(isns_db_t *db)
{
	/* Nothing yet */
	db->id_in_transaction = 0;
}
