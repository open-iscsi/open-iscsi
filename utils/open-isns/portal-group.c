/*
 * iSNS object model - portal group specific code
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#include <stdlib.h>
#include <string.h>
#include "isns.h"
#include "objects.h"
#include "vendor.h"
#include "attrs.h"
#include "util.h"

/* For relationship stuff - should go */
#include "db.h"


/*
 * Retrieve attribute @old_tag from object @obj, create a copy with
 * tag @new_tag, and append it to list @dst.
 * (Helper function for the portal group stuff)
 */
static int
__isns_object_translate_attr(isns_object_t *obj,
		uint32_t old_tag, uint32_t new_tag,
		isns_attr_list_t *dst)
{
	isns_value_t	value;

	if (!isns_attr_list_get_value(&obj->ie_attrs, old_tag, &value))
		return 0;
	isns_attr_list_append_value(dst, new_tag, NULL, &value);
	return 1;
}


/*
 * Portal Group
 */
static isns_object_t *
__isns_pg_create(const isns_attr_list_t *attrs, uint32_t pg_tag,
		isns_object_t *portal, isns_object_t *node)
{
	isns_object_t	*obj;

	obj = isns_create_object(&isns_iscsi_pg_template, attrs,
			isns_object_get_entity(portal));

	/*
	 * 3.4
	 *
	 * Each Portal and iSCSI Storage Node registered in an Entity can
	 * be associated using a Portal Group (PG) object.  The PG Tag
	 * (PGT), if non-NULL, indicates that the associated Portal
	 * provides access to the associated iSCSI Storage Node in
	 * the Entity.	All Portals that have the same PGT value for
	 * a specific iSCSI Storage Node allow coordinated access to
	 * that node.
	 *
	 * 5.6.5.2
	 *
	 * If the PGT of the Portal Group is not NULL, then a relationship
	 * exists between the indicated Storage Node and Portal; if the
	 * PGT is NULL, then no relationship exists.
	 */
	if (pg_tag != 0) {
		isns_object_set_uint32(obj,
				ISNS_TAG_PG_TAG, pg_tag);
	} else {
		/* A NULL PGT indicates that the
		 * storage node cannot be accessed through
		 * this portal. */
		isns_object_set_nil(obj, ISNS_TAG_PG_TAG);
	}

	/* This object represents a relationship between portal
	   and storage node. Create a relation. */
	obj->ie_relation = isns_create_relation(obj,
			ISNS_RELATION_PORTAL_GROUP,
			portal, node);

	return obj;
}

/*
 * Find the portal for a given portal group
 */
static isns_object_t *
__isns_pg_find_portal(isns_db_t *db, isns_object_t *pg,
		const isns_object_list_t *extra_objs)
{
	isns_attr_list_t key_attrs = ISNS_ATTR_LIST_INIT;
	isns_object_t	*obj = NULL;

	/* FIXME: ISNS_TAG_PG_PORTAL_IP_ADDR -> ...ADDRESS */
	if (!__isns_object_translate_attr(pg,
				ISNS_TAG_PG_PORTAL_IP_ADDR,
				ISNS_TAG_PORTAL_IP_ADDRESS,
				&key_attrs))
		goto out;
	if (!__isns_object_translate_attr(pg,
				ISNS_TAG_PG_PORTAL_TCP_UDP_PORT,
				ISNS_TAG_PORTAL_TCP_UDP_PORT,
				&key_attrs))
		goto out;

	obj = isns_db_lookup(db, &isns_portal_template, &key_attrs);
	if (!obj && extra_objs)
		obj = isns_object_list_lookup(extra_objs,
				&isns_portal_template, &key_attrs);

out:
	isns_attr_list_destroy(&key_attrs);
	return obj;
}

/*
 * Find the node for a given portal group
 */
static isns_object_t *
__isns_pg_find_node(isns_db_t *db, isns_object_t *pg,
		const isns_object_list_t *extra_objs)
{
	isns_attr_list_t key_attrs = ISNS_ATTR_LIST_INIT;
	isns_object_t	*obj = NULL;

	if (!__isns_object_translate_attr(pg,
				ISNS_TAG_PG_ISCSI_NAME,
				ISNS_TAG_ISCSI_NAME,
				&key_attrs))
		goto out;

	obj = isns_db_lookup(db, &isns_iscsi_node_template, &key_attrs);
	if (!obj && extra_objs)
		obj = isns_object_list_lookup(extra_objs,
				&isns_iscsi_node_template, &key_attrs);

out:
	isns_attr_list_destroy(&key_attrs);
	return obj;
}

/*
 * When creating a portal group, it must not connect nodes and
 * portals from other entities. However, it is perfectly fine to
 * link objects in limbo.
 */
static inline int
__isns_pg_may_relate(isns_object_t *entity, isns_object_t *subordinate)
{
	isns_object_t *other;

	other = isns_object_get_entity(subordinate);
	return other == NULL || other == entity;
}

/*
 * Given a portal group object, create the relationship
 */
isns_relation_t *
isns_db_build_pg_relation(isns_db_t *db, isns_object_t *pg,
		const isns_object_list_t *extra_objs)
{
	isns_object_t   *entity, *node = NULL, *portal = NULL;

	entity = isns_object_get_entity(pg);

	node = __isns_pg_find_node(db, pg, extra_objs);
	if (node == NULL) {
		isns_error("Trying to register PG for non-existant node\n");
		goto failed;
	}
	if (!__isns_pg_may_relate(entity, node)) {
		isns_error("Trying to register PG for node in other entity\n");
		goto failed;
	}

	portal = __isns_pg_find_portal(db, pg, extra_objs);
	if (portal == NULL) {
		isns_error("Trying to register PG for non-existant portal\n");
		goto failed;
	}
	if (!__isns_pg_may_relate(entity, portal)) {
		isns_error("Trying to register PG for portal in other entity\n");
		goto failed;
	}

	pg->ie_relation = isns_create_relation(pg,
				ISNS_RELATION_PORTAL_GROUP,
				node, portal);
	isns_object_release(portal);
	isns_object_release(node);

	return pg->ie_relation;

failed:
	if (portal)
		isns_object_release(portal);
	if (node)
		isns_object_release(node);
	return NULL;
}

/*
 * Create a portal group given node, portal and PGT
 */
isns_object_t *
isns_create_portal_group(isns_object_t *portal,
		isns_object_t *node, uint32_t pg_tag)
{
	isns_attr_list_t key_attrs = ISNS_ATTR_LIST_INIT;
	isns_object_t	*obj = NULL;

	if (portal == NULL || node == NULL)
		return NULL;

	if (node->ie_container != portal->ie_container) {
		isns_error("Refusing to create portal group "
			   "linking objects from different entities\n");
		return NULL;
	}

	if (__isns_object_translate_attr(node,
				ISNS_TAG_ISCSI_NAME,
				ISNS_TAG_PG_ISCSI_NAME,
				&key_attrs)
	 && __isns_object_translate_attr(portal,
		 		ISNS_TAG_PORTAL_IP_ADDRESS,
				ISNS_TAG_PG_PORTAL_IP_ADDR,
				&key_attrs)
	 && __isns_object_translate_attr(portal,
		 		ISNS_TAG_PORTAL_TCP_UDP_PORT,
				ISNS_TAG_PG_PORTAL_TCP_UDP_PORT,
				&key_attrs)) {
		obj = __isns_pg_create(&key_attrs, pg_tag, portal, node);
	}

	isns_attr_list_destroy(&key_attrs);
	return obj;
}

/*
 * 5.6.5.1
 * New PG objects are registered when an associated Portal or
 * iSCSI Node object is registered.  An explicit PG object
 * registration MAY follow a Portal or iSCSI Node object
 * registration in a DevAttrReg message.
 * [...]
 * If the PGT value is not included in the Storage Node or
 * Portal object registration, and if a PGT value was not
 * previously registered for the relationship, then the PGT for
 * the corresponding PG object SHALL be registered with a value
 * of 0x00000001.
 *
 * We return non-NULL if the object was created.
 */
isns_object_t *
isns_create_default_portal_group(isns_db_t *db,
		isns_object_t *portal, isns_object_t *node)
{
	isns_object_t	*obj;

	if (portal == NULL || node == NULL)
		return 0;

	/* See if there is a PG already */
	obj = isns_db_get_relationship_object(db, node, portal,
			ISNS_RELATION_PORTAL_GROUP);
	if (obj != NULL) {
		isns_object_release(obj);
		return NULL;
	}

	return isns_create_portal_group(portal, node, 1);
}

static uint32_t	iscsi_pg_attrs[] = {
	ISNS_TAG_PG_ISCSI_NAME,
	ISNS_TAG_PG_PORTAL_IP_ADDR,
	ISNS_TAG_PG_PORTAL_TCP_UDP_PORT,
	ISNS_TAG_PG_TAG,
	ISNS_TAG_PG_INDEX,
};

static uint32_t	iscsi_pg_key_attrs[] = {
	ISNS_TAG_PG_ISCSI_NAME,
	ISNS_TAG_PG_PORTAL_IP_ADDR,
	ISNS_TAG_PG_PORTAL_TCP_UDP_PORT,
};

isns_object_template_t		isns_iscsi_pg_template = {
	.iot_name	= "iSCSI Portal Group",
	.iot_handle	= ISNS_OBJECT_TYPE_PG,
	.iot_attrs	= iscsi_pg_attrs,
	.iot_num_attrs	= array_num_elements(iscsi_pg_attrs),
	.iot_keys	= iscsi_pg_key_attrs,
	.iot_num_keys	= array_num_elements(iscsi_pg_key_attrs),
	.iot_attrs	= iscsi_pg_attrs,
	.iot_keys	= iscsi_pg_key_attrs,
	.iot_index	= ISNS_TAG_PG_INDEX,
	.iot_next_index	= ISNS_TAG_PG_NEXT_INDEX,
	.iot_container	= &isns_entity_template,
	.iot_relation_type = ISNS_RELATION_PORTAL_GROUP,
	.iot_build_relation = isns_db_build_pg_relation,
};

