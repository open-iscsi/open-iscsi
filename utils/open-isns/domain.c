/*
 * iSNS object model - discovery domain specific code
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "isns.h"
#include "objects.h"
#include "util.h"

static int
__isns_default_dd_rebuild(isns_object_t *obj, isns_db_t *db)
{
	isns_object_list_t list = ISNS_OBJECT_LIST_INIT;
	unsigned int	i;

	isns_object_prune_attrs(obj);

	isns_db_get_domainless(db, &isns_iscsi_node_template, &list);
	for (i = 0; i < list.iol_count; ++i) {
		isns_object_t	*node = list.iol_data[i];
		const char	*name;
		uint32_t	type;

		if (!isns_object_get_uint32(node,
				ISNS_TAG_ISCSI_NODE_TYPE,
				&type))
			continue;
		if (type & ISNS_ISCSI_CONTROL_MASK)
			continue;
		if (!isns_object_get_string(node,
				ISNS_TAG_ISCSI_NAME,
				&name))
			continue;
		isns_object_set_string(obj,
				ISNS_TAG_DD_MEMBER_ISCSI_NAME,
				name);
	}

	return ISNS_SUCCESS;
}

/*
 * Create the default domain
 */
isns_object_t *
isns_create_default_domain(void)
{
	isns_object_t	*obj;

	obj = isns_create_object(&isns_dd_template, NULL, NULL);
	if (!obj)
		return NULL;

	isns_object_set_uint32(obj, ISNS_TAG_DD_ID, 0);
	obj->ie_rebuild = __isns_default_dd_rebuild;
	return obj;
}

/*
 * Check object type
 */
int
isns_object_is_dd(const isns_object_t *obj)
{
	return ISNS_IS_DD(obj);
}

int
isns_object_is_ddset(const isns_object_t *obj)
{
	return ISNS_IS_DDSET(obj);
}

/*
 * Keep track of DD membership through a bit vector
 */
int
isns_object_mark_membership(isns_object_t *obj, uint32_t id)
{
	if (!obj->ie_membership)
		obj->ie_membership = isns_bitvector_alloc();

	return isns_bitvector_set_bit(obj->ie_membership, id);
}

int
isns_object_test_membership(const isns_object_t *obj, uint32_t id)
{
	if (!obj->ie_membership)
		return 0;

	return isns_bitvector_test_bit(obj->ie_membership, id);
}

int
isns_object_clear_membership(isns_object_t *obj, uint32_t id)
{
	if (!obj->ie_membership)
		return 0;

	return isns_bitvector_clear_bit(obj->ie_membership, id);
}

/*
 * Check whether the two objects share a discovery domain,
 * and if so, return the DD_ID.
 * Returns -1 otherwise.
 */
int
isns_object_test_visibility(const isns_object_t *a, const isns_object_t *b)
{
	/* The admin can tell isnsd to put all nodes which are *not*
	 * in any discovery domain, into the so-called default domain */
	if (isns_config.ic_use_default_domain
	 && a->ie_template == b->ie_template
	 && isns_bitvector_is_empty(a->ie_membership)
	 && isns_bitvector_is_empty(b->ie_membership))
		return 1;

	return isns_bitvector_intersect(a->ie_membership, b->ie_membership, NULL) >= 0;
}

/*
 * Return all visible nodes and portals
 */
static int
__isns_object_vis_callback(uint32_t dd_id, void *ptr)
{
	isns_object_list_t *list = ptr;

	/* Get all active members */
	isns_dd_get_members(dd_id, list, 1);
	return 0;
}

void
isns_object_get_visible(const isns_object_t *obj,
			isns_db_t *db,
			isns_object_list_t *result)
{
	if (isns_bitvector_is_empty(obj->ie_membership)) {
		/* Get all other nodes not in any DD */
		if (isns_config.ic_use_default_domain)
			isns_db_get_domainless(db,
					obj->ie_template,
					result);
		return;
	}

	isns_bitvector_foreach(obj->ie_membership,
			__isns_object_vis_callback,
			result);
}

/*
 * Object templates
 */
static uint32_t discovery_domain_attrs[] = {
	ISNS_TAG_DD_ID,
	ISNS_TAG_DD_SYMBOLIC_NAME,
	ISNS_TAG_DD_MEMBER_ISCSI_INDEX,
	ISNS_TAG_DD_MEMBER_ISCSI_NAME,
	ISNS_TAG_DD_MEMBER_FC_PORT_NAME,
	ISNS_TAG_DD_MEMBER_PORTAL_INDEX,
	ISNS_TAG_DD_MEMBER_PORTAL_IP_ADDR,
	ISNS_TAG_DD_MEMBER_PORTAL_TCP_UDP_PORT,
	ISNS_TAG_DD_FEATURES,
};

static uint32_t discovery_domain_key_attrs[] = {
	ISNS_TAG_DD_ID,
};

isns_object_template_t		isns_dd_template = {
	.iot_name	= "Discovery Domain",
	.iot_handle	= ISNS_OBJECT_TYPE_DD,
	.iot_attrs	= discovery_domain_attrs,
	.iot_num_attrs	= array_num_elements(discovery_domain_attrs),
	.iot_keys	= discovery_domain_key_attrs,
	.iot_num_keys	= array_num_elements(discovery_domain_key_attrs),
	.iot_index	= ISNS_TAG_DD_ID,
	.iot_next_index	= ISNS_TAG_DD_NEXT_ID,
};

static uint32_t dd_set_attrs[] = {
	ISNS_TAG_DD_SET_ID,
	ISNS_TAG_DD_SET_SYMBOLIC_NAME,
	ISNS_TAG_DD_SET_STATUS,
};

static uint32_t dd_set_key_attrs[] = {
	ISNS_TAG_DD_SET_ID,
};

isns_object_template_t		isns_ddset_template = {
	.iot_name	= "Discovery Domain Set",
	.iot_handle	= ISNS_OBJECT_TYPE_DDSET,
	.iot_attrs	= dd_set_attrs,
	.iot_num_attrs	= array_num_elements(dd_set_attrs),
	.iot_keys	= dd_set_key_attrs,
	.iot_num_keys	= array_num_elements(dd_set_key_attrs),
	.iot_next_index	= ISNS_TAG_DD_SET_NEXT_ID,
};

