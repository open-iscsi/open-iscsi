/*
 * iSNS object model
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "isns.h"
#include "objects.h"
#include "source.h"
#include "vendor.h"
#include "attrs.h"
#include "util.h"

/* For relationship stuff - should go */
#include "db.h"

static isns_object_template_t *	isns_object_templates[] = {
	&isns_entity_template,
	&isns_portal_template,
	&isns_iscsi_node_template,
	&isns_fc_port_template,
	&isns_fc_node_template,
	&isns_iscsi_pg_template,
	&isns_dd_template,
	&isns_ddset_template,

	/* vendor-specific templates */
	&isns_policy_template,

	NULL
};

/*
 * Quick lookup of (key) tag to template
 */
#define MAX_QUICK_TAG		2100
static isns_object_template_t *	isns_object_template_key_map[MAX_QUICK_TAG];
static isns_object_template_t *	isns_object_template_any_map[MAX_QUICK_TAG];
static isns_object_template_t *	isns_object_template_idx_map[MAX_QUICK_TAG];
static int			isns_object_maps_inizialized = 0;


static void
__isns_object_maps_init(void)
{
	isns_object_template_t *tmpl;
	uint32_t	i, j, tag;

	isns_object_maps_inizialized = 1;

	for (i = 0; (tmpl = isns_object_templates[i]) != NULL; ++i) {
		if (tmpl->iot_vendor_specific)
			continue;

		tag = tmpl->iot_keys[0];
		isns_assert(tag < MAX_QUICK_TAG);
		isns_object_template_key_map[tag] = tmpl;

		for (j = 0; j < tmpl->iot_num_attrs; ++j) {
			tag = tmpl->iot_attrs[j];
			isns_assert(tag < MAX_QUICK_TAG);
			isns_object_template_any_map[tag] = tmpl;
		}

		if ((tag = tmpl->iot_index) != 0)
			isns_object_template_idx_map[tag] = tmpl;
	}
}

static void
isns_object_maps_init(void)
{
	if (!isns_object_maps_inizialized)
		__isns_object_maps_init();
}

/*
 * Based on a given key attribute, find the corresponding
 * object type.
 */
isns_object_template_t *
isns_object_template_find(uint32_t key_tag)
{
	isns_object_template_t *tmpl;
	unsigned int	i;

	isns_object_maps_init();
	if (key_tag < MAX_QUICK_TAG)
		return isns_object_template_key_map[key_tag];

	for (i = 0; (tmpl = isns_object_templates[i]) != NULL; ++i) {
		if (tmpl->iot_keys[0] == key_tag)
			return tmpl;
	}

	return NULL;
}

/*
 * Given a set of attributes, find the corresponding
 * object type.
 * Any attributes in the list in *addition to* the keys
 * attributes are ignored.
 */
isns_object_template_t *
isns_object_template_for_key_attrs(const isns_attr_list_t *attrs)
{
	isns_object_template_t *tmpl;
	const isns_attr_t *attr;
	unsigned int	i;

	if (attrs->ial_count == 0)
		return NULL;
	attr = attrs->ial_data[0];

	tmpl = isns_object_template_find(attr->ia_tag_id);
	if (tmpl == NULL)
		return NULL;

	/*
	 * 5.6.4.
	 *
	 * Some objects are keyed by more than one object key attribute
	 * value. For example, the Portal object is keyed by attribute
	 * tags 16 and 17.  When describing an object keyed by more than one
	 * key attribute, every object key attribute of that object MUST be
	 * listed sequentially by tag value in the message before non-key
	 * attributes of that object and key attributes of the next object.
	 * A group of key attributes of this kind is treated as a single
	 * logical key attribute when identifying an object.
	 */
	for (i = 1; i < tmpl->iot_num_keys; ++i) {
		attr = attrs->ial_data[i];

		if (attr->ia_tag_id != tmpl->iot_keys[i])
			return NULL;
	}

	return tmpl;
}

isns_object_template_t *
isns_object_template_for_tag(uint32_t tag)
{
	isns_object_template_t *tmpl;
	unsigned int	i, j;

	isns_object_maps_init();
	if (tag < MAX_QUICK_TAG)
		return isns_object_template_any_map[tag];

	for (i = 0; (tmpl = isns_object_templates[i]) != NULL; ++i) {
		for (j = 0; j < tmpl->iot_num_attrs; ++j) {
			if (tmpl->iot_attrs[j] == tag)
				return tmpl;
		}
	}

	return NULL;
}

isns_object_template_t *
isns_object_template_for_index_tag(uint32_t tag)
{
	isns_object_maps_init();
	if (tag >= MAX_QUICK_TAG)
		return NULL;

	return isns_object_template_idx_map[tag];
}

isns_object_template_t *
isns_object_template_by_name(const char *name)
{
	isns_object_template_t **pp, *tmpl;

	pp = isns_object_templates;
	while ((tmpl = *pp++) != NULL) {
		if (!strcasecmp(tmpl->iot_name, name))
			return tmpl;
	}
	return NULL;
}

const char *
isns_object_template_name(isns_object_template_t *tmpl)
{
	if (!tmpl)
		return NULL;
	return tmpl->iot_name;
}

/*
 * Notify any listeners that the object has changed,
 * and mark it dirty.
 * dd_or_dds is used for DD_MEMBER_ADDED and
 * DD_MEMBER_REMOVED events, and refers to the
 * domain or domain set the object was added to or
 * removed from.
 */
void
isns_mark_object(isns_object_t *obj, unsigned int how)
{
	obj->ie_flags |= ISNS_OBJECT_DIRTY;
	obj->ie_mtime = time(NULL);
	obj->ie_scn_bits |= (1 << how);
	isns_object_event(obj, 0, NULL);
}

static void
__isns_mark_object(isns_object_t *obj)
{
	obj->ie_flags |= ISNS_OBJECT_DIRTY;
	obj->ie_mtime = time(NULL);
}

/*
 * Create an object given its object template
 */
isns_object_t *
isns_create_object(isns_object_template_t *tmpl,
		const isns_attr_list_t *attrs,
		isns_object_t *parent)
{
	isns_object_t	*obj;
	unsigned int	i;

	/* Enforce containment rules. */
	if (parent)
		isns_assert(tmpl->iot_container == parent->ie_template);

#ifdef notdef
	/* This check is somewhat costly: */
	if (attrs && tmpl != isns_object_template_for_key_attrs(attrs))
		return NULL;
#endif

	obj = isns_calloc(1, sizeof(*obj));

	obj->ie_users = 1;
	obj->ie_template = tmpl;
	isns_attr_list_init(&obj->ie_attrs);

	if (parent)
		isns_object_attach(obj, parent);

	if (attrs == NULL) {
		/* Make sure that all key attrs are instantiated
		 * and in sequence. */
		for (i = 0; i < tmpl->iot_num_keys; ++i)
			isns_attr_list_append_nil(&obj->ie_attrs,
					tmpl->iot_keys[i]);
	} else {
		/* We rely on the caller to ensure that
		 * attributes are in proper sequence. */
		isns_attr_list_copy(&obj->ie_attrs, attrs);
	}

	/* Just mark it dirty, but do not schedule a
	 * SCN event. */
	__isns_mark_object(obj);

	return obj;
}

/*
 * Obtain an additional reference on the object
 */
isns_object_t *
isns_object_get(isns_object_t *obj)
{
	if (obj) {
		isns_assert(obj->ie_users);
		obj->ie_users++;
	}
	return obj;
}

/*
 * Release a reference on the object
 */
void
isns_object_release(isns_object_t *obj)
{
	unsigned int	i;
	isns_object_t	*child;

	if (!obj)
		return;

	isns_assert(obj->ie_users);
	if (--(obj)->ie_users != 0)
		return;

	/* Must not have any live references to it */
	isns_assert(obj->ie_references == 0);

	/* Must be detached from parent */
	isns_assert(obj->ie_container == NULL);

	/* Release all children. We explicitly clear
	 * ie_container because the destructor
	 * checks for this (in order to catch
	 * refcounting bugs) */
	for (i = 0; i < obj->ie_children.iol_count; ++i) {
		child = obj->ie_children.iol_data[i];
		child->ie_container = NULL;
	}
	isns_object_list_destroy(&obj->ie_children);

	isns_attr_list_destroy(&obj->ie_attrs);

	isns_bitvector_free(obj->ie_membership);
	isns_free(obj);
}

/*
 * Get the topmost container (ie Network Entity)
 * for the given object
 */
isns_object_t *
isns_object_get_entity(isns_object_t *obj)
{
	if (obj == NULL)
		return NULL;
	while (obj->ie_container)
		obj = obj->ie_container;
	if (!ISNS_IS_ENTITY(obj))
		return NULL;
	return obj;
}

int
isns_object_contains(const isns_object_t *ancestor,
		const isns_object_t *descendant)
{
	while (descendant) {
		if (descendant == ancestor)
			return 1;
		descendant = descendant->ie_container;
	}
	return 0;
}

/*
 * Get all children of the specified type
 */
void
isns_object_get_descendants(const isns_object_t *obj,
		isns_object_template_t *tmpl,
		isns_object_list_t *result)
{
	isns_object_t	*child;
	unsigned int	i;

	for (i = 0; i < obj->ie_children.iol_count; ++i) {
		child = obj->ie_children.iol_data[i];
		if (!tmpl || child->ie_template == tmpl)
			isns_object_list_append(result, child);
	}
}

/*
 * Attach an object to a new container
 */
int
isns_object_attach(isns_object_t *obj, isns_object_t *parent)
{
	isns_assert(obj->ie_container == NULL);

	if (parent) {
		/* Copy the owner (ie source) from the parent
		 * object.
		 * Make sure the parent object type is a valid
		 * container for this object.
		 */
		if (parent->ie_template != obj->ie_template->iot_container) {
			isns_error("You are not allowed to add a %s object "
				   "to a %s!\n",
				   obj->ie_template->iot_name,
				   parent->ie_template->iot_name);
			return 0;
		}
		obj->ie_flags = parent->ie_flags & ISNS_OBJECT_PRIVATE;
		isns_object_list_append(&parent->ie_children, obj);
	}
	obj->ie_container = parent;
	return 1;
}

int
isns_object_is_valid_container(const isns_object_t *container,
		isns_object_template_t *child_type)
{
	return child_type->iot_container == container->ie_template;
}

/*
 * Detach an object from its container
 */
int
isns_object_detach(isns_object_t *obj)
{
	isns_object_t	*parent;

	/* Detach from parent */
	if ((parent = obj->ie_container) != NULL) {
		int	removed;

		obj->ie_container = NULL;
		removed = isns_object_list_remove(
				&parent->ie_children, obj);

		isns_assert(removed != 0);
	}

	return 0;
}

/*
 * Check the type of an object
 */
int
isns_object_is(const isns_object_t *obj,
		isns_object_template_t *tmpl)
{
	return obj->ie_template == tmpl;
}

int
isns_object_is_iscsi_node(const isns_object_t *obj)
{
	return ISNS_IS_ISCSI_NODE(obj);
}

int
isns_object_is_fc_port(const isns_object_t *obj)
{
	return ISNS_IS_FC_PORT(obj);
}

int
isns_object_is_fc_node(const isns_object_t *obj)
{
	return ISNS_IS_FC_NODE(obj);
}

int
isns_object_is_portal(const isns_object_t *obj)
{
	return ISNS_IS_PORTAL(obj);
}

int
isns_object_is_pg(const isns_object_t *obj)
{
	return ISNS_IS_PG(obj);
}

int
isns_object_is_policy(const isns_object_t *obj)
{
	return ISNS_IS_POLICY(obj);
}

/*
 * Match an object against a list of attributes.
 */
int
isns_object_match(const isns_object_t *obj,
		const isns_attr_list_t *attrs)
{
	isns_object_template_t *tmpl = obj->ie_template;
	isns_attr_t	*self, *match;
	unsigned int	i, j, from = 0;
	uint32_t	tag;

	/* Fast path: try to compare in-order */
	while (from < attrs->ial_count) {
		match = attrs->ial_data[from];
		self = obj->ie_attrs.ial_data[from];

		if (match->ia_tag_id != self->ia_tag_id)
			goto slow_path;

		if (!isns_attr_match(self, match))
			return 0;

		from++;
	}

	return 1;

slow_path:
	for (i = from; i < attrs->ial_count; ++i) {
		isns_attr_t *found = NULL;

		match = attrs->ial_data[i];

		/*
		 * 5.6.5.2
		 * A Message Key with zero-length TLV(s) is scoped to
		 * every object of the type indicated by the zero-length
		 * TLV(s)
		 */
		if (match->ia_value.iv_type == &isns_attr_type_nil) {
			tag = match->ia_tag_id;
			if (isns_object_attr_valid(tmpl, tag))
				continue;
			return 0;
		}

		for (j = from; j < obj->ie_attrs.ial_count; ++j) {
			self = obj->ie_attrs.ial_data[j];

			if (match->ia_tag_id == self->ia_tag_id) {
				found = self;
				break;
			}
		}

		if (found == NULL)
			return 0;

		if (!isns_attr_match(self, match))
			return 0;
	}
	return 1;
}

/*
 * Find descendant object matching the given key
 */
isns_object_t *
isns_object_find_descendant(isns_object_t *obj, const isns_attr_list_t *keys)
{
	isns_object_list_t list = ISNS_OBJECT_LIST_INIT;
	isns_object_t	*found;

	if (!isns_object_find_descendants(obj, NULL, keys, &list))
		return NULL;

	found = isns_object_get(list.iol_data[0]);
	isns_object_list_destroy(&list);

	return found;
}

int
isns_object_find_descendants(isns_object_t *obj,
		isns_object_template_t *tmpl,
		const isns_attr_list_t *keys,
		isns_object_list_t *result)
{
	isns_object_t	*child;
	unsigned int	i;

	if ((tmpl == NULL || tmpl == obj->ie_template)
	 && (keys == NULL || isns_object_match(obj, keys)))
		isns_object_list_append(result, obj);

	for (i = 0; i < obj->ie_children.iol_count; ++i) {
		child = obj->ie_children.iol_data[i];
		isns_object_find_descendants(child, tmpl, keys, result);
	}

	return result->iol_count;
}

/*
 * Return the object's modification time stamp
 */
time_t
isns_object_last_modified(const isns_object_t *obj)
{
	return obj->ie_mtime;
}

/*
 * Set the SCN bitmap
 */
void
isns_object_set_scn_mask(isns_object_t *obj, uint32_t bitmap)
{
	obj->ie_scn_mask = bitmap;
	__isns_mark_object(obj);
}

/*
 * Debugging utility: print the object
 */
void
isns_object_print(isns_object_t *obj, isns_print_fn_t *fn)
{
	isns_attr_list_print(&obj->ie_attrs, fn);
}

/*
 * Return a string representing the object state
 */
const char *
isns_object_state_string(unsigned int state)
{
	switch (state) {
	case ISNS_OBJECT_STATE_LARVAL:
		return "larval";
	case ISNS_OBJECT_STATE_MATURE:
		return "mature";
	case ISNS_OBJECT_STATE_LIMBO:
		return "limbo";
	case ISNS_OBJECT_STATE_DEAD:
		return "dead";
	}
	return "UNKNOWN";
}

/*
 * This is needed when deregistering an object.
 * Remove all attributes except the key and index attrs.
 */
void
isns_object_prune_attrs(isns_object_t *obj)
{
	isns_object_template_t *tmpl = obj->ie_template;
	uint32_t	tags[16];
	unsigned int	i;

	isns_assert(tmpl->iot_num_keys + 1 <= 16);
	for (i = 0; i < tmpl->iot_num_keys; ++i)
		tags[i] = tmpl->iot_keys[i];
	if (tmpl->iot_index)
		tags[i++] = tmpl->iot_index;
	isns_attr_list_prune(&obj->ie_attrs, tags, i);
}

/*
 * Convenience functions
 */

/*
 * Create a portal object.
 * For now, always assume TCP.
 */
isns_object_t *
isns_create_portal(const isns_portal_info_t *info,
		isns_object_t *parent)
{
	isns_object_t	*obj;

	obj = isns_create_object(&isns_portal_template, NULL, parent);
	isns_portal_to_object(info,
			ISNS_TAG_PORTAL_IP_ADDRESS,
			ISNS_TAG_PORTAL_TCP_UDP_PORT,
			obj);
	return obj;
}

/*
 * Extract all key attrs and place them
 * in the attribute list.
 */
int
isns_object_extract_keys(const isns_object_t *obj,
		isns_attr_list_t *list)
{
	isns_object_template_t *tmpl = obj->ie_template;
	const isns_attr_list_t *src = &obj->ie_attrs;
	unsigned int	i;

	for (i = 0; i < tmpl->iot_num_keys; ++i) {
		isns_attr_t	*attr;

		if (!isns_attr_list_get_attr(src, tmpl->iot_keys[i], &attr))
			return 0;
		isns_attr_list_append_attr(list, attr);
	}

	return 1;
}

/*
 * Extract all attributes we are permitted to overwrite and place them
 * in the attribute list.
 */
int
isns_object_extract_writable(const isns_object_t *obj,
		isns_attr_list_t *list)
{
	const isns_attr_list_t *src = &obj->ie_attrs;
	unsigned int	i;

	for (i = 0; i < src->ial_count; ++i) {
		isns_attr_t	*attr = src->ial_data[i];

		if (attr->ia_tag->it_readonly)
			continue;
		isns_attr_list_append_attr(list, attr);
	}

	return 1;
}

/*
 * Extract all attrs and place them
 * in the attribute list. We copy the attributes
 * as they appear inside the object; which allows
 * duplicate attributes (eg inside a discovery domain).
 */
int
isns_object_extract_all(const isns_object_t *obj, isns_attr_list_t *list)
{
	isns_attr_list_append_list(list, &obj->ie_attrs);
	return 1;
}

/*
 * Check if the given object is valid
 */
int
isns_object_attr_valid(isns_object_template_t *tmpl, uint32_t tag)
{
	const uint32_t	*attr_tags = tmpl->iot_attrs;
	unsigned int	i;

	for (i = 0; i < tmpl->iot_num_attrs; ++i) {
		if (*attr_tags == tag)
			return 1;
		++attr_tags;
	}
	return 0;
}

/*
 * Set an object attribute
 */
static int
__isns_object_set_attr(isns_object_t *obj, uint32_t tag,
		const isns_attr_type_t *type,
		const isns_value_t *value)
{
	const isns_tag_type_t *tag_type;

	if (!isns_object_attr_valid(obj->ie_template, tag))
		return 0;

	tag_type = isns_tag_type_by_id(tag);
	if (type != &isns_attr_type_nil
	 && type != tag_type->it_type) {
		isns_warning("application bug: cannot set attr %s(id=%u, "
			"type=%s) to a value of type %s\n",
			tag_type->it_name, tag,
			tag_type->it_type->it_name,
			type->it_name);
		return 0;
	}

	isns_attr_list_update_value(&obj->ie_attrs,
			tag, tag_type, value);

	/* Timestamp updates should just be written out, but we
	 * do not want to trigger SCN messages and such. */
	if (tag != ISNS_TAG_TIMESTAMP)
		isns_mark_object(obj, ISNS_SCN_OBJECT_UPDATED);
	else
		__isns_mark_object(obj);
	return 1;
}

/*
 * Copy an attribute to the object
 */
int
isns_object_set_attr(isns_object_t *obj, isns_attr_t *attr)
{
	isns_attr_list_t *list = &obj->ie_attrs;
	uint32_t	tag = attr->ia_tag_id;

	/* If this attribute exists within the object,
	 * and it cannot occur multiple times, replace it. */
	if (!attr->ia_tag->it_multiple
	 && isns_attr_list_replace_attr(list, attr))
		goto done;

	/* It doesn't exist; make sure it's a valid
	 * attribute. */
	if (!isns_object_attr_valid(obj->ie_template, tag))
		return 0;

	isns_attr_list_append_attr(list, attr);

done:
	isns_mark_object(obj, ISNS_SCN_OBJECT_UPDATED);
	return 1;
}

int
isns_object_set_attrlist(isns_object_t *obj, const isns_attr_list_t *attrs)
{
	unsigned int	i;

	for (i = 0; i < attrs->ial_count; ++i) {
		isns_attr_t	*attr = attrs->ial_data[i];
		if (!isns_object_set_attr(obj, attr))
			return 0;
	}
	isns_mark_object(obj, ISNS_SCN_OBJECT_UPDATED);
	return 1;
}

/*
 * Untyped version of isns_object_set.
 * Any type checking must be done by the caller;
 * failure to do so will result in the end of the world.
 */
int
isns_object_set_value(isns_object_t *obj, uint32_t tag, const void *data)
{
	return isns_attr_list_update(&obj->ie_attrs, tag, data);
}

/*
 * Typed versions of isns_object_set
 */
int
isns_object_set_nil(isns_object_t *obj, uint32_t tag)
{
	return __isns_object_set_attr(obj, tag,
			&isns_attr_type_nil, NULL);
}

int
isns_object_set_string(isns_object_t *obj, uint32_t tag,
		const char *value)
{
	isns_value_t var = ISNS_VALUE_INIT(string, (char *) value);
	int	rc;

	rc = __isns_object_set_attr(obj, tag,
			&isns_attr_type_string, &var);
	return rc;
}

int
isns_object_set_uint32(isns_object_t *obj, uint32_t tag,
		uint32_t value)
{
	isns_value_t var = ISNS_VALUE_INIT(uint32, value);

	return __isns_object_set_attr(obj, tag,
			&isns_attr_type_uint32, &var);
}

int
isns_object_set_uint64(isns_object_t *obj,	
				uint32_t tag,
				uint64_t value)
{
	isns_value_t var = ISNS_VALUE_INIT(uint64, value);

	return __isns_object_set_attr(obj, tag,
			&isns_attr_type_uint64, &var);
}

int
isns_object_set_ipaddr(isns_object_t *obj, uint32_t tag,
		const struct in6_addr *value)
{
	isns_value_t var = ISNS_VALUE_INIT(ipaddr, *value);

	return __isns_object_set_attr(obj, tag,
			&isns_attr_type_ipaddr, &var);
}

/*
 * Query object attributes
 */
int
isns_object_get_attr(const isns_object_t *obj, uint32_t tag,
		isns_attr_t **result)
{
	return isns_attr_list_get_attr(&obj->ie_attrs, tag, result);
}

int
isns_object_get_attrlist(isns_object_t *obj,
		isns_attr_list_t *result,
		const isns_attr_list_t *req_attrs)
{
	isns_attr_list_t *attrs = &obj->ie_attrs;
	isns_attr_t	*attr;
	unsigned int	i;

	if (req_attrs == NULL) {
		/* Retrieve all attributes */
		isns_attr_list_append_list(result, attrs);
	} else {
		for (i = 0; i < req_attrs->ial_count; ++i) {
			uint32_t tag = req_attrs->ial_data[i]->ia_tag_id;

			if (tag == obj->ie_template->iot_next_index) {
				/* FIXME: for now, we fake this value.
				 * We need the DB object at this point
				 * to find out what the next unused
				 * index is.
				 */
				isns_attr_list_append_uint32(result,
						tag, 0);
			} else
			if (isns_attr_list_get_attr(attrs, tag, &attr))
				isns_attr_list_append_attr(result, attr);
		}
	}
	return 1;
}

int
isns_object_get_key_attrs(isns_object_t *obj,
			isns_attr_list_t *result)
{
	isns_object_template_t *tmpl = obj->ie_template;
	isns_attr_list_t *attrs = &obj->ie_attrs;
	isns_attr_t	*attr;
	unsigned int	i;

	for (i = 0; i < tmpl->iot_num_keys; ++i) {
		uint32_t	tag = tmpl->iot_keys[i];

		if (!isns_attr_list_get_attr(attrs, tag, &attr)) {
			isns_error("%s: %s object is missing key attr %u\n",
					__FUNCTION__,
					tmpl->iot_name,
					tag);
			return 0;
		}
		isns_attr_list_append_attr(result, attr);
	}
	return 1;
}

int
isns_object_get_string(const isns_object_t *obj, uint32_t tag,
			const char **result)
{
	isns_attr_t	*attr;

	if (!isns_object_get_attr(obj, tag, &attr)
	 || !ISNS_ATTR_IS_STRING(attr))
		return 0;

	*result = attr->ia_value.iv_string;
	return 1;
}

int
isns_object_get_ipaddr(const isns_object_t *obj, uint32_t tag,
			struct in6_addr *result)
{
	isns_attr_t	*attr;

	if (!isns_object_get_attr(obj, tag, &attr)
	 || !ISNS_ATTR_IS_IPADDR(attr))
		return 0;

	*result = attr->ia_value.iv_ipaddr;
	return 1;
}

int
isns_object_get_uint32(const isns_object_t *obj, uint32_t tag,
			uint32_t *result)
{
	isns_attr_t	*attr;

	if (!isns_object_get_attr(obj, tag, &attr)
	 || !ISNS_ATTR_IS_UINT32(attr))
		return 0;

	*result = attr->ia_value.iv_uint32;
	return 1;
}

int
isns_object_get_uint64(const isns_object_t *obj, uint32_t tag,
			uint64_t *result)
{
	isns_attr_t	*attr;

	if (!isns_object_get_attr(obj, tag, &attr)
	 || !ISNS_ATTR_IS_UINT64(attr))
		return 0;

	*result = attr->ia_value.iv_uint64;
	return 1;
}

int
isns_object_get_opaque(const isns_object_t *obj, uint32_t tag,
			const void **ptr, size_t *len)
{
	isns_attr_t	*attr;

	if (!isns_object_get_attr(obj, tag, &attr)
	 || !ISNS_ATTR_IS_OPAQUE(attr))
		return 0;

	*ptr = attr->ia_value.iv_opaque.ptr;
	*len = attr->ia_value.iv_opaque.len;
	return 1;
}

int
isns_object_delete_attr(isns_object_t *obj, uint32_t tag)
{
	return isns_attr_list_remove_tag(&obj->ie_attrs, tag);
}

int
isns_object_remove_member(isns_object_t *obj,
		const isns_attr_t *attr,
		const uint32_t *subordinate_tags)
{
	return isns_attr_list_remove_member(&obj->ie_attrs,
			attr, subordinate_tags);
}

/*
 * Object list functions
 */
void
isns_object_list_init(isns_object_list_t *list)
{
	memset(list, 0, sizeof(*list));
}

static inline void
__isns_object_list_resize(isns_object_list_t *list, unsigned int count)
{
	unsigned int	max;

	max = (list->iol_count + 15) & ~15;
	if (count < max)
		return;

	count = (count + 15) & ~15;
	list->iol_data = isns_realloc(list->iol_data, count * sizeof(isns_object_t *));
	if (!list->iol_data)
		isns_fatal("Out of memory!\n");
}

void
isns_object_list_append(isns_object_list_t *list, isns_object_t *obj)
{
	__isns_object_list_resize(list, list->iol_count + 1);
	list->iol_data[list->iol_count++] = obj;
	obj->ie_users++;
}

void
isns_object_list_append_list(isns_object_list_t *dst,
			const isns_object_list_t *src)
{
	unsigned int	i, j;

	__isns_object_list_resize(dst, dst->iol_count + src->iol_count);
	j = dst->iol_count;
	for (i = 0; i < src->iol_count; ++i, ++j) {
		isns_object_t *obj = src->iol_data[i];

		dst->iol_data[j] = obj;
		obj->ie_users++;
	}
	dst->iol_count = j;
}

int
isns_object_list_contains(const isns_object_list_t *list,
		isns_object_t *obj)
{
	unsigned int	i;

	for (i = 0; i < list->iol_count; ++i) {
		if (obj == list->iol_data[i])
			return 1;
	}
	return 0;
}

isns_object_t *
isns_object_list_lookup(const isns_object_list_t *list,
		isns_object_template_t *tmpl,
		const isns_attr_list_t *keys)
{
	unsigned int	i;

	if (!tmpl && !keys)
		return NULL;

	if (!tmpl && !(tmpl = isns_object_template_for_key_attrs(keys)))
		return NULL;

	for (i = 0; i < list->iol_count; ++i) {
		isns_object_t	*obj = list->iol_data[i];

		if (obj->ie_template != tmpl)
			continue;
		if (keys && !isns_object_match(obj, keys))
			continue;

		obj->ie_users++;
		return obj;
	}

	return NULL;
}


int
isns_object_list_gang_lookup(const isns_object_list_t *list,
		isns_object_template_t *tmpl,
		const isns_attr_list_t *keys,
		isns_object_list_t *result)
{
	unsigned int	i;

	if (!tmpl && !keys)
		return ISNS_INVALID_QUERY;

	if (!tmpl && !(tmpl = isns_object_template_for_key_attrs(keys)))
		return ISNS_INVALID_QUERY;

	for (i = 0; i < list->iol_count; ++i) {
		isns_object_t	*obj = list->iol_data[i];

		if (obj->ie_template != tmpl)
			continue;
		if (keys && !isns_object_match(obj, keys))
			continue;

		isns_object_list_append(result, obj);
	}

	return ISNS_SUCCESS;
}


void
isns_object_list_destroy(isns_object_list_t *list)
{
	unsigned int	i;

	for (i = 0; i < list->iol_count; ++i) {
		isns_object_t	*obj = list->iol_data[i];

		isns_object_release(obj);
	}

	isns_free(list->iol_data);
	memset(list, 0, sizeof(*list));
}

int
isns_object_list_remove(isns_object_list_t *list, isns_object_t *tbr)
{
	unsigned int	i, last;

	last = list->iol_count - 1;
	for (i = 0; i < list->iol_count; ++i) {
		isns_object_t	*obj = list->iol_data[i];

		if (obj == tbr) {
			list->iol_data[i] = list->iol_data[last];
			list->iol_count--;
			isns_object_release(tbr);
			return 1;
		}
	}
	return 0;
}

static int
isns_object_compare_id(const void *pa, const void *pb)
{
	const isns_object_t *a = *(const isns_object_t **) pa;
	const isns_object_t *b = *(const isns_object_t **) pb;

	return (int) a->ie_index - (int) b->ie_index;
}

void
isns_object_list_sort(isns_object_list_t *list)
{
	if (list->iol_count == 0)
		return;

	qsort(list->iol_data, list->iol_count,
			sizeof(void *), isns_object_compare_id);
}

void
isns_object_list_uniq(isns_object_list_t *list)
{
	isns_object_t	*prev = NULL, *this;
	unsigned int	i, j;

	isns_object_list_sort(list);
	for (i = j = 0; i < list->iol_count; i++) {
		this = list->iol_data[i];
		if (this != prev)
			list->iol_data[j++] = this;
		prev = this;
	}
	list->iol_count = j;
}

void
isns_object_list_print(const isns_object_list_t *list, isns_print_fn_t *fn)
{
	unsigned int	i;

	if (list->iol_count == 0) {
		fn("(Object list empty)\n");
		return;
	}

	for (i = 0; i < list->iol_count; ++i) {
		isns_object_t *obj;

		obj = list->iol_data[i];
		fn("object[%u] = <%s>\n", i,
				obj->ie_template->iot_name);
		isns_object_print(obj, fn);
	}
}

/*
 * Handle object references
 */
void
isns_object_reference_set(isns_object_ref_t *ref, isns_object_t *obj)
{
	isns_object_t *old;

	if (obj) {
		isns_assert(obj->ie_users);
		obj->ie_references++;
		obj->ie_users++;
	}
	if ((old = ref->obj) != NULL) {
		isns_assert(old->ie_references);
		old->ie_references--;
		isns_object_release(old);
	}
	ref->obj = obj;
}

void
isns_object_reference_drop(isns_object_ref_t *ref)
{
	isns_object_reference_set(ref, NULL);
}

/*
 * Helper function for portal/object conversion
 */
int
isns_portal_from_object(isns_portal_info_t *portal,
		uint32_t addr_tag, uint32_t port_tag,
		const isns_object_t *obj)
{
	return isns_portal_from_attr_list(portal,
			addr_tag, port_tag, &obj->ie_attrs);
}

int
isns_portal_to_object(const isns_portal_info_t *portal, 
		uint32_t addr_tag, uint32_t port_tag,
		isns_object_t *obj)
{
	return isns_portal_to_attr_list(portal,
			addr_tag, port_tag,
			&obj->ie_attrs);
}

/*
 * Portal
 */
static uint32_t	portal_attrs[] = {
	ISNS_TAG_PORTAL_IP_ADDRESS,
	ISNS_TAG_PORTAL_TCP_UDP_PORT,
	ISNS_TAG_PORTAL_SYMBOLIC_NAME,
	ISNS_TAG_ESI_INTERVAL,
	ISNS_TAG_ESI_PORT,
	ISNS_TAG_PORTAL_INDEX,
	ISNS_TAG_SCN_PORT,
	ISNS_TAG_PORTAL_NEXT_INDEX,
	ISNS_TAG_PORTAL_SECURITY_BITMAP,
	ISNS_TAG_PORTAL_ISAKMP_PHASE_1,
	ISNS_TAG_PORTAL_ISAKMP_PHASE_2,
	ISNS_TAG_PORTAL_CERTIFICATE,
};

static uint32_t	portal_key_attrs[] = {
	ISNS_TAG_PORTAL_IP_ADDRESS,
	ISNS_TAG_PORTAL_TCP_UDP_PORT,
};

isns_object_template_t		isns_portal_template = {
	.iot_name	= "Portal",
	.iot_handle	= ISNS_OBJECT_TYPE_PORTAL,
	.iot_attrs	= portal_attrs,
	.iot_num_attrs	= array_num_elements(portal_attrs),
	.iot_keys	= portal_key_attrs,
	.iot_num_keys	= array_num_elements(portal_key_attrs),
	.iot_index	= ISNS_TAG_PORTAL_INDEX,
	.iot_next_index	= ISNS_TAG_PORTAL_NEXT_INDEX,
	.iot_container	= &isns_entity_template,
};
