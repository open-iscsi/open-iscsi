/*
 * iSNS object model - network entity specific code
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "isns.h"
#include "objects.h"
#include "util.h"

/*
 * Create a network entity
 */
isns_object_t *
isns_create_entity(int protocol, const char *name)
{
	isns_object_t	*obj;

	obj = isns_create_object(&isns_entity_template, NULL, NULL);
	isns_object_set_string(obj,
			ISNS_TAG_ENTITY_IDENTIFIER,
			name);
	isns_object_set_uint32(obj,
			ISNS_TAG_ENTITY_PROTOCOL,
			protocol);

	return obj;
}

isns_object_t *
isns_create_entity_for_source(const isns_source_t *source,
		const char *eid)
{
	switch (isns_source_type(source)) {
	case ISNS_TAG_ISCSI_NAME:
		return isns_create_entity(ISNS_ENTITY_PROTOCOL_ISCSI, eid);

	case ISNS_TAG_FC_PORT_NAME_WWPN:
		return isns_create_entity(ISNS_ENTITY_PROTOCOL_IFCP, eid);
	}

	return NULL;
}

const char *
isns_entity_name(const isns_object_t *node)
{
	const isns_attr_t *attr;

	if (node->ie_attrs.ial_count == 0)
		return NULL;
	attr = node->ie_attrs.ial_data[0];
	if (attr->ia_value.iv_type != &isns_attr_type_string
	 || attr->ia_tag_id != ISNS_TAG_ENTITY_IDENTIFIER)
		return NULL;

	return attr->ia_value.iv_string;

}

int
isns_object_is_entity(const isns_object_t *obj)
{
	return ISNS_IS_ENTITY(obj);
}

/*
 * 6.2.4.  Entity Registration Timestamp
 *
 * This field indicates the most recent time when the Network Entity
 * registration occurred or when an associated object attribute was
 * updated or queried by the iSNS client registering the Network Entity.
 * The time format is, in seconds, the update period since the standard
 * base time of 00:00:00 GMT on January 1, 1970.  This field cannot be
 * explicitly registered.  This timestamp TLV format is also used in
 * the SCN and ESI messages.
 *
 * Implementer's note: we consider any kind of activity from
 * the client an indication that it is still alive.
 * Only exception is the pseudo-entity that holds the access control
 * information; we never assign it a timestamp so it is never subject
 * to expiry.
 */
void
isns_entity_touch(isns_object_t *obj)
{
	/* Do not add a timestamp to entity CONTROL */
	if (obj == NULL
	 || (obj->ie_flags & ISNS_OBJECT_PRIVATE)
	 || obj->ie_template != &isns_entity_template)
		return;
	isns_object_set_uint64(obj, ISNS_TAG_TIMESTAMP, time(NULL));
}

/*
 * Object template
 */
static uint32_t entity_attrs[] = {
	ISNS_TAG_ENTITY_IDENTIFIER,
	ISNS_TAG_ENTITY_PROTOCOL,
	ISNS_TAG_MGMT_IP_ADDRESS,
	ISNS_TAG_TIMESTAMP,
	ISNS_TAG_PROTOCOL_VERSION_RANGE,
	ISNS_TAG_REGISTRATION_PERIOD,
	ISNS_TAG_ENTITY_INDEX,
	ISNS_TAG_ENTITY_ISAKMP_PHASE_1,
	ISNS_TAG_ENTITY_CERTIFICATE,
};

static uint32_t	entity_key_attrs[] = {
	ISNS_TAG_ENTITY_IDENTIFIER,
};

isns_object_template_t		isns_entity_template = {
	.iot_name	= "Network Entity",
	.iot_handle	= ISNS_OBJECT_TYPE_ENTITY,
	.iot_attrs	= entity_attrs,
	.iot_num_attrs	= array_num_elements(entity_attrs),
	.iot_keys	= entity_key_attrs,
	.iot_num_keys	= array_num_elements(entity_key_attrs),
	.iot_index	= ISNS_TAG_ENTITY_INDEX,
	.iot_next_index	= ISNS_TAG_ENTITY_NEXT_INDEX,
};

