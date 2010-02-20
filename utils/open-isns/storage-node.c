/*
 * iSNS object model - storage node
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "isns.h"
#include "objects.h"
#include "util.h"

isns_object_t *
isns_create_storage_node(const char *name, uint32_t type,
			isns_object_t *parent)
{
	isns_object_t	*obj;

	if (parent && !ISNS_IS_ENTITY(parent)) {
		isns_warning("Invalid container type \"%s\" for storage node: "
			"should be \"%s\"\n",
			parent->ie_template->iot_name,
			isns_entity_template.iot_name);
		return NULL;
	}

	obj = isns_create_object(&isns_iscsi_node_template, NULL, parent);
	isns_object_set_string(obj,
			ISNS_TAG_ISCSI_NAME, name);
	isns_object_set_uint32(obj,
			ISNS_TAG_ISCSI_NODE_TYPE, type);

	return obj;
}

isns_object_t *
isns_create_storage_node2(const isns_source_t *source,
				uint32_t type,
				isns_object_t *parent)
{
	isns_attr_t	*name_attr;
	isns_object_t	*obj;

	if (parent && !ISNS_IS_ENTITY(parent)) {
		isns_warning("Invalid container type \"%s\" for storage node: "
			"should be \"%s\"\n",
			parent->ie_template->iot_name,
			isns_entity_template.iot_name);
		return NULL;
	}
	if ((name_attr = isns_source_attr(source)) == NULL) {
		isns_warning("No source attribute\n");
		return NULL;
	}

	if (name_attr->ia_tag_id == ISNS_TAG_ISCSI_NAME) {
		obj = isns_create_object(&isns_iscsi_node_template, NULL, parent);
		isns_attr_list_update_attr(&obj->ie_attrs, name_attr);
		isns_object_set_uint32(obj,
				ISNS_TAG_ISCSI_NODE_TYPE, type);
	} else {
		/* No iFCP yet, sorry */
		isns_warning("%s: source tag type %u not supported\n",
				__FUNCTION__);
		return NULL;
	}

	return obj;
}

isns_object_t *
isns_create_iscsi_initiator(const char *name,
			isns_object_t *parent)
{
	return isns_create_storage_node(name, 
			1 << ISNS_ISCSI_NODE_TYPE_INITIATOR,
			parent);
}

isns_object_t *
isns_create_iscsi_target(const char *name,
			isns_object_t *parent)
{
	return isns_create_storage_node(name, 
			1 << ISNS_ISCSI_NODE_TYPE_TARGET,
			parent);
}

const char *
isns_storage_node_name(const isns_object_t *node)
{
	const isns_attr_t *attr;

	if (node->ie_attrs.ial_count == 0)
		return NULL;
	attr = node->ie_attrs.ial_data[0];
	if (attr->ia_value.iv_type != &isns_attr_type_string)
		return NULL;

	switch (attr->ia_tag_id) {
	case ISNS_TAG_ISCSI_NAME:
	case ISNS_TAG_FC_PORT_NAME_WWPN:
		return attr->ia_value.iv_string;
	}

	return 0;

}

isns_attr_t *
isns_storage_node_key_attr(const isns_object_t *node)
{
	if (node->ie_attrs.ial_count == 0)
		return NULL;
	return node->ie_attrs.ial_data[0];
}

static uint32_t iscsi_node_attrs[] = {
	ISNS_TAG_ISCSI_NAME,
	ISNS_TAG_ISCSI_NODE_TYPE,
	ISNS_TAG_ISCSI_ALIAS,
	ISNS_TAG_ISCSI_SCN_BITMAP,
	ISNS_TAG_ISCSI_NODE_INDEX,
	ISNS_TAG_WWNN_TOKEN,
	ISNS_TAG_ISCSI_AUTHMETHOD,
	/* RFC 4171 lists a "iSCSI node certificate"
	 * as an option attribute of an iSCSI
	 * storage node, but doesn't define it anywhere
	 * in the spec.
	 */
};

static uint32_t iscsi_node_key_attrs[] = {
	ISNS_TAG_ISCSI_NAME,
};

isns_object_template_t		isns_iscsi_node_template = {
	.iot_name	= "iSCSI Storage Node",
	.iot_handle	= ISNS_OBJECT_TYPE_NODE,
	.iot_attrs	= iscsi_node_attrs,
	.iot_num_attrs	= array_num_elements(iscsi_node_attrs),
	.iot_keys	= iscsi_node_key_attrs,
	.iot_num_keys	= array_num_elements(iscsi_node_key_attrs),
	.iot_index	= ISNS_TAG_ISCSI_NODE_INDEX,
	.iot_next_index	= ISNS_TAG_ISCSI_NODE_NEXT_INDEX,
	.iot_container	= &isns_entity_template,
};

static uint32_t fc_port_attrs[] = {
	ISNS_TAG_FC_PORT_NAME_WWPN,
	ISNS_TAG_PORT_ID,
	ISNS_TAG_FC_PORT_TYPE,
	ISNS_TAG_SYMBOLIC_PORT_NAME,
	ISNS_TAG_FABRIC_PORT_NAME,
	ISNS_TAG_HARD_ADDRESS,
	ISNS_TAG_PORT_IP_ADDRESS,
	ISNS_TAG_CLASS_OF_SERVICE,
	ISNS_TAG_FC4_TYPES,
	ISNS_TAG_FC4_DESCRIPTOR,
	ISNS_TAG_FC4_FEATURES,
	ISNS_TAG_IFCP_SCN_BITMAP,
	ISNS_TAG_PORT_ROLE,
	ISNS_TAG_PERMANENT_PORT_NAME,
};

static uint32_t fc_port_key_attrs[] = {
	ISNS_TAG_FC_PORT_NAME_WWPN,
};

isns_object_template_t		isns_fc_port_template = {
	.iot_name	= "iFCP Port",
	.iot_handle	= ISNS_OBJECT_TYPE_FC_PORT,
	.iot_attrs	= fc_port_attrs,
	.iot_num_attrs	= array_num_elements(fc_port_attrs),
	.iot_keys	= fc_port_key_attrs,
	.iot_num_keys	= array_num_elements(fc_port_key_attrs),
	.iot_container	= &isns_entity_template,
};

static uint32_t fc_node_attrs[] = {
	ISNS_TAG_FC_NODE_NAME_WWNN,
	ISNS_TAG_SYMBOLIC_NODE_NAME,
	ISNS_TAG_NODE_IP_ADDRESS,
	ISNS_TAG_NODE_IPA,
	ISNS_TAG_PROXY_ISCSI_NAME,
};

static uint32_t fc_node_key_attrs[] = {
	ISNS_TAG_FC_NODE_NAME_WWNN,
};

isns_object_template_t		isns_fc_node_template = {
	.iot_name	= "iFCP Device Node",
	.iot_handle	= ISNS_OBJECT_TYPE_FC_NODE,
	.iot_attrs	= fc_node_attrs,
	.iot_num_attrs	= array_num_elements(fc_node_attrs),
	.iot_keys	= fc_node_key_attrs,
	.iot_num_keys	= array_num_elements(fc_node_key_attrs),
	.iot_container	= &isns_fc_port_template,
};

