/*
 * iSNS vendor specific objects
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#include <stdlib.h>
#include <string.h>
#include "isns.h"
#include "objects.h"
#include "attrs.h"
#include "vendor.h"
#include "util.h"

static uint32_t policy_attrs[] = {
	OPENISNS_TAG_POLICY_SPI,
	OPENISNS_TAG_POLICY_KEY,
	OPENISNS_TAG_POLICY_ENTITY,
	OPENISNS_TAG_POLICY_OBJECT_TYPE,
	OPENISNS_TAG_POLICY_NODE_NAME,
	OPENISNS_TAG_POLICY_NODE_TYPE,
	OPENISNS_TAG_POLICY_FUNCTIONS,
	OPENISNS_TAG_POLICY_VISIBLE_DD,
	OPENISNS_TAG_POLICY_DEFAULT_DD,
};

static uint32_t policy_key_attrs[] = {
	OPENISNS_TAG_POLICY_SPI,
};

isns_object_template_t		isns_policy_template = {
	.iot_name	= "Policy",
	.iot_handle	= ISNS_OBJECT_TYPE_POLICY,
	.iot_attrs	= policy_attrs,
	.iot_num_attrs	= array_num_elements(policy_attrs),
	.iot_keys	= policy_key_attrs,
	.iot_num_keys	= array_num_elements(policy_key_attrs),
	.iot_container	= &isns_entity_template,
	.iot_vendor_specific = 1,
};

