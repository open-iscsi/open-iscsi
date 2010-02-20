/*
 * iSNS "vendor-specific" protocol definitions
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#ifndef ISNS_VENDOR_H
#define ISNS_VENDOR_H

#include "isns-proto.h"

/*
 * We're poor, we don't own a OUI. Let's fake one.
 */
#define OPENISNS_VENDOR_OUI	0xFFFF00
#define OPENISNS_VENDOR_PREFIX	(OPENISNS_VENDOR_OUI << 8)
#define OPENISNS_IS_PRIVATE_ATTR(tag) (((tag) >> 16) == 0xFFFF)

enum openisns_vendor_tag {
	/* Security Policy Identifier */
	OPENISNS_TAG_POLICY_SPI	= OPENISNS_VENDOR_PREFIX + ISNS_VENDOR_SPECIFIC_OTHER_BASE,

	__OPENISNS_TAG_POLICY_RESERVED,

	/* DSA signature key (public) */
	OPENISNS_TAG_POLICY_KEY,

	/* Entity name to use */
	OPENISNS_TAG_POLICY_ENTITY,

	/* Functions the client is permitted to invoke */
	OPENISNS_TAG_POLICY_FUNCTIONS,

	/* Object types the client is permitted to see. */
	OPENISNS_TAG_POLICY_OBJECT_TYPE,

	/* iSCSI node name the client is permitted to register.
	 * This attribute may occur multiple times.
	 * If absent, it defaults to POLICY_SOURCE_NAME
	 */
	OPENISNS_TAG_POLICY_NODE_NAME,

	/* Node type bitmap the client is permitted to register */
	OPENISNS_TAG_POLICY_NODE_TYPE,

	/* Default discovery domain the client will be
	 * placed in.
	 * Not used yet.
	 */
	OPENISNS_TAG_POLICY_DEFAULT_DD,
	OPENISNS_TAG_POLICY_VISIBLE_DD,
};

extern const struct isns_object_template	isns_policy_template;

#endif /* ISNS_VENDOR_H */
