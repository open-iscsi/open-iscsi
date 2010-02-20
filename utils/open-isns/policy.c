/*
 * Open-iSNS policy engine
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 *
 * For now, policy is static. We can make it configurable
 * later.
 */

#include <string.h>
#include "isns.h"
#include "security.h"
#include "objects.h"
#include "message.h"
#include "util.h"

/*
   A brief discussion of policy

   For now, a principal's name (ie its SPI string) *must* match
   the iSNS source name it uses.

   Special care needs to be taken to restrict which principals
   are permitted to act as a control node. For now, we don't
   implement control node semantics.

 */

static unsigned int	isns_policy_gen = 0;

/*
 * Administrative policy (everything allowed,
 * talks to entity "CONTROL"
 */
static isns_policy_t	isns_superhero_powers = {
	.ip_name		= "administrator",
	.ip_users		= 1,
	.ip_gen			= 0,

	.ip_entity		= ISNS_ENTITY_CONTROL,
	.ip_functions		= ~0,
	.ip_object_types	= ~0,
	.ip_node_types		= ~0,
};

/*
 * Policy for anon user
 */
static isns_policy_t	isns_dweeb_powers = {
	.ip_name		= "anonymous",
	.ip_users		= 1,
	.ip_gen			= 0,

	.ip_functions		= 1 << ISNS_DEVICE_ATTRIBUTE_QUERY,
	.ip_object_types	= 0,
	.ip_node_types		= 0,
};

#define IS_ANON_POLICY(p)	((p) == &isns_dweeb_powers)

/*
 * These are used when security is turned off.
 * Essentially the same as superhero, except
 * no eid specified.
 */
static isns_policy_t	isns_flyingpigs_powers = {
	.ip_name		= "insecure",
	.ip_users		= 1,
	.ip_gen			= 0,

	.ip_functions		= ~0,
	.ip_object_types	= ~0,
	.ip_node_types		= ~0,
};


isns_policy_t *
isns_policy_bind(const isns_message_t *msg)
{
	isns_policy_t		*policy = NULL;
	isns_principal_t	*princ = NULL;

	/* When the admin turns off gravity,
	 * pigs can fly, too. */
	if (isns_config.ic_security == 0) {
		policy = &isns_flyingpigs_powers;
		goto found;
	}

	/* If the caller is the local root user, s/he can
	 * do anything. */
	if (msg->im_creds && msg->im_creds->uid == 0) {
		policy = &isns_superhero_powers;
		goto found;
	}

	/* Tie the SPI given in the auth block to a
	 * source name.
	 * For now, the names have to match. Down the road,
	 * there may be more flexible schemes.
	 */
	if ((princ = msg->im_security) != NULL) {
		if ((policy = princ->is_policy) != NULL)
			goto found;

		isns_error("Internal error - no policy for "
				"principal %s!\n",
				princ->is_name);
	}

	policy = &isns_dweeb_powers;

found:
	policy->ip_users++;
	return policy;
}

/*
 * Check whether the call is permitted.
 * This is particularly useful to prevent rogue
 * clients from messing with Discovery Domains.
 */
int
isns_policy_validate_function(const isns_policy_t *policy,
		const isns_message_t *msg)
{
	uint32_t function = msg->im_header.i_function;
	int	rv = 0;

	if (function >= 32) {
		isns_debug_auth("Bad function code %08x\n", function);
		return 0;
	}

	if (!(policy->ip_functions & (1 << function)))
		goto reject;

	rv = 1;

reject: 
	isns_debug_auth(":: policy %s function %s (%04x) %s\n",
			policy->ip_name,
			isns_function_name(function), function,
			rv? "permitted" : "DENIED");
	return rv;
}

/*
 * Helper function to validate node names and source names
 */
static int
__validate_node_name(const isns_policy_t *policy, const char *name)
{
	const struct string_array *ap;
	unsigned int i;

	/* Control nodes get to do everything */
	if (policy->ip_node_types & ISNS_ISCSI_CONTROL_MASK)
		return 1;

	ap = &policy->ip_node_names;
	for (i = 0; i < ap->count; ++i) {
		const char *s;

		s = ap->list[i];
		if (s == NULL)
			continue;
		if (isns_source_pattern_match(s, name))
			return 1;
	}
	return 0;
}

/*
 * Validate the source of a message
 */
int
isns_policy_validate_source(const isns_policy_t *policy,
		const isns_source_t *source)
{
	const char *src_name = isns_source_name(source);
	int	rv = 0;

	if (!__validate_node_name(policy, src_name))
		goto reject;

	rv = 1;

reject:
	isns_debug_auth(":: policy %s source %s %s\n",
			policy->ip_name, src_name,
			rv? "permitted" : "DENIED");
	return rv;
}

/*
 * Check whether the entity name specified by the client
 * is actually his to use.
 */
int
isns_policy_validate_entity(const isns_policy_t *policy,
			const char *eid)
{
	int	rv = 0, eidlen;

	/* Control nodes get to do everything */
	if (policy->ip_node_types & ISNS_ISCSI_CONTROL_MASK)
		goto accept;

	/* For anonymous clients, refuse any attempt to
	 * create an entity */
	if (IS_ANON_POLICY(policy))
		goto reject;

	/* If no entity is assigned, this means the client
	 * is not permitted to specify its own entity name,
	 * and accept what we assign it.
	 */
	if (policy->ip_entity == NULL)
		goto reject;

	eidlen = strlen(policy->ip_entity);
	if (strncasecmp(policy->ip_entity, eid, eidlen)
	 && (eid[eidlen] == ':' || eid[eidlen] == '\0'))
		goto reject;

accept:	rv = 1;

reject:
	isns_debug_auth(":: policy %s entity ID %s %s\n",
			policy->ip_name, eid,
			rv? "permitted" : "DENIED");
	return rv;
}

const char *
isns_policy_default_entity(const isns_policy_t *policy)
{
	return policy->ip_entity;
}

int
isns_policy_validate_node_name(const isns_policy_t *policy,
			const char *node_name)
{
	int	rv = 0;

	/* Control nodes get to do everything */
	if (policy->ip_node_types & ISNS_ISCSI_CONTROL_MASK)
		goto accept;

	if (!__validate_node_name(policy, node_name))
		goto reject;

accept:	rv = 1;
reject:
	isns_debug_auth(":: policy %s storage node name %s %s\n",
			policy->ip_name, node_name,
			rv? "permitted" : "DENIED");
	return rv;
}

/*
 * Check whether the client is allowed to access
 * the given object in a particular way.
 */
static int
__isns_policy_validate_object_access(const isns_policy_t *policy,
			const isns_source_t *source,
			const isns_object_t *obj,
			isns_object_template_t *tmpl,
			unsigned int function)
{
	uint32_t mask, perm = ISNS_PERMISSION_WRITE;
	int	rv = 0;

	/* Control nodes get to do everything */
	if (policy->ip_node_types & ISNS_ISCSI_CONTROL_MASK)
		goto accept;

	if (function == ISNS_DEVICE_ATTRIBUTE_QUERY
	 || function == ISNS_DEVICE_GET_NEXT)
		perm = ISNS_PERMISSION_READ;

	/*
	 * 5.6.1.  Source Attribute
	 *
	 * For messages that change the contents of the iSNS
	 * database, the iSNS server MUST verify that the Source
	 * Attribute identifies either a Control Node or a Storage
	 * Node that is a part of the Network Entity containing
	 * the added, deleted, or modified objects.
	 *
	 * Note: this statement makes sense for nodes, portals
	 * etc, but not for discovery domains, which are not
	 * part of any network entity (but the Control Node clause
	 * above still applies).
	 */
	if (perm == ISNS_PERMISSION_WRITE && obj != NULL) {
		const isns_object_t *entity;

		entity = obj->ie_container;
		if (entity && entity != source->is_entity)
			goto refuse;

		/* You're not allowed to modify virtual objects */
		if (obj->ie_rebuild)
			goto refuse;
	}

	/* Check whether the client is permitted
	   to access such an object */
	mask = ISNS_ACCESS(tmpl->iot_handle, perm);
	if (!(policy->ip_object_types & mask))
		goto refuse;

	if (source->is_untrusted && (obj->ie_flags & ISNS_OBJECT_PRIVATE))
		goto refuse;

accept:
	rv = 1;

refuse:
	if (obj) {
		isns_debug_auth(":: policy %s operation %s on object %08x (%s) %s\n",
			policy->ip_name,
			isns_function_name(function),
			obj->ie_index,
			tmpl->iot_name,
			rv? "permitted" : "DENIED");
	} else {
		isns_debug_auth(":: policy %s operation %s on %s object %s\n",
			policy->ip_name,
			isns_function_name(function),
			tmpl->iot_name,
			rv? "permitted" : "DENIED");
	}
	return rv;
}

/*
 * Check whether the client is allowed to access
 * the given object. This is called for read functions.
 */
int
isns_policy_validate_object_access(const isns_policy_t *policy,
			const isns_source_t *source,
			const isns_object_t *obj,
			unsigned int function)
{
	return __isns_policy_validate_object_access(policy, source,
			obj, obj->ie_template,
			function);
}

/*
 * Check whether the client is allowed to update
 * the given object.
 */
int
isns_policy_validate_object_update(const isns_policy_t *policy,
			const isns_source_t *source,
			const isns_object_t *obj,
			const isns_attr_list_t *attrs,
			unsigned int function)
{
	return __isns_policy_validate_object_access(policy, source,
			obj, obj->ie_template,
			function);
}

/*
 * Check whether the client is allowed to create an object
 * with the given attrs.
 */
int
isns_policy_validate_object_creation(const isns_policy_t *policy,
			const isns_source_t *source,
			isns_object_template_t *tmpl,
			const isns_attr_list_t *keys,
			const isns_attr_list_t *attrs,
			unsigned int function)
{
	const char	*name = NULL;

	if (tmpl == &isns_entity_template) {
		/* DevReg messages may contain an empty EID
		 * string, which means the server should select
		 * one. */
		if (isns_attr_list_get_string(keys,
				ISNS_TAG_ENTITY_IDENTIFIER, &name)
		 && !isns_policy_validate_entity(policy, name))
			return 0;
	}

	if (tmpl == &isns_iscsi_node_template) {
		if (isns_attr_list_get_string(keys,
				ISNS_TAG_ISCSI_NAME, &name)
		 && !isns_policy_validate_node_name(policy, name))
			return 0;
	}

	/* Should we also include the permitted portals
	 * in the policy? */

	return __isns_policy_validate_object_access(policy, source,
			NULL, tmpl, function);
}

/*
 * Check whether the client is permitted to access
 * or create an object of this type.
 * FIXME: Pass R/W permission bit
 */
int
isns_policy_validate_object_type(const isns_policy_t *policy,
				isns_object_template_t *tmpl,
				unsigned int function)
{
	uint32_t mask;
	int	rv = 0;

	/* Control nodes get to do everything */
	if (policy->ip_node_types & ISNS_ISCSI_CONTROL_MASK)
		goto accept;

	mask = ISNS_ACCESS_R(tmpl->iot_handle);
	if (!(policy->ip_object_types & mask))
		goto reject;

accept:	rv = 1;

reject:
	isns_debug_auth(":: policy %s operation %s on object type %s %s\n",
			policy->ip_name,
			isns_function_name(function),
			tmpl->iot_name,
			rv? "permitted" : "DENIED");
	return rv;
}

int
isns_policy_validate_node_type(const isns_policy_t *policy, uint32_t type)
{
	int	rv = 0;

	if ((~policy->ip_node_types & type) == 0)
		rv = 1;

	isns_debug_auth(":: policy %s registration of node type 0x%x %s\n",
			policy->ip_name, type,
			rv? "permitted" : "DENIED");
	return rv;
}

/*
 * 6.4.4.
 * Management SCNs provide information about all changes to the network,
 * regardless of discovery domain membership.  Registration for management
 * SCNs is indicated by setting bit 26 to 1.  Only Control Nodes may
 * register for management SCNs.  Bits 30 and 31 may only be enabled if
 * bit 26 is set to 1.
 */
int
isns_policy_validate_scn_bitmap(const isns_policy_t *policy,
					uint32_t bitmap)
{
	int	rv = 1;

	if (policy->ip_node_types & ISNS_ISCSI_CONTROL_MASK)
		goto accept;

	if (!(bitmap & ISNS_SCN_MANAGEMENT_REGISTRATION_MASK)) {
		if (bitmap & (ISNS_SCN_DD_MEMBER_ADDED_MASK |
			      ISNS_SCN_DD_MEMBER_REMOVED_MASK))
			goto reject;
		goto accept;
	}

reject:
	rv = 0;

accept:
	isns_debug_auth(":: policy %s scn bitmap 0x%x %s\n",
			policy->ip_name, bitmap,
			rv? "permitted" : "DENIED");
	return rv;
}

/*
 * Create the default policy for a given SPI
 */
isns_policy_t *
isns_policy_default(const char *spi, size_t len)
{
	return __isns_policy_alloc(spi, len);
}

/*
 * Create the policy object for the server we're
 * talking to. The server is allowed to send us
 * ESI and SCN messages, and that's about it.
 */
isns_policy_t *
isns_policy_server(void)
{
	isns_policy_t	*policy;

	policy = __isns_policy_alloc("<server>", 8);

	policy->ip_functions =
		(1 << ISNS_ENTITY_STATUS_INQUIRY) |
		(1 << ISNS_STATE_CHANGE_NOTIFICATION);
	policy->ip_node_types = 0;
	policy->ip_object_types = 0;
	isns_string_array_append(&policy->ip_node_names, "*");
	return policy;
}

/*
 * Allocate an empty policy object
 */
isns_policy_t *
__isns_policy_alloc(const char *spi, size_t len)
{
	isns_policy_t	*policy;

	policy = isns_calloc(1, sizeof(*policy));
	policy->ip_name = isns_malloc(len + 1);
	policy->ip_users = 1;
	policy->ip_gen = isns_policy_gen;

	memcpy(policy->ip_name, spi, len);
	policy->ip_name[len] = '\0';

	/* Only register/query allowed */
	policy->ip_functions =
		(1 << ISNS_DEVICE_ATTRIBUTE_REGISTER) |
		(1 << ISNS_DEVICE_ATTRIBUTE_QUERY) |
		(1 << ISNS_DEVICE_GET_NEXT) |
		(1 << ISNS_DEVICE_DEREGISTER) |
		(1 << ISNS_SCN_REGISTER);

	/* Can only register initiator node(s) */
	policy->ip_node_types =
		ISNS_ISCSI_INITIATOR_MASK;

	/* Can only view/modify standard objects */
	policy->ip_object_types = ISNS_DEFAULT_OBJECT_ACCESS;

	return policy;
}

/*
 * Release a policy object
 */
void
isns_policy_release(isns_policy_t *policy)
{
	if (!policy)
		return;

	isns_assert(policy->ip_users);
	if (--(policy->ip_users))
		return;

	isns_assert(policy != &isns_superhero_powers);
	isns_assert(policy != &isns_flyingpigs_powers);
	isns_assert(policy != &isns_dweeb_powers);

	isns_free(policy->ip_name);
	isns_free(policy->ip_entity);
	isns_free(policy->ip_dd_default);
	isns_string_array_destroy(&policy->ip_node_names);

	isns_free(policy);
}
