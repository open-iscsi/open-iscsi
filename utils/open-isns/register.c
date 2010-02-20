/*
 * Handle iSNS Device Attribute Registration
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "isns.h"
#include "attrs.h"
#include "objects.h"
#include "message.h"
#include "security.h"
#include "util.h"
#include "db.h"


static int	isns_create_default_pgs_for_object(isns_db_t *, isns_object_t *);

/*
 * Create a registration, and set the source name
 */
static isns_simple_t *
__isns_create_registration(isns_source_t *source, isns_object_t *key_obj)
{
	isns_simple_t	*reg;

	reg = isns_simple_create(ISNS_DEVICE_ATTRIBUTE_REGISTER, source, NULL);
	if (reg == NULL)
		return NULL;

	/*
	 * When sending a registration, you can either specify
	 * the object to be modified in the key attrs, or leave
	 * the key empty.
	 */
	if (key_obj == NULL)
		return reg;

	/* User gave us a key object. We need to put the key
	 * attributes into the message attrs, and *all* attrs
	 * into the operating attrs. */
	if (!isns_object_extract_keys(key_obj, &reg->is_message_attrs)) {
		/* bummer - seems the object is missing some
		 * vital organs. */
		isns_warning("%s: object not fully specified, key attrs missing\n",
				__FUNCTION__);
		goto failed;
	}

	/*
	 * The Message Key identifies the object the DevAttrReg message
	 * acts upon.  [...] The key attribute(s) identifying this object
	 * MUST also be included among the Operating Attributes.
	 *
	 * We do not enforce this here, we rely on the caller to get this
	 * right.
	 */
#if 0
	if (!isns_object_extract_all(key_obj, &reg->is_operating_attrs)) {
		isns_warning("%s: unable to extract attrs from key objects\n",
				__FUNCTION__);
		goto failed;
	}
#endif

	return reg;

failed:
	isns_simple_free(reg);
	return NULL;
}

isns_simple_t *
isns_create_registration(isns_client_t *clnt, isns_object_t *key_obj)
{
	return __isns_create_registration(clnt->ic_source, key_obj);
}

isns_simple_t *
isns_create_registration2(isns_client_t *clnt, isns_object_t *key_obj,
		isns_source_t *source)
{
	return __isns_create_registration(source?: clnt->ic_source, key_obj);
}

/*
 * Set the replace flag
 */
void
isns_registration_set_replace(isns_simple_t *reg, int replace)
{
	reg->is_replace = !!replace;
}

/*
 * Add an object to the registration
 */
void
isns_registration_add_object(isns_simple_t *reg, isns_object_t *obj)
{
	isns_object_extract_writable(obj, &reg->is_operating_attrs);
}

void
isns_registration_add_object_list(isns_simple_t *reg, isns_object_list_t *list)
{
	unsigned int i;

	for (i = 0; i < list->iol_count; ++i) {
		isns_object_extract_writable(list->iol_data[i],
				&reg->is_operating_attrs);
	}
}

/*
 * Get the key object given in this message
 *
 * It doesn't say anywhere explicitly in the RFC, but
 * the message key can contain both key and non-key
 * attributes. For instance, you can search by
 * Portal Group Index (section 3.4).
 */
static int
isns_registration_get_key(isns_simple_t *reg, isns_db_t *db, isns_object_t **key_obj)
{
	isns_attr_list_t *keys = &reg->is_message_attrs;
	isns_attr_list_t dummy_keys = ISNS_ATTR_LIST_INIT;
	isns_attr_t	*attr;
	isns_object_t	*obj = NULL;
	const char	*eid = NULL;
	char		eidbuf[128];
	int		status = ISNS_SUCCESS;
	int		obj_must_exist = 0;

	/*
	 * 5.6.5.1
	 * If the Message Key is not present, then the DevAttrReg message
	 * implicitly registers a new Network Entity.  In this case,
	 * the replace bit SHALL be ignored; a new Network Entity SHALL
	 * be created.
	 *
	 * Note that some clients seem to leave the message key
	 * empty, but hide the entity identifier in the operating
	 * attrs.
	 */
	if (keys->ial_count != 0) {
		attr = keys->ial_data[0];

		/*
		 * 5.6.5.1
		 * If the Message Key does not contain an EID, and no
		 * pre-existing objects match the Message Key, then the
		 * DevAttrReg message SHALL be rejected with a status
		 * code of 3 (Invalid Registration).
		 */
		if (keys->ial_count != 1
		 || attr->ia_tag_id != ISNS_TAG_ENTITY_IDENTIFIER)
			obj_must_exist = 1;
	} else {
		/* Empty message key. But the client may have hidden
		 * the EID in the operating attrs :-/
		 */
		if (reg->is_operating_attrs.ial_count == 0)
			goto create_entity;

		attr = reg->is_operating_attrs.ial_data[0];
		if (attr->ia_tag_id != ISNS_TAG_ENTITY_IDENTIFIER)
			goto create_entity;

		isns_attr_list_append_attr(&dummy_keys, attr);
		keys = &dummy_keys;
	}

	/* If the caller specifies an EID, extract it while
	 * we know what we're doing :-) */
	if (attr->ia_tag_id == ISNS_TAG_ENTITY_IDENTIFIER
	 && ISNS_ATTR_IS_STRING(attr))
		eid = attr->ia_value.iv_string;

	/* Look up the object identified by the keys.
	 * We do not scope the lookup, as the client
	 * may want to add nodes to an entity that's
	 * currently empty - and hence not visible to
	 * any DD. */
	if (!ISNS_ATTR_IS_NIL(attr))
		obj = isns_db_lookup(db, NULL, keys);

	if (obj == NULL && obj_must_exist)
		goto err_invalid;

	if (obj != NULL) {
		/*
		 * Policy: verify that the client is permitted
		 * to access this object.
		 *
		 * This includes
		 *  -	the client node must be the object owner,
		 *	or a control node.
		 *  -	the policy must allow modification of
		 *	this object type.
		 */
		if (!isns_policy_validate_object_access(reg->is_policy,
					reg->is_source,
					obj, reg->is_function))
			goto err_unauthorized;

found_object:
		if (reg->is_replace) {
			isns_object_t *container = NULL;

			if (!ISNS_IS_ENTITY(obj)) {
				container = isns_object_get_entity(obj);
				if (container == NULL) {
					isns_error("Trying to replace %s (id %u) "
						   "which has no container\n",
						obj->ie_template->iot_name,
						obj->ie_index);
					goto err_invalid;
				}
			}

			isns_debug_state("Replacing %s (id %u)\n",
				obj->ie_template->iot_name,
				obj->ie_index);
			isns_db_remove(db, obj);
			isns_object_release(obj);

			/* Purge the deleted objects from the database now */
			isns_db_purge(db);

			/* We need to flush pending SCNs because the
			 * objects may be resurrected from limbo,
			 * and we might be looking at stale data. */
			isns_scn_transmit_all();

			/* It's an entity. Nuke it and create
			 * a new one. */
			if (container == NULL) {
				isns_source_set_entity(reg->is_source, NULL);
				goto create_entity;
			}

			obj = isns_object_get(container);
		}

		goto out;
	}

	/*
	 * If the Message Key contains an EID and no pre-existing objects
	 * match the Message Key, then the DevAttrReg message SHALL create a
	 * new Entity with the specified EID and any new object(s) specified
	 * by the Operating Attributes.  The replace bit SHALL be ignored.
	 *
	 * Implementer's note: the EID attribute may be empty, in which case
	 * we also create a new entity.
	 */

create_entity:
	if (!isns_policy_validate_object_creation(reg->is_policy,
				reg->is_source,
				&isns_entity_template, keys, NULL,
				reg->is_function))
		goto err_unauthorized;

	/*
	 * 5.6.5.1
	 * A registration message that creates a new Network Entity object
	 * MUST contain at least one Portal or one Storage Node.  If the
	 * message does not, then it SHALL be considered invalid and result
	 * in a response with Status Code of 3 (Invalid Registration).
	 */
	/* FIXME: Implement this check */

	/* We try to play nice with lazy clients and attempt to
	 * look up the network entity given the source name.
	 * But we don't do this if a non-NULL EID was given,
	 * because the client may explicitly want to specify more
	 * than one Network Entity.
	 */
	if (eid == NULL) {
		obj = reg->is_source->is_entity;
		if (obj != NULL) {
			isns_object_get(obj);
			goto found_object;
		}

		/* The policy may define a default entity name.
		 * If that is the case, use it.
		 */
		eid = isns_policy_default_entity(reg->is_policy);
		if (eid) {
			obj = isns_db_vlookup(db, &isns_entity_template,
					ISNS_TAG_ENTITY_IDENTIFIER, eid,
					0);
			if (obj) {
				reg->is_source->is_entity = isns_object_get(obj);
				goto found_object;
			}
		}
	}

	/*
	 * 5.6.5.1
	 * If the Message Key and Operating Attributes do not contain
	 * an EID attribute, or if the EID attribute has a length of 0,
	 * then a new Network Entity object SHALL be created and the iSNS
	 * server SHALL supply a unique EID value for it.
	 */
	if (eid == NULL)
		eid = isns_db_generate_eid(db, eidbuf, sizeof(eidbuf));

	/*
	 * 6.2.2.  Entity Protocol
	 *
	 * This attribute is required during initial registration of
	 * the Network Entity.
	 *
	 * Implementer's note: we don't rely on this. Instead, the
	 * Entity Protocol is selected based on the source type.
	 * If the client specifies the protocol, the auto-selected
	 * value is overwritten.
	 */
	obj = isns_create_entity_for_source(reg->is_source, eid);
	if (obj == NULL)
		goto err_invalid;

	isns_source_set_entity(reg->is_source, obj);

	/*
	 * 6.2.6
	 * If a Registration Period is not requested by the iSNS
	 * client and Entity Status Inquiry (ESI) messages are not
	 * enabled for that client, then the Registration Period
	 * SHALL be set to a non-zero value by the iSNS server.
	 * This implementation-specific value for the Registration
	 * Period SHALL be returned in the registration response to the
	 * iSNS client.  The Registration Period may be set to zero,
	 * indicating its non-use, only if ESI messages are enabled for
	 * that Network Entity.
	 *
	 * Implementer's note: we diverge from this in two ways:
	 *  -	the admin may choose to disable registration timeout,
	 *	by setting RegistrationPeriod=0 in the config file
	 *
	 *  -	When a new entity is created, we always set the
	 *	registration interval because we cannot know yet
	 *	whether the client will subsequently enable ESI or
	 *	not.
	 *
	 *  -	The control entity (holding policy objects) will
	 *	not expire.
	 */
	if (isns_config.ic_registration_period
	 && strcasecmp(eid, ISNS_ENTITY_CONTROL)) {
		isns_object_set_uint32(obj,
				ISNS_TAG_REGISTRATION_PERIOD,
				isns_config.ic_registration_period);
		isns_object_set_uint64(obj,
				ISNS_TAG_TIMESTAMP,
				time(NULL));
	}

	/* Insert into database, and set the object's owner */
	isns_db_insert(db, obj);

	reg->is_replace = 0;

out:
	*key_obj = obj;
	isns_attr_list_destroy(&dummy_keys);
	return ISNS_SUCCESS;

error:
	if (obj)
		isns_object_release(obj);
	isns_attr_list_destroy(&dummy_keys);
	return status;

err_unauthorized:
	status = ISNS_SOURCE_UNAUTHORIZED;
	goto error;

err_invalid:
	status = ISNS_INVALID_REGISTRATION;
	goto error;
}

static int
isns_registration_get_next_object(isns_db_t *db,
				struct isns_attr_list_scanner *st,
				isns_object_list_t *result)
{
	isns_object_t	*current;
	int		status, esi = 0;

	status = isns_attr_list_scanner_next(st);
	/* We get here if the registration has a trailing PGT */
	if (status == ISNS_NO_SUCH_ENTRY)
		return ISNS_SUCCESS;
	if (status)
		return status;

	/*
	 * Validate the attrlist.
	 * This makes sure the client does not include
	 * duplicate attributes, readonly attributes
	 * such as Registration Timestamp, Index and Next Index,
	 * or privileged data (such as marking a storage node as
	 * control node).
	 */
	status = isns_attr_list_validate(&st->attrs,
			st->policy,
			ISNS_DEVICE_ATTRIBUTE_REGISTER);
	if (status) {
		isns_debug_protocol("invalid attr in message\n");
		return status;
	}

	/*
	 * 6.3.4.  Entity Status Inquiry Interval
	 *
	 * If the iSNS server is unable to support ESI messages
	 * or the ESI Interval requested, it SHALL [...] reject
	 * the ESI request by returning an "ESI Not Available"
	 * Status Code [...]
	 *
	 * Implementer's note: In section 5.7.5.1, the RFC talks
	 * about modifying the requested ESI interval; so it seems
	 * it's okay to be liberal about the ESI intervals we accept,
	 * and update them quietly.
	 */
	if (isns_attr_list_contains(&st->attrs, ISNS_TAG_ESI_PORT)) {
		if (!isns_esi_enabled) {
			isns_debug_esi("Refusing to accept portal "
					"registration with ESI port\n");
			return ISNS_ESI_NOT_AVAILABLE;
		}
		esi = 1;
	}

	/*
	 * Override any registration period specified by the client.
	 */
	if (isns_attr_list_contains(&st->attrs, ISNS_TAG_REGISTRATION_PERIOD)) {
		isns_value_t value = ISNS_VALUE_INIT(uint32,
					isns_config.ic_registration_period);

		isns_attr_list_update_value(&st->attrs,
				ISNS_TAG_REGISTRATION_PERIOD, NULL,
				&value);
	}

	if (st->tmpl == &isns_entity_template) {
		/*
		 * 5.6.5.1.
		 * A maximum of one Network Entity object can be
		 * created or updated with a single DevAttrReg
		 * message.  Consequently, the Operating Attributes
		 * MUST NOT contain more than one Network Entity
		 * object.
		 */
		if (st->entities++) {
			isns_debug_protocol("More than one entity in DevAttrReg msg\n");
			return ISNS_INVALID_REGISTRATION;
		}

		/* This should be the key object.
		 * The EID specified by by the client may be
		 * empty, so don't overwrite the value we
		 * assigned with something else.
		 */
		if (!isns_object_match(st->key_obj, &st->keys)) {
			isns_debug_protocol("Entity mismatch in message vs. operating attrs\n");
			return ISNS_INVALID_REGISTRATION;
		}
		current = isns_object_get(st->key_obj);
	} else
	if (st->tmpl == &isns_dd_template || st->tmpl == &isns_ddset_template) {
		isns_debug_protocol("DevAttrReg of type %s not allowed\n",
				st->tmpl->iot_name);
		return ISNS_INVALID_REGISTRATION;
	} else {
		/* This will also catch objects in limbo. */
		current = isns_db_lookup(db, st->tmpl, &st->keys);
	}

	if (current != NULL) {
		/* 
		 * If the replace bit is not set, then the message updates
		 * the attributes of the object identified by the Message Key
		 * and its subordinate objects.  Existing object containment
		 * relationships MUST NOT be changed.  For existing objects,
		 * key attributes MUST NOT be modified, but new subordinate
		 * objects MAY be added.
		 */

		/*
		 * [...]
		 * If the Node identified by the Source Attribute is
		 * not a Control Node, then the objects in the operating
		 * attributes MUST be members of the same Network Entity
		 * as the Source Node.
		 */
		if (!isns_policy_validate_object_update(st->policy,
					st->source, current, &st->attrs,
					ISNS_DEVICE_ATTRIBUTE_REGISTER)) {
			isns_object_release(current);
			return ISNS_SOURCE_UNAUTHORIZED;
		}

		/* We shouldn't allow messages affecting one Entity
		 * to modify objects owned by a different Entity.
		 *
		 * However, there may be orphan objects (created
		 * while populating discovery domains). These will
		 * not be associated with any Network Entity, so
		 * they're up for grabs.
		 */
		if (st->key_obj == current
		 || st->key_obj == current->ie_container) {
			/* All is well. The current object is the
			 * key object itself, or a direct descendant of the
			 * key object. */
			/* FIXME: with FC we can get deeper nesting;
			 * this needs work. */
		} else
		if (!isns_object_is_valid_container(st->key_obj, st->tmpl)) {
			isns_error("Client attempts to add %s object to a %s - tsk tsk.\n",
					st->tmpl->iot_name,
					st->key_obj->ie_template->iot_name);
			goto invalid_registration;
		} else if (current->ie_container) {
			/* We shouldn't get here in authenticated mode,
			 * but in insecure mode we still may. */
			isns_error("Client attempts to move %s %u to a different %s\n",
					current->ie_template->iot_name,
					current->ie_index,
					st->key_obj->ie_template->iot_name);
			goto invalid_registration;
		}
	} else {
		if (!isns_object_is_valid_container(st->key_obj, st->tmpl)) {
			isns_error("Client attempts to add %s object to a %s - tsk tsk.\n",
					st->tmpl->iot_name,
					st->key_obj->ie_template->iot_name);
			goto invalid_registration;
		}

		if (!isns_policy_validate_object_creation(st->policy,
					st->source, st->tmpl,
					&st->keys, &st->attrs,
					ISNS_DEVICE_ATTRIBUTE_REGISTER)) {
			return ISNS_SOURCE_UNAUTHORIZED;
		}
		current = isns_create_object(st->tmpl, &st->keys,
				isns_object_get_entity(st->key_obj));

		/* We do not insert the new object into the database yet.
		 * That happens after we're done with parsing *all*
		 * objects. */
	}

	if (!isns_object_set_attrlist(current, &st->attrs)) {
		isns_debug_state("Error updating object's attrlist\n");
		isns_object_release(current);
		return ISNS_INTERNAL_ERROR;
	}

	/* If the client specifies an ESI port, make sure the
	 * ESI interval is set and within bounds. */
	if (esi) {
		uint32_t	esi_interval;

		if (!isns_object_get_uint32(current,
					ISNS_TAG_ESI_INTERVAL, &esi_interval)) {
			esi_interval = isns_config.ic_esi_min_interval;
		} else
		if (esi_interval < isns_config.ic_esi_min_interval) {
			esi_interval = isns_config.ic_esi_min_interval;
		} else
		if (esi_interval > isns_config.ic_esi_max_interval) {
			esi_interval = isns_config.ic_esi_max_interval;
		} else {
			esi_interval = 0;
		}

		if (esi_interval)
			isns_object_set_uint32(current,
					ISNS_TAG_ESI_INTERVAL, esi_interval);
	}

	/* Append it to the result list.
	 * We do not return the key object, otherwise
	 * we end up putting it into the response twice.
	 */
	if (current != st->key_obj)
		isns_object_list_append(result, current);

	/*
	 * When a Portal is registered, the Portal attributes MAY immediately be
	 * followed by a PGT attribute. 
	 * [...]
	 * When an iSCSI Storage Node is registered, the Storage Node attributes
	 * MAY immediately be followed by a PGT attribute.
	 */
	if (st->tmpl == &isns_portal_template
	 || st->tmpl == &isns_iscsi_node_template) {
		st->pgt_next_attr = ISNS_TAG_PG_TAG;
		st->pgt_base_object = current;
	} else if (st->tmpl != &isns_iscsi_pg_template) {
		st->pgt_next_attr = 0;
		st->pgt_base_object = NULL;
	}

	isns_object_release(current);
	return ISNS_SUCCESS;

invalid_registration:
	if (current)
		isns_object_release(current);
	return ISNS_INVALID_REGISTRATION;
}

/*
 * Extract the list of objects to be registered from
 * the list of operating attributes.
 */
static int
isns_registration_get_objects(isns_simple_t *reg, isns_db_t *db,
					isns_object_t *key_obj,
					isns_object_list_t *result)
{
	struct isns_attr_list_scanner state;
	int		status = ISNS_SUCCESS;

	isns_attr_list_scanner_init(&state, key_obj, &reg->is_operating_attrs);
	state.source = reg->is_source;
	state.policy = reg->is_policy;

	/*
	 * 5.6.4.
	 * The ordering of Operating Attributes in the message is
	 * important for determining the relationships among objects
	 * and their ownership of non-key attributes.  iSNS protocol
	 * messages that violate these ordering rules SHALL be rejected
	 * with the Status Code of 2 (Message Format Error).
	 */
	/* FIXME: Implement this check */

	while (state.pos < state.orig_attrs.ial_count) {
		status = isns_registration_get_next_object(db,
				&state, result);

		if (status)
			break;
	}

	isns_attr_list_scanner_destroy(&state);
	return status;
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
 */
static int
isns_create_registration_pgs(isns_db_t *db,
		const isns_object_list_t *list)
{
	unsigned int	i, num_created = 0;

	for (i = 0; i < list->iol_count; ++i) {
		isns_object_t	*obj = list->iol_data[i];

		if (ISNS_IS_ISCSI_NODE(obj) || ISNS_IS_PORTAL(obj))
			num_created += isns_create_default_pgs_for_object(db, obj);
	}
	return num_created;
}

static int
isns_create_default_pgs_for_object(isns_db_t *db, isns_object_t *this)
{
	isns_object_template_t *match_tmpl;
	isns_object_t	*entity;
	unsigned int	i, num_created = 0;

	if (ISNS_IS_ISCSI_NODE(this))
		match_tmpl = &isns_portal_template;
	else
		match_tmpl = &isns_iscsi_node_template;

	entity = isns_object_get_entity(this);
	for (i = 0; i < entity->ie_children.iol_count; ++i) {
		isns_object_t	*that = entity->ie_children.iol_data[i], *pg;

		if (that->ie_template != match_tmpl)
			continue;

		/* Create the portal group if it does not
		 * exist. 
		 * Note: we do not return these implicitly
		 * created portal groups - that's a matter
		 * of sheer laziness. We would have to
		 * splice these into the list in the
		 * appropriate location, and I guess it's
		 * not really worth the hassle.
		 */
		if (ISNS_IS_ISCSI_NODE(this))
			pg = isns_create_default_portal_group(db, that, this);
		else
			pg = isns_create_default_portal_group(db, this, that);

		/* There already is a PG linking these two
		 * objects. */
		if (pg == NULL)
			continue;

		isns_db_insert(db, pg);

		isns_debug_message("--Created default PG:--\n");
		isns_object_print(pg, isns_debug_message);

		isns_object_release(pg);
		num_created++;
	}

	return num_created;
}

/*
 * Commit all changes to the DB
 */
static int
isns_commit_registration(isns_db_t *db, isns_object_t *key_obj, isns_object_list_t *list)
{
	unsigned int		i;

	/*
	 * If there are any Portal Groups in this registration, build
	 * the relationship handle:
	 *
	 * 3.4
	 * A new PG object can only be registered by referencing
	 * its associated iSCSI Storage Node or Portal object.
	 * A pre-existing PG object can be modified or queried
	 * by using its Portal Group Index as message key, or
	 * by referencing its associated iSCSI Storage Node or
	 * Portal object.
	 *
	 * Implementation note: isns_db_create_pg_relation
	 * checks whether the referenced node and portal exist,
	 * and belong to the same entity as the PG. If this is
	 * not the case, NULL is returned, and no relation is
	 * defined.
	 */
	for (i = 0; i < list->iol_count; ++i) {
		isns_object_t *obj = list->iol_data[i];
		isns_object_template_t *tmpl;

		tmpl = obj->ie_template;
		if (tmpl->iot_build_relation && !obj->ie_relation
		 && !tmpl->iot_build_relation(db, obj, list)) {
			isns_debug_protocol("Unable to build relation for new %s\n",
					tmpl->iot_name);
			return ISNS_INVALID_REGISTRATION;
		}
	}

	for (i = 0; i < list->iol_count; ++i) {
		isns_object_t *obj = list->iol_data[i];
		isns_object_template_t *tmpl;

		tmpl = obj->ie_template;
		if (key_obj != obj && !obj->ie_container) {
			if (!isns_object_attach(obj, key_obj)) {
				/* This should not fail any longer */
				isns_debug_protocol("Unable to attach %s %u to %s\n",
					tmpl->iot_name, obj->ie_index,
					key_obj->ie_template->iot_name);
				return ISNS_INVALID_REGISTRATION;
			}
		}

		if (obj->ie_state != ISNS_OBJECT_STATE_MATURE)
			isns_db_insert(db, obj);
	}

	return ISNS_SUCCESS;
}

/*
 * Process a registration
 */
int
isns_process_registration(isns_server_t *srv, isns_simple_t *call, isns_simple_t **result)
{
	isns_object_list_t	objects = ISNS_OBJECT_LIST_INIT;
	isns_simple_t		*reply = NULL;
	isns_object_t		*key_obj = NULL;
	isns_db_t		*db = srv->is_db;
	int			status;
	unsigned int		i;

	/*
	 * 5.6.1
	 * For messages that change the contents of the iSNS database,
	 * the iSNS server MUST verify that the Source Attribute
	 * identifies either a Control Node or a Storage Node that is
	 * a part of the Network Entity containing the added, deleted,
	 * or modified objects.
	 *
	 * This check happens in isns_registration_get_key by calling
	 * isns_policy_validate_object_access.
	 */

	/* Get the key object (usually a Network Entity) */
	status = isns_registration_get_key(call, db, &key_obj);
	if (status)
		goto done;

	/* Get the objects to register */
	status = isns_registration_get_objects(call, db, key_obj, &objects);
	if (status != ISNS_SUCCESS)
		goto done;

	/* We parsed the request alright; all semantic checks passed.
	 * Now insert the modified/new objects.
	 * We do this in two passes, by first committing all nodes and
	 * portals, and then committing the portal groups.
	 */
	status = isns_commit_registration(db, key_obj, &objects);
	if (status != ISNS_SUCCESS)
		goto done;

	/* The client may have registered a bunch of storage nodes,
	 * and created an entity in the process. However, there's the
	 * odd chance that the source node name it used was not
	 * registered. However, we need to be able to later find
	 * the entity it registered based on its source name.
	 * So we implicitly create a dummy storage node with the given
	 * source name and attach it.
	 */
#if 1
	if (ISNS_IS_ENTITY(key_obj)
	 && !isns_source_set_node(call->is_source, db)) {
		isns_attr_list_t attrs = ISNS_ATTR_LIST_INIT;
		isns_source_t *source = call->is_source;
		isns_object_t *obj;

		isns_attr_list_append_attr(&attrs, isns_source_attr(source));
		isns_attr_list_append_uint32(&attrs, 
				ISNS_TAG_ISCSI_NODE_TYPE,
				0);
		obj = isns_create_object(&isns_iscsi_node_template,
				&attrs, key_obj);
		if (obj) {
			isns_db_insert(db, obj);
		} else {
			isns_warning("Unable to create dummy storage node "
					"for source %s\n",
					isns_source_name(source));
		}
		isns_attr_list_destroy(&attrs);
	}
#endif

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
	 */
	isns_create_registration_pgs(db, &objects);

	/* Success: create a new registration message, and
	 * send it in our reply. */
	reply = __isns_create_registration(srv->is_source, key_obj);
	if (reply == NULL) {
		status = ISNS_INTERNAL_ERROR;
		goto done;
	}

	/* If the key object was modified (or created)
	 * include it in the response.
	 * We really ought to restrict ourselves to the
	 * key attrs plus those that were modified by this
	 * registration. But right now have no way of
	 * finding out.
	 */
	if (key_obj->ie_flags & ISNS_OBJECT_DIRTY)
		isns_registration_add_object(reply, key_obj);

	for (i = 0; i < objects.iol_count; ++i) {
		isns_registration_add_object(reply,
				objects.iol_data[i]);
	}


done:
	isns_object_list_destroy(&objects);
	isns_object_release(key_obj);
	*result = reply;
	return status;
}

/*
 * Extract the list of objects from the DevAttrReg response
 */
int
isns_registration_response_get_objects(isns_simple_t *reg,
		isns_object_list_t *result)
{
	return isns_simple_response_get_objects(reg, result);
}
