/*
 * Handle iSNS Device Deregistration
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#include <stdlib.h>
#include <string.h>
#include "isns.h"
#include "attrs.h"
#include "objects.h"
#include "message.h"
#include "security.h"
#include "util.h"
#include "db.h"

extern isns_source_t *	isns_server_source;


/*
 * Create a registration, and set the source name
 */
static isns_simple_t *
__isns_create_deregistration(isns_source_t *source, const isns_attr_list_t *attrs)
{
	isns_simple_t	*simp;

	simp = isns_simple_create(ISNS_DEVICE_DEREGISTER, source, NULL);
	if (simp && attrs)
		isns_attr_list_copy(&simp->is_operating_attrs, attrs);
	return simp;
}

isns_simple_t *
isns_create_deregistration(isns_client_t *clnt, const isns_attr_list_t *attrs)
{
	return __isns_create_deregistration(clnt->ic_source, attrs);
}

/*
 * Get the next object identified by the operating attrs.
 */
static int
isns_deregistration_get_next_object(isns_db_t *db,
				struct isns_attr_list_scanner *st,
				isns_object_list_t *result)
{
	isns_object_t	*current;
	int		status;

	status = isns_attr_list_scanner_next(st);
	if (status)
		return status;

	/*
	 * 5.6.5.4.
	 * Valid Operating Attributes for DevDereg
	 * ---------------------------------------
	 *    Entity Identifier
	 *    Portal IP-Address & Portal TCP/UDP Port
	 *    Portal Index
	 *    iSCSI Name
	 *    iSCSI Index
	 *    FC Port Name WWPN
	 *    FC Node Name WWNN
	 *
	 * In other words, deregistration is restricted to Entity,
	 * portal, and node
	 */
	if (st->tmpl != &isns_entity_template
	 && st->tmpl != &isns_iscsi_node_template
	 && st->tmpl != &isns_portal_template)
		return ISNS_INVALID_DEREGISTRATION;

	/* Only key attrs allowed */
	if (st->attrs.ial_count) {
		/* MS Initiators send the Entity protocol along
		 * with the Entity Identifier. */
		isns_debug_protocol("Client included invalid operating attrs "
				"with %s:\n", st->tmpl->iot_name);
		isns_attr_list_print(&st->attrs, isns_debug_protocol);
		/* return ISNS_INVALID_DEREGISTRATION; */
	}

	/*
	 * 5.6.5.4
	 * Attempted deregistration of non-existing entries SHALL not
	 * be considered an isns_error.
	 */
	current = isns_db_lookup(db, st->tmpl, &st->keys);
	if (current != NULL) {
		isns_object_list_append(result, current);
		isns_object_release(current);
	}

	return ISNS_SUCCESS;
}

/*
 * Extract the list of objects to be deregistered from
 * the list of operating attributes.
 */
static int
isns_deregistration_get_objects(isns_simple_t *reg, isns_db_t *db,
					isns_object_list_t *result)
{
	struct isns_attr_list_scanner state;
	int		status = ISNS_SUCCESS;

	isns_attr_list_scanner_init(&state, NULL, &reg->is_operating_attrs);
	state.index_acceptable = 1;
	state.source = reg->is_source;

	while (state.pos < state.orig_attrs.ial_count) {
		status = isns_deregistration_get_next_object(db,
				&state, result);

		if (status == 0)
			continue;

		/* Translate error codes */
		if (status == ISNS_NO_SUCH_ENTRY)
			status = ISNS_SUCCESS;
		else
		if (status == ISNS_INVALID_REGISTRATION)
			status = ISNS_INVALID_DEREGISTRATION;
		break;
	}

	isns_attr_list_scanner_destroy(&state);
	return status;
}

/*
 * Process a deregistration
 *
 * Normally, you would expect that a deregistration removes the
 * object from the database, and that's the end of the story.
 * Unfortunately, someone added Discovery Domains to the protocol,
 * requiring _some_ information to survive as long as an object
 * is referenced by a discovery domain. Specifically, we need to
 * retain the relationship between key attributes (eg iscsi node
 * name) and the object index.
 *
 * Thus, deregistration consists of the following steps
 *  -	the object is removed from the database's global scope,
 *	so that it's no longer visible to DB lookups.
 *
 *  -	the object is detached from its containing Network
 *	Entity.
 *
 *  -	all attributes except the key attr(s) and the index
 *	attribute are removed.
 */
int
isns_process_deregistration(isns_server_t *srv, isns_simple_t *call, isns_simple_t **result)
{
	isns_object_list_t	objects = ISNS_OBJECT_LIST_INIT;
	isns_simple_t		*reply = NULL;
	isns_db_t		*db = srv->is_db;
	int			status, dereg_status;
	unsigned int		i;

	/* Get the objects to deregister */
	status = isns_deregistration_get_objects(call, db, &objects);
	if (status != ISNS_SUCCESS)
		goto done;

	/*
	 * 5.6.5.4
	 *
	 * For messages that change the contents of the iSNS database,
	 * the iSNS server MUST verify that the Source Attribute
	 * identifies either a Control Node or a Storage Node that is
	 * a part of the Network Entity containing the added, deleted,
	 * or modified objects.
	 */
	/*
	 * Implementation note: this can be implemented either by
	 * explicitly checking the object's owner in isns_db_remove
	 * (which is what we do right now), or by matching only
	 * those objects that have the right owner anyway.
	 *
	 * The latter sounds like a better choice if the client
	 * uses NIL attributes, because it limits the scope of
	 * the operation; but then the RFC doesn't say whether
	 * this kind of deregistration would be valid at all.
	 */

	/* Success: create a new simple message, and
	 * send it in our reply. */
	reply = __isns_create_deregistration(srv->is_source, NULL);
	if (reply == NULL) {
		status = ISNS_INTERNAL_ERROR;
		goto done;
	}

	dereg_status = ISNS_SUCCESS;
	for (i = 0; i < objects.iol_count; ++i) {
		isns_object_t	*obj = objects.iol_data[i];

		/* Policy: check that the client is permitted
		 * to deregister this object */
		if (!isns_policy_validate_object_access(call->is_policy,
					call->is_source, obj,
					call->is_function))
			status = ISNS_SOURCE_UNAUTHORIZED;

		if (status == ISNS_SUCCESS)
			status = isns_db_remove(db, obj);
		if (status != ISNS_SUCCESS) {
			/*
			 * 5.7.5.4
			 *
			 * In the event of an error, this response message
			 * contains the appropriate status code as well
			 * as a list of objects from the original DevDereg
			 * message that were not successfully deregistered
			 * from the iSNS database.  This list of objects
			 * is contained in the Operating Attributes
			 * of the DevDeregRsp message.	Note that an
			 * attempted deregistration of a non-existent
			 * object does not constitute an isns_error, and
			 * non-existent entries SHALL not be returned
			 * in the DevDeregRsp message.
			 */
			/*
			 * Implementation: right now this doesn't work
			 * at all, because isns_msg_set_error will
			 * discard the entire message except for the
			 * status word.
			 */
			isns_debug_message("Failed to deregister object: %s (0x%04x)\n",
				isns_strerror(status), status);

			isns_object_extract_all(obj, &reply->is_operating_attrs);
			dereg_status = status;
			continue;
		}

		/*
		 * 5.7.5.4
		 * If all Nodes and Portals associated with a Network
		 * Entity are deregistered, then the Network Entity
		 * SHALL also be removed.
		 * [...]
		 * If both the Portal and iSCSI Storage Node objects
		 * associated with a Portal Group object are removed,
		 * then that Portal Group object SHALL also be removed.
		 * The Portal Group object SHALL remain registered
		 * as long as either of its associated Portal or
		 * iSCSI Storage Node objects remain registered.  If a
		 * deleted Storage Node or Portal object is subsequently
		 * re-registered, then a relationship between the re-
		 * registered object and an existing Portal or Storage
		 * Node object registration, indicated by the PG object,
		 * SHALL be restored.
		 */
		/* isns_db_remove takes care of removing dead entities,
		 * and dead portal groups.
		 */
	}

	if (status == ISNS_SUCCESS)
		status = dereg_status;

done:
	isns_object_list_destroy(&objects);
	*result = reply;
	return status;
}
