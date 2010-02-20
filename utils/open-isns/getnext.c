/*
 * Handle iSNS DevGetNext
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#include <stdlib.h>
#include <string.h>
#include "isns.h"
#include "attrs.h"
#include "message.h"
#include "security.h"
#include "objects.h"
#include "db.h"
#include "util.h"

/*
 * Create a GetNext query, and set the source name
 */
static isns_simple_t *
__isns_create_getnext(isns_source_t *source,
		const isns_attr_list_t *key,
		const isns_attr_list_t *scope)
{
	isns_simple_t *simp;

	simp = isns_simple_create(ISNS_DEVICE_GET_NEXT, source, key);
	if (simp && scope)
		isns_attr_list_copy(&simp->is_operating_attrs,
				scope);
	return simp;
}

isns_simple_t *
isns_create_getnext(isns_client_t *clnt,
		isns_object_template_t *tmpl,
		const isns_attr_list_t *scope)
{
	isns_simple_t *simp;
	unsigned int	i;

	simp = __isns_create_getnext(clnt->ic_source, NULL, scope);
	if (simp == NULL)
		return NULL;

	for (i = 0; i < tmpl->iot_num_keys; ++i) {
		isns_attr_list_append_nil(&simp->is_message_attrs,
				tmpl->iot_keys[i]);
	}
	return simp;
}

isns_simple_t *
isns_create_getnext_followup(isns_client_t *clnt,
		const isns_simple_t *resp,
		const isns_attr_list_t *scope)
{
	return __isns_create_getnext(clnt->ic_source,
			&resp->is_message_attrs, scope);
}

/*
 * Get the list of objects matching this query
 */
static int
isns_getnext_get_object(isns_simple_t *qry, isns_db_t *db,
		isns_object_t **result)
{
	isns_scope_t		*scope;
	isns_attr_list_t	*keys = &qry->is_message_attrs, match;
	isns_object_template_t	*tmpl;
	unsigned int		i;

	/*
	 * 5.6.5.3.
	 * The Message Key Attribute may be an Entity Identifier (EID),
	 * iSCSI Name, iSCSI Index, Portal IP Address and TCP/UDP Port,
	 * Portal Index, PG Index, FC Node Name WWNN, or FC Port Name
	 * WWPN.
	 *
	 * Implementer's comment: In other words, it must be the
	 * key attr(s) of a specific object type, or an index attribute.
	 */
	if ((tmpl = isns_object_template_for_key_attrs(keys)) != NULL) {
		if (keys->ial_count != tmpl->iot_num_keys)
			return ISNS_INVALID_QUERY;
	} else if (keys->ial_count == 1) {
		isns_attr_t *attr = keys->ial_data[0];

		tmpl = isns_object_template_for_index_tag(attr->ia_tag_id);
	}
	if (tmpl == NULL)
		return ISNS_INVALID_QUERY;

	/* Verify whether the client is permitted to retrieve
	 * objects of the given type. */
	if (!isns_policy_validate_object_type(qry->is_policy, tmpl,
					qry->is_function))
		return ISNS_SOURCE_UNAUTHORIZED;

	/*
	 * 5.6.5.3.
	 * The Operating Attributes can be used to specify the scope
	 * of the DevGetNext request, and to specify the attributes of
	 * the next object, which are to be returned in the DevGetNext
	 * response message.  All Operating Attributes MUST be attributes
	 * of the object type identified by the Message Key.
	 */
	match = qry->is_operating_attrs;
	for (i = 0; i < match.ial_count; ++i) {
		isns_attr_t *attr = match.ial_data[i];

		if (tmpl != isns_object_template_for_tag(attr->ia_tag_id))
			return ISNS_INVALID_QUERY;
	}

	/*
	 * 5.6.5.3.
	 * Non-zero-length TLV attributes in the Operating Attributes
	 * are used to scope the DevGetNext message.
	 * [...]
	 * Zero-length TLV attributes MUST be listed after non-zero-length
	 * attributes in the Operating Attributes of the DevGetNext
	 * request message.
	 */
	for (i = 0; i < match.ial_count; ++i) {
		if (ISNS_ATTR_IS_NIL(match.ial_data[i])) {
			match.ial_count = i;
			break;
		}
	}

	/* Get the scope for the originating node. */
	scope = isns_scope_for_call(db, qry);

	*result = isns_scope_get_next(scope, tmpl, keys, &match);

	isns_scope_release(scope);

	if (*result == NULL)
		return ISNS_NO_SUCH_ENTRY;
	return ISNS_SUCCESS;
}

/*
 * Create a Query Response
 */
static isns_simple_t *
isns_create_getnext_response(isns_source_t *source,
		const isns_simple_t *qry, isns_object_t *obj)
{
	const isns_attr_list_t *req_attrs = NULL;
	isns_attr_list_t requested;
	isns_simple_t	*resp;
	unsigned int	i;

	resp = __isns_create_getnext(source, NULL, NULL);

	/*
	 * 5.7.5.3.  Device Get Next Response (DevGetNextRsp)
	 * The Message Key Attribute field returns the object keys
	 * for the next object after the Message Key Attribute in the
	 * original DevGetNext message.
	 *
	 * Implementer's note: slightly convoluted English here. 
	 * I *think* this means the key attributes of the object
	 * we matched.
	 */
	if (!isns_object_get_key_attrs(obj, &resp->is_message_attrs))
		return NULL;

	/*
	 * 5.7.5.3.
	 * The Operating Attribute field returns the Operating Attributes
	 * of the next object as requested in the original DevGetNext
	 * message.  The values of the Operating Attributes are those
	 * associated with the object identified by the Message Key
	 * Attribute field of the DevGetNextRsp message.
	 *
	 * Implementer's note: the RFC doesn't say clearly what to
	 * do when the list of operating attributes does not
	 * contain any NIL TLVs. Let's default to the same
	 * behavior as elsewhere, and return all attributes
	 * in this case.
	 */
	req_attrs = &qry->is_operating_attrs;
	for (i = 0; i < req_attrs->ial_count; ++i) {
		if (ISNS_ATTR_IS_NIL(req_attrs->ial_data[i]))
			break;
	}
	requested.ial_count = req_attrs->ial_count - i;
	requested.ial_data = req_attrs->ial_data + i;
	if (requested.ial_count)
		req_attrs = &requested;
	else
		req_attrs = NULL;

	isns_object_get_attrlist(obj,
			&resp->is_operating_attrs,
			req_attrs);
	return resp;
}

/*
 * Process a GetNext request
 */
int
isns_process_getnext(isns_server_t *srv, isns_simple_t *call, isns_simple_t **result)
{
	isns_simple_t		*reply = NULL;
	isns_object_t		*obj = NULL;
	isns_db_t		*db = srv->is_db;
	int			status;

	/* Get the next object */
	status = isns_getnext_get_object(call, db, &obj);
	if (status != ISNS_SUCCESS)
		goto done;

	/* If it's a virtual object, rebuild it */
	if (obj->ie_rebuild)
		obj->ie_rebuild(obj, srv->is_db);

	/* Success: create a new simple message, and
	 * send it in our reply. */
	reply = isns_create_getnext_response(srv->is_source, call, obj);
	if (reply == NULL)
		status = ISNS_INTERNAL_ERROR;

done:
	if (obj)
		isns_object_release(obj);
	*result = reply;
	return status;
}

/*
 * Parse the object in a getnext response
 */
int
isns_getnext_response_get_object(isns_simple_t *qry,
		isns_object_t **result)
{
	isns_object_template_t *tmpl;

	tmpl = isns_object_template_for_key_attrs(&qry->is_operating_attrs);
	if (tmpl == NULL) {
		isns_error("Cannot determine object type in GetNext response\n");
		return ISNS_ATTRIBUTE_NOT_IMPLEMENTED;
	}

	*result = isns_create_object(tmpl,
			&qry->is_operating_attrs,
			NULL);
	return ISNS_SUCCESS;
}

