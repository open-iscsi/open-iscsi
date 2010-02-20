/*
 * Handle iSNS Device Attribute Query
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
 * Create a query, and set the source name
 */
static isns_simple_t *
__isns_create_query(isns_source_t *source, const isns_attr_list_t *key)
{
	return isns_simple_create(ISNS_DEVICE_ATTRIBUTE_QUERY, source, key);
}

isns_simple_t *
isns_create_query(isns_client_t *clnt, const isns_attr_list_t *key)
{
	return __isns_create_query(clnt->ic_source, key);
}

isns_simple_t *
isns_create_query2(isns_client_t *clnt, const isns_attr_list_t *key, isns_source_t *source)
{
	return __isns_create_query(source?: clnt->ic_source, key);
}

int
isns_query_request_attr_tag(isns_simple_t *qry, uint32_t tag)
{
	isns_attr_list_append_nil(&qry->is_operating_attrs, tag);
	return ISNS_SUCCESS;
}

int
isns_query_request_attr(isns_simple_t *qry, isns_attr_t *attr)
{
	if (!ISNS_ATTR_IS_NIL(attr)) {
		isns_error("Query operating attribute must be NIL\n");
		return ISNS_INVALID_QUERY;
	}
	isns_attr_list_append_attr(&qry->is_operating_attrs, attr);
	return ISNS_SUCCESS;
}

static unsigned int
isns_query_get_requested_types(const isns_attr_list_t *attrs)
{
	unsigned int	i, mask = 0;

	for (i = 0; i < attrs->ial_count; ++i) {
		uint32_t tag = attrs->ial_data[i]->ia_tag_id;
		isns_object_template_t *tmpl;

		tmpl = isns_object_template_find(tag);
		/* Ignore unknown tags */
		if (tmpl == NULL)
			continue;

		mask |= 1 << tmpl->iot_handle;
	}
	return mask;
}

/*
 * Get the list of objects matching this query
 */
static int
isns_query_get_objects(isns_simple_t *qry, isns_db_t *db, isns_object_list_t *result)
{
	isns_scope_t		*scope = NULL;
	isns_object_list_t	matching = ISNS_OBJECT_LIST_INIT;
	isns_attr_list_t	*keys = &qry->is_message_attrs;
	isns_object_template_t	*query_type = NULL;
	unsigned int		i, qry_mask = 0;
	int			status;

	/* 5.6.5.2
	 * If multiple attributes are used as the Message Key, then they
	 * MUST all be from the same object type (e.g., IP address and
	 * TCP/UDP Port are attributes of the Portal object type).
	 */
	for (i = 0; i < keys->ial_count; ++i) {
		isns_object_template_t	*tmpl;
		uint32_t tag = keys->ial_data[i]->ia_tag_id;

		tmpl = isns_object_template_for_tag(tag);
		if (tmpl == NULL)
			return ISNS_ATTRIBUTE_NOT_IMPLEMENTED;
		if (query_type == NULL)
			query_type = tmpl;
		else if (tmpl != query_type)
			return ISNS_INVALID_QUERY;
	}

	/*
	 * 5.6.5.2
	 * An empty Message Key field indicates the query is scoped to
	 * the entire database accessible by the source Node.
	 */
	if (keys->ial_count == 0) {
		query_type = &isns_entity_template;
		keys = NULL;
	}

	/* Policy: check whether the client is allowed to
	 * query this type of object. */
	if (!isns_policy_validate_object_type(qry->is_policy,
				query_type, qry->is_function))
		return ISNS_SOURCE_UNAUTHORIZED;

	/* No scope means that the source is not part of
	 * any discovery domain, and there's no default DD.
	 * Just return an empty reply. */
	scope = isns_scope_for_call(db, qry);
	if (scope == NULL)
		return ISNS_SUCCESS;

	status = isns_scope_gang_lookup(scope, query_type, keys, &matching);
	if (status != ISNS_SUCCESS)
		goto out;

	/* Extract the mask of requested objects */
	qry_mask = isns_query_get_requested_types(&qry->is_operating_attrs);

	/*
	 * 5.6.5.2
	 * The DevAttrQry response message returns attributes of objects
	 * listed in the Operating Attributes that are related to the
	 * Message Key of the original DevAttrQry message.
	 */
	for (i = 0; i < matching.iol_count; ++i) {
		isns_object_t	*obj = matching.iol_data[i];

		if (!isns_policy_validate_object_access(qry->is_policy,
					qry->is_source, obj,
					qry->is_function))
			continue;

		if (obj->ie_container)
			isns_object_list_append(result, obj->ie_container);
		isns_object_list_append(result, obj);
		isns_scope_get_related(scope, obj, qry_mask, result);
	}

out:
	isns_object_list_destroy(&matching);
	isns_scope_release(scope);
	return status;
}

/*
 * Create a Query Response
 */
static isns_simple_t *
isns_create_query_response(isns_server_t *srv,
		const isns_simple_t *qry, const isns_object_list_t *objects)
{
	const isns_attr_list_t *req_attrs = NULL;
	isns_simple_t	*resp;
	unsigned int	i;

	resp = __isns_create_query(srv->is_source, &qry->is_message_attrs);

	/*
	 * 5.7.5.2.
	 * If no Operating Attributes are included in the original
	 * query, then all Operating Attributes SHALL be returned
	 * in the response.
	 */
	if (qry->is_operating_attrs.ial_count != 0)
		req_attrs = &qry->is_operating_attrs;

	for (i = 0; i < objects->iol_count; ++i) {
		isns_object_t	*obj = objects->iol_data[i];

		if (obj->ie_rebuild)
			obj->ie_rebuild(obj, srv->is_db);
		isns_object_get_attrlist(obj,
				&resp->is_operating_attrs,
				req_attrs);
	}
	return resp;
}

int
isns_process_query(isns_server_t *srv, isns_simple_t *call, isns_simple_t **result)
{
	isns_object_list_t	objects = ISNS_OBJECT_LIST_INIT;
	isns_simple_t		*reply = NULL;
	isns_db_t		*db = srv->is_db;
	int			status;

	/* Get the objects matching the query */
	status = isns_query_get_objects(call, db, &objects);
	if (status != ISNS_SUCCESS)
		goto done;

	/* Success: build the response */
	reply = isns_create_query_response(srv, call, &objects);
	if (reply == NULL) {
		status = ISNS_INTERNAL_ERROR;
		goto done;
	}

	/* There's nothing in the spec that tells us what to
	 * return if the query matches no object.
	 */
	if (objects.iol_count == 0) {
		status = ISNS_NO_SUCH_ENTRY;
		goto done;
	}

done:
	isns_object_list_destroy(&objects);
	*result = reply;
	return status;
}

/*
 * Parse the list of objects in a query response
 */
int
isns_query_response_get_objects(isns_simple_t *qry,
		isns_object_list_t *result)
{
	return isns_simple_response_get_objects(qry, result);
}
