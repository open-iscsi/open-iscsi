/*
 * Handle object visibility and scope.
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

struct isns_scope {
	isns_db_t *			ic_db;
	unsigned int			ic_users;
	isns_object_t *			ic_source_node;

	isns_object_template_t *	ic_query_class;

	isns_object_list_t		ic_dd_nodes;
	isns_object_list_t		ic_dd_portals;
	isns_object_list_t		ic_objects;
};

static int	__isns_scope_collect_dd(uint32_t, void *);

/*
 * Allocate an empty scope
 */
isns_scope_t *
isns_scope_alloc(isns_db_t *db)
{
	isns_scope_t *scope;

	scope = isns_calloc(1, sizeof(*scope));

	scope->ic_db = db;
	scope->ic_users = 1;
	return scope;
}

isns_scope_t *
isns_scope_get(isns_scope_t *scope)
{
	if (scope) {
		isns_assert(scope->ic_users);
		scope->ic_users++;
	}
	return scope;
}

void
isns_scope_release(isns_scope_t *scope)
{
	if (!scope)
		return;

	isns_assert(scope->ic_users);
	if (--(scope->ic_users))
		return;

	isns_object_release(scope->ic_source_node);
	isns_object_list_destroy(&scope->ic_dd_nodes);
	isns_object_list_destroy(&scope->ic_dd_portals);
	isns_object_list_destroy(&scope->ic_objects);
	isns_free(scope);
}

/*
 * Get the scope for this operation
 */
isns_scope_t *
isns_scope_for_call(isns_db_t *db, const isns_simple_t *call)
{
	isns_source_t	*source = call->is_source;
	isns_object_t	*node;
	isns_scope_t	*scope;
	uint32_t	node_type;

	/* FIXME use source->is_node and source->is_node_type */

	/* When we get here, we already know that the client
	 * represents the specified source node. */
	node = isns_db_lookup_source_node(db, source);

	/* Allow unknown nodes to query the DB */
	if (node == NULL) {
		node = isns_create_storage_node2(source, 0, NULL);
		if (node == NULL)
			return NULL;
		source->is_untrusted = 1;
	}

	if (isns_object_get_uint32(node, ISNS_TAG_ISCSI_NODE_TYPE, &node_type)
	 && (node_type & ISNS_ISCSI_CONTROL_MASK)) {
		isns_object_release(node);
		return isns_scope_get(db->id_global_scope);
	}

	scope = isns_scope_alloc(db);
	scope->ic_source_node = node;

	{
		isns_object_list_t members = ISNS_OBJECT_LIST_INIT;
		unsigned int	i;

		isns_object_get_visible(node, db, &members);
		isns_object_list_uniq(&members);

		/* If the node is not a member of any DD, allow it
		 * to at least talk to itself. */
		if (members.iol_count == 0)
			isns_object_list_append(&members, node);

		/* Sort DD members into nodes and portals */
		for (i = 0; i < members.iol_count; ++i) {
			isns_object_t *obj = members.iol_data[i];

			if (obj->ie_state != ISNS_OBJECT_STATE_MATURE)
				continue;
			if (!isns_policy_validate_object_access(call->is_policy,
						source, obj,
						call->is_function))
				continue;
			if (ISNS_IS_ISCSI_NODE(obj))
				isns_object_list_append(&scope->ic_dd_nodes, obj);
			else
			if (ISNS_IS_PORTAL(obj))
				isns_object_list_append(&scope->ic_dd_portals, obj);
		}
		isns_object_list_destroy(&members);
	}

	return scope;
}

/*
 * Add an object to a scope
 */
void
isns_scope_add(isns_scope_t *scope, isns_object_t *obj)
{
	isns_object_list_append(&scope->ic_objects, obj);
}

int
isns_scope_remove(isns_scope_t *scope, isns_object_t *obj)
{
	return isns_object_list_remove(&scope->ic_objects, obj);
}

/*
 * Get all objects related through a portal group, optionally
 * including the portal group objects themselves
 */
static void
__isns_scope_get_pg_related(isns_scope_t *scope,
		const isns_object_t *obj,
		isns_object_list_t *result)
{
	isns_object_list_t temp = ISNS_OBJECT_LIST_INIT;
	unsigned int	i;

	/* Get all portal groups related to this object */
	isns_db_get_relationship_objects(scope->ic_db,
			obj, ISNS_RELATION_PORTAL_GROUP, &temp);

	/* Include all portals/nodes that we can reach. */
	for (i = 0; i < temp.iol_count; ++i) {
		isns_object_t	*pg, *other;
		uint32_t	pgt;

		pg = temp.iol_data[i];

		/* Skip any portal group objects with a PG tag of 0;
		 * these actually deny access. */
		if (!isns_object_get_uint32(pg, ISNS_TAG_PG_TAG, &pgt)
		 || pgt == 0)
			continue;

		/* Get the other object.
		 * Note that isns_relation_get_other doesn't
		 * bump the reference count, so there's no need
		 * to call isns_object_release(other). */
		other = isns_relation_get_other(pg->ie_relation, obj);
		if (other->ie_state != ISNS_OBJECT_STATE_MATURE)
			continue;

		isns_object_list_append(result, other);
		isns_object_list_append(result, pg);
	}

	isns_object_list_destroy(&temp);
}

/*
 * Get all portals related to the given node.
 *
 * 2.2.2
 * Placing Portals of a Network Entity into Discovery Domains allows
 * administrators to indicate the preferred IP Portal interface through
 * which storage traffic should access specific Storage Nodes of that
 * Network Entity.  If no Portals of a Network Entity have been placed
 * into a DD, then queries scoped to that DD SHALL report all Portals of
 * that Network Entity.  If one or more Portals of a Network Entity have
 * been placed into a DD, then queries scoped to that DD SHALL report
 * only those Portals that have been explicitly placed in the DD.
 */
static void
__isns_scope_get_portals(isns_scope_t *scope,
		const isns_object_t *node,
		isns_object_list_t *portals,
		isns_object_list_t *pgs,
		int unique)
{
	isns_object_list_t related = ISNS_OBJECT_LIST_INIT;
	unsigned int	i, specific = 0;

	/* Get all portals and portal groups related to the
	 * given node. This will put pairs of (portal, portal-group)
	 * on the list.
	 */
	__isns_scope_get_pg_related(scope, node, &related);

	/* If we're querying for our own portals, don't limit
	 * visibility. */
	if (node == scope->ic_source_node)
		goto report_all_portals;

	/* Check if any of the portals is mentioned in the DD
	 * FIXME: There is some ambiguity over what the right
	 * answer is when you have two nodes (initiator, target),
	 * and two discovery domains linking the two. One
	 * DD mentions a specific portal through which target
	 * should be accessed; the other DD does not (allowing
	 * use of any portal in that entity). Which portals
	 * to return here?
	 * We go for the strict interpretation, ie if *any* DD
	 * restricts access to certain portals, we report only
	 * those.
	 */
	for (i = 0; i < related.iol_count; i += 2) {
		isns_object_t *portal = related.iol_data[i];

		if (isns_object_list_contains(&scope->ic_dd_portals, portal)) {
			if (portals
			 && !(unique || isns_object_list_contains(portals, portal)))
				isns_object_list_append(portals, portal);
			if (pgs)
				isns_object_list_append(pgs,
						related.iol_data[i + 1]);
			specific++;
		}
	}

	if (specific)
		goto out;

report_all_portals:
	/* No specific portal given for this node. Add them all. */
	for (i = 0; i < related.iol_count; i += 2) {
		isns_object_t *portal = related.iol_data[i];

		if (portals
		 && !(unique && isns_object_list_contains(portals, portal)))
			isns_object_list_append(portals, portal);
		if (pgs)
			isns_object_list_append(pgs,
					related.iol_data[i + 1]);
	}

out:
	isns_object_list_destroy(&related);
}

/*
 * Get all nodes reachable through a given portal
 * This is really the same as __isns_scope_get_portals
 * minus the special casing for preferred portals.
 * Still, let's put this into it's own function - the whole
 * thing is already complex enough already.
 */
static void
__isns_scope_get_nodes(isns_scope_t *scope,
		const isns_object_t *portal,
		isns_object_list_t *nodes,
		isns_object_list_t *pgs,
		int unique)
{
	isns_object_list_t related = ISNS_OBJECT_LIST_INIT;
	unsigned int	i;

	/* Get all nodes and portal groups related to the
	 * given node. This will put pairs of (nodes, portal-group)
	 * on the list.
	 */
	__isns_scope_get_pg_related(scope, portal, &related);

	for (i = 0; i < related.iol_count; i += 2) {
		isns_object_t *node = related.iol_data[i];

		if (nodes
		 && !(unique && isns_object_list_contains(nodes, node)))
			isns_object_list_append(nodes, node);
		if (pgs)
			isns_object_list_append(pgs,
					related.iol_data[i + 1]);
	}

	isns_object_list_destroy(&related);
}

static void
__isns_scope_get_default_dd(isns_scope_t *scope)
{
	isns_object_t	*obj;

	if (isns_config.ic_use_default_domain) {
		obj = isns_create_default_domain();
		isns_object_list_append(&scope->ic_objects, obj);
		isns_object_release(obj);
	}
}


/*
 * Scope the query
 */
static void
__isns_scope_prepare_query(isns_scope_t *scope,
		isns_object_template_t *tmpl)
{
	isns_object_list_t *nodes;
	unsigned int	i;

	/* Global and default scope have no source node; they're just
	 * a list of objects.
	 */
	if (scope->ic_source_node == NULL)
		return;

	if (scope->ic_query_class) {
		if (scope->ic_query_class == tmpl)
			return;
		isns_object_list_destroy(&scope->ic_objects);
	}
	scope->ic_query_class = tmpl;

	nodes = &scope->ic_dd_nodes;
	if (tmpl == &isns_entity_template) {
		for (i = 0; i < nodes->iol_count; ++i) {
			isns_object_t *obj = nodes->iol_data[i];

			if (obj->ie_container)
				isns_object_list_append(&scope->ic_objects,
						obj->ie_container);
		}
	} else
	if (tmpl == &isns_iscsi_node_template) {
		for (i = 0; i < nodes->iol_count; ++i) {
			isns_object_t *obj = nodes->iol_data[i];

			isns_object_list_append(&scope->ic_objects, obj);
		}
	} else
	if (tmpl == &isns_portal_template) {
		for (i = 0; i < nodes->iol_count; ++i) {
			isns_object_t *obj = nodes->iol_data[i];

			__isns_scope_get_portals(scope, obj,
					&scope->ic_objects, NULL, 0);
		}
	} else
	if (tmpl == &isns_iscsi_pg_template) {
		for (i = 0; i < nodes->iol_count; ++i) {
			isns_object_t *obj = nodes->iol_data[i];

			__isns_scope_get_portals(scope, obj,
					NULL, &scope->ic_objects, 0);
		}
	} else
	if (tmpl == &isns_dd_template) {
		isns_object_t	*node = scope->ic_source_node;

		if (node && !isns_bitvector_is_empty(node->ie_membership))
			isns_bitvector_foreach(node->ie_membership,
					__isns_scope_collect_dd,
					scope);
		else
			__isns_scope_get_default_dd(scope);
	}

	isns_object_list_uniq(&scope->ic_objects);
}

static int
__isns_scope_collect_dd(uint32_t dd_id, void *ptr)
{
	isns_scope_t *scope = ptr;
	isns_object_t *dd;

	dd = isns_db_vlookup(scope->ic_db, &isns_dd_template,
			ISNS_TAG_DD_ID, dd_id,
			0);
	if (dd) {
		isns_object_list_append(&scope->ic_objects, dd);
		isns_object_release(dd);
	}

	return 0;
}

/*
 * Lookup functions for scope
 */
int
isns_scope_gang_lookup(isns_scope_t *scope,
				isns_object_template_t *tmpl,
				const isns_attr_list_t *match,
				isns_object_list_t *result)
{
	isns_assert(tmpl);

	if (!scope)
		return 0;

	__isns_scope_prepare_query(scope, tmpl);
	return isns_object_list_gang_lookup(&scope->ic_objects,
			tmpl, match, result);
}

/*
 * Get related objects.
 * This is used by the query code.
 */
void
isns_scope_get_related(isns_scope_t *scope,
				const isns_object_t *origin,
				unsigned int type_mask,
				isns_object_list_t *result)
{
	isns_object_template_t *tmpl = origin->ie_template;
	isns_object_list_t	nodes_result = ISNS_OBJECT_LIST_INIT;
	isns_object_list_t	portals_result = ISNS_OBJECT_LIST_INIT;
	isns_object_list_t	*members = &scope->ic_dd_nodes;
	unsigned int		i;

	if (tmpl == &isns_entity_template) {
		/* Entity: include all storage nodes contained,
		 * the portals through which to reach them, and
		 * the portal groups for those. */
		for (i = 0; i < members->iol_count; ++i) {
			isns_object_t *obj = members->iol_data[i];

			if (obj->ie_container != origin)
				continue;

			isns_object_list_append(&nodes_result, obj);
			__isns_scope_get_portals(scope, obj,
						&portals_result,
						&portals_result, 1);
		}
	} else
	if (tmpl == &isns_iscsi_node_template) {
		/* Storage node: include all portals through
		 * which it can be reached, and the portal
		 * groups for those. */
		__isns_scope_get_portals(scope, origin,
					&portals_result,
					&portals_result, 1);
		/* FIXME: Include all discovery domains the
		 * node is a member of. */
	} else
	if (tmpl == &isns_portal_template) {
		/* Portal: include all storage nodes which can
		 * be reached through it, and the portal groups
		 * for those. */
		__isns_scope_get_nodes(scope, origin,
					&portals_result,
					&portals_result, 1);
	} else
	if (tmpl == &isns_iscsi_pg_template) {
		/* Portal group: PGs *are* a relationship, but
		 * unclear how this should be handled.
		 * Return nothing for now. */
	} else
	if (tmpl == &isns_dd_template) {
		/* Discovery domain: no related objects. */
	}

	isns_object_list_append_list(result, &nodes_result);
	isns_object_list_append_list(result, &portals_result);

	isns_object_list_destroy(&nodes_result);
	isns_object_list_destroy(&portals_result);
}

isns_object_t *
isns_scope_get_next(isns_scope_t *scope,
				isns_object_template_t *tmpl,
				const isns_attr_list_t *current,
				const isns_attr_list_t *match)
{
	if (!tmpl || !scope)
		return NULL;

	__isns_scope_prepare_query(scope, tmpl);
	return __isns_db_get_next(&scope->ic_objects, tmpl, current, match);
}
