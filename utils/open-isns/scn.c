/*
 * Handle SCN registration/deregistration/events
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

typedef struct isns_scn isns_scn_t;
typedef struct isns_scn_funnel isns_scn_funnel_t;

struct isns_scn {
	isns_scn_t *		scn_next;
	char *			scn_name;
	isns_object_t *		scn_entity;
	isns_object_t *		scn_owner;
	isns_attr_t *		scn_attr;

	isns_simple_t *		scn_message;
	isns_simple_t *		scn_pending;
	unsigned int		scn_retries;
	time_t			scn_timeout;
	uint16_t		scn_xid;

	time_t			scn_last_update;
	isns_scn_funnel_t *	scn_current_funnel;
	isns_scn_funnel_t *	scn_funnels;
};

struct isns_scn_funnel {
	isns_scn_funnel_t *	scn_next;
	isns_portal_info_t	scn_portal;
	isns_socket_t *		scn_socket;
	unsigned int		scn_bad;
};

static isns_server_t *		isns_scn_server = NULL;
static isns_scn_t *		isns_scn_list;

static isns_scn_t *		isns_scn_create_scn(isns_object_t *, uint32_t, isns_db_t *);
static void			isns_scn_delete_scn(isns_object_t *);
static isns_scn_t *		isns_scn_setup(isns_scn_t *, isns_object_t *);
static void			isns_scn_callback(const isns_db_event_t *, void *);
static void			isns_scn_free(isns_scn_t *);

/*
 * Initialize SCN machinery
 */
void
isns_scn_init(isns_server_t *srv)
{
	isns_db_t	*db = srv->is_db;
	isns_object_list_t nodes = ISNS_OBJECT_LIST_INIT;
	isns_scn_t	**tail;
	unsigned int	i;

	isns_scn_server = srv;
	isns_register_callback(isns_scn_callback, db);

	/* Recover SCN state. */
	isns_db_gang_lookup(db, &isns_iscsi_node_template, NULL, &nodes);
#ifdef notyet
	isns_db_gang_lookup(db, &isns_fc_node_template, NULL, &nodes);
#endif

	tail = &isns_scn_list;
	for (i = 0; i < nodes.iol_count; ++i) {
		isns_object_t	*node = nodes.iol_data[i];
		isns_scn_t	*scn;

		if (!node->ie_scn_mask)
			continue;

		isns_debug_state("Recovering SCN state for %s %u\n",
				node->ie_template->iot_name,
				node->ie_index);
		scn = isns_scn_setup(NULL, node);
		if (scn) {
			*tail = scn;
			tail = &scn->scn_next;
		}
	}
}

/*
 * Support for SCNRegister calls
 */
isns_simple_t *
isns_create_scn_registration2(isns_client_t *clnt, unsigned int bitmap, isns_source_t *source)
{
	isns_simple_t	*call;

	if (!source)
		source = clnt->ic_source;
	call = isns_simple_create(ISNS_SCN_REGISTER, source, NULL);
	if (call) {
		isns_attr_list_append_attr(&call->is_message_attrs,
				isns_source_attr(source));
		isns_attr_list_append_uint32(&call->is_operating_attrs,
				ISNS_TAG_ISCSI_SCN_BITMAP,
				bitmap);
	}
	return call;
}

isns_simple_t *
isns_create_scn_registration(isns_client_t *clnt, unsigned int bitmap)
{
	return isns_create_scn_registration2(clnt, bitmap, clnt->ic_source);
}

/*
 * Create an SCN
 */
isns_simple_t *
isns_create_scn(isns_source_t *source, isns_attr_t *nodeattr, isns_attr_t *tsattr)
{
	isns_simple_t	*call;

	call = isns_simple_create(ISNS_STATE_CHANGE_NOTIFICATION, source, NULL);
	if (call && nodeattr)
		isns_attr_list_append_attr(&call->is_message_attrs, nodeattr);
	if (call && tsattr)
		isns_attr_list_append_attr(&call->is_message_attrs, tsattr);
	return call;
}

static void
isns_scn_add_event(isns_simple_t *call, uint32_t scn_bits,
			const isns_object_t *obj,
			const isns_object_t *dd)
{
	isns_attr_list_t	*attrs = &call->is_message_attrs;

	isns_attr_list_append_uint32(attrs,
			ISNS_TAG_ISCSI_SCN_BITMAP,
			scn_bits);
	isns_object_extract_keys(obj, attrs);
	if (dd)
		isns_object_extract_keys(dd, attrs);
}

/*
 * Process a SCN registration
 */
int
isns_process_scn_register(isns_server_t *srv, isns_simple_t *call, isns_simple_t **result)
{
	isns_attr_list_t *keys = &call->is_message_attrs;
	isns_attr_list_t *attrs = &call->is_operating_attrs;
	isns_db_t	*db = srv->is_db;
	isns_attr_t	*attr;
	isns_object_t	*node = NULL;
	uint32_t	scn_bitmap;
	isns_scn_t	*scn;
	int		status = ISNS_SUCCESS;

	/*
	 * 5.6.5.5
	 * The SCNReg request PDU Payload contains a Source Attribute, a Message
	 * Key Attribute, and an Operating Attribute.  Valid Message Key
	 * Attributes for a SCNReg are shown below:
	 *
	 * Valid Message Key Attributes for SCNReg
	 * ---------------------------------------
	 *  iSCSI Name
	 *  FC Port Name WWPN
	 */
	if (keys->ial_count != 1 || attrs->ial_count != 1)
		return ISNS_SCN_REGISTRATION_REJECTED;

	attr = keys->ial_data[0];
	if (attr->ia_tag_id != ISNS_TAG_ISCSI_NAME &&
	    attr->ia_tag_id != ISNS_TAG_FC_PORT_NAME_WWPN)
		return ISNS_SCN_REGISTRATION_REJECTED;

	/* Look up the storage node for this source. If it does
	 * not exist, reject the message. */
	node = isns_db_lookup(db, NULL, keys);
	if (node == NULL)
		return ISNS_SOURCE_UNKNOWN;

	/*
	 * Policy: verify that the client is permitted
	 * to access this entity.
	 *
	 * This includes
	 *  -	the client node must be the object owner,
	 *	or a control node.
	 *  -	the policy must allow monitoring of
	 *	this object type.
	 */
	if (!isns_policy_validate_object_access(call->is_policy,
				call->is_source,
				node, call->is_function))
		goto unauthorized;

	/*
	 * 5.6.5.5
	 * The SCN Bitmap is the only operating attribute of this message
	 * [...]
	 * Control Nodes MAY conduct registrations for management SCNs;
	 * iSNS clients that are not supporting Control Nodes MUST NOT
	 * conduct registrations for management SCNs.
	 *
	 * Implementer's note: for iFCP sources, we should check for
	 * ISNS_TAG_IFCP_SCN_BITMAP.
	 */
	attr = attrs->ial_data[0];
	if (attr->ia_tag_id != ISNS_TAG_ISCSI_SCN_BITMAP
	 || !ISNS_ATTR_IS_UINT32(attr))
		goto rejected;

	scn_bitmap = attr->ia_value.iv_uint32;
	if (!isns_policy_validate_scn_bitmap(call->is_policy, scn_bitmap))
		goto unauthorized;

	/*
	 * 5.6.5.5
	 * If no SCN Port fields of any Portals of the Storage Node are
	 * registered to receive SCN messages, then the SCNReg message SHALL
	 * be rejected with Status Code 17 (SCN Registration Rejected).
	 */
	if (!(scn = isns_scn_create_scn(node, scn_bitmap, db)))
		goto rejected;

	*result = isns_simple_create(ISNS_SCN_REGISTER, srv->is_source, NULL);
	status = ISNS_SUCCESS;

out:
	if (node)
		isns_object_release(node);

	return status;

rejected:
	status = ISNS_SCN_REGISTRATION_REJECTED;
	goto out;

unauthorized:
	status = ISNS_SOURCE_UNAUTHORIZED;
	goto out;
}

/*
 * Process a SCNDereg message
 */
int
isns_process_scn_deregistration(isns_server_t *srv, isns_simple_t *call, isns_simple_t **result)
{
	isns_attr_list_t *keys = &call->is_message_attrs;
	isns_db_t	*db = srv->is_db;
	isns_attr_t	*attr;
	isns_object_t	*node = NULL;
	int		status = ISNS_SUCCESS;

	/*
	 * 5.6.5.6
	 * The SCNDereg request message PDU Payload contains a Source Attribute
	 * and Message Key Attribute(s).  Valid Message Key Attributes for a
	 * SCNDereg are shown below:
	 *
	 *	  Valid Message Key Attributes for SCNDereg
	 *	  -----------------------------------------
	 *	   iSCSI Name
	 *	   FC Port Name WWPN
	 *
	 * There are no Operating Attributes in the SCNDereg message.
	 */

	if (keys->ial_count != 1)
		return ISNS_SCN_REGISTRATION_REJECTED;

	attr = keys->ial_data[0];
	if (attr->ia_tag_id != ISNS_TAG_ISCSI_NAME &&
	    attr->ia_tag_id != ISNS_TAG_FC_PORT_NAME_WWPN)
		return ISNS_SCN_REGISTRATION_REJECTED;

	/* Look up the storage node for this source. If it does
	 * not exist, reject the message. */
	node = isns_db_lookup(db, NULL, keys);
	if (node == NULL)
		return ISNS_SUCCESS;

	/*
	 * Policy: verify that the client is permitted
	 * to access this entity.
	 *
	 * This includes
	 *  -	the client node must be the object owner,
	 *	or a control node.
	 *  -	the policy must allow monitoring of
	 *	this object type.
	 */
	if (!isns_policy_validate_object_access(call->is_policy,
				call->is_source,
				node, call->is_function))
		goto unauthorized;

	isns_object_set_scn_mask(node, 0);
	isns_scn_delete_scn(node);

	*result = isns_simple_create(ISNS_SCN_DEREGISTER, srv->is_source, NULL);
	status = ISNS_SUCCESS;

out:
	if (node)
		isns_object_release(node);

	return status;

unauthorized:
	status = ISNS_SOURCE_UNAUTHORIZED;
	goto out;
}

/*
 * Set up the SCN object.
 */
static isns_scn_t *
isns_scn_setup(isns_scn_t *scn, isns_object_t *node)
{
	isns_object_list_t portals = ISNS_OBJECT_LIST_INIT;
	isns_object_t	*entity;
	unsigned int	i;

	entity = isns_object_get_entity(node);
	if (entity == NULL
	 || !isns_object_find_descendants(entity,
			 &isns_portal_template, NULL, &portals))
		return NULL;

	for (i = 0; i < portals.iol_count; ++i) {
		isns_object_t	*portal = portals.iol_data[i];
		isns_portal_info_t info;
		isns_scn_funnel_t *funnel;

		/* Extract address and SCN port from portal */
		if (!isns_portal_from_object(&info,
				ISNS_TAG_PORTAL_IP_ADDRESS,
				ISNS_TAG_SCN_PORT,
				portal))
			continue;

		/* We know where to send our notifications! */
		if (scn == NULL) {
			isns_attr_t	*attr;

			if (!isns_object_get_attr(node, ISNS_TAG_ISCSI_NAME, &attr)
			 && !isns_object_get_attr(node, ISNS_TAG_FC_PORT_NAME_WWPN, &attr)) {
				isns_error("Attempt to set up SCN for strange node type\n");
				return NULL;
			}

			scn = isns_calloc(1, sizeof(*scn));
			scn->scn_entity = isns_object_get(entity);
			scn->scn_owner = isns_object_get(node);
			scn->scn_attr = isns_attr_get(attr);
			scn->scn_name = isns_strdup(attr->ia_value.iv_string);
		}

		funnel = isns_calloc(1, sizeof(*funnel));
		funnel->scn_portal = info;
		funnel->scn_next = scn->scn_funnels;
		scn->scn_funnels = funnel;
	}

	isns_object_list_destroy(&portals);
	return scn;
}

/*
 * See if an SCN object exists for the given target;
 * if it doesn't, then create one.
 */
static isns_scn_t *
isns_scn_create_scn(isns_object_t *node, uint32_t bitmap, isns_db_t *db)
{
	isns_scn_t	*scn;

	for (scn = isns_scn_list; scn; scn = scn->scn_next) {
		if (scn->scn_owner == node)
			goto done;
	}

	/* Not found - create it */
	scn = isns_scn_setup(NULL, node);
	if (scn == NULL)
		return NULL;

	scn->scn_next = isns_scn_list;
	isns_scn_list = scn;

done:
	/* We're all set - update the bitmap */
	isns_object_set_scn_mask(node, bitmap);
	return scn;
}

static void
isns_scn_delete_scn(isns_object_t *node)
{
	isns_scn_t	*scn, **pos;

	pos = &isns_scn_list;
	while ((scn = *pos) != NULL) {
		if (scn->scn_owner == node) {
			isns_debug_scn("Deregistering SCN for node %u\n",
					node->ie_index);
			*pos = scn->scn_next;
			isns_scn_free(scn);
			return;
		}
		pos = &scn->scn_next;
	}
}

static void
isns_scn_release_funnels(isns_scn_t *scn)
{
	isns_scn_funnel_t *funnel;

	while ((funnel = scn->scn_funnels) != NULL) {
		scn->scn_funnels = funnel->scn_next;
		if (funnel->scn_socket)
			isns_socket_free(funnel->scn_socket);
		isns_free(funnel);
	}
}

static void
isns_scn_free(isns_scn_t *scn)
{
	isns_scn_release_funnels(scn);
	isns_object_release(scn->scn_owner);
	isns_object_release(scn->scn_entity);
	isns_attr_release(scn->scn_attr);
	isns_free(scn->scn_name);
	isns_free(scn);
}

/*
 * Check whether we should send an event to the target
 */
static inline int
isns_scn_match(isns_scn_t *scn, uint32_t event,
		const isns_object_t *node,
		uint32_t node_type)
{
	if (event == 0)
		return 0;

	if (node->ie_scn_mask & ISNS_SCN_MANAGEMENT_REGISTRATION_MASK)
		return event | ISNS_SCN_MANAGEMENT_REGISTRATION_MASK;

#if 0
	/* This is a normal (non-control) node. Check whether the object
	 * is in the scope of this client. */
	if (!isns_object_in_scope(scn->scn_owner, node))
		return 0;
#endif

	if (node->ie_scn_mask & ISNS_SCN_TARGET_AND_SELF_ONLY_MASK) {
		if (node != scn->scn_owner && !(node_type & ISNS_ISCSI_TARGET_MASK))
			return 0;
	}
	if (node->ie_scn_mask & ISNS_SCN_INITIATOR_AND_SELF_ONLY_MASK) {
		if (node != scn->scn_owner && !(node_type & ISNS_ISCSI_INITIATOR_MASK))
			return 0;
	}

	return event;
}

/*
 * Helper to create time stamp attr
 */
static isns_attr_t *
isns_create_timestamp_attr(void)
{
	isns_value_t	value = ISNS_VALUE_INIT(uint64, time(NULL));

	return isns_attr_alloc(ISNS_TAG_TIMESTAMP, NULL, &value);
}

/*
 * This function is invoked whenever someone changes the
 * database.
 *
 * SCNs are another area where the RFC is fabulously wishy washy.
 * It is not entirely clear when DD/DDS information should be
 * included in a management SCN - one *reasonable* interpretation
 * would be that this happens for DDReg/DDDereg/DDSReg/DDSDereg
 * events only. But some sections make it sound as if DD
 * information is included for all management SCNs.
 */
void
isns_scn_callback(const isns_db_event_t *ev, void *ptr)
{
	isns_object_t	*obj = ev->ie_object;
	isns_scn_t	*scn, **pos;
	isns_attr_t	*timestamp;
	uint32_t	node_type;

	/* Never send out notifications for policy objects and the like. */
	if (obj->ie_flags & ISNS_OBJECT_PRIVATE)
		return;

	/* When an entity is nuked, remove all SCNs to nodes
	 * that registered from there */
	if (ISNS_IS_ENTITY(obj) && (ev->ie_bits & ISNS_SCN_OBJECT_REMOVED_MASK)) {
		pos = &isns_scn_list;
		while ((scn = *pos) != NULL) {
			if (scn->scn_entity != obj) {
				pos = &scn->scn_next;
				continue;
			}
			isns_debug_scn("Deleting SCN registration for %s\n",
					scn->scn_name);
			*pos = scn->scn_next;
			isns_scn_free(scn);
		}
		return;
	}

	/* For now we handle iSCSI nodes only. Maybe later we'll
	 * do iFC nodes as well. */
	if (!ISNS_IS_ISCSI_NODE(obj))
		return;
	if (!isns_object_get_uint32(obj, ISNS_TAG_ISCSI_NODE_TYPE, &node_type))
		return;

	if (ev->ie_recipient) {
		isns_object_t *dst = ev->ie_recipient;

		isns_debug_scn("SCN unicast <%s %u, %s> -> %s %u\n",
				obj->ie_template->iot_name, obj->ie_index,
				isns_event_string(ev->ie_bits),
				dst->ie_template->iot_name, dst->ie_index);
	} else {
		isns_debug_scn("SCN multicast <%s %u, %s>\n",
				obj->ie_template->iot_name, obj->ie_index,
				isns_event_string(ev->ie_bits));
	}
	timestamp = isns_create_timestamp_attr();

	pos = &isns_scn_list;
	while ((scn = *pos) != NULL) {
		unsigned int	scn_bits, management;
		isns_object_t	*recipient, *dd = NULL;
		isns_simple_t	*call;

		recipient = scn->scn_owner;

		/* Check if the node has gone away completely. */
		if (recipient->ie_scn_mask == 0) {
			*pos = scn->scn_next;
			isns_scn_free(scn);
			continue;
		}

		if (recipient->ie_container == NULL) {
			isns_warning("Internal bug - SCN recipient without container\n");
			/* Clear the bitmask and loop over - this will remove it */
			recipient->ie_scn_mask = 0;
			continue;
		}

		/* See if portals were added/removed.
		 * This does not catch updates that modified *just*
		 * the SCN port */
		if (recipient->ie_container->ie_mtime != scn->scn_last_update) {
			/* Rebuild the list of SCN portals */
			isns_scn_release_funnels(scn);
			scn->scn_last_update = 0;
		}
		pos = &scn->scn_next;

		/* Check for unicast events (triggered for DD addition/removal).
		 * For unicast events, we do not mask the SCN bits, so that
		 * clients who have registered for non-management events
		 * will see the membership events for their DDs nevertheless. */
		if (ev->ie_recipient == NULL) {
			scn_bits = ev->ie_bits & recipient->ie_scn_mask;
			if (scn_bits == 0)
				continue;
			/* Management SCNs should not be delivered to nodes
			 * that have not registered for them. */
			if ((ev->ie_bits & ISNS_SCN_MANAGEMENT_REGISTRATION_MASK)
			 && !(recipient->ie_scn_mask & ISNS_SCN_MANAGEMENT_REGISTRATION_MASK))
				continue;
		} else if (recipient == ev->ie_recipient) {
			scn_bits = ev->ie_bits;
		} else {
			/* No match, skip this recipient */
			continue;
		}

		if (scn->scn_last_update == 0) {
			scn->scn_last_update = recipient->ie_container->ie_mtime;
			isns_scn_setup(scn, recipient);
		}

		/* We check for SCN capable portals when processing
		 * the SCN registration. But the portals may go away
		 * in the meantime. */
		if (scn->scn_funnels == NULL)
			continue;

		/* Check SCN bitmask. This will modify the event bits. */
		scn_bits = isns_scn_match(scn, scn_bits, obj, node_type);
		if (scn_bits == 0)
			continue;
		management = !!(scn_bits & ISNS_SCN_MANAGEMENT_REGISTRATION_MASK);

		/*
		 * 2.2.3
		 * A regular SCN registration indicates that the
		 * Discovery Domain Service SHALL be used to control the
		 * distribution of SCN messages.  Receipt of regular
		 * SCNs is limited to the discovery domains in which
		 * the SCN-triggering event takes place.  Regular SCNs
		 * do not contain information about discovery domains.
		 *
		 * Implementer's note: We override check for unicast events.
		 * The reason is that DDDereg will sever the
		 * relationship, and we would never send an SCN for that
		 * event.
		 */
		if (!management && !ev->ie_recipient) {
			if (!isns_object_test_visibility(obj, recipient))
				continue;
		}

		isns_debug_scn("preparing to send SCN to %s\n",
				scn->scn_name);

		if ((call = scn->scn_message) == NULL) {
			call = isns_create_scn(isns_scn_server->is_source,
					scn->scn_attr,
					timestamp);
			if (call == NULL)
				continue;
			scn->scn_message = call;
		}

		/*
		 * If the SCN is a Management SCN, then the SCN message
		 * SHALL also list the DD_ID and/or DDS_ID of the
		 * Discovery Domains and Discovery Domain Sets (if any)
		 * that caused the change in state for that Storage Node.
		 * These additional attributes (i.e., DD_ID and/or DDS_ID)
		 * shall immediately follow the iSCSI Name or FC Port
		 * Name and precede the next SCN bitmap for the next
		 * notification message (if any).
		 */
		if (management && ev->ie_trigger)
			dd = ev->ie_trigger;

		isns_scn_add_event(call, scn_bits, obj, dd);

	}

	isns_attr_release(timestamp);
}

/*
 * Obtain a socket to talk to this guy.
 * Not entirely trivial - this can be both an established
 * (incoming) connection, or one that we should establish.
 *
 * Note, we do not support transmission on the incoming
 * connection yet.
 */
static isns_socket_t *
isns_scn_get_socket(isns_scn_t *scn)
{
	isns_scn_funnel_t *f, *best = NULL;
	isns_socket_t	*sock;
	unsigned int	worst = 0, loops = 0, nfunnels;

	/* Keep it simple for now */
	if ((f = scn->scn_current_funnel) != NULL && f->scn_socket) {
		if (!f->scn_bad)
			return f->scn_socket;
		/* Oops, we've seen timeouts on this socket. */
		isns_socket_free(f->scn_socket);
		f->scn_socket = NULL;
	}

again:
	nfunnels = 0;
	for (f = scn->scn_funnels; f; f = f->scn_next) {
		unsigned int	badness = f->scn_bad;

		if (!best || badness < best->scn_bad)
			best = f;
		if (badness > worst)
			worst = badness;
		nfunnels++;
	}

	if (!best)
		return NULL;

	sock = isns_connect_to_portal(&best->scn_portal);
	if (sock == NULL) {
		/* Make sure we try each funnel exactly once */
		best->scn_bad = worst + 1;
		if (++loops < nfunnels)
			goto again;
		return NULL;
	}

	/* Set the security context */
	isns_socket_set_security_ctx(sock,
			isns_default_security_context(1));

	isns_debug_scn("SCN: %s using portal %s\n",
			scn->scn_name,
			isns_portal_string(&best->scn_portal));
	scn->scn_current_funnel = best;
	best->scn_socket = sock;
	return sock;
}

/*
 * This is the callback function invoked when the SCN message reply
 * comes in, or when the message timed out.
 */
static void
isns_process_scn_response(uint32_t xid, int status, isns_simple_t *msg)
{
	isns_scn_t	*scn;

	if (msg == NULL) {
		isns_debug_scn("SCN timed out\n");
		return;
	}

	isns_debug_scn("Received an SCN response\n");
	for (scn = isns_scn_list; scn; scn = scn->scn_next) {
		if (scn->scn_pending && scn->scn_xid == xid) {
			isns_debug_scn("SCN: %s acknowledged notification\n",
					scn->scn_name);
			isns_simple_free(scn->scn_pending);
			scn->scn_pending = NULL;

			if (scn->scn_current_funnel)
				scn->scn_current_funnel->scn_bad = 0;
		}
	}
}
/*
 * Transmit all pending SCN messages
 *
 * 2.9.2
 * If a Network Entity has multiple Portals with registered SCN UDP Ports,
 * then SCN messages SHALL be delivered to each Portal registered to
 * receive such messages.
 *
 * FIXME: we should make this timer based just as the ESI code.
 */
time_t
isns_scn_transmit_all(void)
{
	time_t		now = time(NULL), next_timeout;
	isns_scn_t	*scn;

	for (scn = isns_scn_list; scn; scn = scn->scn_next) {
		isns_simple_t	*call;
		isns_socket_t	*sock;

		/* We do not allow more than one outstanding
		 * notification for now. */
		if ((call = scn->scn_pending) != NULL) {
			if (scn->scn_timeout > now)
				continue;
			scn->scn_current_funnel->scn_bad++;
			if (--(scn->scn_retries))
				goto retry;
			isns_warning("SCN for %s timed out\n",
					scn->scn_name);
			isns_simple_free(call);
			scn->scn_pending = NULL;
		}

		if ((call = scn->scn_message) == NULL)
			continue;

		isns_debug_scn("SCN: transmit pending message for %s\n",
				scn->scn_name);
		scn->scn_retries = isns_config.ic_scn_retries;
		scn->scn_pending = call;
		scn->scn_message = NULL;

retry:
		if ((sock = isns_scn_get_socket(scn)) == NULL) {
			/* Sorry, no can do. */
			isns_warning("SCN for %s dropped - no portal\n",
					scn->scn_name);
			scn->scn_pending = NULL;
			isns_simple_free(call);
			continue;
		}

		isns_simple_transmit(sock, call, NULL,
				isns_config.ic_scn_timeout,
				isns_process_scn_response);
		scn->scn_xid = call->is_xid;
		scn->scn_timeout = now + isns_config.ic_scn_timeout;
	}

	next_timeout = now + 3600;
	for (scn = isns_scn_list; scn; scn = scn->scn_next) {
		if (scn->scn_pending && scn->scn_timeout < next_timeout)
			next_timeout = scn->scn_timeout;
	}

	return next_timeout;
}

/*
 * Process an incoming State Change Notification
 */
int
isns_process_scn(isns_server_t *srv, isns_simple_t *call, isns_simple_t **reply)
{
	isns_attr_list_t *list = &call->is_message_attrs;
	isns_attr_t	*dstattr, *tsattr;
	const char	*dst_name;
	unsigned int	i;

	/* The first attribute is the destination, and should match
	 * our source name. Don't bother checking. The second is the
	 * time stamp. 
	 */
	if (list->ial_count < 2)
		goto rejected;

	dstattr = list->ial_data[0];
	if (dstattr->ia_tag_id != ISNS_TAG_ISCSI_NAME
	 && dstattr->ia_tag_id != ISNS_TAG_FC_PORT_NAME_WWPN)
		goto rejected;
	if (!ISNS_ATTR_IS_STRING(dstattr))
		goto rejected;
	dst_name = dstattr->ia_value.iv_string;

	tsattr = list->ial_data[1];
	if (tsattr->ia_tag_id != ISNS_TAG_TIMESTAMP)
		return ISNS_SCN_EVENT_REJECTED;

	for (i = 2; i < list->ial_count; ) {
		isns_object_template_t *tmpl;
		isns_attr_t	*bmattr, *srcattr;
		const char	*node_name;
		uint32_t	bitmap;

		if (i + 1 >= list->ial_count)
			goto rejected;

		bmattr = list->ial_data[i++];
		srcattr = list->ial_data[i++];

		/* Validate that bitmap and node type match */
		switch (bmattr->ia_tag_id) {
		case ISNS_TAG_ISCSI_SCN_BITMAP:
			if (srcattr->ia_tag_id != ISNS_TAG_ISCSI_NAME)
				goto rejected;
			tmpl = &isns_iscsi_node_template;
			break;

		case ISNS_TAG_IFCP_SCN_BITMAP:
			if (srcattr->ia_tag_id != ISNS_TAG_FC_PORT_NAME_WWPN)
				goto rejected;
			tmpl = &isns_fc_port_template;
			break;

		default:
			goto rejected;
		}

		/* Skip over and DD_ID or DDS_ID attrs */
		while (i < list->ial_count) {
			isns_attr_t *ddattr = list->ial_data[i];

			if (ddattr->ia_tag_id == ISNS_TAG_ISCSI_SCN_BITMAP
			 || ddattr->ia_tag_id == ISNS_TAG_IFCP_SCN_BITMAP)
				break;
			++i;
		}

		if (!ISNS_ATTR_IS_UINT32(bmattr))
			goto rejected;
		bitmap = bmattr->ia_value.iv_uint32;

		if (!ISNS_ATTR_IS_STRING(srcattr))
			goto rejected;
		node_name = srcattr->ia_value.iv_string;

		if (srv->is_scn_callback)
			srv->is_scn_callback(srv->is_db, bitmap, tmpl, node_name, dst_name);
	}

	/*
	 * 5.7.5.8.  SCN Response (SCNRsp)
	 * The SCNRsp response contains the SCN Destination Attribute
	 * representing the Node identifier that received the SCN.
	 */
	*reply = isns_create_scn(srv->is_source,
			list->ial_data[0],
			NULL);
	return ISNS_SUCCESS;

rejected:
	return ISNS_SCN_EVENT_REJECTED;
}
