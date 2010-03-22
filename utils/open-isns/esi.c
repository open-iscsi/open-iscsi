/*
 * Handle ESI events
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

#define ESI_RETRANS_TIMEOUT	60

typedef struct isns_esi isns_esi_t;
typedef struct isns_esi_portal isns_esi_portal_t;

struct isns_esi {
	isns_list_t		esi_list;
	isns_object_t *		esi_object;
	isns_list_t		esi_portals;

	unsigned int		esi_update : 1;
};

struct isns_esi_portal {
	isns_list_t		esp_list;
	isns_object_t *		esp_object;
	isns_portal_info_t	esp_portal;
	unsigned int		esp_interval;
	isns_portal_info_t	esp_dest;

	isns_socket_t *		esp_socket;
	unsigned int		esp_retries;
	unsigned int		esp_timeout;
	time_t			esp_start;
	time_t			esp_next_xmit;
	uint32_t		esp_xid;
};

int			isns_esi_enabled = 0;
static isns_server_t *	isns_esi_server = NULL;
static ISNS_LIST_DECLARE(isns_esi_list);

static void		isns_esi_transmit(void *);
static void		isns_esi_sendto(isns_esi_t *, isns_esi_portal_t *);
static void		isns_process_esi_response(uint32_t, int,
						  isns_simple_t *);
static void		isns_esi_disconnect(isns_esi_portal_t *);
static void		isns_esi_restart(isns_esi_portal_t *);
static void		isns_esi_drop_portal(isns_esi_portal_t *, isns_db_t *, int);
static void		isns_esi_drop_entity(isns_esi_t *, isns_db_t *, int);
static int		isns_esi_update(isns_esi_t *);
static void		isns_esi_schedule(int);
static void		isns_esi_callback(const isns_db_event_t *, void *);

void
isns_esi_init(isns_server_t *srv)
{
	if (isns_config.ic_esi_retries == 0) {
		isns_debug_esi("ESI disabled by administrator\n");
	} else {
		unsigned int	max_interval;

		isns_register_callback(isns_esi_callback, NULL);
		isns_esi_schedule(0);

		max_interval = isns_config.ic_registration_period / 2;
		if (isns_config.ic_esi_max_interval > max_interval) {
			isns_warning("Max ESI interval adjusted to %u sec "
					"to match registration period\n",
					max_interval);
			isns_config.ic_esi_max_interval = max_interval;
			if (isns_config.ic_esi_min_interval > max_interval)
				isns_config.ic_esi_min_interval = max_interval;
		}
		isns_esi_server = srv;
		isns_esi_enabled = 1;
	}
}

/*
 * Timer callback to send out ESI messages.
 */
void
isns_esi_transmit(void *ptr)
{
	isns_db_t	*db = isns_esi_server->is_db;
	isns_list_t	*esi_pos, *esi_next;
	time_t		now;
	isns_object_t	*obj;
	time_t		next_timeout;

	now = time(NULL);
	next_timeout = now + 3600;

	isns_list_foreach(&isns_esi_list, esi_pos, esi_next) {
		isns_list_t	*esp_pos, *esp_next;
		isns_esi_t	*esi = isns_list_item(isns_esi_t, esi_list, esi_pos);

		if (esi->esi_update) {
			esi->esi_update = 0;
			if (!isns_esi_update(esi))
				continue;
		}

		isns_list_foreach(&esi->esi_portals, esp_pos, esp_next) {
			isns_esi_portal_t *esp = isns_list_item(isns_esi_portal_t,
							esp_list, esp_pos);

			/* Check whether the portal object still exist */
			obj = esp->esp_object;
			if (obj->ie_state != ISNS_OBJECT_STATE_MATURE) {
				isns_esi_drop_portal(esp, db, 0);
				continue;
			}

			if (esp->esp_next_xmit <= now) {
				if (esp->esp_retries == 0) {
					isns_debug_esi("No ESI response from %s - dropping\n",
							isns_portal_string(&esp->esp_dest));
					isns_esi_drop_portal(esp, db, 1);
					continue;
				}

				esp->esp_retries -= 1;
				esp->esp_next_xmit = now + esp->esp_timeout;
				isns_esi_sendto(esi, esp);
			}
			if (esp->esp_next_xmit < next_timeout)
				next_timeout = esp->esp_next_xmit;
		}

		if (isns_list_empty(&esi->esi_portals))
			isns_esi_drop_entity(esi, db, 1);
	}

	isns_debug_esi("Next ESI message in %d seconds\n", next_timeout - now);
	isns_esi_schedule(next_timeout - now);
}

/*
 * Send an ESI message
 */
void
isns_esi_sendto(isns_esi_t *esi, isns_esi_portal_t *esp)
{
	isns_attr_list_t attrs = ISNS_ATTR_LIST_INIT;
	isns_socket_t	*sock;
	isns_simple_t	*msg;

	/* For TCP portals, kill the TCP socket every time. */
	if (esp->esp_dest.proto == IPPROTO_TCP)
		isns_esi_disconnect(esp);

	if (esp->esp_socket == NULL) {
		sock = isns_connect_to_portal(&esp->esp_dest);
		if (sock == NULL)
			return;

		isns_socket_set_security_ctx(sock,
			isns_default_security_context(0));
		/* sock->is_disconnect_fatal = 1; */
		esp->esp_socket = sock;
	}

	isns_attr_list_append_uint64(&attrs,
				ISNS_TAG_TIMESTAMP,
				time(NULL));
	/* The following will extract the ENTITY IDENTIFIER */
	isns_object_extract_keys(esi->esi_object, &attrs);
	isns_portal_to_attr_list(&esp->esp_portal,
				ISNS_TAG_PORTAL_IP_ADDRESS,
				ISNS_TAG_PORTAL_TCP_UDP_PORT,
				&attrs);

	msg = isns_simple_create(ISNS_ENTITY_STATUS_INQUIRY,
					NULL, &attrs);
	if (msg == NULL)
		return;

	isns_debug_esi("*** Sending ESI message to %s (xid=0x%x); %u retries left\n",
			isns_portal_string(&esp->esp_dest),
			msg->is_xid, esp->esp_retries);
	isns_simple_transmit(esp->esp_socket, msg,
			NULL, esp->esp_timeout - 1,
			isns_process_esi_response);
	esp->esp_xid = msg->is_xid;
	isns_simple_free(msg);
}

/*
 * A new entity was added. See if it uses ESI, and create
 * portals and such.
 */
static void
isns_esi_add_entity(isns_object_t *obj)
{
	isns_esi_t	*esi;

	isns_debug_esi("Enable ESI monitoring for entity %u\n", obj->ie_index);
	esi = isns_calloc(1, sizeof(*esi));
	esi->esi_object = isns_object_get(obj);
	esi->esi_update = 1;
	isns_list_init(&esi->esi_list);
	isns_list_init(&esi->esi_portals);

	isns_list_append(&isns_esi_list, &esi->esi_list);
}

/*
 * Given an entity, see if we can find ESI state for it.
 */
static isns_esi_t *
isns_esi_find(isns_object_t *obj)
{
	isns_list_t	*pos, *next;

	isns_list_foreach(&isns_esi_list, pos, next) {
		isns_esi_t	*esi = isns_list_item(isns_esi_t, esi_list, pos);

		if (esi->esi_object == obj)
			return esi;
	}
	return NULL;
}

/*
 * Update the ESI state after an entity has changed
 */
static int
isns_esi_update(isns_esi_t *esi)
{
	isns_object_t	*entity = esi->esi_object;
	ISNS_LIST_DECLARE(hold);
	isns_esi_portal_t *esp;
	unsigned int	i;

	isns_debug_esi("Updating ESI state for entity %u\n", entity->ie_index);

	isns_list_move(&hold, &esi->esi_portals);
	for (i = 0; i < entity->ie_children.iol_count; ++i) {
		isns_object_t	*child = entity->ie_children.iol_data[i];
		isns_portal_info_t esi_portal, portal_info;
		uint32_t	esi_interval;
		isns_list_t	*pos, *next;
		int		changed = 0;

		if (!ISNS_IS_PORTAL(child))
			continue;

		if (!isns_portal_from_object(&portal_info,
					ISNS_TAG_PORTAL_IP_ADDRESS,
					ISNS_TAG_PORTAL_TCP_UDP_PORT,
					child)
		 || !isns_portal_from_object(&esi_portal,
					ISNS_TAG_PORTAL_IP_ADDRESS,
					ISNS_TAG_ESI_PORT,
					child)
		 || !isns_object_get_uint32(child,
					ISNS_TAG_ESI_INTERVAL,
					&esi_interval))
			continue;

		isns_list_foreach(&hold, pos, next) {
			esp = isns_list_item(isns_esi_portal_t, esp_list, pos);

			if (esp->esp_object == child) {
				isns_debug_esi("Updating ESI state for %s\n",
						isns_portal_string(&portal_info));
				isns_list_del(&esp->esp_list);
				goto update;
			}
		}

		isns_debug_esi("Creating ESI state for %s\n",
				isns_portal_string(&portal_info));
		esp = isns_calloc(1, sizeof(*esp));
		esp->esp_object = isns_object_get(child);
		isns_list_init(&esp->esp_list);
		changed = 1;

update:
		if (!isns_portal_equal(&esp->esp_portal, &portal_info)) {
			esp->esp_portal = portal_info;
			changed++;
		}
		if (!isns_portal_equal(&esp->esp_dest, &esi_portal)) {
			isns_esi_disconnect(esp);
			esp->esp_dest = esi_portal;
			changed++;
		}
		if (esp->esp_interval != esi_interval) {
			esp->esp_interval = esi_interval;
			changed++;
		}

		isns_esi_restart(esp);

		isns_list_append(&esi->esi_portals, &esp->esp_list);
	}

	/* Destroy any old ESI portals */
	while (!isns_list_empty(&hold)) {
		esp = isns_list_item(isns_esi_portal_t, esp_list, hold.next);

		isns_esi_drop_portal(esp, NULL, 0);
	}

	/* If the client explicitly unregistered all ESI portals,
	 * stop monitoring it but *without* destroying the entity. */
	if (isns_list_empty(&esi->esi_portals)) {
		isns_esi_drop_entity(esi, NULL, 0);
		return 0;
	}

	return 1;
}

void
isns_esi_restart(isns_esi_portal_t *esp)
{
	unsigned int	timeo;

	isns_esi_disconnect(esp);

	esp->esp_start = time(NULL);
	esp->esp_retries = isns_config.ic_esi_retries;
	esp->esp_next_xmit = esp->esp_start + esp->esp_interval;
	esp->esp_xid = 0;

	timeo = esp->esp_interval / esp->esp_retries;
	if (timeo == 0)
		timeo = 1;
	else if (timeo > ESI_RETRANS_TIMEOUT)
		timeo = ESI_RETRANS_TIMEOUT;
	esp->esp_timeout = timeo;
}

void
isns_esi_disconnect(isns_esi_portal_t *esp)
{
	if (esp->esp_socket)
		isns_socket_free(esp->esp_socket);
	esp->esp_socket = NULL;
}

/*
 * Generic wrapper to dropping an object
 */
static inline void
__isns_esi_drop_object(isns_db_t *db, isns_object_t *obj, unsigned int dead)
{
	if (db && obj && obj->ie_state == ISNS_OBJECT_STATE_MATURE && dead)
		isns_db_remove(db, obj);
	isns_object_release(obj);
}

/*
 * Portal did not respond in time. Drop it
 */
void
isns_esi_drop_portal(isns_esi_portal_t *esp, isns_db_t *db, int dead)
{
	isns_debug_esi("ESI: dropping portal %s\n",
			isns_portal_string(&esp->esp_portal));

	isns_list_del(&esp->esp_list);
	isns_esi_disconnect(esp);
	__isns_esi_drop_object(db, esp->esp_object, dead);
	isns_free(esp);
}

/*
 * We ran out of ESI portals for this entity.
 */
void
isns_esi_drop_entity(isns_esi_t *esi, isns_db_t *db, int dead)
{
	isns_debug_esi("ESI: dropping entity %u\n",
			esi->esi_object->ie_index);

	isns_list_del(&esi->esi_list);
	__isns_esi_drop_object(db, esi->esi_object, dead);

	while (!isns_list_empty(&esi->esi_portals)) {
		isns_esi_portal_t *esp;

		esp = isns_list_item(isns_esi_portal_t, esp_list,
				esi->esi_portals.next);
		isns_esi_drop_portal(esp, db, dead);
	}
	isns_free(esi);
}

/*
 * When receiving an ESI response, find the portal we sent the
 * original message to.
 */
static isns_esi_portal_t *
isns_esi_get_msg_portal(uint32_t xid, isns_esi_t **esip)
{
	isns_list_t	*esi_pos, *esi_next;

	isns_list_foreach(&isns_esi_list, esi_pos, esi_next) {
		isns_esi_t	*esi = isns_list_item(isns_esi_t, esi_list, esi_pos);
		isns_list_t	*esp_pos, *esp_next;

		isns_list_foreach(&esi->esi_portals, esp_pos, esp_next) {
			isns_esi_portal_t *esp = isns_list_item(isns_esi_portal_t,
							esp_list, esp_pos);

			if (esp->esp_xid == xid) {
				*esip = esi;
				return esp;
			}
		}
	}

	return NULL;
}

/*
 * Handle incoming ESI request
 */
int
isns_process_esi(isns_server_t *srv, isns_simple_t *call, isns_simple_t **reply)
{
	const isns_attr_list_t *attrs = &call->is_message_attrs;
	isns_object_t	*portal = NULL;

	/* We just echo back the attributes sent to us by the server,
	 * without further checking. */
	*reply = isns_simple_create(ISNS_ENTITY_STATUS_INQUIRY,
				srv->is_source, attrs);

	/* Look up the portal and update its mtime.
	 * This can help the application find out if a portal has
	 * seen ESIs recently, and react.
	 */
	if (srv->is_db && attrs->ial_count == 4) {
		const isns_attr_t	*addr_attr, *port_attr;

		addr_attr = attrs->ial_data[2];
		port_attr = attrs->ial_data[3];
		if (addr_attr->ia_tag_id == ISNS_TAG_PORTAL_IP_ADDRESS
		 && port_attr->ia_tag_id == ISNS_TAG_PORTAL_TCP_UDP_PORT) {
			isns_attr_list_t key;

			key.ial_count = 2;
			key.ial_data = attrs->ial_data + 2;
			portal = isns_db_lookup(srv->is_db,
					&isns_portal_template,
					&key);
		}

		if (portal)
			portal->ie_mtime = time(NULL);
	}
	return ISNS_SUCCESS;
}

void
isns_process_esi_response(uint32_t xid, int status, isns_simple_t *msg)
{
	isns_portal_info_t	portal_info;
	isns_esi_portal_t	*esp;
	isns_esi_t		*esi;

	if (msg == NULL) {
		isns_debug_esi("ESI call 0x%x timed out\n", xid);
		return;
	}

	/* FIXME: As a matter of security, we should probably
	 * verify that the ESI response originated from the
	 * portal we sent it to; or at least that it was authenticated
	 * by the client we think we're talking to. */

	/* Get the portal */
	if (!isns_portal_from_attr_list(&portal_info,
				ISNS_TAG_PORTAL_IP_ADDRESS,
				ISNS_TAG_PORTAL_TCP_UDP_PORT,
				&msg->is_message_attrs)) {
		isns_debug_esi("Ignoring unintelligible ESI response\n");
		return;
	}

	if (!(esp = isns_esi_get_msg_portal(xid, &esi))) {
		isns_debug_esi("Ignoring unmatched ESI reply\n");
		return;
	}

	if (!isns_portal_equal(&esp->esp_portal, &portal_info)) {
		isns_warning("Faked ESI response for portal %s\n",
				isns_portal_string(&portal_info));
		return;
	}

	isns_debug_esi("Good ESI response from %s\n",
				isns_portal_string(&portal_info));
	isns_esi_restart(esp);

	/* Refresh the entity's registration timestamp */
	isns_object_set_uint64(esi->esi_object,
			ISNS_TAG_TIMESTAMP,
			time(NULL));
	isns_db_sync(isns_esi_server->is_db);
}

/*
 * Helper function to schedule the next timeout
 */
static void
isns_esi_schedule(int timeout)
{
	isns_cancel_timer(isns_esi_transmit, NULL);
	isns_add_oneshot_timer(timeout, isns_esi_transmit, NULL);
}

/*
 * Register an entity for ESI monitoring.
 * This is called when reloading the database.
 */
void
isns_esi_register(isns_object_t *obj)
{
	if (!isns_esi_find(obj))
		isns_esi_add_entity(obj);
	/* We do not call esi_schedule(0) here; that happens in
	 * isns_esi_init already. */
}

/*
 * This callback is invoked whenever an object is added/removed/modified.
 * We use this to keep track of ESI portals and such.
 */
void
isns_esi_callback(const isns_db_event_t *ev, void *ptr)
{
	isns_object_t	*obj, *entity;
	isns_esi_t	*esi;
	uint32_t	event;

	obj = ev->ie_object;
	event = ev->ie_bits;

	if (obj->ie_flags & ISNS_OBJECT_PRIVATE)
		return;

	isns_debug_esi("isns_esi_callback(%p, 0x%x)\n", obj, event);

	if (ISNS_IS_ENTITY(obj)
	 && (event & ISNS_SCN_OBJECT_ADDED_MASK)) {
		if (!isns_esi_find(obj))
			isns_esi_add_entity(obj);
		/* Schedule an immediate ESI timer run */
		isns_esi_schedule(0);
		return;
	}

	if (!(entity = isns_object_get_entity(obj)))
		return;

	esi = isns_esi_find(entity);
	if (esi != NULL)
		esi->esi_update = 1;

	/* Schedule an immediate ESI timer run */
	isns_esi_schedule(0);
}
