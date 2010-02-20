/*
 * iSNS object callbacks for SCN and other stuff
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#include <stdlib.h>
#include <string.h>
#include "isns.h"
#include "objects.h"
#include "vendor.h"
#include "attrs.h"
#include "util.h"

typedef struct isns_object_notifier isns_object_notifier_t;
struct isns_object_notifier {
	isns_list_t		list;
	isns_db_callback_t *	func;
	void *			data;
};

typedef struct isns_cb_event isns_cb_event_t;
struct isns_cb_event {
	isns_list_t		list;
	isns_db_event_t		info;
};

static ISNS_LIST_DECLARE(notifiers);
static ISNS_LIST_DECLARE(events);

static inline void
__isns_db_event(isns_object_t *dst,
		isns_object_t *obj,
		unsigned int bits,
		isns_object_t *trigger)
{
	isns_cb_event_t *ev;
	
	ev = isns_calloc(1, sizeof(*ev));
	ev->info.ie_recipient = isns_object_get(dst);
	ev->info.ie_object = isns_object_get(obj);
	ev->info.ie_bits = bits;
	ev->info.ie_trigger = isns_object_get(trigger);
	isns_list_append(&events, &ev->list);
}

void
isns_object_event(isns_object_t *obj,
		unsigned int bits,
		isns_object_t *trigger)
{
	__isns_db_event(NULL, obj, bits, trigger);
}

void
isns_unicast_event(isns_object_t *dst,
		isns_object_t *obj,
		unsigned int bits,
		isns_object_t *trigger)
{
	__isns_db_event(dst, obj, bits, trigger);
}

/*
 * Given an object pair and an event bitmask,
 * invoke all callbacks
 */
static inline void
isns_call_callbacks(isns_db_event_t *ev)
{
	isns_object_t	*obj = ev->ie_object;
	isns_list_t	*pos, *next;

	ev->ie_bits |= obj->ie_scn_bits;
	if (ev->ie_bits == 0)
		return;
	isns_list_foreach(&notifiers, pos, next) {
		isns_object_notifier_t *not;

		not = isns_list_item(isns_object_notifier_t, list, pos);
		not->func(ev, not->data);
	}
	obj->ie_scn_bits = 0;
}

void
isns_flush_events(void)
{
	while (!isns_list_empty(&events)) {
		isns_cb_event_t *ev = isns_list_item(isns_cb_event_t, list, events.next);

		isns_call_callbacks(&ev->info);
		isns_object_release(ev->info.ie_recipient);
		isns_object_release(ev->info.ie_object);
		isns_object_release(ev->info.ie_trigger);
		isns_list_del(&ev->list);
		isns_free(ev);
	}
}

void
isns_register_callback(isns_db_callback_t *func,
				void *user_data)
{
	isns_object_notifier_t *not;

	not = isns_calloc(1, sizeof(*not));
	not->func = func;
	not->data = user_data;

	isns_list_append(&notifiers, &not->list);
}

const char *
isns_event_string(unsigned int bits)
{
	static const char *names[16] = {
	[ISNS_SCN_DD_MEMBER_ADDED]	= "member added",
	[ISNS_SCN_DD_MEMBER_REMOVED]	= "member removed",
	[ISNS_SCN_OBJECT_UPDATED]	= "updated",
	[ISNS_SCN_OBJECT_ADDED]		= "added",
	[ISNS_SCN_OBJECT_REMOVED]	= "removed",
	[ISNS_SCN_MANAGEMENT_REGISTRATION]= "mgmt registration",
	[ISNS_SCN_TARGET_AND_SELF_ONLY]	= "target+self",
	[ISNS_SCN_INITIATOR_AND_SELF_ONLY]= "initiator+self",
	};
	static char	buffer[128];
	unsigned int	pos = 0, i;


	for (i = 0; i < 16; ++i, bits >>= 1) {
		if (!(bits & 1))
			continue;

		if (names[i]) {
			snprintf(buffer + pos, sizeof(buffer) - pos,
				"%s%s", pos? ", " : "", names[i]);
		} else {
			snprintf(buffer + pos, sizeof(buffer) - pos,
				"%sevent %u", pos? ", " : "", i);
		}
		pos = strlen(buffer);
	}
	if (pos == 0)
		return "<no event>";

	return buffer;
}
