/*
 * iSNS object relationships
 *
 * Relations are used to express a connection between two
 * objects. Currently, two relationship types are implemented:
 *
 *  - portal group: this relates a storage node and a portal
 *  - visibility: this relates a nodes nodes that share a
 *	common discovery domain.
 *
 * Relation objects are nice for portals groups, but kind of
 * awkward for DDs. A better way of expressing DD membership
 * (which also allows for a fast visibility check) could be
 * to store a [bit] vector of DD IDs in each storage node.
 * A visibility check would amount to just doing the bitwise
 * AND of two vectors, and checking for NULL. The only thing
 * to take care of would be to make sure a DD object takes a
 * reference on its members (this is necessary so that objects
 * maintain their ID/name associations even when removed from
 * the database).
 *
 * Aug 22 2007 - changed DD code to use bit vectors. A lot
 *	of code in this file is now obsolete.
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>

#include "isns.h"
#include "objects.h"
#include "util.h"
#include "db.h"

struct isns_relation_soup {
	/* For now, use one plain list. For better
	 * scalability, we'll need a hash table or
	 * something similar later. */
	isns_relation_list_t	irs_data;
};

static void	isns_relation_list_append(isns_relation_list_t *,
			isns_relation_t *);
static int	isns_relation_list_remove(isns_relation_list_t *,
			isns_relation_t *);

isns_relation_soup_t *
isns_relation_soup_alloc(void)
{
	return isns_calloc(1, sizeof(isns_relation_soup_t));
}

void
isns_relation_add(isns_relation_soup_t *soup,
		isns_relation_t *rp)
{
	isns_relation_list_append(&soup->irs_data, rp);
}

isns_relation_t *
isns_relation_find_edge(isns_relation_soup_t *soup,
		const isns_object_t *left,
		const isns_object_t *right,
		unsigned int relation_type)
{
	isns_relation_list_t *list = &soup->irs_data;
	unsigned int	i;

	for (i = 0; i < list->irl_count; ++i) {
		isns_relation_t *rp = list->irl_data[i];

		if (rp->ir_type != relation_type)
			continue;
		if (rp->ir_subordinate[0].obj == left
		 && rp->ir_subordinate[1].obj == right)
			return rp;
		if (rp->ir_subordinate[0].obj == right
		 && rp->ir_subordinate[1].obj == left)
			return rp;
	}
	return NULL;
}

void
isns_relation_get_edge_objects(isns_relation_soup_t *soup,
		const isns_object_t *left,
		unsigned int relation_type,
		isns_object_list_t *result)
{
	isns_relation_list_t *list = &soup->irs_data;
	unsigned int	i;

	for (i = 0; i < list->irl_count; ++i) {
		isns_relation_t *rp = list->irl_data[i];

		if (rp->ir_type != relation_type)
			continue;
		if (rp->ir_object == NULL)
			continue;
		if (rp->ir_subordinate[0].obj == left
		 || rp->ir_subordinate[1].obj == left) {
			isns_object_list_append(result,
				rp->ir_object);
		}
	}
}



void
isns_relation_halfspace(isns_relation_soup_t *soup,
		const isns_object_t *left,
		unsigned int relation_type,
		isns_object_list_t *result)
{
	isns_relation_list_t *list = &soup->irs_data;
	unsigned int	i;

	for (i = 0; i < list->irl_count; ++i) {
		isns_relation_t *rp = list->irl_data[i];

		if (rp->ir_type != relation_type)
			continue;
		if (rp->ir_subordinate[0].obj == left) {
			isns_object_list_append(result,
				rp->ir_subordinate[1].obj);
		} else
		if (rp->ir_subordinate[1].obj == left) {
			isns_object_list_append(result,
				rp->ir_subordinate[0].obj);
		}
	}
}

int
isns_relation_exists(isns_relation_soup_t *soup,
		const isns_object_t *relating_object,
		const isns_object_t *left,
		const isns_object_t *right,
		unsigned int relation_type)
{
	isns_relation_list_t *list = &soup->irs_data;
	unsigned int	i;

	for (i = 0; i < list->irl_count; ++i) {
		isns_relation_t *rp = list->irl_data[i];

		if (rp->ir_type != relation_type)
			continue;
		if (rp->ir_object != relating_object)
			continue;
		if (rp->ir_subordinate[0].obj == left
		 && rp->ir_subordinate[1].obj == right)
			return 1;
		if (rp->ir_subordinate[0].obj == right
		 && rp->ir_subordinate[1].obj == left)
			return 1;
	}
	return 0;
}

isns_object_t *
isns_relation_get_other(const isns_relation_t *rp,
			const isns_object_t *this)
{
	if (rp->ir_subordinate[0].obj == this)
		return rp->ir_subordinate[1].obj;
	if (rp->ir_subordinate[1].obj == this)
		return rp->ir_subordinate[0].obj;
	return NULL;
}

void
isns_relation_remove(isns_relation_soup_t *soup,
		isns_relation_t *rp)
{
	isns_object_release(rp->ir_object);
	rp->ir_object = NULL;

	isns_relation_list_remove(&soup->irs_data, rp);
}

isns_relation_t *
isns_create_relation(isns_object_t *relating_object,
		unsigned int relation_type,
		isns_object_t *subordinate_object1,
		isns_object_t *subordinate_object2)
{
	isns_relation_t *rp;
	
	rp = isns_calloc(1, sizeof(*rp));
	rp->ir_type = relation_type;
	rp->ir_users = 1;
	rp->ir_object = isns_object_get(relating_object);
	isns_object_reference_set(&rp->ir_subordinate[0], subordinate_object1);
	isns_object_reference_set(&rp->ir_subordinate[1], subordinate_object2);

#if 0
	if (relating_object) {
		relating_object->ie_relation = rp;
		rp->ir_users++;
	}
#endif

	return rp;
}

void
isns_relation_sever(isns_relation_t *rp)
{
	isns_object_release(rp->ir_object);
	rp->ir_object = NULL;

	isns_object_reference_drop(&rp->ir_subordinate[0]);
	isns_object_reference_drop(&rp->ir_subordinate[1]);
}

void
isns_relation_release(isns_relation_t *rp)
{
	if (--(rp->ir_users))
		return;

	isns_relation_sever(rp);
	isns_free(rp);
}

/*
 * Check whether the relation references two dead/limbo objects.
 * This is used for dead PG removal.
 */
int
isns_relation_is_dead(const isns_relation_t *rel)
{
	isns_object_t	*left, *right;

	left = rel->ir_subordinate[0].obj;
	right = rel->ir_subordinate[1].obj;
	if ((left->ie_flags & ISNS_OBJECT_DEAD)
	 && (right->ie_flags & ISNS_OBJECT_DEAD))
		return 1;

	return 0;
}

void
isns_relation_list_append(isns_relation_list_t *list,
			isns_relation_t *rp)
{
	if ((list->irl_count % 128) == 0) {
		list->irl_data = isns_realloc(list->irl_data,
				(list->irl_count + 128) * sizeof(void *));
		if (list->irl_data == NULL)
			isns_fatal("out of memory!\n");
	}

	list->irl_data[list->irl_count++] = rp;
	rp->ir_users++;
}

int
isns_relation_list_remove(isns_relation_list_t *list,
			isns_relation_t *rp)
{
	unsigned int	i, count = list->irl_count;

	for (i = 0; i < count; ++i) {
		if (list->irl_data[i] != rp)
			continue;
		if (i < count - 1)
			list->irl_data[i] = list->irl_data[count-1];
		isns_relation_release(rp);
		list->irl_count -= 1;
		return 1;
	}

	return 0;
}
