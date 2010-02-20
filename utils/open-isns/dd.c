/*
 * Handle DD registration/deregistration
 *
 * Discovery domains are weird, even in the context of
 * iSNS. For once thing, all other objects have unique
 * attributes; DDs attributes can appear several times.
 * They should really have made each DD member an object
 * in its own right.
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

#define DD_DEBUG

enum {
	ISNS_DD_MEMBER_ISCSI_NODE = 1,
	ISNS_DD_MEMBER_IFCP_NODE,
	ISNS_DD_MEMBER_PORTAL,
};
/* Must be zero/one: */
enum {
	NOTIFY_MEMBER_ADDED = 0,
	NOTIFY_MEMBER_REMOVED = 1
};

typedef struct isns_dd isns_dd_t;
typedef struct isns_dd_list isns_dd_list_t;
typedef struct isns_dd_member isns_dd_member_t;

struct isns_dd {
	uint32_t		dd_id;
	char *			dd_name;
	uint32_t		dd_features;
	isns_dd_member_t *	dd_members;

	unsigned int		dd_inserted : 1;

	isns_object_t *		dd_object;
};

struct isns_dd_member {
	isns_dd_member_t *	ddm_next;
	unsigned int		ddm_type;
	isns_object_ref_t	ddm_object;

	unsigned int		ddm_added : 1;
	union {
	    uint32_t		ddm_index;

	    /* Index must be first in all structs below.
	     * Yeah, I know. Aliasing is bad. */
	    struct isns_dd_portal {
		uint32_t	index;
	        isns_portal_info_t info;
	    } ddm_portal;
	    struct isns_dd_iscsi_node {
		uint32_t	index;
		char *		name;
	    } ddm_iscsi_node;
	    struct isns_dd_ifcp_node {
		uint32_t	index;
		char *		name;
	    } ddm_ifcp_node;
	};
};

struct isns_dd_list {
	unsigned int		ddl_count;
	isns_dd_t **		ddl_data;
};

/*
 * List of all discovery domains.
 * This duplicates the DD information from the database,
 * but unfortunately this can't be helped - we need to
 * have fast algorithms to compute the membership of a
 * node, and the relative visibility of two nodes.
 */
static int			isns_dd_list_initialized = 0;
static isns_dd_list_t		isns_dd_list;
static uint32_t			isns_dd_next_id = 1;

static isns_dd_t *		isns_dd_alloc(void);
static isns_dd_t *		isns_dd_clone(const isns_dd_t *);
static void			isns_dd_release(isns_dd_t *);
static int			isns_dd_parse_attrs(isns_dd_t *,
					isns_db_t *, const isns_attr_list_t *,
					const isns_dd_t *, int);
static int			isns_dd_remove_members(isns_dd_t *,
					isns_db_t *,
					isns_dd_t *);
static void			isns_dd_notify(const isns_dd_t *,
					isns_dd_member_t *,
					isns_dd_member_t *,
					int);
static void			isns_dd_add_members(isns_dd_t *,
					isns_db_t *,
					isns_dd_t *);
static void			isns_dd_store(isns_db_t *, const isns_dd_t *, int);
static void			isns_dd_destroy(isns_db_t *, isns_dd_t *);
static void			isns_dd_insert(isns_dd_t *);
static isns_dd_t *		isns_dd_by_id(uint32_t);
static isns_dd_t *		isns_dd_by_name(const char *);
static isns_dd_member_t *	isns_dd_create_member(isns_object_t *);
static inline void		isns_dd_member_free(isns_dd_member_t *);
static int			isns_dd_remove_member(isns_dd_t *, isns_object_t *);
static void			isns_dd_list_resize(isns_dd_list_t *, unsigned int);
static void			isns_dd_list_insert(isns_dd_list_t *, isns_dd_t *);
static void			isns_dd_list_remove(isns_dd_list_t *, isns_dd_t *);

static isns_object_t *		isns_dd_get_member_object(isns_db_t *,
					const isns_attr_t *, const isns_attr_t *,
					int);

/*
 * Create DDReg messages
 */
isns_simple_t *
isns_create_dd_registration(isns_client_t *clnt, const isns_attr_list_t *attrs)
{
	isns_simple_t	*msg;
	isns_attr_t	*id_attr;

	msg = isns_simple_create(ISNS_DD_REGISTER, clnt->ic_source, NULL);
	if (msg == NULL)
		return NULL;

	/* If the caller specified a DD_ID, use it in the
	 * message key. */
	if (isns_attr_list_get_attr(attrs, ISNS_TAG_DD_ID, &id_attr))
		isns_attr_list_append_attr(&msg->is_message_attrs, id_attr);

	isns_attr_list_copy(&msg->is_operating_attrs, attrs);
	return msg;
}

isns_simple_t *
isns_create_dd_deregistration(isns_client_t *clnt,
		uint32_t dd_id, const isns_attr_list_t *attrs)
{
	isns_simple_t	*msg;

	msg = isns_simple_create(ISNS_DD_DEREGISTER, clnt->ic_source, NULL);
	if (msg == NULL)
		return NULL;

	isns_attr_list_append_uint32(&msg->is_message_attrs,
			ISNS_TAG_DD_ID, dd_id);

	isns_attr_list_copy(&msg->is_operating_attrs, attrs);
	return msg;
}

/*
 * Process a DD registration
 */
int
isns_process_dd_registration(isns_server_t *srv, isns_simple_t *call, isns_simple_t **result)
{
	isns_simple_t	*reply = NULL;
	isns_attr_list_t *keys = &call->is_message_attrs;
	isns_attr_list_t *attrs = &call->is_operating_attrs;
	isns_db_t	*db = srv->is_db;
	isns_dd_t	*dd = NULL, *temp_dd = NULL;
	isns_attr_t	*attr;
	uint32_t	id = 0;
	int		status;

	/*
	 * 5.6.5.9.
	 * The Message Key, if used, contains the DD_ID of the Discovery
	 * Domain to be registered.  If the Message Key contains a DD_ID
	 * of an existing DD entry in the iSNS database, then the DDReg
	 * message SHALL attempt to update the existing entry.	If the
	 * DD_ID in the Message Key (if used) does not match an existing
	 * DD entry, then the iSNS server SHALL reject the DDReg message
	 * with a status code of 3 (Invalid Registration).
	 */
	switch (keys->ial_count) {
	case 0:
		/* Security: check if the client is allowed to
		 * create a discovery domain */
		if (!isns_policy_validate_object_creation(call->is_policy,
					call->is_source,
					&isns_dd_template,
					keys, attrs,
					call->is_function))
			goto unauthorized;
		break;

	case 1:
		attr = keys->ial_data[0];
		if (attr->ia_tag_id != ISNS_TAG_DD_ID)
			goto reject;
		if (ISNS_ATTR_IS_NIL(attr))
			break;
		if (!ISNS_ATTR_IS_UINT32(attr))
			goto reject;

		id = attr->ia_value.iv_uint32;
		if (id == 0)
			goto reject;

		dd = isns_dd_by_id(id);
		if (dd == NULL) {
			isns_debug_state("DDReg for unknown ID=%u\n", id);
			goto reject;
		}

		/* Security: check if the client is allowed to
		 * mess with this DD. */
		isns_assert(dd->dd_object);
		if (!isns_policy_validate_object_update(call->is_policy,
					call->is_source,
					dd->dd_object, attrs,
					call->is_function))
			goto unauthorized;

		break;

	default:
		goto reject;
	}

	temp_dd = isns_dd_alloc();

	/* Parse the attributes and build a DD object. */
	status = isns_dd_parse_attrs(temp_dd, db, attrs, dd, 1);
	if (status != ISNS_SUCCESS)
		goto out;

	if (dd == NULL) {
		/* Create the DD, and copy the general information
		 * such asn features and symbolic name from temp_dd */
		dd = isns_dd_clone(temp_dd);

		/* Don't assign the attrs to the DD right away.
		 * First and foremost, they may be unsorted. Second,
		 * we really want to hand-pick through them due to
		 * the weird semantics mandated by the RFC. */
		dd->dd_object = isns_create_object(&isns_dd_template, NULL, NULL);
		if (dd->dd_object == NULL)
			goto reject;

		/* Insert new domain into database */
		isns_db_insert(db, dd->dd_object);

		/* Add it to the internal list. Assign DD_ID and
		 * symbolic name if none were given.
		 */
		isns_dd_insert(dd);
	} else {
		if (!dd->dd_id)
			dd->dd_id = temp_dd->dd_id;
		dd->dd_features = temp_dd->dd_features;
		isns_assign_string(&dd->dd_name, temp_dd->dd_name);
	}

	/* Send notifications. This must be done before merging
	 * the list of new members into the DD. 
	 */
	isns_dd_notify(dd, dd->dd_members, temp_dd->dd_members,
			NOTIFY_MEMBER_ADDED);

	/* Update the DD */
	isns_dd_add_members(dd, db, temp_dd);

	/* And add it to the database. */
	isns_dd_store(db, dd, 0);

	reply = isns_simple_create(ISNS_DD_REGISTER, srv->is_source, NULL);
	isns_object_extract_all(dd->dd_object, &reply->is_operating_attrs);

	status = ISNS_SUCCESS;

out:
	isns_dd_release(temp_dd);
	isns_dd_release(dd);
	*result = reply;
	return status;

reject:
	status = ISNS_INVALID_REGISTRATION;
	goto out;

unauthorized:
	status = ISNS_SOURCE_UNAUTHORIZED;
	goto out;
}

/*
 * Process a DD deregistration
 */
int
isns_process_dd_deregistration(isns_server_t *srv, isns_simple_t *call, isns_simple_t **result)
{
	isns_simple_t	*reply = NULL;
	isns_attr_list_t *keys = &call->is_message_attrs;
	isns_attr_list_t *attrs = &call->is_operating_attrs;
	isns_db_t	*db = srv->is_db;
	isns_dd_t	*dd = NULL, *temp_dd = NULL;
	isns_attr_t	*attr;
	uint32_t	id = 0;
	int		status;

	/*
	 * 5.6.5.10.
	 * The Message Key Attribute for a DDDereg message is the DD
	 * ID for the Discovery Domain being removed or having members
	 * removed.
	 */
	if (keys->ial_count != 1)
		goto reject;

	attr = keys->ial_data[0];
	if (attr->ia_tag_id != ISNS_TAG_DD_ID
	 || ISNS_ATTR_IS_NIL(attr)
	 || !ISNS_ATTR_IS_UINT32(attr))
		goto reject;

	id = attr->ia_value.iv_uint32;
	if (id == 0)
		goto reject;

	dd = isns_dd_by_id(id);
	if (dd == NULL)
		goto reject;

	/* Security: check if the client is permitted to
	 * modify the DD object.
	 */
	if (!isns_policy_validate_object_update(call->is_policy,
				call->is_source,
				dd->dd_object, attrs,
				call->is_function))
		goto unauthorized;

	/* 
	 * 5.6.5.10.
	 * If the DD ID matches an existing DD and there are
	 * no Operating Attributes, then the DD SHALL be removed and a
	 * success Status Code returned.  Any existing members of that
	 * DD SHALL remain in the iSNS database without membership in
	 * the just-removed DD.
	 */
	if (attrs->ial_count == 0) {
		isns_dd_member_t	*mp;

		/* Zap the membership bit */
		for (mp = dd->dd_members; mp; mp = mp->ddm_next) {
			isns_object_t	*obj = mp->ddm_object.obj;

			isns_object_clear_membership(obj, dd->dd_id);
		}

		/* Notify all DD members that they will lose the other
		 * nodes. */
		isns_dd_notify(dd, NULL, dd->dd_members, NOTIFY_MEMBER_REMOVED);

		isns_dd_destroy(db, dd);
	} else {
		/* Parse the attributes and build a temporary DD object. */
		temp_dd = isns_dd_alloc();
		status = isns_dd_parse_attrs(temp_dd, db, attrs, dd, 0);
		if (status != ISNS_SUCCESS)
			goto out;

		/* Update the DD object */
		status = isns_dd_remove_members(dd, db, temp_dd);
		if (status != ISNS_SUCCESS)
			goto out;

		/* Send notifications. This must be done before after
		 * updating the DD.
		 */
		isns_dd_notify(dd, dd->dd_members, temp_dd->dd_members,
				NOTIFY_MEMBER_REMOVED);

		/* Store it in the database. */
		isns_dd_store(db, dd, 1);
	}

	reply = isns_simple_create(ISNS_DD_DEREGISTER, srv->is_source, NULL);
	status = ISNS_SUCCESS;

out:
	isns_dd_release(temp_dd);
	isns_dd_release(dd);
	*result = reply;
	return status;

reject:
	status = ISNS_INVALID_DEREGISTRATION;
	goto out;

unauthorized:
	status = ISNS_SOURCE_UNAUTHORIZED;
	goto out;
}

static isns_dd_t *
isns_dd_alloc(void)
{
	return isns_calloc(1, sizeof(isns_dd_t));
}

/*
 * Allocate a clone of the orig_dd, but without
 * copying the members.
 */
static isns_dd_t *
isns_dd_clone(const isns_dd_t *orig_dd)
{
	isns_dd_t	*dd;

	dd = isns_dd_alloc();

	dd->dd_id = orig_dd->dd_id;
	dd->dd_features = orig_dd->dd_features;
	dd->dd_object = isns_object_get(orig_dd->dd_object);
	isns_assign_string(&dd->dd_name, orig_dd->dd_name);

	return dd;
}

static void
isns_dd_release(isns_dd_t *dd)
{
	isns_dd_member_t *member;

	if (dd == NULL || dd->dd_inserted)
		return;

	while ((member = dd->dd_members) != NULL) {
		dd->dd_members = member->ddm_next;
		isns_dd_member_free(member);
	}

	if (dd->dd_object)
		isns_object_release(dd->dd_object);

	isns_free(dd->dd_name);
	isns_free(dd);
}

static isns_dd_member_t *
isns_dd_create_member(isns_object_t *obj)
{
	isns_dd_member_t *new;

	new = isns_calloc(1, sizeof(*new));
	new->ddm_added = 1;

	if (ISNS_IS_ISCSI_NODE(obj))
		new->ddm_type = ISNS_DD_MEMBER_ISCSI_NODE;
	else if (ISNS_IS_PORTAL(obj))
		new->ddm_type = ISNS_DD_MEMBER_PORTAL;
	else if (ISNS_IS_FC_NODE(obj))
		new->ddm_type = ISNS_DD_MEMBER_IFCP_NODE;
	else {
		isns_free(new);
		return NULL;
	}

	isns_object_reference_set(&new->ddm_object, obj);
	return new;
}

static inline void
isns_dd_member_free(isns_dd_member_t *member)
{
	switch (member->ddm_type) {
	case ISNS_DD_MEMBER_ISCSI_NODE:
		isns_free(member->ddm_iscsi_node.name);
		break;

	case ISNS_DD_MEMBER_IFCP_NODE:
		isns_free(member->ddm_ifcp_node.name);
		break;
	}

	isns_object_reference_drop(&member->ddm_object);
	isns_free(member);
}

void
isns_dd_get_members(uint32_t dd_id, isns_object_list_t *list, int active_only)
{
	isns_dd_t	*dd;
	isns_dd_member_t *mp;

	dd = isns_dd_by_id(dd_id);
	if (dd == NULL)
		return;

	for (mp = dd->dd_members; mp; mp = mp->ddm_next) {
		isns_object_t	*obj = mp->ddm_object.obj;

		if (active_only
		 && obj->ie_state != ISNS_OBJECT_STATE_MATURE)
			continue;

		isns_object_list_append(list, obj);
	}
}

/*
 * Helper function to remove a member referencing the given object
 */
static int
isns_dd_remove_member(isns_dd_t *dd, isns_object_t *obj)
{
	isns_dd_member_t *mp, **pos;

	pos = &dd->dd_members;
	while ((mp = *pos) != NULL) {
		if (mp->ddm_object.obj == obj) {
			*pos = mp->ddm_next;
			isns_dd_member_free(mp);
			return 1;
		} else {
			pos = &mp->ddm_next;
		}
	}

	return 0;
}

static void
isns_dd_insert(isns_dd_t *dd)
{
	if (dd->dd_inserted)
		return;

	if (dd->dd_id == 0) {
		uint32_t	id = isns_dd_next_id;
		unsigned int	i;

		for (i = 0; i < isns_dd_list.ddl_count; ++i) {
			isns_dd_t *cur = isns_dd_list.ddl_data[i];

			if (cur->dd_id > id)
				break;
			if (cur->dd_id == id)
				++id;
		}
		isns_debug_state("Allocated new DD_ID %d\n", id);
		dd->dd_id = id;
		isns_dd_next_id = id + 1;
	}

	/*
	 * When creating a new DD, if the DD_Symbolic_Name is
	 * not included in the Operating Attributes, or if it
	 * is included with a zero-length TLV, then the iSNS
	 * server SHALL provide a unique DD_Symbolic_Name value
	 * for the created DD.	The assigned DD_Symbolic_Name
	 * value SHALL be returned in the DDRegRsp message.
	 */
	if (dd->dd_name == NULL) {
		char	namebuf[64];

		snprintf(namebuf, sizeof(namebuf), "isns.dd%u", dd->dd_id);
		isns_assign_string(&dd->dd_name, namebuf);
	}

	isns_dd_list_insert(&isns_dd_list, dd);
	dd->dd_inserted = 1;

#ifdef DD_DEBUG
	/* Safety first - make sure domains are sorted by DD_ID */
	{
		unsigned int i, prev_id = 0;

		for (i = 0; i < isns_dd_list.ddl_count; ++i) {
			isns_dd_t *cur = isns_dd_list.ddl_data[i];

			isns_assert(cur->dd_id > prev_id);
			prev_id = cur->dd_id;
		}
	}
#endif
}

/*
 * Resize the DD list
 */
#define LIST_SIZE(n)	(((n) + 15) & ~15)
void
isns_dd_list_resize(isns_dd_list_t *list, unsigned int last_index)
{
	unsigned int	new_size, cur_size;
	isns_dd_t	**new_data;

	cur_size = LIST_SIZE(list->ddl_count);
	new_size = LIST_SIZE(last_index + 1);
	if (new_size < list->ddl_count)
		return;

	/* We don't use realloc here because we need
	 * to zero the new pointers anyway. */
	new_data = isns_calloc(new_size, sizeof(void *));
	isns_assert(new_data);

	memcpy(new_data, list->ddl_data,
			list->ddl_count * sizeof(void *));
	isns_free(list->ddl_data);

	list->ddl_data =  new_data;
	list->ddl_count = last_index + 1;
}

/*
 * Find the insert position for a given DD ID.
 * returns true iff the DD was found in the list.
 */
static int
__isns_dd_list_find_pos(isns_dd_list_t *list, unsigned int id,
			unsigned int *where)
{
	unsigned int	hi, lo, md;

	lo = 0;
	hi = list->ddl_count;

	/* binary search */
	while (lo < hi) {
		isns_dd_t *cur;

		md = (lo + hi) / 2;
		cur = list->ddl_data[md];

		if (id == cur->dd_id) {
			*where = md;
			return 1;
		}

		if (id < cur->dd_id) {
			hi = md;
		} else {
			lo = md + 1;
		}
	}

	*where = hi;
	return 0;
}

/*
 * In-order insert
 */
static void
isns_dd_list_insert(isns_dd_list_t *list, isns_dd_t *dd)
{
	unsigned int	pos;

	if (__isns_dd_list_find_pos(list, dd->dd_id, &pos)) {
		isns_error("Internal error in %s: DD already listed\n",
				__FUNCTION__);
		return;
	}

	isns_dd_list_resize(list, list->ddl_count);
	/* Shift the tail of the list to make room for new entry. */
	memmove(list->ddl_data + pos + 1,
		list->ddl_data + pos,
		(list->ddl_count - pos - 1) * sizeof(void *));
	list->ddl_data[pos] = dd;
}

/*
 * Remove DD from list
 */
void
isns_dd_list_remove(isns_dd_list_t *list, isns_dd_t *dd)
{
	unsigned int	pos;

	if (!__isns_dd_list_find_pos(list, dd->dd_id, &pos))
		return;

	/* Shift the tail of the list */
	memmove(list->ddl_data + pos,
		list->ddl_data + pos + 1,
		(list->ddl_count - pos - 1) * sizeof(void *));
	list->ddl_count -= 1;
}

isns_dd_t *
isns_dd_by_id(uint32_t id)
{
	unsigned int	i;
	
	for (i = 0; i < isns_dd_list.ddl_count; ++i) {
		isns_dd_t *dd = isns_dd_list.ddl_data[i];

		if (dd && dd->dd_id == id)
			return dd;
	}

	return NULL;
}

static isns_dd_t *
isns_dd_by_name(const char *name)
{
	unsigned int	i;
	
	for (i = 0; i < isns_dd_list.ddl_count; ++i) {
		isns_dd_t *dd = isns_dd_list.ddl_data[i];

		if (dd && !strcmp(dd->dd_name, name))
			return dd;
	}

	return NULL;
}

/*
 * Validate the operating attributes, which is surprisingly
 * tedious for DDs. It appears as if the whole DD/DDset
 * stuff has been slapped onto iSNS as an afterthought.
 *
 * DDReg has some funky rules about how eg iSCSI nodes
 * can be identified by either name or index, and how they
 * relate to each other. Unfortunately, the RFC is very vague
 * in describing how to treat DDReg message that mix these
 * two types of identification, except by saying they
 * need to be consistent.
 */
static int
isns_dd_parse_attrs(isns_dd_t *dd, isns_db_t *db,
		const isns_attr_list_t *attrs,
		const isns_dd_t *orig_dd,
		int is_registration)
{
	isns_dd_member_t **tail;
	const isns_dd_t	*conflict;
	unsigned int	i;
	int		rv = ISNS_SUCCESS;

	if (orig_dd) {
		dd->dd_id = orig_dd->dd_id;
		dd->dd_features = orig_dd->dd_features;
		isns_assign_string(&dd->dd_name, orig_dd->dd_name);
	}

	isns_assert(dd->dd_members == NULL);
	tail = &dd->dd_members;

	for (i = 0; i < attrs->ial_count; ++i) {
		isns_object_t	*obj = NULL;
		isns_attr_t	*attr, *next = NULL;
		const char	*name;
		uint32_t	id;

		attr = attrs->ial_data[i];

		if (!isns_object_attr_valid(&isns_dd_template, attr->ia_tag_id))
			return ISNS_INVALID_REGISTRATION;

		switch (attr->ia_tag_id) {
		case ISNS_TAG_DD_ID:
			/* Ignore this attribute in DDDereg messages */
			if (!is_registration)
				continue;

			/*
			 * 5.6.5.9.
			 * A DDReg message with no Message Key SHALL result
			 * in the attempted creation of a new Discovery Domain
			 * (DD).  If the DD_ID attribute (with non-zero length)
			 * is included among the Operating Attributes in the
			 * DDReg message, then the new Discovery Domain SHALL be
			 * assigned the value contained in that DD_ID attribute.
			 *
			 * If the DD_ID is included in both the Message
			 * Key and Operating Attributes, then the DD_ID
			 * value in the Message Key MUST be the same as
			 * the DD_ID value in the Operating Attributes.
			 *
			 * Implementer's note: It's not clear why the standard
			 * makes an exception for the DD_ID, while all other
			 * index attributes are read-only.
			 */
			if (ISNS_ATTR_IS_NIL(attr))
				break;

			id = attr->ia_value.iv_uint32;
			if (dd->dd_id != 0) {
				if (dd->dd_id != id)
					goto invalid;
			} else if ((conflict = isns_dd_by_id(id)) != NULL) {
				isns_debug_state("DDReg: requested ID %d "
						"clashes with existing DD (%s)\n",
						id, conflict->dd_name);
				goto invalid;
			}
			dd->dd_id = id;
			break;

		case ISNS_TAG_DD_SYMBOLIC_NAME:
			/* Ignore this attribute in DDDereg messages */
			if (!is_registration)
				continue;

			/*
			 * If the DD_Symbolic_Name is an operating
			 * attribute and its value is unique (i.e., it
			 * does not match the registered DD_Symbolic_Name
			 * for another DD), then the value SHALL be stored
			 * in the iSNS database as the DD_Symbolic_Name
			 * for the specified Discovery Domain.	If the
			 * value for the DD_Symbolic_Name is not unique,
			 * then the iSNS server SHALL reject the attempted
			 * DD registration with a status code of 3
			 * (Invalid Registration).
			 */
			if (ISNS_ATTR_IS_NIL(attr))
				break;

			name = attr->ia_value.iv_string;
			if (dd->dd_name && strcmp(name, dd->dd_name)) {
				isns_debug_state("DDReg: symbolic name conflict: "
						"id=%d name=%s requested=%s\n",
						dd->dd_id, dd->dd_name, name);
				goto invalid;
			}
			if (dd->dd_name)
				break;

			if ((conflict = isns_dd_by_name(name)) != NULL) {
				isns_debug_state("DDReg: requested symbolic name (%s) "
						"clashes with existing DD (id=%d)\n",
						name, conflict->dd_id);
				goto invalid;
			}
			isns_assign_string(&dd->dd_name, name);
			break;

		case ISNS_TAG_DD_FEATURES:
			/* Ignore this attribute in DDDereg messages */
			if (!is_registration)
				continue;

			/*
			 * When creating a new DD, if the DD_Features
			 * attribute is not included in the Operating
			 * Attributes, then the iSNS server SHALL assign
			 * the default value.  The default value for
			 * DD_Features is 0.
			 */
			if (ISNS_ATTR_IS_UINT32(attr))
				dd->dd_features = attr->ia_value.iv_uint32;
			break;

		case ISNS_TAG_DD_MEMBER_PORTAL_IP_ADDR:
			/* portal address must be followed by port */
			if (i + 1 >= attrs->ial_count)
				goto invalid;

			next = attrs->ial_data[i + 1];
			if (next->ia_tag_id != ISNS_TAG_DD_MEMBER_PORTAL_TCP_UDP_PORT)
				goto invalid;
			i += 1;
			/* fallthru to normal case */

		case ISNS_TAG_DD_MEMBER_PORTAL_INDEX:
		case ISNS_TAG_DD_MEMBER_ISCSI_INDEX:
		case ISNS_TAG_DD_MEMBER_ISCSI_NAME:
		case ISNS_TAG_DD_MEMBER_FC_PORT_NAME:
			if (ISNS_ATTR_IS_NIL(attr))
				goto invalid;

			obj = isns_dd_get_member_object(db,
					attr, next,
					is_registration);
			/* For a DD deregistration, it's okay if the
			 * object does not exist. */
			if (obj == NULL && is_registration)
				goto invalid;
			break;

		invalid:
			rv = ISNS_INVALID_REGISTRATION;
			continue;

		}

		if (obj) {
			if (is_registration
			 && isns_object_test_membership(obj, dd->dd_id)) {
				/* Duplicates are ignored */
				isns_debug_state("Ignoring duplicate DD registration "
						 "for %s %u\n",
						 obj->ie_template->iot_name,
						 obj->ie_index);
			} else {
				/* This just adds the member to the temporary DD object,
				 * without changing any state in the database. */
				isns_dd_member_t *new;

				new = isns_dd_create_member(obj);
				if (new) {
					*tail = new;
					tail = &new->ddm_next;
				}
			}
			isns_object_release(obj);
		}
	}

	return rv;
}

/*
 * Helper function: extract live nodes from the DD member list
 */
static inline void
isns_dd_get_member_nodes(isns_dd_member_t *members, isns_object_list_t *result)
{
	isns_dd_member_t	*mp;

	/* Extract iSCSI nodes from both list. */
	for (mp = members; mp; mp = mp->ddm_next) {
		isns_object_t	*obj = mp->ddm_object.obj;

		if (ISNS_IS_ISCSI_NODE(obj)
		 && obj->ie_state == ISNS_OBJECT_STATE_MATURE)
			isns_object_list_append(result, obj);
	}
}

void
isns_dd_notify(const isns_dd_t *dd, isns_dd_member_t *unchanged,
		isns_dd_member_t *changed, int removed)
{
	isns_object_list_t	dd_objects = ISNS_OBJECT_LIST_INIT;
	isns_object_list_t	changed_objects = ISNS_OBJECT_LIST_INIT;
	unsigned int		i, j, event;

	/* Extract iSCSI nodes from both list. */
	isns_dd_get_member_nodes(unchanged, &dd_objects);
	isns_dd_get_member_nodes(changed, &changed_objects);

	/* Send a management SCN multicast to all
	 * control nodes that care. */
	event = removed? ISNS_SCN_DD_MEMBER_REMOVED_MASK : ISNS_SCN_DD_MEMBER_ADDED_MASK;
	for (i = 0; i < changed_objects.iol_count; ++i) {
		isns_object_t	*obj = changed_objects.iol_data[i];

		isns_object_event(obj,
				event | ISNS_SCN_MANAGEMENT_REGISTRATION_MASK,
				dd->dd_object);
	}

#ifdef notagoodidea
	/* Not sure - it may be good to send OBJECT ADDED/REMOVED instead
	 * of the DD membership messages. However, right now the SCN code
	 * will nuke all SCN registrations for a node when it sees a
	 * REMOVE event for it.
	 */
	event = removed? ISNS_SCN_OBJECT_REMOVED_MASK : ISNS_SCN_OBJECT_ADDED_MASK;
#endif

	/* If we added an iscsi node, loop over all members
	 * and send unicast events to each iscsi node,
	 * informing them that a new member has been added/removed.
	 */
	for (j = 0; j < changed_objects.iol_count; ++j) {
		isns_object_t	*changed = changed_objects.iol_data[j];

		for (i = 0; i < dd_objects.iol_count; ++i) {
			isns_object_t	*obj = dd_objects.iol_data[i];

			/* For member removal, do not send notifications
			 * if the two nodes are still visible to each
			 * other through a different discovery domain */
			if (removed && isns_object_test_visibility(obj, changed))
				continue;

			/* Inform the old node that the new node was
			 * added/removed. */
			isns_unicast_event(obj, changed, event, NULL);

			/* Inform the new node that the old node became
			 * (in)accessible to it. */
			isns_unicast_event(changed, obj, event, NULL);
		}

		/* Finally, inform each changed node of the other
		 * DD members that became (in)accessible to it. */
		for (i = 0; i < changed_objects.iol_count; ++i) {
			isns_object_t	*obj = changed_objects.iol_data[i];

			if (obj == changed)
				continue;

			if (removed && isns_object_test_visibility(obj, changed))
				continue;

			isns_unicast_event(changed, obj, event, NULL);
		}
	}
}

void
isns_dd_add_members(isns_dd_t *dd, isns_db_t *db, isns_dd_t *new_dd)
{
	isns_dd_member_t *mp, **tail;

	for (mp = new_dd->dd_members; mp; mp = mp->ddm_next) {
		const char	*node_name;
		isns_object_t	*obj = mp->ddm_object.obj;

		/*
		 * If the Operating Attributes contain a DD
		 * Member iSCSI Name value for a Storage Node
		 * that is currently not registered in the iSNS
		 * database, then the iSNS server MUST allocate an
		 * unused iSCSI Node Index for that Storage Node.
		 * The assigned iSCSI Node Index SHALL be returned
		 * in the DDRegRsp message as the DD Member iSCSI
		 * Node Index.	The allocated iSCSI Node Index
		 * value SHALL be assigned to the Storage Node
		 * if and when it registers in the iSNS database.
		 * [And likewise for portals]
		 */
		if (obj->ie_index == 0)
			isns_db_insert_limbo(db, obj);
		mp->ddm_index = obj->ie_index;

		/* Record the fact that the object is a member of
		 * this DD */
		isns_object_mark_membership(obj, dd->dd_id);

		switch (mp->ddm_type) {
		case ISNS_DD_MEMBER_ISCSI_NODE:
			if (isns_object_get_string(obj, ISNS_TAG_ISCSI_NAME, &node_name))
				isns_assign_string(&mp->ddm_iscsi_node.name, node_name);

			break;

		case ISNS_DD_MEMBER_IFCP_NODE:
			if (isns_object_get_string(obj, ISNS_TAG_FC_PORT_NAME_WWPN, &node_name))
				isns_assign_string(&mp->ddm_ifcp_node.name, node_name);

			break;

		case ISNS_DD_MEMBER_PORTAL:
			isns_portal_from_object(&mp->ddm_portal.info,
					ISNS_TAG_PORTAL_IP_ADDRESS,
					ISNS_TAG_PORTAL_TCP_UDP_PORT,
					obj);
			break;
		}
	}

	/* Find the tail of the DD member list */
	tail = &dd->dd_members;
	while ((mp = *tail) != NULL)
		tail = &mp->ddm_next;

	/* Append the new list of members */
	*tail = new_dd->dd_members;
	new_dd->dd_members = NULL;
}

/*
 * Remove members from a DD
 */
int
isns_dd_remove_members(isns_dd_t *dd, isns_db_t *db, isns_dd_t *temp_dd)
{
	isns_dd_member_t *mp;

	for (mp = temp_dd->dd_members; mp; mp = mp->ddm_next) {
		isns_object_t	*obj = mp->ddm_object.obj;

		/* Clear the membership bit. If the object wasn't in this
		 * DD to begin with, bail out right away. */
		if (!isns_object_clear_membership(obj, dd->dd_id)) {
			isns_debug_state("DD dereg: object %d is not in this DD\n",
						obj->ie_index);
			continue;
		}

		if (!isns_dd_remove_member(dd, obj))
			isns_error("%s: DD member not found in internal list\n",
				__FUNCTION__);
	}

	return ISNS_SUCCESS;
}

void
isns_dd_store(isns_db_t *db, const isns_dd_t *dd, int rewrite)
{
	isns_object_t	*obj = dd->dd_object;
	isns_dd_member_t *member;

	if (rewrite)
		isns_object_prune_attrs(obj);

	isns_object_set_uint32(obj, ISNS_TAG_DD_ID, dd->dd_id);
	isns_object_set_string(obj, ISNS_TAG_DD_SYMBOLIC_NAME, dd->dd_name);
	isns_object_set_uint32(obj, ISNS_TAG_DD_FEATURES, dd->dd_features);

	for (member = dd->dd_members; member; member = member->ddm_next) {
		struct isns_dd_iscsi_node *node;
		struct isns_dd_portal *portal;

		if (!member->ddm_added && !rewrite)
			continue;

		switch (member->ddm_type) {
		case ISNS_DD_MEMBER_ISCSI_NODE:
			node = &member->ddm_iscsi_node;

			isns_object_set_uint32(obj,
					ISNS_TAG_DD_MEMBER_ISCSI_INDEX,
					node->index);
			if (node->name)
				isns_object_set_string(obj,
					ISNS_TAG_DD_MEMBER_ISCSI_NAME,
					node->name);
			break;

		case ISNS_DD_MEMBER_PORTAL:
			portal = &member->ddm_portal;

			isns_object_set_uint32(obj,
					ISNS_TAG_DD_MEMBER_PORTAL_INDEX,
					portal->index);
			if (portal->info.addr.sin6_family != AF_UNSPEC) {
				isns_portal_to_object(&portal->info,
					ISNS_TAG_DD_MEMBER_PORTAL_IP_ADDR,
					ISNS_TAG_DD_MEMBER_PORTAL_TCP_UDP_PORT,
					obj);
			}
			break;
		}

		member->ddm_added = 0;
	}
}

/*
 * Destroy a DD
 * The caller should call isns_dd_release to free the DD object.
 */
void
isns_dd_destroy(isns_db_t *db, isns_dd_t *dd)
{
	isns_db_remove(db, dd->dd_object);
	isns_dd_list_remove(&isns_dd_list, dd);
	dd->dd_inserted = 0;
}

int
isns_dd_load_all(isns_db_t *db)
{
	isns_object_list_t list = ISNS_OBJECT_LIST_INIT;
	unsigned int	i;
	int		rc;

	if (isns_dd_list_initialized)
		return ISNS_SUCCESS;

	rc = isns_db_gang_lookup(db, &isns_dd_template, NULL, &list);
	if (rc != ISNS_SUCCESS)
		return rc;

	for (i = 0; i < list.iol_count; ++i) {
		isns_object_t *obj = list.iol_data[i];
		isns_dd_t *dd = NULL, *temp_dd = NULL;
		isns_dd_member_t *mp;

		temp_dd = isns_dd_alloc();

		rc = isns_dd_parse_attrs(temp_dd, db, &obj->ie_attrs, NULL, 1);
		if (rc) {
			if (temp_dd->dd_id == 0) {
				isns_error("Problem converting DD object (index 0x%x). No DD_ID\n",
					   obj->ie_index);
				goto next;
			}
			isns_error("Problem converting DD %u. Proceeding anyway.\n",
				   temp_dd->dd_id);
		} else {
			isns_debug_state("Loaded DD %d from database\n", temp_dd->dd_id);
		}

		dd = isns_dd_clone(temp_dd);

		dd->dd_object = isns_object_get(obj);

		isns_dd_insert(dd);
		isns_dd_add_members(dd, db, temp_dd);

		/* Clear the ddm_added flag for all members, to
		 * prevent all information from being duplicated
		 * to the DB on the next DD modification. */
		for (mp = dd->dd_members; mp; mp = mp->ddm_next)
			mp->ddm_added = 0;

next:
		isns_dd_release(temp_dd);
	}

	isns_object_list_destroy(&list);
	isns_dd_list_initialized = 1;
	return ISNS_SUCCESS;
}

isns_object_t *
isns_dd_get_member_object(isns_db_t *db, const isns_attr_t *key1,
		const isns_attr_t *key2,
		int create)
{
	isns_attr_list_t query = ISNS_ATTR_LIST_INIT;
	isns_object_template_t *tmpl = NULL;
	isns_object_t	*obj;
	isns_portal_info_t portal_info;
	const char	*key_string = NULL;
	uint32_t	key_index = 0;

	switch (key1->ia_tag_id) {
	case ISNS_TAG_DD_MEMBER_ISCSI_INDEX:
		key_index = key1->ia_value.iv_uint32;
		isns_attr_list_append_uint32(&query,
				ISNS_TAG_ISCSI_NODE_INDEX,
				key_index);
		tmpl = &isns_iscsi_node_template;
		break;

	case ISNS_TAG_DD_MEMBER_ISCSI_NAME:
		key_string = key1->ia_value.iv_string;
		isns_attr_list_append_string(&query,
				ISNS_TAG_ISCSI_NAME,
				key_string);
		tmpl = &isns_iscsi_node_template;
		break;

	case ISNS_TAG_DD_MEMBER_FC_PORT_NAME:
		key_string = key1->ia_value.iv_string;
		isns_attr_list_append_string(&query,
				ISNS_TAG_FC_PORT_NAME_WWPN,
				key_string);
		tmpl = &isns_fc_port_template;
		break;

	case ISNS_TAG_DD_MEMBER_PORTAL_INDEX:
		key_index = key1->ia_value.iv_uint32;
		isns_attr_list_append_uint32(&query,
				ISNS_TAG_PORTAL_INDEX,
				key_index);
		tmpl = &isns_portal_template;
		break;

	case ISNS_TAG_DD_MEMBER_PORTAL_IP_ADDR:
		if (!isns_portal_from_attr_pair(&portal_info, key1, key2)
		 || !isns_portal_to_attr_list(&portal_info,
			 ISNS_TAG_PORTAL_IP_ADDRESS,
			 ISNS_TAG_PORTAL_TCP_UDP_PORT,
			 &query))
			return NULL;

		key_string = isns_portal_string(&portal_info);
		tmpl = &isns_portal_template;
		break;

	default:
		return NULL;
	}

	obj = isns_db_lookup(db, tmpl, &query);
	if (!obj && create) {
		if (!key_string) {
			isns_debug_state("Attempt to register %s DD member "
					"with unknown index %u\n",
					tmpl->iot_name, key_index);
			goto out;
		}

		obj = isns_create_object(tmpl, &query, NULL);
		if (obj != NULL)
			isns_debug_state("Created limbo object for "
					"%s DD member %s\n",
					tmpl->iot_name, key_string);
	}

out:
	isns_attr_list_destroy(&query);
	return obj;

}
