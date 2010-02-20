/*
 * iSNS object model
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#ifndef ISNS_OBJECTS_H
#define ISNS_OBJECTS_H

#include "isns.h"
#include "attrs.h"

enum isns_object_id {
	ISNS_OBJECT_TYPE_ENTITY = 1,
	ISNS_OBJECT_TYPE_NODE,
	ISNS_OBJECT_TYPE_PORTAL,
	ISNS_OBJECT_TYPE_PG,
	ISNS_OBJECT_TYPE_DD,
	ISNS_OBJECT_TYPE_DDSET,
	ISNS_OBJECT_TYPE_POLICY,
	ISNS_OBJECT_TYPE_FC_PORT,
	ISNS_OBJECT_TYPE_FC_NODE,

	__ISNS_OBJECT_TYPE_MAX
};


struct isns_object_template {
	const char *		iot_name;
	unsigned int		iot_handle;	/* internal handle */
	unsigned int		iot_num_attrs;
	unsigned int		iot_num_keys;
	uint32_t *		iot_attrs;
	uint32_t *		iot_keys;
	uint32_t		iot_index;
	uint32_t		iot_next_index;

	isns_object_template_t *iot_container;

	unsigned int		iot_relation_type;
	isns_relation_t *	(*iot_build_relation)(isns_db_t *,
					isns_object_t *,
					const isns_object_list_t *);

	unsigned int		iot_vendor_specific : 1;
};

struct isns_object {
	/* There are two kinds of users of an object
	 *  -	Temporary references that result from the
	 *	object being examined; being on a list,
	 *	etc. The main purpose of these references
	 *	is to make sure the object doesn't go away
	 *	while being used.
	 *
	 *	These are accounted for by ie_users.
	 *
	 *  -	Permanent references that result from the
	 *	object being references by other objects
	 *	(usually relations) such as a Portal Group,
	 *	or a Discovery Domain.
	 *
	 *	These are accounted for by ie_references.
	 *
	 *	The main purpose of these references is to
	 *	model some of the weirder life cycle states
	 *	described in RFC 4711.
	 *
	 * Every reference via ie_references implies a
	 * reference via ie_users.
	 */
	unsigned int		ie_users;
	unsigned int		ie_references;

	uint32_t		ie_index;

	unsigned int		ie_state;
	unsigned int		ie_flags;
	time_t			ie_mtime;

	uint32_t		ie_scn_mask;	/* Events this node listens for */
	uint32_t		ie_scn_bits;	/* Current event bits */

	isns_attr_list_t	ie_attrs;
	isns_object_t *		ie_container;
	isns_object_template_t *ie_template;

	isns_relation_t *	ie_relation;
	isns_object_list_t	ie_children;

	/* Bit vector describing DD membership */
	isns_bitvector_t *	ie_membership;

	/* Support for virtual objects */
	int			(*ie_rebuild)(isns_object_t *, isns_db_t *);
};

typedef struct isns_object_ref {
	isns_object_t *		obj;
} isns_object_ref_t;

enum {
	ISNS_RELATION_NONE = 0,
	ISNS_RELATION_PORTAL_GROUP,
};

struct isns_relation {
	unsigned int		ir_type;
	unsigned int		ir_users;
	isns_object_t *		ir_object;
	isns_object_ref_t	ir_subordinate[2];
};

typedef struct isns_relation_soup isns_relation_soup_t;

typedef struct isns_relation_list isns_relation_list_t;
struct isns_relation_list {
	unsigned int		irl_count;
	isns_relation_t **	irl_data;
};
#define ISNS_RELATION_LIST_INIT { .irl_count = 0, .irl_data = NULL }

#define ISNS_OBJECT_DIRTY	0x0001
#define ISNS_OBJECT_PRIVATE	0x0002
#define ISNS_OBJECT_DEAD	0x0004

enum {
	ISNS_OBJECT_STATE_LARVAL,
	ISNS_OBJECT_STATE_MATURE,
	ISNS_OBJECT_STATE_LIMBO,
	ISNS_OBJECT_STATE_DEAD,
};

extern int	isns_object_remove_member(isns_object_t *obj,
				const isns_attr_t *attr,
				const uint32_t *subordinate_tags);

extern void	isns_object_reference_set(isns_object_ref_t *ref,
				isns_object_t *obj);
extern void	isns_object_reference_drop(isns_object_ref_t *ref);

extern const char *isns_object_state_string(unsigned int);

extern isns_object_template_t *isns_object_template_by_name(const char *);
extern int	isns_object_is_valid_container(const isns_object_t *,
				isns_object_template_t *);

extern void	isns_object_set_scn_mask(isns_object_t *, uint32_t);

extern isns_object_t *isns_create_default_domain(void);

/*
 * Helper macros for object type check
 */
#define __ISNS_OBJECT_TYPE_CHECK(obj, type) \
		((obj)->ie_template == &isns_##type##_template)
#define ISNS_IS_ENTITY(obj)	__ISNS_OBJECT_TYPE_CHECK(obj, entity)
#define ISNS_IS_ISCSI_NODE(obj)	__ISNS_OBJECT_TYPE_CHECK(obj, iscsi_node)
#define ISNS_IS_FC_PORT(obj)	__ISNS_OBJECT_TYPE_CHECK(obj, fc_port)
#define ISNS_IS_FC_NODE(obj)	__ISNS_OBJECT_TYPE_CHECK(obj, fc_node)
#define ISNS_IS_PORTAL(obj)	__ISNS_OBJECT_TYPE_CHECK(obj, portal)
#define ISNS_IS_PG(obj)		__ISNS_OBJECT_TYPE_CHECK(obj, iscsi_pg)
#define ISNS_IS_POLICY(obj)	__ISNS_OBJECT_TYPE_CHECK(obj, policy)
#define ISNS_IS_DD(obj)		__ISNS_OBJECT_TYPE_CHECK(obj, dd)
#define ISNS_IS_DDSET(obj)	__ISNS_OBJECT_TYPE_CHECK(obj, ddset)

#endif /* ISNS_OBJECTS_H */
