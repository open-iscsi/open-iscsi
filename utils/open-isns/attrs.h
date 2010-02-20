/*
 * iSNS object attributes
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#ifndef ISNS_ATTRS_H
#define ISNS_ATTRS_H

#include <netinet/in.h>
#include "buffer.h"
#include "isns.h"

/*
 * Type identifier
 */
enum {
	ISNS_ATTR_TYPE_NIL = 0,
	ISNS_ATTR_TYPE_OPAQUE,
	ISNS_ATTR_TYPE_STRING,
	ISNS_ATTR_TYPE_INT32,
	ISNS_ATTR_TYPE_UINT32,
	ISNS_ATTR_TYPE_UINT64,
	ISNS_ATTR_TYPE_IPADDR,
	ISNS_ATTR_TYPE_RANGE16,

	__ISNS_ATTR_TYPE_BUILTIN_MAX
};

/*
 * Union holding an attribute value
 */
typedef struct isns_value {
	const struct isns_attr_type *	iv_type;

	/* Data is stuffed into an anonymous union */
	union {
		uint32_t		iv_nil;
		struct __isns_opaque {
			void *		ptr;
			size_t		len;
		}			iv_opaque;
		char *			iv_string;
		int32_t			iv_int32;
		uint32_t		iv_uint32;
		uint64_t		iv_uint64;
		struct in6_addr		iv_ipaddr;
		struct {
			uint16_t	min, max;
		}			iv_range;
	};
} isns_value_t;

#define __ISNS_ATTRTYPE(type)	isns_attr_type_##type
#define __ISNS_MEMBER(type)	iv_##type
#define ISNS_VALUE_INIT(type, value) \
	(isns_value_t) { .iv_type = &__ISNS_ATTRTYPE(type), \
		         { .__ISNS_MEMBER(type) = (value) } }

#define isns_attr_initialize(attrp, tag, type, value) do { \
		isns_attr_t *__attr = (attrp);		\
		uint32_t __tag = (tag);			\
		__attr->ia_users = 1;			\
		__attr->ia_tag_id = (__tag);		\
		__attr->ia_tag = isns_tag_type_by_id(__tag); \
		__attr->ia_value = ISNS_VALUE_INIT(type, value); \
	} while (0)
#define ISNS_ATTR_INIT(tag, type, value) (isns_attr_t) {	\
	 	.ia_users = 1,					\
		.ia_tag_id = (tag),				\
		.ia_tag = isns_tag_type_by_id(tag),		\
		.ia_value = ISNS_VALUE_INIT(type, value)	\
	}

/*
 * Attribute type
 */
typedef struct isns_attr_type {
	uint32_t	it_id;
	const char *	it_name;

	void		(*it_assign)(isns_value_t *, const isns_value_t *);
	int		(*it_set)(isns_value_t *, const void *);
	int		(*it_get)(isns_value_t *, void *);
	int		(*it_match)(const isns_value_t *, const isns_value_t *);
	int		(*it_compare)(const isns_value_t *, const isns_value_t *);
	int		(*it_encode)(buf_t *, const isns_value_t *);
	int		(*it_decode)(buf_t *, size_t, isns_value_t *);
	void		(*it_destroy)(isns_value_t *);
	void		(*it_print)(const isns_value_t *, char *, size_t);
	int		(*it_parse)(isns_value_t *, const char *);
} isns_attr_type_t;

/*
 * Tag info: for each tag, provides a printable name,
 * and the attribute type associated with it.
 */
struct isns_tag_type {
	uint32_t	it_id;
	const char *	it_name;
	unsigned int	it_multiple : 1,
			it_readonly : 1;
	isns_attr_type_t *it_type;

	int		(*it_validate)(const isns_value_t *,
					const isns_policy_t *);
	void		(*it_print)(const isns_value_t *, char *, size_t);
	int		(*it_parse)(isns_value_t *, const char *);
	const char *	(*it_help)(void);
};

/*
 * Attribute
 */
struct isns_attr {
	unsigned int		ia_users;
	uint32_t		ia_tag_id;
	const isns_tag_type_t *	ia_tag;
	isns_value_t		ia_value;
};

extern isns_attr_type_t	isns_attr_type_nil;
extern isns_attr_type_t	isns_attr_type_opaque;
extern isns_attr_type_t	isns_attr_type_string;
extern isns_attr_type_t	isns_attr_type_int32;
extern isns_attr_type_t	isns_attr_type_uint32;
extern isns_attr_type_t	isns_attr_type_uint64;
extern isns_attr_type_t	isns_attr_type_ipaddr;
extern isns_attr_type_t	isns_attr_type_range16;

extern isns_attr_t *	isns_attr_alloc(uint32_t, const isns_tag_type_t *,
					const isns_value_t *);

extern void		isns_attr_list_append_value(isns_attr_list_t *,
					uint32_t tag, const isns_tag_type_t *,
					const isns_value_t *);
extern void		isns_attr_list_update_value(isns_attr_list_t *,
					uint32_t tag, const isns_tag_type_t *,
					const isns_value_t *);
extern int		isns_attr_list_get_value(const isns_attr_list_t *,
					uint32_t tag,
					isns_value_t *);
extern int		isns_attr_list_get_uint32(const isns_attr_list_t *,
					uint32_t tag,
					uint32_t *);
extern int		isns_attr_list_get_string(const isns_attr_list_t *,
					uint32_t tag,
					const char **);

extern int		isns_attr_list_validate(const isns_attr_list_t *,
					const isns_policy_t *,
					unsigned int function);
extern int		isns_attr_validate(const isns_attr_t *,
					const isns_policy_t *);

extern void		isns_attr_list_prune(isns_attr_list_t *,
					const uint32_t *,
					unsigned int);
extern int		isns_attr_list_remove_member(isns_attr_list_t *,
					const isns_attr_t *,
					const uint32_t *);
extern void		isns_attr_list_update_attr(isns_attr_list_t *,
					const isns_attr_t *);

extern int		isns_attr_decode(buf_t *, isns_attr_t **);
extern int		isns_attr_encode(buf_t *, const isns_attr_t *);

extern int		isns_attr_list_decode(buf_t *, isns_attr_list_t *);
extern int		isns_attr_list_decode_delimited(buf_t *, isns_attr_list_t *);
extern int		isns_attr_list_encode(buf_t *, const isns_attr_list_t *);
extern int		isns_encode_delimiter(buf_t *);

extern const isns_tag_type_t *isns_tag_type_by_id(unsigned int);
extern const isns_attr_type_t *isns_attr_type_by_id(unsigned int);

typedef struct isns_quick_attr_list isns_quick_attr_list_t;
struct isns_quick_attr_list {
	isns_attr_list_t	iqa_list;
	isns_attr_t *		iqa_attrs[1];
	isns_attr_t		iqa_attr;
};
#define ISNS_QUICK_ATTR_LIST_DECLARE(qlist, tag, type, value) \
	isns_quick_attr_list_t qlist = {			\
		.iqa_list = (isns_attr_list_t) {		\
			.ial_data = qlist.iqa_attrs,		\
			.ial_count = 1				\
		},						\
		.iqa_attrs = { &qlist.iqa_attr },		\
		.iqa_attr = ISNS_ATTR_INIT(tag, type, value),	\
	}

/*
 * The following is used to chop up an incoming attr list as
 * given in eg. a DevAttrReg message into separate chunks,
 * following the ordering constraints laid out in the RFC.
 *
 * isns_attr_list_scanner_init initializes the scanner state.
 *
 * isns_attr_list_scanner_next advances to the next object in
 * the list, returning the keys and attrs for one object.
 *
 * The isns_attr_list_scanner struct should really be opaque, but
 * we put it here so you can declare a scanner variable on the
 * stack.
 */
struct isns_attr_list_scanner {
	isns_source_t *		source;
	isns_policy_t *		policy;
	isns_object_t *		key_obj;
	isns_attr_list_t	orig_attrs;
	unsigned int		pos;

	isns_attr_list_t	keys;
	isns_attr_list_t	attrs;
	isns_object_template_t *tmpl;
	unsigned int		num_key_attrs;

	unsigned int		entities;

	uint32_t		pgt_next_attr;
	uint32_t		pgt_value;
	const char *		pgt_iscsi_name;
	isns_portal_info_t	pgt_portal_info;
	isns_object_t *		pgt_base_object;

	unsigned int		index_acceptable : 1;
};

extern void		isns_attr_list_scanner_init(struct isns_attr_list_scanner *,
				isns_object_t *key_obj,
				const isns_attr_list_t *attrs);
extern int		isns_attr_list_scanner_next(struct isns_attr_list_scanner *);
extern void		isns_attr_list_scanner_destroy(struct isns_attr_list_scanner *);

/*
 * The following is used to parse attribute lists given as
 * a bunch of strings.
 */
struct isns_attr_list_parser {
	struct isns_tag_prefix *prefix;
	const char *		default_port;

	unsigned int		multi_type_permitted : 1,
				nil_permitted : 1;

	isns_attr_t *		(*load_key)(const char *);
	isns_attr_t *		(*generate_key)(void);
};

extern int		isns_attr_list_split(char *line, char **argv, unsigned int argc_max);
extern void		isns_attr_list_parser_init(struct isns_attr_list_parser *,
				isns_object_template_t *);
extern int		isns_parse_attrs(unsigned int, char **,
				isns_attr_list_t *, struct isns_attr_list_parser *);
extern int		isns_parse_query_attrs(unsigned int, char **,
				isns_attr_list_t *, isns_attr_list_t *,
				struct isns_attr_list_parser *);
extern void		isns_attr_list_parser_help(struct isns_attr_list_parser *);
extern isns_object_template_t *isns_attr_list_parser_context(const struct isns_attr_list_parser *);
extern int		isns_print_attrs(isns_object_t *, char **, unsigned int);

#endif /* ISNS_ATTRS_H */
