/*
 * Handle iSNS attributes and attribute lists
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "util.h"
#include "vendor.h"
#include "attrs.h"
#include "isns.h"

/* Implementation limit - sanity checking */
#define ISNS_ATTR_MAX_LEN	8192

static void	__isns_attr_set_value(isns_attr_t *, const isns_value_t *);

/*
 * Allocate an attribute
 */
isns_attr_t *
isns_attr_alloc(uint32_t tag, const isns_tag_type_t *tag_type, const isns_value_t *value)
{
	isns_attr_t	*attr;

	if (tag_type == NULL)
		tag_type = isns_tag_type_by_id(tag);

	attr = isns_calloc(1, sizeof(*attr));
	if (!attr)
		isns_fatal("Out of memory!\n");

	attr->ia_users = 1;
	attr->ia_tag_id = tag;
	attr->ia_tag = tag_type;

	__isns_attr_set_value(attr, value);
	return attr;
}

isns_attr_t *
isns_attr_get(isns_attr_t *attr)
{
	if (attr) {
		isns_assert(attr->ia_users);
		attr->ia_users++;
	}
	return attr;
}

void
isns_attr_release(isns_attr_t *attr)
{
	const isns_attr_type_t *type;

	isns_assert(attr->ia_users);
	if (--(attr->ia_users))
		return;

	type = attr->ia_value.iv_type;
	if (type->it_destroy)
		type->it_destroy(&attr->ia_value);
	isns_free(attr);
}

/*
 * Assign a value to an attribute
 */
void
__isns_attr_set_value(isns_attr_t *attr, const isns_value_t *new_value)
{
	const isns_attr_type_t *type, *old_type;
	isns_value_t *old_value;

	old_value = &attr->ia_value;
	if (old_value == new_value)
		return;

	old_type = old_value->iv_type;
	if (old_type && old_type->it_destroy)
		old_type->it_destroy(old_value);

	if (!new_value || !(type = new_value->iv_type))
		type = attr->ia_tag->it_type;

	/* When assigning the value to the attr, check
	 * whether it needs special attention. */
	if (new_value) {
		if (type->it_assign) {
			type->it_assign(&attr->ia_value, new_value);
		} else {
			attr->ia_value = *new_value;
		}
	}
	attr->ia_value.iv_type = type;
}

/*
 * Compare two attributes.
 * Returns non-null when attributes are the same, else 0.
 */
int
isns_attr_match(const isns_attr_t *a, const isns_attr_t *b)
{
	const isns_attr_type_t *type;

	if (a->ia_tag_id != b->ia_tag_id)
		return 0;

	/* NIL acts as a wildcard */
	if (a->ia_value.iv_type == &isns_attr_type_nil
	 || b->ia_value.iv_type == &isns_attr_type_nil)
		return 1;

	if (a->ia_value.iv_type != b->ia_value.iv_type)
		return 0;
	type = a->ia_value.iv_type;

	if (type->it_match)
		return type->it_match(&a->ia_value, &b->ia_value);

	return !memcmp(&a->ia_value, &b->ia_value, sizeof(isns_value_t));
}

/*
 * Lexicographical comparison of two attributes.
 * Returns -1 when a is less than b, +1 when a is greater than
 * b, and 0 if equal.
 */
int
isns_attr_compare(const isns_attr_t *a, const isns_attr_t *b)
{
	const isns_attr_type_t *type = a->ia_value.iv_type;

	isns_assert(a->ia_tag_id == b->ia_tag_id);

	if (type != b->ia_value.iv_type) {
		/* One of them must be NIL */
		if (type == &isns_attr_type_nil)
			return -1;
		return 1;
	}

	/* If both are NIL, consider them equal */
	if (type == &isns_attr_type_nil)
		return 0;

	/* A few types need special comparison functions, but
	 * most don't. The reason is, we don't care whether the
	 * ordering this creates is the "canonical" ordering for
	 * this type, eg for integers. All that matters is that
	 * there is some consistent ordering suitable for
	 * DevGetNext.
	 */
	if (type->it_compare)
		return type->it_compare(&a->ia_value, &b->ia_value);

	return memcmp(&a->ia_value, &b->ia_value, sizeof(isns_value_t));
}

/*
 * Convert a string to an attribute
 */
isns_attr_t *
isns_attr_from_string(uint32_t tag, const char *string)
{
	const isns_tag_type_t *tag_type;
	int		(*parse)(isns_value_t *, const char *);
	isns_value_t	value;

	memset(&value, 0, sizeof(value));

	tag_type = isns_tag_type_by_id(tag);
	if (!tag_type)
		return NULL;

	parse = tag_type->it_parse;
	if (parse == NULL)
		parse = tag_type->it_type->it_parse;

	if (!parse || !parse(&value, string))
		return NULL;

	return isns_attr_alloc(tag, tag_type, &value);
}

/*
 * Initialize an attribute list.
 */
void
isns_attr_list_init(isns_attr_list_t *list)
{
	memset(list, 0, sizeof(*list));
}

static inline void
__isns_attr_list_resize(isns_attr_list_t *list, unsigned int count)
{
	unsigned int	max;

	max = (list->ial_count + 15) & ~15;
	if (count < max)
		return;

	count = (count + 15) & ~15;
	list->ial_data = isns_realloc(list->ial_data, count * sizeof(isns_attr_t *));
	if (!list->ial_data)
		isns_fatal("Out of memory!\n");
}

void
isns_attr_list_append_list(isns_attr_list_t *dst,
		const isns_attr_list_t *src)
{
	unsigned int	i, j;

	__isns_attr_list_resize(dst, dst->ial_count + src->ial_count);
	j = dst->ial_count;
	for (i = 0; i < src->ial_count; ++i, ++j) {
		isns_attr_t *attr = src->ial_data[i];

		dst->ial_data[j] = attr;
		attr->ia_users++;
	}
	dst->ial_count = j;
}

void
isns_attr_list_copy(isns_attr_list_t *dst,
		const isns_attr_list_t *src)
{
	isns_attr_list_destroy(dst);
	isns_attr_list_append_list(dst, src);
}

void
isns_attr_list_destroy(isns_attr_list_t *list)
{
	unsigned int	i;

	for (i = 0; i < list->ial_count; ++i) {
		isns_attr_t *attr = list->ial_data[i];

		isns_attr_release(attr);
	}

	if (list->ial_data)
		isns_free(list->ial_data);
	memset(list, 0, sizeof(*list));
}

int
isns_attr_list_remove_tag(isns_attr_list_t *list, uint32_t tag)
{
	unsigned int	i = 0, j = 0, removed = 0;

	for (i = 0; i < list->ial_count; ++i) {
		isns_attr_t *attr = list->ial_data[i];

		if (attr->ia_tag_id == tag) {
			isns_attr_release(attr);
			removed++;
		} else {
			list->ial_data[j++] = attr;
		}
	}
	list->ial_count = j;
	return removed;
}

/*
 * Locate the given attribute in the list, remove it
 * and any following attributes that have a tag from the
 * @subordinate_tags list. This is used by the DDDereg
 * code to remove DD members.
 */
int
isns_attr_list_remove_member(isns_attr_list_t *list,
		const isns_attr_t *match,
		const uint32_t *subordinate_tags)
{
	unsigned int	i = 0, j = 0, k, removed = 0, purging = 0;

	while (i < list->ial_count) {
		isns_attr_t *attr = list->ial_data[i++];

		if (purging && subordinate_tags) {
			for (k = 0; subordinate_tags[k]; ++k) {
				if (attr->ia_tag_id == subordinate_tags[k])
					goto purge_attr;
			}
		}
		purging = 0;

		if (!isns_attr_match(attr, match)) {
			list->ial_data[j++] = attr;
			continue;
		}

purge_attr:
		isns_attr_release(attr);
		purging = 1;
		removed++;
	}
	list->ial_count = j;
	return removed;
}

/*
 * Find the first attribute with the given tag
 */
static inline isns_attr_t *
__isns_attr_list_find(const isns_attr_list_t *list, uint32_t tag)
{
	isns_attr_t	*attr;
	unsigned int	i;

	for (i = 0; i < list->ial_count; ++i) {
		attr = list->ial_data[i];

		if (attr->ia_tag_id == tag)
			return attr;
	}

	return NULL;
}

/*
 * Add a new attribute at the end of the list
 */
static inline void
__isns_attr_list_append_attr(isns_attr_list_t *list, isns_attr_t *attr)
{
	__isns_attr_list_resize(list, list->ial_count + 1);
	list->ial_data[list->ial_count++] = attr;
}

void
isns_attr_list_append_attr(isns_attr_list_t *list, isns_attr_t *attr)
{
	attr->ia_users++;
	__isns_attr_list_append_attr(list, attr);
}

/*
 * Append an element to an attribute list
 */
static void
__isns_attr_list_append(isns_attr_list_t *list,
		uint32_t tag, const isns_tag_type_t *tag_type,
		const isns_value_t *value)
{
	isns_attr_t	 *attr;

	if (tag_type == NULL)
		tag_type = isns_tag_type_by_id(tag);
	if (value->iv_type != &isns_attr_type_nil
	 && value->iv_type != tag_type->it_type) {
		isns_warning("Using wrong type (%s) "
			"when encoding attribute %04x (%s) - should be %s\n",
			value->iv_type->it_name,
			tag, tag_type->it_name,
			tag_type->it_type->it_name);
	}

	attr = isns_attr_alloc(tag, tag_type, value);
	__isns_attr_list_append_attr(list, attr);
}

/*
 * Update an element to an attribute list
 */
static void
__isns_attr_list_update(isns_attr_list_t *list,
		uint32_t tag, const isns_tag_type_t *tag_type,
		const isns_value_t *value)
{
	const isns_attr_type_t *type = value->iv_type;
	isns_attr_t	 *attr;

	if (tag_type == NULL)
		tag_type = isns_tag_type_by_id(tag);
	if (type != &isns_attr_type_nil
	 && type != tag_type->it_type) {
		isns_warning("Using wrong type (%s) "
			"when encoding attribute %04x (%s) - should be %s\n",
			type->it_name,
			tag, tag_type->it_name,
			tag_type->it_type->it_name);
	}

	if (tag_type->it_multiple
	 || (attr = __isns_attr_list_find(list, tag)) == NULL) {
		attr = isns_attr_alloc(tag, tag_type, NULL);
		__isns_attr_list_append_attr(list, attr);
	}

	__isns_attr_set_value(attr, value);
}

/*
 * Append an element to an attribute list - public interface
 */
void
isns_attr_list_append_value(isns_attr_list_t *list,
		uint32_t tag, const isns_tag_type_t *tag_type,
		const isns_value_t *value)
{
	__isns_attr_list_append(list, tag, tag_type, value);
}

/*
 * Update an element of an attribute list - public interface
 */
void
isns_attr_list_update_value(isns_attr_list_t *list,
		uint32_t tag, const isns_tag_type_t *tag_type,
		const isns_value_t *value)
{
	__isns_attr_list_update(list, tag, tag_type, value);
}

void
isns_attr_list_update_attr(isns_attr_list_t *list,
		const isns_attr_t *attr)
{
	__isns_attr_list_update(list, attr->ia_tag_id,
			attr->ia_tag, &attr->ia_value);
}

/*
 * Replace an attribute on a list
 */
int
isns_attr_list_replace_attr(isns_attr_list_t *list,
		isns_attr_t *attr)
{
	unsigned int	i;

	for (i = 0; i < list->ial_count; ++i) {
		isns_attr_t	*other = list->ial_data[i];

		if (other->ia_tag_id == attr->ia_tag_id) {
			list->ial_data[i] = attr;
			attr->ia_users++;
			isns_attr_release(other);
			return 1;
		}
	}
	return 0;
}

/*
 * Retrieve an element of an attribute list
 */
int
isns_attr_list_get_attr(const isns_attr_list_t *list,
		uint32_t tag, isns_attr_t **result)
{
	*result = __isns_attr_list_find(list, tag);
	return *result != NULL;
}

int
isns_attr_list_get_value(const isns_attr_list_t *list,
		uint32_t tag, isns_value_t *value)
{
	isns_attr_t	*attr;

	if (!(attr = __isns_attr_list_find(list, tag)))
		return 0;

	*value = attr->ia_value;
	return 1;
}

int
isns_attr_list_get_uint32(const isns_attr_list_t *list,
		uint32_t tag, uint32_t *value)
{
	isns_attr_t	*attr;

	if (!(attr = __isns_attr_list_find(list, tag))
	 || !ISNS_ATTR_IS_UINT32(attr))
		return 0;

	*value = attr->ia_value.iv_uint32;
	return 1;
}

int
isns_attr_list_get_ipaddr(const isns_attr_list_t *list,
		uint32_t tag, struct in6_addr *value)
{
	isns_attr_t	*attr;

	if (!(attr = __isns_attr_list_find(list, tag))
	 || !ISNS_ATTR_IS_IPADDR(attr))
		return 0;

	*value = attr->ia_value.iv_ipaddr;
	return 1;
}

int
isns_attr_list_get_string(const isns_attr_list_t *list,
		uint32_t tag, const char **value)
{
	isns_attr_t	*attr;

	if (!(attr = __isns_attr_list_find(list, tag))
	 || !ISNS_ATTR_IS_STRING(attr))
		return 0;

	*value = attr->ia_value.iv_string;
	return 1;
}

int
isns_attr_list_contains(const isns_attr_list_t *list,
		uint32_t tag)
{
	return __isns_attr_list_find(list, tag) != NULL;
}

/*
 * Some attribute types have an implied ordering,
 * which is needed for GetNext. This is used to
 * compare two lists.
 */

/*
 * Typed versions of isns_attr_list_append
 */
void
isns_attr_list_append_nil(isns_attr_list_t *list, uint32_t tag)
{
	isns_value_t var = ISNS_VALUE_INIT(nil, 0);

	__isns_attr_list_append(list, tag, NULL, &var);
}

void
isns_attr_list_append_string(isns_attr_list_t *list,
			uint32_t tag, const char *value)
{
	isns_value_t var = ISNS_VALUE_INIT(string, (char *) value);

	__isns_attr_list_append(list, tag, NULL, &var);
}

void
isns_attr_list_append_uint32(isns_attr_list_t *list,
			uint32_t tag, uint32_t value)
{
	isns_value_t var = ISNS_VALUE_INIT(uint32, value);

	__isns_attr_list_append(list, tag, NULL, &var);
}

void
isns_attr_list_append_int32(isns_attr_list_t *list,
			uint32_t tag, int32_t value)
{
	isns_value_t var = ISNS_VALUE_INIT(int32, value);

	__isns_attr_list_append(list, tag, NULL, &var);
}

void
isns_attr_list_append_uint64(isns_attr_list_t *list,
			uint32_t tag, int64_t value)
{
	isns_value_t var = ISNS_VALUE_INIT(uint64, value);

	__isns_attr_list_append(list, tag, NULL, &var);
}

void
isns_attr_list_append_ipaddr(isns_attr_list_t *list,
			uint32_t tag, const struct in6_addr *value)
{
	isns_value_t var = ISNS_VALUE_INIT(ipaddr, *value);

	__isns_attr_list_append(list, tag, NULL, &var);
}

/*
 * Untyped version of isns_attr_list_append and isns_attr_list_update.
 * The caller must make sure that the type of @data matches the tag's type.
 */
int
isns_attr_list_append(isns_attr_list_t *list, uint32_t tag, const void *data)
{
	const isns_tag_type_t *tag_type;
	isns_value_t var;

	if (!(tag_type = isns_tag_type_by_id(tag)))
		return 0;

	var.iv_type = tag_type->it_type;
	if (!var.iv_type->it_set(&var, data))
		return 0;

	__isns_attr_list_append(list, tag, tag_type, &var);
	return 1;
}

int
isns_attr_list_update(isns_attr_list_t *list, uint32_t tag, const void *data)
{
	const isns_tag_type_t *tag_type;
	isns_attr_type_t *type;
	isns_value_t var;

	if (!(tag_type = isns_tag_type_by_id(tag)))
		return 0;

	type = tag_type->it_type;
	var.iv_type = type;
	if (!type->it_set(&var, data))
		return 0;

	__isns_attr_list_update(list, tag, tag_type, &var);
	return 1;
}

/*
 * Validate the attribute list.
 */
int
isns_attr_validate(const isns_attr_t *attr,
		const isns_policy_t *policy)
{
	const isns_tag_type_t *tag_type;

	tag_type = attr->ia_tag;
	if (tag_type->it_validate == NULL)
		return 1;
	return tag_type->it_validate(&attr->ia_value, policy);
}

int
isns_attr_list_validate(const isns_attr_list_t *list,
			const isns_policy_t *policy,
			unsigned int function)
{
	DECLARE_BITMAP(seen, __ISNS_TAG_MAX);
	unsigned int	i;

	for (i = 0; i < list->ial_count; ++i) {
		const isns_tag_type_t *tag_type;
		isns_attr_t	*attr = list->ial_data[i];
		uint32_t	tag = attr->ia_tag_id;
		unsigned int	bit;

		if (attr == NULL)
			return ISNS_INTERNAL_ERROR;

		tag_type = attr->ia_tag;
		if (tag_type == NULL)
			return ISNS_INTERNAL_ERROR;

		bit = tag;
		if (OPENISNS_IS_PRIVATE_ATTR(tag))
			bit -= OPENISNS_VENDOR_PREFIX;
		if (bit >= __ISNS_TAG_MAX)
			goto invalid;

		if (attr->ia_value.iv_type == &isns_attr_type_nil) {
			if (test_bit(seen, bit))
				goto invalid;
		} else
		if (attr->ia_value.iv_type == tag_type->it_type) {
			if (!tag_type->it_multiple && test_bit(seen, bit))
				goto invalid;

			if (!isns_attr_validate(attr, policy))
				goto invalid;
		} else {
			return ISNS_INTERNAL_ERROR;
		}

		if (function == ISNS_DEVICE_ATTRIBUTE_REGISTER
		 && tag_type->it_readonly)
			goto invalid;

		set_bit(seen, bit);
	}

	return ISNS_SUCCESS;

invalid:
	switch (function) {
	case ISNS_DEVICE_ATTRIBUTE_REGISTER:
		return ISNS_INVALID_REGISTRATION;

	case ISNS_DEVICE_DEREGISTER:
		return ISNS_INVALID_DEREGISTRATION;

	case ISNS_DEVICE_ATTRIBUTE_QUERY:
	case ISNS_DEVICE_GET_NEXT:
		return ISNS_INVALID_QUERY;
	}
	return ISNS_ATTRIBUTE_NOT_IMPLEMENTED;
}

/*
 * Debug helper: print attribute list
 */
void
isns_attr_list_print(const isns_attr_list_t *list, isns_print_fn_t *fn)
{
	unsigned int	i;

	for (i = 0; i < list->ial_count; ++i)
		isns_attr_print(list->ial_data[i], fn);
}

char *
isns_attr_print_value(const isns_attr_t *attr, char *buffer, size_t size)
{
	const isns_tag_type_t *tag_type = attr->ia_tag;
	const isns_attr_type_t *type = attr->ia_value.iv_type;

	if (tag_type->it_print && type == tag_type->it_type)
		tag_type->it_print(&attr->ia_value, buffer, size);
	else
		type->it_print(&attr->ia_value, buffer, size);
	return buffer;
}

void
isns_attr_print(const isns_attr_t *attr, isns_print_fn_t *fn)
{
	const isns_tag_type_t *tag_type = attr->ia_tag;
	const isns_attr_type_t *type = attr->ia_value.iv_type;
	uint32_t	tag;
	char		value[512], *vspec = "";

	tag = attr->ia_tag_id;
	if (OPENISNS_IS_PRIVATE_ATTR(tag)) {
		tag -= OPENISNS_VENDOR_PREFIX;
		vspec = "v";
	}

	fn("  %04x%1s %-12s: %s = %s\n",
			tag, vspec,
			type->it_name,
			tag_type? tag_type->it_name : "Unknown Attribute",
			isns_attr_print_value(attr, value, sizeof(value)));
}

/*
 * TLV encode a single attribute
 */
int
isns_attr_encode(buf_t *bp, const isns_attr_t *attr)
{
	const isns_value_t *value = &attr->ia_value;
	const isns_attr_type_t *type = value->iv_type;

	if (!buf_put32(bp, attr->ia_tag_id)
	 || !type->it_encode(bp, value))
		return ISNS_INTERNAL_ERROR;

	return ISNS_SUCCESS;
}

/*
 * TLV decode a single attribute
 */
int
isns_attr_decode(buf_t *bp, isns_attr_t **result)
{
	isns_attr_t	*attr = NULL;
	isns_value_t	*value;
	uint32_t	tag, len;

	if (!buf_get32(bp, &tag)
	 || !buf_get32(bp, &len))
		goto msg_fmt_error;

	/* Attributes MUST be word aligned */
	if (len & 3)
		goto msg_fmt_error;

	if (len > ISNS_ATTR_MAX_LEN)
		goto msg_fmt_error;

	/* Allocate the attribute */
	attr = isns_attr_alloc(tag, NULL, NULL);

	value = &attr->ia_value;
	if (len == 0)
		value->iv_type = &isns_attr_type_nil;

	if (!value->iv_type->it_decode(bp, len, value))
		goto msg_fmt_error;

	*result = attr;
	return ISNS_SUCCESS;

msg_fmt_error:
	isns_error("Error decoding attribute, tag=0x%04x, len=%u\n",
				tag, len);
	if (attr)
		isns_attr_release(attr);
	return ISNS_MESSAGE_FORMAT_ERROR;
}


/*
 * Decode the list of TLV encoded attributes inside an
 * iSNS message.
 */
static int
__isns_attr_list_decode(buf_t *bp, isns_attr_list_t *list, int delimited)
{
	int	status;

	while (buf_avail(bp)) {
		isns_attr_t	*attr;

		status = isns_attr_decode(bp, &attr);
		if (status != ISNS_SUCCESS)
			return status;

		if (delimited && attr->ia_tag_id == ISNS_TAG_DELIMITER) {
			isns_attr_release(attr);
			break;
		}

		__isns_attr_list_append_attr(list, attr);
	}

	return ISNS_SUCCESS;
}

int
isns_attr_list_decode(buf_t *bp, isns_attr_list_t *list)
{
	return __isns_attr_list_decode(bp, list, 0);
}

int
isns_attr_list_decode_delimited(buf_t *bp, isns_attr_list_t *list)
{
	return __isns_attr_list_decode(bp, list, 1);
}

/*
 * Remove all attributes from a list save those matching
 * the given tags.
 */
void
isns_attr_list_prune(isns_attr_list_t *list,
		const uint32_t *tags, unsigned int num_tags)
{
	unsigned int	i, j, k;

	for (i = j = 0; i < list->ial_count; ++i) {
		isns_attr_t *attr = list->ial_data[i];

		for (k = 0; k < num_tags; ++k) {
			if (attr->ia_tag_id == tags[k]) {
				list->ial_data[j++] = attr;
				goto next;
			}
		}

		isns_attr_release(attr);

next:		;
	}

	list->ial_count = j;
}

/*
 * TLV ecode the list of attributes to go with
 * iSNS message.
 */
int
isns_attr_list_encode(buf_t *bp, const isns_attr_list_t *list)
{
	unsigned int	i, status = ISNS_SUCCESS;

	for (i = 0; i < list->ial_count; ++i) {
		struct isns_attr *attr = list->ial_data[i];

		status = isns_attr_encode(bp, attr);
		if (status)
			break;
	}
	return status;
}

/*
 * Encode the delimiter attribute
 */
int
isns_encode_delimiter(buf_t *bp)
{
	uint32_t tag = 0, len = 0;

	if (!buf_put32(bp, tag)
	 || !buf_put32(bp, len))
		return ISNS_INTERNAL_ERROR;

	return ISNS_SUCCESS;
}

/*
 * Padded encoding
 */
static inline int
isns_encode_padded(buf_t *bp, const void *ptr, size_t len)
{
	if (!buf_put(bp, ptr, len))
		return 0;

	if ((len & 3) == 0)
		return 1;

	return buf_put(bp, "\0\0\0", 4 - (len & 3));
}

/*
 * Helper functions to deal with portal information
 */
void
isns_portal_init(isns_portal_info_t *portal,
		const struct sockaddr *saddr, int proto)
{
	const struct sockaddr_in *sin;

	memset(portal, 0, sizeof(*portal));
	switch (saddr->sa_family) {
	case AF_INET6:
		portal->addr = *(const struct sockaddr_in6 *) saddr;
		break;

	case AF_INET:
		sin = (const struct sockaddr_in *) saddr;
		portal->addr.sin6_addr.s6_addr32[3] = sin->sin_addr.s_addr;
		portal->addr.sin6_port = sin->sin_port;
		portal->addr.sin6_family = AF_INET6;
		break;
	default:
		isns_warning("Unknown address family in isns_portal_init\n");
		return;
	}

	portal->proto = proto;
}

int
isns_portal_from_attr_list(isns_portal_info_t *portal,
				uint32_t addr_tag, uint32_t port_tag,
				const isns_attr_list_t *list)
{
	const isns_attr_t *addr_attr = NULL, *port_attr = NULL;
	unsigned int	i;

	for (i = 0; i + 1 < list->ial_count; ++i) {
		const isns_attr_t *attr = list->ial_data[i];

		if (!ISNS_ATTR_IS_IPADDR(attr))
			continue;
		if (addr_tag && attr->ia_tag_id != addr_tag)
			continue;
		addr_attr = attr;
		if (port_tag == 0) {
			port_attr = list->ial_data[i + 1];
			goto extract_portal;
		}
		break;
	}

	/* We have a specific port tag. */
	while (++i < list->ial_count) {
		const isns_attr_t *attr = list->ial_data[i];

		if (attr->ia_tag_id == port_tag) {
			port_attr = attr;
			goto extract_portal;
		}
	}

	return 0;

extract_portal:
	return isns_portal_from_attr_pair(portal,
				addr_attr, port_attr);
}

int
isns_portal_from_attr_pair(isns_portal_info_t *portal,
				const isns_attr_t *addr_attr,
				const isns_attr_t *port_attr)
{
	uint32_t	portspec;

	memset(portal, 0, sizeof(*portal));
	portal->addr.sin6_family = AF_INET6;

	if (!ISNS_ATTR_IS_IPADDR(addr_attr)
	 || !ISNS_ATTR_IS_UINT32(port_attr))
		return 0;

	portal->addr.sin6_addr = addr_attr->ia_value.iv_ipaddr;

	portspec = port_attr->ia_value.iv_uint32;
	portal->addr.sin6_port = htons(portspec & 0xffff);
	portal->proto = (portspec & ISNS_PORTAL_PORT_UDP_MASK)? IPPROTO_UDP : IPPROTO_TCP;

	return 1;
}

int
isns_portal_to_attr_list(const isns_portal_info_t *portal,
				uint32_t addr_tag, uint32_t port_tag,
				isns_attr_list_t *list)
{
	uint32_t	portspec;

	portspec = htons(portal->addr.sin6_port);
	if (portal->proto == IPPROTO_UDP)
		portspec |= ISNS_PORTAL_PORT_UDP_MASK;

	{
		isns_value_t addr_value = ISNS_VALUE_INIT(ipaddr, portal->addr.sin6_addr);
		isns_value_t port_value = ISNS_VALUE_INIT(uint32, portspec);

		isns_attr_list_update_value(list, addr_tag, NULL, &addr_value);
		isns_attr_list_update_value(list, port_tag, NULL, &port_value);
	}

	return 1;
}

const char *
isns_portal_string(const isns_portal_info_t *portal)
{
	const struct sockaddr_in6 *six = &portal->addr;
	static char	buffer[128];
	char		abuf[128];

	inet_ntop(six->sin6_family, &six->sin6_addr, abuf, sizeof(abuf));
	snprintf(buffer, sizeof(buffer), "[%s]:%d/%s",
			abuf, ntohs(six->sin6_port),
			(portal->proto == IPPROTO_UDP)? "udp" : "tcp");
	return buffer;
}

int
isns_portal_is_wildcard(const isns_portal_info_t *portal)
{
	return !memcmp(&portal->addr.sin6_addr,
			&in6addr_any,
			sizeof(struct in6_addr));
}

int
isns_portal_equal(const isns_portal_info_t *a,
		const isns_portal_info_t *b)
{
	if (a->proto != b->proto)
		return 0;
	return !memcmp(&a->addr, &b->addr, sizeof(a->addr));
}

uint32_t
isns_portal_tcpudp_port(const isns_portal_info_t *portal)
{
	uint32_t	port;

	port = isns_addr_get_port((const struct sockaddr *) &portal->addr);
	if (portal->proto == IPPROTO_UDP)
		port |= ISNS_PORTAL_PORT_UDP_MASK;
	return port;
}

int
isns_portal_parse(isns_portal_info_t *portal,
			const char *spec,
			const char *default_port)
{
	struct sockaddr_storage addr;
	char	*copy, *psp;
	int	alen, proto = IPPROTO_TCP, sock_type = SOCK_STREAM;

	if (spec[0] == '/') {
		isns_warning("%s: no AF_LOCAL addresses for portals!\n",
				__FUNCTION__);
		return 0;
	}

	/* Look at trailing /tcp or /udp */
	copy = isns_strdup(spec);
	if ((psp = strrchr(copy, '/')) != NULL) {
		if (!strcasecmp(psp, "/udp")) {
			sock_type = SOCK_DGRAM;
			proto = IPPROTO_UDP;
			*psp = '\0';
		} else
		if (!strcasecmp(psp, "/tcp")) {
			sock_type = SOCK_STREAM;
			proto = IPPROTO_TCP;
			*psp = '\0';
		}
	}

	alen = isns_get_address(&addr, copy, default_port, 0, sock_type, 0);
	isns_free(copy);

	if (alen < 0)
		return 0;

	isns_portal_init(portal, (struct sockaddr *) &addr, proto);
	return 1;
}

/*
 * Attribute type NIL
 */
static int
isns_attr_type_nil_encode(buf_t *bp, const isns_value_t *value)
{
	return buf_put32(bp, 0);
}

static int
isns_attr_type_nil_decode(buf_t *bp, size_t len, isns_value_t *value)
{
	return len == 0;
}

static void
isns_attr_type_nil_print(const isns_value_t *value, char *buf, size_t size)
{
	snprintf(buf, size, "<empty>");
}

static int
isns_attr_type_nil_parse(isns_value_t *value, const char *string)
{
	if (string && *string)
		return 0;
	return 1;
}

isns_attr_type_t isns_attr_type_nil = {
	.it_id		= ISNS_ATTR_TYPE_NIL,
	.it_name	= "nil",
	.it_encode	= isns_attr_type_nil_encode,
	.it_decode	= isns_attr_type_nil_decode,
	.it_print	= isns_attr_type_nil_print,
	.it_parse	= isns_attr_type_nil_parse,
};

/*
 * Attribute type UINT32
 */
static int
isns_attr_type_uint32_encode(buf_t *bp, const isns_value_t *value)
{
	return buf_put32(bp, 4) && buf_put32(bp, value->iv_uint32);
}

static int
isns_attr_type_uint32_decode(buf_t *bp, size_t len, isns_value_t *value)
{
	if (len != 4)
		return 0;
	return buf_get32(bp, &value->iv_uint32);
}

static void
isns_attr_type_uint32_print(const isns_value_t *value, char *buf, size_t size)
{
	snprintf(buf, size, "%u", value->iv_uint32);
}

static int
isns_attr_type_uint32_parse(isns_value_t *value, const char *string)
{
	char	*end;

	value->iv_uint32 = strtoul(string, &end, 0);
	return *end == '\0';
}

static void
isns_attr_type_int32_print(const isns_value_t *value, char *buf, size_t size)
{
	snprintf(buf, size, "%d", value->iv_uint32);
}

static int
isns_attr_type_int32_parse(isns_value_t *value, const char *string)
{
	char	*end;

	value->iv_int32 = strtol(string, &end, 0);
	return *end == '\0';
}

isns_attr_type_t isns_attr_type_uint32 = {
	.it_id		= ISNS_ATTR_TYPE_UINT32,
	.it_name	= "uint32",
	.it_encode	= isns_attr_type_uint32_encode,
	.it_decode	= isns_attr_type_uint32_decode,
	.it_print	= isns_attr_type_uint32_print,
	.it_parse	= isns_attr_type_uint32_parse,
};

isns_attr_type_t isns_attr_type_int32 = {
	.it_id		= ISNS_ATTR_TYPE_INT32,
	.it_name	= "int32",
	.it_encode	= isns_attr_type_uint32_encode,
	.it_decode	= isns_attr_type_uint32_decode,
	.it_print	= isns_attr_type_int32_print,
	.it_parse	= isns_attr_type_int32_parse,
};

/*
 * 16bit min/max
 */
static int
isns_attr_type_range16_encode(buf_t *bp, const isns_value_t *value)
{
	uint32_t	word;

	word = (value->iv_range.max << 16) | value->iv_range.min;
	return buf_put32(bp, 4) && buf_put32(bp, word);
}

static int
isns_attr_type_range16_decode(buf_t *bp, size_t len, isns_value_t *value)
{
	uint32_t	word;

	if (len != 4)
		return 0;
	if (!buf_get32(bp, &word))
		return 0;
	value->iv_range.max = word >> 16;
	value->iv_range.min = word & 0xFFFF;
	return 1;
}

static void
isns_attr_type_range16_print(const isns_value_t *value, char *buf, size_t size)
{
	snprintf(buf, size, "[%u, %u]", value->iv_range.min, value->iv_range.max);
}

isns_attr_type_t isns_attr_type_range16 = {
	.it_id		= ISNS_ATTR_TYPE_RANGE16,
	.it_name	= "range16",
	.it_encode	= isns_attr_type_range16_encode,
	.it_decode	= isns_attr_type_range16_decode,
	.it_print	= isns_attr_type_range16_print,
//	.it_parse	= isns_attr_type_range16_parse,
};


/*
 * 64bit integers
 */
static int
isns_attr_type_uint64_encode(buf_t *bp, const isns_value_t *value)
{
	return buf_put32(bp, 8) && buf_put64(bp, value->iv_uint64);
}

static int
isns_attr_type_uint64_decode(buf_t *bp, size_t len, isns_value_t *value)
{
	if (len != 8)
		return 0;
	return buf_get64(bp, &value->iv_uint64);
}

static void
isns_attr_type_uint64_print(const isns_value_t *value, char *buf, size_t size)
{
	snprintf(buf, size, "%Lu", (unsigned long long) value->iv_uint64);
}

static int
isns_attr_type_uint64_parse(isns_value_t *value, const char *string)
{
	char	*end;

	value->iv_uint64 = strtoull(string, &end, 0);
	return *end == '\0';
}

isns_attr_type_t isns_attr_type_uint64 = {
	.it_id		= ISNS_ATTR_TYPE_UINT64,
	.it_name	= "uint64",
	.it_encode	= isns_attr_type_uint64_encode,
	.it_decode	= isns_attr_type_uint64_decode,
	.it_print	= isns_attr_type_uint64_print,
	.it_parse	= isns_attr_type_uint64_parse,
};

/*
 * Attribute type STRING
 */
static void
isns_attr_type_string_destroy(isns_value_t *value)
{
	isns_free(value->iv_string);
	value->iv_string = NULL;
}

static int
isns_attr_type_string_match(const isns_value_t *a, const isns_value_t *b)
{
	if (a->iv_string && b->iv_string)
		return !strcmp(a->iv_string, b->iv_string);

	return a->iv_string == b->iv_string;
}

static int
isns_attr_type_string_compare(const isns_value_t *a, const isns_value_t *b)
{
	if (a->iv_string && b->iv_string)
		return strcmp(a->iv_string, b->iv_string);

	return a->iv_string? 1 : -1;
}

static int
isns_attr_type_string_encode(buf_t *bp, const isns_value_t *value)
{
	uint32_t	len;

	len = value->iv_string? strlen(value->iv_string) + 1 : 0;

	if (!buf_put32(bp, ISNS_PAD(len)))
		return 0;

	if (len && !isns_encode_padded(bp, value->iv_string, len))
		return 0;

	return 1;
}

static int
isns_attr_type_string_decode(buf_t *bp, size_t len, isns_value_t *value)
{
	/* Is this legal? */
	if (len == 0)
		return 1;

	/* The string should be NUL terminated, but
	 * better be safe than sorry. */
	value->iv_string = isns_malloc(len + 1);
	if (!buf_get(bp, value->iv_string, len)) {
		isns_free(value->iv_string);
		return 0;
	}
	value->iv_string[len] = '\0';
	return 1;
}

static void
isns_attr_type_string_print(const isns_value_t *value, char *buf, size_t size)
{
	if (!value->iv_string)
		snprintf(buf, size, "(empty)");
	else
		snprintf(buf, size, "\"%s\"", value->iv_string);
}

static int
isns_attr_type_string_parse(isns_value_t *value, const char *string)
{
	value->iv_string = isns_strdup(string);
	return 1;
}

static void
isns_attr_type_string_assign(isns_value_t *value, const isns_value_t *new_value)
{
	isns_assert(!value->iv_string);
	if (new_value->iv_string)
		value->iv_string = isns_strdup(new_value->iv_string);
}

isns_attr_type_t isns_attr_type_string = {
	.it_id		= ISNS_ATTR_TYPE_STRING,
	.it_name	= "string",
	.it_assign	= isns_attr_type_string_assign,
	.it_destroy	= isns_attr_type_string_destroy,
	.it_match	= isns_attr_type_string_match,
	.it_compare	= isns_attr_type_string_compare,
	.it_encode	= isns_attr_type_string_encode,
	.it_decode	= isns_attr_type_string_decode,
	.it_print	= isns_attr_type_string_print,
	.it_parse	= isns_attr_type_string_parse,
};

/*
 * Attribute type IPADDR
 */
static int
isns_attr_type_ipaddr_encode(buf_t *bp, const isns_value_t *value)
{
	if (!buf_put32(bp, 16)
	 || !buf_put(bp, &value->iv_ipaddr, 16))
		return 0;

	return 1;
}

static int
isns_attr_type_ipaddr_decode(buf_t *bp, size_t len, isns_value_t *value)
{
	if (len != 16)
		return 0;

	return buf_get(bp, &value->iv_ipaddr, 16);
}

static void
isns_attr_type_ipaddr_print(const isns_value_t *value, char *buf, size_t size)
{
	const struct in6_addr *addr = &value->iv_ipaddr;
	char	buffer[INET6_ADDRSTRLEN + 1];

	/* The standard requires IPv4 mapping, but
	 * some oldish implementations seem to use
	 * IPv4 compatible addresss. */
	if (IN6_IS_ADDR_V4MAPPED(addr) || IN6_IS_ADDR_V4COMPAT(addr)) {
		struct in_addr ipv4;

		ipv4.s_addr = addr->s6_addr32[3];
		inet_ntop(AF_INET, &ipv4, buffer, sizeof(buffer));
	} else {
		inet_ntop(AF_INET6, addr, buffer, sizeof(buffer));
	}
	snprintf(buf, size, "%s", buffer);
}

static int
isns_attr_type_ipaddr_parse(isns_value_t *value, const char *string)
{
	struct in_addr	addr4;

	if (inet_pton(AF_INET, string, &addr4)) {
		value->iv_ipaddr = in6addr_any;
		value->iv_ipaddr.s6_addr32[3] = addr4.s_addr;
		return 1;
	}

	return inet_pton(AF_INET6, string, &value->iv_ipaddr);
}

isns_attr_type_t isns_attr_type_ipaddr = {
	.it_id		= ISNS_ATTR_TYPE_IPADDR,
	.it_name	= "ipaddr",
	.it_encode	= isns_attr_type_ipaddr_encode,
	.it_decode	= isns_attr_type_ipaddr_decode,
	.it_print	= isns_attr_type_ipaddr_print,
	.it_parse	= isns_attr_type_ipaddr_parse,
};

/*
 * Attribute type OPAQUE
 */
static void
isns_attr_type_opaque_assign(isns_value_t *value, const isns_value_t *new_value)
{
	size_t new_len = new_value->iv_opaque.len;
	isns_assert(value->iv_opaque.len == 0);
	if (new_len) {
		value->iv_opaque.ptr = isns_malloc(new_len);
		value->iv_opaque.len = new_len;
		memcpy(value->iv_opaque.ptr,
				new_value->iv_opaque.ptr,
				new_len);
	}
}

static void
isns_attr_type_opaque_destroy(isns_value_t *value)
{
	isns_free(value->iv_opaque.ptr);
	value->iv_opaque.ptr = NULL;
	value->iv_opaque.len = 0;
}

static int
isns_attr_type_opaque_match(const isns_value_t *a, const isns_value_t *b)
{
	if (a->iv_opaque.len != b->iv_opaque.len)
		return 0;
	return !memcmp(a->iv_opaque.ptr, b->iv_opaque.ptr, a->iv_opaque.len);
}

static int
isns_attr_type_opaque_compare(const isns_value_t *a, const isns_value_t *b)
{
	long	delta;

	delta = a->iv_opaque.len - b->iv_opaque.len;
	if (delta)
		return delta;

	return memcmp(a->iv_opaque.ptr, b->iv_opaque.ptr, a->iv_opaque.len);
}

static int
isns_attr_type_opaque_encode(buf_t *bp, const isns_value_t *value)
{
	uint32_t	len;

	len = value->iv_opaque.len;
	if (len & 3)
		return 0;

	if (!buf_put32(bp, len)
	 || !buf_put(bp, value->iv_opaque.ptr, len))
		return 0;

	return 1;
}

static int
isns_attr_type_opaque_decode(buf_t *bp, size_t len, isns_value_t *value)
{
	value->iv_opaque.ptr = isns_malloc(len);
	if (!buf_get(bp, value->iv_opaque.ptr, len)) {
		isns_free(value->iv_opaque.ptr);
		return 0;
	}

	value->iv_opaque.len = len;
	return 1;
}

static void
isns_attr_type_opaque_print(const isns_value_t *value, char *buf, size_t size)
{
	unsigned char	*data = value->iv_opaque.ptr;
	unsigned int	i, len;

	/* There must be room for "<...>\0" */
	if (size < 6)
		return;
	size -= 6;

	if ((len = value->iv_opaque.len) > 20)
		len = 20;
	if (size < 3 * len)
		len = size / 3;

	*buf++ = '<';
	for (i = 0; i < len; ++i) {
		if (i)
			*buf++ = ' ';
		sprintf(buf, "%02x", data[i]);
		buf += 2;
	}
	if (len < value->iv_opaque.len) {
		strcat(buf, "...");
		buf += 4;
	}
	*buf++ = '>';
	*buf++ = '\0';
}

isns_attr_type_t isns_attr_type_opaque = {
	.it_id		= ISNS_ATTR_TYPE_OPAQUE,
	.it_name	= "opaque",
	.it_assign	= isns_attr_type_opaque_assign,
	.it_destroy	= isns_attr_type_opaque_destroy,
	.it_match	= isns_attr_type_opaque_match,
	.it_compare	= isns_attr_type_opaque_compare,
	.it_encode	= isns_attr_type_opaque_encode,
	.it_decode	= isns_attr_type_opaque_decode,
	.it_print	= isns_attr_type_opaque_print,
};

/*
 * Map attribute type IDs to attribute types
 */
static isns_attr_type_t *
isns_attr_types_builtin[__ISNS_ATTR_TYPE_BUILTIN_MAX] = {
[ISNS_ATTR_TYPE_NIL]		= &isns_attr_type_nil,
[ISNS_ATTR_TYPE_OPAQUE]		= &isns_attr_type_opaque,
[ISNS_ATTR_TYPE_STRING]		= &isns_attr_type_string,
[ISNS_ATTR_TYPE_INT32]		= &isns_attr_type_int32,
[ISNS_ATTR_TYPE_UINT32]		= &isns_attr_type_uint32,
[ISNS_ATTR_TYPE_UINT64]		= &isns_attr_type_uint64,
[ISNS_ATTR_TYPE_IPADDR]		= &isns_attr_type_ipaddr,
[ISNS_ATTR_TYPE_RANGE16]	= &isns_attr_type_range16,
};

const isns_attr_type_t *
isns_attr_type_by_id(unsigned int id)
{
	if (id < __ISNS_ATTR_TYPE_BUILTIN_MAX)
		return isns_attr_types_builtin[id];

	/* TODO: handle dynamic registration of attrtypes
	 * for vendor extensions. */
	return NULL;
}
