/*
 * Common handling for iSNS message parsing
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 *
 */

#include <stdlib.h>
#include <string.h>
#include "isns.h"
#include "attrs.h"
#include "message.h"
#include "objects.h"
#include "security.h"
#include "socket.h"
#include "util.h"

typedef void isns_simple_callback_fn_t(uint32_t, int status, isns_simple_t *);

static int	isns_attr_list_scanner_get_pg(struct isns_attr_list_scanner *st);

/*
 * Allocate an empty simple message
 */
static isns_simple_t *
__isns_alloc_simple(void)
{
	isns_simple_t	*simp;

	simp = isns_calloc(1, sizeof(*simp));

	isns_attr_list_init(&simp->is_message_attrs);
	isns_attr_list_init(&simp->is_operating_attrs);

	return simp;
}

/*
 * Create a simple message, and set the source name
 */
isns_simple_t *
isns_simple_create(uint32_t function, isns_source_t *source,
		const isns_attr_list_t *key)
{
	isns_simple_t	*simp;

	simp = __isns_alloc_simple();
	simp->is_function = function;
	simp->is_source = source;
	if (source != NULL)
		source->is_users++;

	if (key)
		isns_attr_list_copy(&simp->is_message_attrs, key);

	return simp;
}

/*
 * Perform a call to the server, waiting for the response.
 */
int
isns_simple_call(isns_socket_t *sock, isns_simple_t **inout)
{
	isns_simple_t	*simp = *inout;
	isns_message_t	*msg, *resp;
	int		status;

	isns_simple_print(simp, isns_debug_message);

	status = isns_simple_encode(simp, &msg);
	if (status != ISNS_SUCCESS) {
		isns_error("Unable to encode %s: %s\n",
				isns_function_name(simp->is_function),
				isns_strerror(status));
		return status;
	}

	isns_debug_message("Sending request, len=%d\n",
			buf_avail(msg->im_payload));

	resp = isns_socket_call(sock, msg,
			isns_config.ic_network.call_timeout);
	isns_assert(msg->im_users == 1);
	isns_message_release(msg);

	if (resp == NULL) {
		isns_error("Timed out while waiting for reply\n");
		return ISNS_INTERNAL_ERROR;
	}

	isns_debug_message("Received reply, len=%d\n",
			buf_avail(resp->im_payload));
	isns_assert(resp->im_users == 1);

	status = isns_message_status(resp);
	if (status != ISNS_SUCCESS) {
		isns_message_release(resp);
		return status;
	}

	status = isns_simple_decode(resp, &simp);
	isns_message_release(resp);

	if (status) {
		isns_error("Unable to decode server response: %s (status 0x%04x)\n",
				isns_strerror(status), status);
		return status;
	}

	isns_simple_print(simp, isns_debug_message);

	isns_simple_free(*inout);
	*inout = simp;
	return ISNS_SUCCESS;
}

/*
 * This callback is invoked from the network layer when
 * we received a response to an async message
 */
static void
isns_simple_recv_response(isns_message_t *cmsg, isns_message_t *rmsg)
{
	isns_simple_callback_fn_t *user_callback;
	isns_simple_t	*resp = NULL;
	int		status = ISNS_INTERNAL_ERROR;

	/* rmsg being NULL means the call timed out. */
	if (rmsg == NULL)
		goto callback;

	status = isns_message_status(rmsg);
	if (status != ISNS_SUCCESS) {
		isns_error("Server flags error: %s (status 0x%04x)\n",
			    isns_strerror(status), status);
		goto callback;
	}

	status = isns_simple_decode(rmsg, &resp);
	if (status) {
		isns_error("Unable to decode server response: %s (status 0x%04x)\n",
				isns_strerror(status), status);
		resp = NULL;
		goto callback;
	}

	isns_simple_print(resp, isns_debug_message);

callback:
	user_callback = cmsg->im_calldata;
	if (user_callback)
		user_callback(cmsg->im_xid, status, resp);
	if (resp)
		isns_simple_free(resp);
}

/*
 * Transmit a call, without waiting for the response.
 */
int
isns_simple_transmit(isns_socket_t *sock, isns_simple_t *call,
			const isns_portal_info_t *dest,
			unsigned int timeout,
			isns_simple_callback_fn_t *user_callback)
{
	isns_message_t	*msg;
	int		status;

	isns_simple_print(call, isns_debug_message);

	status = isns_simple_encode(call, &msg);
	if (status != ISNS_SUCCESS) {
		isns_error("Unable to encode %s: %s\n",
				isns_function_name(call->is_function),
				isns_strerror(status));
		return status;
	}

	isns_debug_message("Sending message, len=%d\n",
			buf_avail(msg->im_payload));

	if (user_callback) {
		msg->im_callback = isns_simple_recv_response;
		msg->im_calldata = user_callback;
	}

	if (!isns_socket_submit(sock, msg, timeout))
		status = ISNS_INTERNAL_ERROR;
	isns_message_release(msg);
	return status;
}

/*
 * Delete the simple message object
 */
void
isns_simple_free(isns_simple_t *simp)
{
	if (simp == NULL)
		return;

	isns_attr_list_destroy(&simp->is_message_attrs);
	isns_attr_list_destroy(&simp->is_operating_attrs);
	isns_source_release(simp->is_source);
	isns_policy_release(simp->is_policy);
	isns_free(simp);
}

/*
 * Get the source associated with this simple message
 */
isns_source_t *
isns_simple_get_source(isns_simple_t *simp)
{
	return simp->is_source;
}

const isns_attr_list_t *
isns_simple_get_attrs(isns_simple_t *simp)
{
	return &simp->is_operating_attrs;
}

/*
 * Determine whether message includes a source attr.
 */
static inline int
isns_simple_include_source(uint16_t function)
{
	if (function & 0x8000)
		return 0;
	switch (function) {
	case ISNS_STATE_CHANGE_NOTIFICATION:
	case ISNS_ENTITY_STATUS_INQUIRY:
		return 0;
	}
	return 1;
}

/*
 * Decode a simple message
 */
int
isns_simple_decode(isns_message_t *msg, isns_simple_t **result)
{
	isns_simple_t	*simp = __isns_alloc_simple();
	buf_t		*bp = msg->im_payload;
	int		status = ISNS_SUCCESS;

	simp->is_function = msg->im_header.i_function;
	simp->is_xid = msg->im_xid;

	if (isns_simple_include_source(simp->is_function)) {
		status = isns_source_decode(bp, &simp->is_source);
		if (status != ISNS_SUCCESS)
			goto out;
	}

	switch (simp->is_function & 0x7FFF) {
	case ISNS_ENTITY_STATUS_INQUIRY:
	case ISNS_STATE_CHANGE_NOTIFICATION:
		/* Server messages do not include a source */
		status = isns_attr_list_decode(bp,
				&simp->is_message_attrs);
		break;

	default:
		status = isns_attr_list_decode_delimited(bp,
				&simp->is_message_attrs);
		if (status == ISNS_SUCCESS)
			status = isns_attr_list_decode(bp,
				&simp->is_operating_attrs);
	}

	if (msg->im_header.i_flags & ISNS_F_REPLACE)
		simp->is_replace = 1;

out:
	if (status == ISNS_SUCCESS) {
		*result = simp;
	} else {
		isns_simple_free(simp);
		*result = NULL;
	}
	return status;
}

/*
 * Encode a simple message reply or response
 */
static int
__isns_simple_encode(isns_simple_t *simp, buf_t *bp)
{
	int	status = ISNS_SUCCESS;

	if (isns_simple_include_source(simp->is_function)) {
		if (simp->is_source == NULL) {
			isns_error("Cannot encode %s message - caller forgot to set source\n",
				  isns_function_name(simp->is_function));
			return ISNS_SOURCE_UNKNOWN;
		}
		status = isns_source_encode(bp, simp->is_source);
	}

	if (status == ISNS_SUCCESS)
		status = isns_attr_list_encode(bp, &simp->is_message_attrs);

	/* Some functions have just one set of attrs. */
	switch (simp->is_function & 0x7fff) {
	/* It's not entirely clear which calls actually have the delimiter.
	 * The spec is sometimes a little vague on this. */
	case ISNS_SCN_DEREGISTER:
	case ISNS_ENTITY_STATUS_INQUIRY:
	case ISNS_STATE_CHANGE_NOTIFICATION:
		break;

	default:
		if (status == ISNS_SUCCESS)
			status = isns_encode_delimiter(bp);
		if (status == ISNS_SUCCESS)
			status = isns_attr_list_encode(bp, &simp->is_operating_attrs);
		break;
	}

	return status;
}

int
isns_simple_encode(isns_simple_t *simp, isns_message_t **result)
{
	isns_message_t *msg;
	int status, flags;

	flags = ISNS_F_CLIENT;
	if (simp->is_replace)
		flags |= ISNS_F_REPLACE;
	msg = isns_create_message(simp->is_function, flags);

	/* FIXME: for UDP sockets, isns_simple_t may contain a
	   destination address. */

	status = __isns_simple_encode(simp, msg->im_payload);
	if (status != ISNS_SUCCESS) {
		isns_message_release(msg);
		msg = NULL;
	}

	/* Report the XID to the caller */
	simp->is_xid = msg->im_xid;

	*result = msg;
	return status;
}

int
isns_simple_encode_response(isns_simple_t *reg,
		const isns_message_t *request, isns_message_t **result)
{
	isns_message_t *msg;
	int status;

	msg = isns_create_reply(request);

	status = __isns_simple_encode(reg, msg->im_payload);
	if (status != ISNS_SUCCESS) {
		isns_message_release(msg);
		msg = NULL;
	}

	*result = msg;
	return status;
}

int
isns_simple_decode_response(isns_message_t *resp, isns_simple_t **result)
{
	return isns_simple_decode(resp, result);
}

/*
 * Extract the list of objects from a DevAttrReg/DevAttrQry
 * response or similar.
 */
int
isns_simple_response_get_objects(isns_simple_t *resp,
		isns_object_list_t *result)
{
	struct isns_attr_list_scanner state;
	int	status = ISNS_SUCCESS;

	isns_attr_list_scanner_init(&state, NULL, &resp->is_operating_attrs);
	while (1) {
		isns_object_t	*obj;

		status = isns_attr_list_scanner_next(&state);
		if (status == ISNS_NO_SUCH_ENTRY) {
			status = ISNS_SUCCESS;
			break;
		}
		if (status)
			break;

		obj = isns_create_object(state.tmpl, &state.keys, NULL);

		isns_object_set_attrlist(obj, &state.attrs);
		if (obj != state.key_obj)
			isns_object_list_append(result, obj);
		isns_object_release(obj);
	}

	isns_attr_list_scanner_destroy(&state);
	return status;
}

/*
 * Print a simple message object
 */
void
isns_simple_print(isns_simple_t *simp, isns_print_fn_t *fn)
{
	char	buffer[256];

	if (fn == isns_debug_message
	 && !isns_debug_enabled(DBG_MESSAGE))
		return;

	fn("---%s%s---\n",
			isns_function_name(simp->is_function),
			simp->is_replace? "[REPLACE]" : "");
	if (simp->is_source) {
		fn("Source:\n", buffer);
		isns_attr_print(simp->is_source->is_attr, fn);
	} else {
		fn("Source: <empty>\n");
	}

	if (simp->is_message_attrs.ial_count == 0) {
		fn("Message attributes: <empty list>\n");
	} else {
		fn("Message attributes:\n");
		isns_attr_list_print(&simp->is_message_attrs, fn);
	}
	if (simp->is_operating_attrs.ial_count == 0) {
		fn("Operating attributes: <empty list>\n");
	} else {
		fn("Operating attributes:\n");
		isns_attr_list_print(&simp->is_operating_attrs, fn);
	}
}

/*
 * This set of functions analyzes the operating attrs of a registration,
 * or a query response, and chops it up into separate chunks, one
 * per objects.
 *
 * It always returns the keys and attrs for one object,
 * following the ordering constraints laid out in the RFC.
 */
void
isns_attr_list_scanner_init(struct isns_attr_list_scanner *st,
			isns_object_t *key_obj,
			const isns_attr_list_t *attrs)
{
	memset(st, 0, sizeof(*st));
	st->orig_attrs = *attrs;
	st->key_obj = key_obj;
}

void
isns_attr_list_scanner_destroy(struct isns_attr_list_scanner *st)
{
	isns_attr_list_destroy(&st->keys);
	isns_attr_list_destroy(&st->attrs);
	memset(st, 0, sizeof(*st));
}

int
isns_attr_list_scanner_next(struct isns_attr_list_scanner *st)
{
	isns_attr_t	*attr;
	unsigned int	i, pos = st->pos;

	isns_attr_list_destroy(&st->keys);
	isns_attr_list_destroy(&st->attrs);

	if (st->orig_attrs.ial_count <= pos)
		return ISNS_NO_SUCH_ENTRY;

	attr = st->orig_attrs.ial_data[pos];

	/* handle those funky inlined PGT definitions */
	if (st->pgt_next_attr && attr->ia_tag_id == st->pgt_next_attr)
		return isns_attr_list_scanner_get_pg(st);

	/* This isn't really structured programming anymore */
	if (st->index_acceptable
	 && (st->tmpl = isns_object_template_for_index_tag(attr->ia_tag_id)))
		goto copy_attrs;

	/*
	 * Find the object template for the given key attr(s).
	 * This function also enforces restrictions on the
	 * order of key attributes.
	 */
	st->tmpl = isns_object_template_find(attr->ia_tag_id);
	if (st->tmpl == NULL) {
		isns_debug_protocol("%s: attr %u is not a key attr\n",
				__FUNCTION__, attr->ia_tag_id);
		return ISNS_INVALID_REGISTRATION;
	}

	/* Copy the key attrs */
	for (i = 0; i < st->tmpl->iot_num_keys; ++i, ++pos) {
		if (pos >= st->orig_attrs.ial_count) {
			isns_debug_protocol("%s: incomplete %s object "
					"(key attr %u missing)\n",
					__FUNCTION__, st->tmpl->iot_name, pos);
			return ISNS_INVALID_REGISTRATION;
		}
		attr = st->orig_attrs.ial_data[pos];

		/* Make sure key attrs are complete and in order */
		if (attr->ia_tag_id != st->tmpl->iot_keys[i]) {
			isns_debug_protocol("%s: incomplete %s object "
					"(key attr %u missing)\n",
					__FUNCTION__, st->tmpl->iot_name, pos);
			return ISNS_INVALID_REGISTRATION;
		}

		isns_attr_list_append_attr(&st->keys, attr);
	}

	/*
	 * Consume all non-key attributes corresponding to the
	 * object class. We stop whenever we hit another
	 * key attribute, or an attribute that does not belong to
	 * the object type (eg when a storage node is followed by
	 * a PGT attribute, as described in section 5.6.5.1).
	 */
copy_attrs:
	while (pos < st->orig_attrs.ial_count) {
		uint32_t	tag;

		attr = st->orig_attrs.ial_data[pos];
		tag = attr->ia_tag_id;

		if (!isns_object_attr_valid(st->tmpl, tag)
		 || isns_object_template_find(tag) != NULL)
			break;

		pos++;
		isns_attr_list_append_attr(&st->attrs, attr);
	}
	st->pos = pos;

	return ISNS_SUCCESS;
}

int
isns_attr_list_scanner_get_pg(struct isns_attr_list_scanner *st)
{
	isns_attr_t	*attr, *next = NULL;
	unsigned int	pos = st->pos;


	attr = st->orig_attrs.ial_data[st->pos++];
	if (st->pgt_next_attr == ISNS_TAG_PG_TAG) {
		isns_object_t	*base = st->pgt_base_object;

		if (ISNS_ATTR_IS_NIL(attr))
			st->pgt_value = 0;
		else if (ISNS_ATTR_IS_UINT32(attr))
			st->pgt_value = attr->ia_value.iv_uint32;
		else
			return ISNS_INVALID_REGISTRATION;

		if (ISNS_IS_PORTAL(base)
		 && isns_portal_from_object(&st->pgt_portal_info,
					ISNS_TAG_PORTAL_IP_ADDRESS,
					ISNS_TAG_PORTAL_TCP_UDP_PORT,
					base)) {
			st->pgt_next_attr = ISNS_TAG_PG_ISCSI_NAME;
		} else
		if (ISNS_IS_ISCSI_NODE(base)
		 && isns_object_get_string(base,
					ISNS_TAG_ISCSI_NAME,
					&st->pgt_iscsi_name)) {
			st->pgt_next_attr = ISNS_TAG_PORTAL_IP_ADDRESS;
		} else {
			return ISNS_INTERNAL_ERROR;
		}

		/* Trailing PGT at end of list. Shrug. */
		if (st->pos >= st->orig_attrs.ial_count)
			return ISNS_NO_SUCH_ENTRY;

		attr = st->orig_attrs.ial_data[st->pos++];
		if (attr->ia_tag_id != st->pgt_next_attr) {
			/* Some clients may do this; catch them so
			 * we can fix it. */
			isns_error("Oops, client sends PGT followed by <%s>\n",
					attr->ia_tag->it_name);
			return ISNS_INVALID_REGISTRATION;
		}
	}

	st->tmpl = &isns_iscsi_pg_template;
	if (st->pgt_next_attr == ISNS_TAG_PG_ISCSI_NAME) {
		isns_attr_list_append_attr(&st->keys, attr);
		isns_portal_to_attr_list(&st->pgt_portal_info,
					ISNS_TAG_PG_PORTAL_IP_ADDR,
					ISNS_TAG_PG_PORTAL_TCP_UDP_PORT,
					&st->keys);
	} else
	if (st->pgt_next_attr == ISNS_TAG_PG_PORTAL_IP_ADDR) {
		if (st->pos >= st->orig_attrs.ial_count)
			return ISNS_INVALID_REGISTRATION;

		next = st->orig_attrs.ial_data[st->pos++];
		if (next->ia_tag_id != ISNS_TAG_PORTAL_TCP_UDP_PORT)
			return ISNS_INVALID_REGISTRATION;

		isns_attr_list_append_string(&st->keys,
					ISNS_TAG_PG_ISCSI_NAME,
					st->pgt_iscsi_name);
		isns_attr_list_append_attr(&st->keys, attr);
		isns_attr_list_append_attr(&st->keys, next);
	} else {
		return ISNS_INTERNAL_ERROR;
	}

	isns_attr_list_append_uint32(&st->attrs,
				ISNS_TAG_PG_TAG,
				st->pgt_value);

	/* Copy other PG attributes if present */
	for (pos = st->pos; pos < st->orig_attrs.ial_count; ++pos) {
		uint32_t	tag;

		attr = st->orig_attrs.ial_data[pos];
		tag = attr->ia_tag_id;

		/*
		 * Additional sets of PGTs and PG iSCSI Names to be
		 * associated to the registered Portal MAY follow.
		 */
		if (tag == ISNS_TAG_PG_TAG) {
			st->pgt_next_attr = tag;
			break;
		}

		if (tag == ISNS_TAG_PG_ISCSI_NAME
		 || tag == ISNS_TAG_PG_PORTAL_IP_ADDR
		 || tag == ISNS_TAG_PG_PORTAL_TCP_UDP_PORT
		 || !isns_object_attr_valid(st->tmpl, tag))
			break;

		isns_attr_list_append_attr(&st->attrs, attr);
	}
	st->pos = pos;

	return ISNS_SUCCESS;
}

/*
 * Get the name of a function
 */
#define __ISNS_MAX_FUNCTION	16
static const char *	isns_req_function_names[__ISNS_MAX_FUNCTION] = {
[ISNS_DEVICE_ATTRIBUTE_REGISTER]= "DevAttrReg",
[ISNS_DEVICE_ATTRIBUTE_QUERY]	= "DevAttrQry",
[ISNS_DEVICE_GET_NEXT]		= "DevGetNext",
[ISNS_DEVICE_DEREGISTER]	= "DevDereg",
[ISNS_SCN_REGISTER]		= "SCNReg",
[ISNS_SCN_DEREGISTER]		= "SCNDereg",
[ISNS_SCN_EVENT]		= "SCNEvent",
[ISNS_STATE_CHANGE_NOTIFICATION]= "SCN",
[ISNS_DD_REGISTER]		= "DDReg",
[ISNS_DD_DEREGISTER]		= "DDDereg",
[ISNS_DDS_REGISTER]		= "DDSReg",
[ISNS_DDS_DEREGISTER]		= "DDSDereg",
[ISNS_ENTITY_STATUS_INQUIRY]	= "ESI",
[ISNS_HEARTBEAT]		= "Heartbeat",
};
static const char *	isns_resp_function_names[__ISNS_MAX_FUNCTION] = {
[ISNS_DEVICE_ATTRIBUTE_REGISTER]= "DevAttrRegResp",
[ISNS_DEVICE_ATTRIBUTE_QUERY]	= "DevAttrQryResp",
[ISNS_DEVICE_GET_NEXT]		= "DevGetNextResp",
[ISNS_DEVICE_DEREGISTER]	= "DevDeregResp",
[ISNS_SCN_REGISTER]		= "SCNRegResp",
[ISNS_SCN_DEREGISTER]		= "SCNDeregResp",
[ISNS_SCN_EVENT]		= "SCNEventResp",
[ISNS_STATE_CHANGE_NOTIFICATION]= "SCNResp",
[ISNS_DD_REGISTER]		= "DDRegResp",
[ISNS_DD_DEREGISTER]		= "DDDeregResp",
[ISNS_DDS_REGISTER]		= "DDSRegResp",
[ISNS_DDS_DEREGISTER]		= "DDSDeregResp",
[ISNS_ENTITY_STATUS_INQUIRY]	= "ESIRsp",
/* No response code for heartbeat */
};

const char *
isns_function_name(uint32_t function)
{
	static char	namebuf[32];
	const char	**names, *name;
	unsigned int	num = function;

	names = isns_req_function_names;
	if (num & 0x8000) {
		names = isns_resp_function_names;
		num &= 0x7fff;
	}
	name = NULL;
	if (num < __ISNS_MAX_FUNCTION)
		name = names[num];
	if (name == NULL) {
		snprintf(namebuf, sizeof(namebuf),
				"<function %08x>",
				function);
		name = namebuf;
	}

	return name;
}

