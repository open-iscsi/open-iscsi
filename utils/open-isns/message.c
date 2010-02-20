/*
 * iSNS message handling functions
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 *
 *
 */

#include <stdlib.h>
#include <string.h>
#include <sys/time.h>	/* for timercmp */
#include <unistd.h>	/* gethostname */
#include <ctype.h>
#include "isns.h"
#include "attrs.h"
#include "message.h"
#include "socket.h"
#include "util.h"

/* iSCSI qualified names include the year and
 * month in which the domain was assigned.
 * See RFC 3720, section 3.2.6.3.1.
 * That's one of these wonderful committee
 * type of ideas that makes it hard for everyone,
 * from coder to sysadmin.
 * Since we have no way of finding out here,
 * we fake it by assigning a date before the
 * dawn of time.
 */
#define DUMMY_IQN_PREFIX	"iqn.1967-12."

static uint32_t		isns_xid = 1;

/*
 * Initialize a message object
 */
isns_message_t *
__isns_alloc_message(uint32_t xid, size_t size, void (*destroy)(isns_message_t *))
{
	isns_message_t	*msg;

	isns_assert(size >= sizeof(*msg));
	msg = isns_calloc(1, size);

	isns_list_init(&msg->im_list);
	msg->im_users = 1;
	msg->im_xid = xid;
	msg->im_destroy = destroy;

	return msg;
}

static int
__isns_message_init(isns_message_t *msg,
			uint16_t function, uint16_t flags,
			size_t payload_len)
{
	struct isns_hdr *hdr = &msg->im_header;

	/* Pad to multiple of 4 octets */
	payload_len = (payload_len + 3) & ~3UL;

	/* For now, we don't do segmentation */
	if (payload_len > ISNS_MAX_PDU_SIZE)
		return 0;

	/* msg->im_header is in host byte order */
	hdr->i_version = ISNS_VERSION;
	hdr->i_function = function;
	hdr->i_flags = flags;
	hdr->i_length = payload_len;
	hdr->i_xid = msg->im_xid;
	hdr->i_seq = 0;

	/* Allocate buffer and reserve room for header */
	msg->im_payload = buf_alloc(sizeof(*hdr) + payload_len);
	buf_push(msg->im_payload, sizeof(*hdr));

	return 1;
}

/*
 * Allocate a message object.
 */
static isns_message_t *
__isns_create_message(uint32_t xid, uint16_t function, uint16_t flags)
{
	isns_message_t *msg;

	msg = __isns_alloc_message(xid, sizeof(*msg), NULL);
	__isns_message_init(msg, function, flags, ISNS_MAX_MESSAGE);

	return msg;
}

/*
 * Allocate a request message
 */
isns_message_t *
isns_create_message(uint16_t function, uint16_t flags)
{
	return __isns_create_message(isns_xid++, function, flags);
}

/*
 * Allocate a response message
 */
isns_message_t *
isns_create_reply(const isns_message_t *msg)
{
	uint16_t function = msg->im_header.i_function;;
	isns_message_t	*resp;

	resp = __isns_create_message(msg->im_xid, function | 0x8000, ISNS_F_SERVER);
	resp->im_addr = msg->im_addr;
	resp->im_addrlen = msg->im_addrlen;

	/* Default to ISNS_SUCCESS */
	buf_put32(resp->im_payload, ISNS_SUCCESS);

	return resp;
}

/*
 * Delete a message
 */
void
isns_message_release(isns_message_t *msg)
{
	if (msg == NULL)
		return;

	isns_assert(msg->im_users);
	if (--(msg->im_users))
		return;

	if (msg->im_destroy)
		msg->im_destroy(msg);
	if (msg->im_payload)
		buf_free(msg->im_payload);
	isns_principal_free(msg->im_security);

	isns_list_del(&msg->im_list);
	isns_free(msg);
}

/*
 * Extract the status from a reply message
 */
int
isns_message_status(isns_message_t *msg)
{
	uint32_t	status;

	if (!(msg->im_header.i_function & 0x8000)
	 || !buf_get32(msg->im_payload, &status))
		return ISNS_MESSAGE_FORMAT_ERROR;
	return status;
}

/*
 * Obtain the socket on which the message was received.
 */
isns_socket_t *
isns_message_socket(const isns_message_t *msg)
{
	return msg->im_socket;
}

/*
 * Obtain the message's security context
 */
isns_security_t *
isns_message_security(const isns_message_t *msg)
{
	if (!msg->im_socket)
		return NULL;
	return msg->im_socket->is_security;
}

unsigned int
isns_message_function(const isns_message_t *msg)
{
	return msg->im_header.i_function;
}

/*
 * Reset the response message, and encode isns_error
 * status
 */
void
isns_message_set_error(isns_message_t *msg, uint32_t status)
{
	/* Clear the buffer. This just resets head + tail */
	buf_clear(msg->im_payload);

	/* Now move past the header, and overwrite the
	 * status word. */
	buf_push(msg->im_payload, sizeof(struct isns_hdr));
	buf_put32(msg->im_payload, status);
}

/*
 * Message queue handling. Most related functions are
 * in message.h
 */
void
isns_message_queue_move(isns_message_queue_t *dstq,
		isns_message_t *msg)
{
	unsigned int	src_ref = 0;

	/* If the message was on a different queue,
	 * the source queue will hold a reference
	 * to it. Account for that and fix up the
	 * refcount after we've appended it to the
	 * destination queue. */
	if (isns_message_unlink(msg))
		src_ref = 1;

	isns_message_queue_append(dstq, msg);
	msg->im_users -= src_ref;
}

/*
 * Insert a messsage into a queue sorted by resend timeout
 */
void
isns_message_queue_insert_sorted(isns_message_queue_t *q,
		int sort, isns_message_t *msg)
{
	isns_list_t	*pos;
	isns_message_t	*__m;

	isns_assert(msg->im_queue == NULL);
	if (sort == ISNS_MQ_SORT_RESEND_TIMEOUT) {
		isns_message_queue_foreach(q, pos, __m) {
			if (timercmp(&msg->im_resend_timeout,
				     &__m->im_resend_timeout, <))
				break;
		}
	} else {
		isns_message_queue_append(q, msg);
		return;
	}

	/* Insert before pos */
	__isns_list_insert(pos->prev, &msg->im_list, pos);
	q->imq_count++;

	msg->im_queue = q;
	msg->im_users++;
}

/*
 * Message queue handling
 */
void
isns_message_queue_destroy(isns_message_queue_t *q)
{
	isns_message_t	*msg;

	while ((msg = isns_message_dequeue(q)) != NULL)
		isns_message_release(msg);
}

/*
 * Find a message with matching xid and address.
 * (address, alen) may be NULL.
 */
isns_message_t *
isns_message_queue_find(isns_message_queue_t *q, uint32_t xid,
		const struct sockaddr_storage *addr, socklen_t alen)
{
	isns_message_t	*msg;
	isns_list_t	*pos;

	isns_message_queue_foreach(q, pos, msg) {
		if (msg->im_xid != xid)
			continue;
		if (alen == 0)
			return msg;

		if (msg->im_addrlen == alen
		 && !memcmp(&msg->im_addr, addr, alen))
			return msg;
	}

	return NULL;
}

/*
 * Convert a hostname into an iSCSI qualified name
 * We omit the dismbiguating YYYY-MM infix because
 * we have no way of finding out, short of bothering
 * whois.
 */
static char *
__revert_fqdn(const char *prefix, const char *__fqdn, const char *suffix)
{
	static char	namebuf[1024] = { '\0' };
	char		*fqdn, *result = NULL;
	int		pos, count = 0;

	if (prefix)
		strcpy(namebuf, prefix);
	pos = strlen(namebuf);

	fqdn = isns_strdup(__fqdn);
	while (1) {
		char	*dot, *comp;
		int	comp_len;

		if ((dot = strrchr(fqdn, '.')) != NULL) {
			*dot++ = '\0';
			comp = dot;
		} else {
			comp = fqdn;
		}

		if (*comp == '\0')
			continue;
		comp_len = strlen(comp);
		if (pos + comp_len + 2 > sizeof(namebuf)) {
			isns_error("%s: FQDN too long\n", __FUNCTION__);
			goto out;
		}
		if (count++)
			namebuf[pos++] = '.';
		strcpy(namebuf + pos, comp);
		pos += comp_len;

		if (dot == NULL)
			break;
	}

	if (suffix) {
		int	sfx_len = strlen(suffix);

		if (pos + sfx_len + 2 > sizeof(namebuf)) {
			isns_error("%s: name too long\n", __FUNCTION__);
			goto out;
		}
		namebuf[pos++] = ':';
		strcpy(namebuf + pos, suffix);
		pos += sfx_len;
	}

	result = isns_strdup(namebuf);

out:	isns_free(fqdn);
	return result;
}

/*
 * Initialize all names
 */
int
isns_init_names(void)
{
	if (isns_config.ic_host_name == NULL) {
		char	namebuf[1024], *fqdn;

		if (gethostname(namebuf, sizeof(namebuf)) < 0) {
			isns_error("gehostname: %m\n");
			return 0;
		}
		fqdn = isns_get_canon_name(namebuf);
		if (fqdn == NULL) {
			/* FIXME: we could get some unique value here
			 * such as the IP address, and concat that
			 * with iqn.2005-01.org.open-iscsi.ip for the
			 * source name.
			 */
			isns_error("Unable to get fully qualified hostname\n");
			return 0;
		}
		isns_config.ic_host_name = fqdn;
	}

	if (isns_config.ic_auth_name == NULL) {
		isns_config.ic_auth_name = isns_config.ic_host_name;
	}

	if (isns_config.ic_entity_name == NULL) {
		isns_config.ic_entity_name = isns_config.ic_auth_name;
	}

	if (isns_config.ic_source_name == NULL) {
		isns_config.ic_source_name = __revert_fqdn(DUMMY_IQN_PREFIX,
				isns_config.ic_host_name,
				isns_config.ic_source_suffix);
		if (isns_config.ic_source_name == NULL) {
			isns_error("Unable to build source name\n");
			return 0;
		}
	}

	return 1;
}

/*
 * Match a source name to a pattern (which is really just
 * the entity identifier, usually).
 *
 * If the pattern is of the form "match:rev-fqdn", the
 * source name must match
 *	iqn.[YYYY-MM.]<rev-fqdn>
 * optionally followed by dot, colon or hyphen and arbitrary
 * text.
 *
 * If the pattern does not start with "match:", the source name
 * must match the pattern literally (case insensitively).
 */
int
isns_source_pattern_match(const char *pattern, const char *source)
{
	unsigned int	rev_len;

	isns_debug_message("%s(%s, %s)\n",
			__FUNCTION__, pattern, source);

	if (!strcmp(pattern, "*"))
		return 1;

	if (strncmp(pattern, "match:", 6))
		return !strcasecmp(pattern, source);
	pattern += 6;

	if (strncasecmp(source, "iqn.", 4))
		return 0;
	source += 4;

	rev_len = strlen(pattern);
	if (strncasecmp(source, pattern, rev_len)) {
		/* See if the next component is YYYY-MM */
		if (!(isdigit(source[0])
		   && isdigit(source[1])
		   && isdigit(source[2])
		   && isdigit(source[3])
		   && source[4] == '-'
		   && isdigit(source[5])
		   && isdigit(source[6])
		   && source[7] == '.'))
			return 0;
		source += 8;

		if (strncasecmp(source, pattern, rev_len))
			return 0;
	}

	source += rev_len;
	if (source[0] != '.'
	 && source[0] != ':'
	 && source[0] != '-'
	 && source[0] != '\0')
		return 0;

	return 1;
}

/*
 * This really just reverts the FQDN so it can
 * be used in isns_source_entity_match
 */
char *
isns_build_source_pattern(const char *fqdn)
{
	return __revert_fqdn("match:", fqdn, NULL);
}

/*
 * Manage source objects
 */
static isns_source_t *
__isns_source_create(isns_attr_t *name_attr)
{
	isns_source_t	*source = isns_calloc(1, sizeof(*source));

	source->is_users = 1;
	source->is_attr = name_attr;
	return source;
}

isns_source_t *
isns_source_create(isns_attr_t *name_attr)
{
	if (name_attr->ia_tag_id != ISNS_TAG_ISCSI_NAME
	 && name_attr->ia_tag_id != ISNS_TAG_FC_PORT_NAME_WWPN)
		return NULL;

	name_attr->ia_users++;
	return __isns_source_create(name_attr);
}

isns_source_t *
isns_source_from_object(const isns_object_t *node)
{
	isns_attr_t	*attr;

	if (!(attr = isns_storage_node_key_attr(node)))
		return NULL;
	return isns_source_create(attr);
}

isns_source_t *
isns_source_create_iscsi(const char *name)
{
	isns_value_t	var = ISNS_VALUE_INIT(string, (char *) name);
	isns_attr_t	*attr;

	attr = isns_attr_alloc(ISNS_TAG_ISCSI_NAME, NULL, &var);
	return __isns_source_create(attr);
}

/*
 * This is used to attach a dummy source to iSNS responses
 * until I fixed up all the code that relies on msg->is_source
 * to be valid all the time.
 */
isns_source_t *
isns_source_dummy(void)
{
	static isns_source_t *dummy = NULL;

	if (!dummy)
		dummy = isns_source_create_iscsi(".dummy.");
	return isns_source_get(dummy);
}

uint32_t
isns_source_type(const isns_source_t *source)
{
	return source->is_attr->ia_tag_id;
}

const char *
isns_source_name(const isns_source_t *source)
{
	return source->is_attr->ia_value.iv_string;
}

isns_attr_t *
isns_source_attr(const isns_source_t *source)
{
	return source->is_attr;
}

/*
 * Obtain an additional reference on the source object
 */
isns_source_t *
isns_source_get(isns_source_t *source)
{
	if (source)
		source->is_users++;
	return source;
}

/*
 * Look up the node corresponding to this source name
 * When we get here, we have already verified that the
 * client is permitted (by policy) to use this source node.
 */
int
isns_source_set_node(isns_source_t *source, isns_db_t *db)
{
	isns_object_t	*node, *entity;
	uint32_t	node_type;

	if (source->is_node)
		return 1;

	if (db == NULL)
		return 0;

	node = isns_db_lookup_source_node(db, source);
	if (node == NULL)
		return 0;

	if (!isns_object_get_uint32(node, ISNS_TAG_ISCSI_NODE_TYPE, &node_type))
		node_type = 0;

	source->is_node = node;
	source->is_node_type = node_type;

	if ((entity = isns_object_get_entity(node)) != NULL)
		source->is_entity = isns_object_get(entity);
	return 1;
}

void
isns_source_set_entity(isns_source_t *source, isns_object_t *obj)
{
	if (obj)
		isns_object_get(obj);
	isns_object_release(source->is_entity);
	source->is_entity = obj;
}

/*
 * Release a reference on the source object
 */
void
isns_source_release(isns_source_t *source)
{
	if (source && --source->is_users == 0) {
		isns_attr_release(source->is_attr);
		isns_object_release(source->is_node);
		isns_object_release(source->is_entity);
		memset(source, 0xa5, sizeof(*source));
		isns_free(source);
	}
}

/*
 * Compare two source objects
 */
int
isns_source_match(const isns_source_t *a,
		const isns_source_t *b)
{
	if (a && b)
		return isns_attr_match(a->is_attr, b->is_attr);
	return 0;
}

/*
 * Encode/decode source object
 */
int
isns_source_encode(buf_t *bp, const isns_source_t *source)
{
	if (source == NULL) {
		isns_attr_t nil = ISNS_ATTR_INIT(ISNS_TAG_DELIMITER, nil, 0);
		
		return isns_attr_encode(bp, &nil);
	}
	return isns_attr_encode(bp, source->is_attr);
}

int
isns_source_decode(buf_t *bp, isns_source_t **result)
{
	isns_attr_t	*attr;
	int		status;

	status = isns_attr_decode(bp, &attr);
	if (status == ISNS_SUCCESS) {
		/*
		 * 5.6.1
		 * The Source Attribute uniquely identifies the source of the
		 * message.  Valid Source Attribute types are shown below.
		 *
		 *	Valid Source Attributes
		 *	-----------------------
		 *	iSCSI Name
		 *	FC Port Name WWPN
		 */
		switch (attr->ia_tag_id) {
#if 0
		case ISNS_TAG_DELIMITER:
			*result = NULL;
			break;
#endif

		case ISNS_TAG_ISCSI_NAME:
			*result = __isns_source_create(attr);
			break;

		case ISNS_TAG_FC_PORT_NAME_WWPN:
			*result = __isns_source_create(attr);
			break;

		default:
			isns_attr_release(attr);
			return ISNS_SOURCE_UNKNOWN;
		}
	}
	return status;
}
