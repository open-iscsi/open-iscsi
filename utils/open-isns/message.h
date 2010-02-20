/*
 * iSNS message definitions and functions
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#ifndef ISNS_MESSAGE_H
#define ISNS_MESSAGE_H

#include "attrs.h"
#include "source.h"
#include "util.h"

typedef struct isns_message_queue isns_message_queue_t;

struct isns_simple {
	uint32_t		is_function;
	isns_source_t *		is_source;
	isns_policy_t *		is_policy;
	uint16_t		is_xid;

	unsigned int		is_replace : 1;

	isns_attr_list_t	is_message_attrs;
	isns_attr_list_t	is_operating_attrs;
};

struct isns_message {
	unsigned int		im_users;
	isns_list_t		im_list;
	struct sockaddr_storage	im_addr;
	socklen_t		im_addrlen;
	uint32_t		im_xid;
	struct isns_hdr		im_header;
	struct isns_buf *	im_payload;
	isns_socket_t *		im_socket;
	isns_principal_t *	im_security;
	struct ucred *		im_creds;

	isns_message_queue_t *	im_queue;

	/* When to retransmit */
	struct timeval		im_resend_timeout;
	struct timeval		im_timeout;

	void			(*im_destroy)(isns_message_t *);
	void			(*im_callback)(isns_message_t *,
					isns_message_t *);
	void *			im_calldata;
};

enum {
	ISNS_MQ_SORT_NONE,
	ISNS_MQ_SORT_RESEND_TIMEOUT,
};

struct isns_message_queue {
	isns_list_t		imq_list;
	size_t			imq_count;
};

struct isns_server {
	isns_source_t *		is_source;
	isns_db_t *		is_db;

	isns_scn_callback_fn_t *is_scn_callback;
	struct isns_service_ops *is_ops;
};

extern isns_message_t *	__isns_alloc_message(uint32_t, size_t, void (*)(isns_message_t *));
extern isns_security_t *isns_message_security(const isns_message_t *);

extern isns_message_t *	isns_message_queue_find(isns_message_queue_t *, uint32_t,
				const struct sockaddr_storage *, socklen_t);
extern void		isns_message_queue_insert_sorted(isns_message_queue_t *,
				int, isns_message_t *);
extern void		isns_message_queue_move(isns_message_queue_t *,
				isns_message_t *);
extern void		isns_message_queue_destroy(isns_message_queue_t *);

extern isns_simple_t *	isns_simple_create(uint32_t,
				isns_source_t *,
				const isns_attr_list_t *);
extern void		isns_simple_free(isns_simple_t *);
extern int		isns_simple_encode(isns_simple_t *,
				isns_message_t **result);
extern int		isns_simple_decode(isns_message_t *,
				isns_simple_t **);
extern int		isns_simple_encode_response(isns_simple_t *,
				const isns_message_t *, isns_message_t **);
extern int		isns_simple_response_get_objects(isns_simple_t *,
				isns_object_list_t *);
extern const char *	isns_function_name(uint32_t);

extern isns_source_t *	isns_simple_get_source(isns_simple_t *);

extern int		isns_process_registration(isns_server_t *, isns_simple_t *, isns_simple_t **);
extern int		isns_process_query(isns_server_t *, isns_simple_t *, isns_simple_t **);
extern int		isns_process_getnext(isns_server_t *, isns_simple_t *, isns_simple_t **);
extern int		isns_process_deregistration(isns_server_t *, isns_simple_t *, isns_simple_t **);
extern int		isns_process_scn_register(isns_server_t *, isns_simple_t *, isns_simple_t **);
extern int		isns_process_scn_deregistration(isns_server_t *, isns_simple_t *, isns_simple_t **);
extern int		isns_process_dd_registration(isns_server_t *, isns_simple_t *, isns_simple_t **);
extern int		isns_process_dd_deregistration(isns_server_t *, isns_simple_t *, isns_simple_t **);
extern int		isns_process_esi(isns_server_t *, isns_simple_t *, isns_simple_t **);
extern int		isns_process_scn(isns_server_t *, isns_simple_t *, isns_simple_t **);

/*
 * Inline functions for message queues.
 */
static inline void
isns_message_queue_init(isns_message_queue_t *q)
{
	isns_list_init(&q->imq_list);
	q->imq_count = 0;
}

static inline isns_message_t *
isns_message_queue_head(const isns_message_queue_t *q)
{
	isns_list_t	*pos = q->imq_list.next;

	if (pos == &q->imq_list)
		return NULL;
	return isns_list_item(isns_message_t, im_list, pos);
}

static inline void
isns_message_queue_append(isns_message_queue_t *q, isns_message_t *msg)
{
	isns_assert(msg->im_queue == NULL);
	isns_list_append(&q->imq_list, &msg->im_list);
	q->imq_count++;

	msg->im_queue = q;
	msg->im_users++;
}

static inline isns_message_t *
isns_message_queue_remove(isns_message_queue_t *q, isns_message_t *msg)
{
	isns_assert(msg->im_queue == q);
	isns_list_del(&msg->im_list);
	msg->im_queue = NULL;
	q->imq_count--;

	return msg;
}

static inline isns_message_t *
isns_message_unlink(isns_message_t *msg)
{
	if (msg->im_queue)
		return isns_message_queue_remove(msg->im_queue, msg);
	return NULL;
}

static inline isns_message_t *
isns_message_dequeue(isns_message_queue_t *q)
{
	isns_message_t	*msg;

	if ((msg = isns_message_queue_head(q)) != NULL) {
		isns_list_del(&msg->im_list);
		msg->im_queue = NULL;
		q->imq_count--;
	}
	return msg;
}

/*
 * Iterator for looping over all messages in a queue
 */
static inline void
isns_message_queue_begin(isns_message_queue_t *q, isns_list_t **pos)
{
	*pos = q->imq_list.next;
}

static inline isns_message_t *
isns_message_queue_next(isns_message_queue_t *q, isns_list_t **pos)
{
	isns_list_t *next = *pos;

	if (next == &q->imq_list)
		return NULL;
	*pos = next->next;
	return isns_list_item(isns_message_t, im_list, next);
}

#define isns_message_queue_foreach(q, pos, item) \
	for (isns_message_queue_begin(q, &pos); \
	     (item = isns_message_queue_next(q, &pos)) != NULL; \
	    )

#endif /* ISNS_MESSAGE_H */
