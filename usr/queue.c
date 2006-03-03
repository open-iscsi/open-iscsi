/*
 * iSCSI event queue
 *
 * Copyright (C) 2004 Dmitry Yusupov, Alex Aizman
 * maintained by open-iscsi@googlegroups.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * See the file COPYING included with this distribution for more details.
 */

#include <stdlib.h>
#include <string.h>
#include <search.h>
#include "queue.h"
#include "log.h"
#include "actor.h"

queue_t*
queue_create(int pages_initial, int pages_max, queued_f queued,
	     void *queued_data)
{
	queue_t *queue;

	if ((queue = malloc(sizeof(queue_t))) == NULL) {
		log_error("out of memory when allocating queue_t");
		return NULL;
	}

	queue->queued_func = queued;
	queue->queued_data = queued_data;
	queue->pages_current = pages_initial;
	queue->start_ptr = malloc(queue->pages_current * QUEUE_BUF_SIZE);
	if (queue->start_ptr == NULL) {
		log_error("out of memory when allocating queue's pages");
		free(queue);
		return NULL;
	}
	memset(queue->start_ptr, 0, queue->pages_current * QUEUE_BUF_SIZE);
	queue->head_ptr = queue->tail_ptr = queue->start_ptr;
	queue->end_ptr = (char *)queue->start_ptr +
		queue->pages_current * QUEUE_BUF_SIZE;
	queue->pages_initial = pages_initial;
	queue->pages_max = pages_max;
	queue->list_head.q_forw = &queue->list_head;
	queue->list_head.q_back = &queue->list_head;
	queue->count = 0;

	return queue;
}

void
queue_destroy(queue_t* queue)
{
	if (queue->list_head.q_forw != &queue->list_head) {
		log_error("destroying non-empty queue 0x%p", queue);
	}
	free(queue->start_ptr);
	free(queue);
}

static queue_status_e
__io_queue_grow(queue_t *queue)
{
	void *newbuf, *oldbuf;
	struct qelem *item;
	queue_item_t *elem;

	log_debug(7, "queue 0x%p:%d is growing", queue, queue->pages_current);

	newbuf = malloc((queue->pages_current + 1) * QUEUE_BUF_SIZE);
	if (newbuf == NULL) {
		return QUEUE_OUT_OF_MEMORY;
	}
	memcpy(newbuf, queue->start_ptr, queue->pages_current * QUEUE_BUF_SIZE);
	oldbuf = queue->start_ptr;

	/* adjust queue sizes */
	queue->start_ptr = newbuf;
	queue->end_ptr = (char *)newbuf +
			(queue->pages_current + 1) * QUEUE_BUF_SIZE;
	queue->tail_ptr = (char *)newbuf + ((char *)queue->tail_ptr -
					    (char *)oldbuf);
	queue->head_ptr = (char *)newbuf + ((char *)queue->head_ptr -
					    (char *)oldbuf);
	queue->list_head.q_forw = (struct qelem *) (void *)((char *)newbuf +
			((char *)queue->list_head.q_forw - (char *)oldbuf));
	queue->list_head.q_back = (struct qelem *) (void *)((char *)newbuf +
			((char *)queue->list_head.q_back - (char *)oldbuf));
	/* adjust queue list */
	for (item = queue->list_head.q_forw;
	     item != queue->list_head.q_forw; item = item->q_forw) {
		elem = (queue_item_t *)item;
		if (elem->item.q_forw != &queue->list_head) {
			elem->item.q_forw =
				(struct qelem *)(void *)((char *)newbuf +
				 ((char *)elem->item.q_forw - (char *)oldbuf));
		}
		if (elem->item.q_back != &queue->list_head) {
			elem->item.q_back =
				(struct qelem *) (void *)((char *)newbuf +
				 ((char *)elem->item.q_back - (char *)oldbuf));
		}
	}
	free(oldbuf);
	queue->pages_current++;

	return QUEUE_OK;
}

queue_status_e
queue_consume(queue_t *queue, int data_max_size, queue_item_t *item)
{
	int real_size;
	queue_item_t *elem;

	if (queue->list_head.q_forw == &queue->list_head) {
		if (queue->count)
			log_error("queue integrety lost! Bug?");
		return QUEUE_IS_EMPTY;
	}
	elem = (queue_item_t *)queue->list_head.q_forw;
	if (elem->data_size > data_max_size) {
		return QUEUE_NOT_ENOUGH_SPACE;
	}
	remque(&elem->item);
	real_size = elem->data_size + sizeof(queue_item_t);
	if (queue->head_ptr == elem) {
		queue->head_ptr = (char *)queue->head_ptr + real_size;
		log_debug(7,
			"event_type: %d removing from the head: "
			"0x%p:0x%p:0x%p:0x%p elem 0x%p length %d",
			elem->event_type,
			queue->start_ptr,
			queue->head_ptr,
			queue->tail_ptr,
			queue->end_ptr,
			elem,
			real_size);
	} else if ((char *)queue->tail_ptr - real_size == (char*)elem) {
		queue->tail_ptr = (char *)queue->tail_ptr - real_size;
		log_debug(7,
			"event_type: %d removing from the tail: "
			"0x%p:0x%p:0x%p:0x%p elem 0x%p length %d",
			elem->event_type,
			queue->start_ptr,
			queue->head_ptr,
			queue->tail_ptr,
			queue->end_ptr,
			elem,
			real_size);
	} else {
		log_debug(7,
			"event_type: %d removing from the list: "
			"0x%p:0x%p:0x%p:0x%p elem 0x%p length %d",
			elem->event_type,
			queue->start_ptr,
			queue->head_ptr,
			queue->tail_ptr,
			queue->end_ptr,
			elem,
			real_size);
	}
	memcpy(item, elem, sizeof(queue_item_t));
	memcpy(queue_item_data(item), queue_item_data(elem), elem->data_size);

	if (queue->list_head.q_forw == &queue->list_head) {
		/* reset buffer pointers just to be clean */
		queue->head_ptr = queue->tail_ptr = queue->start_ptr;
	}

	queue->count--;

	return QUEUE_OK;
}

void
queue_flush(queue_t *queue)
{
	unsigned char item_buf[sizeof(queue_item_t) + EVENT_PAYLOAD_MAX];
	queue_item_t *item = (queue_item_t *)(void *)item_buf;

	/* flush queue by consuming all enqueued items */
	while (queue_consume(queue, EVENT_PAYLOAD_MAX,
				item) != QUEUE_IS_EMPTY) {
		/* do nothing */
		log_debug(7, "item %p(%d) flushed", item, item->event_type);
	}
}

void*
queue_item_data (queue_item_t *item)
{
	return (char *)item + sizeof(queue_item_t);
}

queue_status_e
queue_produce(queue_t *queue, int event_type, void *context,
	      const int data_size, void *data)
{
	int real_size = data_size + sizeof(queue_item_t);
	queue_item_t *elem;

try_again:
	if ((char *)queue->tail_ptr + real_size <= (char *)queue->end_ptr) {
		elem = queue->tail_ptr;
		queue->tail_ptr = (void *)((char *)queue->tail_ptr + real_size);
		log_debug(7, "event_type: %d adding to the tail: "
			"0x%p:0x%p:0x%p:0x%p elem 0x%p length %d",
			event_type,
			queue->start_ptr,
			queue->head_ptr,
			queue->tail_ptr,
			queue->end_ptr,
			elem,
			real_size);
	} else if ((char *)queue->head_ptr - real_size >=
					(char *)queue->start_ptr) {
		elem = (void *)((char *)queue->head_ptr - real_size);
		queue->head_ptr = elem;
		log_debug(7, "event_type: %d adding to the head: "
			"0x%p:0x%p:0x%p:0x%p length %d",
			event_type,
			queue->start_ptr,
			queue->head_ptr,
			queue->tail_ptr,
			queue->end_ptr,
			real_size);
	} else {
		queue_status_e status;

		if (queue->pages_current >= queue->pages_max) {
			return QUEUE_IS_FULL;
		}

		/* grow */
		status = __io_queue_grow(queue);
		if (status != QUEUE_OK) {
			return status;
		}

		goto try_again;
	}
	elem->data_size = data_size;
	elem->event_type = event_type;
	elem->context = context;
	memcpy(queue_item_data(elem), data, data_size);
	insque(&elem->item, queue->list_head.q_back);

	if (queue->queued_func)
		queue->queued_func(queue->queued_data, event_type);

	queue->count++;

	return QUEUE_OK;
}

