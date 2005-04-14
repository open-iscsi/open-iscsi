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

#ifndef QUEUE_H
#define QUEUE_H

#include "types.h"

#define QUEUE_BUF_SIZE			4096
#define EVENT_PAYLOAD_MAX		(DATASEG_MAX+HDRSEG_MAX)

typedef enum queue_status_e {
	QUEUE_OK		= 0,
	QUEUE_IS_FULL		= 1,
	QUEUE_IS_EMPTY		= 2,
	QUEUE_OUT_OF_MEMORY	= 3,
	QUEUE_NOT_ENOUGH_SPACE	= 4
} queue_status_e;

typedef struct queue_item_t {
	struct qelem	item;
	int		event_type;
	int		data_size;
	void		*context;
} queue_item_t;

typedef void (*queued_f) (void *data, int event_type);

typedef struct queue_t {
	void				*start_ptr;
	void				*end_ptr;
	void				*head_ptr;
	void				*tail_ptr;
	unsigned int			pages_initial;
	unsigned int			pages_max;
	unsigned int			pages_current;
	struct qelem			list_head;
	queued_f			queued_func;
	void				*queued_data;
	int				count;
} queue_t;

extern queue_t* queue_create(int pages_initial, int pages_max,
				queued_f queued_func, void *queued_data);
extern void queue_destroy(queue_t *queue);
extern void* queue_item_data(queue_item_t *item);
extern queue_status_e queue_produce(queue_t* queue, int event_type,
	    void *context, const int data_size, void *data);
extern queue_status_e queue_consume(queue_t *queue, int	data_max_size,
				    queue_item_t *item);
extern void queue_flush(queue_t *queue);

#endif /* QUEUE_H */
