/*
 * Copyright (C) 2002 Cisco Systems, Inc.
 * maintained by linux-iscsi-devel@lists.sourceforge.net
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

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/param.h>

#include "strings.h"
#include "log.h"

int str_init_buffer(struct str_buffer *s, size_t initial_allocation)
{
	if (s) {
		memset(s, 0, sizeof (*s));
		s->buffer = NULL;
		if (initial_allocation) {
			s->buffer = malloc(initial_allocation);
			if (s->buffer) {
				s->allocated_length = initial_allocation;
				memset(s->buffer, 0, initial_allocation);
			}
		}
		s->data_length = 0;
		return 1;
	}

	return 0;
}

struct str_buffer *str_alloc_buffer(size_t initial_allocation)
{
	struct str_buffer *s = calloc(1, sizeof (*s));

	if (s)
		str_init_buffer(s, initial_allocation);

	return s;
}

void str_free_buffer(struct str_buffer *s)
{
	if (s) {
		if (s->buffer) {
			free(s->buffer);
			s->buffer = NULL;
		}
		s->allocated_length = 0;
		s->data_length = 0;
	}
}

int str_enlarge_data(struct str_buffer *s, int length)
{
	void *new_buf;

	if (s) {
		s->data_length += length;
		if (s->data_length > s->allocated_length) {
			log_debug(7, "enlarge buffer from %lu to %lu\n",
				  s->allocated_length, s->data_length);
			new_buf = realloc(s->buffer, s->data_length);
			if (!new_buf) {
				/* too big */
				log_error("enlarged buffer %p to %d data "
					  "bytes, with only %d bytes of buffer "
					  "space", s, (int)s->data_length,
					   (int)s->allocated_length);
				return ENOMEM;
			}
			s->buffer = new_buf;
			memset(s->buffer + s->allocated_length, 0,
			       s->data_length - s->allocated_length);
			s->allocated_length = s->data_length;
		}
	}

	return 0;
}

void str_remove_initial(struct str_buffer *s, int length)
{
	char *remaining;
	int amount;

	if (s && length) {
		remaining = s->buffer + length;
		amount = s->data_length - length;

		if (amount < 0)
			amount = 0;
		if (amount)
			memmove(s->buffer, remaining, amount);
		s->data_length = amount;
		s->buffer[amount] = '\0';
	}
}

/* truncate the data length down */
void str_truncate_buffer(struct str_buffer *s, size_t length)
{
	if (s) {
		if (!s->data_length)
			return;
		if (length <= s->data_length) {
			s->data_length = length;
			s->buffer[s->data_length] = '\0';
		} else if (length <= s->allocated_length) {
			/* clear the data, and declare the
			 * data length to be larger
			 */
			memset(s->buffer + s->data_length, 0,
			       length - s->data_length);
			s->data_length = length;
		} else {
			log_error(
			       "couldn't truncate data buffer to length %d, "
			       "only allocated %d",
			       (int)length, (int)s->allocated_length);
		}
	}
}

char *str_buffer_data(struct str_buffer *s)
{
	if (s)
		return s->buffer;
	else
		return NULL;
}

size_t str_data_length(struct str_buffer * s)
{
	if (s)
		return s->data_length;
	else
		return 0;
}

size_t str_unused_length(struct str_buffer * s)
{
	if (s)
		return s->allocated_length - s->data_length;
	else
		return 0;
}
