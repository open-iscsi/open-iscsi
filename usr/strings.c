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

int
init_string_buffer(struct string_buffer *s, size_t initial_allocation)
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

struct string_buffer *
alloc_string_buffer(size_t initial_allocation)
{
	struct string_buffer *s = calloc(1, sizeof (*s));

	if (s) {
		init_string_buffer(s, initial_allocation);
	}

	return s;
}

void
free_string_buffer(struct string_buffer *s)
{
	if (s) {
		if (s->buffer) {
			free(s->buffer);
			s->buffer = NULL;
		}
		s->allocated_length = 0;
		s->data_length = 0;
		free(s);
	}
}

void
enlarge_data(struct string_buffer *s, int length)
{
	if (s) {
		s->data_length += length;
		if (s->data_length >= s->allocated_length) {
			/* too big */
			log_error("enlarged buffer %p to %d data bytes, "
			       "with only %d bytes of buffer space",
			       s, (int)s->data_length,
			       (int)s->allocated_length);
		}
	}
}

void
remove_initial(struct string_buffer *s, int length)
{
	char *remaining = s->buffer + length;
	int amount = s->data_length - length;

	if (s && length) {
		memmove(s->buffer, remaining, amount);
		s->data_length = amount;
		s->buffer[amount] = '\0';
	}
}

static int
realloc_buffer(struct string_buffer *s, size_t min_length)
{
	size_t length = MAX(min_length + 1, s->allocated_length + 1024);
	char *buf = realloc(s->buffer, length);

	if (buf) {
		s->buffer = buf;
		s->buffer[length - 1] = '\0';
		s->allocated_length = length;
		return 1;
	} else {
		log_error(
		       "failed to allocate more space for string buffer %p", s);
		return 0;
	}
}

/* truncate the data length down */
void
truncate_buffer(struct string_buffer *s, size_t length)
{
	if (s) {
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

/* append a string onto the buffer */
int
append_string(struct string_buffer *s, const char *str)
{
	size_t length = strlen(str);
	size_t needed = s->data_length + length + 1;	/* existing + new +
							 * trailing NUL
							 */

	if (needed >= s->allocated_length) {
		/* need more space */
		if (!realloc_buffer(s, needed))
			return 0;
	}

	strcpy(s->buffer + s->data_length, str);
	s->data_length += length;
	return 1;
}

int
append_sprintf(struct string_buffer *s, const char *format, ...)
{
	va_list args;
	size_t appended;
	size_t available = s->allocated_length - s->data_length - 1;
	int ret = 0;

	va_start(args, format);

	for (;;) {
		appended = vsnprintf(s->buffer + s->data_length, available,
				     format, args);

		if (appended < 0) {
			/* error, need more space, but don't know how much */
			if (!realloc_buffer(s, s->data_length + 1024))
				goto done;
		} else if (appended >= available) {
			/* what would have been output overflows the buffer,
			 * need more space
			 */
			if (!realloc_buffer(s, s->data_length + appended))
				goto done;
		} else {
			/* it fit */
			s->data_length += appended;
			ret = 1;
			break;
		}
	}

 done:
	va_end(args);

	return ret;
}

/* append a string after the NUL at the end of any current data.  This
 * maintains NUL termination of all strings
 */
int
adjoin_string(struct string_buffer *s, const char *str)
{
	size_t length = strlen(str) + 1;
	size_t needed;

	if (s->buffer[s->data_length - 1] == '\0')
		needed = s->data_length + length;	/* lengths include NULs
							 */
	else
		needed = s->data_length + 1 + length;	/* existing + NUL +
							 * new + NUL
							 */
	if (needed >= s->allocated_length) {
		/* need more space */
		if (!realloc_buffer(s, needed))
			return 0;
	}

	if (s->buffer[s->data_length - 1] == '\0') {
		memcpy(s->buffer + s->data_length, str, length);
						/* lengths already include NULs
						 */
		s->data_length += length;	/* new string + NUL */
	} else {
		memcpy(s->buffer + s->data_length + 1, str, length);
						/* NUL + new + NUL */
		s->data_length += 1 + length;	/* NUL + new string + NUL */
	}

	return 1;
}

char *
buffer_data(struct string_buffer *s)
{
	if (s)
		return s->buffer;
	else
		return NULL;
}

size_t
data_length(struct string_buffer * s)
{
	if (s)
		return s->data_length;
	else
		return 0;
}

size_t
unused_length(struct string_buffer * s)
{
	if (s)
		return s->allocated_length - s->data_length;
	else
		return 0;
}

/* write the entire buffer to the fd, or exit */
void
write_buffer(struct string_buffer *s, int fd)
{
	const char *data = buffer_data(s);
	const char *end = data + data_length(s);
	int result;

	/* write the target info to the pipe */
	log_debug(7, "writing to pipe %d, data %p, size %d, text '%s'",
		  fd, data, (int)(end - data), data);
	while (data < end) {
		result = write(fd, data, end - data);
		if (result < 0) {
			if (errno != EINTR) {
				log_error("can't write to pipe %d", fd);
				exit(1);
			}
		} else {
			data += result;
		}
	}
}
