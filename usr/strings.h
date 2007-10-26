/*
 * iSCSI variable-sized string buffers
 *
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

#ifndef STRINGS_H
#define STRINGS_H

struct string_buffer {
	size_t allocated_length;
	size_t data_length;	/* not including the trailing NUL */
	char *buffer;
};

extern int init_string_buffer(struct string_buffer *s,
			      size_t initial_allocation);
extern struct string_buffer *alloc_string_buffer(size_t initial_allocation);
extern void free_string_buffer(struct string_buffer *s);

extern void enlarge_data(struct string_buffer *s, int length);
extern void remove_initial(struct string_buffer *s, int length);
extern void truncate_buffer(struct string_buffer *s, size_t length);
extern char *buffer_data(struct string_buffer *s);
extern size_t data_length(struct string_buffer *s);
extern size_t unused_length(struct string_buffer *s);

#endif /* STRINGS_H */
