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

struct str_buffer {
	size_t allocated_length;
	size_t data_length;	/* not including the trailing NUL */
	char *buffer;
};

extern int str_init_buffer(struct str_buffer *s, size_t initial_allocation);
extern struct str_buffer *str_alloc_buffer(size_t initial_allocation);
extern void str_free_buffer(struct str_buffer *s);

extern int str_enlarge_data(struct str_buffer *s, int length);
extern void str_remove_initial(struct str_buffer *s, int length);
extern void str_truncate_buffer(struct str_buffer *s, size_t length);
extern char *str_buffer_data(struct str_buffer *s);
extern size_t str_data_length(struct str_buffer *s);
extern size_t str_unused_length(struct str_buffer *s);

#endif /* STRINGS_H */
