/*
 * iSNS source attribute handling
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#ifndef ISNS_SOURCE_H
#define ISNS_SOURCE_H

#include "attrs.h"

struct isns_source {
	unsigned int		is_users;
	isns_attr_t *		is_attr;
	unsigned int		is_untrusted : 1;

	isns_object_t *		is_node;
	unsigned int		is_node_type;

	isns_object_t *		is_entity;
};

extern int		isns_source_encode(buf_t *, const isns_source_t *);
extern int		isns_source_decode(buf_t *, isns_source_t **);
extern int		isns_source_set_node(isns_source_t *, isns_db_t *);
extern void		isns_source_set_entity(isns_source_t *, isns_object_t *);
extern isns_source_t *	isns_source_dummy(void);

extern char *		isns_build_source_pattern(const char *);
extern int		isns_source_pattern_match(const char *, const char *);

#endif /* ISNS_SOURCE_H */
