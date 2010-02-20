/*
 * Open-iSNS types
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#ifndef ISNS_TYPES_H
#define ISNS_TYPES_H

typedef struct isns_simple	isns_simple_t;
typedef struct isns_source	isns_source_t;
typedef struct isns_object	isns_object_t;
typedef struct isns_relation	isns_relation_t;
typedef struct isns_attr	isns_attr_t;
typedef struct isns_attr_list	isns_attr_list_t;
typedef struct isns_message	isns_message_t;
typedef struct isns_socket	isns_socket_t;
typedef struct isns_db		isns_db_t;
typedef struct isns_tag_type	isns_tag_type_t;
typedef const struct isns_object_template isns_object_template_t;
typedef struct isns_authdata	isns_authdata_t;
typedef struct isns_security	isns_security_t;
typedef struct isns_principal	isns_principal_t;
typedef struct isns_policy	isns_policy_t;
typedef struct isns_keystore	isns_keystore_t;
typedef struct isns_scope	isns_scope_t;
typedef struct isns_portal_info isns_portal_info_t;
typedef struct isns_server	isns_server_t;
typedef struct isns_db_event	isns_db_event_t;
typedef struct isns_bitvector	isns_bitvector_t;

typedef struct isns_object_list {
	unsigned int		iol_count;
	isns_object_t **	iol_data;
} isns_object_list_t;

#define ISNS_OBJECT_LIST_INIT	{ .iol_count = 0, .iol_data = NULL }

/*
 * An attribute list
 */
struct isns_attr_list {
	unsigned int		ial_count;
	isns_attr_t **		ial_data;
};
#define ISNS_ATTR_LIST_INIT	{ .ial_count = 0, .ial_data = NULL }

/*
 * Function types.
 */
typedef void			isns_print_fn_t(const char *, ...);
typedef void			isns_timer_callback_t(void *);


#endif /* ISNS_TYPES_H */


