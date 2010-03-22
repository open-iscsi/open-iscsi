/*
 * iSNS implementation - library header file.
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 *
 * This file contains all declarations and definitions
 * commonly required by users of libisns.
 */

#ifndef ISNS_H
#define ISNS_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <stdio.h>

#include <isns-proto.h>
#include "types.h"

#define ISNS_MAX_BUFFER		8192
#define ISNS_MAX_MESSAGE	8192


/*
 * Client handle
 */
typedef struct isns_client isns_client_t;
struct isns_client {
	isns_source_t *	ic_source;
	isns_socket_t *	ic_socket;
};

/*
 * Server operations
 */
typedef int	isns_service_fn_t(isns_server_t *, isns_simple_t *, isns_simple_t **);
typedef void	isns_scn_callback_fn_t(isns_db_t *, uint32_t scn_bits,
					isns_object_template_t *node_type,
					const char *node_name,
					const char *recipient);
struct isns_service_ops {
	isns_service_fn_t *	process_registration;
	isns_service_fn_t *	process_query;
	isns_service_fn_t *	process_getnext;
	isns_service_fn_t *	process_deregistration;
	isns_service_fn_t *	process_scn_registration;
	isns_service_fn_t *	process_scn_deregistration;
	isns_service_fn_t *	process_scn_event;
	isns_service_fn_t *	process_scn;
	isns_service_fn_t *	process_dd_registration;
	isns_service_fn_t *	process_dd_deregistration;
	isns_service_fn_t *	process_esi;
	isns_service_fn_t *	process_heartbeat;
};

extern struct isns_service_ops	isns_default_service_ops;
extern struct isns_service_ops	isns_callback_service_ops;

/*
 * Output function
 */
void			isns_print_stdout(const char *, ...);

/*
 * Database events
 */
struct isns_db_event {
	isns_object_t *		ie_recipient;	/* Recipient node or NULL */
	isns_object_t *		ie_object;	/* Affected object */
	isns_object_t *		ie_trigger;	/* Triggering object */
	unsigned int		ie_bits;	/* SCN bitmask */
};
typedef void		isns_db_callback_t(const isns_db_event_t *,
					void *user_data);

/*
 * Handling of client objects
 */
extern isns_client_t *	isns_create_default_client(isns_security_t *);
extern isns_client_t *	isns_create_client(isns_security_t *,
				const char *source_name);
extern isns_client_t *	isns_create_local_client(isns_security_t *,
				const char *source_name);
extern int		isns_client_call(isns_client_t *,
				isns_simple_t **inout);
extern void		isns_client_destroy(isns_client_t *);
extern int		isns_client_get_local_address(const isns_client_t *,
				isns_portal_info_t *);

/*
 * Handling of server objects
 */
extern isns_server_t *	isns_create_server(isns_source_t *,
				isns_db_t *,
				struct isns_service_ops *);
extern void		isns_server_set_scn_callback(isns_server_t *,
				isns_scn_callback_fn_t *);


/*
 * Handling of source names
 */
extern int		isns_init_names(void);
extern const char *	isns_default_source_name(void);
extern isns_source_t *	isns_source_create(isns_attr_t *);
extern isns_source_t *	isns_source_create_iscsi(const char *name);
extern isns_source_t *	isns_source_create_ifcp(const char *name);
extern uint32_t		isns_source_type(const isns_source_t *);
extern const char *	isns_source_name(const isns_source_t *);
extern isns_attr_t *	isns_source_attr(const isns_source_t *);
extern isns_source_t *	isns_source_get(isns_source_t *);
extern isns_source_t *	isns_source_from_object(const isns_object_t *);
extern void		isns_source_release(isns_source_t *);
extern int		isns_source_match(const isns_source_t *,
				const isns_source_t *);

extern void		isns_server_set_source(isns_source_t *);
extern isns_message_t *	isns_process_message(isns_server_t *, isns_message_t *);

extern void		isns_simple_print(isns_simple_t *,
				isns_print_fn_t *);
extern int		isns_simple_call(isns_socket_t *,
				isns_simple_t **);
extern int		isns_simple_transmit(isns_socket_t *,
				isns_simple_t *,
				const isns_portal_info_t *,
				unsigned int,
				void (*callback)(uint32_t, int,
						 isns_simple_t *));
extern void		isns_simple_free(isns_simple_t *);
extern const isns_attr_list_t *isns_simple_get_attrs(isns_simple_t *);

extern isns_simple_t *	isns_create_query(isns_client_t *clnt,
				const isns_attr_list_t *query_key);
extern isns_simple_t *	isns_create_query2(isns_client_t *clnt,
				const isns_attr_list_t *query_key,
				isns_source_t *source);
extern int		isns_query_request_attr_tag(isns_simple_t *,
				uint32_t);
extern int		isns_query_request_attr(isns_simple_t *,
				isns_attr_t *);
extern int		isns_query_response_get_objects(isns_simple_t *qry,
				isns_object_list_t *result);

extern isns_simple_t *	isns_create_registration(isns_client_t *clnt,
				isns_object_t *key_object);
extern isns_simple_t *	isns_create_registration2(isns_client_t *clnt,
				isns_object_t *key_object,
				isns_source_t *source);
extern void		isns_registration_set_replace(isns_simple_t *, int);
extern void		isns_registration_add_object(isns_simple_t *,
				isns_object_t *object);
extern void		isns_registration_add_object_list(isns_simple_t *,
				isns_object_list_t *);
extern int		isns_registration_response_get_objects(isns_simple_t *,
				isns_object_list_t *);

extern isns_simple_t *	isns_create_getnext(isns_client_t *,
				isns_object_template_t *,
				const isns_attr_list_t *);
extern int		isns_getnext_response_get_object(isns_simple_t *,
				isns_object_t **);
extern isns_simple_t *	isns_create_getnext_followup(isns_client_t *,
				const isns_simple_t *,
				const isns_attr_list_t *);

extern isns_simple_t *	isns_create_deregistration(isns_client_t *clnt,
				const isns_attr_list_t *);

extern isns_simple_t *	isns_create_scn_registration(isns_client_t *clnt,
				unsigned int);
extern isns_simple_t *	isns_create_scn_registration2(isns_client_t *clnt,
				unsigned int,
				isns_source_t *);

extern int		isns_dd_load_all(isns_db_t *);
extern void		isns_dd_get_members(uint32_t, isns_object_list_t *, int);
extern isns_simple_t *	isns_create_dd_registration(isns_client_t *,
				const isns_attr_list_t *);
extern isns_simple_t *	isns_create_dd_deregistration(isns_client_t *,
				uint32_t, const isns_attr_list_t *);

extern isns_object_t *	isns_create_object(isns_object_template_t *,
				const isns_attr_list_t *,
				isns_object_t *);
extern isns_object_t *	isns_create_entity(int, const char *);
extern isns_object_t *	isns_create_entity_for_source(const isns_source_t *,
				const char *);
extern const char *	isns_entity_name(const isns_object_t *);
extern isns_object_t *	isns_create_portal(const isns_portal_info_t *,
				isns_object_t *parent);
extern isns_object_t *	isns_create_storage_node(const char *name,
				uint32_t type_mask,
				isns_object_t *parent);
extern isns_object_t *	isns_create_storage_node2(const isns_source_t *,
				uint32_t type_mask,
				isns_object_t *parent);
extern isns_object_t *	isns_create_iscsi_initiator(const char *name,
				isns_object_t *parent);
extern isns_object_t *	isns_create_iscsi_target(const char *name,
				isns_object_t *parent);
extern const char *	isns_storage_node_name(const isns_object_t *);
extern isns_attr_t *	isns_storage_node_key_attr(const isns_object_t *);
extern isns_object_t *	isns_create_portal_group(isns_object_t *portal,
				isns_object_t *iscsi_node, uint32_t pg_tag);
extern isns_object_t *	isns_create_default_portal_group(isns_db_t *,
				isns_object_t *portal,
				isns_object_t *node);
extern void		isns_get_portal_groups(isns_object_t *portal,
				isns_object_t *node,
				isns_object_list_t *result);

extern const char *	isns_object_template_name(isns_object_template_t *);
extern int		isns_object_set_attr(isns_object_t *, isns_attr_t *);
extern int		isns_object_set_attrlist(isns_object_t *, const isns_attr_list_t *);
extern isns_object_t *	isns_object_get(isns_object_t *);
extern int		isns_object_get_attrlist(isns_object_t *obj,
				isns_attr_list_t *result,
				const isns_attr_list_t *requested_attrs);
extern int		isns_object_get_key_attrs(isns_object_t *,
				isns_attr_list_t *);
extern int		isns_object_get_attr(const isns_object_t *, uint32_t,
				isns_attr_t **);
extern void		isns_object_get_related(isns_db_t *,
				isns_object_t *, isns_object_list_t *);
extern void		isns_object_get_descendants(const isns_object_t *,
				isns_object_template_t *,
				isns_object_list_t *);
extern void		isns_object_release(isns_object_t *);
extern int		isns_object_match(const isns_object_t *,
				const isns_attr_list_t *);
extern isns_object_t *	isns_object_get_entity(isns_object_t *);
extern int		isns_object_attr_valid(isns_object_template_t *, uint32_t);
extern int		isns_object_contains(const isns_object_t *, const isns_object_t *);
extern int		isns_object_delete_attr(isns_object_t *, uint32_t);
extern int		isns_object_is(const isns_object_t *,
				isns_object_template_t *);
extern int		isns_object_is_entity(const isns_object_t *);
extern int		isns_object_is_iscsi_node(const isns_object_t *);
extern int		isns_object_is_fc_port(const isns_object_t *);
extern int		isns_object_is_fc_node(const isns_object_t *);
extern int		isns_object_is_portal(const isns_object_t *);
extern int		isns_object_is_pg(const isns_object_t *);
extern int		isns_object_is_policy(const isns_object_t *);
extern int		isns_object_is_dd(const isns_object_t *);
extern int		isns_object_is_ddset(const isns_object_t *);
extern void		isns_object_print(isns_object_t *,
				isns_print_fn_t *);
extern time_t		isns_object_last_modified(const isns_object_t *);
extern int		isns_object_mark_membership(isns_object_t *, uint32_t);
extern int		isns_object_clear_membership(isns_object_t *, uint32_t);
extern int		isns_object_test_membership(const isns_object_t *, uint32_t);
extern int		isns_object_test_visibility(const isns_object_t *,
				const isns_object_t *);
extern void		isns_object_get_visible(const isns_object_t *,
				isns_db_t *, isns_object_list_t *);
extern void		isns_entity_touch(isns_object_t *);
extern int		isns_object_extract_keys(const isns_object_t *,
				isns_attr_list_t *);
extern int		isns_object_extract_all(const isns_object_t *,
				isns_attr_list_t *);
extern int		isns_object_extract_writable(const isns_object_t *,
				isns_attr_list_t *);


extern int		isns_object_set_nil(isns_object_t *obj,	
				uint32_t tag);
extern int		isns_object_set_string(isns_object_t *obj,	
				uint32_t tag,
				const char *value);
extern int		isns_object_set_uint32(isns_object_t *obj,	
				uint32_t tag,
				uint32_t value);
extern int		isns_object_set_uint64(isns_object_t *obj,	
				uint32_t tag,
				uint64_t value);
extern int		isns_object_set_ipaddr(isns_object_t *obj,	
				uint32_t tag,
				const struct in6_addr *value);

extern int		isns_object_get_string(const isns_object_t *,
				uint32_t,
				const char **);
extern int		isns_object_get_ipaddr(const isns_object_t *,
				uint32_t,
				struct in6_addr *);
extern int		isns_object_get_uint32(const isns_object_t *,
				uint32_t,
				uint32_t *);
extern int		isns_object_get_uint64(const isns_object_t *,
				uint32_t,
				uint64_t *);
extern int		isns_object_get_opaque(const isns_object_t *,
				uint32_t,
				const void **, size_t *);


extern int		isns_object_find_descendants(isns_object_t *obj,
				isns_object_template_t *,
				const isns_attr_list_t *keys,
				isns_object_list_t *result);
extern isns_object_t *	isns_object_find_descendant(isns_object_t *obj,
				const isns_attr_list_t *keys);
extern int		isns_object_detach(isns_object_t *);
extern int		isns_object_attach(isns_object_t *, isns_object_t *);
extern void		isns_object_prune_attrs(isns_object_t *);
extern void		isns_mark_object(isns_object_t *, unsigned int);

extern int		isns_get_entity_identifier(isns_object_t *, const char **);
extern int		isns_get_entity_protocol(isns_object_t *, isns_entity_protocol_t *);
extern int		isns_get_entity_index(isns_object_t *, uint32_t *);

extern int		isns_get_portal_ipaddr(isns_object_t *, struct in6_addr *);
extern int		isns_get_portal_tcpudp_port(isns_object_t *,
				int *ipprotocol, uint16_t *port);
extern int		isns_get_portal_index(isns_object_t *, uint32_t *);

extern int		isns_get_address(struct sockaddr_storage *,
				const char *, const char *, int, int, int);
extern char *		isns_get_canon_name(const char *);

extern isns_db_t *	isns_db_open(const char *location);
extern isns_db_t *	isns_db_open_shadow(isns_object_list_t *);
extern isns_object_t *	isns_db_lookup(isns_db_t *,
				isns_object_template_t *,
				const isns_attr_list_t *);
extern isns_object_t *	isns_db_vlookup(isns_db_t *,
				isns_object_template_t *,
				...);
extern int		isns_db_gang_lookup(isns_db_t *,
				isns_object_template_t *,
				const isns_attr_list_t *,
				isns_object_list_t *);
extern isns_object_t *	isns_db_get_next(isns_db_t *,
				isns_object_template_t *,
				const isns_attr_list_t *current,
				const isns_attr_list_t *scope,
				const isns_source_t *source);
extern isns_object_t *	isns_db_lookup_source_node(isns_db_t *,
				const isns_source_t *);
extern void		isns_db_get_domainless(isns_db_t *,
				isns_object_template_t *,
				isns_object_list_t *);
extern uint32_t		isns_db_allocate_index(isns_db_t *);
extern void		isns_db_insert(isns_db_t *, isns_object_t *);
extern void		isns_db_insert_limbo(isns_db_t *, isns_object_t *);
extern int		isns_db_remove(isns_db_t *, isns_object_t *);
extern time_t		isns_db_expire(isns_db_t *);
extern void		isns_db_purge(isns_db_t *);
extern void		isns_db_sync(isns_db_t *);
extern const char *	isns_db_generate_eid(isns_db_t *, char *, size_t);
extern isns_object_t *	isns_db_get_control(isns_db_t *);
extern void		isns_db_print(isns_db_t *,
				isns_print_fn_t *);

extern void		isns_db_begin_transaction(isns_db_t *);
extern void		isns_db_commit(isns_db_t *);
extern void		isns_db_rollback(isns_db_t *);

extern void		isns_object_event(isns_object_t *obj,
				unsigned int bits,
				isns_object_t *trigger);
extern void		isns_unicast_event(isns_object_t *dst,
				isns_object_t *obj,
				unsigned int bits,
				isns_object_t *trigger);
extern void		isns_register_callback(isns_db_callback_t *,
				void *);
extern void		isns_flush_events(void);
extern const char *	isns_event_string(unsigned int);

extern void		isns_add_timer(unsigned int,
				isns_timer_callback_t *, void *);
extern void		isns_add_oneshot_timer(unsigned int,
				isns_timer_callback_t *, void *);
extern void		isns_cancel_timer(isns_timer_callback_t *, void *);
extern time_t		isns_run_timers(void);

extern void		isns_object_list_init(isns_object_list_t *);
extern void		isns_object_list_destroy(isns_object_list_t *);
extern int		isns_object_list_contains(const isns_object_list_t *,
				isns_object_t *);
extern void		isns_object_list_append(isns_object_list_t *,
				isns_object_t *);
extern void		isns_object_list_append_list(isns_object_list_t *,
				const isns_object_list_t *);
extern isns_object_t *	isns_object_list_lookup(const isns_object_list_t *,
				isns_object_template_t *,
				const isns_attr_list_t *);
extern int		isns_object_list_gang_lookup(const isns_object_list_t *,
				isns_object_template_t *,
				const isns_attr_list_t *,
				isns_object_list_t *);
extern int		isns_object_list_remove(isns_object_list_t *,
				isns_object_t *);
extern void		isns_object_list_uniq(isns_object_list_t *);
extern void		isns_object_list_print(const isns_object_list_t *,
				isns_print_fn_t *);

isns_object_template_t *isns_object_template_for_key_attrs(const isns_attr_list_t *);
isns_object_template_t *isns_object_template_for_tag(uint32_t);
isns_object_template_t *isns_object_template_for_index_tag(uint32_t);
isns_object_template_t *isns_object_template_find(uint32_t);

extern int		isns_attr_set(isns_attr_t *, const void *);
extern isns_attr_t *	isns_attr_get(isns_attr_t *);
extern void		isns_attr_release(isns_attr_t *);
extern void		isns_attr_print(const isns_attr_t *,
				isns_print_fn_t *);
extern char *		isns_attr_print_value(const isns_attr_t *,
				char *, size_t);
extern int		isns_attr_match(const isns_attr_t *,
				const isns_attr_t *);
extern int		isns_attr_compare(const isns_attr_t *,
				const isns_attr_t *);
extern isns_attr_t *	isns_attr_from_string(uint32_t, const char *);

extern void		isns_attr_list_print(const isns_attr_list_t *,
				isns_print_fn_t *);

extern void		isns_attr_list_init(isns_attr_list_t *);
extern void		isns_attr_list_copy(isns_attr_list_t *,
				const isns_attr_list_t *);
extern void		isns_attr_list_destroy(isns_attr_list_t *);
extern int		isns_attr_list_remove_tag(isns_attr_list_t *,
				uint32_t);

extern void		isns_attr_list_append_attr(isns_attr_list_t *,
				isns_attr_t *);
extern void		isns_attr_list_append_list(isns_attr_list_t *,
				const isns_attr_list_t *);
extern int		isns_attr_list_replace_attr(isns_attr_list_t *,
				isns_attr_t *);
/* Warning: this does *NOT* return a reference to the attribute */
extern int		isns_attr_list_get_attr(const isns_attr_list_t *,
				uint32_t tag,
				isns_attr_t **);

extern void		isns_attr_list_append_nil(isns_attr_list_t *,
				uint32_t tag);
extern void		isns_attr_list_append_string(isns_attr_list_t *,
				uint32_t tag, const char *value);
extern void		isns_attr_list_append_uint32(isns_attr_list_t *,
				uint32_t tag, uint32_t value);
extern void		isns_attr_list_append_uint64(isns_attr_list_t *,
				uint32_t, int64_t);
extern void		isns_attr_list_append_int32(isns_attr_list_t *,
				uint32_t tag, int32_t value);
extern void		isns_attr_list_append_opaque(isns_attr_list_t *,
				uint32_t tag, const void *ptr, size_t len);
extern void		isns_attr_list_append_ipaddr(isns_attr_list_t *,
				uint32_t tag, const struct in6_addr *);

extern int		isns_attr_list_append(isns_attr_list_t *,
				uint32_t tag, const void *);
extern int		isns_attr_list_update(isns_attr_list_t *,
				uint32_t tag, const void *);

extern int		isns_attr_list_contains(const isns_attr_list_t *,
				uint32_t tag);
extern int		isns_attr_list_compare(const isns_attr_list_t *,
				const isns_attr_list_t *);

/*
 * Helper macros
 */
#define ISNS_ATTR_TYPE_CHECK(attr, type) \
		((attr)->ia_value.iv_type == &isns_attr_type_##type)
#define ISNS_ATTR_IS_NIL(attr) \
		ISNS_ATTR_TYPE_CHECK(attr, nil)
#define ISNS_ATTR_IS_STRING(attr) \
		ISNS_ATTR_TYPE_CHECK(attr, string)
#define ISNS_ATTR_IS_IPADDR(attr) \
		ISNS_ATTR_TYPE_CHECK(attr, ipaddr)
#define ISNS_ATTR_IS_UINT32(attr) \
		ISNS_ATTR_TYPE_CHECK(attr, uint32)
#define ISNS_ATTR_IS_UINT64(attr) \
		ISNS_ATTR_TYPE_CHECK(attr, uint64)
#define ISNS_ATTR_IS_OPAQUE(attr) \
		ISNS_ATTR_TYPE_CHECK(attr, opaque)



extern isns_socket_t *	isns_create_server_socket(const char *hostname, const char *portname,
				int af_hint, int sock_type);
extern isns_socket_t *	isns_create_client_socket(const char *hostname, const char *portname,
				int af_hint, int sock_type);
extern isns_socket_t *	isns_create_bound_client_socket(const char *myaddr,
				const char *hostname, const char *portname,
				int af_hint, int sock_type);
extern isns_socket_t *	isns_connect_to_portal(const isns_portal_info_t *);
extern void		isns_socket_set_report_failure(isns_socket_t *);
extern void		isns_socket_set_disconnect_fatal(isns_socket_t *);
extern int		isns_socket_get_local_addr(const isns_socket_t *,
				struct sockaddr_storage *);
extern int		isns_socket_get_portal_info(const isns_socket_t *,
				isns_portal_info_t *);
extern void		isns_socket_set_security_ctx(isns_socket_t *,
				isns_security_t *);
extern isns_message_t *	isns_recv_message(struct timeval *timeout);
extern isns_message_t *	isns_socket_call(isns_socket_t *, isns_message_t *, long);
extern int		isns_socket_send(isns_socket_t *, isns_message_t *);
extern void		isns_socket_free(isns_socket_t *);
extern int		isns_addr_get_port(const struct sockaddr *);
extern void		isns_addr_set_port(struct sockaddr *, unsigned int);
extern isns_socket_t *	isns_socket_find_server(const isns_portal_info_t *);

extern isns_message_t *	isns_create_message(uint16_t function, uint16_t flags);
extern isns_message_t *	isns_create_reply(const isns_message_t *);
extern int		isns_message_init(isns_message_t *,
				uint16_t, uint16_t, size_t);
extern int		isns_message_status(isns_message_t *);
extern void		isns_message_release(isns_message_t *);
extern unsigned int	isns_message_function(const isns_message_t *);
extern isns_socket_t *	isns_message_socket(const isns_message_t *);
extern void		isns_message_set_error(isns_message_t *, uint32_t);

extern const char *	isns_strerror(enum isns_status);
extern const char *	isns_function_name(unsigned int);

/*
 * Security related functions
 */
extern int		isns_security_init(void);
extern isns_principal_t *isns_security_load_privkey(isns_security_t *,
				const char *filename);
extern isns_principal_t *isns_security_load_pubkey(isns_security_t *,
				const char *filename);
extern isns_security_t *isns_default_security_context(int server_only);
extern isns_security_t *isns_control_security_context(int server_only);
extern isns_security_t *isns_create_dsa_context(void);
extern void		isns_security_set_identity(isns_security_t *, isns_principal_t *);
extern void		isns_principal_free(isns_principal_t *);
extern void		isns_add_principal(isns_security_t *, isns_principal_t *);
extern isns_keystore_t *isns_create_keystore(const char *);
extern void		isns_security_set_keystore(isns_security_t *,
				isns_keystore_t *);
extern void		isns_principal_set_name(isns_principal_t *, const char *);
extern const char *	isns_principal_name(const isns_principal_t *);

extern isns_object_template_t	isns_entity_template;
extern isns_object_template_t	isns_portal_template;
extern isns_object_template_t	isns_iscsi_node_template;
extern isns_object_template_t	isns_fc_port_template;
extern isns_object_template_t	isns_fc_node_template;
extern isns_object_template_t	isns_iscsi_pg_template;
extern isns_object_template_t	isns_dd_template;
extern isns_object_template_t	isns_ddset_template;

/*
 * Config file parser
 */
struct isns_config {
	char *		ic_host_name;
	char *		ic_auth_name;
	char *		ic_source_name;
	char *		ic_source_suffix;
	char *		ic_entity_name;

	char *		ic_server_name;
	char *		ic_bind_address;
	char *		ic_database;
	char *		ic_auth_key_file;
	char *		ic_server_key_file;
	char *		ic_client_keystore;
	char *		ic_control_socket;
	char *		ic_pidfile;
	char *		ic_local_registry_file;
	int		ic_security;
	int		ic_slp_register;

	char *		ic_control_name;
	char *		ic_control_key_file;

	unsigned int	ic_registration_period;
	unsigned int	ic_scn_timeout;
	unsigned int	ic_scn_retries;
	char *		ic_scn_callout;

	unsigned int	ic_esi_max_interval;
	unsigned int	ic_esi_min_interval;
	unsigned int	ic_esi_retries;

	unsigned int	ic_use_default_domain;

	struct {
	   unsigned int	policy;
	   unsigned int	replay_window;
	   unsigned int	timestamp_jitter;
	   int		allow_unknown_peers;
	}		ic_auth;
	struct {
	   unsigned int	max_sockets;
	   unsigned int	connect_timeout;
	   unsigned int	reconnect_timeout;
	   unsigned int	call_timeout;
	   unsigned int	udp_retrans_timeout;
	   unsigned int	tcp_retrans_timeout;
	   unsigned int	idle_timeout;
	} ic_network;
	struct {
	   char *	param_file;
	   unsigned int	key_bits;
	} ic_dsa;

};

extern struct isns_config isns_config;
extern int		isns_read_config(const char *);
extern int		isns_config_set(const char *, char *);

/*
 * Reserved entity name for Policy information
 */
#define ISNS_ENTITY_CONTROL	"CONTROL"


/*
 * Helpers to deal with portal information
 */
struct isns_portal_info {
	struct sockaddr_in6	addr;
	int			proto;
};

extern void		isns_portal_init(isns_portal_info_t *,
				const struct sockaddr *, int);
extern int		isns_portal_parse(isns_portal_info_t *portal,
				const char *addr_spec,
				const char *default_port);
extern int		isns_portal_from_attr_list(isns_portal_info_t *,
				uint32_t addr_tag, uint32_t port_tag,
				const isns_attr_list_t *);
extern int		isns_portal_from_attr_pair(isns_portal_info_t *,
				const isns_attr_t *,
				const isns_attr_t *);
extern int		isns_portal_from_object(isns_portal_info_t *,
				uint32_t addr_tag, uint32_t port_tag,
				const isns_object_t *);
extern int		isns_portal_from_sockaddr(isns_portal_info_t *,
				const struct sockaddr_storage *);
extern int		isns_portal_to_sockaddr(const isns_portal_info_t *,
				struct sockaddr_storage *);
extern int		isns_portal_to_attr_list(const isns_portal_info_t *,
				uint32_t addr_tag, uint32_t port_tag,
				isns_attr_list_t *);
extern int		isns_portal_to_object(const isns_portal_info_t *,
				uint32_t addr_tag, uint32_t port_tag,
				isns_object_t *);
extern int		isns_portal_is_wildcard(const isns_portal_info_t *);
extern uint32_t		isns_portal_tcpudp_port(const isns_portal_info_t *);
extern const char *	isns_portal_string(const isns_portal_info_t *);
extern int		isns_portal_equal(const isns_portal_info_t *,
				const isns_portal_info_t *);
extern int		isns_enumerate_portals(isns_portal_info_t *,
				unsigned int);
extern int		isns_get_nr_portals(void);

/* Local registry stuff */
extern int		isns_local_registry_load(const char *, pid_t, isns_object_list_t *);
extern int		isns_local_registry_store(const char *, pid_t, const isns_object_list_t *);
extern int		isns_local_registry_purge(const char *, pid_t);

/* Should go somwhere else .*/
extern int		isns_esi_enabled;

extern void		isns_esi_init(isns_server_t *);
extern void		isns_esi_register(isns_object_t *);

extern void		isns_scn_init(isns_server_t *);
extern time_t		isns_scn_transmit_all(void);

#endif /* ISNS_H */
