/*
 * Security functions for iSNS
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#ifndef ISNS_SECURITY_H
#define ISNS_SECURITY_H

#include <openssl/evp.h>
#include "buffer.h"
#include "util.h"

/*
 * Security context
 */
struct isns_security {
	const char *		is_name;
	unsigned int		is_type;
	unsigned int		is_replay_window;
	unsigned int		is_timestamp_jitter;

	/* Our own key and identity */
	isns_principal_t *	is_self;

	/* Key store for peer keys */
	isns_principal_t *	is_peers;
	isns_keystore_t *	is_peer_keys;

	EVP_PKEY *		(*is_load_private)(isns_security_t *ctx,
					const char *filename);
	EVP_PKEY *		(*is_load_public)(isns_security_t *ctx,
					const char *filename);
	int			(*is_verify)(isns_security_t *ctx,
					isns_principal_t *peer,
					buf_t *pdu,
					const struct isns_authblk *);
	int			(*is_sign)(isns_security_t *ctx,
					isns_principal_t *peer,
					buf_t *pdu,
					struct isns_authblk *);
};

struct isns_principal {
	unsigned int		is_users;
	isns_principal_t *	is_next;
	char *			is_name;
	unsigned int		is_namelen;
	EVP_PKEY *		is_key;
	unsigned int		is_generation;
	uint64_t		is_timestamp;

	isns_policy_t *		is_policy;
};

struct isns_policy {
	unsigned int		ip_users;
	unsigned int		ip_gen;

	/* SPI */
	char *			ip_name;

	/* The client's entity name. This is usually
	 * the FQDN. */
	char *			ip_entity;

	/* Bitmap of functions the client is
	 * permitted to call. */
	unsigned int		ip_functions;

	/* Bitmap of object types the client is
	 * permitted to register (uses iot_handle) */
	unsigned int		ip_object_types;

	/* Names of storage nodes the client is permitted
	 * to register. */
	struct string_array	ip_node_names;

	/* Storage node types the client is permitted
	 * to read or modify. */
	unsigned int		ip_node_types;

	/* The client's default Discovery Domain */
	char *			ip_dd_default;
};

#define ISNS_PERMISSION_READ	0x01
#define ISNS_PERMISSION_WRITE	0x02
#define ISNS_ACCESS(t, p)	((p) << (2 * (t)))
#define ISNS_ACCESS_W(t)	ISNS_ACCESS(t, ISNS_PERMISSION_WRITE)
#define ISNS_ACCESS_R(t)	ISNS_ACCESS(t, ISNS_PERMISSION_READ)
#define ISNS_ACCESS_RW(t)	ISNS_ACCESS(t, ISNS_PERMISSION_READ|ISNS_PERMISSION_WRITE)

#define ISNS_DEFAULT_OBJECT_ACCESS \
		ISNS_ACCESS_RW(ISNS_OBJECT_TYPE_ENTITY) | \
		ISNS_ACCESS_RW(ISNS_OBJECT_TYPE_NODE) | \
		ISNS_ACCESS_RW(ISNS_OBJECT_TYPE_FC_PORT) | \
		ISNS_ACCESS_RW(ISNS_OBJECT_TYPE_FC_NODE) | \
		ISNS_ACCESS_RW(ISNS_OBJECT_TYPE_PORTAL) | \
		ISNS_ACCESS_RW(ISNS_OBJECT_TYPE_PG) | \
		ISNS_ACCESS_R(ISNS_OBJECT_TYPE_DD)

struct isns_keystore {
	char *			ic_name;
	unsigned int		ic_generation;
	EVP_PKEY *		(*ic_find)(isns_keystore_t *,
					const char *, size_t);
	isns_policy_t *		(*ic_get_policy)(isns_keystore_t *,
					const char *, size_t);
};

extern isns_principal_t *	isns_get_principal(isns_security_t *,
					const char *, size_t);
extern int			isns_security_sign(isns_security_t *,
					isns_principal_t *, buf_t *,
					struct isns_authblk *);
extern int			isns_security_verify(isns_security_t *,
					isns_principal_t *, buf_t *,
					struct isns_authblk *);
extern int			isns_security_protected_entity(isns_security_t *,
					const char *);

extern isns_keystore_t *	isns_create_keystore(const char *);
extern isns_keystore_t *	isns_create_simple_keystore(const char *);
extern isns_keystore_t *	isns_create_db_keystore(isns_db_t *);

extern int			isns_authblock_encode(buf_t *,
					const struct isns_authblk *);
extern int			isns_authblock_decode(buf_t *,
					struct isns_authblk *);

extern isns_policy_t *		__isns_policy_alloc(const char *, size_t);
extern isns_policy_t *		isns_policy_bind(const isns_message_t *);
extern void			isns_principal_set_policy(isns_principal_t *,
					isns_policy_t *);
extern void			isns_policy_release(isns_policy_t *);
extern int			isns_policy_validate_function(const isns_policy_t *,
					const isns_message_t *);
extern int			isns_policy_validate_source(const isns_policy_t *,
					const isns_source_t *);
extern int			isns_policy_validate_object_access(const isns_policy_t *,
					const isns_source_t *,
					const isns_object_t *,
					unsigned int);
extern int			isns_policy_validate_object_update(const isns_policy_t *,
					const isns_source_t *,
					const isns_object_t *,
					const isns_attr_list_t *,
					unsigned int);
extern int			isns_policy_validate_object_creation(const isns_policy_t *,
					const isns_source_t *,
					isns_object_template_t *,
					const isns_attr_list_t *,
					const isns_attr_list_t *,
					unsigned int);
extern int			isns_policy_validate_object_type(const isns_policy_t *,
					isns_object_template_t *,
					unsigned int function);
extern int			isns_policy_validate_node_type(const isns_policy_t *,
					uint32_t type);
extern int			isns_policy_validate_entity(const isns_policy_t *,
					const char *);
extern int			isns_policy_validate_node_name(const isns_policy_t *,
					const char *);
extern int			isns_policy_validate_scn_bitmap(const isns_policy_t *,
					uint32_t);
extern const char *		isns_policy_default_entity(const isns_policy_t *);
extern isns_policy_t *		isns_policy_default(const char *, size_t);
extern isns_policy_t *		isns_policy_server(void);

extern EVP_PKEY *		isns_dsa_decode_public(const void *, size_t);
extern int			isns_dsa_encode_public(EVP_PKEY *,
					void **, size_t *);
extern EVP_PKEY *		isns_dsa_load_public(const char *);
extern int			isns_dsa_store_private(const char *, EVP_PKEY *);
extern EVP_PKEY *		isns_dsa_generate_key(void);
extern int			isns_dsa_init_params(const char *);
extern int			isns_dsa_init_key(const char *);

#endif /* ISNS_SECURITY_H */
