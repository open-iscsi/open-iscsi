/*
 * Use database as policy and keystore
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#include <sys/stat.h>
#include <string.h>
#include <unistd.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include "isns.h"
#include "security.h"
#include "objects.h"
#include "vendor.h"
#include "util.h"
#include "config.h"

/*
 * DB keystore
 */
typedef struct isns_db_keystore isns_db_keystore_t;
struct isns_db_keystore {
	isns_keystore_t		sd_base;
	isns_db_t *		sd_db;
	isns_object_t *		sd_control;
};

/*
 * Look up the policy object given its SPI
 */
isns_object_t *
__isns_db_keystore_lookup(isns_db_keystore_t *store,
		const char *name, size_t namelen)
{
	isns_attr_list_t keys = ISNS_ATTR_LIST_INIT;
	char		namebuf[256];

	if (namelen >= sizeof(namebuf))
		return NULL;
	memcpy(namebuf, name, namelen);
	namebuf[namelen] = '\0';

	isns_attr_list_append_string(&keys,
			OPENISNS_TAG_POLICY_SPI,
			namebuf);
	return isns_db_lookup(store->sd_db, NULL, &keys);
}

/*
 * Load a DSA key from the DB store
 */
static EVP_PKEY *
__isns_db_keystore_find(isns_keystore_t *store_base,
		const char *name, size_t namelen)
{
#ifdef WITH_SECURITY
	isns_db_keystore_t *store = (isns_db_keystore_t *) store_base;
	isns_object_t	*obj;
	const void	*key_data;
	size_t		key_size;

	obj = __isns_db_keystore_lookup(store, name, namelen);
	if (obj == NULL)
		return NULL;

	if (!isns_object_get_opaque(obj, OPENISNS_TAG_POLICY_KEY,
				&key_data, &key_size))
		return NULL;

	return isns_dsa_decode_public(key_data, key_size);
#else
	return NULL;
#endif
}

/*
 * Retrieve policy from database
 */
static void
__isns_db_keystore_copy_policy_string(isns_object_t *obj,
		uint32_t tag, char **var)
{
	const char	*value;

	if (!isns_object_get_string(obj, tag, &value))
		return;
	isns_assign_string(var, value);
}

static void
__isns_db_keystore_copy_policy_strings(isns_object_t *obj,
		uint32_t tag, struct string_array *array)
{
	isns_attr_list_t *attrs = &obj->ie_attrs;
	unsigned int	i;

	for (i = 0; i < attrs->ial_count; ++i) {
		isns_attr_t *attr = attrs->ial_data[i];

		if (attr->ia_tag_id != tag
		 || !ISNS_ATTR_IS_STRING(attr))
			continue;
		isns_string_array_append(array, attr->ia_value.iv_string);
	}
}

static isns_policy_t *
__isns_db_keystore_get_policy(isns_keystore_t *store_base,
		     const char *name, size_t namelen)
{
	isns_db_keystore_t *store = (isns_db_keystore_t *) store_base;
	isns_policy_t	*policy;
	isns_object_t	*obj;
	uint32_t	intval;

	obj = __isns_db_keystore_lookup(store, name, namelen);
	if (obj == NULL)
		return NULL;

	policy = __isns_policy_alloc(name, namelen);

	/* retrieve policy bits from object */
#if 0
	__isns_db_keystore_copy_policy_string(obj,
			OPENISNS_TAG_POLICY_SOURCE_NAME,
			&policy->ip_source);
#endif
	__isns_db_keystore_copy_policy_string(obj,
			OPENISNS_TAG_POLICY_ENTITY,
			&policy->ip_entity);
	__isns_db_keystore_copy_policy_string(obj,
			OPENISNS_TAG_POLICY_DEFAULT_DD,
			&policy->ip_dd_default);
	__isns_db_keystore_copy_policy_strings(obj,
			OPENISNS_TAG_POLICY_NODE_NAME,
			&policy->ip_node_names);

	if (isns_object_get_uint32(obj, OPENISNS_TAG_POLICY_OBJECT_TYPE, &intval))
		policy->ip_object_types = intval;
	if (isns_object_get_uint32(obj, OPENISNS_TAG_POLICY_NODE_TYPE, &intval))
		policy->ip_node_types = intval;
	if (isns_object_get_uint32(obj, OPENISNS_TAG_POLICY_FUNCTIONS, &intval))
		policy->ip_functions = intval;

	return policy;
}

void
__isns_db_keystore_change_notify(const isns_db_event_t *ev, void *handle)
{
	isns_db_keystore_t *store = handle;
	isns_object_t *obj = ev->ie_object;

	if (isns_object_get_entity(obj) == store->sd_control) {
		isns_debug_auth("DB keystore: policy data was modified\n");
		store->sd_base.ic_generation++;
	}
}

isns_keystore_t *
isns_create_db_keystore(isns_db_t *db)
{
	isns_db_keystore_t *store;
	isns_object_t	*entity;

	isns_debug_auth("Creating DB keystore\n");
	if (!(entity = isns_db_get_control(db))) {
		isns_error("Could not create control entity in database\n");
		return NULL;
	}
	isns_debug_auth("Control entity is 0x%08x\n", entity->ie_index);

	store = isns_calloc(1, sizeof(*store));
	store->sd_base.ic_name = "database key store";
	store->sd_base.ic_find = __isns_db_keystore_find;
	store->sd_base.ic_get_policy = __isns_db_keystore_get_policy;
	store->sd_control = entity;
	store->sd_db = db;

	isns_register_callback(__isns_db_keystore_change_notify, store);

	return (isns_keystore_t *) store;
}

