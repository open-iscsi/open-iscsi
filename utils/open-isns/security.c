/*
 * Security functions for iSNS
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "isns.h"
#include "security.h"
#include "source.h"
#include "util.h"
#include "config.h"

#ifdef WITH_SECURITY

/*
 * Allocate a security peer
 */
static isns_principal_t *
isns_create_principal(const char *spi, size_t spi_len, EVP_PKEY *pk)
{
	char		keydesc[32];
	isns_principal_t *peer;

	peer = isns_calloc(1, sizeof(*peer));
	peer->is_users = 1;
	if (spi) {
		peer->is_name = isns_malloc(spi_len + 1);
		memcpy(peer->is_name, spi, spi_len);
		peer->is_name[spi_len] = '\0';
		peer->is_namelen = spi_len;
	}

	peer->is_key = pk;
	if (pk) {
		const char	*algo;

		switch (pk->type) {
		case EVP_PKEY_DSA: algo = "DSA"; break;
		case EVP_PKEY_RSA: algo = "RSA"; break;
		default: algo = "unknown"; break;
		}

		snprintf(keydesc, sizeof(keydesc), " (%s/%u)",
				algo, EVP_PKEY_bits(pk));
	}

	isns_debug_auth("Created security principal \"%s\"%s\n",
			peer->is_name, keydesc);
	return peer;
}

static void
isns_principal_set_key(isns_principal_t *princ, EVP_PKEY *key)
{
	if (princ->is_key == key)
		return;
	if (princ->is_key)
		EVP_PKEY_free(princ->is_key);
	princ->is_key = key;
}

void
isns_principal_free(isns_principal_t *peer)
{
	if (!peer)
		return;

	isns_assert(peer->is_users);
	if (--(peer->is_users))
		return;

	if (peer->is_name)
		isns_free(peer->is_name);
	if (peer->is_key)
		EVP_PKEY_free(peer->is_key);
	isns_policy_release(peer->is_policy);
	isns_free(peer);
}

/*
 * Set the principal's name
 */
void
isns_principal_set_name(isns_principal_t *princ, const char *spi)
{
	isns_assign_string(&princ->is_name, spi);
	isns_debug_auth("Setting principal name to \"%s\"\n", spi);
}

const char *
isns_principal_name(const isns_principal_t *princ)
{
	return princ->is_name;
}

/*
 * Cache policy in the principal object.
 */
void
isns_principal_set_policy(isns_principal_t *princ,
		isns_policy_t *policy)
{
	if (policy)
		policy->ip_users++;
	isns_policy_release(princ->is_policy);
	princ->is_policy = policy;
}

/*
 * Key management functions for a security context.
 */
isns_principal_t *
isns_security_load_privkey(isns_security_t *ctx, const char *filename)
{
	EVP_PKEY	*pkey;

	isns_debug_auth("Loading private %s key from %s\n",
				ctx->is_name, filename);
	if (!ctx->is_load_private)
		return NULL;
	if (!(pkey = ctx->is_load_private(ctx, filename))) {
		isns_error("Unable to load private %s key from %s\n",
				ctx->is_name, filename);
		return NULL;
	}

	return isns_create_principal(NULL, 0, pkey);
}

isns_principal_t *
isns_security_load_pubkey(isns_security_t *ctx, const char *filename)
{
	EVP_PKEY	*pkey;

	isns_debug_auth("Loading public %s key from %s\n",
				ctx->is_name, filename);
	if (!ctx->is_load_public)
		return NULL;
	if (!(pkey = ctx->is_load_public(ctx, filename))) {
		isns_error("Unable to load public %s key from %s\n",
				ctx->is_name, filename);
		return NULL;
	}

	return isns_create_principal(NULL, 0, pkey);
}

void
isns_security_set_identity(isns_security_t *ctx, isns_principal_t *princ)
{
	if (princ)
		princ->is_users++;
	if (ctx->is_self)
		isns_principal_free(ctx->is_self);
	ctx->is_self = princ;
}

void
isns_add_principal(isns_security_t *ctx, isns_principal_t *princ)
{
	if (princ)
		princ->is_users++;
	princ->is_next = ctx->is_peers;
	ctx->is_peers = princ;
}

isns_principal_t *
isns_get_principal(isns_security_t *ctx, const char *spi, size_t spi_len)
{
	isns_principal_t *princ;
	isns_policy_t	*policy;
	isns_keystore_t *ks;
	EVP_PKEY	*pk;

	ks = ctx->is_peer_keys;

	for (princ = ctx->is_peers; princ; princ = princ->is_next) {
		/* In a client socket, we set the (expected)
		 * public key of the peer through
		 * isns_security_set_peer_key, which will
		 * just put it on the peers list.
		 * This key usually has no name.
		 */
		if (princ->is_name == NULL) {
			princ->is_users++;
			return princ;
		}
		if (spi_len == princ->is_namelen
		 && !memcmp(princ->is_name, spi, spi_len)) {
			/* Check whether the cached key and policy
			 * might be stale. */
			if (ks && ks->ic_generation != princ->is_generation) {
				pk = ks->ic_find(ks, spi, spi_len);
				if (pk == NULL) {
					isns_debug_auth("Unable to refresh key "
						"for principal %.*s - probably deleted\n",
						spi_len, spi);
					return NULL;
				}
				isns_debug_auth("Refresh key for principal %.*s\n",
						spi_len, spi);
				isns_principal_set_key(princ, pk);
				princ->is_users++;
				goto refresh_policy;
			}
			princ->is_users++;
			return princ;
		}
	}

	if ((ks = ctx->is_peer_keys) == NULL)
		return NULL;

	if (!(pk = ks->ic_find(ks, spi, spi_len)))
		return NULL;
	princ = isns_create_principal(spi, spi_len, pk);

	/* Add it to the list */
	princ->is_next = ctx->is_peers;
	ctx->is_peers = princ;
	princ->is_users++;

	/* Bind the policy for this peer */
refresh_policy:
	if (!ks->ic_get_policy
	 || !(policy = ks->ic_get_policy(ks, spi, spi_len)))
		policy = isns_policy_default(spi, spi_len);

	/* If no entity is set, use the SPI */
	if (policy->ip_entity == NULL)
		isns_assign_string(&policy->ip_entity, policy->ip_name);

	/* If the list of permitted node names is empty,
	 * default to the standard pattern derived from
	 * the reversed entity name */
	if (policy->ip_node_names.count == 0) {
		char	*pattern;

		pattern = isns_build_source_pattern(policy->ip_entity);
		if (pattern != NULL)
			isns_string_array_append(&policy->ip_node_names,
					pattern);
		isns_free(pattern);
	}

	isns_principal_set_policy(princ, policy);
	isns_policy_release(policy);

	/* Remember the keystore generation number */
	princ->is_generation = ks->ic_generation;

	return princ;
}

/*
 * Create a keystore for a security context.
 * Key stores let the server side retrieve the
 * keys associated with a given SPI.
 *
 * For now, we support just simple key stores,
 * but this could be extended to support
 * URLs such as ldaps://ldap.example.com
 */
isns_keystore_t *
isns_create_keystore(const char *spec)
{
	if (*spec != '/')
		return NULL;

	return isns_create_simple_keystore(spec);
}

/*
 * Attach the keystore to the security context
 */
void
isns_security_set_keystore(isns_security_t *ctx,
			isns_keystore_t *ks)
{
	ctx->is_peer_keys = ks;
}

/*
 * Check that the client supplied time stamp is within a
 * certain window.
 */
static int
isns_security_check_timestamp(isns_security_t *ctx,
					isns_principal_t *peer,
					uint64_t timestamp)
{
	int64_t	delta;

	/* The time stamp must not be earlier than timestamp_jitter
	 * before the last message received. */
	if (peer->is_timestamp) {
		delta = timestamp - peer->is_timestamp;
		if (delta < -(int64_t) ctx->is_timestamp_jitter)
			return 0;
	}

	/* We allow the client's clock to diverge from ours, within
	 * certain limits. */
	if (ctx->is_replay_window != 0) {
		time_t	now = time(NULL);

		delta = timestamp - now;
		if (delta < 0)
			delta = -delta;
		if (delta > ctx->is_replay_window)
			return 0;
	}

	peer->is_timestamp = timestamp;
	return 1;
}

int
isns_security_sign(isns_security_t *ctx, isns_principal_t *peer,
		buf_t *bp, struct isns_authblk *auth)
{
	if (!ctx->is_sign) {
		isns_debug_auth("isns_security_sign: auth context without "
				"sign handler.\n");
		return 0;
	}
	if (!ctx->is_sign(ctx, peer, bp, auth)) {
		isns_debug_auth("Failed to sign message, spi=%s\n",
				peer->is_name);
		return 0;
	}

	return 1;
}

int
isns_security_verify(isns_security_t *ctx, isns_principal_t *peer,
		buf_t *bp, struct isns_authblk *auth)
{
	if (!isns_security_check_timestamp(ctx, peer, auth->iab_timestamp)) {
		isns_debug_auth("Possible replay attack (bad timestamp) "
				"from spi=%s\n", peer->is_name);
		return 0;
	}

	if (!ctx->is_verify) {
		isns_debug_auth("isns_security_verify: auth context without "
				"verify handler.\n");
		return 0;
	}
	if (!ctx->is_verify(ctx, peer, bp, auth)) {
		isns_debug_auth("Failed to authenticate message, spi=%s\n",
				peer->is_name);
		return 0;
	}

	return 1;
}

/*
 * Initialize security services.
 */
int
isns_security_init(void)
{
	if (!isns_config.ic_dsa.param_file) {
		isns_error("No DSA parameter file - please edit configuration\n");
		return 0;
	}

	if (!isns_dsa_init_params(isns_config.ic_dsa.param_file))
		return 0;

	if (!isns_config.ic_auth_key_file) {
		isns_error("No AuthKey specified; please edit configuration\n");
		return 0;
	}

	if (!isns_dsa_init_key(isns_config.ic_auth_key_file))
		return 0;

	return 1;
}

#else /* WITH_SECURITY */

static void
isns_no_security(void)
{
	static int complain = 0;

	if (complain++ < 5)
		isns_error("iSNS authentication disabled in this build\n");
}

int
isns_security_init(void)
{
	isns_no_security();
	return 0;
}

isns_keystore_t *
isns_create_keystore(const char *spec)
{
	isns_no_security();
	return NULL;
}

void
isns_security_set_keystore(isns_security_t *ctx,
			isns_keystore_t *ks)
{
	isns_no_security();
}

void
isns_principal_free(isns_principal_t *peer)
{
}

isns_principal_t *
isns_get_principal(isns_security_t *ctx, const char *spi, size_t spi_len)
{
	return NULL;
}

const char *
isns_principal_name(const isns_principal_t *princ)
{
	return NULL;
}

#endif /* WITH_SECURITY */
