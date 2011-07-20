/*
 * Client functions
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

#include <isns.h>
#include "security.h"
#include "util.h"
#include "internal.h"
#include "config.h"

static isns_client_t *
__isns_create_default_client(isns_socket_t *sock, isns_security_t *ctx,
		const char *source_name)
{
	isns_client_t	*clnt;

	clnt = isns_calloc(1, sizeof(*clnt));

	if (!source_name)
		source_name = isns_config.ic_source_name;

	clnt->ic_source = isns_source_create_iscsi(source_name);
	clnt->ic_socket = sock;

	isns_socket_set_security_ctx(clnt->ic_socket, ctx);

	return clnt;
}

isns_client_t *
isns_create_client(isns_security_t *ctx, const char *source_name)
{
	isns_socket_t	*sock;
	const char	*server_name;

	server_name = isns_config.ic_server_name;
	if (!strcasecmp(server_name, "SLP:")
	 && !(server_name = isns_slp_find())) {
		isns_error("Unable to locate iSNS server through SLP\n");
		return NULL;
	}

	sock = isns_create_bound_client_socket(
			isns_config.ic_bind_address,
			server_name,
			"isns", 0, SOCK_STREAM);
	if (sock == NULL) {
		isns_error("Unable to create socket for host \"%s\"\n",
			isns_config.ic_server_name);
		return NULL;
	}

	return __isns_create_default_client(sock,
			ctx? : isns_default_security_context(0),
			source_name);
}

isns_client_t *
isns_create_default_client(isns_security_t *ctx)
{
	return isns_create_client(ctx, isns_config.ic_source_name);
}

isns_client_t *
isns_create_local_client(isns_security_t *ctx, const char *source_name)
{
	isns_socket_t	*sock;

	if (isns_config.ic_control_socket == NULL)
		isns_fatal("Cannot use local mode: no local control socket\n");

	sock = isns_create_client_socket(isns_config.ic_control_socket,
			NULL, 0, SOCK_STREAM);
	if (sock == NULL) {
		isns_error("Unable to create control socket (%s)\n",
			isns_config.ic_control_socket);
		return NULL;
	}

	return __isns_create_default_client(sock, ctx, source_name);
}

int
isns_client_call(isns_client_t *clnt,
		isns_simple_t **inout)
{
	return isns_simple_call(clnt->ic_socket, inout);
}

void
isns_client_destroy(isns_client_t *clnt)
{
	if (clnt->ic_socket)
		isns_socket_free(clnt->ic_socket);
	if (clnt->ic_source)
		isns_source_release(clnt->ic_source);
	isns_free(clnt);
}

/*
 * Get the local address
 */
int
isns_client_get_local_address(const isns_client_t *clnt,
				isns_portal_info_t *portal_info)
{
	return isns_socket_get_portal_info(clnt->ic_socket, portal_info);
}

/*
 * Create a security context
 */
static isns_security_t *
__create_security_context(const char *name, const char *auth_key,
		const char *server_key)
{
#ifdef WITH_SECURITY
	isns_security_t 	*ctx;
	isns_principal_t	*princ;
#endif /* WITH_SECURITY */

	if (!isns_config.ic_security)
		return NULL;

#ifndef WITH_SECURITY
	isns_error("Cannot create security context: security disabled at build time\n");
	return NULL;
#else /* WITH_SECURITY */
	ctx = isns_create_dsa_context();
	if (ctx == NULL)
		isns_fatal("Unable to create security context\n");

	/* Load my own key */
	princ = isns_security_load_privkey(ctx, auth_key);
	if (!princ)
		isns_fatal("Unable to load private key from %s\n",
				auth_key);

	isns_principal_set_name(princ, name);
	isns_security_set_identity(ctx, princ);

	if (server_key) {
		/* We're a client, and we want to load the
		 * server's public key in order to authenticate
		 * the server's responses.
		 */
		princ = isns_security_load_pubkey(ctx, server_key);
		if (!princ)
			isns_fatal("Unable to load public key from %s\n",
					server_key);

		/* Do *not* set a name for this principal -
		 * this will be the default principal used when
		 * verifying the server's reply, which is a good thing
		 * because we don't know what SPI the server will
		 * be using. */
		isns_add_principal(ctx, princ);

		/* But set a policy for the server which allows it
		   to send ESI and SCN messages */
		isns_principal_set_policy(princ, isns_policy_server());
	}

	return ctx;
#endif /* WITH_SECURITY */
}

/*
 * Create the default security context
 */
isns_security_t *
isns_default_security_context(int server_only)
{
	static isns_security_t 	*ctx;

	if (ctx == NULL)
		ctx = __create_security_context(isns_config.ic_auth_name,
				isns_config.ic_auth_key_file,
				server_only? NULL : isns_config.ic_server_key_file);
	return ctx;
}

/*
 * Create the control security context
 */
isns_security_t *
isns_control_security_context(int server_only)
{
	static isns_security_t 	*ctx;

	if (ctx == NULL)
		ctx = __create_security_context(isns_config.ic_control_name,
				isns_config.ic_control_key_file,
				server_only? NULL : isns_config.ic_server_key_file);
	return ctx;
}
