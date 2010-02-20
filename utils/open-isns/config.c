/*
 * Config file reader
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include "isns.h"
#include "util.h"
#include "paths.h"

/*
 * iSNS configuration
 */
struct isns_config	isns_config = {
	/* Security parameters */
	.ic_security		= -1,
	.ic_auth_key_file	= ISNS_ETCDIR "/auth_key",
	.ic_server_key_file	= ISNS_ETCDIR "/server_key.pub",
	.ic_client_keystore	= "DB:",
	.ic_control_socket	= ISNS_RUNDIR "/isnsctl",
	.ic_pidfile		= ISNS_RUNDIR "/isnsd.pid",
	.ic_local_registry_file	= ISNS_DEFAULT_LOCAL_REGISTRY,

	.ic_control_name	= "isns.control",
	.ic_control_key_file	= ISNS_ETCDIR "/control.key",

	.ic_registration_period = 3600,		/* 1 hour */
	.ic_scn_timeout		= 60,
	.ic_scn_retries		= 3,

	.ic_esi_max_interval	= 600,		/* 10 minutes */
	.ic_esi_min_interval	= 60,		/* 1 minute */
	.ic_esi_retries		= 3,

	.ic_auth = {
		.replay_window = 300,		/* 5 min clock skew */
		.timestamp_jitter = 1,		/* 1 sec timestamp jitter */
		.allow_unknown_peers = 1,
	},
	.ic_network = {
		.max_sockets = 1024,
		.connect_timeout = 5,
		.reconnect_timeout = 10,
		.call_timeout = 60,
		.udp_retrans_timeout = 10,
		.tcp_retrans_timeout = 60,
		.idle_timeout = 300,
	},
	.ic_dsa = {
		.param_file = ISNS_ETCDIR "/dsa.params",
	},
};

/*
 * Default string values need to be dup'ed,
 * so that later assignment does't try to free
 * these strings.
 */
static inline void
__isns_config_defaults(void)
{
	static int	defaults_init = 1;

	if (!defaults_init)
		return;

#define DUP(member) \
	if (isns_config.member) \
		isns_config.member = isns_strdup(isns_config.member)

	DUP(ic_source_name);
	DUP(ic_database);
	DUP(ic_server_name);
	DUP(ic_bind_address);
	DUP(ic_auth_key_file);
	DUP(ic_server_key_file);
	DUP(ic_client_keystore);
	DUP(ic_control_socket);
	DUP(ic_pidfile);
	DUP(ic_control_name);
	DUP(ic_control_key_file);
	DUP(ic_local_registry_file);
	DUP(ic_dsa.param_file);

#undef DUP

	defaults_init = 0;
}

/*
 * Read the iSNS configuration file
 */
int
isns_read_config(const char *filename)
{
	FILE	*fp;
	char	*name, *pos;

	__isns_config_defaults();

	if ((fp = fopen(filename, "r")) == NULL) {
		perror(filename);
		return -1;
	}

	while ((pos = parser_get_next_line(fp)) != NULL) {
		pos[strcspn(pos, "#")] = '\0';

		if (!(name = parser_get_next_word(&pos)))
			continue;

		isns_config_set(name, pos);
	}

	fclose(fp);

	/* Massage the config file */
	if (isns_config.ic_security < 0) {
		/* By default, we will enable authentication
		 * whenever we find our private key, and
		 * the server's public key. */
		if (access(isns_config.ic_auth_key_file, R_OK) == 0
		 && access(isns_config.ic_server_key_file, R_OK) == 0)
			isns_config.ic_security = 1;
		else
			isns_config.ic_security = 0;
	}

	isns_init_names();

	return 0;
}

int
isns_config_set(const char *name, char *pos)
{
	char	*value;

	value = parser_get_rest_of_line(&pos);
	if (value)
		while (isspace(*value) || *value == '=')
			++value;
	if (!strcasecmp(name, "HostName")) {
		if (!value)
			goto no_value;
		isns_assign_string(&isns_config.ic_host_name, value);
	} else if (!strcasecmp(name, "SourceName")) {
		if (!value)
			goto no_value;
		isns_assign_string(&isns_config.ic_source_name, value);
	} else if (!strcasecmp(name, "AuthName")) {
		if (!value)
			goto no_value;
		isns_assign_string(&isns_config.ic_auth_name, value);
	} else if (!strcasecmp(name, "Database")) {
		if (!value)
			goto no_value;
		isns_assign_string(&isns_config.ic_database, value);
	} else if (!strcasecmp(name, "ServerAddress")) {
		if (!value)
			goto no_value;
		isns_assign_string(&isns_config.ic_server_name, value);
	} else if (!strcasecmp(name, "BindAddress")) {
		if (!value)
			goto no_value;
		isns_assign_string(&isns_config.ic_bind_address, value);
	} else if (!strcasecmp(name, "ControlSocket")) {
		if (!value)
			goto no_value;
		isns_assign_string(&isns_config.ic_control_socket, value);
	} else if (!strcasecmp(name, "PIDFile")) {
		if (!value)
			goto no_value;
		isns_assign_string(&isns_config.ic_pidfile, value);
	} else if (!strcasecmp(name, "LocalRegistry")) {
		if (!value)
			goto no_value;
		isns_assign_string(&isns_config.ic_local_registry_file, value);
	} else if (!strcasecmp(name, "RegistrationPeriod")) {
		if (!value)
			goto no_value;
		isns_config.ic_registration_period = parse_timeout(value);
	} else if (!strcasecmp(name, "SCNTimeout")) {
		if (!value)
			goto no_value;
		isns_config.ic_scn_timeout = parse_timeout(value);
	} else if (!strcasecmp(name, "SCNRetries")) {
		if (!value)
			goto no_value;
		isns_config.ic_scn_retries = parse_int(value);
	} else if (!strcasecmp(name, "SCNCallout")) {
		if (!value)
			goto no_value;
		isns_assign_string(&isns_config.ic_scn_callout, value);
	} else if (!strcasecmp(name, "ESIMinInterval")) {
		if (!value)
			goto no_value;
		isns_config.ic_esi_min_interval = parse_timeout(value);
	} else if (!strcasecmp(name, "ESIMaxInterval")) {
		if (!value)
			goto no_value;
		isns_config.ic_esi_max_interval = parse_timeout(value);
	} else if (!strcasecmp(name, "ESIRetries")) {
		if (!value)
			goto no_value;
		isns_config.ic_esi_retries = parse_int(value);
	} else if (!strcasecmp(name, "DefaultDiscoveryDomain")) {
		if (!value)
			goto no_value;
		isns_config.ic_use_default_domain = parse_int(value);
	} else if (!strcasecmp(name, "SLPRegister")) {
		if (!value)
			goto no_value;
		isns_config.ic_slp_register = parse_int(value);
	} else if (!strcasecmp(name, "Security")) {
		if (!value)
			goto no_value;
		isns_config.ic_security = parse_int(value);
	} else if (!strcasecmp(name, "AuthKeyFile")) {
		if (!value)
			goto no_value;
		isns_assign_string(&isns_config.ic_auth_key_file, value);
	} else if (!strcasecmp(name, "ServerKeyFile")) {
		if (!value)
			goto no_value;
		isns_assign_string(&isns_config.ic_server_key_file, value);
	} else if (!strcasecmp(name, "ClientKeyStore")
		|| !strcasecmp(name, "KeyStore")) {
		if (!value)
			goto no_value;
		isns_assign_string(&isns_config.ic_client_keystore, value);
	} else if (!strcasecmp(name, "Control.SourceName")) {
		if (!value)
			goto no_value;
		isns_assign_string(&isns_config.ic_control_name, value);
	} else if (!strcasecmp(name, "Control.AuthKeyFile")) {
		if (!value)
			goto no_value;
		isns_assign_string(&isns_config.ic_control_key_file, value);
	} else if (!strcasecmp(name, "Auth.ReplayWindow")) {
		if (!value)
			goto no_value;
		isns_config.ic_auth.replay_window = parse_timeout(value);
	} else if (!strcasecmp(name, "Auth.TimestampJitter")) {
		if (!value)
			goto no_value;
		isns_config.ic_auth.timestamp_jitter = parse_timeout(value);
	} else if (!strcasecmp(name, "Network.MaxSockets")) {
		if (!value)
			goto no_value;
		isns_config.ic_network.max_sockets = parse_timeout(value);
	} else if (!strcasecmp(name, "Network.ConnectTimeout")) {
		if (!value)
			goto no_value;
		isns_config.ic_network.connect_timeout = parse_timeout(value);
	} else if (!strcasecmp(name, "Network.ReconnectTimeout")) {
		if (!value)
			goto no_value;
		isns_config.ic_network.reconnect_timeout = parse_timeout(value);
	} else if (!strcasecmp(name, "Network.CallTimeout")) {
		if (!value)
			goto no_value;
		isns_config.ic_network.call_timeout = parse_timeout(value);
	} else {
		fprintf(stderr, "Unknown config item %s=%s\n", name, value);
	}
	return 0;

no_value:
	fprintf(stderr,
		"*** Missing value in configuration assignment for %s ***\n",
		name);
	return -1;
}
