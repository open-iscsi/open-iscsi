/*
 * iSCSI Configuration Reader/Updater
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

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "config.h"
#include "log.h"

void
iscsi_init_config_defaults(struct iscsi_config_defaults *defaults)
{
	/* enabled/disabled */
	defaults->enabled = 1;

	/* discovery defaults */
	defaults->continuous_sendtargets = 1;	/* auto detect */
	defaults->send_async_text = 1;
#ifdef SLP_ENABLE
	defaults->slp_multicast = 1;
#else
	defaults->slp_multicast = 0;
#endif
	defaults->slp_scopes = NULL;
	defaults->slp_poll_interval = 5 * 60;	/* 5 minutes */

	/* auth options */
	defaults->auth_options.authmethod = CHAP_AUTHENTICATION;
	defaults->auth_options.password_length = 0;
	defaults->auth_options.password_length_in = 0;

	/* connection timeouts */
	defaults->connection_timeout_options.login_timeout = 15;
	defaults->connection_timeout_options.auth_timeout = 45;
	defaults->connection_timeout_options.active_timeout = 5;
	defaults->connection_timeout_options.idle_timeout = 60;
	defaults->connection_timeout_options.ping_timeout = 5;

	/* error timeouts */
	defaults->error_timeout_options.abort_timeout = 10;
	defaults->error_timeout_options.reset_timeout = 30;

	/* session timeouts */
	defaults->session_timeout_options.replacement_timeout = 0;

	/* tcp options */
	defaults->tcp_options.window_size = 256 * 1024;

	/* iSCSI operational parameters */
	defaults->iscsi_options.InitialR2T = 0;
	defaults->iscsi_options.ImmediateData = 1;
	defaults->iscsi_options.MaxRecvDataSegmentLength = 128 * 1024;
	defaults->iscsi_options.FirstBurstLength = 256 * 1024;
	defaults->iscsi_options.MaxBurstLength = (16 * 1024 * 1024) - 1024;
	defaults->iscsi_options.DefaultTime2Wait = 0;	
				/* we only use session reinstatement (ERL 0) */
	defaults->iscsi_options.DefaultTime2Retain = 0;	
				/* we only use session reinstatement (ERL 0) */
	defaults->iscsi_options.HeaderDigest = CONFIG_DIGEST_PREFER_OFF;
	defaults->iscsi_options.DataDigest = CONFIG_DIGEST_PREFER_OFF;

}

char *
get_iscsi_initiatorname(char *pathname)
{
	FILE *f = NULL;
	int c;
	char *line, buffer[1024];
	char *name = NULL;

	if (!pathname) {
		log_error("No pathname to load InitiatorName from");
		return NULL;
	}

	/* get the InitiatorName */
	if ((f = fopen(pathname, "r"))) {
		while ((line = fgets(buffer, sizeof (buffer), f))) {

			while (line && isspace(c = *line))
				line++;

			if (strncmp(line, "InitiatorName=", 14) == 0) {
				char *end = line + 14;

				/* the name is everything up to the first
				 * bit of whitespace
				 */
				while (*end && (!isspace(c = *end)))
					end++;

				if (isspace(c = *end))
					*end = '\0';

				if (end > line + 14)
					name = strdup(line + 14);
			}
		}
		fclose(f);
		if (!name) {
			log_error(
			       "an InitiatorName is required, but "
			       "was not found in %s", pathname);
			return NULL;
		} else {
			log_debug(5, "InitiatorName=%s\n", name);
		}
		return name;
	} else {
		log_error("cannot open InitiatorName configuration file %s",
			 pathname);
		return NULL;
	}
}

int
add_config_entry(struct iscsi_config *config, struct iscsi_config_entry *entry)
{
	if (config == NULL || entry == NULL)
		return 0;

	if (config->head) {
		entry->prev = config->tail;
		entry->next = NULL;
		config->tail->next = entry;
		config->tail = entry;
	} else {
		entry->next = entry->prev = NULL;
		config->head = config->tail = entry;
	}

	return 1;
}

int
remove_config_entry(struct iscsi_config *config,
		    struct iscsi_config_entry *entry)
{
	if (config == NULL || entry == NULL)
		return 0;

	if (entry == config->head) {
		config->head = entry->next;
		if (config->head == NULL)
			config->tail = NULL;
		entry->next = entry->prev = NULL;
		return 1;
	} else if (entry == config->tail) {
		entry->prev->next = NULL;
		config->tail = entry->prev;
		entry->next = entry->prev = NULL;
		return 1;
	} else if (entry->prev && entry->next) {
		entry->prev->next = entry->next;
		entry->next->prev = entry->prev;
		entry->next = entry->prev = NULL;
		return 1;
	} else {
		return 0;
	}
}

void
free_config_entry(struct iscsi_config_entry *entry)
{
	if (entry == NULL)
		return;

	switch (entry->type) {
	case CONFIG_TYPE_SENDTARGETS:{
			struct iscsi_sendtargets_config *sendtargets =
			    entry->config.sendtargets;

			if (sendtargets->address) {
				free(sendtargets->address);
				sendtargets->address = NULL;
			}

			free(sendtargets);
			entry->config.sendtargets = NULL;
			break;
		}
	case CONFIG_TYPE_SLP:{
			struct iscsi_slp_config *slp = entry->config.slp;

			if (slp->interfaces) {
				free(slp->interfaces);
				slp->interfaces = NULL;
			}

			if (slp->address) {
				free(slp->address);
				slp->address = NULL;
			}

			if (slp->scopes) {
				free(slp->scopes);
				slp->scopes = NULL;
			}

			free(slp);
			entry->config.slp = NULL;
			break;
		}
	case CONFIG_TYPE_DISCOVERY_FILE:{
			struct iscsi_discovery_file_config *file =
			    entry->config.file;

			if (file->filename) {
				free(file->filename);
				file->filename = NULL;
			}
			if (file->address) {
				free(file->address);
				file->address = NULL;
			}
			if (file->port) {
				free(file->port);
				file->port = NULL;
			}

			free(file);
			entry->config.file = NULL;
			break;
		}
	case CONFIG_TYPE_TARGETNAME:{
			struct iscsi_targetname_config *targetname =
			    entry->config.targetname;

			if (targetname->TargetName)
				free(targetname->TargetName);

			free(targetname);
			entry->config.targetname = NULL;
			break;
		}
	case CONFIG_TYPE_SUBNET:{
			struct iscsi_subnet_config *subnet =
			    entry->config.subnet;

			if (subnet->address)
				free(subnet->address);

			free(subnet);
			entry->config.subnet = NULL;
			break;
		}
	default:
		log_error("can't free unknown config entry %p type %u\n",
		       entry, entry->type);
		break;
	}

	free(entry);
}

struct iscsi_auth_config *
entry_auth_options(struct iscsi_config_entry *entry)
{
	if (entry == NULL)
		return NULL;

	switch (entry->type) {
	case CONFIG_TYPE_SENDTARGETS:{
			struct iscsi_sendtargets_config *sendtargets =
			    entry->config.sendtargets;

			return &sendtargets->auth_options;
		}
	case CONFIG_TYPE_SLP:{
			struct iscsi_slp_config *slp = entry->config.slp;

			return &slp->auth_options;
		}
	case CONFIG_TYPE_DISCOVERY_FILE:{
			struct iscsi_discovery_file_config *file =
			    entry->config.file;

			return &file->auth_options;
		}
	case CONFIG_TYPE_TARGETNAME:{
#ifdef PER_TARGETNAME_AUTH
			struct iscsi_targetname_config *targetname =
			    entry->config.targetname;

			return &targetname->auth_options;
#else
			/* disable configuring auth by TargetName for now,
			 * and always get the auth options at run-time
			 * from discovery
			 */
			return NULL;
#endif
		}
	case CONFIG_TYPE_SUBNET:{
			return NULL;
		}
	default:
		return NULL;
	}
}

struct iscsi_connection_timeout_config *
entry_connection_timeout_options(struct iscsi_config_entry *entry)
{
	if (entry == NULL)
		return NULL;

	switch (entry->type) {
	case CONFIG_TYPE_SENDTARGETS:{
			struct iscsi_sendtargets_config *sendtargets =
			    entry->config.sendtargets;

			return &sendtargets->connection_timeout_options;
		}
	case CONFIG_TYPE_SLP:{
			return NULL;
		}
	case CONFIG_TYPE_TARGETNAME:{
			struct iscsi_targetname_config *targetname =
			    entry->config.targetname;

			return &targetname->connection_timeout_options;
		}
	case CONFIG_TYPE_SUBNET:{
			struct iscsi_subnet_config *subnet =
			    entry->config.subnet;

			return &subnet->connection_timeout_options;
		}
	default:
		return NULL;
	}
}

struct iscsi_session_timeout_config *
entry_session_timeout_options(struct iscsi_config_entry *entry)
{
	if (entry == NULL)
		return NULL;

	switch (entry->type) {
	case CONFIG_TYPE_SENDTARGETS:{
			return NULL;
		}
	case CONFIG_TYPE_SLP:{
			return NULL;
		}
	case CONFIG_TYPE_TARGETNAME:{
			struct iscsi_targetname_config *targetname =
			    entry->config.targetname;

			return &targetname->session_timeout_options;
		}
	case CONFIG_TYPE_SUBNET:{
			return NULL;
		}
	default:
		return NULL;
	}
}

struct iscsi_error_timeout_config *
entry_error_timeout_options(struct iscsi_config_entry *entry)
{
	if (entry == NULL)
		return NULL;

	switch (entry->type) {
	case CONFIG_TYPE_SENDTARGETS:{
			return NULL;
		}
	case CONFIG_TYPE_SLP:{
			return NULL;
		}
	case CONFIG_TYPE_TARGETNAME:{
			struct iscsi_targetname_config *targetname =
			    entry->config.targetname;

			return &targetname->error_timeout_options;
		}
	case CONFIG_TYPE_SUBNET:{
			struct iscsi_subnet_config *subnet =
			    entry->config.subnet;

			return &subnet->error_timeout_options;
		}
	default:
		return NULL;
	}
}

struct iscsi_tcp_config *
entry_tcp_options(struct iscsi_config_entry *entry)
{
	if (entry == NULL)
		return NULL;

	switch (entry->type) {
	case CONFIG_TYPE_SENDTARGETS:{
			return NULL;
		}
	case CONFIG_TYPE_SLP:{
			return NULL;
		}
	case CONFIG_TYPE_TARGETNAME:{
			struct iscsi_targetname_config *targetname =
			    entry->config.targetname;

			return &targetname->tcp_options;
		}
	case CONFIG_TYPE_SUBNET:{
			struct iscsi_subnet_config *subnet =
			    entry->config.subnet;

			return &subnet->tcp_options;
		}
	default:
		return NULL;
	}
}

struct iscsi_operational_config *
entry_iscsi_options(struct iscsi_config_entry *entry)
{
	if (entry == NULL)
		return NULL;

	switch (entry->type) {
	case CONFIG_TYPE_SENDTARGETS:{
			return NULL;
		}
	case CONFIG_TYPE_SLP:{
			return NULL;
		}
	case CONFIG_TYPE_TARGETNAME:{
			struct iscsi_targetname_config *targetname =
			    entry->config.targetname;

			return &targetname->iscsi_options;
		}
	case CONFIG_TYPE_SUBNET:{
			return NULL;
		}
	default:
		return NULL;
	}
}

int
same_portal_descriptor(struct iscsi_portal_descriptor *p1,
		       struct iscsi_portal_descriptor *p2)
{
	if (p1->port != p2->port)
		return 0;

	if (p1->tag != p2->tag)
		return 0;

	if (p1->ip_length != p2->ip_length)
		return 0;

	if (memcmp(p1->ip, p2->ip, p1->ip_length))
		return 0;

	return 1;
}

int
same_portal_descriptors(struct iscsi_portal_descriptor *portals1,
			struct iscsi_portal_descriptor *portals2)
{
	struct iscsi_portal_descriptor *p1, *p2;

	if (portals1 && !portals2)
		return 0;

	if (!portals1 && portals2)
		return 0;

	/* same when p1 is a subset of p2 and p2 is a subset of p1 */

	for (p1 = portals1; p1; p1 = p1->next) {
		int same = 0;

		for (p2 = portals2; p2; p2 = p2->next) {
			if (same_portal_descriptor(p1, p2)) {
				same = 1;
				break;
			}
		}

		if (!same)
			return 0;
	}

	for (p2 = portals2; p2; p2 = p2->next) {
		int same = 0;

		for (p1 = portals1; p1; p1 = p1->next) {
			if (same_portal_descriptor(p1, p2)) {
				same = 1;
				break;
			}
		}

		if (!same)
			return 0;
	}

	return 1;
}

int
same_portal_config(struct iscsi_portal_config *p1,
		   struct iscsi_portal_config *p2)
{
	/* Note: this needs to be updated whenever new structures are
	 * added to the portal config
	 */
	if (memcmp
	    (&p1->connection_timeout_options, &p2->connection_timeout_options,
	     sizeof (p1->connection_timeout_options)))
		return 0;

	if (memcmp(&p1->session_timeout_options, &p2->session_timeout_options,
		   sizeof (p1->session_timeout_options)))
		return 0;

	if (memcmp(&p1->error_timeout_options, &p2->error_timeout_options,
		   sizeof (p1->error_timeout_options)))
		return 0;

	if (memcmp(&p1->tcp_options, &p2->tcp_options,
		   sizeof (p1->tcp_options)))
		return 0;

	if (memcmp(&p1->iscsi_options, &p2->iscsi_options,
		   sizeof (p1->iscsi_options)))
		return 0;

	if (!same_portal_descriptor(p1->descriptor, p2->descriptor))
		return 0;

	return 1;
}

int
same_portal_configs(struct iscsi_portal_config *p1,
		    struct iscsi_portal_config *p2)
{
	/* FIXME: ordering currently matters, but perhaps shouldn't */
	while (p1 || p2) {

		if (p1 && !p2)
			return 0;

		if (!p1 && p2)
			return 0;

		if (!same_portal_config(p1, p2))
			return 0;

		p1 = p1->next;
		p2 = p2->next;
	}

	return 1;
}

int
same_session_config(struct iscsi_session_config *s1,
		    struct iscsi_session_config *s2)
{
	/* Note: this needs to be updated whenever fields are
	 * added to struct iscsi_session_config
	 */

	if (s1->iscsi_bus != s2->iscsi_bus)
		return 0;

	if (s1->target_id != s2->target_id)
		return 0;

	if (memcmp(s1->isid, s2->isid, sizeof (s1->isid)))
		return 0;

	if (s1->path_number != s2->path_number)
		return 0;

	if (!same_portal_config(s1->portal, s2->portal))
		return 0;

	return 1;
}

int
same_target_config(struct iscsi_target_config *t1,
		   struct iscsi_target_config *t2)
{
	/* Note: this needs to be updated whenever fields are
	 * added to struct iscsi_target_config
	 */

	if (!t1 && !t2)
		return 1;

	if (t1 && !t2)
		return 0;

	if (!t1 && t2)
		return 0;

	if (t1->enabled != t2->enabled)
		return 0;

	if (memcmp
	    (&t1->auth_options, &t2->auth_options, sizeof (t1->auth_options)))
		return 0;

	/* we don't recursively compare session configs */

	return 1;
}

void
free_portal_descriptors(struct iscsi_portal_descriptor *portals)
{
	struct iscsi_portal_descriptor *portal;

	while ((portal = portals)) {
		portals = portal->next;
		if (portal->address) {
			log_debug(6, "freeing portal descriptor address %p",
				 portal->address);
			free(portal->address);
		}
		log_debug(6, "freeing portal descriptor %p", portal);
		free(portal);
	}
}

void
free_session_config(struct iscsi_session_config *config)
{

	/* free the portal config */

	/*
	 * we assume something else (the daemon's struct iscsi_target)
	 * is managing the lifetime of the descriptors, so we
	 * don't free them here.
	 */

	log_debug(6, "freeing portal config %p of session config %p",
		 config->portal, config);
	free(config->portal);

	/* and the config itself */
	log_debug(6, "freeing session config %p of target config %p", config,
		 config->target);
	free(config);
}

void
free_target_config(struct iscsi_target_config *config)
{
	struct iscsi_session_config *session;

	/* free the session configs */
	while ((session = config->sessions)) {
		config->sessions = session->next;

		free_session_config(session);
	}

	/* we assume something else (the daemon's struct iscsi_target)
	 * is managing the lifetime of the TargetName, so we dont
	 * free it here.
	 */
	config->TargetName = NULL;

	/* don't leave passwords in memory */
	memset(&config->auth_options, 0, sizeof (config->auth_options));

	/* free the config itself */
	log_debug(6, "freeing target config %p", config);
	free(config);
}

int
parse_boolean(char *str)
{
	char *end = str;
	int value = -1;
	int c;

	/* stop at the first whitespace */
	while (*end && !isspace(c = *end))
		end++;
	*end = '\0';

	if (strncasecmp(str, "yes", 3) == 0) {
		value = 1;
	} else if (strncasecmp(str, "no", 2) == 0) {
		value = 0;
	} else {
		value = strtol(str, &end, 0);
		/* check for invalid input */
		if (*str && (*end != '\0'))
			value = -1;
	}

	return value;
}

int
parse_number(char *str)
{
	char *end = str;
	int number = -1;
	int c;

	/* stop at the first whitespace */
	while (*end && !isspace(c = *end))
		end++;
	*end = '\0';

	number = strtol(str, &end, 0);

	if (*str && (*end == '\0'))
		return number;	/* it was all valid */
	else
		return -1;	/* something was invalid */
}

/* FIXME: accept suffixes for seconds, minutes, hours */
int
parse_time(char *str)
{
	char *end = str;
	int number = -1;
	int c;
	int units = 1;

	/* stop at the first whitespace */
	while (*end && !isspace(c = *end))
		end++;
	*end = '\0';

	end--;
	switch (*end) {
	case 's':
		units = 1;	/* seconds */
		*end = '\0';
		break;
	case 'm':
		units = 60;	/* minutes */
		*end = '\0';
		break;
	case 'h':
		units = 60 * 60;	/* hours */
		*end = '\0';
		break;
	default:
		/* let strtol flag it as invalid */
		break;
	}
	end++;

	/* FIXME: check for overflow */
	number = strtol(str, &end, 0) * units;

	if (*str && (*end == '\0'))
		return number;	/* it was all valid */
	else
		return -1;	/* something was invalid */
}

/*
 * If string is quoted, terminate it at the end quote
 * - else terminate at first whitespace.
 * Return pointer after leading quote.
 */
char *
parse_quoted_string(char *strp)
{
	char *cp, *retp = strp;
	int c;

	if (*strp == '"') {
		cp = ++strp;
		retp = cp;
		/* find the end quote and NUL it */
		while ((*cp != '\0') && (*cp != '"')) {
			cp++;
		}
		*cp = '\0';
	} else {
		/* not quoted - terminate it at first whitespace */
		cp = strp;
		while ((*cp != '\0') && (!isspace(c = *cp))) {
			cp++;
		}
		*cp = '\0';
	}

	return retp;
}

/*
 * update the existing config so that it matches
 * what's currently in the config file
 * FIXME: use a real parser.
 */
int
update_iscsi_config(const char *pathname, struct iscsi_config *config)
{
	FILE *f = NULL;
	char *line, *nl, buffer[2048];
	int c;
	struct iscsi_config_entry *entry = NULL, *current_entry =
	    NULL, *slp_entry = NULL;
	int indent = 0, entry_indent = 0;
	int line_number = 1;
	int slp_multicast_seen = 0;

	if (!config)
		return 0;

	f = fopen(pathname, "r");
	if (!f) {
		log_error("Cannot open configuration file %s", pathname);
		return 0;
	}

	log_debug(5, "updating config %p from %s", config, pathname);

	/* clear out any existing config */
	while ((entry = config->head)) {
		remove_config_entry(config, entry);
		free_config_entry(entry);
	}


	memset(config, 0, sizeof (*config));
	config->head = config->tail = NULL;

	/* reset to the platform's usual defaults */
	iscsi_init_config_defaults(&config->defaults);

	/* process the config file */
	do {
		line = fgets(buffer, sizeof (buffer), f);
		line_number++;
		if (!line)
			continue;

		/* skip but record leading whitespace */
		indent = 0;
		while (isspace(c = *line)) {
			if (*line == '\t')
				indent += 8;
			else
				indent++;

			line++;
		}

		/* strip trailing whitespace, including the newline.
		 * anything that needs the whitespace must be quoted.
		 */
		nl = line + strlen(line) - 1;
		if (*nl == '\n') {
			do {
				*nl = '\0';
				nl--;
			} while (isspace(c = *nl));
		} else {
			log_error("config file line %d too long",
			       line_number);
			return 0;
		}

		/* process any non-empty, non-comment lines */
		if (*line && (*line != '#')) {

			log_debug(7, "config indent %d, line %s", indent, line);

			/* if this line isn't indented farther than
			 * the current entry, it's unrelated.
			 */
			if (indent <= entry_indent)
				current_entry = NULL;

			if ((strncasecmp(line, "TargetIpAddr=", 13) == 0) ||
			    (strncasecmp(line, "DiscoveryAddress=", 17) == 0)) {
				char *addr = NULL, *port = NULL;
				char *sep = line;
				struct iscsi_sendtargets_config
				    *sendtargets_config = NULL;

				/* find the start of the address */
				while (*sep && *sep != '=')
					sep++;
				addr = ++sep;
				if (*addr) {
					/* look for a port number */
					/* FIXME: ought to handle the
					 * IPv6 syntax in the iSCSI spec
					 */
					while (*sep && !isspace(c = *sep)
					       && *sep != ':')
						sep++;
					if (*sep == ':') {
						*sep = '\0';
						port = ++sep;
						while (*sep
						       && isdigit(c =
									*sep))
							sep++;
						*sep = '\0';
					} else
						*sep = '\0';

					/* create a new sendtargets config entry
					 */
					entry = calloc(1, sizeof (*entry));
					if (entry == NULL) {
						log_error(
						       "failed to allocate "
						       "config entry");
						return 0;
					}
					entry->line_number = line_number;

					sendtargets_config =
					    calloc(1,
						   sizeof
						   (*sendtargets_config));
					if (sendtargets_config == NULL) {
						free(entry);
						entry = NULL;
						log_error(
						       "failed to allocate "
						       "sendtargets config");
						return 0;
					}

					entry->type = CONFIG_TYPE_SENDTARGETS;
					entry->config.sendtargets =
					    sendtargets_config;

					/* capture the current global defaults
					 */
					memcpy(&sendtargets_config->
					       auth_options,
					       &config->defaults.auth_options,
					       sizeof (sendtargets_config->
						       auth_options));
					memcpy(&sendtargets_config->
					       connection_timeout_options,
					       &config->defaults.
					       connection_timeout_options,
					       sizeof (sendtargets_config->
						       connection_timeout_options));
					sendtargets_config->continuous =
					    config->defaults.
					    continuous_sendtargets;
					sendtargets_config->send_async_text =
					    config->defaults.send_async_text;

					/* record the address and port */
					sendtargets_config->address =
					    strdup(addr);
					if (port && *port
					    && atoi(port) > 0)
						sendtargets_config->port =
						    atoi(port);
					else
						sendtargets_config->port =
						    ISCSI_DEFAULT_PORT;

					/* append it to the list of all
					 * config entries
					 */
					add_config_entry(config, entry);
					log_debug(5,
						 "config entry %p "
						 "sendtargets %p = %s:%d",
						 entry, sendtargets_config,
						 addr,
						 sendtargets_config->port);

					/* indented settings in the config file
					 * may modify this entry
					 */
					current_entry = entry;
					entry_indent = indent;
				} else {
					log_error(
					       "error on line %d of %s, an "
					       "address is required",
					       line_number, pathname);
				}
			} else if (strncasecmp(line, "DiscoveryFile=", 14) == 0) {
				char *filename = line + 14;
				struct iscsi_discovery_file_config *file_config;

				if (strlen(filename)) {
					/* create a new sendtargets config entry					 */
					entry = calloc(1, sizeof (*entry));
					if (entry == NULL) {
						log_error(
						       "failed to allocate "
						       "config entry");
						return 0;
					}
					entry->line_number = line_number;

					file_config =
					    calloc(1, sizeof (*file_config));
					if (file_config == NULL) {
						free(entry);
						entry = NULL;
						log_error(
						       "failed to allocate "
						       "discovery file config");
						return 0;
					}

					entry->type =
					    CONFIG_TYPE_DISCOVERY_FILE;
					entry->config.file = file_config;

					/* capture the current global defaults
					 */
					file_config->read_size = 512;
						/* FIXME: make this configurable						 */
					file_config->continuous =
					    config->defaults.
					    continuous_sendtargets;
					memcpy(&file_config->auth_options,
					       &config->defaults.auth_options,
					       sizeof (file_config->
						       auth_options));

					/* record the filename */
					file_config->filename =
					    strdup(filename);

					/* append it to the list of all
					 * config entries
					 */
					add_config_entry(config, entry);
					log_debug(5,
						 "config entry %p discovery "
						 "file %p = %s",
						 entry, file_config, filename);

					/* indented settings in the config file
					 * may modify this entry
					 */
					current_entry = entry;
					entry_indent = indent;
				} else {
					log_error(
					       "error on line %d of %s, "
					       "DiscoveryFile entry requires "
					       "a filename",
					       line_number, pathname);
				}
			} else if (strncasecmp(line, "Continuous=", 11) == 0) {
				int value = parse_boolean(line + 11);

				if (value < 0) {
					log_error(
					       "error on line %d of %s, "
					       "invalid value %s",
					       line_number, pathname,
					       line + 11);
				} else if (current_entry
					   && current_entry->type ==
					   CONFIG_TYPE_SENDTARGETS) {
					struct iscsi_sendtargets_config
					    *sendtargets =
					    current_entry->config.sendtargets;

					sendtargets->continuous = value;
					log_debug(5,
						 "config entry %p sendtargets "
						 "config %p continuous %d",
						 current_entry, sendtargets,
						 value);
				} else if (current_entry
					   && current_entry->type ==
					   CONFIG_TYPE_DISCOVERY_FILE) {
					struct iscsi_discovery_file_config
					*file_config =
					    current_entry->config.file;

					file_config->continuous = value;
					log_debug(5,
						 "config entry %p discovery "
						 "file config %p continuous %d",
						 current_entry, file_config,
						 value);
				} else {
					config->defaults.
					    continuous_sendtargets = value;
					log_debug(5,
						 "config global continuous "
						 "discovery %d",
						 value);
				}
			} else if (strncasecmp(line, "SendAsyncText=", 14) == 0) {
				char *str = &line[14];
				int value = parse_boolean(str);

				if (value >= 0) {
					if (current_entry
					    && current_entry->type ==
					    CONFIG_TYPE_SENDTARGETS) {
						struct iscsi_sendtargets_config
						*sendtargets =
						    current_entry->config.
						    sendtargets;
						sendtargets->send_async_text =
						    value;
						log_debug(5,
							 "config entry %p "
							 "sendtargets config%p "
							 "sendasynctext %d",
							 current_entry,
							 sendtargets, value);
					} else {
						config->defaults.
						    send_async_text = value;
						log_debug(5,
							 "config global "
							 "SendAsyncText "
							 "value %d",
							 value);
					}
				} else {
					log_error(
					       "error on line %d of %s, "
					       "invalid value %s",
					       line_number, pathname,
					       line + 14);
				}
			} else if (strncasecmp(line, "ReadSize=", 9) == 0) {
				int value = parse_number(line + 9);

				/* for testing, allow variable read sizes
				 * to simulate varying PDU sizes
				 */
				if (value < 0) {
					log_error(
					       "error on line %d of %s, "
					       "invalid entry %s",
					       line_number, pathname, line);
				} else if (current_entry
					   && current_entry->type ==
					   CONFIG_TYPE_DISCOVERY_FILE) {
					struct iscsi_discovery_file_config
					*file_config =
					    current_entry->config.file;

					file_config->read_size = value;
					log_debug(5,
						 "config entry %p discovery "
						 "file config %p continuous %d",
						 current_entry, file_config,
						 value);
				} else {
					log_error(
					       "error on line %d of %s, "
					       "invalid entry %s",
					       line_number, pathname, line);
				}
			} else if (strncasecmp(line, "DefaultAddress=", 15) ==
				   0) {
				/* allow DiscoveryFile entries to specify
				 * a default address, so that TargetAddresses
				 * can be omitted from the discovery file.
				 */
				if (current_entry
				    && current_entry->type ==
				    CONFIG_TYPE_DISCOVERY_FILE) {
					struct iscsi_discovery_file_config
					*file_config =
					    current_entry->config.file;
					char *address = line + 15;
					char *port = NULL;

					if ((port = strrchr(address, ':'))) {
						*port = '\0';
						port++;
						file_config->port =
						    strdup(port);
					} else {
						file_config->port =
						    strdup("3260");
					}

					file_config->address = strdup(address);
					log_debug(5,
						 "config entry %p discovery "
						 "file config %p address %s "
						 "port %s ",
						 current_entry, file_config,
						 file_config->address,
						 file_config->port);
				} else {
					log_error(
					       "error on line %d of %s, "
					       "invalid entry %s",
					       line_number, pathname, line);
				}
			} else if (strncasecmp(line,"SLPMulticast=",13) == 0) {
				char *value = parse_quoted_string(line + 13);
				struct iscsi_slp_config *slp_config;

				slp_multicast_seen = 1;

				if ((value == NULL) || (*value == '\0')) {
					log_error(
					       "error on line %d of %s, "
					       "SLPMulticast requires a list "
					       "of interface names\n",
					       line_number, pathname);
					continue;
				}

				/* add an entry for SLP */
				entry = calloc(1, sizeof (*entry));
				if (entry == NULL) {
					log_error(
					       "failed to allocate "
					       "config entry");
					return 0;
				}
				entry->line_number = line_number;

				slp_config =
				    calloc(1, sizeof (struct iscsi_slp_config));
				if (slp_config == NULL) {
					log_error(
					       "failed to allocate SLP config");
					return 0;
				}

				entry->type = CONFIG_TYPE_SLP;
				entry->config.slp = slp_config;

				slp_entry = entry;

				/* capture the global defaults */
				memcpy(&slp_config->auth_options,
				       &config->defaults.auth_options,
				       sizeof (slp_config->auth_options));
				if (config->defaults.slp_scopes)
					slp_config->scopes =
					    strdup(config->defaults.slp_scopes);
				else
					slp_config->scopes = NULL;
				slp_config->poll_interval =
				    config->defaults.slp_poll_interval;

				/* multicast on the specified interfaces */
				slp_config->interfaces = strdup(value);
				slp_config->address = NULL;
				slp_config->port = 0;

				/* append it to the list of all config entries
				 */
				add_config_entry(config, entry);
				log_debug(5,
					 "config entry %p SLPMulticast %p = %s",
					 entry, slp_config, value);

				/* indented settings in the config file
				 * may modify this entry
				 */
				current_entry = entry;
				entry_indent = indent;
			} else if (strncasecmp(line, "SLPUnicast=", 11) == 0) {
				char *addr = NULL, *port = NULL;
				char *sep = line;
				struct iscsi_slp_config *slp_config = NULL;

				/* find the start of the address */
				while (*sep && *sep != '=')
					sep++;

				addr = ++sep;
				if (*addr) {
					/* look for a port number */
					/* FIXME: ought to handle the IPv6
					 * syntax in the iSCSI spec
					 */
					while (*sep && !isspace(c = *sep)
					       && *sep != ':')
						sep++;
					if (*sep == ':') {
						*sep = '\0';
						port = ++sep;
						while (*sep
						       && isdigit(c = *sep))
							sep++;
						*sep = '\0';
					} else
						*sep = '\0';

					/* create a new slp config entry */
					entry = calloc(1, sizeof (*entry));
					if (entry == NULL) {
						log_error(
						       "failed to allocate "
						       "config entry");
						return 0;
					}
					entry->line_number = line_number;

					slp_config =
					    calloc(1, sizeof (*slp_config));
					if (slp_config == NULL) {
						free(entry);
						entry = NULL;
						log_error(
						       "failed to allocate "
						       "SLP config");
						return 0;
					}

					entry->type = CONFIG_TYPE_SLP;
					entry->config.slp = slp_config;

					/* capture the current global defaults
					 */
					memcpy(&slp_config->auth_options,
					       &config->defaults.auth_options,
					       sizeof (slp_config->
						       auth_options));
					if (config->defaults.slp_scopes)
						slp_config->scopes =
						    strdup(config->defaults.
							   slp_scopes);
					else
						slp_config->scopes = NULL;
					slp_config->poll_interval =
					    config->defaults.slp_poll_interval;

					/* record the address and port */
					slp_config->address = strdup(addr);
					if (port && *port && (atoi(port) > 0))	/* FIXME: check for invalid port strings */
						slp_config->port =
						    atoi(port);
					else
						slp_config->port = ISCSI_DEFAULT_PORT;	/* FIXME: what is the default SLP port? */

					slp_config->interfaces = NULL;
						/* let the OS pick an interface
						 * for unicasts
						 */

					/* append it to the list of all
					 * config entries
					 */
					add_config_entry(config, entry);
					log_debug(5,
						 "config entry %p SLPUnicast "
						 "%p = %s:%d",
						 entry, slp_config, addr,
						 slp_config->port);

					/* indented settings in the config file
					 * may modify this entry
					 */
					current_entry = entry;
					entry_indent = indent;
				} else {
					log_error(
					       "error on line %d of %s, an "
					       "address is required",
					       line_number, pathname);
				}
			} else if (strncasecmp(line, "PollInterval=", 13) == 0) {
				int value = parse_time(line + 13);

				if (value < 0) {
					log_error(
					       "error on line %d of %s, "
					       "illegal value %s",
					       line_number, pathname,
					       line + 13);
				} else if (current_entry
					   && current_entry->type ==
					   CONFIG_TYPE_SLP) {
					struct iscsi_slp_config *slp =
					    current_entry->config.slp;

					slp->poll_interval = value;
					log_debug(5,
						 "config entry %p poll "
						 "interval %d",
						 slp, value);
				} else {
					config->defaults.slp_poll_interval =
					    value;
					log_debug(5,
						 "config global SLP "
						 "poll interval %d",
						 value);
				}
			} else if (strncasecmp(line, "TargetName=", 11) == 0) {
				/* settings for a specific iSCSI TargetName
				 * (can be quoted)
				 */
				char *n = parse_quoted_string(line + 11);
				struct iscsi_targetname_config
				    *targetname_config;

				entry = calloc(1, sizeof (*entry));
				if (entry == NULL) {
					log_error(
					       "failed to allocate "
					       "config entry");
					return 0;
				}
				entry->line_number = line_number;

				targetname_config =
				    calloc(1, sizeof (*targetname_config));
				if (targetname_config == NULL) {
					free(entry);
					entry = NULL;
					log_error(
					       "failed to allocate "
					       "TargetName config");
					return 0;
				}

				entry->type = CONFIG_TYPE_TARGETNAME;
				entry->config.targetname = targetname_config;

				targetname_config->TargetName = strdup(n);

				/* capture the current global defaults */
				targetname_config->enabled =
				    config->defaults.enabled;

				memcpy(&targetname_config->auth_options,
				       &config->defaults.auth_options,
				       sizeof (targetname_config->
					       auth_options));

				memcpy(&targetname_config->
				       connection_timeout_options,
				       &config->defaults.
				       connection_timeout_options,
				       sizeof (targetname_config->
					       connection_timeout_options));
				memcpy(&targetname_config->
				       session_timeout_options,
				       &config->defaults.
				       session_timeout_options,
				       sizeof (targetname_config->
					       session_timeout_options));
				memcpy(&targetname_config->
				       error_timeout_options,
				       &config->defaults.error_timeout_options,
				       sizeof (targetname_config->
					       error_timeout_options));
				memcpy(&targetname_config->tcp_options,
				       &config->defaults.tcp_options,
				       sizeof (targetname_config->tcp_options));
				memcpy(&targetname_config->iscsi_options,
				       &config->defaults.iscsi_options,
				       sizeof (targetname_config->
					       iscsi_options));

				/* append it to the list of all config entries
				 */
				add_config_entry(config, entry);
				log_debug(5,
					 "config entry %p targetname %p = %s",
					 entry, targetname_config, n);

				/* indented settings in the config file
				 * may modify this entry
				 */
				current_entry = entry;
				entry_indent = indent;
			} else if (strncasecmp(line, "Enabled=", 8) == 0) {
				char *str = &line[8];
				int value = parse_boolean(str);

				if (value >= 0) {
					if (current_entry) {
						if (current_entry->type ==
						    CONFIG_TYPE_TARGETNAME) {
							struct iscsi_targetname_config
							*targetname_config =
							    current_entry->
							    config.targetname;

							targetname_config->
							    enabled = value;
							log_debug(5,
								 "config entry "
								 "%p targetname"
								 " %p to %s %s",
								 current_entry,
								 targetname_config,
								 targetname_config->
								 TargetName,
								 value ?
								 "enabled" :
								 "disabled");
						} else {
							log_error(
							       "error on line "
							       "%d of %s, "
							       "enabled does "
							       "not apply to "
							       "the current "
							       "entry",
							       line_number,
							       pathname);
						}
					} else {
						log_debug(5,
							 "config global "
							 "targets %s",
							 value ? "enabled" :
							 "disabled");
						config->defaults.enabled =
						    value;
					}
				} else
					log_error(
					       "error on line %d of %s, "
					       "illegal value %s",
					       line_number, pathname, str);
			} else if ((strncasecmp(line, "Username=", 9) == 0) ||
				 (strncasecmp(line, "UsernameOut=", 12) == 0) ||
				 (strncasecmp(line, "OutgoingUsername=", 17) ==
				  0)) {
				/* Username string can be quoted */
				char *u, *cp = &line[8];

				/* find start of value */
				while (*cp && *cp != '=') {
					cp++;
				}
				u = parse_quoted_string(++cp);

				if (current_entry) {
					struct iscsi_auth_config *auth_options =
					    entry_auth_options(current_entry);
					if (auth_options) {
						strncpy(auth_options->username,
							u,
							sizeof (auth_options->
								username));
						auth_options->
						    username[sizeof
							     (auth_options->
							      username) - 1] =
						    '\0';
						log_debug(5,
							 "config entry %p "
							 "outgoing username %s",
							 current_entry,
							 auth_options->
							 username);
					} else {
						log_error(
						       "Invalid entry on line"
						       " %d of %s,"
						       " current entry cannot "
						       "have an outgoing "
						       "username, see man "
						       "page of iscsi.conf",
						       line_number, pathname);
					}
				} else {
					/* default to use while processing the
					 * rest of the config file
					 */
					strncpy(config->defaults.auth_options.
						username, u,
						sizeof (config->defaults.
							auth_options.username));
					config->defaults.auth_options.
					    username[sizeof
						     (config->defaults.
						      auth_options.username) -
						     1] = '\0';
					log_debug(5,
						 "config global outgoing "
						 "username %s",
						 config->defaults.auth_options.
						 username);
				}
			} else if ((strncasecmp(line, "UsernameIn=", 11) == 0)
				   ||
				   (strncasecmp(line, "IncomingUsername=", 17)
				    == 0)) {
				char *u, *cp = line + 10;

				/* find start of value */
				while (*cp && *cp != '=') {
					cp++;
				}
				u = parse_quoted_string(++cp);

				if (current_entry) {
					struct iscsi_auth_config *auth_options =
					    entry_auth_options(current_entry);
					if (auth_options) {
						strncpy(auth_options->
							username_in, u,
							sizeof (auth_options->
								username_in));
						auth_options->
						    username_in[sizeof
								(auth_options->
								 username_in) -
								1] = '\0';
						log_debug(5,
							 "config entry %p "
							 "incoming username %s",
							 current_entry,
							 auth_options->
							 username_in);
					} else {
						log_error(
						       "Invalid entry on line"
						       " %d of %s,"
						       " current entry cannot "
						       "have an incoming "
						       "username, see "
						       "man page of iscsi."
						       "conf",
						       line_number, pathname);
					}
				} else {
					/* default to use while processing the
					 * rest of the config file
					 */
					strncpy(config->defaults.auth_options.
						username_in, u,
						sizeof (config->defaults.
							auth_options.
							username_in));
					config->defaults.auth_options.
					    username_in[sizeof
							(config->defaults.
							 auth_options.
							 username_in) - 1] =
					    '\0';
					log_debug(5,
						 "config global incoming "
						 "username %s",
						 config->defaults.auth_options.
						 username_in);
				}
			} else if ((strncasecmp(line, "Password=", 9) == 0) ||
				   (strncasecmp(line, "PasswordOut=", 12) == 0)
				   ||
				   (strncasecmp(line, "OutgoingPassword=", 17)
				    == 0)) {
				/* Password string can be quoted */
				char *p, *cp = &line[8];

				/* find start of value */
				while (*cp && *cp != '=') {
					cp++;
				}
				p = parse_quoted_string(++cp);

				if (current_entry) {
					struct iscsi_auth_config *auth_options =
					    entry_auth_options(current_entry);
					if (auth_options) {
						strncpy(auth_options->password,
							p,
							sizeof (auth_options->
								password));
						auth_options->
						    password[sizeof
							     (auth_options->
							      password) - 1] =
						    '\0';
						auth_options->password_length =
						    strlen(auth_options->
							   password);
						log_debug(5,
							 "config entry %p "
							 "outgoing password %s "
							 "length %u",
							 current_entry,
							 auth_options->password,
							 auth_options->
							 password_length);
					} else {
						log_error(
						       "Invalid entry on line "
						       "%d of %s,"
						       " current entry cannot "
						       "have an outgoing "
						       "password, see "
						       "man page of iscsi."
						       "conf",
						       line_number, pathname);
					}
				} else {
					/* default to use while processing the
					 * rest of the config file
					 */
					strncpy(config->defaults.auth_options.
						password, p,
						sizeof (config->defaults.
							auth_options.password));
					config->defaults.auth_options.
					    password[sizeof
						     (config->defaults.
						      auth_options.password) -
						     1] = '\0';
					config->defaults.auth_options.
					    password_length =
					    strlen(config->defaults.
						   auth_options.password);
					log_debug(5,
						 "config global outgoing "
						 "password %s length %u",
						 config->defaults.auth_options.
						 password,
						 config->defaults.auth_options.
						 password_length);
				}
			} else if ((strncasecmp(line, "PasswordIn=", 11) == 0)
				   ||
				   (strncasecmp(line, "IncomingPassword=", 17)
				    == 0)) {
				char *p, *cp = line + 10;

				/* find start of value */
				while (*cp && *cp != '=') {
					cp++;
				}
				p = parse_quoted_string(++cp);

				if (current_entry) {
					struct iscsi_auth_config *auth_options =
					    entry_auth_options(current_entry);
					if (auth_options) {
						strncpy(auth_options->
							password_in, p,
							sizeof (auth_options->
								password_in));
						auth_options->
						    password_in[sizeof
								(auth_options->
								 password_in) -
								1] = '\0';
						auth_options->
						    password_length_in =
						    strlen(auth_options->
							   password_in);
						log_debug(5,
							 "config entry %p "
							 "incoming password %s,"
							 " length %u",
							 current_entry,
							 auth_options->
							 password_in,
							 auth_options->
							 password_length_in);
					} else {
						log_error(
						       "Invalid entry on line "
						       "%d of %s,"
						       " current entry cannot "
						       "have an incoming "
						       "password, see "
						       "man page of iscsi."
						       "conf",
						       line_number, pathname);
					}
				} else {
					/* default to use while processing the
					 * rest of the config file
					 */
					strncpy(config->defaults.auth_options.
						password_in, p,
						sizeof (config->defaults.
							auth_options.
							password_in));
					config->defaults.auth_options.
					    password_in[sizeof
							(config->defaults.
							 auth_options.
							 password_in) - 1] =
					    '\0';
					config->defaults.auth_options.
					    password_length_in =
					    strlen(config->defaults.
						   auth_options.password_in);
					log_debug(1,
						 "config global incoming "
						 "password %s, length %u",
						 config->defaults.auth_options.
						 password_in,
						 config->defaults.auth_options.
						 password_length_in);
				}
			} else if ((strncasecmp(line, "Subnet=", 7) == 0)
				   || (strncasecmp(line, "Address=", 8) == 0)) {
				char *address = line + 6;
				char *mask;
				struct in_addr addr;

				struct iscsi_subnet_config *subnet_config;

				while (*address && (*address != '='))
					address++;

				address++;

				entry = calloc(1, sizeof (*entry));
				if (entry == NULL) {
					log_error(
					       "failed to allocate "
					       "config entry");
					return 0;
				}
				entry->line_number = line_number;

				subnet_config =
				    calloc(1, sizeof (*subnet_config));
				if (subnet_config == NULL) {
					free(entry);
					entry = NULL;
					log_error(
					       "failed to allocate "
					       "Subnet config");
					return 0;
				}

				entry->type = CONFIG_TYPE_SUBNET;
				entry->config.subnet = subnet_config;

				subnet_config->subnet_mask = 0xFFFFFFFFU;

				/* look for a subnet mask */
				if ((mask = strrchr(address, '/'))) {
					int bits;

					*mask = '\0';	/* terminate the address							 */
					mask++;	/* and calculate the mask */
					bits = atoi(mask);
					if ((bits >= 0) && (bits < 32))
						subnet_config->subnet_mask =
						    0xFFFFFFFFU << (32 - bits);
				} else if ((mask = strrchr(address, '&'))) {
					*mask = '\0';	/* terminate the address							 */
					mask++;	/* and calculate the mask */
					subnet_config->subnet_mask =
					    (uint32_t) strtoul(mask, NULL, 16);
				}

				subnet_config->address = strdup(address);

				/* FIXME: IPv6 */
				if (inet_aton(address, &addr)) {
					subnet_config->ip_length = 4;
					memcpy(subnet_config->ip_address,
					       &addr.s_addr, 4);
				} else {
					/* discard this entry */
					log_error(
					       "error on line %d of %s, "
					       "bogus Subnet address %s\n",
					       line_number, pathname, address);
					free_config_entry(entry);
					entry = NULL;
					continue;
				}

				/* capture the current global defaults */
				memcpy(&subnet_config->
				       connection_timeout_options,
				       &config->defaults.
				       connection_timeout_options,
				       sizeof (subnet_config->
					       connection_timeout_options));
				memcpy(&subnet_config->error_timeout_options,
				       &config->defaults.error_timeout_options,
				       sizeof (subnet_config->
					       error_timeout_options));
				memcpy(&subnet_config->tcp_options,
				       &config->defaults.tcp_options,
				       sizeof (subnet_config->tcp_options));

				/* append it to the list of all config entries
				 */
				add_config_entry(config, entry);
				log_debug(5,
					 "config entry %p subnet %p = addr %s "
					 "ip %u.%u.%u.%u mask 0x%x\n",
					 entry, subnet_config, address,
					 subnet_config->ip_address[0],
					 subnet_config->ip_address[1],
					 subnet_config->ip_address[2],
					 subnet_config->ip_address[3],
					 subnet_config->subnet_mask);

				/* indented settings in the config file may
				 * modify this entry
				 */
				current_entry = entry;
				entry_indent = indent;
			} else if (strncasecmp(line, "TCPWindowSize=", 14) == 0) {
				char *num = &line[14];
				int value = parse_number(num);

				if (value >= 0) {
					if (current_entry) {
						struct iscsi_tcp_config
						    *tcp_options =
						    entry_tcp_options
						    (current_entry);

						if (tcp_options) {
							tcp_options->
							    window_size = value;
							log_debug(5,
								 "config entry "
								 "%p "
								 "TCPWindowSize"
								 " %d",
								 current_entry,
								 value);
						} else {
							log_error(
							       "Invalid entry "
							       "on line "
							       "%d of %s, "
							       "TCPWindowSize "
							       "does not apply "
							       "to the current "
							       "entry, see "
							       "man page of"
							       "iscsi.conf",
							       line_number,
							       pathname);
						}
					} else {
						config->defaults.tcp_options.
						    window_size = value;
						log_debug(5,
							 "config global "
							 "TCPWindowSize %d",
							 value);
					}
				} else
					log_error(
					       "error on line %d, "
					       "invalid TCPWindowSize %s",
					       line_number, num);
			} else if (strncasecmp(line, "InitialR2T=", 11) == 0) {
				char *str = &line[11];
				int value = parse_boolean(str);

				if (value >= 0) {
					if (current_entry) {
						struct iscsi_operational_config
						*iscsi_options =
						    entry_iscsi_options
						    (current_entry);

						if (iscsi_options) {
							log_debug(5,
								 "config entry "
								 "%p InitialR2T"
								 " %d",
								 current_entry,
								 value);
							iscsi_options->
							    InitialR2T = value;
						} else {
							log_error(
							       "Invalid "
							       "InitialR2T"
							       " entry on "
							       "line "
							       "%d of %s, "
							       "see man page "
							       "of iscsi."
							       "conf",
							       line_number,
							       pathname);
						}
					} else {
						log_debug(5,
							 "config global "
							 "InitialR2T %d",
							 value);
						config->defaults.iscsi_options.
						    InitialR2T = value;
					}
				} else
					log_error(
					       "error on line %d of %s, "
					       "invalid InitialR2T %s",
					       line_number, pathname, str);
			} else if (strncasecmp(line, "ImmediateData=", 14) == 0) {
				char *str = &line[14];
				int value = parse_boolean(str);

				if (value >= 0) {
					if (current_entry) {
						struct iscsi_operational_config
						*iscsi_options =
						    entry_iscsi_options
						    (current_entry);

						if (iscsi_options) {
							log_debug(5,
								 "config entry "
								 "%p "
								 "ImmediateData"
								 " %d",
								 current_entry,
								 value);
							iscsi_options->
							    ImmediateData =
							    value;
						} else {
							log_error(
							       "Invalid "
							       "ImmediateData"
							       " entry on "
							       "line "
							       "%d of %s, "
							       "see man page"
							       " of iscsi."
							       "conf",
							       line_number,
							       pathname);
						}
					} else {
						log_debug(5,
							 "config global "
							 "ImmediateData %d",
							 value);
						config->defaults.iscsi_options.
						    ImmediateData = value;
					}
				} else
					log_error(
					       "error on line %d of %s, "
					       "invalid ImmediateData %s",
					       line_number, pathname, str);
			} else
			    if (strncasecmp
				(line, "MaxRecvDataSegmentLength=", 25) == 0) {
				char *num = &line[25];
				int value = parse_number(num);

				if (value >= 0) {
					if (current_entry) {
						struct iscsi_operational_config
						*iscsi_options =
						    entry_iscsi_options
						    (current_entry);

						if (iscsi_options) {
							log_debug(5,
								 "config entry "
								 "%p "
								 "MaxRecvDataSegmentLength "
								 "%d",
								 current_entry,
								 value);
							iscsi_options->
							    MaxRecvDataSegmentLength
							    = value;
						} else {
							log_error(
							       "Invalid "
							       "MaxRecvDataSegmentLength"
							       " entry on line"
							       " %d of %s, "
							       "see man page"
							       " of iscsi."
							       "conf",
							       line_number,
							       pathname);
						}
					} else {
						log_debug(5,
							 "config global "
							 "MaxRecvDataSegmentLength "
							 "%d",
							 value);
						config->defaults.iscsi_options.
						    MaxRecvDataSegmentLength =
						    value;
					}
				} else
					log_error(
					       "error on line %d of %s, invalid"
					       " MaxRecvDataSegmentLength %s",
					       line_number, pathname, num);
			} else if (strncasecmp(line, "FirstBurstLength=", 17) ==
				   0) {
				char *num = &line[17];
				int value = parse_number(num);

				if (value >= 0) {
					if (current_entry) {
						struct iscsi_operational_config
						*iscsi_options =
						    entry_iscsi_options
						    (current_entry);

						if (iscsi_options) {
							log_debug(5,
								 "config entry "
								 "%p "
								 "FirstBurstLength"
								 " %d",
								 current_entry,
								 value);
							iscsi_options->
							    FirstBurstLength =
							    value;
						} else {
							log_error(
							       "Invalid "
							       "FirstBurstLength"
							       " entry on line"
							       " %d of %s, "
							       "see man page "
							       "of iscsi."
							       "conf",
							       line_number,
							       pathname);
						}
					} else {
						log_debug(5,
							 "config global "
							 "FirstBurstLength %d",
							 value);
						config->defaults.iscsi_options.
						    FirstBurstLength = value;
					}
				} else
					log_error(
					       "error on line %d of %s, "
					       "invalid FirstBurstLength %s",
					       line_number, pathname, num);
			} else if (strncasecmp(line, "MaxBurstLength=", 15) ==
				   0) {
				char *num = &line[15];
				int value = parse_number(num);

				if (value >= 0) {
					if (current_entry) {
						struct iscsi_operational_config
						*iscsi_options =
						    entry_iscsi_options
						    (current_entry);

						if (iscsi_options) {
							log_debug(5,
								 "config entry "
								 "%p "
								 "MaxBurstLength"
								 " %d",
								 current_entry,
								 value);
							iscsi_options->
							    MaxBurstLength =
							    value;
						} else {
							log_error(
							       "Invalid "
							       "MaxBurstLength"
							       " entry on line"
							       " %d of %s, "
							       "see man page "
							       "of iscsi."
							       "conf",
							       line_number,
							       pathname);
						}
					} else {
						log_debug(5,
							 "config global "
							 "MaxBurstLength %d",
							 value);
						config->defaults.iscsi_options.
						    MaxBurstLength = value;
					}
				} else
					log_error(
					       "error on line %d of %s, invalid"
					       " MaxBurstLength %s",
					       line_number, pathname, num);
			} else if (strncasecmp(line, "HeaderDigest=", 13) == 0) {
				char *m = line + 13;
				int digest = -1;

				if ((strcasecmp(m, "never") == 0)
				    || (strcasecmp(m, "no") == 0)
				    || (strcasecmp(m, "none") == 0))
					digest = CONFIG_DIGEST_NEVER;
				else if ((strcasecmp(m, "always") == 0)
					 || (strcasecmp(m, "yes") == 0)
					 || (strcasecmp(m, "crc32c") == 0))
					digest = CONFIG_DIGEST_ALWAYS;
				else if ((strcasecmp(m, "prefer-on") == 0))
					digest = CONFIG_DIGEST_PREFER_ON;
				else if ((strcasecmp(m, "prefer-off") == 0))
					digest = CONFIG_DIGEST_PREFER_OFF;
				else {
					digest = -1;
					log_error(
					       "error on line %d of %s, invalid"
					       " HeaderDigest type %s\n",
					       line_number, pathname, m);
				}

				if (digest != -1) {
					if (current_entry) {
						struct iscsi_operational_config
						*iscsi_options =
						    entry_iscsi_options
						    (current_entry);
						if (iscsi_options) {
							log_debug(5,
								 "config entry "
								 "%p "
								 "HeaderDigest "
								 "%d",
								 current_entry,
								 digest);
							iscsi_options->
							    HeaderDigest =
							    digest;
						} else {
							log_error(
							       "error on line "
							       "%d of %s, "
							       "current entry "
							       "does not have "
							       "iSCSI settings,"
							       " invalid "
							       "HeaderDigest "
							       "%s",
							       line_number,
							       pathname, m);
						}
					} else {
						/* default to use while
						 * processing the rest of the
						 * config file
						 */
						log_debug(5,
							 "config global "
							 "HeaderDigest %d",
							 digest);
						config->defaults.iscsi_options.
						    HeaderDigest = digest;
					}
				}
			} else if (strncasecmp(line, "DataDigest=", 11) == 0) {
				char *m = line + 11;
				int digest = -1;

				if ((strcasecmp(m, "never") == 0)
				    || (strcasecmp(m, "no") == 0)
				    || (strcasecmp(m, "none") == 0))
					digest = CONFIG_DIGEST_NEVER;
				else if ((strcasecmp(m, "always") == 0)
					 || (strcasecmp(m, "yes") == 0)
					 || (strcasecmp(m, "crc32c") == 0))
					digest = CONFIG_DIGEST_ALWAYS;
				else if ((strcasecmp(m, "prefer-on") == 0))
					digest = CONFIG_DIGEST_PREFER_ON;
				else if ((strcasecmp(m, "prefer-off") == 0))
					digest = CONFIG_DIGEST_PREFER_OFF;
				else {
					digest = -1;
					log_error(
					       "error on line %d of %s, invalid"
					       " DataDigest type %s\n",
					       line_number, pathname, m);
				}

				if (digest != -1) {
					if (current_entry) {
						struct iscsi_operational_config
						*iscsi_options =
						    entry_iscsi_options
						    (current_entry);
						if (iscsi_options) {
							log_debug(5,
								 "config entry "
								 "%p "
								 "DataDigest "
								 "%d",
								 current_entry,
								 digest);
							iscsi_options->
							    DataDigest = digest;
						} else {
							log_error(
							       "error on line "
							       "%d of %s, "
							       "current entry "
							       "does not have "
							       "iSCSI settings,"
							       " invalid "
							       "DataDigest "
							       "value %s",
							       line_number,
							       pathname, m);
						}
					} else {
						/* default to use while
						 * processing the rest of the
						 * config file
						 */
						log_debug(5,
							 "config global "
							 "DataDigest %d",
							 digest);
						config->defaults.iscsi_options.
						    DataDigest = digest;
					}
				}
			} else if (strncasecmp(line, "LoginTimeout=", 13) == 0) {
				char *num = &line[13];
				int value = parse_time(num);

				if (value >= 0) {
					if (current_entry) {
						struct iscsi_connection_timeout_config
						*options =
						    entry_connection_timeout_options
						    (current_entry);

						if (options) {
							log_debug(5,
								 "config entry "
								 "%p "
								 "LoginTimeout "
								 "%d",
								 current_entry,
								 value);
							options->login_timeout =
							    value;
						} else {
							log_error(
							       "error on line "
							       "%d of %s, "
							       "current entry "
							       "does not have "
							       "connection "
							       "timeout "
							       "settings, "
							       "invalid "
							       "LoginTimeout "
							       "%d, see man"
							       "page of iscsi"
							       ".conf",
							       line_number,
							       pathname, value);
						}
					} else {
						log_debug(5,
							 "config global LoginTimeout %d",
							 value);
						config->defaults.
						    connection_timeout_options.
						    login_timeout = value;
					}
				} else
					log_error(
					       "error on line %d of %s, "
					       "invalid LoginTimeout %s",
					       line_number, pathname, num);
			} else if (strncasecmp(line, "AuthTimeout=", 12) == 0) {
				char *num = &line[12];
				int value = parse_time(num);

				if (value >= 0) {
					if (current_entry) {
						struct iscsi_connection_timeout_config
						*options =
						    entry_connection_timeout_options
						    (current_entry);

						if (options) {
							log_debug(5,
								 "config entry "
								 "%p "
								 "AuthTimeout "
								 "%d",
								 current_entry,
								 value);
							options->auth_timeout =
							    value;
						} else {
							log_error(
							       "error on line "
							       "%d of %s, "
							       "current entry "
							       "does not have "
							       "connection "
							       "timeout "
							       "settings, "
							       "invalid "
							       "AuthTimeout %d"
							       ", see man "
							       "page of "
							       "iscsi.conf",
							       line_number,
							       pathname, value);
						}
					} else {
						log_debug(5,
							 "config global "
							 "AuthTimeout %d",
							 value);
						config->defaults.
						    connection_timeout_options.
						    auth_timeout = value;
					}
				} else
					log_error(
					       "error on line %d of %s, "
					       "invalid AuthTimeout %s",
					       line_number, pathname, num);
			} else if (strncasecmp(line, "ActiveTimeout=", 14) == 0) {
				char *num = &line[14];
				int value = parse_time(num);

				if (value >= 0) {
					if (current_entry) {
						struct iscsi_connection_timeout_config
						*options =
						    entry_connection_timeout_options
						    (current_entry);

						if (options) {
							log_debug(5,
								 "config entry "
								 "%p "
								 "ActiveTimeout"
								 " %d",
								 current_entry,
								 value);
							options->
							    active_timeout =
							    value;
						} else {
							log_error(
							       "error on line "
							       "%d of %s, "
							       "current entry "
							       "does not have "
							       "connection "
							       "timeout "
							       "settings, "
							       "invalid "
							       "ActiveTimeout "
							       "%d, see man "
							       "page of iscsi"
							       ".conf",
							       line_number,
							       pathname, value);
						}
					} else {
						log_debug(5,
							 "config global "
							 "ActiveTimeout %d",
							 value);
						config->defaults.
						    connection_timeout_options.
						    active_timeout = value;
					}
				} else
					log_error(
					       "error on line %d of %s, "
					       "invalid ActiveTimeout %s",
					       line_number, pathname, num);
			} else if (strncasecmp(line, "IdleTimeout=", 12) == 0) {
				char *num = &line[12];
				int value = parse_time(num);

				if (value >= 0) {
					if (current_entry) {
						struct iscsi_connection_timeout_config
						*options =
						    entry_connection_timeout_options
						    (current_entry);

						if (options) {
							options->idle_timeout =
							    value;
							log_debug(5,
								 "config entry "
								 "%p "
								 "IdleTimeout "
								 "%d",
								 current_entry,
								 value);
						} else {
							log_error(
							       "error on line "
							       "%d of %s, "
							       "current entry "
							       "does not have "
							       "connection "
							       "timeout "
							       "settings, "
							       "invalid "
							       "IdleTimeout %d"
							       ", see man page"
							       " of iscsi"
							       ".conf",
							       line_number,
							       pathname, value);
						}
					} else {
						config->defaults.
						    connection_timeout_options.
						    idle_timeout = value;
						log_debug(5,
							 "config global "
							 "IdleTimeout %d",
							 value);
					}
				} else
					log_error(
					       "error on line %d of %s, "
					       "invalid IdleTimeout %s",
					       line_number, pathname, num);
			} else if (strncasecmp(line, "PingTimeout=", 12) == 0) {
				char *num = &line[12];
				int value = parse_time(num);

				if (value >= 0) {
					if (current_entry) {
						struct iscsi_connection_timeout_config
						*options =
						    entry_connection_timeout_options
						    (current_entry);

						if (options) {
							options->ping_timeout =
							    value;
							log_debug(5,
								 "config entry "
								 "%p "
								 "PingTimeout "
								 "%d",
								 current_entry,
								 value);
						} else {
							log_error(
							       "error on line "
							       "%d of %s, "
							       "current entry "
							       "does not have "
							       "connection "
							       "timeout "
							       "settings, "
							       "invalid "
							       "PingTimeout %d"
							       ", see man "
							       "page of iscsi"
							       ".conf",
							       line_number,
							       pathname, value);
						}
					} else {
						config->defaults.
						    connection_timeout_options.
						    ping_timeout = value;
						log_debug(5,
							 "config global "
							 "PingTimeout %d",
							 value);
					}
				} else
					log_error(
					       "error on line %d of %s, invalid"
					       " PingTimeout %s",
					       line_number, pathname, num);
			} else if (strncasecmp(line, "AbortTimeout=", 13) == 0) {
				char *num = &line[13];
				int value = parse_time(num);

				if (value >= 0) {
					if (current_entry) {
						struct iscsi_error_timeout_config
						*options =
						    entry_error_timeout_options
						    (current_entry);

						if (options) {
							options->abort_timeout =
							    value;
							log_debug(5,
								 "config entry "
								 "%p "
								 "AbortTimeout "
								 "%d",
								 current_entry,
								 value);
						} else {
							log_error(
							       "error on line "
							       "%d of %s, "
							       "current entry "
							       "does not have "
							       "error timeout "
							       "settings, "
							       "invalid "
							       "AbortTimeout "
							       "%d, see man "
							       "page of iscsi"
							       ".conf",
							       line_number,
							       pathname, value);
						}
					} else {
						config->defaults.
						    error_timeout_options.
						    abort_timeout = value;
						log_debug(5,
							 "config global "
							 "AbortTimeout %d",
							 value);
					}
				} else
					log_error(
					       "error on line %d of %s, "
					       "invalid AbortTimeout %s",
					       line_number, pathname, num);
			} else if (strncasecmp(line, "ResetTimeout=", 13) == 0) {
				char *num = &line[13];
				int value = parse_time(num);

				if (value >= 0) {
					if (current_entry) {
						struct iscsi_error_timeout_config
						*options =
						    entry_error_timeout_options
						    (current_entry);

						if (options) {
							options->reset_timeout =
							    value;
							log_debug(5,
								 "config entry "
								 "%p "
								 "ResetTimeout "
								 "%d",
								 current_entry,
								 value);
						} else {
							log_error(
							       "error on line "
							       "%d of %s, "
							       "current entry "
							       "does not have "
							       "error timeout "
							       "settings, "
							       "invalid "
							       "ResetTimeout "
							       "%d, see man "
							       "page of iscsi"
							       ".conf",
							       line_number,
							       pathname, value);
						}
					} else {
						config->defaults.
						    error_timeout_options.
						    abort_timeout = value;
						log_debug(5,
							 "config global "
							 "ResetTimeout %d",
							 value);
					}
				} else
					log_error(
					       "error on line %d of %s, "
					       "invalid ResetTimeout %s",
					       line_number, pathname, num);
			} else if (strncasecmp(line, "ConnFailTimeout=", 16) ==
				   0) {
				char *num = &line[16];
				int value = parse_time(num);

				if (value >= 0) {
					if (current_entry) {
						struct iscsi_session_timeout_config
						*options =
						    entry_session_timeout_options
						    (current_entry);

						if (options) {
							options->
							    replacement_timeout
							    = value;
							log_debug(5,
								 "config entry "
								 "%p "
								 "ConnFailTimeout"
								 " %d",
								 current_entry,
								 value);
						} else {
							log_error(
							       "error on line "
							       "%d of %s, "
							       "current entry "
							       "does not have "
							       "session timeout"
							       " settings, "
							       "invalid "
							       "ConnFailTimeout"
							       " %d, see man"
							       "page of iscsi"
							       ".conf",
							       line_number,
							       pathname, value);
						}
					} else {
						config->defaults.
						    session_timeout_options.
						    replacement_timeout = value;
						log_debug(5,
							 "config global "
							 "ConnFailTimeout %d",
							 value);
					}
				} else {
					log_error(
					       "error on line %d of %s, "
					       "invalid ConnFailTimeout %s",
					       line_number, pathname, num);
				}
			} else if (strncasecmp(line, "Target,Lun=", 11) == 0) {
				/* do nothing, the LUN activator used to use
				 * these, but it's been replaced
				 */
			} else if (*line && (*line != '#')) {
				/* if it's not a comment, warn about it */
				log_warning(
				       "error on line %d of %s, ignoring "
				       "unrecognized line %s",
				       line_number, pathname, line);
			}
		}
	} while (line);

	fclose(f);

	if (!slp_multicast_seen && config->defaults.slp_multicast) {
		/* FIXME: if SLP multicast is possible, but we didn't find a
		 * config file entry for it, assume SLPMulticast=all
		 */
	}

	log_debug(1, "updated config %p from %s", config, pathname);

	return 1;
}

/* update the target config based on the config file */
int
update_target_config(struct iscsi_target_config *target,
		     struct iscsi_config *config,
		     struct iscsi_auth_config *auth_options)
{
	int ret = 1;

	struct iscsi_config_entry *entry;

	log_debug(5,
		 "setting defaults for target config %p to %s from config %p",
		 target, target->TargetName, config);

	/* start with the global defaults */
	target->enabled = config->defaults.enabled;

	memcpy(&target->auth_options, &config->defaults.auth_options,
	       sizeof (target->auth_options));

	/* the global authentication defaults can be overriden when a config is
	 * created, typically based on the authentication settings from a
	 * discovery process.
	 */
	if (auth_options) {
		/* these completely override the current settings, even if that
		 * means removing an existing username and password. This is
		 * needed to deal with some broken targets that can't do
		 * security phase properly.
		 * It must be possible to disable all authentication.
		 */
		memcpy(&target->auth_options, auth_options,
		       sizeof (target->auth_options));
		log_debug(5,
			 "overriding target config %p auth options %p in favor "
			 "of auth options %p\n",
			 target, &target->auth_options, auth_options);
	}

	/* apply the config file entries, which may override the defaults for
	 * particular targets or subnets, or for particular sections of
	 * the config file by resetting the globals between groups of
	 * TargetName or Subnet entries.
	 */
	for (entry = config->head; entry; entry = entry->next) {
		/* if the config entry is applicable to this target, apply it */
		switch (entry->type) {
		case CONFIG_TYPE_TARGETNAME:{
				struct iscsi_targetname_config
				    *targetname_config =
				    entry->config.targetname;

				if (strcmp
				    (target->TargetName,
				     targetname_config->TargetName) == 0) {
					log_debug(5,
						 "applying config entry %p line"
						 " %d targetname config %p to "
						 "target config %p",
						 entry, entry->line_number,
						 targetname_config, target);

					/* apply any target-wide settings */
					target->enabled =
					    targetname_config->enabled;
#ifdef PER_TARGETNAME_AUTH
					/* FIXME: should we remove this, since
					 * it's more likely to cause problems
					 * than be a useful feature?  When would
					 * a user need different credentials
					 * for the discovery and target logins?
					 */
					log_debug(5,
						 "applying username %s password"
						 " %p to target config %p",
						 targetname_config->
						 auth_options.username,
						 targetname_config->
						 auth_options.password, target);
					memcpy(&target->auth_options,
					       &targetname_config->auth_options,
					       sizeof (target->auth_options));
#else
					log_debug(5,
						 "target config %p currently "
						 "has username %s password %s",
						 target,
						 target->auth_options.username,
						 target->auth_options.password);
#endif
				} else {
					log_debug(5,
						 "config entry %p line %d "
						 "targetname config %p does not"
						 " apply to target config %p",
						 entry, entry->line_number,
						 targetname_config, target);
				}
				break;
			}
		case CONFIG_TYPE_SUBNET:{
				/* not relevant for a target config */
				break;
			}
		default:
			break;
		}
	}

	/* sanity check the target config */
	if (target->auth_options.username_in[0]
	    || target->auth_options.password_length_in) {
		/* if we're expecting incoming credentials, we must have
		 * outgoing credentials
		 */
		if (target->auth_options.username[0] == '\0') {
			log_error(
			       "target %s requires an outgoing username when "
			       "incoming credentials are expected\n",
			       target->TargetName);
			ret = 0;
		}
		if (target->auth_options.password_length == 0) {
			log_error(
			       "target %s requires an outgoing password when "
			       "incoming credentiuals are expected\n",
			       target->TargetName);
			ret = 0;
		}
	}

	return ret;
}

/* update the session configs and portal configs, based on the config file */
int
update_session_configs(struct iscsi_target_config *target,
		       struct iscsi_config *config)
{
	struct iscsi_config_entry *entry;
	struct iscsi_session_config *session_config;

	/* start with the global defaults for each portal config
	 * of each new session
	 */
	for (session_config = target->sessions; session_config;
	     session_config = session_config->next) {
		struct iscsi_portal_config *portal_config;

		portal_config = session_config->portal;

		memcpy(&portal_config->connection_timeout_options,
		       &config->defaults.connection_timeout_options,
		       sizeof (portal_config->connection_timeout_options));
		memcpy(&portal_config->session_timeout_options,
		       &config->defaults.session_timeout_options,
		       sizeof (portal_config->session_timeout_options));
		memcpy(&portal_config->error_timeout_options,
		       &config->defaults.error_timeout_options,
		       sizeof (portal_config->error_timeout_options));
		memcpy(&portal_config->tcp_options,
		       &config->defaults.tcp_options,
		       sizeof (portal_config->tcp_options));
		memcpy(&portal_config->iscsi_options,
		       &config->defaults.iscsi_options,
		       sizeof (portal_config->iscsi_options));
	}

	/* apply the config file, which may override the defaults for
	 * particular targets or subnets, or for particular sections of
	 * the config file by resetting the globals between groups of
	 * TargetName or Subnet entries.
	 */
	for (entry = config->head; entry; entry = entry->next) {
		/* if the config entry is applicable to this session, apply it
		 */
		switch (entry->type) {
		case CONFIG_TYPE_TARGETNAME:{
				struct iscsi_targetname_config
				    *targetname_config =
				    entry->config.targetname;

				if (strcmp
				    (target->TargetName,
				     targetname_config->TargetName) == 0) {
					log_debug(5,
						 "applying config entry %p line"
						 " %d targetname config %p to "
						 "target config %p sessions %p",
						 entry, entry->line_number,
						 targetname_config, target,
						 target->sessions);

					for (session_config = target->sessions;
					     session_config;
					     session_config =
					     session_config->next) {
						struct iscsi_portal_config
						*portal_config;

						/* apply these options to every
						 * portal for this session
						 */
						portal_config =
						     session_config->portal;

						log_debug(5, "applying "
							 "config entry %p "
							 "targetname config %p "
							 "to session #%d "
							 "config %p portal "
							 "config %p", entry,
							 targetname_config,
							 session_config->
							 path_number,
							 session_config,
							 portal_config);

						memcpy(&portal_config->
						       tcp_options,
						       &targetname_config->
						       tcp_options,
						       sizeof(portal_config->
						       tcp_options));
						memcpy(&portal_config->
						       connection_timeout_options,
						       &targetname_config->
						       connection_timeout_options,
						       sizeof(portal_config->
						       connection_timeout_options));
						memcpy(&portal_config->
						       session_timeout_options,
							       &targetname_config->
						       session_timeout_options,
						       sizeof(portal_config->
							session_timeout_options));
						memcpy(&portal_config->
						       error_timeout_options,
						       &targetname_config->
						       error_timeout_options,
						       sizeof(portal_config->
						       error_timeout_options));
						memcpy(&portal_config->
						       iscsi_options,
						       &targetname_config->
						       iscsi_options,
						       sizeof(portal_config->
						       iscsi_options));

					}
				} else {
					log_debug(5,
						 "config entry %p line %d "
						 "targetname config %p does not"
						 " apply to target config %p",
						 entry, entry->line_number,
						 targetname_config, target);
				}
				break;
			}
		case CONFIG_TYPE_SUBNET:{
				struct iscsi_subnet_config *subnet_config =
				    entry->config.subnet;

				for (session_config = target->sessions;
				     session_config;
				     session_config = session_config->next) {
					struct iscsi_portal_config
					    *portal_config;

					/* apply these options to every portal
					 * for this session
					 */
					portal_config =
					     session_config->portal;
					/* FIXME: IPv6 */
					if (portal_config->descriptor &&
					    portal_config->descriptor->ip_length ==
					   4) {
						uint32_t a1, a2;

						a1 = portal_config->descriptor->
						     ip[0] << 24;
						a1 |= portal_config->
						      descriptor->ip[1] << 16;
						a1 |= portal_config->
						      descriptor->ip[2] << 8;
						a1 |= portal_config->
						      descriptor->ip[3];
						a1 &= subnet_config->
						      subnet_mask;

						a2 = subnet_config->
						     ip_address[0] << 24;
						a2 |= subnet_config->
						      ip_address[1] << 16;
						a2 |= subnet_config->
						      ip_address[2] << 8;
						a2 |= subnet_config->
						      ip_address[3];
						a2 &= subnet_config->
						      subnet_mask;

						if (a1 == a2) {
							log_debug(5,
								 "applying config entry %p line %d subnet config %p to session config %p portal config %p",
								 entry,
								 entry->
								 line_number,
								 subnet_config,
								 session_config,
								 portal_config);

							memcpy
							    (&portal_config->
							     connection_timeout_options,
							     &subnet_config->
							     connection_timeout_options,
							     sizeof
							     (portal_config->
							      connection_timeout_options));
							memcpy
							    (&portal_config->
							     error_timeout_options,
							     &subnet_config->
							     error_timeout_options,
							     sizeof
							     (portal_config->
							      error_timeout_options));
							memcpy
							    (&portal_config->
							     tcp_options,
							     &subnet_config->
							     tcp_options,
							     sizeof
							     (portal_config->
							      tcp_options));
						} else {
							log_debug(5,
								 "config entry %p line %d subnet config %p does not apply to target config %p",
								 entry,
								 entry->
								 line_number,
								 subnet_config,
								 target);
						}
					}
				}
				break;
			}
		default:
			break;
		}
	}

	return 1;
}

/* create one or more session configs based on the target config. */
void
create_session_configs(struct iscsi_target_config *target,
		       struct iscsi_portal_descriptor *descriptors,
		       struct iscsi_config *config)
{
	struct iscsi_session_config *session = NULL;
	struct iscsi_portal_descriptor *descriptor = NULL;
	struct iscsi_portal_config *portal = NULL;
	struct iscsi_session_config *prior = NULL;
	int path_number = 1;

	/* disabled targets have no sessions */
	if (!target->enabled) {
		log_debug(1, "target %p is disabled, creating no sessions to %s",
			 target, target->TargetName);
		return;
	}

	log_debug(1, "creating session configs for target config %p to %s",
		 target, target->TargetName);


	/* one session for each portal */
	for (descriptor = descriptors; descriptor;
	     descriptor = descriptor->next) {
		session = calloc(1, sizeof (*session));
		if (session == NULL) {
			log_error("couldn't allocate session "
					 "config for target %s",
					 target->TargetName);
			break;
		}

		portal = calloc(1, sizeof (*portal));
		if (portal == NULL) {
			log_error("couldn't allocate portal "
					 "config for target %s",
					 target->TargetName);
			break;
		}

		/* initialize session and portal */
		session->next = NULL;
		session->isid[0] = DRIVER_ISID_0;
		session->isid[1] = DRIVER_ISID_1;
		session->isid[2] = DRIVER_ISID_2;
		session->isid[3] = (path_number >> 16) & 0xFF;
		session->isid[4] = (path_number >> 8) & 0xFF;
		session->isid[5] = (path_number) & 0xFF;
		session->path_number = path_number++;
		session->target = target;

		portal->descriptor = descriptor;
		/* only one portal */
		portal->next = NULL;
		session->portal = portal;

		log_debug(1, "target config %p session #%d config %p portal %p "
			    "using descriptor %p", target, session->path_number,			    session, portal, descriptor);

		/* add it to the list of new session configs */
		if (prior) {
			log_debug(7, "session %p portal %p follows session %p "
				    "for target %p", session, portal, prior,
				    target);
			prior->next = session;
		} else {
			log_debug(7, "session %p portal %p is first session "
				    "for target %p", session, portal, target);
			target->sessions = session;
		}
		prior = session;
	/*FIXME what do I do with prior -krmurthy */
	}

	/* fill in the session and portal configs based on the config file info
	 */
	update_session_configs(target, config);

}

struct iscsi_target_config *
create_target_config(char *name, struct iscsi_portal_descriptor *descriptors,
		     struct iscsi_config *config,
		     struct iscsi_auth_config *auth_options)
{
	struct iscsi_target_config *target = calloc(1, sizeof (*target));

	if (target) {
		target->TargetName = name;
		target->sessions = NULL;

		log_debug(6, "allocated target config %p", target);

		if (!update_target_config(target, config, auth_options)) {
			free(target);
			target = NULL;
		}

		create_session_configs(target, descriptors, config);
	}

	return target;
}
