/*
 * iSCSI Configuration
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

#ifndef CONFIG_H
#define CONFIG_H

#include "types.h"
#include "auth.h"	/* for the username and password sizes */

/* default iSCSI port number */
#define ISCSI_DEFAULT_PORT 3260

/* ISIDs now have a typed naming authority in them.  We use an OUI */
#define DRIVER_ISID_0  0x00
#define DRIVER_ISID_1  0x02
#define DRIVER_ISID_2  0x3D

/* default window size */
#define TCP_WINDOW_SIZE (256 * 1024)

/* the following structures store the options set in the config file.
 * a structure is defined for each logically-related group of options.
 * if you are adding a new option, first check if it should belong
 * to one of the existing groups.  If it does, add it.  If not, define
 * a new structure.
 */

/* all authentication-related options should be added to this structure.
 * this structure is per-session, and can be configured
 * by TargetName but not Subnet.
 */
struct iscsi_auth_config {
	unsigned int authmethod;
	char username[AUTH_STR_MAX_LEN];
	unsigned char password[AUTH_STR_MAX_LEN];
	unsigned int password_length;
	char username_in[AUTH_STR_MAX_LEN];
	unsigned char password_in[AUTH_STR_MAX_LEN];
	unsigned int password_length_in;
};

/* all per-connection timeouts go in this structure.
 * this structure is per-portal, and can be configured
 * both by TargetName and Subnet.
 */
struct iscsi_connection_timeout_config {
	int login_timeout;
	int auth_timeout;
	int active_timeout;
	int idle_timeout;
	int ping_timeout;
};

/* all per-connection timeouts go in this structure.
 * this structure is per-session, and can be configured
 * by TargetName but not by Subnet.
 */
struct iscsi_session_timeout_config {
	int replacement_timeout;
};

/* all error handling timeouts go in this structure.
 * this structure is per-portal, and can be configured
 * both by TargetName and Subnet.
 */
struct iscsi_error_timeout_config {
	int abort_timeout;
	int reset_timeout;
};

/* all TCP options go in this structure.
 * this structure is per-portal, and can be configured
 * both by TargetName and Subnet.
 */
struct iscsi_tcp_config {
	int window_size;
	int type_of_service;	/* try to set IP TOS bits */
};

/* all iSCSI operational params go in this structure.
 * this structure is per-portal, and can be configured
 * both by TargetName and Subnet.
 */
struct iscsi_operational_config {
	int protocol;
	int InitialR2T;
	int ImmediateData;
	int MaxRecvDataSegmentLength;
	int FirstBurstLength;
	int MaxBurstLength;
	int DefaultTime2Wait;
	int DefaultTime2Retain;
	int HeaderDigest;
	int DataDigest;
};

#define CONFIG_DIGEST_NEVER  0
#define CONFIG_DIGEST_ALWAYS 1
#define CONFIG_DIGEST_PREFER_ON 2
#define CONFIG_DIGEST_PREFER_OFF 3

/* the following structures represent the contents of the config file */

struct iscsi_targetname_config {
	char *TargetName;
	int enabled;
	struct iscsi_auth_config auth_options;
	struct iscsi_tcp_config tcp_options;
	struct iscsi_connection_timeout_config connection_timeout_options;
	struct iscsi_session_timeout_config session_timeout_options;
	struct iscsi_error_timeout_config error_timeout_options;
	struct iscsi_operational_config iscsi_options;
};

struct iscsi_subnet_config {
	char *address;
	int ip_length;
	char ip_address[16];
	int port;
	uint32_t subnet_mask;	/* IPv4 subnet mask */
	struct iscsi_connection_timeout_config connection_timeout_options;
	struct iscsi_error_timeout_config error_timeout_options;
	struct iscsi_tcp_config tcp_options;
};

struct iscsi_sendtargets_config {
	char *address;
	int port;
	int continuous;
	int send_async_text;
	struct iscsi_auth_config auth_options;
	struct iscsi_connection_timeout_config connection_timeout_options;
};

struct iscsi_slp_config {
	char *address;		/* for unicast */
	int port;		/* for unicast */
	char *scopes;
	char *interfaces;	/* for multicast, list of interfaces names,
				 * "all", or "none"
				 */
	int poll_interval;
	struct iscsi_auth_config auth_options;
};

struct iscsi_discovery_file_config {
	char *filename;
	int read_size;
	char *address;
	char *port;
	int continuous;
	struct iscsi_auth_config auth_options;
};

/* config defaults */
struct iscsi_config_defaults {
	/* discovery defaults */
	int continuous_sendtargets;	/* if non-zero, default to keeping
					 * iSCSI discovery sessions open
					 */
	int send_async_text;	/* if non-zero, target will send
				 * vendor specific async events.
				 */
	int slp_multicast;	/* if non-zero, default to attempting SLP
				 * multicast discovery of all targets this
				 * initiator can access
				 */
	char *slp_scopes;
	int slp_poll_interval;

	/* global default options, used if no options are in the config,
	 * or if the user sets global defaults in the config file.
	 */
	int enabled;
	struct iscsi_auth_config auth_options;
	struct iscsi_connection_timeout_config connection_timeout_options;
	struct iscsi_error_timeout_config error_timeout_options;
	struct iscsi_session_timeout_config session_timeout_options;
	struct iscsi_tcp_config tcp_options;
	struct iscsi_operational_config iscsi_options;
};

struct iscsi_config_entry {
	struct iscsi_config_entry *prev;
	struct iscsi_config_entry *next;
	int type;
	int line_number;
	union {
		struct iscsi_sendtargets_config *sendtargets;
		struct iscsi_slp_config *slp;
		struct iscsi_discovery_file_config *file;
		struct iscsi_targetname_config *targetname;
		struct iscsi_subnet_config *subnet;
	} config;
};

#define CONFIG_TYPE_UNKNOWN        0
#define CONFIG_TYPE_SENDTARGETS    1
#define CONFIG_TYPE_SLP            2
#define CONFIG_TYPE_DISCOVERY_FILE 3
#define CONFIG_TYPE_TARGETNAME     4
#define CONFIG_TYPE_SUBNET         5
#define CONFIG_TYPE_ADDRESS        6

/* collect all iscsi config file info together */
struct iscsi_config {
	struct iscsi_config_defaults defaults;
	struct iscsi_config_entry *head;
	struct iscsi_config_entry *tail;
};

/* the following structures represent the run-time configuration,
 * computed based on the discovery info and the structures representing
 * the config file contents.
 */

/* discovery produces portal descriptors.
 * this arguably belongs in a different header file,
 * but is here since everything references them
 * via portal_configs
 */
struct iscsi_portal_descriptor {
	struct iscsi_portal_descriptor *next;
	char *address;		/* text string */
	char ip[16];		/* binary IP */
	int ip_length;
	int port;
	int tag;
};

#define PORTAL_GROUP_TAG_UNKNOWN -1

/* structures dynamically created as the main daemon collects discovery info
 * and processes config info
 */

struct iscsi_portal_config {
	struct iscsi_portal_config *next;
	struct iscsi_portal_descriptor *descriptor;	/* the target_config's
							 * portal descriptor
							 */
	/* and the config options to use when the connection uses this portal */
	struct iscsi_connection_timeout_config connection_timeout_options;
	struct iscsi_session_timeout_config session_timeout_options;
	struct iscsi_error_timeout_config error_timeout_options;
	struct iscsi_tcp_config tcp_options;
	struct iscsi_operational_config iscsi_options;
};

struct iscsi_portal_config_list {
	struct iscsi_portal_config *head;
	struct iscsi_portal_config *tail;
};

/* config code doesn't need to care about what's in the session process struct
 */
struct iscsi_session_process;

struct iscsi_target_config;

/* a normal iSCSI session */
struct iscsi_session_config {
	struct iscsi_session_config *next;
	struct iscsi_session_process *process;
	struct iscsi_target_config *target;
	struct iscsi_portal_config *portal;
	int iscsi_bus;
	int target_id;
	unsigned char isid[6];
	int path_number;
};

struct iscsi_discovery_process;

struct iscsi_target_config {
	char *TargetName;	/* typically shared with some other structure,
				 * which manages the lifetime
				 */

	/* options that only make sense for the target as a whole */
	int enabled;
	struct iscsi_auth_config auth_options;

	struct iscsi_session_config *sessions;

};

/* exported functions */
extern char *get_iscsi_initiatorname(char *pathname);

extern int update_iscsi_config(const char *pathname,
			       struct iscsi_config *config);

extern int add_config_entry(struct iscsi_config *config,
			    struct iscsi_config_entry *entry);
extern int remove_config_entry(struct iscsi_config *config,
			       struct iscsi_config_entry *entry);
extern void free_config_entry(struct iscsi_config_entry *entry);

extern struct iscsi_target_config *create_target_config(char *name,
							struct
							iscsi_portal_descriptor
							*portals,
							struct iscsi_config
							*config,
							struct iscsi_auth_config
							*auth_options);

extern void free_target_config(struct iscsi_target_config *config);

extern void create_session_configs(struct iscsi_target_config *target,
				   struct iscsi_portal_descriptor *portals,
				   struct iscsi_config *config);

extern void free_session_config(struct iscsi_session_config *config);

extern void free_portal_descriptors(struct iscsi_portal_descriptor *portals);

extern void iscsi_init_config_defaults(struct iscsi_config_defaults *defaults);

/* comparisons */
extern int same_portal_descriptor(struct iscsi_portal_descriptor *p1,
				  struct iscsi_portal_descriptor *p2);
extern int same_portal_descriptors(struct iscsi_portal_descriptor *portals1,
				   struct iscsi_portal_descriptor *portals2);
extern int same_portal_config(struct iscsi_portal_config *p1,
			      struct iscsi_portal_config *p2);
extern int same_portal_configs(struct iscsi_portal_config *portals1,
			       struct iscsi_portal_config *portals2);
extern int same_session_config(struct iscsi_session_config *s1,
			       struct iscsi_session_config *s2);
extern int same_target_config(struct iscsi_target_config *t1,
			      struct iscsi_target_config *t2);

#endif /* CONFIG_H */
