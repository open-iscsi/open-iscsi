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

#define PORTAL_GROUP_TAG_UNKNOWN -1

/* default iSCSI port number */
#define ISCSI_DEFAULT_PORT 3260

#define CHAP_AUTHENTICATION     1

/* ISIDs now have a typed naming authority in them.  We use an OUI */
#define DRIVER_ISID_0  0x00
#define DRIVER_ISID_1  0x02
#define DRIVER_ISID_2  0x3D

/* default window size */
#define TCP_WINDOW_SIZE (256 * 1024)

/* number of possible connections per session */
#define ISCSI_CNX_MAX		16

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

struct iscsi_cnx_operational_config {
	int MaxRecvDataSegmentLength;
	int HeaderDigest;
	int DataDigest;
};

/* all iSCSI operational params go in this structure.
 * this structure is per-portal, and can be configured
 * both by TargetName and Subnet.
 */
struct iscsi_session_operational_config {
	int protocol;
	int InitialR2T;
	int ImmediateData;
	int FirstBurstLength;
	int MaxBurstLength;
	int DefaultTime2Wait;
	int DefaultTime2Retain;
	int MaxConnections;
};

#define CONFIG_DIGEST_NEVER  0
#define CONFIG_DIGEST_ALWAYS 1
#define CONFIG_DIGEST_PREFER_ON 2
#define CONFIG_DIGEST_PREFER_OFF 3

struct iscsi_sendtargets_config {
	char address[16];
	int port;
	int continuous;
	int send_async_text;
	struct iscsi_auth_config auth;
	struct iscsi_connection_timeout_config cnx_timeo;
};

struct iscsi_slp_config {
	char address[16];		/* for unicast */
	int port;		/* for unicast */
	char *scopes;
	char *interfaces;	/* for multicast, list of interfaces names,
				 * "all", or "none" */
	int poll_interval;
	struct iscsi_auth_config auth;
};

typedef enum iscsi_startup {
	ISCSI_STARTUP_MANUAL,
	ISCSI_STARTUP_AUTOMATIC,
} iscsi_startup_e;

typedef enum discovery_type {
	DISCOVERY_TYPE_SENDTARGETS,
	DISCOVERY_TYPE_SLP,
	DISCOVERY_TYPE_ISNS,
} discovery_type_e;

typedef struct cnx_rec {
	iscsi_startup_e				startup;
	char					address[16];
	int					port;
	struct iscsi_tcp_config			tcp;
	struct iscsi_connection_timeout_config	timeo;
	struct iscsi_cnx_operational_config	iscsi;
} cnx_rec_t;

typedef struct session_rec {
	int					initial_cmdsn;
	struct iscsi_auth_config		auth;
	struct iscsi_session_timeout_config	timeo;
	struct iscsi_error_timeout_config	err_timeo;
	struct iscsi_session_operational_config	iscsi;
} session_rec_t;

typedef struct node_rec {
	int					id;
	char					name[TARGET_NAME_MAXLEN];
	int					tpgt;
	int					active_cnx;
	iscsi_startup_e				startup;
	session_rec_t				session;
	cnx_rec_t				cnx[ISCSI_CNX_MAX];
} node_rec_t;

typedef struct discovery_rec {
	int					id;
	iscsi_startup_e				startup;
	discovery_type_e			type;
	union {
		struct iscsi_sendtargets_config	sendtargets;
		struct iscsi_slp_config		slp;
	} u;
} discovery_rec_t;

#endif /* CONFIG_H */
