/*
 * iSCSI Initiator
 *
 * Copyright (C) 2004 Dmitry Yusupov, Alex Aizman
 * maintained by open-iscsi@@googlegroups.com
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

#ifndef INITIATOR_H
#define INITIATOR_H

#include <stdint.h>

#include "iscsi_proto.h"
#include "auth.h"

/* daemon's session structure */
struct iscsi_session {
	int socket_fd;
	int login_timeout;
	int auth_timeout;
	int active_timeout;
	int idle_timeout;
	int ping_timeout;
	int vendor_specific_keys;
	unsigned int irrelevant_keys_bitmap;
	int send_async_text;
	uint32_t itt;
	uint32_t cmdsn;
	uint32_t exp_cmdsn;
	uint32_t max_cmdsn;
	uint32_t exp_statsn;
	int immediate_data;
	int initial_r2t;
	int max_recv_data_segment_len;	/* the value we declare */
	int max_xmit_data_segment_len;	/* the value declared by the target */
	int first_burst_len;
	int max_burst_len;
	int data_pdu_in_order;
	int data_seq_in_order;
	int def_time2wait;
	int def_time2retain;
	int header_digest;
	int data_digest;
	int type;
	int current_stage;
	int next_stage;
	int partial_response;
	int portal_group_tag;
	uint8_t isid[6];
	uint16_t tsih;
	int channel;
	int target_id;
	char target_name[TARGET_NAME_MAXLEN + 1];
	char *target_alias;
	char *initiator_name;
	char *initiator_alias;
	int ip_length;
	uint8_t ip_address[16];
	int port;
	int tcp_window_size;
	struct auth_str_block auth_recv_string_block;
	struct auth_str_block auth_send_string_block;
	struct auth_large_binary auth_recv_binary_block;
	struct auth_large_binary auth_send_binary_block;
	struct iscsi_acl auth_client_block;
	struct iscsi_acl *auth_client;
	int num_auth_buffers;
	struct auth_buffer_desc auth_buffers[5];
	int bidirectional_auth;
	char username[AUTH_STR_MAX_LEN];
	uint8_t password[AUTH_STR_MAX_LEN];
	int password_length;
	char username_in[AUTH_STR_MAX_LEN];
	uint8_t password_in[AUTH_STR_MAX_LEN];
	int password_length_in;
};
extern int iscsi_update_address(struct iscsi_session *session, char *address);

/* login.c */

#define ISCSI_SESSION_TYPE_NORMAL 0
#define ISCSI_SESSION_TYPE_DISCOVERY 1

/* not defined by iSCSI, but used in the login code to determine
 * when to send the initial Login PDU
 */
#define ISCSI_INITIAL_LOGIN_STAGE -1

#define ISCSI_TEXT_SEPARATOR     '='

enum iscsi_login_status {
	LOGIN_OK = 0,		/* library worked, but caller must check
				 * the status class and detail
				 */
	LOGIN_IO_ERROR,		/* PDU I/O failed, connection have been
				 * closed or reset
				 */
	LOGIN_FAILED,		/* misc. failure */
	LOGIN_VERSION_MISMATCH,	/* incompatible iSCSI protocol version */
	LOGIN_NEGOTIATION_FAILED,	/* didn't like a key value
					 * (or received an unknown key)
					 */
	LOGIN_AUTHENTICATION_FAILED,	/* auth code indicated failure */
	LOGIN_WRONG_PORTAL_GROUP,	/* portal group tag didn't match
					 * the one required
					 */
	LOGIN_REDIRECTION_FAILED,	/* couldn't handle the redirection
					 * requested by the target
					 */
	LOGIN_INVALID_PDU,	/* received an incorrect opcode,
				 * or bogus fields in a PDU
				 */
};

/* implemented in iscsi-login.c for use on all platforms */
extern int iscsi_add_text(struct iscsi_session *session, struct iscsi_hdr *pdu,
			  char *data, int max_data_length, char *param,
			  char *value);
extern enum iscsi_login_status iscsi_login(struct iscsi_session *session,
					   char *buffer, uint32_t bufsize,
					   uint8_t * status_class,
					   uint8_t * status_detail);

/* Digest types */
#define ISCSI_DIGEST_NONE  0
#define ISCSI_DIGEST_CRC32C 1
#define ISCSI_DIGEST_CRC32C_NONE 2	/* offer both, prefer CRC32C */
#define ISCSI_DIGEST_NONE_CRC32C 3	/* offer both, prefer None */

#define IRRELEVANT_MAXCONNECTIONS	0x01
#define IRRELEVANT_INITIALR2T		0x02
#define IRRELEVANT_IMMEDIATEDATA	0x04
#define IRRELEVANT_MAXBURSTLENGTH	0x08
#define IRRELEVANT_FIRSTBURSTLENGTH	0x10
#define IRRELEVANT_MAXOUTSTANDINGR2T	0x20
#define IRRELEVANT_DATAPDUINORDER	0x40
#define IRRELEVANT_DATASEQUENCEINORDER	0x80

#endif /* INITIATOR_H */
