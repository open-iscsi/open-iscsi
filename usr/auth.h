/*
 * iSCSI Authorization Library
 *
 * maintained by open-iscsi@@googlegroups.com
 *
 * Originally based on:
 * Copyright (C) 2001 Cisco Systems, Inc.
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
#ifndef AUTH_CLIENT_H
#define AUTH_CLIENT_H

struct iscsi_session;

enum {
	AUTH_STR_MAX_LEN = 256,
	AUTH_STR_BLOCK_MAX_LEN = 1024,
	AUTH_LARGE_BINARY_MAX_LEN = 1024,
	AUTH_RECV_END_MAX_COUNT = 10,
	ACL_SIGNATURE = 0x5984B2E3,
	AUTH_CHAP_RSP_LEN = 16,
};

/*
 * Note: The ordering of these values are chosen to match
 *       the ordering of the keys as shown in the iSCSI spec.
 *       The order of table key_names in acl_get_key_name()
 *       must match the order defined by enum auth_key_type.
 */
enum auth_key_type {
	AUTH_KEY_TYPE_NONE = -1,
	AUTH_KEY_TYPE_FIRST = 0,
	AUTH_KEY_TYPE_AUTH_METHOD = AUTH_KEY_TYPE_FIRST,
	AUTH_KEY_TYPE_CHAP_ALG,
	AUTH_KEY_TYPE_CHAP_USERNAME,
	AUTH_KEY_TYPE_CHAP_RSP,
	AUTH_KEY_TYPE_CHAP_IDENTIFIER,
	AUTH_KEY_TYPE_CHAP_CHALLENGE,
	AUTH_KEY_TYPE_MAX_COUNT,
	AUTH_KEY_TYPE_LAST = AUTH_KEY_TYPE_MAX_COUNT - 1
};

enum {
	/* Common options for all keys. */
	AUTH_OPTION_REJECT = -2,
	AUTH_OPTION_NOT_PRESENT = -1,
	AUTH_OPTION_NONE = 1,

	AUTH_METHOD_CHAP = 2,
	AUTH_METHOD_MAX_COUNT = 2,

	AUTH_CHAP_ALG_MD5 = 5,
	AUTH_CHAP_ALG_MAX_COUNT = 2
};

enum auth_neg_role {
	AUTH_NEG_ROLE_ORIGINATOR = 1,
	AUTH_NEG_ROLE_RESPONDER = 2
};

enum auth_status {
	AUTH_STATUS_NO_ERROR = 0,
	AUTH_STATUS_ERROR,
	AUTH_STATUS_PASS,
	AUTH_STATUS_FAIL,
	AUTH_STATUS_CONTINUE,
};

/*
 * Note: The order of table dbg_text in acl_dbg_status_to_text()
 *       must match the ordered defined by enum auth_dbg_status.
 */
enum auth_dbg_status {
	AUTH_DBG_STATUS_NOT_SET = 0,

	AUTH_DBG_STATUS_AUTH_PASS,
	AUTH_DBG_STATUS_AUTH_RMT_FALSE,

	AUTH_DBG_STATUS_AUTH_FAIL,

	AUTH_DBG_STATUS_AUTH_METHOD_BAD,
	AUTH_DBG_STATUS_CHAP_ALG_BAD,
	AUTH_DBG_STATUS_PASSWD_DECRYPT_FAILED,
	AUTH_DBG_STATUS_PASSWD_TOO_SHORT_WITH_NO_IPSEC,
	AUTH_DBG_STATUS_AUTH_SERVER_ERROR,
	AUTH_DBG_STATUS_AUTH_STATUS_BAD,
	AUTH_DBG_STATUS_AUTHPASS_NOT_VALID,
	AUTH_DBG_STATUS_SEND_DUP_SET_KEY_VALUE,
	AUTH_DBG_STATUS_SEND_STR_TOO_LONG,
	AUTH_DBG_STATUS_SEND_TOO_MUCH_DATA,

	AUTH_DBG_STATUS_AUTH_METHOD_EXPECTED,
	AUTH_DBG_STATUS_CHAP_ALG_EXPECTED,
	AUTH_DBG_STATUS_CHAP_IDENTIFIER_EXPECTED,
	AUTH_DBG_STATUS_CHAP_CHALLENGE_EXPECTED,
	AUTH_DBG_STATUS_CHAP_RSP_EXPECTED,
	AUTH_DBG_STATUS_CHAP_USERNAME_EXPECTED,

	AUTH_DBG_STATUS_AUTH_METHOD_NOT_PRESENT,
	AUTH_DBG_STATUS_AUTH_METHOD_REJECT,
	AUTH_DBG_STATUS_AUTH_METHOD_NONE,
	AUTH_DBG_STATUS_CHAP_ALG_REJECT,
	AUTH_DBG_STATUS_CHAP_CHALLENGE_REFLECTED,
	AUTH_DBG_STATUS_PASSWD_IDENTICAL,

	AUTH_DBG_STATUS_LOCAL_PASSWD_NOT_SET,

	AUTH_DBG_STATUS_CHAP_IDENTIFIER_BAD,
	AUTH_DBG_STATUS_CHALLENGE_BAD,
	AUTH_DBG_STATUS_CHAP_RSP_BAD,
	AUTH_DBG_STATUS_UNEXPECTED_KEY_PRESENT,
	AUTH_DBG_STATUS_T_BIT_SET_ILLEGAL,
	AUTH_DBG_STATUS_T_BIT_SET_PREMATURE,

	AUTH_DBG_STATUS_RECV_MSG_COUNT_LIMIT,
	AUTH_DBG_STATUS_RECV_DUP_SET_KEY_VALUE,
	AUTH_DBG_STATUS_RECV_STR_TOO_LONG,
	AUTH_DBG_STATUS_RECV_TOO_MUCH_DATA,
	AUTH_DBG_STATUS_MAX_COUNT
};

enum auth_node_type {
	TYPE_INITIATOR = 1,
	TYPE_TARGET = 2
};

enum auth_phase {
	AUTH_PHASE_CONFIGURE = 1,
	AUTH_PHASE_NEGOTIATE,
	AUTH_PHASE_AUTHENTICATE,
	AUTH_PHASE_DONE,
	AUTH_PHASE_ERROR
};

enum auth_local_state {
	AUTH_LOCAL_STATE_SEND_ALG = 1,
	AUTH_LOCAL_STATE_RECV_ALG,
	AUTH_LOCAL_STATE_RECV_CHALLENGE,
	AUTH_LOCAL_STATE_DONE,
	AUTH_LOCAL_STATE_ERROR
};

enum auth_rmt_state {
	AUTH_RMT_STATE_SEND_ALG = 1,
	AUTH_RMT_STATE_SEND_CHALLENGE,
	AUTH_RMT_STATE_RECV_RSP,
	AUTH_RMT_STATE_DONE,
	AUTH_RMT_STATE_ERROR
};

struct auth_buffer_desc {
	unsigned int length;
	void *address;
};

struct auth_key {
	unsigned int present:1;
	unsigned int processed:1;
	unsigned int value_set:1;
	char *string;
};

struct auth_large_binary_key {
	unsigned int length;
	unsigned char *large_binary;
};

struct auth_key_block {
	unsigned int transit_bit:1;
	unsigned int dup_set:1;
	unsigned int str_too_long:1;
	unsigned int too_much_data:1;
	unsigned int blk_length:16;
	char *str_block;
	struct auth_key key[AUTH_KEY_TYPE_MAX_COUNT];
};

struct auth_str_block {
	char str_block[AUTH_STR_BLOCK_MAX_LEN];
};

struct auth_large_binary {
	unsigned char large_binary[AUTH_LARGE_BINARY_MAX_LEN];
};

struct iscsi_acl {
	unsigned long signature;

	enum auth_node_type node_type;
	unsigned int auth_method_count;
	int auth_method_list[AUTH_METHOD_MAX_COUNT];
	enum auth_neg_role auth_method_neg_role;
	unsigned int chap_alg_count;
	int chap_alg_list[AUTH_CHAP_ALG_MAX_COUNT];
	int auth_rmt;
	char username[AUTH_STR_MAX_LEN];
	int passwd_present;
	unsigned int passwd_length;
	unsigned char passwd_data[AUTH_STR_MAX_LEN];
	unsigned int chap_challenge_len;
	int ip_sec;

	unsigned int auth_method_valid_count;
	int auth_method_valid_list[AUTH_METHOD_MAX_COUNT];
	int auth_method_valid_neg_role;

	int recv_in_progress_flag;
	int recv_end_count;
	struct iscsi_session *session_handle;	/*
						 * session_handle can only be
						 * used by acl_chap_auth_request
						 */
	enum auth_phase phase;
	enum auth_local_state local_state;
	enum auth_rmt_state rmt_state;
	enum auth_status rmt_auth_status;
	enum auth_dbg_status dbg_status;
	int negotiated_auth_method;
	int negotiated_chap_alg;
	int auth_rsp_flag;
	int auth_server_error_flag;
	int transit_bit_sent_flag;

	unsigned int send_chap_identifier;
	struct auth_large_binary_key send_chap_challenge;
	char chap_username[AUTH_STR_MAX_LEN];

	int recv_chap_challenge_status;
	struct auth_large_binary_key recv_chap_challenge;

	char scratch_key_value[AUTH_STR_MAX_LEN];

	struct auth_key_block recv_key_block;
	struct auth_key_block send_key_block;
};

extern int acl_init(int node_type, int buf_desc_count,
		    struct auth_buffer_desc *buff_desc);
extern int acl_finish(struct iscsi_acl *client);

extern int acl_recv_begin(struct iscsi_acl *client);
extern int acl_recv_end(struct iscsi_acl *client,
			struct iscsi_session *session_handle);
extern const char *acl_get_key_name(int key_type);
extern int acl_get_next_key_type(int *key_type);
extern int acl_recv_key_value(struct iscsi_acl *client, int key_type,
			      const char *user_key_val);
extern int acl_send_key_val(struct iscsi_acl *client, int key_type,
			    int *key_present, char *user_key_val,
			    unsigned int max_length);
extern int acl_recv_transit_bit(struct iscsi_acl *client, int value);
extern int acl_send_transit_bit(struct iscsi_acl *client, int *value);
extern int acl_set_user_name(struct iscsi_acl *client, const char *username);
extern int acl_set_passwd(struct iscsi_acl *client,
			  const unsigned char *pw_data, unsigned int pw_len);
extern int acl_set_auth_rmt(struct iscsi_acl *client, int auth_rmt);
extern int acl_set_ip_sec(struct iscsi_acl *client, int ip_sec);
extern int acl_get_dbg_status(struct iscsi_acl *client, int *value);
extern const char *acl_dbg_status_to_text(int dbg_status);
extern enum auth_dbg_status acl_chap_compute_rsp(struct iscsi_acl *client,
						 int rmt_auth,
						 unsigned int id,
						 unsigned char *challenge_data,
						 unsigned int challenge_len,
						 unsigned char *response_data);
extern int acl_chap_auth_request(struct iscsi_acl *client, char *username,
				 unsigned int id,
				 unsigned char *challenge_data,
				 unsigned int challenge_length,
				 unsigned char *response_data,
				 unsigned int rsp_length);
extern int acl_data(unsigned char *out_data, unsigned int *out_length,
		    unsigned char *in_data, unsigned int in_length);
#endif				/* #ifndef ISCSIAUTHCLIENT_H */
