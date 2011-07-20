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
 * This file implements the iSCSI CHAP authentication method based on
 * RFC 3720.  The code in this file is meant to be common for both kernel and
 * user level and makes use of only limited  library  functions, presently only
 * string.h. Routines specific to kernel, user level are implemented in
 * seperate files under the appropriate directories.
 * This code in this files assumes a single thread of execution
 * for each iscsi_acl structure, and does no locking.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "sysdeps.h"
#include "auth.h"
#include "initiator.h"
#include "md5.h"
#include "log.h"

static const char acl_hexstring[] = "0123456789abcdefABCDEF";
static const char acl_base64_string[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char acl_authmethod_set_chap_alg_list[] = "CHAP";
static const char acl_reject_option_name[] = "Reject";

void auth_md5_init(struct MD5Context *);
void auth_md5_update(struct MD5Context *, unsigned char *, unsigned int);
void auth_md5_final(unsigned char *, struct MD5Context *);
void get_random_bytes(unsigned char *data, unsigned int length);
size_t strlcpy(char *, const char *, size_t);
size_t strlcat(char *, const char *, size_t);

enum auth_dbg_status
acl_chap_compute_rsp(struct iscsi_acl *client, int rmt_auth, unsigned int id,
		     unsigned char *challenge_data,
		     unsigned int challenge_length,
		     unsigned char *response_data)
{
	unsigned char id_data[1];
	struct MD5Context context;
	unsigned char out_data[AUTH_STR_MAX_LEN];
	unsigned int out_length = AUTH_STR_MAX_LEN;

	if (!client->passwd_present)
		return AUTH_DBG_STATUS_LOCAL_PASSWD_NOT_SET;

	auth_md5_init(&context);

	/* id byte */
	id_data[0] = id;
	auth_md5_update(&context, id_data, 1);

	/* decrypt password */
	if (acl_data(out_data, &out_length, client->passwd_data,
		     client->passwd_length))
		return AUTH_DBG_STATUS_PASSWD_DECRYPT_FAILED;

	if (!rmt_auth && !client->ip_sec && out_length < 12)
		return AUTH_DBG_STATUS_PASSWD_TOO_SHORT_WITH_NO_IPSEC;

	/* shared secret */
	auth_md5_update(&context, out_data, out_length);

	/* clear decrypted password */
	memset(out_data, 0, AUTH_STR_MAX_LEN);

	/* challenge value */
	auth_md5_update(&context, challenge_data, challenge_length);

	auth_md5_final(response_data, &context);

	return AUTH_DBG_STATUS_NOT_SET;	/* no error */
}

/*
 * Authenticate a target's CHAP response.
 */
int
acl_chap_auth_request(struct iscsi_acl *client, char *username, unsigned int id,
		      unsigned char *challenge_data,
		      unsigned int challenge_length,
		      unsigned char *response_data,
		      unsigned int rsp_length)
{
	iscsi_session_t *session = client->session_handle;
	struct MD5Context context;
	unsigned char verify_data[16];

	/* the expected credentials are in the session */
	if (session->username_in == NULL) {
		log_error("failing authentication, no incoming username "
			  "configured to authenticate target %s\n",
			  session->target_name);
		return AUTH_STATUS_FAIL;
	}
	if (strcmp(username, session->username_in) != 0) {
		log_error("failing authentication, received incorrect "
			  "username from target %s\n", session->target_name);
		return AUTH_STATUS_FAIL;
	}

	if ((session->password_in_length < 1) ||
	    (session->password_in == NULL) ||
	    (session->password_in[0] == '\0')) {
		log_error("failing authentication, no incoming password "
		       "configured to authenticate target %s\n",
		       session->target_name);
		return AUTH_STATUS_FAIL;
	}

	/* challenge length is I->T, and shouldn't need to be checked */

	if (rsp_length != sizeof(verify_data)) {
		log_error("failing authentication, received incorrect "
			  "CHAP response length %u from target %s\n",
			  rsp_length, session->target_name);
		return AUTH_STATUS_FAIL;
	}

	auth_md5_init(&context);

	/* id byte */
	verify_data[0] = id;
	auth_md5_update(&context, verify_data, 1);

	/* shared secret */
	auth_md5_update(&context, (unsigned char *)session->password_in,
			session->password_in_length);

	/* challenge value */
	auth_md5_update(&context, (unsigned char *)challenge_data,
			challenge_length);

	auth_md5_final(verify_data, &context);

	if (memcmp(response_data, verify_data, sizeof(verify_data)) == 0) {
		log_debug(1, "initiator authenticated target %s\n",
			  session->target_name);
		return AUTH_STATUS_PASS;
	}

	log_error("failing authentication, received incorrect CHAP "
		  "response from target %s\n", session->target_name);
	return AUTH_STATUS_FAIL;
}

void
auth_md5_init(struct MD5Context *context)
{
	MD5Init(context);
}

void
auth_md5_update(struct MD5Context *context, unsigned char *data,
		unsigned int length)
{
	MD5Update(context, data, length);
}

void
auth_md5_final(unsigned char *hash, struct MD5Context *context)
{
	MD5Final(hash, context);
}

void
get_random_bytes(unsigned char *data, unsigned int length)
{

	long r;
        unsigned n;
	int fd;

	fd = open("/dev/urandom", O_RDONLY);
        while (length > 0) {

		if (!fd || read(fd, &r, sizeof(long)) != -1)
			r = rand();
                r = r ^ (r >> 8);
                r = r ^ (r >> 4);
                n = r & 0x7;

		if (!fd || read(fd, &r, sizeof(long)) != -1)
			r = rand();
                r = r ^ (r >> 8);
                r = r ^ (r >> 5);
                n = (n << 3) | (r & 0x7);

		if (!fd || read(fd, &r, sizeof(long)) != -1)
			r = rand();
                r = r ^ (r >> 8);
                r = r ^ (r >> 5);
                n = (n << 2) | (r & 0x3);

                *data++ = n;
                length--;
        }
	if (fd)
		close(fd);
}

static const char acl_none_option_name[] = "None";

static int
acl_text_to_number(const char *text, unsigned long *num)
{
	char *end;
	unsigned long number = *num;

	if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X'))
		number = strtoul(text + 2, &end, 16);
	else
		number = strtoul(text, &end, 10);

	if (*text != '\0' && *end == '\0') {
		*num = number;
		return 0;	/* No error */
	} else
		return 1;	/* Error */
}

static int
acl_chk_string(const char *s, unsigned int max_len, unsigned int *out_len)
{
	unsigned int len;

	if (!s)
		return 1;

	for (len = 0; len < max_len; len++)
		if (*s++ == '\0') {
			if (out_len)
				*out_len = len;
			return 0;
		}

	return 1;
}

static int
acl_str_index(const char *s, int c)
{
	char *str = strchr(s, c);

	if (str)
		return (str - s);
	else
		return -1;
}

static int
acl_chk_auth_mthd_optn(int val)
{
	if (val == AUTH_OPTION_NONE || val == AUTH_METHOD_CHAP)
		return 0;

	return 1;
}

static const char *
acl_authmethod_optn_to_text(int value)
{
	const char *s;
	switch (value) {
	case AUTH_OPTION_REJECT:
		s = acl_reject_option_name;
		break;
	case AUTH_OPTION_NONE:
		s = acl_none_option_name;
		break;
	case AUTH_METHOD_CHAP:
		s = acl_authmethod_set_chap_alg_list;
		break;
	default:
		s = NULL;
	}
	return s;
}

static int
acl_chk_chap_alg_optn(int chap_algorithm)
{
	if (chap_algorithm == AUTH_OPTION_NONE ||
	    chap_algorithm == AUTH_CHAP_ALG_MD5)
		return 0;

	return 1;
}

static int
acl_data_to_text(unsigned char *data, unsigned int data_length, char *text,
		 unsigned int text_length)
{
	unsigned long n;

	if (!text || text_length == 0)
		return 1;

	if (!data || data_length == 0) {
		*text = '\0';
		return 1;
	}

	if (text_length < 3) {
		*text = '\0';
		return 1;
	}

	*text++ = '0';
	*text++ = 'x';

	text_length -= 2;

	while (data_length > 0) {

		if (text_length < 3) {
			*text = '\0';
			return 1;
		}

		n = *data++;
		data_length--;

		*text++ = acl_hexstring[(n >> 4) & 0xf];
		*text++ = acl_hexstring[n & 0xf];

		text_length -= 2;
	}

	*text = '\0';

	return 0;
}

static int
acl_hex_to_data(const char *text, unsigned int text_length, unsigned char *data,
		unsigned int *data_lenp)
{
	int i;
	unsigned int n1;
	unsigned int n2;
	unsigned int data_length = *data_lenp;

	if ((text_length % 2) == 1) {

		i = acl_str_index(acl_hexstring, *text++);
		if (i < 0)
			return 1;	/* error, bad character */

		if (i > 15)
			i -= 6;
		n2 = i;

		if (data_length < 1)
			return 1;	/* error, too much data */

		*data++ = n2;
		data_length--;
	}

	while (*text != '\0') {
		i = acl_str_index(acl_hexstring, *text++);
		if (i < 0)
			return 1;	/* error, bad character */

		if (i > 15)
			i -= 6;
		n1 = i;

		if (*text == '\0')
			return 1;	/* error, odd string length */

		i = acl_str_index(acl_hexstring, *text++);
		if (i < 0)
			return 1;	/* error, bad character */

		if (i > 15)
			i -= 6;
		n2 = i;

		if (data_length < 1)
			return 1;	/* error, too much data */

		*data++ = (n1 << 4) | n2;
		data_length--;
	}

	if (data_length >= *data_lenp)
		return 1;	/* error, no data */

	*data_lenp = *data_lenp - data_length;

	return 0;		/* no error */
}

static int
acl_base64_to_data(const char *text, unsigned char *data,
		   unsigned int *data_lenp)
{
	int i;
	unsigned int n;
	unsigned int count;
	unsigned int data_length = *data_lenp;

	n = 0;
	count = 0;

	while (*text != '\0' && *text != '=') {

		i = acl_str_index(acl_base64_string, *text++);
		if (i < 0)
			return 1;	/* error, bad character */

		n = (n << 6 | (unsigned int)i);
		count++;

		if (count >= 4) {
			if (data_length < 3)
				return 1;	/* error, too much data */
			*data++ = n >> 16;
			*data++ = n >> 8;
			*data++ = n;
			data_length -= 3;
			n = 0;
			count = 0;
		}
	}

	while (*text != '\0')
		if (*text++ != '=')
			return 1;	/* error, bad pad */

	if (count == 0) {
		/* do nothing */
	} else if (count == 2) {
		if (data_length < 1)
			return 1;	/* error, too much data */
		n = n >> 4;
		*data++ = n;
		data_length--;
	} else if (count == 3) {
		if (data_length < 2)
			return 1;	/* error, too much data */
		n = n >> 2;
		*data++ = n >> 8;
		*data++ = n;
		data_length -= 2;
	} else
		return 1;	/* bad encoding */

	if (data_length >= *data_lenp)
		return 1;	/* error, no data */

	*data_lenp = *data_lenp - data_length;

	return 0;		/* no error */
}

static int
acl_text_to_data(const char *text, unsigned char *data,
		 unsigned int *data_length)
{
	int status;
	unsigned int text_length;

	status = acl_chk_string(text, 2 + 2 * AUTH_LARGE_BINARY_MAX_LEN + 1,
				&text_length);
	if (status)
		return status;

	if (text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
		/* skip prefix */
		text += 2;
		text_length -= 2;
		status = acl_hex_to_data(text, text_length, data, data_length);
	} else if (text[0] == '0' && (text[1] == 'b' || text[1] == 'B')) {
		/* skip prefix */
		text += 2;
		text_length -= 2;
		status = acl_base64_to_data(text, data, data_length);
	} else
		status = 1;	/* prefix not recognized. */

	return status;
}

static void
acl_init_key_blk(struct auth_key_block *key_blk)
{
	char *str_block = key_blk->str_block;

	memset(key_blk, 0, sizeof(*key_blk));
	key_blk->str_block = str_block;
}

static void
acl_set_key_value(struct auth_key_block *key_blk, int key_type,
		  const char *key_val)
{
	unsigned int length;
	char *string;

	if (key_blk->key[key_type].value_set) {
		key_blk->dup_set = 1;
		return;
	}

	key_blk->key[key_type].value_set = 1;

	if (!key_val)
		return;

	if (acl_chk_string(key_val, AUTH_STR_MAX_LEN, &length)) {
		key_blk->str_too_long = 1;
		return;
	}

	length += 1;

	if ((key_blk->blk_length + length) > AUTH_STR_BLOCK_MAX_LEN) {
		key_blk->too_much_data = 1;
		return;
	}

	string = &key_blk->str_block[key_blk->blk_length];

	if (strlcpy(string, key_val, length) >= length) {
		key_blk->too_much_data = 1;
		return;
	}
	key_blk->blk_length += length;

	key_blk->key[key_type].string = string;
	key_blk->key[key_type].present = 1;
}

static const char *
acl_get_key_val(struct auth_key_block *key_blk, int key_type)
{
	key_blk->key[key_type].processed = 1;

	if (!key_blk->key[key_type].present)
		return NULL;

	return key_blk->key[key_type].string;
}

static void
acl_chk_key(struct iscsi_acl *client, int key_type, int *negotiated_option,
	    unsigned int option_count, int *option_list,
	    const char *(*value_to_text) (int))
{
	const char *key_val;
	int length;
	unsigned int i;

	key_val = acl_get_key_val(&client->recv_key_block, key_type);
	if (!key_val) {
		*negotiated_option = AUTH_OPTION_NOT_PRESENT;
		return;
	}

	while (*key_val != '\0') {

		length = 0;

		while (*key_val != '\0' && *key_val != ',')
			client->scratch_key_value[length++] = *key_val++;

		if (*key_val == ',')
			key_val++;
		client->scratch_key_value[length++] = '\0';

		for (i = 0; i < option_count; i++) {
			const char *s = (*value_to_text)(option_list[i]);

			if (!s)
				continue;

			if (strcmp(client->scratch_key_value, s) == 0) {
				*negotiated_option = option_list[i];
				return;
			}
		}
	}

	*negotiated_option = AUTH_OPTION_REJECT;
}

static void
acl_set_key(struct iscsi_acl *client, int key_type, unsigned int option_count,
	    int *option_list, const char *(*value_to_text)(int))
{
	unsigned int i;

	if (option_count == 0) {
		/*
		 * No valid options to send, but we always want to
		 * send something.
		 */
		acl_set_key_value(&client->send_key_block, key_type,
				  acl_none_option_name);
		return;
	}

	if (option_count == 1 && option_list[0] == AUTH_OPTION_NOT_PRESENT) {
		acl_set_key_value(&client->send_key_block, key_type, NULL);
		return;
	}

	for (i = 0; i < option_count; i++) {
		const char *s = (*value_to_text)(option_list[i]);

		if (!s)
			continue;

		if (i == 0)
			strlcpy(client->scratch_key_value, s,
				   AUTH_STR_MAX_LEN);
		else {
			strlcat(client->scratch_key_value, ",",
				   AUTH_STR_MAX_LEN);
			strlcat(client->scratch_key_value, s,
				   AUTH_STR_MAX_LEN);
		}
	}

	acl_set_key_value(&client->send_key_block, key_type,
			  client->scratch_key_value);
}

static void
acl_chk_auth_method_key(struct iscsi_acl *client)
{
	acl_chk_key(client, AUTH_KEY_TYPE_AUTH_METHOD,
		    &client->negotiated_auth_method,
		    client->auth_method_valid_count,
		    client->auth_method_valid_list,
		    acl_authmethod_optn_to_text);
}

static void
acl_set_auth_method_key(struct iscsi_acl *client,
			unsigned int auth_method_count, int *auth_method_list)
{
	acl_set_key(client, AUTH_KEY_TYPE_AUTH_METHOD, auth_method_count,
		    auth_method_list, acl_authmethod_optn_to_text);
}

static void
acl_chk_chap_alg_key(struct iscsi_acl *client)
{
	const char *key_val;
	int length;
	unsigned long number;
	unsigned int i;

	key_val = acl_get_key_val(&client->recv_key_block,
				  AUTH_KEY_TYPE_CHAP_ALG);
	if (!key_val) {
		client->negotiated_chap_alg = AUTH_OPTION_NOT_PRESENT;
		return;
	}

	while (*key_val != '\0') {

		length = 0;

		while (*key_val != '\0' && *key_val != ',')
			client->scratch_key_value[length++] = *key_val++;

		if (*key_val == ',')
			key_val++;
		client->scratch_key_value[length++] = '\0';

		if (acl_text_to_number(client->scratch_key_value, &number))
			continue;


		for (i = 0; i < client->chap_alg_count; i++)
			if (number == (unsigned long)client->chap_alg_list[i])
			{
				client->negotiated_chap_alg = number;
				return;
			}
	}

	client->negotiated_chap_alg = AUTH_OPTION_REJECT;
}

static void
acl_set_chap_alg_key(struct iscsi_acl *client, unsigned int chap_alg_count,
		     int *chap_alg_list)
{
	unsigned int i;

	if (chap_alg_count == 0) {
		acl_set_key_value(&client->send_key_block,
				  AUTH_KEY_TYPE_CHAP_ALG, NULL);
		return;
	}

	if (chap_alg_count == 1 &&
	    chap_alg_list[0] == AUTH_OPTION_NOT_PRESENT) {
		acl_set_key_value(&client->send_key_block,
				  AUTH_KEY_TYPE_CHAP_ALG, NULL);
		return;
	}

	if (chap_alg_count == 1 && chap_alg_list[0] == AUTH_OPTION_REJECT) {
		acl_set_key_value(&client->send_key_block,
				  AUTH_KEY_TYPE_CHAP_ALG,
				  acl_reject_option_name);
		return;
	}

	for (i = 0; i < chap_alg_count; i++) {
		char s[20];

		snprintf(s, sizeof(s), "%lu",(unsigned long)chap_alg_list[i]);

		if (i == 0)
			strlcpy(client->scratch_key_value, s,
				   AUTH_STR_MAX_LEN);
		 else {
			strlcat(client->scratch_key_value, ",",
				   AUTH_STR_MAX_LEN);
			strlcat(client->scratch_key_value, s,
				   AUTH_STR_MAX_LEN);
		}
	}

	acl_set_key_value(&client->send_key_block, AUTH_KEY_TYPE_CHAP_ALG,
			  client->scratch_key_value);
}

static void
acl_next_phase(struct iscsi_acl *client)
{
	switch (client->phase) {
	case AUTH_PHASE_CONFIGURE:
		client->phase = AUTH_PHASE_NEGOTIATE;
		break;
	case AUTH_PHASE_NEGOTIATE:
		client->phase = AUTH_PHASE_AUTHENTICATE;

		if (client->negotiated_auth_method == AUTH_OPTION_REJECT ||
		    client->negotiated_auth_method == AUTH_OPTION_NOT_PRESENT ||
		    client->negotiated_auth_method == AUTH_OPTION_NONE) {

			client->local_state = AUTH_LOCAL_STATE_DONE;
			client->rmt_state = AUTH_RMT_STATE_DONE;

			if (client->auth_rmt) {
				client->rmt_auth_status = AUTH_STATUS_FAIL;
				client->phase = AUTH_PHASE_DONE;
			} else
				client->rmt_auth_status = AUTH_STATUS_PASS;

			switch (client->negotiated_auth_method) {
			case AUTH_OPTION_REJECT:
				client->dbg_status =
				    AUTH_DBG_STATUS_AUTH_METHOD_REJECT;
				break;
			case AUTH_OPTION_NOT_PRESENT:
				client->dbg_status =
				    AUTH_DBG_STATUS_AUTH_METHOD_NOT_PRESENT;
				break;
			case AUTH_OPTION_NONE:
				client->dbg_status =
				    AUTH_DBG_STATUS_AUTH_METHOD_NONE;
			}

		} else if (client->negotiated_auth_method == AUTH_METHOD_CHAP) {
			client->local_state = AUTH_LOCAL_STATE_SEND_ALG;
			client->rmt_state = AUTH_RMT_STATE_SEND_ALG;
		} else {

			client->local_state = AUTH_LOCAL_STATE_DONE;
			client->rmt_state = AUTH_RMT_STATE_DONE;
			client->rmt_auth_status = AUTH_STATUS_FAIL;
			client->dbg_status = AUTH_DBG_STATUS_AUTH_METHOD_BAD;
		}
		break;
	case AUTH_PHASE_AUTHENTICATE:
		client->phase = AUTH_PHASE_DONE;
		break;
	case AUTH_PHASE_DONE:
	case AUTH_PHASE_ERROR:
	default:
		client->phase = AUTH_PHASE_ERROR;
	}
}

static void
acl_local_auth(struct iscsi_acl *client)
{
	unsigned int chap_identifier;
	unsigned char response_data[AUTH_CHAP_RSP_LEN];
	unsigned long number;
	int status;
	enum auth_dbg_status dbg_status;
	const char *chap_identifier_key_val;
	const char *chap_challenge_key_val;

	switch (client->local_state) {
	case AUTH_LOCAL_STATE_SEND_ALG:
		if (client->node_type == TYPE_INITIATOR) {
			acl_set_chap_alg_key(client, client->chap_alg_count,
					     client->chap_alg_list);
			client->local_state = AUTH_LOCAL_STATE_RECV_ALG;
			break;
		}
		/* Fall through */
	case AUTH_LOCAL_STATE_RECV_ALG:
		acl_chk_chap_alg_key(client);

		if (client->node_type == TYPE_TARGET)
			acl_set_chap_alg_key(client, 1,
					     &client->negotiated_chap_alg);

		/* Make sure only supported CHAP algorithm is used. */
		if (client->negotiated_chap_alg == AUTH_OPTION_NOT_PRESENT) {
			client->local_state = AUTH_LOCAL_STATE_ERROR;
			client->dbg_status = AUTH_DBG_STATUS_CHAP_ALG_EXPECTED;
			break;
		} else if (client->negotiated_chap_alg == AUTH_OPTION_REJECT) {
			client->local_state = AUTH_LOCAL_STATE_ERROR;
			client->dbg_status = AUTH_DBG_STATUS_CHAP_ALG_REJECT;
			break;
		} else if (client->negotiated_chap_alg != AUTH_CHAP_ALG_MD5) {
			client->local_state = AUTH_LOCAL_STATE_ERROR;
			client->dbg_status = AUTH_DBG_STATUS_CHAP_ALG_BAD;
			break;
		}
		if (client->node_type == TYPE_TARGET) {
			client->local_state = AUTH_LOCAL_STATE_RECV_CHALLENGE;
			break;
		}
		/* Fall through */
	case AUTH_LOCAL_STATE_RECV_CHALLENGE:
		chap_identifier_key_val = acl_get_key_val(&client->recv_key_block,
							  AUTH_KEY_TYPE_CHAP_IDENTIFIER);
		chap_challenge_key_val = acl_get_key_val(&client->recv_key_block,
							 AUTH_KEY_TYPE_CHAP_CHALLENGE);
		if (client->node_type == TYPE_TARGET) {
			if (!chap_identifier_key_val &&
			    !chap_challenge_key_val) {
				client->local_state = AUTH_LOCAL_STATE_DONE;
				break;
			}
		}

		if (!chap_identifier_key_val) {
			client->local_state = AUTH_LOCAL_STATE_ERROR;
			client->dbg_status =
			    AUTH_DBG_STATUS_CHAP_IDENTIFIER_EXPECTED;
			break;
		}

		if (!chap_challenge_key_val) {
			client->local_state = AUTH_LOCAL_STATE_ERROR;
			client->dbg_status =
			    AUTH_DBG_STATUS_CHAP_CHALLENGE_EXPECTED;
			break;
		}

		status = acl_text_to_number(chap_identifier_key_val, &number);
		if (status || (255 < number)) {
			client->local_state = AUTH_LOCAL_STATE_ERROR;
			client->dbg_status = AUTH_DBG_STATUS_CHAP_IDENTIFIER_BAD;
			break;
		}
		chap_identifier = number;

		if (client->recv_chap_challenge_status) {
			client->local_state = AUTH_LOCAL_STATE_ERROR;
			client->dbg_status = AUTH_DBG_STATUS_CHALLENGE_BAD;
			break;
		}

		if (client->node_type == TYPE_TARGET &&
		    client->recv_chap_challenge.length ==
		    client->send_chap_challenge.length &&
		    memcmp(client->recv_chap_challenge.large_binary,
			   client->send_chap_challenge.large_binary,
			   client->send_chap_challenge.length) == 0) {
			client->local_state = AUTH_LOCAL_STATE_ERROR;
			client->dbg_status =
			    AUTH_DBG_STATUS_CHAP_CHALLENGE_REFLECTED;
			break;
		}

		dbg_status = acl_chap_compute_rsp(client, 0,
						  chap_identifier,
						  client->recv_chap_challenge.large_binary,
						  client->recv_chap_challenge.length,
						  response_data);

		if (dbg_status != AUTH_DBG_STATUS_NOT_SET) {
			client->local_state = AUTH_LOCAL_STATE_ERROR;
			client->dbg_status = dbg_status;
			break;
		}

		acl_data_to_text(response_data,
				 AUTH_CHAP_RSP_LEN, client->scratch_key_value,
				 AUTH_STR_MAX_LEN);
		acl_set_key_value(&client->send_key_block,
				  AUTH_KEY_TYPE_CHAP_RSP,
				  client->scratch_key_value);
		acl_set_key_value(&client->send_key_block,
				  AUTH_KEY_TYPE_CHAP_USERNAME,
				  client->username);

		client->local_state = AUTH_LOCAL_STATE_DONE;
		break;
	case AUTH_LOCAL_STATE_DONE:
		break;
	case AUTH_LOCAL_STATE_ERROR:
	default:
		client->phase = AUTH_PHASE_ERROR;
	}
}

static void
acl_rmt_auth(struct iscsi_acl *client)
{
	unsigned char id_data[1];
	unsigned char response_data[AUTH_STR_MAX_LEN];
	unsigned int rsp_len = AUTH_STR_MAX_LEN;
	unsigned char my_rsp_data[AUTH_CHAP_RSP_LEN];
	int status;
	enum auth_dbg_status dbg_status;
	const char *chap_rsp_key_val;
	const char *chap_username_key_val;

	switch (client->rmt_state) {
	case AUTH_RMT_STATE_SEND_ALG:
		if (client->node_type == TYPE_INITIATOR) {
			client->rmt_state = AUTH_RMT_STATE_SEND_CHALLENGE;
			break;
		}
		/* Fall through */
	case AUTH_RMT_STATE_SEND_CHALLENGE:
		if (!client->auth_rmt) {
			client->rmt_auth_status = AUTH_STATUS_PASS;
			client->dbg_status = AUTH_DBG_STATUS_AUTH_RMT_FALSE;
			client->rmt_state = AUTH_RMT_STATE_DONE;
			break;
		}
		get_random_bytes(id_data, 1);
		client->send_chap_identifier = id_data[0];
		snprintf(client->scratch_key_value, AUTH_STR_MAX_LEN, "%lu",
			 (unsigned long)client->send_chap_identifier);
		acl_set_key_value(&client->send_key_block,
				  AUTH_KEY_TYPE_CHAP_IDENTIFIER,
				  client->scratch_key_value);

		client->send_chap_challenge.length = client->chap_challenge_len;
		get_random_bytes(client->send_chap_challenge.large_binary,
				 client->send_chap_challenge.length);
		acl_set_key_value(&client->send_key_block,
				  AUTH_KEY_TYPE_CHAP_CHALLENGE, "");

		client->rmt_state = AUTH_RMT_STATE_RECV_RSP;
		break;
	case AUTH_RMT_STATE_RECV_RSP:
		chap_rsp_key_val = acl_get_key_val(&client->recv_key_block,
						   AUTH_KEY_TYPE_CHAP_RSP);
		chap_username_key_val = acl_get_key_val(&client->recv_key_block,
							 AUTH_KEY_TYPE_CHAP_USERNAME);

		if (!chap_rsp_key_val) {
			client->rmt_state = AUTH_RMT_STATE_ERROR;
			client->dbg_status = AUTH_DBG_STATUS_CHAP_RSP_EXPECTED;
			break;
		}

		if (!chap_username_key_val) {
			client->rmt_state = AUTH_RMT_STATE_ERROR;
			client->dbg_status = AUTH_DBG_STATUS_CHAP_USERNAME_EXPECTED;
			break;
		}

		status = acl_text_to_data(chap_rsp_key_val, response_data,
					  &rsp_len);

		if (status) {
			client->rmt_state = AUTH_RMT_STATE_ERROR;
			client->dbg_status = AUTH_DBG_STATUS_CHAP_RSP_BAD;
			break;
		}

		if (rsp_len == AUTH_CHAP_RSP_LEN) {
			dbg_status = acl_chap_compute_rsp(client, 1,
							  client->send_chap_identifier,
							  client->send_chap_challenge.large_binary,
							  client->send_chap_challenge.length,
							  my_rsp_data);

			if (dbg_status == AUTH_DBG_STATUS_NOT_SET &&
			    memcmp(my_rsp_data, response_data,
				   AUTH_CHAP_RSP_LEN) == 0) {
				client->rmt_state = AUTH_RMT_STATE_ERROR;
				client->dbg_status = AUTH_DBG_STATUS_PASSWD_IDENTICAL;
				break;
			}
		}

		strlcpy(client->chap_username, chap_username_key_val,
			AUTH_STR_MAX_LEN);

		status = acl_chap_auth_request(client, client->chap_username,
					       client->send_chap_identifier,
					       client->send_chap_challenge.
					       large_binary,
					       client->send_chap_challenge.
					       length, response_data,
					       rsp_len);

		client->rmt_auth_status = (enum auth_status) status;
		client->auth_rsp_flag = 1;

		if (client->auth_server_error_flag) {
			client->rmt_auth_status = AUTH_STATUS_FAIL;
			client->dbg_status = AUTH_DBG_STATUS_AUTH_SERVER_ERROR;
		} else if (client->rmt_auth_status == AUTH_STATUS_PASS)
			client->dbg_status = AUTH_DBG_STATUS_AUTH_PASS;
		else if (client->rmt_auth_status == AUTH_STATUS_FAIL)
			client->dbg_status = AUTH_DBG_STATUS_AUTH_FAIL;
		else {
			client->rmt_auth_status = AUTH_STATUS_FAIL;
			client->dbg_status = AUTH_DBG_STATUS_AUTH_STATUS_BAD;
		}
		client->rmt_state = AUTH_RMT_STATE_DONE;

		/* Fall through */
	case AUTH_RMT_STATE_DONE:
		break;
	case AUTH_RMT_STATE_ERROR:
	default:
		client->phase = AUTH_PHASE_ERROR;
	}
}

static void
acl_hand_shake(struct iscsi_acl *client)
{
	if (client->phase == AUTH_PHASE_DONE)

		/*
		 * Should only happen if authentication
		 * protocol error occured.
		 */
		return;

	if (client->node_type == TYPE_INITIATOR)

		/*
		 * Target should only have set T bit on response if
		 * initiator set it on previous message.
		 */
		if (client->recv_key_block.transit_bit &&
		    !client->transit_bit_sent_flag) {
			client->rmt_auth_status = AUTH_STATUS_FAIL;
			client->phase = AUTH_PHASE_DONE;
			client->dbg_status =
			    AUTH_DBG_STATUS_T_BIT_SET_ILLEGAL;
			return;
		}

	if (client->phase == AUTH_PHASE_NEGOTIATE) {
		/*
		 * Should only happen if waiting for peer
		 * to send AuthMethod key or set Transit Bit.
		 */
		if (client->node_type == TYPE_INITIATOR)
			client->send_key_block.transit_bit = 1;
		return;
	}

	if (client->rmt_state == AUTH_RMT_STATE_RECV_RSP ||
	    client->rmt_state == AUTH_RMT_STATE_DONE) {
		if (client->node_type == TYPE_INITIATOR) {
			if (client->recv_key_block.transit_bit) {
				if (client->rmt_state !=
				    AUTH_RMT_STATE_DONE)
					goto recv_transit_bit_err;
				acl_next_phase(client);
			} else
				client->send_key_block.transit_bit = 1;
		} else {
			if (client->rmt_state == AUTH_RMT_STATE_DONE &&
			    client->rmt_auth_status != AUTH_STATUS_PASS)
				/*
				 * Authentication failed, don't do T bit
				 * handshake.
				 */
				acl_next_phase(client);
			else {
				/*
				 * Target can only set T bit on response if
				 * initiator set it on current message.
				 */
				if (client->recv_key_block.transit_bit) {
					client->send_key_block.transit_bit = 1;
					acl_next_phase(client);
				}
			}
		}
	} else
		if (client->node_type == TYPE_INITIATOR)
			if (client->recv_key_block.transit_bit)
				goto recv_transit_bit_err;
	return;

 recv_transit_bit_err:
	/*
	 * Target set T bit on response but
	 * initiator was not done with authentication.
	 */
	client->rmt_auth_status = AUTH_STATUS_FAIL;
	client->phase = AUTH_PHASE_DONE;
	client->dbg_status = AUTH_DBG_STATUS_T_BIT_SET_PREMATURE;
}

static int
acl_rcv_end_status(struct iscsi_acl *client)
{
	int auth_status;
	int key_type;

	if (client->phase == AUTH_PHASE_ERROR)
		return AUTH_STATUS_ERROR;

	if (client->phase == AUTH_PHASE_DONE) {

		/* Perform sanity check against configured parameters. */
		if (client->auth_rmt && !client->auth_rsp_flag &&
		    client->rmt_auth_status == AUTH_STATUS_PASS) {
			client->rmt_auth_status = AUTH_STATUS_FAIL;
			client->dbg_status = AUTH_DBG_STATUS_AUTHPASS_NOT_VALID;
		}

		auth_status = client->rmt_auth_status;

	} else
		auth_status = AUTH_STATUS_CONTINUE;

	if (auth_status == AUTH_STATUS_CONTINUE ||
	    auth_status == AUTH_STATUS_PASS) {
		if (client->send_key_block.dup_set) {
			client->rmt_auth_status = AUTH_STATUS_FAIL;
			client->phase = AUTH_PHASE_DONE;
			client->dbg_status =
			    AUTH_DBG_STATUS_SEND_DUP_SET_KEY_VALUE;
			auth_status = AUTH_STATUS_FAIL;
		} else if (client->send_key_block.str_too_long) {
			client->rmt_auth_status = AUTH_STATUS_FAIL;
			client->phase = AUTH_PHASE_DONE;
			client->dbg_status =
			    AUTH_DBG_STATUS_SEND_STR_TOO_LONG;
			auth_status = AUTH_STATUS_FAIL;
		} else if (client->send_key_block.too_much_data) {
			client->rmt_auth_status = AUTH_STATUS_FAIL;
			client->phase = AUTH_PHASE_DONE;
			client->dbg_status =
			    AUTH_DBG_STATUS_SEND_TOO_MUCH_DATA;
			auth_status = AUTH_STATUS_FAIL;
		} else {
			/* Check that all incoming keys have been processed. */

			for (key_type = AUTH_KEY_TYPE_FIRST;
			     key_type < AUTH_KEY_TYPE_MAX_COUNT; key_type++)
				if (client->recv_key_block.key[key_type].present &&
				    !client->recv_key_block.key[key_type].
				    processed)
					break;

			if (key_type < AUTH_KEY_TYPE_MAX_COUNT) {
				client->rmt_auth_status = AUTH_STATUS_FAIL;
				client->phase = AUTH_PHASE_DONE;
				client->dbg_status =
				    AUTH_DBG_STATUS_UNEXPECTED_KEY_PRESENT;
				auth_status = AUTH_STATUS_FAIL;
			}
		}
	}

	if (auth_status != AUTH_STATUS_PASS &&
	    auth_status != AUTH_STATUS_CONTINUE) {
		int auth_method_key_present = 0;
		int chap_alg_key_present = 0;

		/*
		 * Suppress send keys on error,
		 * except for AuthMethod and CHAP_A.
		 */
		if (client->node_type == TYPE_TARGET) {
			if (acl_get_key_val(&client->send_key_block,
					    AUTH_KEY_TYPE_AUTH_METHOD))
				auth_method_key_present = 1;
			else if (acl_get_key_val(&client->send_key_block,
						 AUTH_KEY_TYPE_CHAP_ALG))
				chap_alg_key_present = 1;
		}

		acl_init_key_blk(&client->send_key_block);

		if (client->node_type == TYPE_TARGET) {
			if (auth_method_key_present &&
			    client->negotiated_auth_method ==
			    AUTH_OPTION_REJECT)
				acl_set_key_value(&client->send_key_block,
						  AUTH_KEY_TYPE_AUTH_METHOD,
						  acl_reject_option_name);
			else if (chap_alg_key_present &&
				 client->negotiated_chap_alg ==
				 AUTH_OPTION_REJECT)
				acl_set_key_value(&client->send_key_block,
						  AUTH_KEY_TYPE_CHAP_ALG,
						  acl_reject_option_name);
		}
	}
	client->recv_in_progress_flag = 0;

	return auth_status;
}

int
acl_recv_begin(struct iscsi_acl *client)
{
	if (!client || client->signature != ACL_SIGNATURE)
		return AUTH_STATUS_ERROR;

	if (client->phase == AUTH_PHASE_ERROR)
		return AUTH_STATUS_ERROR;

	if (client->phase == AUTH_PHASE_DONE) {
		client->phase = AUTH_PHASE_ERROR;
		return AUTH_STATUS_ERROR;
	}

	if (client->recv_in_progress_flag) {
		client->phase = AUTH_PHASE_ERROR;
		return AUTH_STATUS_ERROR;
	}

	client->recv_in_progress_flag = 1;

	if (client->phase == AUTH_PHASE_CONFIGURE)
		acl_next_phase(client);

	client->transit_bit_sent_flag = client->send_key_block.transit_bit;

	acl_init_key_blk(&client->recv_key_block);
	acl_init_key_blk(&client->send_key_block);

	return AUTH_STATUS_NO_ERROR;
}

int
acl_recv_end(struct iscsi_acl *client, iscsi_session_t *session_handle)
{
	int next_phase_flag = 0;

	if (!client || client->signature != ACL_SIGNATURE)
		return AUTH_STATUS_ERROR;

	if (client->phase == AUTH_PHASE_ERROR)
		return AUTH_STATUS_ERROR;

	if (!client->recv_in_progress_flag)  {
		client->phase = AUTH_PHASE_ERROR;
		return AUTH_STATUS_ERROR;
	}

	if (client->recv_end_count > AUTH_RECV_END_MAX_COUNT) {
		client->rmt_auth_status = AUTH_STATUS_FAIL;
		client->phase = AUTH_PHASE_DONE;
		client->dbg_status = AUTH_DBG_STATUS_RECV_MSG_COUNT_LIMIT;
	} else if (client->recv_key_block.dup_set) {
		client->rmt_auth_status = AUTH_STATUS_FAIL;
		client->phase = AUTH_PHASE_DONE;
		client->dbg_status = AUTH_DBG_STATUS_RECV_DUP_SET_KEY_VALUE;
	} else if (client->recv_key_block.str_too_long) {
		client->rmt_auth_status = AUTH_STATUS_FAIL;
		client->phase = AUTH_PHASE_DONE;
		client->dbg_status = AUTH_DBG_STATUS_RECV_STR_TOO_LONG;
	} else if (client->recv_key_block.too_much_data) {
		client->rmt_auth_status = AUTH_STATUS_FAIL;
		client->phase = AUTH_PHASE_DONE;
		client->dbg_status = AUTH_DBG_STATUS_RECV_TOO_MUCH_DATA;
	}

	client->recv_end_count++;
	client->session_handle = session_handle;

	switch (client->phase) {
	case AUTH_PHASE_NEGOTIATE:
		acl_chk_auth_method_key(client);
		if (client->auth_method_valid_neg_role ==
		    AUTH_NEG_ROLE_RESPONDER) {
			if (client->negotiated_auth_method ==
			    AUTH_OPTION_NOT_PRESENT) {
				if (client->auth_rmt ||
				    !client->recv_key_block.transit_bit) {
					/*
					 * No AuthMethod key from peer on
					 * first message, try moving the
					 * process along by sending the
					 * AuthMethod key.
					 */

					client->auth_method_valid_neg_role =
					    AUTH_NEG_ROLE_ORIGINATOR;
					acl_set_auth_method_key(client,
								client->auth_method_valid_count,
								client->auth_method_valid_list);
					break;
				}

				/*
				 * Special case if peer sent no AuthMethod key,
				 * but did set Transit Bit, allowing this side
				 * to do a null authentication, and compelete
				 * the iSCSI security phase without either side
				 * sending the AuthMethod key.
				 */
			} else
				/* Send response to AuthMethod key. */
				acl_set_auth_method_key(client, 1,
						        &client->negotiated_auth_method);

			if (client->node_type == TYPE_INITIATOR)
				acl_next_phase(client);
			else
				next_phase_flag = 1;
		} else {

			if (client->negotiated_auth_method ==
			    AUTH_OPTION_NOT_PRESENT) {
				client->rmt_auth_status = AUTH_STATUS_FAIL;
				client->phase = AUTH_PHASE_DONE;
				client->dbg_status =
				    AUTH_DBG_STATUS_AUTH_METHOD_EXPECTED;
				break;
			}

			acl_next_phase(client);
		}
		break;
	case AUTH_PHASE_AUTHENTICATE:
	case AUTH_PHASE_DONE:
		break;
	default:
		client->phase = AUTH_PHASE_ERROR;
		return AUTH_STATUS_ERROR;
	}

	switch (client->phase) {
	case AUTH_PHASE_NEGOTIATE:
		if (next_phase_flag)
			acl_next_phase(client);
		break;
	case AUTH_PHASE_AUTHENTICATE:
		/*
		 * Must call acl_local_auth()
		 * before acl_rmt_auth()
		 * to insure processing of the CHAP algorithm key,
		 * and to avoid leaving an in progress request to the
		 * authentication service.
		 */
		acl_local_auth(client);

		if (client->local_state != AUTH_LOCAL_STATE_ERROR)
			acl_rmt_auth(client);

		if (client->local_state == AUTH_LOCAL_STATE_ERROR ||
		    client->rmt_state == AUTH_RMT_STATE_ERROR) {

			client->rmt_auth_status = AUTH_STATUS_FAIL;
			client->phase = AUTH_PHASE_DONE;
			/* client->dbg_status should already be set. */
		}
		break;
	case AUTH_PHASE_DONE:
		break;
	default:
		client->phase = AUTH_PHASE_ERROR;
		return AUTH_STATUS_ERROR;
	}

	acl_hand_shake(client);

	return acl_rcv_end_status(client);
}

const char *
acl_get_key_name(int key_type)
{
	/*
	 * Note: The ordering of this table must match the order
	 *       defined by enum auth_key_type in iscsi-auth-client.h.
	 */
	static char *const key_names[AUTH_KEY_TYPE_MAX_COUNT] = {
		"AuthMethod",
		"CHAP_A",
		"CHAP_N",
		"CHAP_R",
		"CHAP_I",
		"CHAP_C"
	};

	if (key_type < AUTH_KEY_TYPE_FIRST || key_type > AUTH_KEY_TYPE_LAST)
		return NULL;

	return key_names[key_type];
}

int
acl_get_next_key_type(int *key_type)
{
	if (*key_type >= AUTH_KEY_TYPE_LAST)
		return AUTH_STATUS_ERROR;

	if (*key_type < AUTH_KEY_TYPE_FIRST)
		*key_type = AUTH_KEY_TYPE_FIRST;
	else
		(*key_type)++;

	return AUTH_STATUS_NO_ERROR;
}

int
acl_recv_key_value(struct iscsi_acl *client, int key_type,
		   const char *user_key_val)
{
	if (!client || client->signature != ACL_SIGNATURE)
		return AUTH_STATUS_ERROR;

	if (client->phase != AUTH_PHASE_NEGOTIATE &&
	    client->phase != AUTH_PHASE_AUTHENTICATE) {
		client->phase = AUTH_PHASE_ERROR;
		return AUTH_STATUS_ERROR;
	}

	if (key_type < AUTH_KEY_TYPE_FIRST || key_type > AUTH_KEY_TYPE_LAST) {
		client->phase = AUTH_PHASE_ERROR;
		return AUTH_STATUS_ERROR;
	}

	if (key_type == AUTH_KEY_TYPE_CHAP_CHALLENGE) {
		client->recv_chap_challenge.length =
		    AUTH_LARGE_BINARY_MAX_LEN;
		client->recv_chap_challenge_status =
		    acl_text_to_data(user_key_val,
				     client->recv_chap_challenge.large_binary,
				     &client->recv_chap_challenge.length);
		user_key_val = "";
	}

	acl_set_key_value(&client->recv_key_block, key_type, user_key_val);

	return AUTH_STATUS_NO_ERROR;
}

int
acl_send_key_val(struct iscsi_acl *client, int key_type, int *key_present,
		 char *user_key_val, unsigned int max_length)
{
	const char *key_val;

	if (!client || client->signature != ACL_SIGNATURE)
		return AUTH_STATUS_ERROR;

	if (client->phase != AUTH_PHASE_CONFIGURE &&
	    client->phase != AUTH_PHASE_NEGOTIATE &&
	    client->phase != AUTH_PHASE_AUTHENTICATE &&
	    client->phase != AUTH_PHASE_DONE) {
		client->phase = AUTH_PHASE_ERROR;
		return AUTH_STATUS_ERROR;
	}

	if (key_type < AUTH_KEY_TYPE_FIRST || key_type > AUTH_KEY_TYPE_LAST) {
		client->phase = AUTH_PHASE_ERROR;
		return AUTH_STATUS_ERROR;
	}

	key_val = acl_get_key_val(&client->send_key_block, key_type);
	if (key_val) {
		if (key_type == AUTH_KEY_TYPE_CHAP_CHALLENGE) {
			if (acl_data_to_text(client->send_chap_challenge.large_binary,
					     client->send_chap_challenge.length, user_key_val,
					     max_length)) {
				client->phase = AUTH_PHASE_ERROR;
				return AUTH_STATUS_ERROR;
			}
		} else if (strlcpy(user_key_val, key_val, max_length) >=
			   max_length) {
				client->phase = AUTH_PHASE_ERROR;
				return AUTH_STATUS_ERROR;
			}
		*key_present = 1;
	} else
		*key_present = 0;

	return AUTH_STATUS_NO_ERROR;
}

int
acl_recv_transit_bit(struct iscsi_acl *client, int value)
{
	if (!client || client->signature != ACL_SIGNATURE)
		return AUTH_STATUS_ERROR;

	if (client->phase != AUTH_PHASE_NEGOTIATE &&
	    client->phase != AUTH_PHASE_AUTHENTICATE) {

		client->phase = AUTH_PHASE_ERROR;
		return AUTH_STATUS_ERROR;
	}

	if (value)
		client->recv_key_block.transit_bit = 1;
	else
		client->recv_key_block.transit_bit = 0;

	return AUTH_STATUS_NO_ERROR;
}

int
acl_send_transit_bit(struct iscsi_acl *client, int *value)
{
	if (!client || client->signature != ACL_SIGNATURE)
		return AUTH_STATUS_ERROR;

	if (client->phase != AUTH_PHASE_CONFIGURE &&
	    client->phase != AUTH_PHASE_NEGOTIATE &&
	    client->phase != AUTH_PHASE_AUTHENTICATE &&
	    client->phase != AUTH_PHASE_DONE) {

		client->phase = AUTH_PHASE_ERROR;
		return AUTH_STATUS_ERROR;
	}

	*value = client->send_key_block.transit_bit;

	return AUTH_STATUS_NO_ERROR;
}

static int
acl_set_option_list(struct iscsi_acl *client, unsigned int opt_count,
		    const int *opt_list, unsigned int *clnt_optn_count,
		    int *clnt_optn_list, unsigned int optn_max_count,
		    int (*chk_option)(int),
		    int (*chk_list)(unsigned int opt_count, const int *opt_list))
{
	unsigned int i, j;

	if (!client || client->signature != ACL_SIGNATURE)
		return AUTH_STATUS_ERROR;

	if (client->phase != AUTH_PHASE_CONFIGURE ||
	    opt_count > optn_max_count) {
		client->phase = AUTH_PHASE_ERROR;
		return AUTH_STATUS_ERROR;
	}

	for (i = 0; i < opt_count; i++)
		if (chk_option(opt_list[i])) {
			client->phase = AUTH_PHASE_ERROR;
			return AUTH_STATUS_ERROR;
		}

	/* Check for duplicate entries. */
	for (i = 0; i < opt_count; i++)
		for (j = 0; j < opt_count; j++) {
			if (j == i)
				continue;
			if (opt_list[i] == opt_list[j]) {
				client->phase = AUTH_PHASE_ERROR;
				return AUTH_STATUS_ERROR;
			}
		}

	/* Check for key specific constraints. */
	if (chk_list)
		if (chk_list(opt_count, opt_list)) {
			client->phase = AUTH_PHASE_ERROR;
			return AUTH_STATUS_ERROR;
		}

	for (i = 0; i < opt_count; i++)
		clnt_optn_list[i] = opt_list[i];

	*clnt_optn_count = opt_count;

	return AUTH_STATUS_NO_ERROR;
}

static int
acl_chk_auth_method_list(unsigned int option_count, const int *option_list)
{
	unsigned int i;

	if (!option_list || option_count < 2)
		return 1;

	if (option_list[option_count - 1] != AUTH_OPTION_NONE)
		return 1;

	for (i = 0; i < (option_count - 1); i++)
		if (option_list[i] != AUTH_OPTION_NONE)
			return 0;

	return 0;
}

static void
acl_set_auth_method_valid(struct iscsi_acl *client)
{
	unsigned int i, j = 0;
	int option = 0;

	/*
	 * Following checks may need to be revised if
	 * authentication options other than CHAP and none
	 * are supported.
	 */
	if (client->node_type == TYPE_INITIATOR) {
		if (client->auth_rmt)
			/*
			 * If initiator doing authentication,
			 * don't offer authentication option none.
			 */
			option = 1;
		else if (!client->passwd_present)
			/*
			 * If initiator password not set,
			 * only offer authentication option none.
			 */
			option = 2;
	}

	if (client->node_type == TYPE_TARGET) {
		if (client->auth_rmt)
			/*
			 * If target doing authentication,
			 * don't accept authentication option none.
			 */
			option = 1;
		else
			/*
			 * If target not doing authentication,
			 * only accept authentication option none.
			 */
			option = 2;
	}

	for (i = 0; i < client->auth_method_count; i++) {
		if (option == 1) {
			if (client->auth_method_list[i] == AUTH_OPTION_NONE)
				continue;
		} else if (option == 2)
			if (client->auth_method_list[i] != AUTH_OPTION_NONE)
				continue;
		client->auth_method_valid_list[j++] = client->auth_method_list[i];
	}

	client->auth_method_valid_count = j;

	acl_init_key_blk(&client->send_key_block);

	if (client->node_type == TYPE_INITIATOR) {
		if (client->auth_rmt) {
			/*
			 * Initiator wants to authenticate target,
			 * always send AuthMethod key.
			 */
			client->send_key_block.transit_bit = 0;
			client->auth_method_valid_neg_role =
			    AUTH_NEG_ROLE_ORIGINATOR;
		} else {
			client->send_key_block.transit_bit = 1;
			client->auth_method_valid_neg_role =
			    client->auth_method_neg_role;
		}
	} else {
		client->send_key_block.transit_bit = 0;
		client->auth_method_valid_neg_role = AUTH_NEG_ROLE_RESPONDER;
	}

	if (client->auth_method_valid_neg_role == AUTH_NEG_ROLE_ORIGINATOR)
		acl_set_auth_method_key(client, client->auth_method_valid_count,
				        client->auth_method_valid_list);
	else {
		int value = AUTH_OPTION_NOT_PRESENT;
		acl_set_auth_method_key(client, 1, &value);
	}
}

static int
acl_set_auth_method_list(struct iscsi_acl *client, unsigned int option_count,
			 const int *option_list)
{
	int status;

	status = acl_set_option_list(client, option_count, option_list,
				     &client->auth_method_count,
				     client->auth_method_list,
				     AUTH_METHOD_MAX_COUNT,
				     acl_chk_auth_mthd_optn,
				     acl_chk_auth_method_list);

	if (status != AUTH_STATUS_NO_ERROR)
		return status;

	/* Setting authMethod affects auth_method_valid. */
	acl_set_auth_method_valid(client);

	return AUTH_STATUS_NO_ERROR;
}

static int
acl_chk_chap_alg_list(unsigned int option_count, const int *option_list)
{
	if (!option_list || option_count < 1)
		return 1;

	return 0;
}

static int
acl_set_chap_alg_list(struct iscsi_acl *client, unsigned int option_count,
		      const int *option_list)
{
	return acl_set_option_list(client, option_count, option_list,
				   &client->chap_alg_count,
				   client->chap_alg_list,
				   AUTH_CHAP_ALG_MAX_COUNT,
				   acl_chk_chap_alg_optn,
				   acl_chk_chap_alg_list);
}

int
acl_init(int node_type, int buf_desc_count, struct auth_buffer_desc *buff_desc)
{
	struct iscsi_acl *client;
	struct auth_str_block *recv_str_blk;
	struct auth_str_block *send_str_blk;
	struct auth_large_binary *recv_chap_challenge;
	struct auth_large_binary *send_chap_challenge;
	int value_list[2];

	if (buf_desc_count != 5 || !buff_desc)
		return AUTH_STATUS_ERROR;

	if (!buff_desc[0].address ||
	    buff_desc[0].length != sizeof(*client))
		return AUTH_STATUS_ERROR;
	client = (struct iscsi_acl *)buff_desc[0].address;

	if (!buff_desc[1].address ||
	    buff_desc[1].length != sizeof(*recv_str_blk))
		return AUTH_STATUS_ERROR;
	recv_str_blk = (struct auth_str_block *)buff_desc[1].address;

	if (!buff_desc[2].address ||
	    buff_desc[2].length != sizeof(*send_str_blk))
		return AUTH_STATUS_ERROR;

	send_str_blk = (struct auth_str_block *)buff_desc[2].address;

	if (!buff_desc[3].address ||
	    buff_desc[3].length != sizeof(*recv_chap_challenge))
		return AUTH_STATUS_ERROR;

	recv_chap_challenge = (struct auth_large_binary *)
			     buff_desc[3].address;

	if (!buff_desc[4].address ||
	    buff_desc[4].length != sizeof(*send_chap_challenge))
		return AUTH_STATUS_ERROR;
	send_chap_challenge = (struct auth_large_binary *)
			    buff_desc[4].address;
	memset(client, 0, sizeof(*client));
	memset(recv_str_blk, 0, sizeof(*recv_str_blk));
	memset(send_str_blk, 0, sizeof(*send_str_blk));
	memset(recv_chap_challenge, 0, sizeof(*recv_chap_challenge));
	memset(send_chap_challenge, 0, sizeof(*send_chap_challenge));

	client->recv_key_block.str_block = recv_str_blk->str_block;
	client->send_key_block.str_block = send_str_blk->str_block;
	client->recv_chap_challenge.large_binary = recv_chap_challenge->large_binary;
	client->send_chap_challenge.large_binary = send_chap_challenge->large_binary;

	if (node_type != TYPE_INITIATOR  && node_type != TYPE_TARGET) {
		client->phase = AUTH_PHASE_ERROR;
		return AUTH_STATUS_ERROR;
	}

	client->signature = ACL_SIGNATURE;
	client->node_type = (enum auth_node_type) node_type;
	client->auth_rmt = 1;
	client->passwd_present = 0;
	client->chap_challenge_len = AUTH_CHAP_RSP_LEN;
	client->ip_sec = 0;

	client->phase = AUTH_PHASE_CONFIGURE;
	client->negotiated_auth_method = AUTH_OPTION_NOT_PRESENT;
	client->negotiated_chap_alg = AUTH_OPTION_NOT_PRESENT;

	if (client->node_type == TYPE_INITIATOR)
		client->auth_method_neg_role = AUTH_NEG_ROLE_ORIGINATOR;
	else
		/* Initial value ignored for Target. */
		client->auth_method_neg_role = AUTH_NEG_ROLE_RESPONDER;

	value_list[0] = AUTH_METHOD_CHAP;
	value_list[1] = AUTH_OPTION_NONE;

	/*
	 * Must call after setting auth_rmt, password,
	 * and auth_method_neg_role
	 */
	if (acl_set_auth_method_list(client, 2, value_list) !=
	    AUTH_STATUS_NO_ERROR) {
		client->phase = AUTH_PHASE_ERROR;
		return AUTH_STATUS_ERROR;
	}

	value_list[0] = AUTH_CHAP_ALG_MD5;

	if (acl_set_chap_alg_list(client, 1, value_list) !=
	    AUTH_STATUS_NO_ERROR) {
		client->phase = AUTH_PHASE_ERROR;
		return AUTH_STATUS_ERROR;
	}

	return AUTH_STATUS_NO_ERROR;
}

int
acl_finish(struct iscsi_acl *client)
{
	if (!client || client->signature != ACL_SIGNATURE)
		return AUTH_STATUS_ERROR;

	memset(client, 0, sizeof(*client));

	return AUTH_STATUS_NO_ERROR;
}

int
acl_set_user_name(struct iscsi_acl *client, const char *username)
{
	if (!client || client->signature != ACL_SIGNATURE)
		return AUTH_STATUS_ERROR;

	if (client->phase != AUTH_PHASE_CONFIGURE ||
	    acl_chk_string(username, AUTH_STR_MAX_LEN, NULL)) {
		client->phase = AUTH_PHASE_ERROR;
		return AUTH_STATUS_ERROR;
	}

	if (!username)
		client->username[0] = '\0';
	else if (strlcpy(client->username, username, AUTH_STR_MAX_LEN) >=
		 AUTH_STR_MAX_LEN) {
		client->phase = AUTH_PHASE_ERROR;
		return AUTH_STATUS_ERROR;
	}

	return AUTH_STATUS_NO_ERROR;
}

int
acl_set_passwd(struct iscsi_acl *client, const unsigned char *passwd_data,
	       unsigned int passwd_length)
{
	if (!client || client->signature != ACL_SIGNATURE)
		return AUTH_STATUS_ERROR;

	if (client->phase != AUTH_PHASE_CONFIGURE ||
	    passwd_length > AUTH_STR_MAX_LEN) {
		client->phase = AUTH_PHASE_ERROR;
		return AUTH_STATUS_ERROR;
	}

	memcpy(client->passwd_data, passwd_data, passwd_length);
	client->passwd_length = passwd_length;
	client->passwd_present = 1;

	/* Setting password may affect auth_method_valid. */
	acl_set_auth_method_valid(client);

	return AUTH_STATUS_NO_ERROR;
}

int
acl_set_auth_rmt(struct iscsi_acl *client, int auth_rmt)
{
	if (!client || client->signature != ACL_SIGNATURE)
		return AUTH_STATUS_ERROR;

	if (client->phase != AUTH_PHASE_CONFIGURE) {
		client->phase = AUTH_PHASE_ERROR;
		return AUTH_STATUS_ERROR;
	}

	client->auth_rmt = auth_rmt;

	/* Setting auth_rmt may affect auth_method_valid. */
	acl_set_auth_method_valid(client);

	return AUTH_STATUS_NO_ERROR;
}

int
acl_set_ip_sec(struct iscsi_acl *client, int ip_sec)
{
	if (!client || client->signature != ACL_SIGNATURE)
		return AUTH_STATUS_ERROR;

	if (client->phase != AUTH_PHASE_CONFIGURE) {
		client->phase = AUTH_PHASE_ERROR;
		return AUTH_STATUS_ERROR;
	}

	client->ip_sec = ip_sec;

	return AUTH_STATUS_NO_ERROR;
}

int
acl_get_dbg_status(struct iscsi_acl *client, int *value)
{
	if (!client || client->signature != ACL_SIGNATURE)
		return AUTH_STATUS_ERROR;

	if (client->phase != AUTH_PHASE_DONE) {
		client->phase = AUTH_PHASE_ERROR;
		return AUTH_STATUS_ERROR;
	}

	*value = client->dbg_status;

	return AUTH_STATUS_NO_ERROR;
}

const char *
acl_dbg_status_to_text(int dbg_status)
{
	/*
	 * Note: The ordering of this table must match the order
	 *       defined by enum auth_dbg_status in iscsi-auth-client.h.
	 */
	static char *const dbg_text[AUTH_DBG_STATUS_MAX_COUNT] = {
		"Debug status not set",
		"Authentication request passed",
		"Authentication not enabled",
		"Authentication request failed",
		"AuthMethod bad",
		"CHAP algorithm bad",
		"Decrypt password failed",
		"Local password too short with no IPSec",
		"Unexpected error from authentication server",
		"Authentication request status bad",
		"Authentication pass status not valid",
		"Same key set more than once on send",
		"Key value too long on send",
		"Too much data on send",
		"AuthMethod key expected",
		"CHAP algorithm key expected",
		"CHAP identifier expected",
		"CHAP challenge expected",
		"CHAP response expected",
		"CHAP username expected",
		"AuthMethod key not present",
		"AuthMethod negotiation failed",
		"AuthMethod negotiated to none",
		"CHAP algorithm negotiation failed",
		"CHAP challange reflected",
		"Local password same as remote",
		"Local password not set",
		"CHAP identifier bad",
		"CHAP challenge bad",
		"CHAP response bad",
		"Unexpected key present",
		"T bit set on response, but not on previous message",
		"T bit set on response, but authenticaton not complete",
		"Message count limit reached on receive",
		"Same key set more than once on receive",
		"Key value too long on receive",
		"Too much data on receive"
	};

	if (dbg_status < 0 || dbg_status >= AUTH_DBG_STATUS_MAX_COUNT)
		return "Unknown error";

	return dbg_text[dbg_status];
}

int
acl_data(unsigned char *out_data, unsigned int *out_length,
         unsigned char *in_data, unsigned int in_length)
{
	if (*out_length < in_length)
		return 1;       /* error */

	memcpy(out_data, in_data, in_length);
	*out_length = in_length;

	return 0;               /* no error */
}

