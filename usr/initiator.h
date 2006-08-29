/*
 * iSCSI Initiator
 *
 * Copyright (C) 2004 Dmitry Yusupov, Alex Aizman
 * maintained by open-iscsi@googlegroups.com
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

#include "types.h"
#include "iscsi_proto.h"
#include "iscsi_if.h"
#include "auth.h"
#include "mgmt_ipc.h"
#include "config.h"
#include "actor.h"
#include "queue.h"

#define ST_CONFIG_DIR		"/etc/iscsi/send_targets"
#define NODE_CONFIG_DIR		"/etc/iscsi/nodes"
#define CONFIG_FILE		"/etc/iscsi/iscsid.conf"
#define PID_FILE		"/etc/iscsi/iscsid.pid"
#define INITIATOR_NAME_FILE	"/etc/iscsi/initiatorname.iscsi"
#define LOCK_FILE		"/etc/iscsi/lock"
#define LOCK_WRITE_FILE		"/etc/iscsi/lock.write"

#define DEF_ISCSI_PORT		3260

typedef enum conn_login_status_e {
	CONN_LOGIN_SUCCESS		= 0,
	CONN_LOGIN_FAILED		= 1,
	CONN_LOGIN_IO_ERR		= 2,
	CONN_LOGIN_RETRY		= 3,
	CONN_LOGIN_IMM_RETRY		= 4,
	CONN_LOGIN_IMM_REDIRECT_RETRY	= 5,
} conn_login_status_e;

enum iscsi_login_status {
	LOGIN_OK			= 0,
	LOGIN_IO_ERROR			= 1,
	LOGIN_FAILED			= 2,
	LOGIN_VERSION_MISMATCH		= 3,
	LOGIN_NEGOTIATION_FAILED	= 4,
	LOGIN_AUTHENTICATION_FAILED	= 5,
	LOGIN_WRONG_PORTAL_GROUP	= 6,
	LOGIN_REDIRECTION_FAILED	= 7,
	LOGIN_INVALID_PDU		= 8,
	LOGIN_REDIRECT			= 9,
};

typedef enum iscsi_conn_state_e {
	STATE_FREE			= 0,
	STATE_XPT_WAIT			= 1,
	STATE_IN_LOGIN			= 2,
	STATE_LOGGED_IN			= 3,
	STATE_IN_LOGOUT			= 4,
	STATE_LOGOUT_REQUESTED		= 5,
	STATE_CLEANUP_WAIT		= 6,
} iscsi_conn_state_e;

typedef enum iscsi_session_r_stage_e {
	R_STAGE_NO_CHANGE		= 0,
	R_STAGE_SESSION_CLEANUP		= 1,
	R_STAGE_SESSION_REOPEN		= 2,
	R_STAGE_SESSION_REDIRECT	= 3,
} iscsi_session_r_stage_e;

typedef enum iscsi_event_e {
	EV_UNKNOWN			= 0,
	EV_CONN_RECV_PDU		= 1,
	EV_CONN_POLL			= 2,
	EV_CONN_TIMER			= 3,
	EV_CONN_ERROR			= 4,
} iscsi_event_e;

typedef struct iscsi_event {
	queue_item_t item;
	char payload[EVENT_PAYLOAD_MAX];
} iscsi_event_t;

struct queue_task;

typedef struct iscsi_login_context {
	int cid;
	char *buffer;
	size_t bufsize;
	uint8_t status_class;
	uint8_t status_detail;
	struct iscsi_acl *auth_client;
	struct iscsi_hdr pdu;
	struct iscsi_login_rsp *login_rsp;
	char *data;
	int received_pdu;
	int max_data_length;
	int timeout;
	int final;
	enum iscsi_login_status ret;
	struct queue_task *qtask;
} iscsi_login_context_t;

struct iscsi_session;
struct iscsi_conn;

typedef void (*send_pdu_begin_f) (uint64_t transport_handle, uint32_t sid,
                                  uint32_t cid, int hdr_size, int data_size);
typedef int (*send_pdu_end_f) (uint64_t transport_handle, uint32_t sid,
			       uint32_t cid, int *retcode);
typedef int (*recv_pdu_begin_f) (uint64_t transport_handle, 
				 uintptr_t recv_handle, uintptr_t *pdu_handle,
				 int *pdu_size);
typedef int (*recv_pdu_end_f) (uint64_t transport_handle, uintptr_t conn_handle,
                             uintptr_t pdu_handle);
typedef void (*send_pdu_timer_add_f)(struct iscsi_conn *conn, int timeout);
typedef void (*send_pdu_timer_remove_f)(struct iscsi_conn *conn);

/* daemon's connection structure */
typedef struct iscsi_conn {
	struct qelem item; /* must stay at the top */
	uint32_t id;
	uintptr_t recv_handle;
	struct iscsi_session *session;
	iscsi_login_context_t login_context;
	char data[DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH];
	char host[NI_MAXHOST];	/* scratch */
	iscsi_conn_state_e state;
	actor_t connect_timer;
	actor_t send_pdu_timer;

	actor_t noop_out_timer;
	actor_t noop_out_timeout_timer;

	int send_pdu_in_progress;

	int kernel_io;
	send_pdu_begin_f send_pdu_begin;
	send_pdu_end_f send_pdu_end;
	recv_pdu_begin_f recv_pdu_begin;
	recv_pdu_end_f recv_pdu_end;
	send_pdu_timer_add_f send_pdu_timer_add;
	send_pdu_timer_remove_f send_pdu_timer_remove;

#define RECVPOOL_MAX	32
	void* recvpool[RECVPOOL_MAX];

	/* login state machine */
	int current_stage;
	int next_stage;
	int partial_response;
	conn_login_status_e status;

	/* tcp/socket settings */
	int socket_fd;
	/* address being used for normal session connection */
	struct sockaddr_storage saddr;
	/* address recieved during login */
	struct sockaddr_storage failback_saddr;
	int tcp_window_size;
	int type_of_service;

	/* used for the IPC of bind and for connect/poll/disconnect by
         * transports (eg iser) which does these ops from the kernel.
         * In the case of TCP, it is just the transport_fd casted to u64. */
	uint64_t transport_ep_handle;

	/* timeouts */
	int login_timeout;
	int auth_timeout;
	int active_timeout;
	int idle_timeout;
	int ping_timeout;

	int noop_out_interval;
	int noop_out_timeout;

	/* sequencing */
	uint32_t exp_statsn;

	/* negotiated parameters */
	uint32_t hdrdgst_en;
	uint32_t datadgst_en;
	uint32_t max_recv_dlength;	/* the value we declare */
	uint32_t max_xmit_dlength;	/* the value declared by the target */
} iscsi_conn_t;

typedef struct queue_task {
	iscsi_conn_t *conn;
	union {
		/* iSCSI requests originated via IPC */
		struct ipcreq_login {
			iscsiadm_req_t req;
			iscsiadm_rsp_t rsp;
			int mgmt_ipc_fd;
		} login;
		struct ipcreq_logout {
			iscsiadm_req_t req;
			iscsiadm_rsp_t rsp;
			int mgmt_ipc_fd;
		} logout;
		/* iSCSI requests originated via CTL */
		struct ctlreq_recv_pdu {
		} recv_pdu;
	} u;
} queue_task_t;

typedef enum iscsi_provider_status_e {
	PROVIDER_STATUS_UNKNOWN		= 0,
	PROVIDER_STATUS_OPERATIONAL	= 1,
	PROVIDER_STATUS_FAILED		= 2,
} iscsi_provider_status_e;

struct iscsi_uspace_transport;

/* represents data path provider */
typedef struct iscsi_provider_t {
	uint64_t handle;
	uint32_t caps;
	iscsi_provider_status_e status;
	char name[ISCSI_TRANSPORT_NAME_MAXLEN];
	struct qelem sessions;
	struct iscsi_uspace_transport *utransport;
} iscsi_provider_t;

/* daemon's session structure */
typedef struct iscsi_session {
	struct qelem item; /* must stay at the top */
	uint32_t id;
	uint32_t hostno;
	int refcount;
	uint64_t transport_handle;
	iscsi_provider_t *provider;
	node_rec_t nrec; /* copy of original Node record in database */
	unsigned int irrelevant_keys_bitmap;
	int send_async_text;
	uint32_t itt;
	uint32_t cmdsn;
	uint32_t exp_cmdsn;
	uint32_t max_cmdsn;
	int erl;
	uint32_t imm_data_en;
	uint32_t initial_r2t_en;
	uint32_t first_burst;
	uint32_t max_burst;
	uint32_t pdu_inorder_en;
	uint32_t dataseq_inorder_en;
	uint32_t def_time2wait;
	uint32_t def_time2retain;
	int type;
	int portal_group_tag;
	uint8_t isid[6];
	uint16_t tsih;
	int channel;
	int target_id;
	char target_name[TARGET_NAME_MAXLEN + 1];
	char *target_alias;
	char *initiator_name;
	char *initiator_alias;
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
	int password_in_length;
	iscsi_conn_t conn[ISCSI_CONN_MAX];
	int ctrl_fd;
	uint32_t param_mask;

	/* connection reopens during recovery */
	int reopen_cnt;
	queue_task_t reopen_qtask;
	iscsi_session_r_stage_e r_stage;
	uint32_t replacement_timeout;

	/* session's processing */
	actor_t mainloop;
	queue_t *queue;
	queue_t *splice_queue;

} iscsi_session_t;

/* iscsid.c */
extern iscsi_provider_t *provider;
extern int num_providers;

/* login.c */

#define ISCSI_SESSION_TYPE_NORMAL 0
#define ISCSI_SESSION_TYPE_DISCOVERY 1

/* not defined by iSCSI, but used in the login code to determine
 * when to send the initial Login PDU
 */
#define ISCSI_INITIAL_LOGIN_STAGE -1

#define ISCSI_TEXT_SEPARATOR     '='

/* implemented in iscsi-login.c for use on all platforms */
extern int iscsi_add_text(struct iscsi_hdr *hdr, char *data, int max_data_length,
			char *param, char *value);
extern enum iscsi_login_status iscsi_login(iscsi_session_t *session, int cid,
		   char *buffer, size_t bufsize, uint8_t * status_class,
		   uint8_t * status_detail);
extern int iscsi_update_address(iscsi_conn_t *conn, char *address);
extern int iscsi_login_begin(iscsi_session_t *session,
			     iscsi_login_context_t *c);
extern int iscsi_login_req(iscsi_session_t *session, iscsi_login_context_t *c);
extern int iscsi_login_rsp(iscsi_session_t *session, iscsi_login_context_t *c);
extern int resolve_address(char *host, char *port, struct sockaddr_storage *ss);

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


/*
 * These user/kernel IPC calls are used by transports (eg iSER) that have their
 * native connection managed from the kernel. The IPC for having the user space
 * code being able to do it, is implemented as an enhancement of the open iscsi
 * netlink IPC scheme, currently with the ability to connect/poll-for-establish
 * ment/disconnect an opaque transport dependent 64 bit ep (endpoint) handle.
 * The exact IPC ABI for that matter is defined in iscsi_if.h
 */
/* netlink.c */
extern int ktransport_ep_connect(iscsi_conn_t *conn, int non_blocking);
extern int ktransport_ep_poll(iscsi_conn_t *conn, int timeout_ms);
extern void ktransport_ep_disconnect(iscsi_conn_t *conn);

/* io.c */
extern int iscsi_io_tcp_poll(iscsi_conn_t *conn, int timeout_ms);
extern int iscsi_io_tcp_connect(iscsi_conn_t *conn, int non_blocking);
extern void iscsi_io_tcp_disconnect(iscsi_conn_t *conn);

extern int iscsi_io_connect(iscsi_conn_t *conn);
extern void iscsi_io_disconnect(iscsi_conn_t *conn);
extern int iscsi_io_send_pdu(iscsi_conn_t *conn, struct iscsi_hdr *hdr,
	       int hdr_digest, char *data, int data_digest, int timeout);
extern int iscsi_io_recv_pdu(iscsi_conn_t *conn, struct iscsi_hdr *hdr,
	int hdr_digest, char *data, int max_data_length, int data_digest,
	int timeout);

/* initiator.c */
extern int session_login_task(node_rec_t *rec, queue_task_t *qtask);
extern int session_logout_task(iscsi_session_t *session, queue_task_t *qtask);
extern iscsi_session_t *session_find_by_rec(node_rec_t *rec);
extern int session_is_running(node_rec_t *rec);
extern void* recvpool_get(iscsi_conn_t *conn, int ev_size);
extern void recvpool_put(iscsi_conn_t *conn, void *handle);
extern mgmt_ipc_err_e iscsi_sync_session(node_rec_t *rec, queue_task_t
					 *tsk, uint32_t sid);

extern char sysfs_file[];

#endif /* INITIATOR_H */
