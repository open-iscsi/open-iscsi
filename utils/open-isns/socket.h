/*
 * iSNS network code
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#ifndef ISNS_SOCKET_H
#define ISNS_SOCKET_H

#include "isns.h"
#include "buffer.h"
#include "message.h"

struct isns_partial_msg {
	isns_message_t		imp_base;
	uint32_t		imp_flags;
	uint32_t		imp_first_seq;
	uint32_t		imp_last_seq;
	unsigned int		imp_pdu_count;
	unsigned int		imp_msg_size;
	buf_t *			imp_chain;

	struct ucred		imp_credbuf;
};

#define imp_users		imp_base.im_users
#define imp_list		imp_base.im_list
#define imp_xid			imp_base.im_xid
#define imp_header		imp_base.im_header
#define imp_addr		imp_base.im_addr
#define imp_addrlen		imp_base.im_addrlen
#define imp_header		imp_base.im_header
#define imp_payload		imp_base.im_payload
#define imp_security		imp_base.im_security
#define imp_creds		imp_base.im_creds

enum {
	ISNS_SOCK_LISTENING,
	ISNS_SOCK_CONNECTING,
	ISNS_SOCK_IDLE,
	ISNS_SOCK_FAILED,
	ISNS_SOCK_DISCONNECTED,
	ISNS_SOCK_DEAD,
};

/* Helper class */
struct __isns_socket_addr {
	struct sockaddr_storage	addr;
	socklen_t		addrlen;
	struct addrinfo *	list;
};

struct isns_socket {
	isns_list_t		is_list;
	int			is_desc;
	int			is_type;
	unsigned int		is_client : 1,
				is_autoclose : 1,
				is_disconnect_fatal : 1,
				is_report_failure : 1,
				is_destroy : 1;
	unsigned int		is_users;
	int			is_poll_mask;
	int			is_state;

	isns_security_t *	is_security;

	struct __isns_socket_addr is_src, is_dst;

	unsigned int		is_retrans_timeout;

	/* If we're past this time, is_timeout() is called. */
	struct timeval		is_deadline;

	buf_t *			is_recv_buf;
	buf_t *			is_xmit_buf;

	size_t			is_queue_size;
	isns_message_queue_t	is_partial;
	isns_message_queue_t	is_complete;
	isns_message_queue_t	is_pending;

	void			(*is_poll_in)(isns_socket_t *);
	void			(*is_poll_out)(isns_socket_t *);
	void			(*is_poll_hup)(isns_socket_t *);
	void			(*is_poll_err)(isns_socket_t *);
	void			(*is_timeout)(isns_socket_t *);
	void			(*is_error)(isns_socket_t *, int);
};

extern int			isns_socket_submit(isns_socket_t *,
					isns_message_t *,
					long);

#endif /* ISNS_SOCKET_H */
