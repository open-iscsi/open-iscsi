/*
 * Socket handling code
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/time.h>
#include <sys/un.h>
#include <string.h>
#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <fcntl.h>

#include "buffer.h"
#include "isns.h"
#include "socket.h"
#include "security.h"
#include "util.h"
#include "config.h"

#define SOCK_DEBUG_VERBOSE	0

#ifndef AI_ADDRCONFIG
# define AI_ADDRCONFIG		0
#endif
#ifndef AI_V4MAPPED
# define AI_V4MAPPED		0
#endif

enum {
	ISNS_MSG_DISCARD,
	ISNS_MSG_DONE,
	ISNS_MSG_RETURN
};

static isns_socket_t *__isns_create_socket(struct addrinfo *src,
			struct addrinfo *dst,
			int sock_type);
static struct addrinfo *isns_get_address_list(const char *, const char *,
			int, int, int);
static void	release_addrinfo(struct addrinfo *);
static void	isns_net_dgram_recv(isns_socket_t *);
static void	isns_net_dgram_xmit(isns_socket_t *);
static void	isns_net_stream_accept(isns_socket_t *);
static void	isns_net_stream_recv(isns_socket_t *);
static void	isns_net_stream_xmit(isns_socket_t *);
static void	isns_net_stream_hup(isns_socket_t *);
static void	isns_net_stream_error(isns_socket_t *, int);
static void	isns_net_stream_reconnect(isns_socket_t *);
static void	isns_net_stream_disconnect(isns_socket_t *);
static isns_socket_t *isns_net_alloc(int);
static int	isns_socket_open(isns_socket_t *);
static int	isns_socket_queue_message(isns_socket_t *, isns_message_t *);
static int	isns_socket_retransmit_queued(isns_socket_t *);

static ISNS_LIST_DECLARE(all_sockets);

#define debug_verbose(args ...) do { \
	if (SOCK_DEBUG_VERBOSE >= 1) isns_debug_socket(args); \
} while (0)
#define debug_verbose2(args ...) do { \
	if (SOCK_DEBUG_VERBOSE >= 2) isns_debug_socket(args); \
} while (0)

/*
 * Helper function for looking at incoming PDUs
 */
static inline buf_t *
isns_socket_next_pdu(isns_socket_t *sock)
{
	buf_t		*bp = sock->is_recv_buf;
	unsigned int	avail;
	struct isns_hdr	*hdr;
	uint32_t	pdu_len = 0;

	if (bp == NULL)
		return NULL;

	avail = buf_avail(bp);
	if (avail < sizeof(*hdr))
		return NULL;
	hdr = buf_head(bp);
	pdu_len = sizeof(*hdr) + ntohs(hdr->i_length);

	if (avail < pdu_len)
		return NULL;

	/* Check for presence of authentication block */
	if (hdr->i_flags & htons(ISNS_F_AUTHBLK_PRESENT)) {
		uint32_t	*authblk, authlen;

		authblk = (uint32_t *) ((char *) hdr + pdu_len);
		if (avail < pdu_len + ISNS_AUTHBLK_SIZE)
			return NULL;

		authlen = ntohl(authblk[1]);
		if (authlen < 20 || authlen > ISNS_MAX_MESSAGE) {
			/* The authblock is garbage.
			 * The only reliable way to signal such a problem
			 * is by dropping the connection.
			 */
			isns_error("socket error: bad auth block\n");
			sock->is_state = ISNS_SOCK_DEAD;
			return NULL;
		}

		pdu_len += authlen;
		if (avail < pdu_len)
			return NULL;
	}

	return buf_split(&sock->is_recv_buf, pdu_len);
}

/*
 * Try to assemble the message from PDUs
 */
static inline int
isns_msg_complete(struct isns_partial_msg *msg)
{
	buf_t	*msg_buf, **chain, *bp;

	/* Return if we haven't seen first and last frag */
	if (((~msg->imp_flags) & (ISNS_F_FIRST_PDU|ISNS_F_LAST_PDU)))
		return 0;

	/* Simple - unfragmented case: just move
	 * the PDU on the chain to the payload */
	if (msg->imp_first_seq == msg->imp_last_seq) {
		msg->imp_payload = msg->imp_chain;
		buf_pull(msg->imp_payload, sizeof(struct isns_hdr));
		msg->imp_chain = NULL;
		return 1;
	}

	/* Do we have all fragments? */
	if (msg->imp_last_seq - msg->imp_first_seq + 1
			!= msg->imp_pdu_count)
		return 0;

	msg_buf = buf_alloc(msg->imp_msg_size);

	chain = &msg->imp_chain;
	while ((bp = *chain) != NULL) {
		/* Pull the header off */
		buf_pull(bp, sizeof(struct isns_hdr));
		buf_put(msg_buf, buf_head(bp), buf_avail(bp));

		*chain = bp->next;
		buf_free(bp);
	}

	return 0;
}

/*
 * Clear the "partial" part of the message
 */
static void
__isns_msg_clear_partial(struct isns_partial_msg *msg)
{
	buf_list_free(msg->imp_chain);
	msg->imp_chain = NULL;
}

/*
 * Add an authentication block to an outgoing PDU
 */
#ifdef WITH_SECURITY
static int
isns_pdu_seal(isns_security_t *ctx, buf_t *pdu)
{
	struct isns_authblk	auth;
	isns_principal_t	*self;

	if (!(self = ctx->is_self)) {
		isns_error("Cannot sign PDU: no sender identity for socket\n");
		return 0;
	}

	auth.iab_bsd = ctx->is_type;
	auth.iab_timestamp = time(NULL);
	auth.iab_spi = self->is_name;
	auth.iab_spi_len = strlen(self->is_name);

	if (!isns_security_sign(ctx, self, pdu, &auth)) {
		isns_error("Cannot sign PDU: error creating signature\n");
		return 0;
	}

	auth.iab_length = ISNS_AUTHBLK_SIZE +
			auth.iab_spi_len +
			auth.iab_sig_len;
	if (!isns_authblock_encode(pdu, &auth))
		return 0;

	isns_debug_message("Successfully signed message (authlen=%u, spilen=%u, siglen=%u)\n",
			auth.iab_length, auth.iab_spi_len, auth.iab_sig_len);

	return 1;
}

/*
 * Authenticate a PDU
 *
 * The RFC is doing a bit of handwaving around the
 * authentication issue. For example, it never
 * spells out exactly which parts of the message
 * are included in the SHA1 hash to be signed.
 *
 * It also says that the auth block "is identical in format
 * to the SLP authentication block", but all fields
 * are twice as wide.
 *
 * There's not even an error code to tell the client
 * we were unable to authenticate him :-(
 *
 * Interoperability problems, here I come...
 */
static int
isns_pdu_authenticate(isns_security_t *sec,
		struct isns_partial_msg *msg, buf_t *bp)
{
	struct isns_hdr		*hdr = buf_head(bp);
	unsigned int		pdu_len, avail;
	struct isns_authblk	authblk;
	isns_principal_t *	peer = NULL;
	buf_t			auth_buf;

	isns_debug_auth("Message has authblock; trying to authenticate\n");

	/* In the TCP path, we checked this before, but
	 * better safe than sorry. */
	avail = buf_avail(bp);
	pdu_len = sizeof(*hdr) + ntohs(hdr->i_length);
	if (avail < pdu_len + ISNS_AUTHBLK_SIZE) {
		isns_debug_auth("authblock truncated\n");
		return 0;
	}

	/* Get the auth block */
	buf_set(&auth_buf, buf_head(bp) + pdu_len, avail - pdu_len);
	if (!isns_authblock_decode(&auth_buf, &authblk)) {
		isns_debug_auth("error decoding authblock\n");
		return 0;
	}

	/* Truncate the buffer (this just sets the
	 * tail pointer, but doesn't free memory */
	if (!buf_truncate(bp, pdu_len)) {
		isns_debug_auth("buf_truncate failed - cosmic particles?\n");
		return 0;
	}

	/* If the socket doesn't have a security context,
	 * just ignore the auth block. */
	if (sec == NULL) {
		msg->imp_header.i_flags &= ~ISNS_F_AUTHBLK_PRESENT;
		return 1;
	}

	if (authblk.iab_bsd != sec->is_type)
		goto failed;

	peer = isns_get_principal(sec, authblk.iab_spi, authblk.iab_spi_len);
	if (peer == NULL) {
		/* If the admin allows unknown peers, we must make
		 * sure, however, to not allow an unauthenticated
		 * PDU to be inserted into an authenticated message.
		 */
		if (isns_config.ic_auth.allow_unknown_peers
		 && msg->imp_security == NULL) {
			isns_debug_message(
				"Accepting unknown peer spi=\"%.*s\" as "
				"anonymous peer\n",
				authblk.iab_spi_len, authblk.iab_spi);
			return 1;
		}

		isns_debug_message(
			"Unable to create security peer for spi=%.*s\n",
			authblk.iab_spi_len, authblk.iab_spi);

		goto failed;
	}

	if (!isns_security_verify(sec, peer, bp, &authblk)) {
		/* Authentication failed */
		goto failed;
	}

	/* The RFC doesn't say how to deal with fragmented
	 * messages with different BSDs or SPIs.
	 * kickban seems the right approach.
	 * We discard this segment rather than failing
	 * the entire message.
	 */
	if (msg->imp_chain == NULL) {
		msg->imp_security = peer;
		peer->is_users++;
	} else
	if (msg->imp_security != peer) {
		goto failed;
	}

	isns_principal_free(peer);
	return 1;

failed:
	isns_principal_free(peer);
	return 0;
}
#else /* WITH_SECURITY */
static int
isns_pdu_authenticate(isns_security_t *sec,
		struct isns_partial_msg *msg, buf_t *bp)
{
	return 0;
}

#endif

/*
 * Enqueue an incoming PDU on the socket.
 *
 * A single iSNS message may be split up into
 * several PDUs, so we need to perform
 * reassembly here.
 *
 * This function also verifies the authentication
 * block, if present.
 */
static void
isns_pdu_enqueue(isns_socket_t *sock,
		struct sockaddr_storage *addr, socklen_t alen,
		buf_t *segment, struct ucred *creds)
{
	isns_message_queue_t *q = &sock->is_partial;
	struct isns_partial_msg *msg;
	buf_t		**chain, *bp;
	struct isns_hdr	*hdr;
	uint32_t	xid, seq, flags;

	hdr = (struct isns_hdr *) buf_head(segment);
	xid = ntohs(hdr->i_xid);
	seq = ntohs(hdr->i_seq);
	flags = ntohs(hdr->i_flags);

	isns_debug_socket("Incoming PDU xid=%04x seq=%u len=%u func=%s%s%s%s%s%s\n",
			xid, seq, ntohs(hdr->i_length),
			isns_function_name(ntohs(hdr->i_function)),
			(flags & ISNS_F_CLIENT)? " client" : "",
			(flags & ISNS_F_SERVER)? " server" : "",
			(flags & ISNS_F_AUTHBLK_PRESENT)? " authblk" : "",
			(flags & ISNS_F_FIRST_PDU)? " first" : "",
			(flags & ISNS_F_LAST_PDU)? " last" : "");

	/* Find the message matching (addr, xid) */
	msg = (struct isns_partial_msg *) isns_message_queue_find(q, xid, addr, alen);
	if (msg != NULL) {
		if (msg->imp_creds
		 && (!creds || memcmp(msg->imp_creds, creds, sizeof(*creds)))) {
			isns_warning("socket: credentials mismatch! Dropping PDU\n");
			goto drop;
		}
		hdr = &msg->imp_header;
		goto found;
	}

	msg = (struct isns_partial_msg *) __isns_alloc_message(xid, sizeof(*msg),
			(void (*)(isns_message_t *)) __isns_msg_clear_partial);
	memcpy(&msg->imp_addr, addr, alen);
	msg->imp_addrlen = alen;

	msg->imp_header = *hdr;
	msg->imp_header.i_seq = 0;

	isns_message_queue_append(q, &msg->imp_base);
	isns_message_release(&msg->imp_base);
	/* Message is owned by is_partial now */

	/* Fix up the PDU header */
	hdr = &msg->imp_header;
	hdr->i_version = ntohs(hdr->i_version);
	hdr->i_function = ntohs(hdr->i_function);
	hdr->i_length = ntohs(hdr->i_length);
	hdr->i_flags = ntohs(hdr->i_flags);
	hdr->i_xid = ntohs(hdr->i_xid);
	hdr->i_seq = ntohs(hdr->i_seq);

	if (creds) {
		msg->imp_credbuf = *creds;
		msg->imp_creds = &msg->imp_credbuf;
	}

found:
	if (flags & ISNS_F_AUTHBLK_PRESENT) {
		/* When authentication fails - should we drop the
		 * message or treat it as unauthenticated?
		 * For now we drop it, but a more user friendly 
		 * approach might be to just treat it as
		 * unauthenticated.
		 */
		if (!isns_pdu_authenticate(sock->is_security, msg, segment))
			goto drop;
	} else
	if (msg->imp_header.i_flags & ISNS_F_AUTHBLK_PRESENT) {
		/* Oops, unauthenticated fragment in an
		 * authenticated message. */
		isns_debug_message(
			"Oops, unauthenticated fragment in an "
			"authenticated message!\n");
		goto drop;
	}

	if ((flags & ISNS_F_FIRST_PDU)
	 && !(msg->imp_flags & ISNS_F_FIRST_PDU)) {
		/* FIXME: first seq must be zero */
		msg->imp_first_seq = seq;
		msg->imp_flags |= ISNS_F_FIRST_PDU;
	}
	if ((flags & ISNS_F_LAST_PDU)
	 && !(msg->imp_flags & ISNS_F_LAST_PDU)) {
		msg->imp_last_seq = seq;
		msg->imp_flags |= ISNS_F_LAST_PDU;
	}

	chain = &msg->imp_chain;
	while ((bp = *chain) != NULL) {
		struct isns_hdr *ohdr = buf_head(bp);

		/* Duplicate? Drop it! */
		if (seq == ohdr->i_seq)
			goto drop;
		if (seq < ohdr->i_seq)
			break;
		chain = &bp->next;
	}
	segment->next = *chain;
	*chain = segment;

	msg->imp_msg_size += buf_avail(segment) - sizeof(*hdr);
	msg->imp_pdu_count++;

	/* We received first and last PDU - check if the
	 * chain is complete */
	if (isns_msg_complete(msg)) {
		/* Remove from partial queue.
		 * We clean the part of the message that is
		 * not in imp_base, so that we can pass this
		 * to the caller and have him call
		 * isns_message_release on it.
		 */
		__isns_msg_clear_partial(msg);

		/* Move from partial queue to complete queue. */
		isns_message_queue_move(&sock->is_complete,
				&msg->imp_base);
		msg->imp_base.im_socket = sock;
	}

	return;

drop:
	buf_free(segment);
	return;
}

/*
 * Send side handling
 */
static void
isns_send_update(isns_socket_t *sock)
{
	buf_t *bp = sock->is_xmit_buf;

	if (bp && buf_avail(bp) == 0) {
		sock->is_xmit_buf = bp->next;
		buf_free(bp);
	}

	if (sock->is_xmit_buf)
		sock->is_poll_mask |= POLLOUT;
	else
		sock->is_poll_mask &= ~POLLOUT;
}

/*
 * Close the socket
 */
static void
isns_net_close(isns_socket_t *sock, int next_state)
{
	if (sock->is_desc >= 0) {
		close(sock->is_desc);
		sock->is_desc = -1;
	}
	sock->is_poll_mask &= ~(POLLIN|POLLOUT);
	sock->is_state = next_state;

	buf_list_free(sock->is_xmit_buf);
	sock->is_xmit_buf = NULL;

	buf_free(sock->is_recv_buf);
	sock->is_recv_buf = NULL;

	isns_message_queue_destroy(&sock->is_partial);
	isns_message_queue_destroy(&sock->is_complete);
}

static void
isns_net_set_timeout(isns_socket_t *sock,
			void (*func)(isns_socket_t *),
			unsigned int timeout)
{
	gettimeofday(&sock->is_deadline, NULL);
	sock->is_deadline.tv_sec += timeout;
	sock->is_timeout = func;
}

static void
isns_net_cancel_timeout(isns_socket_t *sock)
{
	timerclear(&sock->is_deadline);
}

void
isns_net_error(isns_socket_t *sock, int err_code)
{
	if (sock->is_error)
		sock->is_error(sock, err_code);
}

/*
 * Create a passive socket (server side)
 */
isns_socket_t *
isns_create_server_socket(const char *src_spec, const char *portspec, int af_hint, int sock_type)
{
	struct addrinfo *src;

	src = isns_get_address_list(src_spec, portspec,
			af_hint, sock_type, AI_PASSIVE);
	if (src == NULL)
		return NULL;

	return __isns_create_socket(src, NULL, sock_type);
}

/*
 * Accept incoming connections.
 */
void
isns_net_stream_accept(isns_socket_t *sock)
{
	isns_socket_t *child;
	size_t	optlen;
	int	fd, passcred = 0;

	fd = accept(sock->is_desc, NULL, NULL);
	if (fd < 0) {
		if (errno != EINTR)
			isns_error("Error accepting connection: %m\n");
		return;
	}

	optlen = sizeof(passcred);
	if (getsockopt(sock->is_desc, SOL_SOCKET, SO_PASSCRED,
				&passcred, &optlen) >= 0) {
		setsockopt(fd, SOL_SOCKET, SO_PASSCRED,
				&passcred, sizeof(passcred));
	}

	child = isns_net_alloc(fd);
	child->is_type = SOCK_STREAM;
	child->is_autoclose = 1;
	child->is_disconnect_fatal = 1;
	child->is_poll_in = isns_net_stream_recv;
	child->is_poll_out = isns_net_stream_xmit;
	child->is_poll_hup = isns_net_stream_hup;
	child->is_error = isns_net_stream_error;
	child->is_poll_mask = POLLIN|POLLHUP;
	child->is_security = sock->is_security;

	if (isns_config.ic_network.idle_timeout)
		isns_net_set_timeout(child,
			isns_net_stream_disconnect,
			isns_config.ic_network.idle_timeout);

	isns_list_append(&all_sockets, &child->is_list);
}

/*
 * This is called from the socket code when it detects
 * an error condition.
 */
static void
isns_net_stream_error(isns_socket_t *sock, int err_code)
{
	int	timeo = 0, next_state = ISNS_SOCK_DEAD;

	if (err_code == EAGAIN)
		return;

	isns_debug_socket("isns_net_stream_error: %s\n", strerror(err_code));

	switch (err_code) {
	case EINTR: /* ignored */
		return;

	case ECONNREFUSED:
	case ECONNRESET:
	case EHOSTUNREACH:
	case ENETUNREACH:
	case ENOTCONN:
	case EPIPE:
		if (sock->is_disconnect_fatal) {
			isns_warning("socket disconnect, killing socket\n");
			break;
		}

		/* fallthrough to disconnect */
		timeo = isns_config.ic_network.reconnect_timeout;

	case ETIMEDOUT:
		/* Disconnect and try to reconnect */
		if (sock->is_client) {
			/* FIXME: We don't want this warning for ESI and
			 * SCN sockets on the server side. */
			isns_warning("socket disconnect, retrying in %u sec\n",
					timeo);
			isns_net_set_timeout(sock,
					isns_net_stream_reconnect,
					timeo);
			next_state = ISNS_SOCK_DISCONNECTED;
			break;
		}

		/* fallthru */

	default:
		isns_error("socket error: %s\n", strerror(err_code));
	}

	/* Close the socket right away */
	isns_net_close(sock, next_state);
}

/*
 * recvmsg wrapper handling SCM_CREDENTIALS passing
 */
static int
isns_net_recvmsg(isns_socket_t *sock,
		void *buffer, size_t count,
		struct sockaddr *addr, socklen_t *alen,
		struct ucred **cred)
{
	static struct ucred cred_buf;
	unsigned int	control[128];
	struct cmsghdr	*cmsg;
	struct msghdr	msg;
	struct iovec	iov;
	int		len;

	*cred = NULL;

	iov.iov_base = buffer;
	iov.iov_len = count;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = addr;
	msg.msg_namelen = *alen;
	msg.msg_iov = &iov;
	msg.msg_iovlen = 1;
	msg.msg_control = control;
	msg.msg_controllen = sizeof(control);

	len = recvmsg(sock->is_desc, &msg, MSG_DONTWAIT);

	if (len < 0)
		return len;

	cmsg = CMSG_FIRSTHDR(&msg);
	while (cmsg) {
		if (cmsg->cmsg_level == SOL_SOCKET
		 && cmsg->cmsg_type == SCM_CREDENTIALS) {
			memcpy(&cred_buf, CMSG_DATA(cmsg), sizeof(cred_buf));
			*cred = &cred_buf;
			break;
		}

		cmsg = CMSG_NXTHDR(&msg, cmsg);
	}

	*alen = msg.msg_namelen;
	return len;
}

void
isns_net_stream_recv(isns_socket_t *sock)
{
	unsigned char	buffer[ISNS_MAX_BUFFER];
	struct sockaddr_storage addr;
	struct ucred	*creds = NULL;
	socklen_t	alen = sizeof(addr);
	buf_t		*bp;
	size_t		count, total = 0;
	int		len;

again:
	if ((bp = sock->is_recv_buf) == NULL) {
		bp = buf_alloc(ISNS_MAX_MESSAGE);
		sock->is_recv_buf = bp;
	}

	if ((count = buf_tailroom(bp)) > sizeof(buffer))
		count = sizeof(buffer);

	if (count == 0) {
		/* Message too large */
		isns_net_stream_error(sock, EMSGSIZE);
		return;
	}

#if 0
	len = recvfrom(sock->is_desc, buffer, count, MSG_DONTWAIT,
			(struct sockaddr *) &addr, &alen);
#else
	len = isns_net_recvmsg(sock, buffer, count,
			(struct sockaddr *) &addr, &alen,
			&creds);
#endif
	if (len < 0) {
		isns_net_stream_error(sock, errno);
		return;
	}
	if (len == 0) {
		if (total == 0)
			sock->is_poll_mask &= ~POLLIN;
		return;
	}

	/* We received some data from client, re-arm the
	 * idle disconnect timer */
	if (sock->is_autoclose
	 && isns_config.ic_network.idle_timeout)
		isns_net_set_timeout(sock,
			isns_net_stream_disconnect,
			isns_config.ic_network.idle_timeout);

	buf_put(bp, buffer, len);
	total += len;

	/* Chop up the recv buffer into PDUs */
	while ((bp = isns_socket_next_pdu(sock)) != NULL) {
		/* We have a full PDU; enqueue it */
		/* We shouldn't have more than one partial message
		 * on a TCP connection; we could check this here.
		 */
		isns_pdu_enqueue(sock, &addr, alen, bp, creds);
	}

	goto again;
}

void
isns_net_stream_xmit(isns_socket_t *sock)
{
	unsigned int	count;
	buf_t		*bp = sock->is_xmit_buf;
	int		len;

	/* If a connecting socket can send, it has
	 * the TCP three-way handshake. */
	if (sock->is_state == ISNS_SOCK_CONNECTING) {
		sock->is_state = ISNS_SOCK_IDLE;
		sock->is_poll_mask |= POLLIN;
		isns_net_cancel_timeout(sock);
	}

	if (bp == NULL)
		return;

	count = buf_avail(bp);
	len = send(sock->is_desc, buf_head(bp), count, MSG_DONTWAIT);
	if (len < 0) {
		isns_net_stream_error(sock, errno);
		return;
	}

	debug_verbose("isns_net_stream_xmit(%p, count=%u): transmitted %d\n",
			sock, count, len);
	buf_pull(bp, len);
	isns_send_update(sock);
}

void
isns_net_stream_hup(isns_socket_t *sock)
{
	sock->is_poll_mask &= ~POLLIN;
	/* POLLHUP while connecting means we failed */
	if (sock->is_state == ISNS_SOCK_CONNECTING)
		isns_net_stream_error(sock, ECONNREFUSED);
}

/*
 * Clone an addrinfo list
 */
static struct addrinfo *
clone_addrinfo(const struct addrinfo *ai)
{
	struct addrinfo *res = NULL, **p;

	p = &res;
	for (; ai; ai = ai->ai_next) {
		struct addrinfo *new;

		if (ai->ai_addrlen > sizeof(struct sockaddr_storage))
			continue;

		new = isns_calloc(1, sizeof(*new) + ai->ai_addrlen);
		new->ai_family = ai->ai_family;
		new->ai_socktype = ai->ai_socktype;
		new->ai_protocol = ai->ai_protocol;
		new->ai_addrlen = ai->ai_addrlen;
		new->ai_addr = (struct sockaddr *) (new + 1);
		memcpy(new->ai_addr, ai->ai_addr, new->ai_addrlen);

		*p = new;
		p = &new->ai_next;
	}

	return res;
}

static struct addrinfo *
__make_addrinfo(const struct sockaddr *ap, socklen_t alen, int socktype)
{
	struct addrinfo *new;

	new = isns_calloc(1, sizeof(*new) + alen);
	new->ai_family = ap->sa_family;
	new->ai_socktype = socktype;
	new->ai_protocol = 0;
	new->ai_addrlen = alen;
	new->ai_addr = (struct sockaddr *) (new + 1);
	memcpy(new->ai_addr, ap, alen);

	return new;
}

static struct addrinfo *
make_addrinfo_unix(const char *pathname, int socktype)
{
	unsigned int	len = strlen(pathname);
	struct sockaddr_un sun;

	if (len + 1 > sizeof(sun.sun_path)) {
		isns_error("Can't set AF_LOCAL address: path too long!\n");
		return NULL;
	}

	sun.sun_family = AF_LOCAL;
	strcpy(sun.sun_path, pathname);
	return __make_addrinfo((struct sockaddr *) &sun, SUN_LEN(&sun) + 1, socktype);
}

static struct addrinfo *
make_addrinfo_any(int family, int socktype)
{
	struct sockaddr_storage addr = { .ss_family = AF_UNSPEC };
	struct addrinfo *res;

	if (family != AF_UNSPEC) {
		addr.ss_family = family;
		res = __make_addrinfo((struct sockaddr *) &addr, sizeof(addr), socktype);
	} else {
		addr.ss_family = AF_INET6;
		res = __make_addrinfo((struct sockaddr *) &addr, sizeof(addr), socktype);
		addr.ss_family = AF_INET;
		res->ai_next = __make_addrinfo((struct sockaddr *) &addr, sizeof(addr), socktype);
	}

	return res;
}

/*
 * Release addrinfo created by functions above.
 * We cannot use freeaddrinfo, as we don't know how it
 * is implemented.
 */
static void
release_addrinfo(struct addrinfo *ai)
{
	struct addrinfo	*next;

	for (; ai; ai = next) {
		next = ai->ai_next;
		isns_free(ai);
	}
}

static void
__isns_sockaddr_set_current(struct __isns_socket_addr *info,
		const struct addrinfo *ai)
{
	if (!ai)
		return;

	/* Cannot overflow; we check addrlen in clone_addrinfo */
	memcpy(&info->addr, ai->ai_addr, ai->ai_addrlen);
	info->addrlen = ai->ai_addrlen;
}

static void
isns_sockaddr_init(struct __isns_socket_addr *info,
		struct addrinfo *ai)
{
	if (ai == NULL)
		return;

	__isns_sockaddr_set_current(info, ai);

	/* keep a copy so that we can loop through
	 * all addrs */
	info->list = ai;

	/* Make the list circular */
	while (ai->ai_next)
		ai = ai->ai_next;
	ai->ai_next = info->list;
}

static void
isns_sockaddr_destroy(struct __isns_socket_addr *info)
{
	struct addrinfo *ai, *next;

	if ((ai = info->list) != NULL) {
		/* Break the circular list */
		info->list = NULL;
		next = ai->ai_next;
		ai->ai_next = NULL;
		isns_assert(next);

		/* Can't use freeaddrinfo on homegrown
		 * addrinfo lists. */
		release_addrinfo(next);
	}
}

static int
isns_sockaddr_set_next(struct __isns_socket_addr *info)
{
	struct addrinfo *ai;

	if (!(ai = info->list))
		return 0;

	info->list = ai->ai_next;
	__isns_sockaddr_set_current(info, info->list);
	return 1;
}

/*
 * This function is used to pick a matching source address
 * when connecting to some server.
 */
static int
isns_sockaddr_select(struct __isns_socket_addr *info,
		const struct sockaddr_storage *hint)
{
	struct addrinfo *head = info->list, *ai;

	if (info->list == NULL)
		return 0;

	if (hint->ss_family == AF_INET6) {
		struct addrinfo *good = NULL, *best = NULL;

		ai = head; 
		do {
			if (ai->ai_family == AF_INET) {
				/* Possible improvement: when
				 * destination is not a private network,
				 * prefer non-private source. */
				good = ai;
			} else
			if (ai->ai_family == AF_INET6) {
				/* Possible improvement: prefer IPv6 addr
				 * with same address scope (local, global)
				 */
				best = ai;
				break;
			}

			ai = ai->ai_next;
		} while (ai != head);

		if (!best)
			best = good;
		if (best) {
			__isns_sockaddr_set_current(info, best);
			return 1;
		}
	} else
	if (hint->ss_family == AF_INET || hint->ss_family == AF_LOCAL) {
		ai = head; 
		do {
			if (ai->ai_family == hint->ss_family) {
				__isns_sockaddr_set_current(info, ai);
				return 1;
			}
			ai = ai->ai_next;
		} while (ai != head);
	}

	return 0;
}

void
isns_net_stream_reconnect(isns_socket_t *sock)
{
	struct sockaddr *addr = (struct sockaddr *) &sock->is_dst.addr;

	debug_verbose("isns_net_stream_reconnect(%p)\n", sock);

	/* If we timed out while connecting, close the socket
	 * and try again. */
	if (sock->is_state == ISNS_SOCK_CONNECTING) {
		isns_net_close(sock, ISNS_SOCK_DISCONNECTED);
		isns_sockaddr_set_next(&sock->is_dst);
	}

	if (!isns_socket_open(sock)) {
		isns_error("isns_net_stream_reconnect: cannot create socket\n");
		sock->is_state = ISNS_SOCK_DEAD;
		return;
	}

	if (connect(sock->is_desc, addr, sock->is_dst.addrlen) >= 0) {
		sock->is_state = ISNS_SOCK_IDLE;
		sock->is_poll_mask |= POLLIN;
	} else 
	if (errno == EINTR || errno == EINPROGRESS) {
		sock->is_state = ISNS_SOCK_CONNECTING;
		isns_net_set_timeout(sock,
				isns_net_stream_reconnect,
				isns_config.ic_network.connect_timeout);
		sock->is_poll_mask |= POLLOUT;
	} else {
		isns_net_stream_error(sock, errno);
		return;
	}

	/* We're connected, or in the process of doing so.
	 * Check if there are any pending messages, and
	 * retransmit them. */
	isns_socket_retransmit_queued(sock);
}

void
isns_net_stream_disconnect(isns_socket_t *sock)
{
	isns_debug_socket("Disconnecting idle socket\n");
	isns_net_close(sock, ISNS_SOCK_DEAD);
}

/*
 * Datagram send/recv
 */
static int
isns_net_dgram_connect(isns_socket_t *sock)
{
	return connect(sock->is_desc,
			(struct sockaddr *) &sock->is_dst.addr,
			sock->is_dst.addrlen);
}

void
isns_net_dgram_recv(isns_socket_t *sock)
{
	unsigned char	buffer[ISNS_MAX_BUFFER];
	struct sockaddr_storage addr;
	socklen_t	alen = sizeof(addr);
	buf_t		*bp;
	int		len;

	len = recvfrom(sock->is_desc, buffer, sizeof(buffer),
			MSG_DONTWAIT, (struct sockaddr *) &addr, &alen);
	if (len < 0) {
		isns_error("recv: %m\n");
		return;
	}
	if (len == 0)
		return;

	bp = buf_alloc(len);
	if (bp == NULL)
		return;

	buf_put(bp, buffer, len);
	isns_pdu_enqueue(sock, &addr, alen, bp, NULL);
}

void
isns_net_dgram_xmit(isns_socket_t *sock)
{
	unsigned int	count;
	buf_t		*bp = sock->is_xmit_buf;
	int		len;

	count = buf_avail(bp);
	if (bp->addrlen) {
		len = sendto(sock->is_desc, buf_head(bp), count, MSG_DONTWAIT,
			(struct sockaddr *) &bp->addr, bp->addrlen);
	} else {
		len = sendto(sock->is_desc, buf_head(bp), count, MSG_DONTWAIT,
			NULL, 0);
	}

	/* Even if sendto failed, we will pull the pending buffer
	 * off the send chain. Else we'll loop forever on an
	 * unreachable host. */
	if (len < 0)
		isns_error("send: %m\n");

	buf_pull(bp, count);
	isns_send_update(sock);
}

/*
 * Bind socket to random port
 */
static int
__isns_socket_bind_random(int fd,
		const struct sockaddr *orig_addr,
		socklen_t src_len)
{
	struct sockaddr_storage addr;
	struct sockaddr *src_addr;
	uint16_t min = 888, max = 1024;
	unsigned int loop = 0;

	/* Copy the address to a writable location */
	isns_assert(src_len <= sizeof(addr));
	memcpy(&addr, orig_addr, src_len);
	src_addr = (struct sockaddr *) &addr;

	/* Bind to a random port */
	do {
		uint16_t port;

		port = random();
		port = min + (port % (max - min));

		isns_addr_set_port(src_addr, port);
		
		if (bind(fd, src_addr, src_len) == 0)
			return 1;

		if (errno == EACCES && min < 1024) {
			min = 1024;
			max = 65535;
			continue;
		}
	} while (errno == EADDRINUSE && ++loop < 128);

	isns_error("Unable to bind socket\n");
	return 0;
}

/*
 * Create a socket
 */
isns_socket_t *
__isns_create_socket(struct addrinfo *src, struct addrinfo *dst, int sock_type)
{
	isns_socket_t *sock;

	sock = isns_net_alloc(-1);
	sock->is_type = sock_type;
	
	/* Set address lists */
	isns_sockaddr_init(&sock->is_dst, dst);
	isns_sockaddr_init(&sock->is_src, src);

	if (dst) {
		/* This is an outgoing connection. */
		sock->is_client = 1;

		if (!isns_socket_open(sock))
			goto failed;

		if (sock_type == SOCK_DGRAM) {
			sock->is_poll_in = isns_net_dgram_recv;
			sock->is_poll_out = isns_net_dgram_xmit;
			sock->is_poll_mask = POLLIN;

			sock->is_retrans_timeout = isns_config.ic_network.udp_retrans_timeout;

			while (isns_net_dgram_connect(sock) < 0) {
				if (isns_sockaddr_set_next(&sock->is_dst)
				 && sock->is_dst.list != dst)
					continue;
				isns_error("Unable to connect: %m\n");
				goto failed;
			}
		} else {
			/* Stream socket */
			sock->is_poll_in = isns_net_stream_recv;
			sock->is_poll_out = isns_net_stream_xmit;
			sock->is_poll_hup = isns_net_stream_hup;
			sock->is_error = isns_net_stream_error;
			sock->is_poll_mask = POLLHUP;

			sock->is_retrans_timeout = isns_config.ic_network.tcp_retrans_timeout;

			isns_net_stream_reconnect(sock);
		}
	} else {
		if (!isns_socket_open(sock))
			goto failed;

		if (sock_type == SOCK_DGRAM) {
			sock->is_poll_in = isns_net_dgram_recv;
			sock->is_poll_out = isns_net_dgram_xmit;
			sock->is_state = ISNS_SOCK_IDLE;
		} else {
			sock->is_poll_in = isns_net_stream_accept;
			sock->is_error = isns_net_stream_error;
			sock->is_state = ISNS_SOCK_LISTENING;
		}
		sock->is_poll_mask = POLLIN;
	}

	isns_list_append(&all_sockets, &sock->is_list);
	return sock;

failed:
	isns_socket_free(sock);
	return NULL;
}

/*
 * Connect to the master process
 */
isns_socket_t *
isns_create_bound_client_socket(const char *src_spec, const char *dst_spec,
		const char *portspec, int af_hint, int sock_type)
{
	struct addrinfo	*src = NULL, *dst;

	if (src_spec) {
		src = isns_get_address_list(src_spec, NULL, af_hint, sock_type, 0);
		if (src == NULL)
			return NULL;
	}

	dst = isns_get_address_list(dst_spec, portspec, af_hint, sock_type, 0);
	if (dst == NULL) {
		release_addrinfo(src);
		return NULL;
	}

	return __isns_create_socket(src, dst, sock_type);
}

isns_socket_t *
isns_create_client_socket(const char *dst_spec, const char *portspec, int af_hint, int sock_type)
{
	return isns_create_bound_client_socket(NULL, dst_spec, portspec, af_hint, sock_type);
}

static inline int
isns_socket_type_from_portal(const isns_portal_info_t *info)
{
	switch (info->proto) {
	case IPPROTO_TCP:
		return SOCK_STREAM;
	case IPPROTO_UDP:
		return SOCK_DGRAM;
	default:
		isns_error("Unknown protocol %d in portal\n", info->proto);
	}
	return -1;
}

isns_socket_t *
isns_connect_to_portal(const isns_portal_info_t *info)
{
	struct sockaddr_storage dst_addr;
	struct addrinfo *ai;
	int dst_alen, sock_type;

	if ((sock_type = isns_socket_type_from_portal(info)) < 0)
		return NULL;

	dst_alen = isns_portal_to_sockaddr(info, &dst_addr);
	ai = __make_addrinfo((struct sockaddr *) &dst_addr, dst_alen, sock_type);

	return __isns_create_socket(NULL, ai, sock_type);
}

/*
 * Make server side disconnects isns_fatal.
 * Nice for command line apps.
 */
void
isns_socket_set_disconnect_fatal(isns_socket_t *sock)
{
	sock->is_disconnect_fatal = 1;
}

void
isns_socket_set_report_failure(isns_socket_t *sock)
{
	sock->is_report_failure = 1;
}

/*
 * Set the socket's security context
 */
void
isns_socket_set_security_ctx(isns_socket_t *sock,
				isns_security_t *ctx)
{
	sock->is_security = ctx;
}

/*
 * Create a socket
 */
static isns_socket_t *
isns_net_alloc(int fd)
{
	isns_socket_t *new;

	new = isns_calloc(1, sizeof(*new));
	new->is_desc = fd;
	if (fd >= 0)
		new->is_state = ISNS_SOCK_IDLE;
	else
		new->is_state = ISNS_SOCK_DISCONNECTED;

	isns_message_queue_init(&new->is_partial);
	isns_message_queue_init(&new->is_complete);
	isns_message_queue_init(&new->is_pending);
	isns_list_init(&new->is_list);

	return new;
}

/*
 * Open the socket
 */
static int
isns_socket_open(isns_socket_t *sock)
{
	int	af, fd, state = ISNS_SOCK_IDLE;

	if (sock->is_desc >= 0)
		return 1;

	af = sock->is_dst.addr.ss_family;
	if (af != AF_UNSPEC) {
		/* Select a matching source address */
		if (sock->is_src.list
		 && !isns_sockaddr_select(&sock->is_src, &sock->is_dst.addr)) {
			isns_warning("No matching source address for given destination\n");
			return 0;
		}
	} else {
		af = sock->is_src.addr.ss_family;
		if (af == AF_UNSPEC)
			return 0;
	}

	if ((fd = socket(af, sock->is_type, 0)) < 0) {
		isns_error("Unable to create socket: %m\n");
		return 0;
	}

	if (sock->is_src.addr.ss_family != AF_UNSPEC) {
		const struct sockaddr *src_addr;
		int	src_len, on = 1, bound = 0;

		src_addr = (struct sockaddr *) &sock->is_src.addr;
		src_len = sock->is_src.addrlen;

		/* For debugging only! */
		if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
			isns_error("setsockopt(SO_REUSEADDR) failed: %m\n");
			goto failed;
		}

		switch (af) {
		case AF_LOCAL:
			unlink(((struct sockaddr_un *) src_addr)->sun_path);

			if (sock->is_type == SOCK_STREAM
			 && setsockopt(fd, SOL_SOCKET, SO_PASSCRED,
				 		&on, sizeof(on)) < 0) {
				isns_error("setsockopt(SO_PASSCRED) failed: %m\n");
				goto failed;
			}
			break;

		case AF_INET:
		case AF_INET6:
			if (isns_addr_get_port(src_addr) == 0) {
				if (!__isns_socket_bind_random(fd, src_addr, src_len))
					goto failed;
				bound++;
			}
			break;
		}

		if (!bound && bind(fd, src_addr, src_len) < 0) {
			isns_error("Unable to bind socket: %m\n");
			goto failed;
		}
	}

	if (sock->is_client) {
		/* Set to nonblocking behavior; makes the connect
		 * call return instantly. */
		fcntl(fd, F_SETFL, O_NONBLOCK);
	} else {
		if (sock->is_type == SOCK_STREAM) {
			if (listen(fd, 128) < 0) {
				isns_error("Unable to listen on socket: %m\n");
				goto failed;
			}
			state = ISNS_SOCK_LISTENING;
		}
	}

	sock->is_desc = fd;
	sock->is_state = state;
	return 1;

failed:
	close(fd);
	return 0;
}

/*
 * Destroy a socket
 */
static inline void
isns_socket_destroy(isns_socket_t *sock)
{
	isns_sockaddr_destroy(&sock->is_dst);
	isns_sockaddr_destroy(&sock->is_src);
	isns_free(sock);
}

void
isns_socket_free(isns_socket_t *sock)
{
	isns_net_close(sock, ISNS_SOCK_DEAD);
	isns_list_del(&sock->is_list);

	sock->is_destroy = 1;
	if (sock->is_users == 0)
		isns_socket_destroy(sock);
}

int
isns_socket_release(isns_socket_t *sock)
{
	isns_assert(sock->is_users);
	sock->is_users -= 1;

	if (sock->is_destroy) {
		if (!sock->is_users)
			isns_socket_destroy(sock);
		return 0;
	}
	return 1;
}

/*
 * Display a socket
 */
#if SOCK_DEBUG_VERBOSE > 0
static const char *
isns_socket_state_name(int state)
{
	static char xbuf[16];

	switch (state) {
	case ISNS_SOCK_LISTENING:
		return "listening";
	case ISNS_SOCK_CONNECTING:
		return "connecting";
	case ISNS_SOCK_IDLE:
		return "idle";
	case ISNS_SOCK_FAILED:
		return "failed";
	case ISNS_SOCK_DISCONNECTED:
		return "disconnected";
	case ISNS_SOCK_DEAD:
		return "dead";
	}
	snprintf(xbuf, sizeof(xbuf), "<%u>", state);
	return xbuf;
}

static void
isns_print_socket(const isns_socket_t *sock)
{
	isns_message_t	*msg = NULL;
	char	buffer[8192];
	size_t	pos = 0, size = sizeof(buffer);

	snprintf(buffer + pos, size - pos,
			"socket %p desc %d state %s",
			sock, sock->is_desc,
			isns_socket_state_name(sock->is_state));
	pos = strlen(buffer);

	if (timerisset(&sock->is_deadline)) {
		snprintf(buffer + pos, size - pos, " deadline=%ldms",
				__timeout_millisec(NULL, &sock->is_deadline));
		pos = strlen(buffer);
	}

	if ((msg = isns_message_queue_head(&sock->is_pending)) != NULL) {
		snprintf(buffer + pos, size - pos, " msg timeout=%ldms",
				__timeout_millisec(NULL, &msg->im_timeout));
		pos = strlen(buffer);
	}

	isns_debug_socket("%s\n", buffer);
}
#else
#define isns_print_socket(p)	do { } while (0)
#endif

/*
 * Process incoming messages, and timeouts
 */
static int
isns_net_validate(isns_socket_t *sock, isns_message_t *msg,
		const isns_message_t *check_msg)
{
	isns_message_t *orig = NULL;
	int	verdict = ISNS_MSG_DISCARD;

	if (sock->is_security && !msg->im_security) {
		/* Rude server, or malicious man in the
		 * middle. */
		isns_debug_message("Ignoring unauthenticated message\n");
		goto out;
	}

	/* If this is a request, return it. */
	if (!(msg->im_header.i_function & 0x8000)) {
		if (check_msg == NULL) {
			verdict = ISNS_MSG_RETURN;
		} else {
			/* Else: see if there's a server attached to this
			 * socket. */
		}
		goto out;
	}

	orig = isns_message_queue_find(&sock->is_pending, msg->im_xid, NULL, 0);
	if (orig == NULL) {
		isns_debug_message("Ignoring spurious response message (xid=%04x)\n",
				msg->im_xid);
		goto out;
	}

	isns_message_unlink(orig);
	if (orig->im_header.i_function != (msg->im_header.i_function & 0x7FFF)) {
		isns_debug_message("Response message doesn't match function\n");
		goto out;
	}

	if (check_msg == orig) {
		verdict = ISNS_MSG_RETURN;
	} else {
		isns_debug_message("Received response for pending message 0x%x\n",
				msg->im_xid);
		if (orig->im_callback)
			orig->im_callback(orig, msg);
		verdict = ISNS_MSG_DONE;
	}

out:
	isns_message_release(orig);
	return verdict;
}

static void
isns_net_timeout(isns_socket_t *sock, isns_message_t *msg)
{
	if (msg->im_callback)
		msg->im_callback(msg, NULL);
	isns_message_release(msg);
}

/*
 * Helper function to update timeout
 */
static inline void
__set_timeout(struct timeval *end, unsigned long timeout)
{
	gettimeofday(end, NULL);
	end->tv_sec += timeout;
}

static inline int
__timeout_expired(const struct timeval *now, const struct timeval *expires)
{
	/* FIXME: Should ignore sub-millisecond remainder */
	return timercmp(now, expires, >=);
}

static long
__timeout_millisec(const struct timeval *now, const struct timeval *expires)
{
	struct timeval	__now, delta = { 0, 0 };

	if (now == NULL) {
		gettimeofday(&__now, NULL);
		now = &__now;
	}

	timersub(expires, now, &delta);

	return delta.tv_sec * 1000 + delta.tv_usec / 1000;
}

static inline void
__update_timeout(struct timeval *end, const struct timeval *timeout)
{
	if (!timerisset(end) || timercmp(timeout, end, <))
		*end = *timeout;
}

/*
 * Get the next iSNS message
 */
isns_message_t *
__isns_recv_message(const struct timeval *end_time, isns_message_t *watch_msg)
{
	isns_socket_t	*sock, **sock_list;
	isns_list_t	*pos, *next;
	struct pollfd	*pfd;
	unsigned int	i, count, max_sockets;
	struct timeval	now, this_end;
	int		r;

	max_sockets = isns_config.ic_network.max_sockets;
	sock_list = alloca(max_sockets * sizeof(sock_list[0]));
	pfd = alloca(max_sockets * sizeof(pfd[0]));

again:
	timerclear(&this_end);
	gettimeofday(&now, NULL);

	if (end_time) {
		if (__timeout_expired(&now, end_time))
			return NULL;
		this_end = *end_time;
	}

	i = 0;
	isns_list_foreach(&all_sockets, pos, next) {
		isns_socket_t	*sock = isns_list_item(isns_socket_t, is_list, pos);
		isns_message_t	*msg = NULL;

		/* We need to be a little careful here; callbacks may
		 * mark the socket for destruction.
		 * Bumping is_users while we're busy with the socket
		 * prevents mayhem. */
		sock->is_users++;

		while ((msg = isns_message_dequeue(&sock->is_complete)) != NULL) {
			switch (isns_net_validate(sock, msg, watch_msg)) {
			case ISNS_MSG_RETURN:
				isns_assert(!sock->is_destroy);
				isns_socket_release(sock);
				return msg;
			default:
				isns_message_release(msg);
				isns_socket_release(sock);
				return NULL;
			}
		}

		isns_print_socket(sock);

		/* This handles reconnect, idle disconnect etc. */
		while (timerisset(&sock->is_deadline)) {
			if (__timeout_expired(&now, &sock->is_deadline)) {
				timerclear(&sock->is_deadline);
				sock->is_timeout(sock);
				isns_print_socket(sock);
				continue;
			}
			__update_timeout(&this_end, &sock->is_deadline);
			break;
		}

		/* No more input and output means closed&dead */
		if (sock->is_state == ISNS_SOCK_IDLE
		 && !(sock->is_poll_mask & (POLLIN|POLLOUT))) {
			isns_debug_socket("connection closed by peer, killing socket\n");
			isns_net_close(sock, ISNS_SOCK_FAILED);
		}

		/* Check whether pending messages have timed out. */
		while ((msg = isns_message_queue_head(&sock->is_pending)) !=
		        NULL) {
			if (__timeout_expired(&now, &msg->im_timeout)) {
				isns_debug_socket("sock %p message %04x timed out\n",
						sock, msg->im_xid);
				isns_message_unlink(msg);
				if (msg == watch_msg) {
					isns_message_release(msg);
					isns_socket_release(sock);
					return NULL;
				}

				isns_net_timeout(sock, msg);
				continue;
			}

			if (!__timeout_expired(&now, &msg->im_resend_timeout)) {
				__update_timeout(&this_end,
						&msg->im_resend_timeout);
				/* In odd configurations, the call_timeout
				 * may be lower than the resend_timeout */
				__update_timeout(&this_end,
						&msg->im_timeout);
				break;
			}

			isns_debug_socket("sock %p message %04x - "
					"minor timeout, resending.\n",
					sock, msg->im_xid);

			/* If a TCP socket times out, something is
			 * fishy. Force a reconnect, which will resend
			 * all pending messages. */
			if (sock->is_type == SOCK_STREAM) {
				isns_net_close(sock, ISNS_SOCK_DISCONNECTED);
				isns_net_set_timeout(sock,
					isns_net_stream_reconnect,
					0);
				break;
			}

			/* UDP socket - retransmit this one message */
			isns_message_queue_remove(&sock->is_pending, msg);
			isns_socket_queue_message(sock, msg);
			isns_message_release(msg);
		}

		/* 
		 * If the socket on which we're waiting right
		 * now got disconnected, or had any other kind of
		 * error, return right away to let the caller know.
		 */
		if (sock->is_state == ISNS_SOCK_FAILED) {
			if (sock->is_disconnect_fatal)
				goto kill_socket;
			if (sock->is_report_failure) {
				isns_socket_release(sock);
				return NULL;
			}
			sock->is_state = ISNS_SOCK_DISCONNECTED;
			isns_socket_release(sock);
			continue;
		}

		if (sock->is_state == ISNS_SOCK_DEAD) {
kill_socket:
			isns_list_del(&sock->is_list);
			if (sock->is_report_failure) {
				isns_socket_release(sock);
				return NULL;
			}
			if (!sock->is_client)
				isns_socket_free(sock);
			isns_socket_release(sock);
			continue;
		}

		/* This will return 0 if the socket was marked for
		 * destruction. */
		if (!isns_socket_release(sock))
			continue;

		/* should not happen */
		if (i >= max_sockets)
			break;

		pfd[i].fd = sock->is_desc;
		pfd[i].events = sock->is_poll_mask;
		sock_list[i] = sock;
		i++;
	}
	count = i;

	if (timerisset(&this_end)) {
		long		millisec;

		/* timeval arithmetic can yield sub-millisecond timeouts.
		 * Round up to prevent looping. */
		millisec = __timeout_millisec(&now, &this_end);
		if (millisec == 0)
			millisec += 1;

		debug_verbose2("poll(%p, %u, %d)\n", pfd, count, millisec);
		r = poll(pfd, count, millisec);
	} else {
		r = poll(pfd, count, -1);
	}

	if (r < 0) {
		if (errno != EINTR)
			isns_error("poll returned error: %m\n");
		return NULL;
	}

	/* Any new incoming connections will be added to the
	 * head of the list. */
	for (i = 0; i < count; ++i) {
		sock = sock_list[i];
		if (pfd[i].revents & POLLIN)
			sock->is_poll_in(sock);
		if (pfd[i].revents & POLLOUT)
			sock->is_poll_out(sock);
		if (pfd[i].revents & POLLHUP)
			sock->is_poll_hup(sock);
	}

	goto again;
}

isns_message_t *
isns_recv_message(struct timeval *timeout)
{
	isns_message_t	*msg;
	struct timeval	end;

	if (timeout == NULL)
		return __isns_recv_message(NULL, NULL);

	gettimeofday(&end, NULL);
	timeradd(&end, timeout, &end);
	msg = __isns_recv_message(&end, NULL);

	if (msg == NULL)
		return msg;
	isns_debug_socket("Next message xid=%04x\n", msg->im_xid);
	if (msg->im_security) {
		isns_debug_message("Received authenticated message from \"%s\"\n",
				isns_principal_name(msg->im_security));
	} else if (isns_config.ic_security) {
		isns_debug_message("Received unauthenticated message\n");
	} else {
		isns_debug_message("Received message\n");
	}
	return msg;
}

int
isns_socket_send(isns_socket_t *sock, isns_message_t *msg)
{
	struct isns_hdr	*hdr;
	size_t		pdu_len;
	buf_t		*bp;

	/* If the socket is disconnected, and the
	 * reconnect timeout is not set, force a
	 * reconnect right away. */
	if (sock->is_state == ISNS_SOCK_DISCONNECTED
	 && !timerisset(&sock->is_deadline)) {
		isns_net_set_timeout(sock,
			isns_net_stream_reconnect, 0);
	}

	if (!(bp = msg->im_payload))
		return 0;

	pdu_len = buf_avail(bp);
	if (pdu_len < sizeof(*hdr))
		return 0;

	/* Pad PDU to multiple of 4 bytes, if needed */
	if (pdu_len & 3) {
		unsigned int pad = 4 - (pdu_len & 3);

		if (!buf_put(bp, "\0\0\0", pad))
			return 0;
		pdu_len += pad;
	}

	if (!(bp = buf_dup(bp)))
		return 0;

	hdr = buf_head(bp);

	hdr->i_version = htons(msg->im_header.i_version);
	hdr->i_function = htons(msg->im_header.i_function);
	hdr->i_flags = htons(msg->im_header.i_flags);
	hdr->i_length = htons(pdu_len - sizeof(*hdr));
	hdr->i_xid = htons(msg->im_header.i_xid);
	hdr->i_seq = htons(msg->im_header.i_seq);

	/* For now, we deal with unfragmented messages only. */
	hdr->i_flags |= htons(ISNS_F_FIRST_PDU|ISNS_F_LAST_PDU);

	if (sock->is_security) {
#ifdef WITH_SECURITY
		hdr->i_flags |= htons(ISNS_F_AUTHBLK_PRESENT);
		if (!isns_pdu_seal(sock->is_security, bp)) {
			isns_debug_message("Error adding auth block to outgoing PDU\n");
			goto error;
		}
#else
		isns_debug_message("%s: Authentication not supported\n",
				__FUNCTION__);
		goto error;
#endif
	}

	bp->addr = msg->im_addr;
	bp->addrlen = msg->im_addrlen;

	buf_list_append(&sock->is_xmit_buf, bp);
	sock->is_poll_mask |= POLLOUT;

	/* Set the retransmit timeout */
	__set_timeout(&msg->im_resend_timeout, sock->is_retrans_timeout);
	return 1;

error:
	buf_free(bp);
	return 0;
}

/*
 * Queue a message to a socket
 */
int
isns_socket_queue_message(isns_socket_t *sock, isns_message_t *msg)
{
	if (!isns_socket_send(sock, msg))
		return 0;

	/* Insert sorted by timeout. For now, this amounts to
	 * appending at the end of the list, but that may change
	 * if we implement exponential backoff for UDP */
	isns_message_queue_insert_sorted(&sock->is_pending,
			ISNS_MQ_SORT_RESEND_TIMEOUT, msg);
	msg->im_socket = sock;
	return 1;
}

/*
 * Retransmit any queued messages
 */
int
isns_socket_retransmit_queued(isns_socket_t *sock)
{
	isns_message_t	*msg;
	isns_list_t	*pos;

	isns_debug_socket("%s(%p)\n", __FUNCTION__, sock);
	isns_message_queue_foreach(&sock->is_pending, pos, msg) {
		if (!isns_socket_send(sock, msg))
			isns_warning("Unable to retransmit message\n");
	}
	return 1;
}

/*
 * Submit a message to the socket, for asynchronous calls
 */
int
isns_socket_submit(isns_socket_t *sock, isns_message_t *msg, long timeout)
{
	if (timeout <= 0)
		timeout = isns_config.ic_network.call_timeout;

	__set_timeout(&msg->im_timeout, timeout);
	return isns_socket_queue_message(sock, msg);
}

/*
 * Transmit a message and wait for a response.
 */
isns_message_t *
isns_socket_call(isns_socket_t *sock, isns_message_t *msg, long timeout)
{
	isns_message_t	*resp;

	debug_verbose("isns_socket_call(sock=%p, msg=%p, timeout=%ld)\n",
			sock, msg, timeout);
	if (timeout <= 0)
		timeout = isns_config.ic_network.call_timeout;

	__set_timeout(&msg->im_timeout, timeout);
	if (!isns_socket_queue_message(sock, msg))
		return NULL;

	sock->is_report_failure = 1;
	resp = __isns_recv_message(NULL, msg);
	sock->is_report_failure = 0;

	if (isns_message_unlink(msg)) {
		/* We can get here if __isns_recv_message returned
		 * due to a fatal socket error. */
		isns_debug_socket("%s: msg not unlinked!\n", __FUNCTION__);
		isns_message_release(msg);
	}

	if (resp == NULL && sock->is_type == SOCK_STREAM)
		isns_net_close(sock, ISNS_SOCK_DISCONNECTED);

	return resp;
}

/*
 * Resolve a hostname
 */
struct addrinfo *
isns_get_address_list(const char *addrspec, const char *port,
		int af_hint, int sock_type, int flags)
{
	struct addrinfo hints, *found = NULL, *res = NULL;
	char	*copy = NULL, *host = NULL, *s;
	int	rv;

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_ADDRCONFIG;

	if (addrspec && addrspec[0] == '/') {
		if (af_hint != AF_LOCAL && af_hint != AF_UNSPEC) {
			isns_debug_socket("Path as address, but af_hint=%d\n",
					af_hint);
			goto bad_address;
		}

		res = make_addrinfo_unix(addrspec, SOCK_STREAM);
		goto out;
	}

	if (addrspec) {
		copy = host = isns_strdup(addrspec);
		if (*host == '[') {
			hints.ai_flags |= AI_NUMERICHOST;
			if ((s = strchr(host, ']')) == NULL)
				goto bad_address;

			*s++ = '\0';
			if (*s == ':')
				port = ++s;
			else if (*s)
				goto bad_address;
		} else if ((s = strchr(host, ':')) != NULL) {
			*s++ = '\0';
			if (!*s)
				goto bad_address;
			port = s;
		}

		if (*host == '\0')
			host = NULL;
	} else if (port == NULL) {
		/* Just wildcard */
		res = make_addrinfo_any(af_hint, sock_type);
		goto out;
	}

	hints.ai_family = af_hint;
	hints.ai_flags |= flags;
	hints.ai_socktype = sock_type;
	if (af_hint == AF_INET6)
		hints.ai_flags |= AI_V4MAPPED;

	rv = getaddrinfo(host, port, &hints, &found);
	if (rv) {
		isns_error("Cannot resolve address \"%s\": %s\n",
			addrspec, gai_strerror(rv));
		goto out;
	}

	if (found == NULL) {
		isns_error("No useable addresses returned.\n");
		goto out;
	}

	res = clone_addrinfo(found);

out:
	if (found)
		freeaddrinfo(found);
	isns_free(copy);
	return res;

bad_address:
	isns_error("Cannot parse address spec \"%s\"\n",
		addrspec);
	goto out;
}

int
isns_get_address(struct sockaddr_storage *result,
			const char *addrspec,
			const char *port,
			int af_hint, int sock_type, int flags)
{
	struct addrinfo	*ai;
	int alen;

	if (!(ai = isns_get_address_list(addrspec, port, af_hint, sock_type, flags)))
		return -1;

	alen = ai->ai_addrlen;
	if (alen > sizeof(*result))
		return -1;
	memcpy(result, ai->ai_addr, alen);
	release_addrinfo(ai);
	return alen;
}

/*
 * Get the canonical hostname
 */
char *
isns_get_canon_name(const char *hostname)
{
	struct addrinfo hints, *res = NULL;
	char	*fqdn = NULL;
	int	rv;

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_CANONNAME;

	rv = getaddrinfo(hostname, NULL, &hints, &res);
	if (rv) {
		isns_error("Cannot resolve hostname \"%s\": %s\n",
			hostname, gai_strerror(rv));
		goto out;
	}

	if (res == NULL) {
		isns_error("No useable addresses returned.\n");
		goto out;
	}


	fqdn = isns_strdup(res->ai_canonname);

out:
	if (res)
		freeaddrinfo(res);
	return fqdn;
}

int
isns_socket_get_local_addr(const isns_socket_t *sock,
		struct sockaddr_storage *addr)
{
	socklen_t	alen;

	if (sock->is_desc < 0)
		return 0;
	if (getsockname(sock->is_desc,
			(struct sockaddr *) addr, &alen) < 0) {
		isns_error("getsockname: %m\n");
		return 0;
	}

	return 1;
}

int
isns_socket_get_portal_info(const isns_socket_t *sock,
				isns_portal_info_t *portal)
{
	struct sockaddr_storage addr;
	socklen_t	alen;
	int		fd, success = 0;

	memset(portal, 0, sizeof(*portal));

	/* If the socket is currently closed (eg because the
	 * server shut down the connection), we cannot get the
	 * local address easily. Create a temporary UDP socket,
	 * connect it, and query that socket. */
	if ((fd = sock->is_desc) < 0) {
		const struct sockaddr *daddr;
		
		daddr = (struct sockaddr *) &sock->is_dst.addr;
		fd = socket(daddr->sa_family, SOCK_DGRAM, 0);
		if (fd < 0)
			goto out;
		if (connect(fd, daddr, sizeof(sock->is_dst.addr)) < 0)
			goto out;
	}

	alen = sizeof(addr);
	if (getsockname(fd, (struct sockaddr *) &addr, &alen) < 0) {
		isns_error("getsockname: %m\n");
		goto out;
	}

	if (!isns_portal_from_sockaddr(portal, &addr))
		goto out;
	if (sock->is_type == SOCK_STREAM)
		portal->proto = IPPROTO_TCP;
	else
		portal->proto = IPPROTO_UDP;

	debug_verbose("socket_get_portal: %s\n", isns_portal_string(portal));
	success = 1;

out:
	/* If we used a temp UDP socket, close it */
	if (fd >= 0 && fd != sock->is_desc)
		close(fd);
	return success;
}

isns_socket_t *
isns_socket_find_server(const isns_portal_info_t *portal)
{
	struct sockaddr_storage bound_addr;
	int sock_type, addr_len;
	isns_list_t *pos, *next;

	addr_len = isns_portal_to_sockaddr(portal, &bound_addr);
	if ((sock_type = isns_socket_type_from_portal(portal)) < 0)
		return NULL;

	isns_list_foreach(&all_sockets, pos, next) {
		isns_socket_t	*sock = isns_list_item(isns_socket_t, is_list, pos);

		if (!sock->is_client
		 && sock->is_type == sock_type
		 && sock->is_dst.addrlen == addr_len
		 && !memcmp(&sock->is_dst.addr, &bound_addr, addr_len)) {
			sock->is_users++;
			return sock;
		}
	}

	return NULL;
}

int
isns_addr_get_port(const struct sockaddr *addr)
{
	const struct sockaddr_in *sin;
	const struct sockaddr_in6 *six;

	switch (addr->sa_family) {
	case AF_INET:
		sin = (const struct sockaddr_in *) addr;
		return ntohs(sin->sin_port);

	case AF_INET6:
		six = (const struct sockaddr_in6 *) addr;
		return ntohs(six->sin6_port);
	}
	return 0;
}

void
isns_addr_set_port(struct sockaddr *addr, unsigned int port)
{
	struct sockaddr_in *sin;
	struct sockaddr_in6 *six;

	switch (addr->sa_family) {
	case AF_INET:
		sin = (struct sockaddr_in *) addr;
		sin->sin_port = htons(port);
		break;

	case AF_INET6:
		six = (struct sockaddr_in6 *) addr;
		six->sin6_port = htons(port);
		break;
	}
}
