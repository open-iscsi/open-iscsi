/*
 * iSCSI I/O Library
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
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/poll.h>
#include <sys/ioctl.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "types.h"
#include "iscsi_proto.h"
#include "initiator.h"
#include "iscsi_ipc.h"
#include "log.h"
#include "transport.h"
#include "idbm.h"
#include "iface.h"
#include "sysdeps.h"

#define LOG_CONN_CLOSED(conn) \
do { \
	getnameinfo((struct sockaddr *) &conn->saddr, sizeof(conn->saddr), \
		    conn->host, sizeof(conn->host), NULL, 0, NI_NUMERICHOST); \
	log_error("Connection to Discovery Address %s closed", conn->host); \
} while (0)

#define LOG_CONN_FAIL(conn) \
do { \
	getnameinfo((struct sockaddr *) &conn->saddr, sizeof(conn->saddr), \
		    conn->host, sizeof(conn->host), NULL, 0, NI_NUMERICHOST); \
	log_error("Connection to Discovery Address %s failed", conn->host); \
} while (0)

static int timedout;

static void
sigalarm_handler(int unused)
{
	timedout = 1;
}

static void
set_non_blocking(int fd)
{
	int res = fcntl(fd, F_GETFL);

	if (res != -1) {
		res = fcntl(fd, F_SETFL, res | O_NONBLOCK);
		if (res)
			log_warning("unable to set fd flags (%s)!",
				    strerror(errno));
	} else
		log_warning("unable to get fd flags (%s)!", strerror(errno));

}

#if 0
/* not used by anyone */
static int get_hwaddress_from_netdev(char *netdev, char *hwaddress)
{
	struct ifaddrs *ifap, *ifa;
	struct sockaddr_in *s4;
	struct sockaddr_in6 *s6;
	struct ifreq if_hwaddr;
	int found = 0, sockfd;
	unsigned char *hwaddr;
	char buf[INET6_ADDRSTRLEN];

	if (getifaddrs(&ifap)) {
		log_error("Could not match hwaddress %s to netdev. "
			  "getifaddrs failed %d", hwaddress, errno);
		return 0;
	}

	/* Open a basic socket. */
	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		log_error("Could not open socket for ioctl.");
		goto free_ifap;
	}

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		if (!ifa->ifa_addr)
			continue;

		switch (ifa->ifa_addr->sa_family) {
		case AF_INET:
			s4 = (struct sockaddr_in *)(ifa->ifa_addr);
			if (!inet_ntop(ifa->ifa_addr->sa_family,
				      (void *)&(s4->sin_addr), buf,
				      INET_ADDRSTRLEN))
				continue;
			log_debug(4, "name %s addr %s\n", ifa->ifa_name, buf);
			break;
		case AF_INET6:
			s6 = (struct sockaddr_in6 *)(ifa->ifa_addr);
			if (!inet_ntop(ifa->ifa_addr->sa_family,
			    (void *)&(s6->sin6_addr), buf, INET6_ADDRSTRLEN))
				continue;
			log_debug(4, "name %s addr %s\n", ifa->ifa_name, buf);
			break;
		default:
			continue;
		}

		if (strcmp(ifa->ifa_name, netdev))
			continue;

		strncpy(if_hwaddr.ifr_name, ifa->ifa_name, IFNAMSIZ);
		if (ioctl(sockfd, SIOCGIFHWADDR, &if_hwaddr) < 0) {
			log_error("Could not match %s to netdevice.",
				  hwaddress);
			continue;
		}

		/* check for ARPHRD_ETHER (ethernet) */
		if (if_hwaddr.ifr_hwaddr.sa_family != 1)
			continue;
		hwaddr = (unsigned char *)if_hwaddr.ifr_hwaddr.sa_data;

		memset(hwaddress, 0, ISCSI_MAX_IFACE_LEN);
		/* TODO should look and covert so we do not need tmp buf */
		sprintf(hwaddress, "%2.2x:%2.2x:%2.2x:%2.2x:%2.2x:%2.2x",
			hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3],
			hwaddr[4], hwaddr[5]);
		log_debug(4, "Found hardware address %s", hwaddress);
		found = 1;
		break;
	}

	close(sockfd);
free_ifap:
	freeifaddrs(ifap);
	return found;
}
#endif


#if 0

This is not supported for now, because it is not exactly what we want.
It also turns out that targets will send packets to other interfaces
causing all types of weird things to happen.


static int bind_src_by_address(int sockfd, char *address)
{
	int rc = 0;
	char port[NI_MAXSERV];
	struct sockaddr_storage saddr;

	memset(&saddr, 0, sizeof(struct sockaddr_storage));
	if (resolve_address(address, port, &saddr)) {
		log_error("Could not bind %s to conn.", address);
		return -1;
	}

	switch (saddr.ss_family) {
	case AF_INET:
		rc = bind(sockfd, (struct sockaddr *)&saddr,
			  sizeof(struct sockaddr_in));
		break;
	case AF_INET6:
		rc = bind(sockfd, (struct sockaddr *)&saddr,
			  sizeof(struct sockaddr_in6));
		break;
	default:
		rc = -1;
	}
	if (rc)
		log_error("Could not bind %s to %d.", address, sockfd);
	else
		log_debug(4, "Bound %s to socket fd %d", address, sockfd);
	return rc;
}
#endif

static int bind_conn_to_iface(iscsi_conn_t *conn, struct iface_rec *iface)
{
	struct iscsi_session *session = conn->session;

	memset(session->netdev, 0, IFNAMSIZ);
	if (iface_is_bound_by_hwaddr(iface) &&
	    net_get_netdev_from_hwaddress(iface->hwaddress, session->netdev)) {
		log_error("Cannot match %s to net/scsi interface.",
			  iface->hwaddress);
                return -1;
	} else if (iface_is_bound_by_netdev(iface))
		strcpy(session->netdev, iface->netdev);
	else if (iface_is_bound_by_ipaddr(iface)) {
		/*
		 * we never supported this but now with offload having to
		 * set the ip address in the iface, useris may forget to
		 * set the offload's transport type and we end up here by
		 * accident.
		 */
		log_error("Cannot bind %s to net/scsi interface. This is not "
			  "supported with software iSCSI (iscsi_tcp).",
			   iface->ipaddress);
		return -1;
	}

	if (strlen(session->netdev)) {
		struct ifreq ifr;

		log_debug(4, "Binding session %d to %s", session->id,
			  session->netdev);
		memset(&ifr, 0, sizeof(ifr));
		strlcpy(ifr.ifr_name, session->netdev, IFNAMSIZ);

		if (setsockopt(conn->socket_fd, SOL_SOCKET, SO_BINDTODEVICE,
			       session->netdev,
			       strlen(session->netdev) + 1) < 0) {
			log_error("Could not bind connection %d to %s\n",
				  conn->id, session->netdev);
			return -1;
		}
	}

	return 0;
}

int
iscsi_io_tcp_connect(iscsi_conn_t *conn, int non_blocking)
{
	int rc, onearg;
	struct sockaddr_storage *ss = &conn->saddr;
	char serv[NI_MAXSERV];

	/* create a socket */
	conn->socket_fd = socket(ss->ss_family, SOCK_STREAM, IPPROTO_TCP);

	/* the trasport ep handle is used to bind with */
	conn->transport_ep_handle = conn->socket_fd;

	if (conn->socket_fd < 0) {
		log_error("cannot create TCP socket");
		return -1;
	}

	if (conn->session) {
		if (bind_conn_to_iface(conn, &conn->session->nrec.iface))
			return -1;
	}

	onearg = 1;
	rc = setsockopt(conn->socket_fd, IPPROTO_TCP, TCP_NODELAY, &onearg,
			sizeof (onearg));
	if (rc < 0) {
		log_error("cannot set TCP_NODELAY option on socket");
		close(conn->socket_fd);
		conn->socket_fd = -1;
		return rc;
	}

	/* optionally set the window sizes */
	if (conn->tcp_window_size) {
		int window_size = conn->tcp_window_size;
		socklen_t arglen = sizeof (window_size);

		if (setsockopt(conn->socket_fd, SOL_SOCKET, SO_RCVBUF,
		       (char *) &window_size, sizeof (window_size)) < 0) {
			log_warning("failed to set TCP recv window size "
				    "to %u", window_size);
		} else {
			if (getsockopt(conn->socket_fd, SOL_SOCKET, SO_RCVBUF,
				       (char *) &window_size, &arglen) >= 0) {
				log_debug(4, "set TCP recv window size to %u, "
					  "actually got %u",
					  conn->tcp_window_size, window_size);
			}
		}

		window_size = conn->tcp_window_size;
		arglen = sizeof (window_size);

		if (setsockopt(conn->socket_fd, SOL_SOCKET, SO_SNDBUF,
		       (char *) &window_size, sizeof (window_size)) < 0) {
			log_warning("failed to set TCP send window size "
				    "to %u", window_size);
		} else {
			if (getsockopt(conn->socket_fd, SOL_SOCKET, SO_SNDBUF,
				       (char *) &window_size, &arglen) >= 0) {
				log_debug(4, "set TCP send window size to %u, "
					  "actually got %u",
					  conn->tcp_window_size, window_size);
			}
		}
	}

	/*
	 * Build a TCP connection to the target
	 */
	getnameinfo((struct sockaddr *) ss, sizeof(*ss),
		    conn->host, sizeof(conn->host), serv, sizeof(serv),
		    NI_NUMERICHOST|NI_NUMERICSERV);

	log_debug(1, "connecting to %s:%s", conn->host, serv);
	if (non_blocking)
		set_non_blocking(conn->socket_fd);
	rc = connect(conn->socket_fd, (struct sockaddr *) ss, sizeof (*ss));
	return rc;
}

int
iscsi_io_tcp_poll(iscsi_conn_t *conn, int timeout_ms)
{
	int rc;
	struct pollfd pdesc;
	char serv[NI_MAXSERV], lserv[NI_MAXSERV];
	struct sockaddr_storage ss;
	socklen_t len = sizeof(ss);

	pdesc.fd = conn->socket_fd;
	pdesc.events = POLLOUT;
	rc = poll(&pdesc, 1, timeout_ms);
	if (rc == 0)
		return 0;

	if (rc < 0) {
		getnameinfo((struct sockaddr *) &conn->saddr,
			    sizeof(conn->saddr),
			    conn->host, sizeof(conn->host), serv, sizeof(serv),
			    NI_NUMERICHOST|NI_NUMERICSERV);

		log_error("cannot make connection to %s:%s (%s)",
			  conn->host, serv, strerror(errno));
		return rc;
	}

	len = sizeof(int);
	if (getsockopt(conn->socket_fd, SOL_SOCKET, SO_ERROR,
			(char *) &rc, &len) < 0) {
		log_error("getsockopt for connect poll failed\n");
		return -1;
	}
	if (rc) {
		getnameinfo((struct sockaddr *) &conn->saddr,
			    sizeof(conn->saddr),
			    conn->host, sizeof(conn->host), serv, sizeof(serv),
			    NI_NUMERICHOST|NI_NUMERICSERV);

		log_error("connect to %s:%s failed (%s)\n",
			  conn->host, serv, strerror(rc));
		return -rc;
	}

	len = sizeof(ss);
	if (log_level > 0 &&
	    getsockname(conn->socket_fd, (struct sockaddr *) &ss, &len) >= 0) {
		getnameinfo((struct sockaddr *) &conn->saddr,
			    sizeof(conn->saddr), conn->host,
			    sizeof(conn->host), serv, sizeof(serv),
			    NI_NUMERICHOST|NI_NUMERICSERV);

		getnameinfo((struct sockaddr *) &ss, sizeof(ss),
			     NULL, 0, lserv, sizeof(lserv), NI_NUMERICSERV);

		log_debug(1, "connected local port %s to %s:%s",
			  lserv, conn->host, serv);
	}
	return 1;
}

void
iscsi_io_tcp_disconnect(iscsi_conn_t *conn)
{
	if (conn->socket_fd >= 0) {
		log_debug(1, "disconnecting conn %p, fd %d", conn,
			 conn->socket_fd);
		close(conn->socket_fd);
		conn->socket_fd = -1;
	}
}

int
iscsi_io_connect(iscsi_conn_t *conn)
{
	int rc, ret;
	struct sigaction action;
	struct sigaction old;
	char serv[NI_MAXSERV];

	/* set a timeout, since the socket calls may take a long time to
	 * timeout on their own
	 */
	memset(&action, 0, sizeof (struct sigaction));
	memset(&old, 0, sizeof (struct sigaction));
	action.sa_sigaction = NULL;
	action.sa_flags = 0;
	action.sa_handler = sigalarm_handler;
	sigaction(SIGALRM, &action, &old);
	timedout = 0;
	alarm(conn->login_timeout);

	/* perform blocking TCP connect operation when no async request
	 * associated. SendTargets Discovery know to work in such a mode.
	 */
	rc = iscsi_io_tcp_connect(conn, 0);
	if (timedout) {
		log_debug(1, "socket %d connect timed out", conn->socket_fd);
		ret = 0;
		goto done;
	} else if (rc < 0) {
		getnameinfo((struct sockaddr *) &conn->saddr,
			    sizeof(conn->saddr),
			    conn->host, sizeof(conn->host), serv, sizeof(serv),
			    NI_NUMERICHOST|NI_NUMERICSERV);
		log_error("cannot make connection to %s:%s (%d)",
			  conn->host, serv, errno);
		close(conn->socket_fd);
		ret = 0;
		goto done;
	} else if (log_level > 0) {
		struct sockaddr_storage ss;
		char lserv[NI_MAXSERV];
		socklen_t salen = sizeof(ss);

		if (getsockname(conn->socket_fd, (struct sockaddr *) &ss,
				&salen) >= 0) {
			getnameinfo((struct sockaddr *) &conn->saddr,
				    sizeof(conn->saddr),
				    conn->host, sizeof(conn->host), serv,
				    sizeof(serv), NI_NUMERICHOST|NI_NUMERICSERV);

			getnameinfo((struct sockaddr *) &ss,
				    sizeof(ss),
				    NULL, 0, lserv, sizeof(lserv),
				    NI_NUMERICSERV);

			log_debug(1, "connected local port %s to %s:%s",
				  lserv, conn->host, serv);
		}
	}

	ret = 1;

done:
	alarm(0);
	sigaction(SIGALRM, &old, NULL);
	return ret;
}

void
iscsi_io_disconnect(iscsi_conn_t *conn)
{
	iscsi_io_tcp_disconnect(conn);
}

static void
iscsi_log_text(struct iscsi_hdr *pdu, char *data)
{
	int dlength = ntoh24(pdu->dlength);
	char *text = data;
	char *end = text + dlength;

	while (text && (text < end)) {
		log_debug(4, ">    %s", text);
		text += strlen(text);
		while ((text < end) && (*text == '\0'))
			text++;
	}
}

int
iscsi_io_send_pdu(iscsi_conn_t *conn, struct iscsi_hdr *hdr,
	       int hdr_digest, char *data, int data_digest, int timeout)
{
	int rc, ret = 0;
	char *header = (char *) hdr;
	char *end;
	char pad[4];
	struct iovec vec[3];
	int pad_bytes;
	int pdu_length = sizeof (*hdr) + hdr->hlength + ntoh24(hdr->dlength);
	int remaining;
	struct sigaction action;
	struct sigaction old;
	iscsi_session_t *session = conn->session;

	/* set a timeout, since the socket calls may take a long time
	 * to timeout on their own
	 */
	if (!ipc) {
		memset(&action, 0, sizeof (struct sigaction));
		memset(&old, 0, sizeof (struct sigaction));
		action.sa_sigaction = NULL;
		action.sa_flags = 0;
		action.sa_handler = sigalarm_handler;
		sigaction(SIGALRM, &action, &old);
		timedout = 0;
		alarm(timeout);
	}

	memset(&pad, 0, sizeof (pad));
	memset(&vec, 0, sizeof (vec));

	switch (hdr->opcode & ISCSI_OPCODE_MASK) {
	case ISCSI_OP_LOGIN:{
		struct iscsi_login *login_hdr = (struct iscsi_login *) hdr;

		log_debug(4, "sending login PDU with current stage "
			 "%d, next stage %d, transit 0x%x, isid"
			 " 0x%02x%02x%02x%02x%02x%02x exp_statsn %u",
			 ISCSI_LOGIN_CURRENT_STAGE(login_hdr->flags),
			 ISCSI_LOGIN_NEXT_STAGE(login_hdr->flags),
			 login_hdr->flags & ISCSI_FLAG_LOGIN_TRANSIT,
			 login_hdr->isid[0], login_hdr->isid[1],
			 login_hdr->isid[2], login_hdr->isid[3],
			 login_hdr->isid[4], login_hdr->isid[5],
			 ntohl(login_hdr->exp_statsn));

			iscsi_log_text(hdr, data);
		break;
	}
	case ISCSI_OP_TEXT:{
		struct iscsi_text *text_hdr = (struct iscsi_text *) hdr;

		log_debug(4, "sending text pdu with CmdSN %x, exp_statsn %u",
			 ntohl(text_hdr->cmdsn), ntohl(text_hdr->cmdsn));
		iscsi_log_text(hdr, data);
		break;
	}
	case ISCSI_OP_NOOP_OUT:{
		struct iscsi_nopout *nopout_hdr = (struct iscsi_nopout *) hdr;

		log_debug(4, "sending Nop-out pdu with ttt %x, CmdSN %x:",
			 ntohl(nopout_hdr->ttt), ntohl(nopout_hdr->cmdsn));
		iscsi_log_text(hdr, data);
		break;
	}
	default:
		log_debug(4, "sending pdu opcode 0x%x:", hdr->opcode);
		break;
	}

	/* send the PDU header */
	header = (char *) hdr;
	end = header + sizeof (*hdr) + hdr->hlength;

	/* send all the data and any padding */
	if (pdu_length % ISCSI_PAD_LEN)
		pad_bytes = ISCSI_PAD_LEN - (pdu_length % ISCSI_PAD_LEN);
	else
		pad_bytes = 0;

	if (ipc)
		ipc->send_pdu_begin(session->t->handle, session->id,
				    conn->id, end - header,
				    ntoh24(hdr->dlength) + pad_bytes);

	while (header < end) {
		vec[0].iov_base = header;
		vec[0].iov_len = end - header;

		if (!ipc)
			rc = writev(session->ctrl_fd, vec, 1);
		else
			rc = ipc->writev(0, vec, 1);
		if (timedout) {
			log_error("socket %d write timed out",
			       conn->socket_fd);
			ret = 0;
			goto done;
		} else if ((rc <= 0) && (errno != EAGAIN)) {
			LOG_CONN_FAIL(conn);
			ret = 0;
			goto done;
		} else if (rc > 0) {
			log_debug(4, "wrote %d bytes of PDU header", rc);
			header += rc;
		}
	}

	end = data + ntoh24(hdr->dlength);
	remaining = ntoh24(hdr->dlength) + pad_bytes;

	while (remaining > 0) {
		vec[0].iov_base = data;
		vec[0].iov_len = end - data;
		vec[1].iov_base = (void *) &pad;
		vec[1].iov_len = pad_bytes;

		if (!ipc)
			rc = writev(session->ctrl_fd, vec, 2);
		else
			rc = ipc->writev(0, vec, 2);
		if (timedout) {
			log_error("socket %d write timed out",
			       conn->socket_fd);
			ret = 0;
			goto done;
		} else if ((rc <= 0) && (errno != EAGAIN)) {
			LOG_CONN_FAIL(conn);
			ret = 0;
			goto done;
		} else if (rc > 0) {
			log_debug(4, "wrote %d bytes of PDU data", rc);
			remaining -= rc;
			if (data < end) {
				data += rc;
				if (data > end)
					data = end;
			}
		}
	}

	if (ipc) {
		if (ipc->send_pdu_end(session->t->handle, session->id,
				      conn->id, &rc)) {
			ret = 0;
			goto done;
		}
	}

	ret = 1;

      done:
	if (!ipc) {
		alarm(0);
		sigaction(SIGALRM, &old, NULL);
		timedout = 0;
	}
	return ret;
}

int
iscsi_io_recv_pdu(iscsi_conn_t *conn, struct iscsi_hdr *hdr,
	       int hdr_digest, char *data, int max_data_length, int data_digest,
	       int timeout)
{
	uint32_t h_bytes = 0;
	uint32_t ahs_bytes = 0;
	uint32_t d_bytes = 0;
	uint32_t ahslength = 0;
	uint32_t dlength = 0;
	uint32_t pad = 0;
	int rlen = 0;
	int failed = 0;
	char *header = (char *) hdr;
	char *end = data + max_data_length;
	struct sigaction action;
	struct sigaction old;
	iscsi_session_t *session = conn->session;

	memset(data, 0, max_data_length);

	/* set a timeout, since the socket calls may take a long
	 * time to timeout on their own
	 */
	if (!ipc) {
		memset(&action, 0, sizeof (struct sigaction));
		memset(&old, 0, sizeof (struct sigaction));
		action.sa_sigaction = NULL;
		action.sa_flags = 0;
		action.sa_handler = sigalarm_handler;
		sigaction(SIGALRM, &action, &old);
		timedout = 0;
		alarm(timeout);
	} else {
		if (ipc->recv_pdu_begin(conn)) {
			failed = 1;
			goto done;
		}
	}

	/* read a response header */
	do {
		if (!ipc)
			rlen = read(session->ctrl_fd, header,
					sizeof (*hdr) - h_bytes);
		else
			rlen = ipc->read(header, sizeof (*hdr) - h_bytes);
		if (timedout) {
			log_error("socket %d header read timed out",
			       conn->socket_fd);
			failed = 1;
			goto done;
		} else if (rlen == 0) {
			LOG_CONN_CLOSED(conn);
			failed = 1;
			goto done;
		} else if ((rlen < 0) && (errno != EAGAIN)) {
			LOG_CONN_FAIL(conn);
			failed = 1;
			goto done;
		} else if (rlen > 0) {
			log_debug(4, "read %d bytes of PDU header", rlen);
			header += rlen;
			h_bytes += rlen;
		}
	} while (h_bytes < sizeof (*hdr));

	log_debug(4, "read %d PDU header bytes, opcode 0x%x, dlength %u, "
		 "data %p, max %u", h_bytes, hdr->opcode,
		 ntoh24(hdr->dlength), data, max_data_length);

	/* check for additional headers */
	ahslength = hdr->hlength;	/* already includes padding */
	if (ahslength) {
		log_warning("additional header segment length %u not supported",
		       ahslength);
		failed = 1;
		goto done;
	}

	/* read exactly what we expect, plus padding */
	dlength = hdr->dlength[0] << 16;
	dlength |= hdr->dlength[1] << 8;
	dlength |= hdr->dlength[2];

	/* if we only expected to receive a header, exit */
	if (dlength == 0)
		goto done;

	if (data + dlength > end) {
		log_warning("buffer size %u too small for data length %u",
		       max_data_length, dlength);
		failed = 1;
		goto done;
	}

	/* read the rest into our buffer */
	d_bytes = 0;
	while (d_bytes < dlength) {
		if (!ipc)
			rlen = read(session->ctrl_fd, data + d_bytes,
					dlength - d_bytes);
		else
			rlen = ipc->read(data + d_bytes, dlength - d_bytes);
		if (timedout) {
			log_error("socket %d data read timed out",
			       conn->socket_fd);
			failed = 1;
			goto done;
		} else if (rlen == 0) {
			LOG_CONN_CLOSED(conn);
			failed = 1;
			goto done;
		} else if ((rlen < 0 && errno != EAGAIN)) {
			LOG_CONN_FAIL(conn);
			failed = 1;
			goto done;
		} else if (rlen > 0) {
			log_debug(4, "read %d bytes of PDU data", rlen);
			d_bytes += rlen;
		}
	}

	/* handle PDU data padding.
	 * data is padded in case of kernel_io */
	pad = dlength % ISCSI_PAD_LEN;
	if (pad && !ipc) {
		int pad_bytes = pad = ISCSI_PAD_LEN - pad;
		char bytes[ISCSI_PAD_LEN];

		while (pad_bytes > 0) {
			rlen = read(conn->socket_fd, &bytes, pad_bytes);
			if (timedout) {
				log_error("socket %d pad read timed out",
				       conn->socket_fd);
				failed = 1;
				goto done;
			} else if (rlen == 0) {
				LOG_CONN_CLOSED(conn);
				failed = 1;
				goto done;
			} else if ((rlen < 0 && errno != EAGAIN)) {
				LOG_CONN_FAIL(conn);
				failed = 1;
				goto done;
			} else if (rlen > 0) {
				log_debug(4, "read %d pad bytes", rlen);
				pad_bytes -= rlen;
			}
		}
	}

	switch (hdr->opcode) {
	case ISCSI_OP_TEXT_RSP:
		log_debug(4, "finished reading text PDU, %u hdr, %u "
			 "ah, %u data, %u pad",
			 h_bytes, ahs_bytes, d_bytes, pad);
		iscsi_log_text(hdr, data);
		break;
	case ISCSI_OP_LOGIN_RSP:{
		struct iscsi_login_rsp *login_rsp =
			    (struct iscsi_login_rsp *) hdr;

		log_debug(4, "finished reading login PDU, %u hdr, "
			 "%u ah, %u data, %u pad",
			  h_bytes, ahs_bytes, d_bytes, pad);
		log_debug(4, "login current stage %d, next stage "
			 "%d, transit 0x%x",
			 ISCSI_LOGIN_CURRENT_STAGE(login_rsp->flags),
			 ISCSI_LOGIN_NEXT_STAGE(login_rsp->flags),
			 login_rsp->flags & ISCSI_FLAG_LOGIN_TRANSIT);
		iscsi_log_text(hdr, data);
		break;
	}
	case ISCSI_OP_ASYNC_EVENT:
		/* FIXME: log the event info */
		break;
	default:
		break;
	}

done:
	if (!ipc) {
		alarm(0);
		sigaction(SIGALRM, &old, NULL);
	} else {
		/* finalyze receive transaction */
		if (ipc->recv_pdu_end(conn)) {
			failed = 1;
		}
	}

	if (timedout || failed) {
		timedout = 0;
		return 0;
	}

	return h_bytes + ahs_bytes + d_bytes;
}
