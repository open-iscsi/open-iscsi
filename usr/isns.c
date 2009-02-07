/*
 * iSNS functions
 *
 * Copyright (C) 2006 FUJITA Tomonori <tomof@acm.org>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>

#include "initiator.h"
#include "idbm.h"
#include "log.h"
#include "util.h"
#include "isns_proto.h"
#include "sysdeps.h"

enum isns_task_state {
	ISNS_TASK_WAIT_CONN,
	ISNS_TASK_SEND_PDU,
	ISNS_TASK_RECV_PDU,
};

struct isns_task {
	int state;
	int fd;
	int len;
	char data[ISCSI_DEF_MAX_RECV_SEG_LEN];
	int transaction;
	int done;
	int retry;
	queue_task_t *qtask;
	struct actor actor;
};

static struct sockaddr_storage ss;
static uint16_t transaction;

static char isns_address[NI_MAXHOST];
static int isns_port = 3205, isns_listen_port, max_retry = 10000;

static void isns_poll(void *data);

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

#define get_hdr_param(hdr, function, length, flags, transaction, sequence)	\
{										\
	function = ntohs(hdr->function);					\
	length = ntohs(hdr->length);						\
	flags = ntohs(hdr->flags);						\
	transaction = ntohs(hdr->transaction);					\
	sequence = ntohs(hdr->sequence);					\
}

/* use io.c */
static int set_non_blocking(int fd)
{
	int res = fcntl(fd, F_GETFL);

	if (res == -1)
		log_warning("unable to get fd flags %m");
	else {
		res = fcntl(fd, F_SETFL, res | O_NONBLOCK);
		if (res)
			log_warning("unable to set fd flags %m");
	}

	return res;
}

static void
isns_hdr_init(struct isns_hdr *hdr, uint16_t function, uint16_t length,
	      uint16_t flags, uint16_t trans, uint16_t sequence)
{
	hdr->version = htons(0x0001);
	hdr->function = htons(function);
	hdr->length = htons(length);
	hdr->flags = htons(flags);
	hdr->transaction = htons(trans);
	hdr->sequence = htons(sequence);
}

static int
isns_tlv_set(struct isns_tlv **tlv, uint32_t tag, uint32_t length, void *value)
{
	if (length)
		memcpy((*tlv)->value, value, length);
	if (length % ISNS_ALIGN)
		length += (ISNS_ALIGN - (length % ISNS_ALIGN));

	(*tlv)->tag = htonl(tag);
	(*tlv)->length = htonl(length);

	length += sizeof(struct isns_tlv);
	*tlv = (struct isns_tlv *) ((char *) *tlv + length);

	return length;
}

static void build_dev_reg_req(struct isns_task *task)
{
	struct isns_hdr *hdr = (struct isns_hdr *) task->data;
	struct isns_tlv *tlv = (struct isns_tlv *) hdr->pdu;
	struct sockaddr_storage lss;
	static uint8_t ip[16];
	char eid[NI_MAXHOST];
	char *name = dconfig->initiator_name;
	char *alias = dconfig->initiator_alias;
	socklen_t slen = sizeof(lss);
	int i;
	uint16_t flags = 0, length = 0;
	uint32_t addr;
	uint32_t port;
	uint32_t node = htonl(ISNS_NODE_INITIATOR);
	uint32_t type = htonl(2);

	memset(hdr, 0, sizeof(task->data));

	getsockname(task->fd, (struct sockaddr *) &lss, &slen);
	getnameinfo((struct sockaddr *) &lss, sizeof(lss), eid, sizeof(eid),
		    NULL, 0, 0);

	switch (lss.ss_family) {
	case AF_INET:
		addr = (((struct sockaddr_in *) &lss)->sin_addr.s_addr);

		ip[10] = ip[11] = 0xff;
		ip[15] = 0xff & (addr >> 24);
		ip[14] = 0xff & (addr >> 16);
		ip[13] = 0xff & (addr >> 8);
		ip[12] = 0xff & addr;
		port = ((struct sockaddr_in *) &lss)->sin_port;
		break;
	case AF_INET6:
		for (i = 0; i < ARRAY_SIZE(ip); i++)
			ip[i] = ((struct sockaddr_in6 *) &lss)->sin6_addr.s6_addr[i];
		break;
		port = ((struct sockaddr_in6 *) &lss)->sin6_port;
	}

	port = htonl(ntohs(port));

        length += isns_tlv_set(&tlv, ISNS_ATTR_ISCSI_NAME, strlen(name), name);
	length += isns_tlv_set(&tlv, ISNS_ATTR_ENTITY_IDENTIFIER,
			       strlen(eid), eid);
	length += isns_tlv_set(&tlv, 0, 0, 0);
	length += isns_tlv_set(&tlv, ISNS_ATTR_ENTITY_IDENTIFIER,
			       strlen(eid), eid);

	length += isns_tlv_set(&tlv, ISNS_ATTR_ENTITY_PROTOCOL,
			       sizeof(type), &type);
	length += isns_tlv_set(&tlv, ISNS_ATTR_PORTAL_IP_ADDRESS,
			       sizeof(ip), &ip);
	length += isns_tlv_set(&tlv, ISNS_ATTR_PORTAL_PORT,
			       sizeof(port), &port);
	flags = ISNS_FLAG_REPLACE;

	port = htonl(isns_listen_port);
	length += isns_tlv_set(&tlv, ISNS_ATTR_ESI_PORT,
			       sizeof(port), &port);

	length += isns_tlv_set(&tlv, ISNS_ATTR_ISCSI_NAME, strlen(name), name);
	length += isns_tlv_set(&tlv, ISNS_ATTR_ISCSI_NODE_TYPE,
			       sizeof(node), &node);
	if(alias)
		 length += isns_tlv_set(&tlv, ISNS_ATTR_ISCSI_ALIAS,
					strlen(alias), alias);

	flags |= ISNS_FLAG_CLIENT | ISNS_FLAG_LAST_PDU | ISNS_FLAG_FIRST_PDU;
	task->transaction = ++transaction;
	isns_hdr_init(hdr, ISNS_FUNC_DEV_ATTR_REG, length, flags,
		      task->transaction, 0);

	task->len = length + sizeof(*hdr);
}

static int isns_connect(void)
{
	int err;
	int fd;

	fd = socket(ss.ss_family, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0) {
		log_error("can't create socket %m");
		return -errno;
	}

	err = set_non_blocking(fd);
	if (err) {
		log_error("can't set non-blocking %m");
		close(fd);
		return -errno;
	}

	err = connect(fd, (struct sockaddr *) &ss, sizeof(ss));
	if (err && errno != EINPROGRESS) {
		log_error("can't connect %m");
		close(fd);
		return -errno;
	}
	return fd;
}

static int isns_send_pdu(struct isns_task *task)
{
	int err;

	err = write(task->fd, task->data + task->done, task->len - task->done);
	if (err < 0) {
		if (errno != EINTR && errno != EAGAIN && errno != EINPROGRESS) {
			log_error("send fail %m");
			return -1;
		}
	} else
		task->done += err;

	return 0;
}
static void isns_free_task(struct isns_task *task)
{
	close(task->fd);
	free(task);
}

static int isns_recv_pdu(struct isns_task *task)
{
	struct isns_hdr *hdr = (struct isns_hdr *) task->data;
	uint16_t function, length, flags, transaction, sequence;
	int err, size;

	if (task->done < sizeof(*hdr))
		size = sizeof(*hdr) - task->done;
	else
		size = task->len + sizeof(*hdr) - task->done;

	err = read(task->fd, task->data + task->done, size);
	if (err <= 0) {
		if (errno != EINTR && errno != EAGAIN && errno != EINPROGRESS) {
			log_error("send fail %m");
			return -1;
		}
	} else {
		task->done += err;

		if (task->done == sizeof(*hdr)) {
			get_hdr_param(hdr, function, length, flags, transaction,
				      sequence);
			task->len = length;
		}
	}
	return 0;
}

static char *isns_get_config_file(void)
{
	return dconfig->config_file;
}

static void add_new_target_node(char *targetname, uint8_t *ip, int port,
				int tag)
{
	int err;
	node_rec_t rec;
	discovery_rec_t drec;
	char dst[INET6_ADDRSTRLEN];

	memset(dst, 0, sizeof(dst));
	/*
	 * some servers are sending compat instead of mapped
	 */
	if (IN6_IS_ADDR_V4MAPPED(ip) || IN6_IS_ADDR_V4COMPAT(ip))
		inet_ntop(AF_INET, ip + 12, dst, sizeof(dst));
	else
		inet_ntop(AF_INET6, ip, dst, sizeof(dst));

	log_debug(1, "add a new target node:%s %s,%d %d",
		  targetname, dst, port, tag);

	if (idbm_init(isns_get_config_file)) {
		log_error("Could not add new target node:%s %s,%d",
			  targetname, dst, port);
		return;
	}
	idbm_node_setup_from_conf(&rec);
	strlcpy(rec.name, targetname, TARGET_NAME_MAXLEN);
	rec.conn[0].port = port;
	rec.tpgt = tag;
	strlcpy(rec.conn[0].address, dst, NI_MAXHOST);

	/* TODO?: shoudl we set the address and port of the server ? */
	memset(&drec, 0, sizeof(discovery_rec_t));
	drec.type = DISCOVERY_TYPE_ISNS;
	err = idbm_add_nodes(&rec, &drec, NULL, 0);
	if (err)
		log_error("Could not add new target node:%s %s,%d",
			  targetname, dst, port);

	idbm_terminate();
}

static int qry_rsp_handle(struct isns_hdr *hdr)
{
	struct isns_tlv *tlv;
	uint16_t function, length, flags, transaction, sequence;
	uint32_t port, tag, status;
	uint8_t *addr;
	char *name;

	get_hdr_param(hdr, function, length, flags, transaction, sequence);

	status = (uint32_t) (*hdr->pdu);
	if (status)
		return status;

	/* skip status */
	tlv = (struct isns_tlv *) ((char *) hdr->pdu + 4);
	length -= 4;

	/* check node type in the message key*/
	if ((ntohl(tlv->tag) != ISNS_ATTR_ISCSI_NODE_TYPE) ||
	    ntohl(*(tlv->value)) != ISNS_NODE_TARGET)
		return EINVAL;

	/* 12 + 8 bytes */
	length -= (sizeof(*tlv) + 4 + 8);
	if (length <= 0) {
		log_error("No target found.");
		return EINVAL;
	}

	tlv = (struct isns_tlv *) ((char *) tlv + 20);

	name = NULL;
	addr = NULL;
	port = tag = 0;

	/* FIXME: this assume the exact order. */
	while (length) {
		uint32_t vlen = ntohl(tlv->length);

		switch (ntohl(tlv->tag)) {
		case ISNS_ATTR_PG_ISCSI_NAME:
			if (name && addr) {
				add_new_target_node(name, addr, port, tag);
				name = NULL;
				addr = NULL;
			}
			name = (char *) tlv->value;
			break;
		case ISNS_ATTR_ISCSI_NODE_TYPE:
			if (ntohl(*(tlv->value)) != ISNS_NODE_TARGET)
				name = NULL;
			break;
		case ISNS_ATTR_PG_PORTAL_IP_ADDRESS:
			addr = (uint8_t *) tlv->value;
			break;
		case ISNS_ATTR_PG_PORTAL_PORT:
			port = ntohl(tlv->value[0]);
			break;
		case ISNS_ATTR_PG_TAG:
			tag = ntohl(tlv->value[0]);
			break;
		case ISNS_ATTR_ISCSI_NAME:
		case ISNS_ATTR_PORTAL_IP_ADDRESS:
		case ISNS_ATTR_PORTAL_PORT:
			break;
		default:
			log_error("unexpected type %d", ntohl(tlv->tag));
			break;
		}

		length -= (sizeof(*tlv) + vlen);
		tlv = (struct isns_tlv *) ((char *) tlv->value + vlen);
	}

	if (name && addr)
		add_new_target_node(name, addr, port, tag);

	return 0;
}

static void send_mgmt_rsp(struct isns_task *task, int err)
{
	mgmt_ipc_write_rsp(task->qtask,
			  err ? MGMT_IPC_ERR_ISNS_UNAVAILABLE : MGMT_IPC_OK);
}

static int isns_task_done(struct isns_task *task)
{
	struct isns_hdr *hdr = (struct isns_hdr *) task->data;
	uint16_t function, length, flags, transaction, sequence;
	uint32_t status = (uint32_t) (*hdr->pdu);
	char *payload = (char *) hdr + sizeof(*hdr);
	int finished = 1;

	get_hdr_param(hdr, function, length, flags, transaction,
		      sequence);

	if (function & 0x8000 && status)
		log_error("error isns response %x %x", function, status);

	switch (function) {
	case ISNS_FUNC_DEV_ATTR_REG_RSP:
		break;
	case ISNS_FUNC_DEV_ATTR_QRY_RSP:
		if (!status)
			qry_rsp_handle((struct isns_hdr *)task->data);
		send_mgmt_rsp(task, status);
		break;
	case ISNS_FUNC_ESI:
		memmove(payload + 4, payload, length);
		*((uint32_t *) payload) = 0;

		length += 4;
		flags = ISNS_FLAG_CLIENT | ISNS_FLAG_LAST_PDU |
			ISNS_FLAG_FIRST_PDU;
		isns_hdr_init(hdr, ISNS_FUNC_ESI_RSP, length, flags,
			      transaction, 0);
		task->state = ISNS_TASK_SEND_PDU;
		task->len = length + sizeof(*hdr);
		task->done = 0;

		actor_new(&task->actor, isns_poll, task);
		actor_schedule(&task->actor);
		finished = 0;
		break;
	default:
		log_error("unexpected function %d", function);
		break;
	}

	return finished;
}

int isns_dev_attr_query_task(queue_task_t *qtask)
{
	int fd;
	struct isns_hdr *hdr;
	struct isns_tlv *tlv;
	char *name = dconfig->initiator_name;
	uint16_t flags, length = 0;
	uint32_t node = htonl(ISNS_NODE_TARGET);
	struct isns_task *task;

	if (!strlen(isns_address))
		return MGMT_IPC_ERR_ISNS_UNAVAILABLE;

	fd = isns_connect();
	if (fd < 0) {
		log_error("%s %m", __FUNCTION__);
		return MGMT_IPC_ERR_ISNS_UNAVAILABLE;
	}

	task = malloc(sizeof(*task));
	if (!task) {
		log_error("%s %m", __FUNCTION__);
		close(fd);
		return MGMT_IPC_ERR_NOMEM;
	}
	memset(task, 0, sizeof(*task));

	task->qtask = qtask;
	task->fd = fd;

	hdr = (struct isns_hdr *) task->data;
	tlv = (struct isns_tlv *) hdr->pdu;

	memset(hdr, 0, sizeof(task->data));

	length += isns_tlv_set(&tlv, ISNS_ATTR_ISCSI_NAME, strlen(name), name);
	length += isns_tlv_set(&tlv, ISNS_ATTR_ISCSI_NODE_TYPE,
			       sizeof(node), &node);
	length += isns_tlv_set(&tlv, 0, 0, 0);
	length += isns_tlv_set(&tlv, ISNS_ATTR_ISCSI_NAME, 0, 0);
	length += isns_tlv_set(&tlv, ISNS_ATTR_ISCSI_NODE_TYPE, 0, 0);
	length += isns_tlv_set(&tlv, ISNS_ATTR_PORTAL_IP_ADDRESS, 0, 0);
	length += isns_tlv_set(&tlv, ISNS_ATTR_PORTAL_PORT, 0, 0);
	length += isns_tlv_set(&tlv, ISNS_ATTR_PG_ISCSI_NAME, 0, 0);
	length += isns_tlv_set(&tlv, ISNS_ATTR_PG_PORTAL_IP_ADDRESS, 0, 0);
	length += isns_tlv_set(&tlv, ISNS_ATTR_PG_PORTAL_PORT, 0, 0);
	length += isns_tlv_set(&tlv, ISNS_ATTR_PG_TAG, 0, 0);

	flags = ISNS_FLAG_CLIENT | ISNS_FLAG_LAST_PDU | ISNS_FLAG_FIRST_PDU;
	task->transaction = ++transaction;
	isns_hdr_init(hdr, ISNS_FUNC_DEV_ATTR_QRY, length, flags,
		      task->transaction, 0);

	task->len = length + sizeof(*hdr);
	task->state = ISNS_TASK_SEND_PDU;

	qtask->rsp.command = MGMT_IPC_ISNS_DEV_ATTR_QUERY;

	actor_new(&task->actor, isns_poll, task);
	actor_schedule(&task->actor);

	return MGMT_IPC_OK;
}

void isns_handle(int listen_fd)
{
	struct sockaddr_storage from;
	socklen_t slen = sizeof(from);
	int fd;
	struct isns_task *task;

	fd = accept(listen_fd, (struct sockaddr *) &from, &slen);
	if (fd < 0) {
		log_error("%s: accept error %m", __FUNCTION__);
		return;
	}

	task = malloc(sizeof(*task));
	if (!task) {
		log_error("%s %m", __FUNCTION__);
		close(fd);
		return;
	}

	memset(task, 0, sizeof(*task));
	task->state = ISNS_TASK_RECV_PDU;
	task->fd = fd;

	actor_new(&task->actor, isns_poll, task);
	actor_schedule(&task->actor);
}

static void isns_poll(void *data)
{
	int err, finished;
	struct pollfd pfd;
	struct isns_task *task = data;
	struct isns_hdr *hdr = (struct isns_hdr *) task->data;
	uint16_t function = ntohs(hdr->function);

	pfd.fd = task->fd;
	switch (task->state) {
	case ISNS_TASK_WAIT_CONN:
	case ISNS_TASK_SEND_PDU:
		pfd.events = POLLOUT;
		break;
	case ISNS_TASK_RECV_PDU:
		pfd.events = POLLIN;
	}

	err = poll(&pfd, 1, 1);
	if (err > 0) {
		switch (task->state) {
		case ISNS_TASK_WAIT_CONN:
			task->state = ISNS_TASK_SEND_PDU;
		case ISNS_TASK_SEND_PDU:
			err = isns_send_pdu(task);
			if (err)
				goto abort_task;
			else {

				if (task->done == task->len) {
					task->state = ISNS_TASK_RECV_PDU;
					task->done = task->len = 0;

					if (function == ISNS_FUNC_ESI_RSP)
						goto free_task;
				}

				actor_new(&task->actor, isns_poll, task);
				actor_schedule(&task->actor);
			}
			break;
		case ISNS_TASK_RECV_PDU:
			err = isns_recv_pdu(task);
			if (err)
				goto abort_task;
			else {
				if (task->done ==
				    task->len + sizeof(struct isns_hdr)) {
					finished = isns_task_done(task);
					if (finished)
						goto free_task;
				} else {
					/* need to read more */
					actor_new(&task->actor, isns_poll,
						  task);
					actor_schedule(&task->actor);
				}
			}
		}
	} else if (!err) {
		/* FIXME */
		if (task->retry++ > max_retry) {
			log_error("abort task");
			goto abort_task;
		} else {
			actor_new(&task->actor, isns_poll, task);
			actor_schedule(&task->actor);
		}
	}

	return;
abort_task:
	if (task->qtask)
		send_mgmt_rsp(task, 1);
free_task:
	isns_free_task(task);
}

static int isns_dev_register(void)
{
	struct isns_task *task;

	task = malloc(sizeof(*task));
	if (!task)
		return -ENOMEM;
	memset(task, 0, sizeof(*task));

	task->fd = isns_connect();
	if (task->fd < 0) {
		free(task);
		return -ENOMEM;
	}

	task->state = ISNS_TASK_WAIT_CONN;
	build_dev_reg_req(task);

	actor_new(&task->actor, isns_poll, task);
	actor_schedule(&task->actor);

	return 0;
}

static int isns_listen_init(int *listen_fd)
{
	int fd, opt, err;
	struct sockaddr_storage lss;
	socklen_t slen;

	fd = socket(ss.ss_family, SOCK_STREAM, IPPROTO_TCP);
	if (fd < 0) {
		log_error("%s %m", __FUNCTION__);
		return -errno;
	}

	opt = 1;
	if (ss.ss_family == AF_INET6) {
		err = setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt,
				 sizeof(opt));
		if (err)
			log_error("%s %m", __FUNCTION__);
		goto out;
	}

	err = listen(fd, 5);
	if (err) {
		log_error("%s %m", __FUNCTION__);
		goto out;
	}

	slen = sizeof(lss);
	err = getsockname(fd, (struct sockaddr *) &lss, &slen);
	if (err) {
		log_error("%s %m", __FUNCTION__);
		goto out;
	}

	if (lss.ss_family == AF_INET6)
		isns_listen_port = ((struct sockaddr_in6 *) &lss)->sin6_port;
	else
		isns_listen_port = ((struct sockaddr_in *) &lss)->sin_port;

	isns_listen_port = ntohs(isns_listen_port);
out:
	if (err) {
		close(fd);
		return -1;
	} else {
		*listen_fd = fd;
		return 0;
	}
}

int isns_init(void)
{
	char buf[2048], port[NI_MAXSERV];
	int fd = -1, err;
	FILE *f;

	f = fopen(isns_get_config_file(), "r");
	if (!f)
		return -EIO;

	while (fgets(buf, sizeof(buf), f)) {
		/* FIXME */
		if (buf[strlen(buf) - 1] == '\n')
			buf[strlen(buf) - 1] = '\0';
		if (!strncmp(buf, "isns.address = ", 15))
			strncpy(isns_address, buf + 15, sizeof(isns_address));
		else if (!strncmp(buf, "isns.port = ", 12))
			isns_port = atoi(buf + 12);
	}

	fclose(f);

	if (!strlen(isns_address))
		return -1;

	snprintf(port, sizeof(port), "%d", isns_port);
	err = resolve_address(isns_address, port, &ss);
	if (err) {
		log_error("can't resolve address %m, %s", isns_address);
		return err;
	}

	err = isns_listen_init(&fd);
	if (err)
		return err;

	isns_dev_register();
	return fd;
}

void isns_exit(void)
{
	/* do nothing for now */
	;
}
