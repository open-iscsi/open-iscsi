/*
 * iSCSI Administration Utility
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

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>

#include "initiator.h"
#include "iscsiadm.h"
#include "log.h"
#include "ipc.h"
#include "ddbm.h"

static char program_name[] = "iscsiadm";

char *initiator_name = "temp.init.name";
char *initiator_alias = "temp.init.alias";

enum iscsiadm_mode {
	MODE_DISCOVERY,
	MODE_SLP,
	MODE_ISNS,
	MODE_DB,
};

enum iscsiadm_op {
	OP_INSERT,
	OP_DELETE,
	OP_UPDATE,
	OP_SHOW,
};

static struct option const long_options[] =
{
	{"mode", required_argument, 0, 'm'},
	{"portal", required_argument, 0, 'p'},
	{"op", required_argument, 0, 'o'},
	{"key", required_argument, 0, 'k'},
	{"value", required_argument, 0, 'v'},
	{"record", no_argument, 0, 'r'},
	{"login", no_argument, 0, 'l'},
	{"debug", required_argument, 0, 'd'},
	{"version", no_argument, 0, 'V'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0},
};

static void usage(int status)
{
	if (status != 0)
		fprintf(stderr, "Try `%s --help' for more information.\n",
			program_name);
	else {
		printf("Usage: %s [OPTION]\n", program_name);
		printf("\
iSCSI Administration Utility.\n\
\n\
  -m, --mode <op>         specify operational mode op = <add|del|discovery>\n\
  -m discovery --portal=[ip:port] --login\n\
                          'sendtargets' discovery for target portal with\n\
                          IP-address [ip] and port [port]. Initiate Login for\n\
                          each discovered target if --login is specified\n\
  -m db                   display all records from internal persistent\n\
                          discovery database\n\
  -m db --record=[id] --op=[op] [--key=[key] --value=[value]]\n\
                          perform specific DB operation [op] for specific\n\
                          record [id]. It could be one of:\n\
                          [insert], [delete], [update] or [show]. In case of\n\
                          [update], you have to provide [key] and [value]\n\
  -d, --debug debuglevel  print debugging information\n\
  -V, --version           display version and exit\n\
  -h, --help              display this help and exit\n");
	}

	exit(status == 0 ? 0 : -1);
}

static int
str_to_op(char *str)
{
	int op;

	if (!strcmp("insert", str))
		op = OP_INSERT;
	else if (!strcmp("delete", str))
		op = OP_DELETE;
	else if (!strcmp("update", str))
		op = OP_UPDATE;
	else if (!strcmp("show", str))
		op = OP_SHOW;
	else
		op = -1;

	return op;
}

static int
str_to_mode(char *str)
{
	int mode;

	if (!strcmp("isns", str))
		mode = MODE_ISNS;
	else if (!strcmp("slp", str))
		mode = MODE_SLP;
	else if (!strcmp("discovery", str))
		mode = MODE_DISCOVERY;
	else if (!strcmp("db", str))
		mode = MODE_DB;
	else
		mode = -1;

	return mode;
}

static char*
str_to_ipport(char *str, int *port)
{
	char *sport;

	if ((sport = strchr(str, ':'))) {
		*sport = '\0';
		sport++;
		*port = strtoul(sport, NULL, 10);
		return str;
	}

	return NULL;
}

#if 0
static int
iscsid_connect(void)
{
	int fd, err;
	struct sockaddr_un addr;

	fd = socket(AF_LOCAL, SOCK_STREAM, 0);
	if (fd < 0)
		return fd;

	memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_LOCAL;
	memcpy((char *) &addr.sun_path + 1, ISCSIADM_NAMESPACE,
		strlen(ISCSIADM_NAMESPACE));

	if ((err = connect(fd, (struct sockaddr *) &addr, sizeof(addr))) < 0)
		fd = err;

	return fd;
}

static int
iscsid_request(int fd, iscsiadm_req_t *req)
{
	int err;

	if ((err = write(fd, req, sizeof(*req))) != sizeof(*req)) {
		fprintf(stderr, "%s: got error %d on write cmd %d\n",
			program_name, err, req->command);
		if (err >= 0)
			err = -EIO;
	}
	return err;
}

static int
iscsid_response(int fd)
{
	int err;
	iscsiadm_rsp_t rsp;

	if ((err = read(fd, &rsp, sizeof(rsp))) != sizeof(rsp)) {
		fprintf(stderr, "%s: got bad response %d on cmd %d\n",
			program_name, err, rsp.command);
		if (err >= 0)
			err = -EIO;
	} else
		err = rsp.err;

	return err;
}

static int
mode_sid_add(int sid)
{
	int fd = -1, err;
	iscsiadm_req_t req;

	if ((fd = iscsid_connect()) < 0) {
		err = fd;
		goto out;
	}

	memset(&req, 0, sizeof(req));
	req.command = C_TARGET_ADD;
	req.tid = tid;
	strncpy(req.u.tadd.name, name, sizeof(req.u.tadd.name) - 1);

	if ((err = iscsid_request(fd, &req)) < 0)
		goto out;

	err = iscsid_response(fd);
out:
	if (fd > 0)
		close(fd);

	return err;
}
#endif

int
main(int argc, char **argv)
{
	char *ip = NULL, *key = NULL, *value = NULL;
	int ch, longindex, mode=-1, port=-1, do_login=0;
	int rc=0, rid=-1, op=-1;
	DBM *dbm;

	/* enable stdout logging */
	log_daemon = 0;
	log_init(program_name);

	while ((ch = getopt_long(argc, argv, "lv:h:m:p:d:r:k:v:o:",
				 long_options, &longindex)) >= 0) {
		switch (ch) {
		case 'o':
			op = str_to_op(optarg);
			break;
		case 'k':
			key = optarg;
			break;
		case 'v':
			value = optarg;
			break;
		case 'r':
			rid = atoi(optarg);
			break;
		case 'l':
			do_login = 1;
			break;
		case 'd':
			log_level = atoi(optarg);
			break;
		case 'm':
			mode = str_to_mode(optarg);
			break;
		case 'p':
			ip = str_to_ipport(optarg, &port);
			break;
		case 'V':
			printf("%s version %s\n", program_name,
				ISCSI_VERSION_STR);
			exit(0);
		case 'h':
			usage(0);
			break;
		}
	}

	if (mode < 0) {
		fprintf(stderr, "%s: You must specify the mode\n",
			program_name);
		return -1;
	}

	if ((dbm = ddbm_open(DB_FILE, access(DB_FILE, F_OK) != 0 ?
				O_CREAT|O_RDWR : O_RDWR)) == NULL) {
		return -1;
	}

	if (mode == MODE_DISCOVERY) {
		struct iscsi_sendtargets_config cfg;
		struct string_buffer info;

		if (ip == NULL || port < 0) {
			fprintf(stderr, "%s: can not parse portal '%s:%d'\n",
				program_name, ip, port);
			rc = -1;
			goto out;
		}

		/* FIXME: customize sendtargets */
		strcpy(cfg.address, ip);
		cfg.port = port;
		cfg.continuous = 0;
		cfg.send_async_text = 0;
		cfg.auth_options.authmethod = CHAP_AUTHENTICATION;
		strcpy(cfg.auth_options.username, "dima");
		strcpy(cfg.auth_options.password, "aloha");
		cfg.auth_options.password_length = strlen("aloha");
		strcpy(cfg.auth_options.username_in, "");
		strcpy(cfg.auth_options.password_in, "");
		cfg.auth_options.password_length_in = 0;
		cfg.connection_timeout_options.login_timeout = 12;
		cfg.connection_timeout_options.auth_timeout = 8;
		cfg.connection_timeout_options.active_timeout = 5;
		cfg.connection_timeout_options.idle_timeout = 3;
		cfg.connection_timeout_options.ping_timeout = 0;

		/*
                 * start sendtargets discovery process based on the
	         * current config
		 */
		init_string_buffer(&info, 8 * 1024);
		rc =  sendtargets_discovery(&cfg, &info);
		ddbm_update_info(dbm, ip, port, DISCOVERY_TYPE_SENDTARGETS,
				 info.buffer);
		truncate_buffer(&info, 0);
		goto out;
	} else if (mode == MODE_DB) {
		if (op == -1 || op == OP_SHOW) {
			ddbm_print(dbm, rid);
			goto out;
		}
	} else {
		fprintf(stderr, "%s: This mode is not yet supported\n",
			program_name);
	}

out:
	ddbm_close(dbm);
	return rc;
}
