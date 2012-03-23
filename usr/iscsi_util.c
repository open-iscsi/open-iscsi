/*
 * Misc helpers
 *
 * Copyright (C) 2004 Dmitry Yusupov, Alex Aizman
 * Copyright (C) 2006 - 2010 Mike Christie
 * Copyright (C) 2006 - 2010 Red Hat, Inc. All rights reserved.
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
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/resource.h>

#include "log.h"
#include "iscsi_settings.h"
#include "iface.h"
#include "session_info.h"
#include "iscsi_util.h"

void daemon_init(void)
{
	int fd;

	fd = open("/dev/null", O_RDWR);
	if (fd == -1) {
		exit(-1);
	}

	dup2(fd, 0);
	dup2(fd, 1);
	dup2(fd, 2);
	setsid();
	if (chdir("/") < 0)
		log_debug(1, "Could not chdir to /: %s", strerror(errno));
}

#define ISCSI_OOM_PATH_LEN 48

int oom_adjust(void)
{
	int fd;
	char path[ISCSI_OOM_PATH_LEN];
	struct stat statb;

	if (nice(-10) < 0)
		log_debug(1, "Could not increase process priority: %s",
			  strerror(errno));

	snprintf(path, ISCSI_OOM_PATH_LEN, "/proc/%d/oom_score_adj", getpid());
	if (stat(path, &statb)) {
		/* older kernel so use old oom_adj file */
		snprintf(path, ISCSI_OOM_PATH_LEN, "/proc/%d/oom_adj",
			 getpid());
	}
	fd = open(path, O_WRONLY);
	if (fd < 0)
		return -1;
	if (write(fd, "-16", 3) < 0) /* for 2.6.11 */
		log_debug(1, "Could not set oom score to -16: %s",
			  strerror(errno));
	if (write(fd, "-17", 3) < 0) /* for Andrea's patch */
		log_debug(1, "Could not set oom score to -17: %s",
			  strerror(errno));
	close(fd);
	return 0;
}

char*
str_to_ipport(char *str, int *port, int *tpgt)
{
	char *stpgt, *sport = str, *ip = str;

	if (!strchr(ip, '.')) {
		if (*ip == '[') {
			/* IPv6 with [] */
			if (!(sport = strchr(ip, ']')))
				return NULL;
			*sport++ = '\0';
			ip++;
			str = sport;
		} else {
			/* hostname or ipv6 */
			sport = strchr(ip, ':');
			if (sport) {
				if (strchr(sport + 1, ':'))
					/* ipv6 */
					sport = NULL;
				else
					/* hostname:port */
					str = sport;
			}
		}
	}

	if (sport && (sport = strchr(str, ':'))) {
		*sport++ = '\0';
		*port = strtoul(sport, NULL, 10);
		str = sport;
	}

	if ((stpgt = strchr(str, ','))) {
		*stpgt++ = '\0';
		*tpgt = strtoul(stpgt, NULL, 10);
	} else
		*tpgt = PORTAL_GROUP_TAG_UNKNOWN;

	log_debug(2, "ip %s, port %d, tgpt %d", ip, *port, *tpgt);
	return ip;
}

#define ISCSI_MAX_FILES 16384

int increase_max_files(void)
{
	struct rlimit rl;
	int err;

	err = getrlimit(RLIMIT_NOFILE, &rl);
	if (err) {
		log_debug(1, "Could not get file limit (err %d)\n", errno);
		return errno;
	}
	log_debug(1, "Max file limits %lu %lu\n", rl.rlim_cur, rl.rlim_max);

	if (rl.rlim_cur < ISCSI_MAX_FILES)
		rl.rlim_cur = ISCSI_MAX_FILES;
	if (rl.rlim_max < ISCSI_MAX_FILES)
		rl.rlim_max = ISCSI_MAX_FILES;

	err = setrlimit(RLIMIT_NOFILE, &rl);
	if (err) {
		log_debug(1, "Could not set file limit to %lu/%lu (err %d)\n",
			  rl.rlim_cur, rl.rlim_max, errno);
		return errno;
	}

	return 0;
}

/*
 * from linux kernel
 */
char *strstrip(char *s)
{
	size_t size;
	char *end;

	size = strlen(s);
	if (!size)
		return s;

	end = s + size - 1;
	while (end >= s && isspace(*end))
		end--;
	*(end + 1) = '\0';

	while (*s && isspace(*s))
		s++;

	return s;
}

/**
 * cfg_get_string_param - return param value
 * @pathname: pathname and filename of config file
 * @key: param name
 *
 * Assumes the delim is a "=". "#" comments a line, but if
 * the "#" is after the key= then it is a valid value.
*/
char *cfg_get_string_param(char *pathname, const char *key)
{
	FILE *f = NULL;
	char *line, buffer[1024];
	char *value = NULL, *param, *comment;

	if (!pathname) {
		log_error("No pathname to load %s from", key);
		return NULL;
	}

	if ((f = fopen(pathname, "r"))) {
		while ((line = fgets(buffer, sizeof (buffer), f))) {
			param = strstr(line, key);
			if (!param)
				continue;

			/* make sure it is not commented out */
			comment = strchr(line, '#');
			if (comment) {
				if (comment < param)
					continue;
			}

			param = strchr(param, '=');
			if (!param) {
				log_error("Invalid config line for %s. "
					  "Missing '='.", key);
				continue;
			}

			param++;
			if (!strlen(param)) {
				log_error("Invalid config line for %s. "
					  "Missing value", key);
				continue;
			}

			param = strstrip(param);
			if (!strlen(param)) {
				log_error("Invalid config line for %s. "
					  "Missing value", key);
				continue;
			}

			value = strdup(param);
			break;
		}
		fclose(f);
		if (value)
			log_debug(5, "%s=%s", key, value);
	} else
		log_error("can't open %s configuration file %s", key, pathname);

	return value;
}

/**
 * iscsi_addr_match - check if the addrs are to the same ip
 * @address1: pattern
 * @address2: address to check
 *
 * If address1 is blank then it matches any string passed in.
 */
static int iscsi_addr_match(char *address1, char *address2)
{
	struct addrinfo hints1, hints2, *res1, *res2;
	int rc;

	if (!strlen(address1))
		return 1;

	if (!strcmp(address1, address2))
		return 1;

	memset(&hints1, 0, sizeof(struct addrinfo));
	hints1.ai_family = AF_UNSPEC;
	hints1.ai_socktype = SOCK_STREAM;

	memset(&hints2, 0, sizeof(struct addrinfo));
	hints2.ai_family = AF_UNSPEC;
	hints2.ai_socktype = SOCK_STREAM;

	/*
	 * didn't match so we have to resolve to see if one is a dnsname
	 * that matches a ip address.
	 */
	rc = getaddrinfo(address1, NULL, &hints1, &res1);
	if (rc) {
		log_debug(1, "Match error. Could not resolve %s: %s", address1,
			  gai_strerror(rc));
		return 0;

	}

	rc = getaddrinfo(address2, NULL, &hints2, &res2);
	if (rc) {
		log_debug(1, "Match error. Could not resolve %s: %s", address2,
			  gai_strerror(rc));
		rc = 0;
		goto free_res1;
	}

	if ((res1->ai_addrlen != res2->ai_addrlen) ||
	    memcmp(res1->ai_addr, res2->ai_addr, res2->ai_addrlen))
		rc = 0;
	else
		rc = 1;

	freeaddrinfo(res2);
free_res1:
	freeaddrinfo(res1);
	return rc;
}

int __iscsi_match_session(node_rec_t *rec, char *targetname,
			  char *address, int port, struct iface_rec *iface,
			  unsigned sid)
{
	if (!rec) {
		log_debug(6, "no rec info to match\n");
		return 1;
	}

	log_debug(6, "match session [%s,%s,%d][%s %s,%s,%s]:%u",
		  rec->name, rec->conn[0].address, rec->conn[0].port,
		  rec->iface.name, rec->iface.transport_name,
		  rec->iface.hwaddress, rec->iface.ipaddress,
		  rec->session.sid);

	if (iface)
		log_debug(6, "to [%s,%s,%d][%s %s,%s,%s]:%u",
			  targetname, address, port, iface->name,
			  iface->transport_name, iface->hwaddress,
			  iface->ipaddress, sid);

	if (rec->session.sid && sid && rec->session.sid != sid)
		return 0;

	if (strlen(rec->name) && strcmp(rec->name, targetname))
		return 0;

	if (!iscsi_addr_match(rec->conn[0].address, address))
		return 0;

	if (rec->conn[0].port != -1 && port != rec->conn[0].port)
		return 0;

	if (!iface_match(&rec->iface, iface))
		return 0;

	return 1;
}

int iscsi_match_session(void *data, struct session_info *info)
{
	return __iscsi_match_session(data, info->targetname,
				     info->persistent_address,
				     info->persistent_port, &info->iface,
				     info->sid);
}

int iscsi_match_session_count(void *data, struct session_info *info)
{
	/*
	 * iscsi_sysfs_for_each_session expects:
	 *   0==match -1==nomatch >0==error
	 * but iscsi_match_session returns:
	 *   1==match 0==nomatch
	 */
	if (iscsi_match_session(data, info))
		return 0;
	return -1;
}

int iscsi_match_target(void *data, struct session_info *info)
{
	return __iscsi_match_session(data, info->targetname,
				     info->persistent_address,
				     info->persistent_port, NULL,
				     MATCH_ANY_SID);
}
