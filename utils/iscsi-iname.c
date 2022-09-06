/*
 * iSCSI InitiatorName creation utility
 * Copyright (C) 2001 Cisco Systems, Inc.
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
 *
 * $Id: iscsi-iname.c,v 1.1.2.3 2005/03/15 06:33:44 wysochanski Exp $
 *
 * iscsi-iname.c - Compute an iSCSI InitiatorName for this host.
 * Note that to ensure uniqueness, the system time is
 * a factor.  This name must be cached and only regenerated
 * if there is no cached value.
 */

#include <stdint.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>
#include <sys/time.h>
#include <getopt.h>
#include <stdbool.h>

#include "md5.h"

#define RANDOM_NUM_GENERATOR	"/dev/urandom"

#define DEFAULT_PREFIX		"iqn.2016-04.com.open-iscsi"

/* iSCSI names have a maximum length of 223 characters, we reserve 13 to append
 * a seperator and 12 characters (6 random bytes in hex representation) */
#define PREFIX_MAX_LEN 210

static void usage(void)
{
	fprintf(stderr, "Usage: iscsi-iname [OPTIONS]\n");
	fprintf(stderr, "Where OPTIONS are from:\n");
	fprintf(stderr, "    -p/--prefix <prefix>          -- set IQN prefix [%s]\n",
			DEFAULT_PREFIX);
	fprintf(stderr, "    -g/--generate-iname-prefix    -- generate the InitiatorName= prefix\n");
	fprintf(stderr, "where <prefix> has max length of %d\n",
		PREFIX_MAX_LEN);
}

int
main(int argc, char *argv[])
{
	struct timeval time;
	struct utsname system_info;
	long hostid;
	struct MD5Context context;
	unsigned char digest[16];
	unsigned char *bytes = digest;
	unsigned char entropy[16];
	int e;
	int fd;
	char *prefix = DEFAULT_PREFIX;
	int c;
	char *short_options = "p:gh";
	struct option const long_options[] = {
		{"help", no_argument, NULL, 'h'},
		{"prefix", required_argument, NULL, 'p'},
		{"generate-iname-prefix", no_argument, NULL, 'g'},
		{NULL, 0, NULL, 0}
	};
	bool generate_iname_prefix = false;

	/* initialize */
	memset(digest, 0, sizeof (digest));
	memset(&context, 0, sizeof (context));
	MD5Init(&context);

	/* take a prefix if given, otherwise use a default. */
	while ((c = getopt_long(argc, argv, short_options, long_options, NULL)) >= 0) {
		switch (c) {
		case 'p':
			prefix = optarg;
			if (strnlen(prefix, PREFIX_MAX_LEN + 1) > PREFIX_MAX_LEN) {
				fprintf(stderr, "error: prefix too long\n");
				usage();
				exit(1);
			}
			break;
		case 'h':
			usage();
			exit(0);
		case 'g':
			generate_iname_prefix = true;
			break;
		default:
		case '?':
			usage();
			exit(1);
		}
	}
	if (optind < argc) {
		fprintf(stderr, "unknown argument(s)\n");
		usage();
		exit(1);
	}

	/* try to feed some entropy from the pool to MD5 in order to get
	 * uniqueness properties
	 */

	fd = open(RANDOM_NUM_GENERATOR, O_RDONLY);
	if (fd != -1) {
		e = read(fd, &entropy, 16);
		if (e >= 1)
			MD5Update(&context, (md5byte *)entropy, e);
		close(fd);
	}

	/* time the name is created is a factor in order to get
	 * uniqueness properties
	 */
	if (gettimeofday(&time, NULL) < 0) {
		perror("error: gettimeofday failed");
		return 1;
	}
	MD5Update(&context, (md5byte *) & time.tv_sec, sizeof (time.tv_sec));
	MD5Update(&context, (md5byte *) & time.tv_usec, sizeof (time.tv_usec));

	/* hostid */
	hostid = gethostid();
	MD5Update(&context, (md5byte *) & hostid, sizeof (hostid));

	/* get the hostname and system name */
	if (uname(&system_info) < 0) {
		perror("error: uname failed");
		return 1;
	}
	MD5Update(&context, (md5byte *) system_info.sysname,
		  sizeof (system_info.sysname));
	MD5Update(&context, (md5byte *) system_info.nodename,
		  sizeof (system_info.nodename));
	MD5Update(&context, (md5byte *) system_info.release,
		  sizeof (system_info.release));
	MD5Update(&context, (md5byte *) system_info.version,
		  sizeof (system_info.version));
	MD5Update(&context, (md5byte *) system_info.machine,
		  sizeof (system_info.machine));

	/* compute the md5 hash of all the bits we just collected */
	MD5Final(digest, &context);

	/* vary which md5 bytes we pick (though we probably don't need to do
	 * this, since hopefully MD5 produces results such that each byte is as
	 * good as any other).
	 */

	fd = open(RANDOM_NUM_GENERATOR, O_RDONLY);
	if (fd != -1) {
		if (read(fd, entropy, 1) == 1)
			bytes = &digest[(entropy[0] % (sizeof(digest) - 6))];
		close(fd);
	}

	/* print the prefix followed by 6 bytes of the MD5 hash */
	printf("%s%s:%x%x%x%x%x%x\n",
		generate_iname_prefix ? "InitiatorName=" : "",
		prefix,
		bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
	return 0;
}
