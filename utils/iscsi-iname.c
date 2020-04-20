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

#include "md5.h"

#define RANDOM_NUM_GENERATOR	"/dev/urandom"

/* iSCSI names have a maximum length of 223 characters, we reserve 13 to append
 * a seperator and 12 characters (6 random bytes in hex representation) */
#define PREFIX_MAX_LEN 210

static void usage(void)
{
	fprintf(stderr, "Usage: iscsi-iname [-h | --help | -p <prefix>]\n");
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
	char *prefix;

	/* initialize */
	memset(digest, 0, sizeof (digest));
	memset(&context, 0, sizeof (context));
	MD5Init(&context);

	/* take a prefix if given, otherwise use a default. */
	if (argc > 1 && argv[1]) {
		prefix = argv[1];
		if (( strcmp(prefix, "-h") == 0 ) ||
		    ( strcmp(prefix, "--help") == 0 )) {
			printf("\nGenerates a unique iSCSI node name "
			       "on every invocation.\n");
			exit(0);
		} else if ( strcmp(prefix, "-p") == 0 ) {
			if (argc != 3) {
				usage();
				exit(1);
			}
			prefix = argv[2];
			if (strnlen(prefix, PREFIX_MAX_LEN + 1) > PREFIX_MAX_LEN) {
				usage();
				exit(1);
			}
		} else {
			usage();
			exit(0);
		}
	} else {
		prefix = "iqn.2016-04.com.open-iscsi";
	}

	/* try to feed some entropy from the pool to MD5 in order to get
	 * uniqueness properties
	 */

	if ((fd = open(RANDOM_NUM_GENERATOR, O_RDONLY))) {
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

	if ((fd = open(RANDOM_NUM_GENERATOR, O_RDONLY))) {
		if (read(fd, entropy, 1) == 1)
			bytes = &digest[(entropy[0] % (sizeof(digest) - 6))];
		close(fd);
	}

	/* print the prefix followed by 6 bytes of the MD5 hash */
	printf("%s:%x%x%x%x%x%x\n", prefix,
		bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]);
	return 0;
}
