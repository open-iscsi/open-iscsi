/*
 * Ioctl and SysFS control
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
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "iscsid.h"
#include "log.h"

#define CTL_DEVICE	"/dev/iscsictl"
#define SYSFS_ROOT	"/sysfs/class/iscsi"

int ctldev_open(void)
{
	FILE *f = NULL;
	char devname[256];
	char buf[256];
	int devn;
	int ctlfd;

	f = fopen("/proc/devices", "r");
	if (!f) {
		log_error("cannot open control path to the driver");
		return -1;
	}

	devn = 0;
	while (!feof(f)) {
		if (!fgets(buf, sizeof (buf), f)) {
			break;
		}
		if (sscanf(buf, "%d %s", &devn, devname) != 2) {
			continue;
		}
		if (!strcmp(devname, "ietctl")) {
			break;
		}
		devn = 0;
	}

	fclose(f);
	if (!devn) {
		log_error("cannot find iscsictl in /proc/devices - "
		     "make sure the module is loaded");
		//return -1;
		return 1;
	}

	unlink(CTL_DEVICE);
	if (mknod(CTL_DEVICE, (S_IFCHR | 0600), (devn << 8))) {
		log_error("cannot create %s %d", CTL_DEVICE, errno);
		return -1;
	}

	ctlfd = open(CTL_DEVICE, O_RDWR);
	if (ctlfd < 0) {
		log_error("cannot open %s %d", CTL_DEVICE, errno);
		return -1;
	}

	log_debug(1, CTL_DEVICE " opened!");

	return ctlfd;
}

void
ctldev_close(int fd)
{
	close(fd);
}
