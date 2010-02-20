/*
 * write pidfile
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>

#include "util.h"

static void
__update_pidfile(int fd)
{
	char	pidbuf[32];

	snprintf(pidbuf, sizeof(pidbuf), "%u\n", getpid());
	if (write(fd, pidbuf, strlen(pidbuf)) < 0)
		isns_fatal("Error writing pid file: %m\n");
	close(fd);
}

static pid_t
__read_pidfile(const char *filename)
{
	char	pidbuf[32];
	FILE	*fp;
	pid_t	pid = -1;

	fp = fopen(filename, "r");
	if (fp != NULL) {
		if (fgets(pidbuf, sizeof(pidbuf), fp))
			pid = strtoul(pidbuf, NULL, 0);
		fclose(fp);
	}
	return pid;
}

void
isns_write_pidfile(const char *filename)
{
	int	fd;
	pid_t	pid;

	fd = open(filename, O_CREAT|O_EXCL|O_WRONLY, 0644);
	if (fd >= 0) {
		__update_pidfile(fd);
		return;
	}

	if (errno != EEXIST)
		isns_fatal("Error creating pid file %s: %m\n",
			filename);

	/* If the pid file is stale, remove it.
	 * Not really needed in real life, but
	 * highly convenient for debugging :) */
	if ((pid = __read_pidfile(filename)) > 0
	 && kill(pid, 0) < 0
	 && errno == ESRCH) {
		isns_debug_general(
			"Removing stale PID file %s\n",
			filename);
		unlink(filename);
	}

	/* Try again */
	fd = open(filename, O_CREAT|O_EXCL|O_WRONLY, 0644);
	if (fd < 0)
		isns_fatal("PID file exists; another daemon "
		      "seems to be running\n");

	__update_pidfile(fd);
}

void
isns_update_pidfile(const char *filename)
{
	int	fd;

	fd = open(filename, O_WRONLY);
	if (fd < 0) {
		isns_fatal("Error opening pid file %s: %m\n",
			filename);
	}

	__update_pidfile(fd);
}

void
isns_remove_pidfile(const char *filename)
{
	unlink(filename);
}
