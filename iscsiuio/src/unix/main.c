/*
 * Copyright (c) 2001, Adam Dunkels.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Adam Dunkels.
 * 4. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This file is part of the uIP TCP/IP stack.
 *
 *
 */

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>
#include <getopt.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/utsname.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <sys/mman.h>

#include "uip.h"
#include "uip_arp.h"
#include "uip_eth.h"

#include "timer.h"

#include "build_date.h"
#include "config.h"
#include "iscsid_ipc.h"
#include "logger.h"
#include "nic.h"
#include "nic_id.h"
#include "nic_nl.h"
#include "nic_utils.h"
#include "options.h"
#include "packet.h"

#include "dhcpc.h"

#include "iscsid_ipc.h"
#include "brcm_iscsi.h"

/*******************************************************************************
 *  Constants
 ******************************************************************************/
#define PFX "main "

static const char default_pid_filepath[] = "/var/run/iscsiuio.pid";

/*******************************************************************************
 *  Global Variables
 ******************************************************************************/
static const struct option long_options[] = {
	{"debug", 0, 0, 0},
	{"version", 0, 0, 0},
	{"help", 0, 0, 0},
	{0, 0, 0, 0}
};

struct options opt = {
	.debug = DEBUG_OFF,
};

int event_loop_stop;
extern nic_t *nic_list;

struct utsname cur_utsname;

/**
 *  cleanup() - This function is called when this program is to be closed
 *              This function will clean up all the cnic uio interfaces and
 *              flush/close the logger
 */
static void cleanup()
{
	iscsid_cleanup();

	nic_remove_all();

	unload_all_nic_libraries();

	LOG_INFO("Done waiting for cnic's/stacks to gracefully close");

	fini_logger(SHUTDOWN_LOGGER);
}

/**
 *  signal_handle_thread() - This is the signal handling thread of this program
 *                           This is the only thread which will handle signals.
 *                           All signals are routed here and handled here to
 *                           provide consistant handling.
 */
static pthread_t signal_thread;
static void *signal_handle_thread(void *arg)
{
	sigset_t set;
	int rc;
	int signal;

	sigfillset(&set);

	LOG_INFO("signal handling thread ready");

signal_wait:
	rc = sigwait(&set, &signal);

	switch (signal) {
	case SIGINT:
		LOG_INFO("Caught SIGINT signal");
		break;
	case SIGUSR1:
		LOG_INFO("Caught SIGUSR1 signal, rotate log");
		fini_logger(SHUTDOWN_LOGGER);
		rc = init_logger(main_log.log_file);
		if (rc != 0)
			printf("Could not initialize the logger in "
			       "signal!\n");
		goto signal_wait;
	default:
		break;
	}
	event_loop_stop = 1;

	LOG_INFO("terminating...");

	cleanup();
	exit(EXIT_SUCCESS);
}

static void show_version()
{
	printf("%s: Version '%s', Build Date: '%s'\n",
	       APP_NAME, PACKAGE_VERSION, build_date);
}

static void main_usage()
{
	show_version();

	printf("\nUsage: %s [OPTION]\n", APP_NAME);
	printf("iscsiuio daemon.\n"
	       "-f, --foreground        make the program run in the foreground\n"
	       "-d, --debug debuglevel  print debugging information\n"
	       "-p, --pid=pidfile       use pid file (default  %s).\n"
	       "-h, --help              display this help and exit\n"
	       "-v, --version           display version and exit\n",
	       default_pid_filepath);
}

static void daemon_init()
{
	int fd;

	fd = open("/dev/null", O_RDWR);
	if (fd == -1)
		exit(-1);

	dup2(fd, 0);
	dup2(fd, 1);
	dup2(fd, 2);
	setsid();
	chdir("/");
}

#define ISCSI_OOM_PATH_LEN 48

int oom_adjust(void)
{
	int fd;
	char path[ISCSI_OOM_PATH_LEN];
	struct stat statb;

	if (nice(-10) < 0)
		LOG_DEBUG("Could not increase process priority: %s",
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
		LOG_DEBUG("Could not set oom score to -16: %s",
			  strerror(errno));
	if (write(fd, "-17", 3) < 0) /* for Andrea's patch */
		LOG_DEBUG("Could not set oom score to -17: %s",
			  strerror(errno));
	close(fd);
	return 0;
}


/*******************************************************************************
 * Main routine
 ******************************************************************************/
int main(int argc, char *argv[])
{
	int rc;
	sigset_t set;
	const char *pid_file = default_pid_filepath;
	int fd;
	int foreground = 0;
	pid_t pid;
	pthread_attr_t attr;

	/*  Record the start time for the user space daemon */
	opt.start_time = time(NULL);

	/*  parse the parameters */
	while (1) {
		int c, option_index;

		c = getopt_long(argc, argv, "fd:p:vh",
				long_options, &option_index);

		if (c == -1)
			break;

		switch (c) {

		case 'f':
			foreground = 1;
			break;

			/* Enable debugging mode */
		case 'd':
			main_log.level = atoi(optarg);
			opt.debug = DEBUG_ON;
			break;
		case 'p':
			pid_file = optarg;
			break;
		case 'v':
			show_version();
			exit(EXIT_SUCCESS);
		case 'h':
		default:
			main_usage();
			exit(EXIT_SUCCESS);
		}
	}

	if (main_log.enabled == LOGGER_ENABLED) {
		/*  initialize the logger */
		rc = init_logger(main_log.log_file);
		if (rc != 0 && opt.debug == DEBUG_ON)
			printf("WARN: Could not initialize the logger\n");
	}

	LOG_INFO("Started iSCSI uio stack: Ver " PACKAGE_VERSION);
	LOG_INFO("Build date: %s", build_date);

	if (opt.debug == DEBUG_ON)
		LOG_INFO("Debug mode enabled");

	event_loop_stop = 0;
	nic_list = NULL;

	/*  Determine the current kernel version */
	memset(&cur_utsname, 0, sizeof(cur_utsname));

	rc = uname(&cur_utsname);
	if (rc == 0) {
		LOG_INFO("Running on sysname: '%s', release: '%s', "
			 "version '%s' machine: '%s'",
			 cur_utsname.sysname, cur_utsname.release,
			 cur_utsname.version, cur_utsname.machine);
	} else
		LOG_WARN("Could not determine kernel version");

	/*  Initialze the iscsid listener */
	rc = iscsid_init();
	if (rc != 0)
		goto error;

	if (!foreground) {
		char buf[64];
		ssize_t written_bytes;

		fd = open(pid_file, O_WRONLY | O_CREAT, 0644);
		if (fd < 0) {
			printf("Unable to create pid file: %s", pid_file);
			exit(1);
		}

		pid = fork();
		if (pid < 0) {
			printf("Starting daemon failed");
			exit(1);
		} else if (pid) {
			exit(0);
		}

		rc = chdir("/");
		if (rc == -1)
			printf("Unable to chdir(\") [%s]", strerror(errno));

		if (lockf(fd, F_TLOCK, 0) < 0) {
			printf("Unable to lock pid file: %s [%s]",
			       pid_file, strerror(errno));
			exit(1);
		}

		rc = ftruncate(fd, 0);
		if (rc == -1)
			printf("ftruncate(%d, 0) failed [%s]",
			       fd, strerror(errno));

		sprintf(buf, "%d\n", getpid());
		written_bytes = write(fd, buf, strlen(buf));
		if (written_bytes == -1)
			printf("Could not write lock file [%s]",
			       strerror(errno));

		daemon_init();
	}

	/*  Load the NIC libraries */
	rc = load_all_nic_libraries();
	if (rc != 0)
		goto error;

	brcm_iscsi_init();

	/*  ensure we don't see any signals */
	sigemptyset(&set);
	sigaddset(&set, SIGINT);
	sigaddset(&set, SIGQUIT);
	sigaddset(&set, SIGTERM);
	sigaddset(&set, SIGUSR1);
	rc = pthread_sigmask(SIG_SETMASK, &set, NULL);

	/*  Spin off the signal handling thread */
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	rc = pthread_create(&signal_thread, &attr, signal_handle_thread, NULL);
	if (rc != 0)
		LOG_ERR("Could not create signal handling thread");

	/* Using sysfs to discover iSCSI hosts */
	nic_discover_iscsi_hosts();

	/* oom-killer will not kill us at the night... */
	if (oom_adjust())
		LOG_DEBUG("Can not adjust oom-killer's pardon");

	/* we don't want our active sessions to be paged out... */
	if (mlockall(MCL_CURRENT | MCL_FUTURE)) {
		LOG_ERR("failed to mlockall, exiting...");
		goto error;
	}

	/*  Start the iscsid listener */
	rc = iscsid_start();
	if (rc != 0)
		goto error;

	/*  NetLink connection to listen to NETLINK_ISCSI private messages */
	nic_nl_open();

error:
	cleanup();
	exit(EXIT_FAILURE);
}
