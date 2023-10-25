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
#ifndef	NO_SYSTEMD
#include <systemd/sd-daemon.h>
#endif
#include <assert.h>

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

static bool foreground = false;	/* daemon running in foreground or background? */

/*******************************************************************************
 *  Constants
 ******************************************************************************/
#define PFX "main "

static const char default_pid_filepath[] = "/run/iscsiuio.pid";

/*******************************************************************************
 *  Global Variables
 ******************************************************************************/
static const struct option long_options[] = {
	{"foreground", no_argument, NULL, 'f'},
	{"debug", required_argument, NULL, 'd'},
	{"pid", required_argument, NULL, 'p'},
	{"version", no_argument, NULL, 'v'},
	{"help", no_argument, NULL, 'h'},
	{NULL, no_argument, NULL, 0}
};

struct options opt = {
	.debug = DEBUG_OFF,
};

int event_loop_stop;
/*
 * The number of threads currently using event_loop_stop for synchronization purposes
 * Each should lock/increment/unlock before starting is processing loop
 * As each observes the stop flag being set it should lock/decrement/unlock
 * This will allow the cleanup routine to not issue cancels to active threads
 */
static int event_loop_observers;
static pthread_mutex_t event_loop_observers_mutex;

extern nic_t *nic_list;

struct utsname cur_utsname;

/*
 * event_loop_observer_add() - Increment the number of areas of code currently 
 * observing event_loop_stop as an exit/shutdown mechanism
 */
void event_loop_observer_add(void)
{
	pthread_mutex_lock(&event_loop_observers_mutex);
	event_loop_observers++;
	pthread_mutex_unlock(&event_loop_observers_mutex);
}

/*
 * event_loop_observer_add() - decrement the number of areas of code currently 
 * observing event_loop_stop as an exit/shutdown mechanism
 */
void event_loop_observer_remove(void)
{
	pthread_mutex_lock(&event_loop_observers_mutex);
	event_loop_observers--;
	pthread_mutex_unlock(&event_loop_observers_mutex);
}

/*
 *  cleanup() - This function is called when this program is to be closed
 *              This function will clean up all the cnic uio interfaces and
 *              flush/close the logger
 */
static void cleanup()
{
	iscsid_cleanup();

	nic_remove_all();

	unload_all_nic_libraries();

	ILOG_INFO("Done waiting for cnic's/stacks to gracefully close");

	fini_logger();
}

/*
 *  signal_handle_thread() - This is the signal handling thread of this program
 *                           This is the only thread which will handle signals.
 *                           All signals are routed here and handled here to
 *                           provide consistant handling.
 */
static pthread_t signal_thread;
static void *signal_handle_thread(void *arg)
{
	sigset_t set;
#define	WAITCOUNT_MAX 10
	int rc, waitcount;
	int signal;

	sigfillset(&set);

	ILOG_INFO("signal handling thread ready");

signal_wait:
	rc = sigwait(&set, &signal);
	if (rc) {
		ILOG_ERR("Cannot wait for signals: %d", rc);
		exit(EXIT_FAILURE);
	}

	switch (signal) {
	case SIGUSR1:
		ILOG_INFO("Caught SIGUSR1 signal, rotate log");
		fini_logger();
		init_logger(foreground);
		goto signal_wait;
	default:
		ILOG_INFO("Caught %s signal", strsignal(signal));
		break;
	}
	event_loop_stop = 1;

	ILOG_INFO("terminating...");

	/*
	 * for debugging shutdown issues, let's wait 10 seconds, max,
	 * to ensure all of our threads shutdown, since we have seen
	 * issues where they may not do so.
	 */
	waitcount = WAITCOUNT_MAX;
	while ((event_loop_observers > 0) && waitcount--) {
		sleep(1);
		if (event_loop_observers <= 0)
			break;	/* they finished while we were sleeping */
		ILOG_INFO("%d threads still polling event_loop_stop flag after %d seconds",
			  event_loop_observers, WAITCOUNT_MAX - waitcount);
	}
	if (event_loop_observers < 0)
		ILOG_DEBUG("Invalid observer count: %d", event_loop_observers);
	else if (event_loop_observers > 0)
		ILOG_ERR("%d unresponsive observers will be cancelled: %d",
			 event_loop_observers);
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
	       "-p, --pid pidfile       use pid file (default  %s).\n"
	       "-h, --help              display this help and exit\n"
	       "-v, --version           display version and exit\n",
	       default_pid_filepath);
}

static void daemon_init()
{
	int fd;
	int res;

	fd = open("/dev/null", O_RDWR);
	assert(fd >= 0);

	dup2(fd, 0);
	dup2(fd, 1);
	dup2(fd, 2);
	setsid();
	res = chdir("/");
	assert(res == 0);
	close(fd);
}

/*
 * make a best effort at ajusting our nice
 * score and our OOM score, but it's not considered
 * fatal if either adjustment fails
 *
 * return 0 on success of OOM adjustment
 */
int oom_adjust(void)
{
	int fd;
	int res = 0;

	errno = 0;
	if (nice(-10) == -1 && errno != 0)
		ILOG_DEBUG("Could not increase process priority: %s",
			  strerror(errno));

	/*
	 * try the modern method of adjusting our OOM score,
	 * then try the old one, if that fails
	 */
	if ((fd = open("/proc/self/oom_score_adj", O_WRONLY)) >= 0) {
		if ((res = write(fd, "-1000", 5)) < 0)
			ILOG_DEBUG("Could not set /proc/self/oom_score_adj to -1000: %s",
				strerror(errno));
	} else if ((fd = open("/proc/self/oom_adj", O_WRONLY)) >= 0) {
		if ((res = write(fd, "-17", 3)) < 0)
			ILOG_DEBUG("Could not set /proc/self/oom_adj to -16: %s",
				strerror(errno));
	} else
		return -1;

	close(fd);
	if (res < 0)
		return res;
	else
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
	bool foreground = false;
	pid_t pid;
	pthread_attr_t attr;
	int pipefds[2];

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
			foreground = true;
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

	init_logger(foreground);

	ILOG_INFO("Started iSCSI uio stack: Ver " PACKAGE_VERSION);
	ILOG_INFO("Build date: %s", build_date);

	if (opt.debug == DEBUG_ON)
		ILOG_INFO("Debug mode enabled");

	event_loop_stop = 0;
	event_loop_observers = 0;
	rc = pthread_mutex_init(&event_loop_observers_mutex, NULL);
	if (rc) {
		ILOG_ERR("Failed to create observer mutex: %d", rc);
		goto error;
	}

	nic_list = NULL;

	/*  Determine the current kernel version */
	memset(&cur_utsname, 0, sizeof(cur_utsname));

	rc = uname(&cur_utsname);
	if (rc == 0) {
		ILOG_INFO("Running on sysname: '%s', release: '%s', version '%s' machine: '%s'",
			 cur_utsname.sysname, cur_utsname.release,
			 cur_utsname.version, cur_utsname.machine);
	} else
		ILOG_WARN("Could not determine kernel version");

	/*  Initialze the iscsid listener */
	rc = iscsid_init();
	if (rc != 0)
		goto error;

	if (!foreground) {
		char buf[64];
		ssize_t written_bytes;

		fd = open(pid_file, O_WRONLY | O_CREAT, 0644);
		if (fd < 0) {
			fprintf(stderr, "ERR: Unable to create pid file: %s\n",
				pid_file);
			exit(1);
		}

		if (pipe(pipefds) < 0) {
			fprintf(stderr, "ERR: Unable to create a PIPE: %s\n",
				strerror(errno));
			exit(1);
		}

		pid = fork();
		if (pid < 0) {
			fprintf(stderr, "ERR: Starting daemon failed\n");
			exit(1);
		} else if (pid) {
			char msgbuf[4];
			int res;

			/* parent: wait for child msg then exit */
			close(pipefds[1]);	/* close unused end */
			res = read(pipefds[0], msgbuf, sizeof(msgbuf));
			assert(res > 0);
			exit(0);
		}

		/* the child */
		rc = chdir("/");
		if (rc == -1)
			fprintf(stderr, "WARN: Unable to chdir(\") [%s]\n", strerror(errno));

		if (lockf(fd, F_TLOCK, 0) < 0) {
			fprintf(stderr, "ERR: Unable to lock pid file: %s [%s]\n",
			       pid_file, strerror(errno));
			exit(1);
		}

		rc = ftruncate(fd, 0);
		if (rc == -1)
			fprintf(stderr, "WARN: ftruncate(%d, 0) failed [%s]\n",
			       fd, strerror(errno));

		sprintf(buf, "%d\n", getpid());
		written_bytes = write(fd, buf, strlen(buf));
		if (written_bytes == -1) {
			fprintf(stderr, "ERR: Could not write pid file [%s]\n",
			       strerror(errno));
			exit(1);
		}
		close(fd);

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
		ILOG_ERR("Could not create signal handling thread");

	/* Using sysfs to discover iSCSI hosts */
	nic_discover_iscsi_hosts();

	/* oom-killer will not kill us at the night... */
	if (oom_adjust())
		ILOG_DEBUG("Can not adjust oom-killer's pardon");

	/* we don't want our active sessions to be paged out... */
	if (mlockall(MCL_CURRENT | MCL_FUTURE)) {
		ILOG_ERR("failed to mlockall, exiting...");
		goto error;
	}

	/*  Start the iscsid listener */
	rc = iscsid_start();
	if (rc != 0)
		goto error;

	if (!foreground) {
		int res;

		/* signal parent they can go away now */
		close(pipefds[0]);	/* close unused end */
		res = write(pipefds[1], "ok\n", 3);
		assert(res > 0);
		close(pipefds[1]);
	}

#ifndef	NO_SYSTEMD
	sd_notify(0, "READY=1\n"
		     "STATUS=Ready to process requests\n");
#endif

	/*  NetLink connection to listen to NETLINK_ISCSI private messages */
	if (nic_nl_open() != 0)
		goto error;
	exit(0);

error:
	cleanup();
	exit(EXIT_FAILURE);
}
