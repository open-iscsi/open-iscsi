/*
 * Copyright (c) 2009-2011, Broadcom Corporation
 * Copyright (c) 2014, QLogic Corporation
 *
 * Written by: Benjamin Li  (benli@broadcom.com)
 *
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
 * logger.c - Logging Utilities
 *
 */
#include <errno.h>
#include <string.h>
#include <time.h>
#include <stdarg.h>
#include <stdlib.h>

#include "options.h"
#include "logger.h"

/******************************************************************************
 * Default logger values
 ******************************************************************************/
static const char default_logger_filename[] = "/var/log/iscsiuio.log";

struct logger main_log = {
	.enabled = LOGGER_ENABLED,
	.fp = NULL,
	.log_file = (char *)default_logger_filename,
	.level = LOG_LEVEL_INFO,
	.lock = PTHREAD_MUTEX_INITIALIZER,
};

/******************************************************************************
 * Logger Functions
 ******************************************************************************/
/**
 *  log_uip() - Main logging function
 *  @param level_str - log level string
 *  @param fmt - log format
 */
void log_uip(char *level_str, char *fmt, ...)
{
	char time_buf[32];
	va_list ap;
	int oldcancelstate = -1;
	time_t t;

	/* try to stop cancellations while holding mutex, else fail quietly */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldcancelstate);

	pthread_mutex_lock(&main_log.lock);

	if (main_log.fp == NULL)
		goto end;		/* logging not enabled */

	va_start(ap, fmt);

	time(&t);
	strftime(time_buf, 26, "%a %b %d %T %Y", localtime(&t));

	fprintf(main_log.fp, "%s [%s]", level_str, time_buf);
	vfprintf(main_log.fp, fmt, ap);
	fprintf(main_log.fp, "\n");

	va_end(ap);

end:
	pthread_mutex_unlock(&main_log.lock);
	/* try to restore previous cancel state if saved, else fail quietly */
	if (oldcancelstate != -1)
		pthread_setcancelstate(oldcancelstate, NULL);
}

/******************************************************************************
 *  Initialize/Clean up routines
 ******************************************************************************/
/**
 *  init_logger() - Prepare the logger
 *  @param filename - path to where the log will be written to
 *  @return 0 on success, <0 on failure
 */
int init_logger(char *filename)
{
	int rc = 0;
	int oldcancelstate = -1;

	/* try to stop cancellations while holding mutex, else fail quietly */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldcancelstate);

	pthread_mutex_lock(&main_log.lock);

	if (opt.debug != DEBUG_ON) {
		rc = -EIO;
		goto disable;
	}
	main_log.fp = fopen(filename, "a");
	if (main_log.fp == NULL) {
		fprintf(stderr, "WARN: Could not create log file: %s <%s>\n",
		       filename, strerror(errno));
		rc = -EIO;
	}
disable:
	if (rc)
		main_log.enabled = LOGGER_DISABLED;
	else
		main_log.enabled = LOGGER_ENABLED;

	pthread_mutex_unlock(&main_log.lock);

	/* try to restore previous cancel state if saved, else fail quietly */
	if (oldcancelstate != -1)
		pthread_setcancelstate(oldcancelstate, NULL);

	if (!rc)
		LOG_INFO("Initialize logger using log file: %s", filename);

	return rc;
}

void fini_logger(int type)
{
	int oldcancelstate = -1;

	/* try to stop cancellations while holding mutex, else fail quietly */
	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &oldcancelstate);

	pthread_mutex_lock(&main_log.lock);

	if (main_log.fp != NULL) {
		fclose(main_log.fp);
		main_log.fp = NULL;

		if (opt.debug == DEBUG_ON) {
			printf("Closed logger\n");
			fflush(stdout);
		}
	}

	if (type == SHUTDOWN_LOGGER) {
		if ((main_log.log_file != NULL) &&
		    (main_log.log_file != default_logger_filename)) {
			free(main_log.log_file);
			main_log.log_file = NULL;
		}
	}

	main_log.enabled = LOGGER_DISABLED;

	pthread_mutex_unlock(&main_log.lock);

	/* try to restore previous cancel state if saved, else fail quietly */
	if (oldcancelstate != -1)
		pthread_setcancelstate(oldcancelstate, NULL);
}
