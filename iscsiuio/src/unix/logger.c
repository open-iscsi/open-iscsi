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
#include <syslog.h>

#include "options.h"
#include "logger.h"

/******************************************************************************
 * Default logger values
 ******************************************************************************/
struct logger main_log = {
	.level = LOG_LEVEL_INFO,
};
static bool using_syslog = false;

/******************************************************************************
 * Logger Functions
 ******************************************************************************/
/**
 *  log_uip() - Main logging function
 *  @param log_prio - log priority level
 *  @param fmt - log format (followed by args, if any)
 */
void log_uip(int log_prio, char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	if (using_syslog)
		vsyslog(log_prio, fmt, ap);
	else {
		FILE *dest = stdout;

		if (log_prio == LOG_ERR)
			dest = stderr;
		vfprintf(dest, fmt, ap);
		fprintf(dest, "\n");
	}
	va_end(ap);
}

/******************************************************************************
 *  Initialize/Clean up routines
 ******************************************************************************/
/**
 *  init_logger() - Prepare the logger
 *  @param foreground_mode - whether we are running in fg or bg
 */
void init_logger(bool foreground_mode)
{
	if (!foreground_mode) {
		using_syslog = true;
		openlog(APP_NAME, 0, LOG_DAEMON);
		setlogmask(LOG_UPTO(LOG_DEBUG));
	}
}

/**
 *  fini_logger() - stop using the logger
 */
void fini_logger(void)
{
	if (using_syslog) {
		syslog(LOG_DEBUG, "Closing logger");
		closelog();
	} else
		fprintf(stderr, "Closing logger\n");
}
