/*
 * Copyright (c) 2009-2011, Broadcom Corporation
 * Copyright (c) 2014, QLogic Corporation
 *
 * Written by:  Benjamin Li  (benli@broadcom.com)
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
 * logger.h - Logging Utilities
 *
 */
#ifndef __LOGGER_H__
#define __LOGGER_H__

#include <pthread.h>
#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <sys/types.h>

/*******************************************************************************
 * Logger Levels
 ******************************************************************************/
#define LOG_LEVEL_PACKET	5
#define LOG_LEVEL_DEBUG		4
#define LOG_LEVEL_INFO		3
#define LOG_LEVEL_WARN		2
#define LOG_LEVEL_ERR		1
#define LOG_LEVEL_UNKNOWN	0

#define LOG_LEVEL_PACKET_STR	"PKT  "
#define LOG_LEVEL_DEBUG_STR	"DBG  "
#define LOG_LEVEL_INFO_STR	"INFO "
#define LOG_LEVEL_WARN_STR	"WARN "
#define LOG_LEVEL_ERR_STR	"ERR  "
#define LOG_LEVEL_UNKNOWN_STR	"?    "

/*******************************************************************************
 * Logging Macro's
 ******************************************************************************/
#define LOG_PACKET(fmt, args...) { if (LOG_LEVEL_PACKET <= \
				       main_log.level) { \
					log_uip(LOG_LEVEL_PACKET_STR, fmt,\
						##args);\
				} }
#define LOG_DEBUG(fmt, args...) { if (LOG_LEVEL_DEBUG <= main_log.level) { \
					log_uip(LOG_LEVEL_DEBUG_STR, fmt,\
						##args);\
				} }

#define LOG_INFO(fmt, args...)  { if (LOG_LEVEL_INFO <= main_log.level) { \
					log_uip(LOG_LEVEL_INFO_STR, fmt,\
						##args); \
				} }
#define LOG_WARN(fmt, args...)  { if (LOG_LEVEL_WARN <= main_log.level) { \
					log_uip(LOG_LEVEL_WARN_STR, fmt,\
						##args); \
				} }
#define LOG_ERR(fmt, args...)   { if (LOG_LEVEL_ERR <= main_log.level) { \
					log_uip(LOG_LEVEL_ERR_STR, fmt,\
						##args); \
				} }

/*******************************************************************************
 * Logging Statistics
 ******************************************************************************/
struct logger_stats {
	uint64_t debug;
	uint64_t info;
	uint64_t warn;
	uint64_t error;

	time_t last_log_time;
};

/*******************************************************************************
 * Logger Structure
 ******************************************************************************/
struct logger {
	FILE *fp;
	char *log_file;
	int8_t level;

#define LOGGER_ENABLED	0x01
#define LOGGER_DISABLED	0x02
	int8_t enabled;

	pthread_mutex_t lock;

	struct logger_stats stats;
};

extern struct logger main_log;

int init_logger(char *);
void log_uip(char *level_str, char *fmt, ...);
void fini_logger(int);

#define CLOSE_LOGGER    0x01
#define SHUTDOWN_LOGGER 0x02

#endif
