/*
 * iSCSI Safe Logging and Tracing Library
 *
 * Copyright (C) 2004 Dmitry Yusupov, Alex Aizman
 * maintained by open-iscsi@googlegroups.com
 *
 * circular buffer code based on log.c from dm-multipath project
 *
 * heavily based on code from log.c:
 *   Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>,
 *   licensed under the terms of the GNU GPL v2.0,
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

#ifndef LOG_H
#define LOG_H

#include <stdarg.h>
#include <sys/types.h>
#include "iscsid.h"

union semun {
	int val;
	struct semid_ds *buf;
	unsigned short int *array;
	struct seminfo *__buf;
};
#include <sys/sem.h>

#define DEFAULT_AREA_SIZE 16384
#define MAX_MSG_SIZE 256

extern int log_level;

struct logmsg {
	short int prio;
	void *next;
	char *str;
};

struct logarea {
	int shmid;
	int shmid_msg;
	int shmid_buff;
	int empty;
	void *head;
	void *tail;
	void *start;
	void *end;
	char *buff;
	struct sembuf ops[1];
	int semid;
	union semun semarg;
};

struct logarea *la;

extern int log_init(char *program_name, int size,
	void (*func)(int prio, void *priv, const char *fmt, va_list ap),
	void *priv);
extern void log_close (pid_t pid);
extern void dump_logmsg (void *);
extern void log_info(const char *fmt, ...)
	__attribute__ ((format (printf, 1, 2)));
extern void log_warning(const char *fmt, ...)
	__attribute__ ((format (printf, 1, 2)));
extern void log_error(const char *fmt, ...)
	__attribute__ ((format (printf, 1, 2)));
extern void log_debug(int level, const char *fmt, ...)
	__attribute__ ((format (printf, 2, 3)));

extern void log_do_log_daemon(int prio, void *priv, const char *fmt, va_list ap);
extern void log_do_log_std(int prio, void *priv, const char *fmt, va_list ap);

#endif	/* LOG_H */
