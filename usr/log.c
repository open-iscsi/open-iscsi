/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <syslog.h>
#include <sys/time.h>

#include "log.h"

int log_daemon = 1;
int log_level = 0;

void log_init(void)
{
	if (log_daemon)
		openlog("iscsid", 0, LOG_DAEMON);
}

static void dolog(int prio, const char *fmt, va_list ap)
{
	if (log_daemon)
		vsyslog(prio, fmt, ap);
	else {
		struct timeval time;

		gettimeofday(&time, NULL);
		fprintf(stderr, "%ld.%06ld: ", time.tv_sec, time.tv_usec);
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
		fflush(stderr);
	}
}

void log_warning(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	dolog(LOG_WARNING, fmt, ap);
	va_end(ap);
}

void log_error(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	dolog(LOG_ERR, fmt, ap);
	va_end(ap);
}

void log_debug(int level, const char *fmt, ...)
{
	if (log_level > level) {
		va_list ap;
		va_start(ap, fmt);
		dolog(LOG_DEBUG, fmt, ap);
		va_end(ap);
	}
}

static void __dump_line(int level, unsigned char *buf, int *cp)
{
	char line[16*3+5], *lp = line;
	int i, cnt;

	cnt = *cp;
	if (!cnt)
		return;
	for (i = 0; i < 16; i++) {
		if (i < cnt)
			lp += sprintf(lp, " %02x", buf[i]);
		else
			lp += sprintf(lp, "   ");
		if ((i % 4) == 3)
			lp += sprintf(lp, " |");
		if (i >= cnt || !isprint(buf[i]))
			buf[i] =  ' ';
	}
	log_debug(level, "%s %.16s |", line, buf);
	*cp = 0;
}

static void __dump_char(int level, unsigned char *buf, int *cp, int ch)
{
	int cnt = (*cp)++;

	buf[cnt] = ch;
	if (cnt == 15)
		__dump_line(level, buf, cp);
}

#define dump_line() __dump_line(level, char_buf, &char_cnt)
#define dump_char(ch) __dump_char(level, char_buf, &char_cnt, ch)

void log_pdu(int level, iscsi_pdu_t *pdu)
{
	unsigned char char_buf[16];
	int char_cnt = 0;
	unsigned char *buf;
	int i;
	return;

	if (log_level <= level)
		return;

	buf = (void *)&pdu->bhs;
	log_debug(level, "BHS: (%p)", buf);
	for (i = 0; i < BHS_SIZE; i++)
		dump_char(*buf++);
	dump_line();

	buf = (void *)pdu->ahs;
	log_debug(level, "AHS: (%p)", buf);
	for (i = 0; i < pdu->ahssize; i++)
		dump_char(*buf++);
	dump_line();

	buf = (void *)pdu->data;
	log_debug(level, "Data: (%p)", buf);
	for (i = 0; i < pdu->datasize; i++)
		dump_char(*buf++);
	dump_line();
}
