/*
 * Logging related utility functions.
 *
 * Copyright (C) 2004-2007 Olaf Kirch <okir@suse.de>
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "util.h"

static unsigned int	log_stdout = 1;
static unsigned int	debugging = 0;

/*
 * When backgrounding, any logging output should
 * go to syslog instead of stdout
 */
void
isns_log_background(void)
{
	log_stdout = 0;
}

/*
 * For output to syslog, sanitize the format string
 * by removing newlines.
 */
static const char *
sanitize_format(const char *fmt)
{
	static char	__fmt[1024];
	unsigned int	len;

	/* Don't bother unless there's a newline */
	if (!strchr(fmt, '\n'))
		return fmt;

	len = strlen(fmt);

	/* Decline if the buffer would overflow */
	if (len >= sizeof(__fmt))
		return fmt;

	strcpy(__fmt, fmt);
	while (len-- && __fmt[len] == '\n')
		__fmt[len] = '\0';

	while (len) {
		if (__fmt[len] == '\n')
			__fmt[len] = ' ';
		--len;
	}

	return __fmt;
}

/*
 * Output to stderr or syslog
 */
static void
voutput(int severity, const char *fmt, va_list ap)
{
	if (log_stdout) {
		switch (severity) {
		case LOG_ERR:
			fprintf(stderr, "Error: ");
			break;
		case LOG_WARNING:
			fprintf(stderr, "Warning: ");
			break;
		case LOG_DEBUG:
			fprintf(stderr, "   ");
			break;
		}
		vfprintf(stderr, fmt, ap);
	} else {
		fmt = sanitize_format(fmt);
		if (!fmt || !*fmt)
			return;
		vsyslog(severity, fmt, ap);
	}
}

void
isns_assert_failed(const char *condition, const char *file, unsigned int line)
{
	isns_error("Assertion failed (%s:%d): %s\n",
			file, line, condition);
	abort();
}

void
isns_fatal(const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	if (log_stdout)
		fprintf(stderr, "** FATAL ERROR **\n");
	voutput(LOG_ERR, fmt, ap);
	va_end(ap);
	exit(1);
}

void
isns_error(const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	voutput(LOG_WARNING, fmt, ap);
	va_end(ap);
}

void
isns_warning(const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	voutput(LOG_NOTICE, fmt, ap);
	va_end(ap);
}

void
isns_notice(const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	voutput(LOG_INFO, fmt, ap);
	va_end(ap);
}

void
isns_enable_debugging(const char *what)
{
	char	*copy, *s, *next;

	if (!strcmp(what, "all")) {
		debugging = ~0U;
		return;
	}
	
	copy = isns_strdup(what);
	
	for (s = copy; s; s = next) {
		if ((next = strchr(s, ',')) != NULL)
			*next++ = '\0';

		if (!strcmp(s, "general"))
			debugging |= (1 << DBG_GENERAL);
		else if (!strcmp(s, "socket"))
			debugging |= (1 << DBG_SOCKET);
		else if (!strcmp(s, "protocol"))
			debugging |= (1 << DBG_PROTOCOL);
		else if (!strcmp(s, "state"))
			debugging |= (1 << DBG_STATE);
		else if (!strcmp(s, "message"))
			debugging |= (1 << DBG_MESSAGE);
		else if (!strcmp(s, "auth"))
			debugging |= (1 << DBG_AUTH);
		else if (!strcmp(s, "scn"))
			debugging |= (1 << DBG_SCN);
		else if (!strcmp(s, "esi"))
			debugging |= (1 << DBG_ESI);
		else {
			isns_error("Ignoring unknown isns_debug facility <<%s>>\n",
					s);
		}
	}
	isns_free(copy);
}

#define DEFINE_DEBUG_FUNC(name, NAME) \
void						\
isns_debug_##name(const char *fmt, ...)		\
{						\
	va_list	ap;				\
						\
	if (!(debugging & (1 << DBG_##NAME)))	\
		return;				\
						\
	va_start(ap, fmt);			\
	voutput(LOG_DEBUG, fmt, ap);		\
	va_end(ap);				\
}
DEFINE_DEBUG_FUNC(general,	GENERAL)
DEFINE_DEBUG_FUNC(socket,	SOCKET)
DEFINE_DEBUG_FUNC(protocol,	PROTOCOL)
DEFINE_DEBUG_FUNC(message,	MESSAGE)
DEFINE_DEBUG_FUNC(auth,		AUTH)
DEFINE_DEBUG_FUNC(state,	STATE)
DEFINE_DEBUG_FUNC(scn,		SCN)
DEFINE_DEBUG_FUNC(esi,		ESI)

int
isns_debug_enabled(int fac)
{
	return (debugging & (1 << fac)) != 0;
}

/*
 * Misc isns_print_fn_t implementations
 */
void
isns_print_stdout(const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	vfprintf(stdout, fmt, ap);
	va_end(ap);
}

void
isns_print_stderr(const char *fmt, ...)
{
	va_list	ap;

	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
}
