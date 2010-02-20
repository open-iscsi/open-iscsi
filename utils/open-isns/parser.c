/*
 * parser.c - simple line based parser
 *
 * Copyright (C) 2006, 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#include <stdlib.h>
#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <err.h>
#include "util.h"

/*
 * By default, the parser will recognize any white space
 * as "word" separators.
 * If you need additional separators, you can put them
 * here.
 */
const char *	parser_separators = NULL;
const char *	parser_punctuation = "=";

char *
parser_get_next_line(FILE *fp)
{
	static char	buffer[8192];
	unsigned int	n = 0, count = 0;
	int		c, continuation = 0;

	while (n < sizeof(buffer) - 1) {
		c = fgetc(fp);
		if (c == EOF)
			break;

		count++;
		if (c == '\r')
			continue;
		/* Discard all blanks
		 * following a backslash-newline
		 */
		if (continuation) {
			if (c == ' ' || c == '\t')
				continue;
			continuation = 0;
		}

		if (c == '\n') {
			if (n && buffer[n-1] == '\\') {
				buffer[--n] = '\0';
				continuation = 1;
			}
			while (n && isspace(buffer[n-1]))
				buffer[--n] = '\0';
			if (!continuation)
				break;
			buffer[n++] = ' ';
			continue;
		}

		buffer[n++] = c;
	}

	if (count == 0)
		return NULL;

	buffer[n] = '\0';
	return buffer;
}

static inline int
is_separator(char c)
{
	if (isspace(c))
		return 1;
	return parser_separators && c && strchr(parser_separators, c);
}

static inline int
is_punctuation(char c)
{
	return parser_punctuation && c && strchr(parser_punctuation, c);
}

char *
parser_get_next_word(char **sp)
{
	static char buffer[512];
	char	*s = *sp, *p = buffer;

	while (is_separator(*s))
		++s;

	if (*s == '\0')
		goto done;

	if (is_punctuation(*s)) {
		*p++ = *s++;
		goto done;
	}

	while (*s && !is_separator(*s) && !is_punctuation(*s))
		*p++ = *s++;

done:
	*p++ = '\0';
	*sp = s;
	return buffer[0]? buffer : NULL;
}

int
parser_split_line(char *line, unsigned int argsmax, char **argv)
{
	unsigned int	argc = 0;
	char		*s;

	while (argc < argsmax && (s = parser_get_next_word(&line)))
		argv[argc++] = strdup(s);
	return argc;
}

char *
parser_get_rest_of_line(char **sp)
{
	char	*s = *sp, *res = NULL;

	while (is_separator(*s))
		++s;

	*sp = "";
	if (*s != '\0')
		res = s;
	return res;
}
