/*
 * util.c
 *
 * Misc utility functions
 *
 * Copyright (C) 2006, 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>
#include <errno.h>
#include "util.h"

unsigned long
parse_size(const char *arg)
{
    unsigned long	mult = 1, ret;
    char		*s;

    ret = strtol(arg, &s, 0);

    switch (*s++) {
    case 'g':
    case 'G':
        mult = 1024 * 1024 * 1024;
	break;
    case 'm':
    case 'M':
        mult = 1024 * 1024;
	break;
    case 'k':
    case 'K':
        mult = 1024;
	break;

    case '\0':
	return ret;

    default:
    bad:
	err(1, "parse_size: unknown unit in \"%s\"\n", arg);
    }

    if (*s != '\0')
	    goto bad;

    return mult * ret;
}

char *
print_size(unsigned long size)
{
	static char	unit[] = "-kMG";
	static char	buffer[64];
	unsigned int	power = 0;

	while (size && !(size % 1024) && power < sizeof(unit)) {
		size /= 1024;
		power++;
	}

	if (!power) {
		snprintf(buffer, sizeof(buffer), "%lu", size);
	} else {
		snprintf(buffer, sizeof(buffer), "%lu%c",
				size, unit[power]);
	}
	return buffer;
}

unsigned int
parse_count(const char *arg)
{
    unsigned long	ret;
    char		*s;

    ret = strtoul(arg, &s, 0);
    if (*s != '\0')
	err(1, "parse_count: unexpected character in \"%s\"\n", arg);

    return ret;
}

int
parse_int(const char *arg)
{
    long	ret;
    char	*s;

    ret = strtol(arg, &s, 0);
    if (*s != '\0')
	err(1, "parse_count: unexpected character in \"%s\"\n", arg);

    return ret;
}

long long
parse_longlong(const char *arg)
{
    long long	ret;
    char	*s;

    ret = strtoll(arg, &s, 0);
    if (*s != '\0')
	err(1, "parse_count: unexpected character in \"%s\"\n", arg);

    return ret;
}

double
parse_double(const char *arg)
{
	double	ret;
	char	*s;

	ret = strtod(arg, &s);
	if (*s != '\0')
		err(1, "parse_count: unexpected character in \"%s\"\n", arg);

	return ret;
}

unsigned int
parse_timeout(const char *arg)
{
	unsigned int	v, ret = 0;
	char		*s;

	do {
		v = strtoul(arg, &s, 10);
		switch (*s) {
		case '\0':
			ret += v;
			break;
		case 'd':
			v *= 24;
		case 'h':
			v *= 60;
		case 'm':
			v *= 60;
		case 's':
			ret += v;
			++s;
			break;

		default:
			errx(1, "parse_timeout: unexpected character in \"%s\"\n",
					arg);
		}

		arg = s;
	} while (*arg);

	return ret;
}

void
isns_string_array_append(struct string_array *array, const char *val)
{
	if (!(array->count % 32)) {
		array->list = isns_realloc(array->list,
				(array->count + 32) * sizeof(val));
	}
	array->list[array->count++] = val? isns_strdup(val) : NULL;
}

void
isns_string_array_destroy(struct string_array *array)
{
	unsigned int	i;

	for (i = 0; i < array->count; ++i)
		isns_free(array->list[i]);
	isns_free(array->list);
	memset(array, 0, sizeof(*array));
}

void
isns_assign_string(char **var, const char *val)
{
	char	*s = NULL;

	if (val && !(s = isns_strdup(val)))
		errx(1, "out of memory");

	if (*var)
		isns_free(*var);
	*var = s;
}

/*
 * Recursively create a directory
 */
int
isns_mkdir_recursive(const char *pathname)
{
	const char *orig_pathname = pathname;
	char	*squirrel[64];
	char	*copy = NULL, *s;
	int	ns = 0;

	if (!pathname || !strcmp(pathname, "."))
		return 0;
	while (1) {
		if (mkdir(pathname, 0755) >= 0) {
			if (ns == 0)
				break;
			*squirrel[--ns] = '/';
			continue;
		}

		if (errno == EEXIST)
			goto good;
		if (errno != ENOENT)
			goto bad;

		if (copy == NULL) {
			copy = isns_strdup(pathname);
			pathname = copy;
		}

		s = strrchr(copy, '/');
		while (s > copy && s[-1] == '/')
			--s;
		*s = '\0';

		isns_assert(ns < 64);
		squirrel[ns++] = s;

		if (s == copy)
			goto bad;
	}

good:	if (copy)
		isns_free(copy);
	errno = 0;
	return 0;

bad:	if (copy)
		isns_free(copy);
	perror(orig_pathname);
	return -1;
}

/*
 * This one differs from POSIX dirname; it does not
 * modify its argument
 */
const char *
isns_dirname(const char *pathname)
{
	static char	buffer[4096];
	char		*s;

	strcpy(buffer, pathname);
	if ((s = strrchr(buffer, '/')) != NULL) {
		*s = '\0';
		return buffer;
	}
	return ".";
}
