/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#ifndef TYPES_H
#define TYPES_H

#include <netinet/in.h>
#include <stdint.h>
#include <sys/types.h>
#include <byteswap.h>
#include <endian.h>

struct qelem {
	struct qelem *q_forw;
	struct qelem *q_back;
};

#define DATASEG_MAX	8192
#define HDRSEG_MAX	48+4

#endif	/* TYPES_H */
