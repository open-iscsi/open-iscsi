/*
 * iSCSI timer
 *
 * Copyright (C) 2002 Cisco Systems, Inc.
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
#include <string.h>
#include <sys/time.h>

void iscsi_timer_clear(struct timeval *timer)
{
	memset(timer, 0, sizeof (*timer));
}

/* set timer to now + seconds */
void iscsi_timer_set(struct timeval *timer, int seconds)
{
	if (timer) {
		memset(timer, 0, sizeof (*timer));
		gettimeofday(timer, NULL);

		timer->tv_sec += seconds;
	}
}

int iscsi_timer_expired(struct timeval *timer)
{
	struct timeval now;

	/* no timer, can't have expired */
	if ((timer == NULL) || ((timer->tv_sec == 0) && (timer->tv_usec == 0)))
		return 0;

	memset(&now, 0, sizeof (now));
	gettimeofday(&now, NULL);

	if (now.tv_sec > timer->tv_sec)
		return 1;
	if ((now.tv_sec == timer->tv_sec) && (now.tv_usec >= timer->tv_usec))
		return 1;
	return 0;
}

int iscsi_timer_msecs_until(struct timeval *timer)
{
	struct timeval now;
	int msecs;
	long partial;

	/* no timer, can't have expired, infinite time til it expires */
	if ((timer == NULL) || ((timer->tv_sec == 0) && (timer->tv_usec == 0)))
		return -1;

	memset(&now, 0, sizeof (now));
	gettimeofday(&now, NULL);

	/* already expired? */
	if (now.tv_sec > timer->tv_sec)
		return 0;
	if ((now.tv_sec == timer->tv_sec) && (now.tv_usec >= timer->tv_usec))
		return 0;

	/* not expired yet, do the math */
	partial = timer->tv_usec - now.tv_usec;
	if (partial < 0) {
		partial += 1000 * 1000;
		msecs = (partial + 500) / 1000;
		msecs += (timer->tv_sec - now.tv_sec - 1) * 1000;
	} else {
		msecs = (partial + 500) / 1000;
		msecs += (timer->tv_sec - now.tv_sec) * 1000;
	}

	return msecs;
}
