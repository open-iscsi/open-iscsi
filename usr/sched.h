/*
 * iSCSI usermode single-threaded scheduler
 *
 * Copyright (C) 2004 Dmitry Yusupov, Alex Aizman
 * maintained by open-iscsi@@googlegroups.com
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
#ifndef SCHED_H
#define SCHED_H

#include "types.h"

#define SCHED_RESOLUTION	250	/* in millis */
#define SCHED_MAX_LOOPS		1

typedef enum sched_state_e {
    SCHED_WAITING,
    SCHED_SCHEDULED,
    SCHED_NOTSCHEDULED,
    SCHED_POLL_WAITING
} sched_state_e;

typedef struct sched {
    struct qelem item;
    sched_state_e state;
    void *data;
    void (*callback)(void * );
    uint32_t scheduled_at;
    uint32_t ttschedule;
} sched_t;

extern void sched_new(sched_t *thread, void (*callback)(void *), void * data);
extern void sched_delete(sched_t *thread);
extern void sched_schedule(sched_t *thread);
extern void sched_timer(sched_t *thread, uint32_t timeout,
			void (*callback)(void *), void *data);
extern int sched_timer_mod(sched_t *thread, uint32_t new_timeout, void *data);
extern void sched_poll(void);
extern void sched_init(void);

#endif
