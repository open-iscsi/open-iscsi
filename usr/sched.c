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

#include "sched.h"
#include "log.h"

static struct qelem pend_list;
static struct qelem poll_list;
static struct qelem sched_list;
static uint32_t previous_time;
static uint32_t scheduler_loops;
static int poll_in_progress;
static uint64_t sched_jiffies = 0;

#define sched_diff(_time1, _time2) ({ \
        uint32_t __ret; \
        if ((_time2) >= (_time1)) \
           __ret = (_time2) - (_time1); \
        else \
           __ret = (0xffffffff - (_time1)) + (_time2); \
        __ret; \
})

#define SCHED_TICKS		sched_jiffies
#define SCHED_TICKS_10MS(_a)	(_a)
#define SCHED_MS_TO_TICKS(_a)	((_a)/SCHED_RESOLUTION)

static uint32_t
sched_diff_time(sched_t *thread, uint32_t current_time)
{
	uint32_t diff_time = sched_diff(thread->scheduled_at, current_time);
	if(diff_time >= thread->ttschedule)
		return 0;
	return (thread->ttschedule - diff_time);
}

void
sched_init(void)
{
	poll_in_progress = 0;
	previous_time = 0;
	scheduler_loops = 0;
	pend_list.q_forw = &pend_list;
	pend_list.q_back = &pend_list;
	sched_list.q_forw = &sched_list;
	sched_list.q_back = &sched_list;
	poll_list.q_forw = &poll_list;
	poll_list.q_back = &poll_list;
}

void
sched_new(sched_t *thread, void (*callback)(void *), void *data)
{
	thread->item.q_forw = &thread->item;
	thread->item.q_back = &thread->item;
	thread->state = SCHED_NOTSCHEDULED;
	thread->callback = callback;
	thread->data = data;
}

void
sched_delete(sched_t *thread)
{
	switch(thread->state) {
	case SCHED_SCHEDULED:
	case SCHED_WAITING:
		log_debug(1, "deleting a scheduled/waiting thread!");
		remque(&thread->item);
		break;
	default:
		break;
	}
	thread->state = SCHED_NOTSCHEDULED;
}

static void
sched_schedule_private(sched_t *thread, uint32_t ttschedule)
{
	uint32_t delay_time, current_time, diff_time;
	struct qelem *next_item;
	sched_t *next_thread;

	delay_time = SCHED_MS_TO_TICKS(ttschedule);
	current_time = SCHED_TICKS;

	/* convert ttscheduled msecs in 10s of msecs by dividing for now.
	 * later we will change param to 10s of msecs */
	switch(thread->state) {
	case SCHED_WAITING:
		log_error("rescheduling a waiting thread!");
	case SCHED_NOTSCHEDULED:
		/* if ttschedule is 0, put in scheduled queue and change
		 * state to scheduled, else add current time to ttschedule and
		 * insert in the queue at the correct point */
		if (delay_time == 0) {
			if (poll_in_progress) {
				thread->state = SCHED_POLL_WAITING;
				insque(&thread->item, &poll_list);
			} else {
				thread->state = SCHED_SCHEDULED;
				insque(&thread->item, &sched_list);
			}
		}
		else {
			thread->state = SCHED_WAITING;
			thread->ttschedule = delay_time;
			thread->scheduled_at = current_time;

			/* insert new entry in sort order */
			next_item = pend_list.q_forw;
			while (next_item != &pend_list) {
				next_thread = (sched_t *)next_item;
				diff_time = sched_diff(
				      next_thread->scheduled_at, current_time);
				if ((diff_time - next_thread->ttschedule) >
				     delay_time)
					break;
				next_item = next_item->q_forw;
			}
			/* find the right place in the queue to insert
			 * need to add code */
			insque(&thread->item, next_item);
		}
		break;
	case SCHED_POLL_WAITING:
	case SCHED_SCHEDULED:
		// don't do anything
		break;
	}

}

void
sched_schedule(sched_t *thread)
{
	sched_schedule_private(thread, 0);
}

void
sched_timer(sched_t *thread, uint32_t timeout, void *data)
{
	thread->data = data;
	sched_schedule_private(thread, timeout);
}

int
sched_timer_mod(sched_t *thread, uint32_t timeout, void *data)
{
	if( thread->state == SCHED_WAITING ) {
		remque(&thread->item);
		thread->data = data;
		sched_schedule_private(thread, timeout);
		return 1;
	}
	return 0;
}

void
sched_check(uint32_t current_time)
{
	while (pend_list.q_forw != &pend_list) {
		sched_t *thread = (sched_t *)pend_list.q_forw;

		if (sched_diff_time(thread, current_time)) {
			/* wait some more */
			break;
		}

		/* it is time to schedule this entry */
		remque(pend_list.q_forw);

		log_debug(2, "thread %08lx was scheduled at %u:%u, curtime %u",
			  (long)thread, thread->scheduled_at,
			  thread->ttschedule, current_time);

		if (poll_in_progress) {
			thread->state = SCHED_POLL_WAITING;
			insque(&thread->item, &poll_list);
		} else {
			thread->state = SCHED_SCHEDULED;
			insque(&thread->item, &sched_list);
		}
	}
}

void
sched_poll(void)
{
	uint32_t current_time;

	/* check that there are no any concurrency */
	if (poll_in_progress) {
		log_error("concurrent sched_poll() is not allowed");
	}

	/* don't check wait list every single poll.
	 * get new time. Shift it to make 10s of msecs approx
	 * if new time is not same as old time */
	if (scheduler_loops++ > SCHED_MAX_LOOPS) {
		/* try coming in about every 100 msecs */
		current_time = SCHED_TICKS;
		scheduler_loops = 0;
		/* checking whether we are in the same tick... */
		if ( SCHED_TICKS_10MS(current_time) !=
		     SCHED_TICKS_10MS(previous_time)) {
			previous_time = current_time;
			sched_check(current_time);
		}
	}

	/* the following code to check in the main data path */
	poll_in_progress = 1;
	while (sched_list.q_forw != &sched_list) {
		sched_t *thread = (sched_t *)sched_list.q_forw;
		if (thread->state != SCHED_SCHEDULED)
			log_debug(1, "sched_list: thread state corrupted!");
		remque(sched_list.q_forw);
		thread->state = SCHED_NOTSCHEDULED;
		thread->callback(thread->data);
	}
	poll_in_progress = 0;

	while (poll_list.q_forw != &poll_list) {
		sched_t *thread = (sched_t *)poll_list.q_forw;
		remque(poll_list.q_forw);
		if (thread->state != SCHED_POLL_WAITING)
			log_debug(1, "poll_list: thread state corrupted!");
		thread->state = SCHED_SCHEDULED;
		insque(&thread->item, &sched_list);
	}

	SCHED_TICKS++;
}
