/*
 * iSCSI usermode single-threaded scheduler
 *
 * Copyright (C) 2004 Dmitry Yusupov, Alex Aizman
 * maintained by open-iscsi@googlegroups.com
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

#include <search.h>
#include "actor.h"
#include "log.h"

static struct qelem pend_list;
static struct qelem poll_list;
static struct qelem actor_list;
static volatile uint32_t previous_time;
static volatile uint32_t scheduler_loops;
static volatile int poll_in_progress;
static volatile uint64_t actor_jiffies = 0;

#define actor_diff(_time1, _time2) ({ \
        uint32_t __ret; \
        if ((_time2) >= (_time1)) \
           __ret = (_time2) - (_time1); \
        else \
           __ret = (0xffffffff - (_time1)) + (_time2); \
        __ret; \
})

#define ACTOR_TICKS		actor_jiffies
#define ACTOR_TICKS_10MS(_a)	(_a)
#define ACTOR_MS_TO_TICKS(_a)	((_a)/ACTOR_RESOLUTION)

static uint32_t
actor_diff_time(actor_t *thread, uint32_t current_time)
{
	uint32_t diff_time = actor_diff(thread->scheduled_at, current_time);
	if(diff_time >= thread->ttschedule)
		return 0;
	return (thread->ttschedule - diff_time);
}

void
actor_init(void)
{
	poll_in_progress = 0;
	previous_time = 0;
	scheduler_loops = 0;
	pend_list.q_forw = &pend_list;
	pend_list.q_back = &pend_list;
	actor_list.q_forw = &actor_list;
	actor_list.q_back = &actor_list;
	poll_list.q_forw = &poll_list;
	poll_list.q_back = &poll_list;
}

void
actor_new(actor_t *thread, void (*callback)(void *), void *data)
{
	thread->item.q_forw = &thread->item;
	thread->item.q_back = &thread->item;
	thread->state = ACTOR_NOTSCHEDULED;
	thread->callback = callback;
	thread->data = data;
}

void
actor_delete(actor_t *thread)
{
	log_debug(7, "thread %08lx delete: state %d", (long)thread,
			thread->state);
	switch(thread->state) {
	case ACTOR_SCHEDULED:
	case ACTOR_WAITING:
	case ACTOR_POLL_WAITING:
		log_debug(1, "deleting a scheduled/waiting thread!");
		remque(&thread->item);
		break;
	default:
		break;
	}
	thread->state = ACTOR_NOTSCHEDULED;
}

static void
actor_schedule_private(actor_t *thread, uint32_t ttschedule)
{
	uint32_t delay_time, current_time, diff_time;
	struct qelem *next_item;
	actor_t *next_thread;

	delay_time = ACTOR_MS_TO_TICKS(ttschedule);
	current_time = ACTOR_TICKS;

	log_debug(7, "thread %08lx schedule: delay %d state %d", (long)thread,
			delay_time, thread->state);

	/* convert ttscheduled msecs in 10s of msecs by dividing for now.
	 * later we will change param to 10s of msecs */
	switch(thread->state) {
	case ACTOR_WAITING:
		log_error("rescheduling a waiting thread!");
	case ACTOR_NOTSCHEDULED:
		/* if ttschedule is 0, put in scheduled queue and change
		 * state to scheduled, else add current time to ttschedule and
		 * insert in the queue at the correct point */
		if (delay_time == 0) {
			if (poll_in_progress) {
				thread->state = ACTOR_POLL_WAITING;
				insque(&thread->item, poll_list.q_back);
			} else {
				thread->state = ACTOR_SCHEDULED;
				insque(&thread->item, actor_list.q_back);
			}
		}
		else {
			thread->state = ACTOR_WAITING;
			thread->ttschedule = delay_time;
			thread->scheduled_at = current_time;

			/* insert new entry in sort order */
			next_item = pend_list.q_forw;
			while (next_item != &pend_list) {
				next_thread = (actor_t *)next_item;
				diff_time = actor_diff(
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
	case ACTOR_POLL_WAITING:
	case ACTOR_SCHEDULED:
		// don't do anything
		break;
	}

}

void
actor_schedule(actor_t *thread)
{
	actor_schedule_private(thread, 0);
}

void
actor_timer(actor_t *thread, uint32_t timeout, void (*callback)(void *),
	    void *data)
{
	actor_new(thread, callback, data);
	actor_schedule_private(thread, timeout);
}

int
actor_timer_mod(actor_t *thread, uint32_t timeout, void *data)
{
	if (thread->state == ACTOR_WAITING) {
		remque(&thread->item);
		thread->data = data;
		actor_schedule_private(thread, timeout);
		return 1;
	}
	return 0;
}

void
actor_check(uint32_t current_time)
{
	while (pend_list.q_forw != &pend_list) {
		actor_t *thread = (actor_t *)pend_list.q_forw;

		if (actor_diff_time(thread, current_time)) {
			log_debug(7, "thread %08lx wait some more",
				(long)thread);
			/* wait some more */
			break;
		}

		/* it is time to schedule this entry */
		remque(&thread->item);

		log_debug(2, "thread %08lx was scheduled at %u:%u, curtime %u "
			"q_forw %p &pend_list %p", (long)thread,
			thread->scheduled_at, thread->ttschedule, current_time,
			pend_list.q_forw, &pend_list);

		if (poll_in_progress) {
			thread->state = ACTOR_POLL_WAITING;
			insque(&thread->item, poll_list.q_back);
			log_debug(7, "thread %08lx now in poll_list",
				(long)thread);
		} else {
			thread->state = ACTOR_SCHEDULED;
			insque(&thread->item, actor_list.q_back);
			log_debug(7, "thread %08lx now in actor_list",
				(long)thread);
		}
	}
}

void
actor_poll(void)
{
	uint32_t current_time;

	/* check that there are no any concurrency */
	if (poll_in_progress) {
		log_error("concurrent actor_poll() is not allowed");
	}

	/* don't check wait list every single poll.
	 * get new time. Shift it to make 10s of msecs approx
	 * if new time is not same as old time */
	if (scheduler_loops++ > ACTOR_MAX_LOOPS) {
		/* try coming in about every 100 msecs */
		current_time = ACTOR_TICKS;
		scheduler_loops = 0;
		/* checking whether we are in the same tick... */
		if ( ACTOR_TICKS_10MS(current_time) !=
		     ACTOR_TICKS_10MS(previous_time)) {
			previous_time = current_time;
			actor_check(current_time);
		}
	}

	/* the following code to check in the main data path */
	poll_in_progress = 1;
	while (actor_list.q_forw != &actor_list) {
		actor_t *thread = (actor_t *)actor_list.q_forw;
		if (thread->state != ACTOR_SCHEDULED)
			log_debug(1, "actor_list: thread state corrupted!");
		remque(&thread->item);
		thread->state = ACTOR_NOTSCHEDULED;
		log_debug(7, "exec thread %08lx callback", (long)thread);
		thread->callback(thread->data);
		log_debug(7, "thread removed\n");
	}
	poll_in_progress = 0;

	while (poll_list.q_forw != &poll_list) {
		actor_t *thread = (actor_t *)poll_list.q_forw;
		if (thread->state != ACTOR_POLL_WAITING)
			log_debug(1, "poll_list: thread state corrupted!");
		remque(&thread->item);
		thread->state = ACTOR_SCHEDULED;
		insque(&thread->item, actor_list.q_back);
		log_debug(7, "thread %08lx removed from poll_list",
			(long)thread);
	}

	ACTOR_TICKS++;
}
