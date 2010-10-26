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
#include <inttypes.h>
#include "actor.h"
#include "log.h"
#include "list.h"

static LIST_HEAD(pend_list);
static LIST_HEAD(poll_list);
static LIST_HEAD(actor_list);
static volatile uint64_t previous_time;
static volatile uint32_t scheduler_loops;
static volatile int poll_in_progress;
static volatile uint64_t actor_jiffies = 0;

#define actor_diff(_time1, _time2) ({ \
        uint64_t __ret; \
        if ((_time2) >= (_time1)) \
           __ret = (_time2) - (_time1); \
        else \
           __ret = ((~0ULL) - (_time1)) + (_time2); \
        __ret; \
})

#define ACTOR_TICKS		actor_jiffies
#define ACTOR_TICKS_10MS(_a)	(_a)
#define ACTOR_MS_TO_TICKS(_a)	((_a)/ACTOR_RESOLUTION)

static uint64_t
actor_diff_time(actor_t *thread, uint64_t current_time)
{
	uint64_t diff_time = actor_diff(thread->scheduled_at, current_time);
	if(diff_time >= thread->ttschedule)
		return 0;
	return (thread->ttschedule - diff_time);
}

#define time_after(a,b) \
	((int64_t)(b) - (int64_t)(a) < 0)

void
actor_init(void)
{
	poll_in_progress = 0;
	previous_time = 0;
	scheduler_loops = 0;
}

void
actor_new(actor_t *thread, void (*callback)(void *), void *data)
{
	INIT_LIST_HEAD(&thread->list);
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
		list_del_init(&thread->list);
		break;
	default:
		break;
	}
	thread->state = ACTOR_NOTSCHEDULED;
}

static void
actor_schedule_private(actor_t *thread, uint32_t ttschedule, int head)
{
	uint64_t delay_time, current_time;
	actor_t *next_thread;

	delay_time = ACTOR_MS_TO_TICKS(ttschedule);
	current_time = ACTOR_TICKS;

	log_debug(7, "thread %p schedule: delay %" PRIu64 " state %d",
		thread, delay_time, thread->state);

	/* convert ttscheduled msecs in 10s of msecs by dividing for now.
	 * later we will change param to 10s of msecs */
	switch(thread->state) {
	case ACTOR_WAITING:
		log_error("rescheduling a waiting thread!");
		list_del(&thread->list);
	case ACTOR_NOTSCHEDULED:
		INIT_LIST_HEAD(&thread->list);
		/* if ttschedule is 0, put in scheduled queue and change
		 * state to scheduled, else add current time to ttschedule and
		 * insert in the queue at the correct point */
		if (delay_time == 0) {
			/* For head addition, it must go onto the head of the
			   actor_list regardless if poll is in progress or not
			 */
			if (poll_in_progress && !head) {
				thread->state = ACTOR_POLL_WAITING;
				list_add_tail(&thread->list,
					      &poll_list);
			} else {
				thread->state = ACTOR_SCHEDULED;
				if (head)
					list_add(&thread->list,
						 &actor_list);
				else
					list_add_tail(&thread->list,
						      &actor_list);
			}
		} else {
			thread->state = ACTOR_WAITING;
			thread->ttschedule = delay_time;
			thread->scheduled_at = current_time;

			/* insert new entry in sort order */
			list_for_each_entry(next_thread, &pend_list, list) {
				log_debug(7, "thread %p %" PRIu64 " %"PRIu64,
					next_thread,
					next_thread->scheduled_at +
					next_thread->ttschedule,
					current_time + delay_time);

				if (time_after(next_thread->scheduled_at +
						       next_thread->ttschedule,
						current_time + delay_time)) {
					list_add(&thread->list,
						 &next_thread->list);
					goto done;
				}
			}

			list_add_tail(&thread->list, &pend_list);
		}
done:
		break;
	case ACTOR_POLL_WAITING:
	case ACTOR_SCHEDULED:
		// don't do anything
		break;
	case ACTOR_INVALID:
		log_error("BUG: Trying to schedule a thread that has not been "
			  "setup. Ignoring sched.");
		break;
	}

}

void
actor_schedule_head(actor_t *thread)
{
	actor_schedule_private(thread, 0, 1);
}

void
actor_schedule(actor_t *thread)
{
	actor_schedule_private(thread, 0, 0);
}

void
actor_timer(actor_t *thread, uint32_t timeout, void (*callback)(void *),
	    void *data)
{
	actor_new(thread, callback, data);
	actor_schedule_private(thread, timeout, 0);
}

int
actor_timer_mod(actor_t *thread, uint32_t timeout, void *data)
{
	if (thread->state == ACTOR_WAITING) {
		list_del_init(&thread->list);
		thread->data = data;
		actor_schedule_private(thread, timeout, 0);
		return 1;
	}
	return 0;
}

void
actor_check(uint64_t current_time)
{
	struct actor *thread, *tmp;

	list_for_each_entry_safe(thread, tmp, &pend_list, list) {
		if (actor_diff_time(thread, current_time)) {
			log_debug(7, "thread %08lx wait some more",
				(long)thread);
			/* wait some more */
			break;
		}

		/* it is time to schedule this entry */
		list_del_init(&thread->list);

		log_debug(2, "thread %08lx was scheduled at %" PRIu64 ":"
			"%" PRIu64 ", curtime %" PRIu64 " q_forw %p "
			"&pend_list %p",
			(long)thread, thread->scheduled_at, thread->ttschedule,
			current_time, pend_list.next, &pend_list);

		if (poll_in_progress) {
			thread->state = ACTOR_POLL_WAITING;
			list_add_tail(&thread->list, &poll_list);
			log_debug(7, "thread %08lx now in poll_list",
				(long)thread);
		} else {
			thread->state = ACTOR_SCHEDULED;
			list_add_tail(&thread->list, &actor_list);
			log_debug(7, "thread %08lx now in actor_list",
				(long)thread);
		}
	}
}

void
actor_poll(void)
{
	uint64_t current_time;
	struct actor *thread;

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
	while (!list_empty(&actor_list)) {
		thread = list_entry(actor_list.next, struct actor, list);
		list_del_init(&thread->list);

		if (thread->state != ACTOR_SCHEDULED)
			log_error("actor_list: thread state corrupted! "
				  "Thread with state %d in actor list.",
				  thread->state);
		thread->state = ACTOR_NOTSCHEDULED;
		log_debug(7, "exec thread %08lx callback", (long)thread);
		thread->callback(thread->data);
		log_debug(7, "thread removed\n");
	}
	poll_in_progress = 0;

	while (!list_empty(&poll_list)) {
		thread = list_entry(poll_list.next, struct actor, list);
		list_del_init(&thread->list);

		if (thread->state != ACTOR_POLL_WAITING)
			log_error("poll_list: thread state corrupted!"
				  "Thread with state %d in poll list.",
				  thread->state);
		thread->state = ACTOR_SCHEDULED;
		list_add_tail(&thread->list, &actor_list);
		log_debug(7, "thread %08lx removed from poll_list",
			(long)thread);
	}

	ACTOR_TICKS++;
}
