/*
 * iSCSI timeout & deferred work handling
 *
 * Copyright (C) 2004 Dmitry Yusupov, Alex Aizman
 * Copyright (C) 2014 Red Hat Inc.
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
#include <time.h>
#include <sys/signalfd.h>
#include <assert.h>
#include <unistd.h>
#include "actor.h"
#include "log.h"
#include "list.h"

static LIST_HEAD(pend_list);
static LIST_HEAD(ready_list);
static volatile int poll_in_progress;

static uint64_t
actor_time_left(actor_t *thread, uint64_t current_time)
{
	if (current_time > thread->ttschedule)
		return 0;
	else
		return (thread->ttschedule - current_time);
}

#define time_after(a,b) \
	((int64_t)(b) - (int64_t)(a) < 0)

void
actor_init(actor_t *thread, void (*callback)(void *), void *data)
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
	case ACTOR_WAITING:
		/* TODO: remove/reset alarm if we were 1st entry in pend_list */
		/* priority: low */
		/* fallthrough */
	case ACTOR_SCHEDULED:
		log_debug(1, "deleting a scheduled/waiting thread!");
		list_del_init(&thread->list);
		if (list_empty(&pend_list)) {
			log_debug(7, "nothing left on pend_list, deactivating alarm");
			alarm(0);
		}

		break;
	default:
		break;
	}
	thread->state = ACTOR_NOTSCHEDULED;
}

/*
 * Inserts actor on pend list and sets alarm if new item is
 * sooner than previous entries.
 */
static void
actor_insert_on_pend_list(actor_t *thread, uint32_t delay_secs)
{
	struct actor *orig_head;
	struct actor *new_head;
	struct actor *next_thread;

	orig_head = list_first_entry_or_null(&pend_list,
					     struct actor, list);

	/* insert new entry in sort order */
	list_for_each_entry(next_thread, &pend_list, list) {
		if (time_after(next_thread->ttschedule, thread->ttschedule)) {
			log_debug(7, "next thread %p due %lld", next_thread,
			  (long long)next_thread->ttschedule);
			log_debug(7, "new thread %p is before (%lld), inserting", thread,
			  (long long)thread->ttschedule);

			/* insert new thread before the next thread */
			__list_add(&thread->list, next_thread->list.prev, &next_thread->list);
			goto inserted;
		}
	}

	if (orig_head) {
		log_debug(7, "last thread %p due %lld", next_thread,
			  (long long)next_thread->ttschedule);
		log_debug(7, "new thread %p is after (%lld), inserting at tail", thread,
			  (long long)thread->ttschedule);
	}
	else
		log_debug(7, "new thread %p due %lld is first item on pend_list", thread,
			  (long long)thread->ttschedule);

	/* Not before any existing entries */
	list_add_tail(&thread->list, &pend_list);

inserted:
	new_head = list_first_entry(&pend_list, struct actor, list);
	if (orig_head != new_head) {
		int result = alarm(delay_secs);
		log_debug(7, "new alarm set for %d seconds, old alarm %d",
			  delay_secs, result);
	}
}

static void
actor_schedule_private(actor_t *thread, uint32_t delay_secs, int head)
{
	time_t current_time;

	struct timespec tv;

	if (clock_gettime(CLOCK_MONOTONIC_COARSE, &tv)) {
		log_error("clock_getime failed, can't schedule!");
		return;
	}

	current_time = tv.tv_sec;

	log_debug(7, "thread %p schedule: delay %u state %d",
		thread, delay_secs, thread->state);

	switch(thread->state) {
	case ACTOR_WAITING:
		log_error("rescheduling a waiting thread!");
		list_del(&thread->list);
		/* fall-through */
	case ACTOR_NOTSCHEDULED:
		INIT_LIST_HEAD(&thread->list);

		if (delay_secs == 0) {
			thread->state = ACTOR_SCHEDULED;
			if (head)
				list_add(&thread->list, &ready_list);
			else
				list_add_tail(&thread->list, &ready_list);
		} else {
			thread->state = ACTOR_WAITING;
			thread->ttschedule = current_time + delay_secs;

			actor_insert_on_pend_list(thread, delay_secs);
		}
		break;
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
actor_timer(actor_t *thread, uint32_t timeout_secs, void (*callback)(void *),
	    void *data)
{
	actor_init(thread, callback, data);
	actor_schedule_private(thread, timeout_secs, 0);
}

void
actor_timer_mod(actor_t *thread, uint32_t new_timeout_secs, void *data)
{
	actor_delete(thread);
	thread->data = data;
	actor_schedule_private(thread, new_timeout_secs, 0);
}

/*
 * Execute all items that have expired.
 *
 * Set an alarm if items remain. Caller must catch SIGALRM and
 * then re-invoke this function.
 */
void
actor_poll(void)
{
	struct actor *thread, *tmp;
	uint64_t current_time;
	struct timespec tv;

	if (poll_in_progress) {
		log_error("recursive actor_poll() is not allowed");
		return;
	}

	if (clock_gettime(CLOCK_MONOTONIC_COARSE, &tv)) {
		log_error("clock_gettime failed, can't schedule!");
		return;
	}

	current_time = tv.tv_sec;

	/*
	 * Move items that are ripe from pend_list to ready_list.
	 * Actors are in sorted order of ascending run time, so
	 * stop at the first unripe entry.
	 */
	log_debug(7, "current time %" PRIu64, current_time);

	list_for_each_entry_safe(thread, tmp, &pend_list, list) {
		uint64_t time_left = actor_time_left(thread, current_time);
		if (time_left) {
			log_debug(7, "thread %08lx due %" PRIu64 ", wait %" PRIu64 " more",
				  (long)thread, thread->ttschedule, time_left);

			alarm(time_left);
			break;
		}

		/* This entry can be run now */
		list_del_init(&thread->list);

		log_debug(2, "thread %08lx was scheduled for "
			  "%" PRIu64 ", curtime %" PRIu64 " q_forw %p "
			  "&pend_list %p",
			  (long)thread, thread->ttschedule,
			  current_time, pend_list.next, &pend_list);

		list_add_tail(&thread->list, &ready_list);
		assert(thread->state == ACTOR_WAITING);
		thread->state = ACTOR_SCHEDULED;
		log_debug(7, "thread %08lx now in ready_list",
			  (long)thread);
	}

	/* Disable alarm if nothing else pending */
	if (list_empty(&pend_list)) {
		log_debug(7, "nothing on pend_list, deactivating alarm");
		alarm(0);
	}

	poll_in_progress = 1;
	while (!list_empty(&ready_list)) {
		thread = list_first_entry(&ready_list, struct actor, list);
		list_del_init(&thread->list);

		if (thread->state != ACTOR_SCHEDULED)
			log_error("ready_list: thread state corrupted! "
				  "Thread with state %d in actor list.",
				  thread->state);
		thread->state = ACTOR_NOTSCHEDULED;
		log_debug(7, "exec thread %08lx callback", (long)thread);
		thread->callback(thread->data);
		log_debug(7, "thread %08lx done", (long)thread);
	}
	poll_in_progress = 0;
}
