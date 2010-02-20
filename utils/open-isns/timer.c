/*
 * Timers (one-short and periodic)
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#include <stdlib.h>
#include <time.h>
#include "isns.h"
#include "util.h"

typedef struct isns_timer isns_timer_t;
struct isns_timer {
	isns_list_t		it_list;
	time_t			it_when;
	unsigned int		it_period;
	isns_timer_callback_t *	it_func;
	void *			it_data;
};


static ISNS_LIST_DECLARE(timers);

static void
__isns_arm_timer(isns_timer_t *tm)
{
	isns_list_t	*pos, *next;
	time_t		when = tm->it_when;

	isns_list_foreach(&timers, pos, next) {
		isns_timer_t *cur = isns_list_item(isns_timer_t, it_list, pos);

		if (when < cur->it_when)
			break;
	}
	isns_item_insert_before(pos, &tm->it_list);
}

static isns_timer_t *
__isns_create_timer(time_t when,
		unsigned int period,
		isns_timer_callback_t *fn,
		void *data)
{
	isns_timer_t	*tm;

	tm = isns_calloc(1, sizeof(*tm));
	tm->it_when = when;
	tm->it_period = period;
	tm->it_func = fn;
	tm->it_data = data;
	return tm;
}

void
isns_add_timer(unsigned int period,
		isns_timer_callback_t *fn,
		void *data)
{
	isns_timer_t	*tm;

	isns_assert(period);
	tm = __isns_create_timer(time(NULL) + period, period, fn, data);
	__isns_arm_timer(tm);
}

void
isns_add_oneshot_timer(unsigned int expires,
		isns_timer_callback_t *fn,
		void *data)
{
	isns_timer_t	*tm;

	tm = __isns_create_timer(time(NULL) + expires, 0, fn, data);
	__isns_arm_timer(tm);
}

void
isns_cancel_timer(isns_timer_callback_t *fn, void *data)
{
	isns_list_t	*pos, *next;

	isns_list_foreach(&timers, pos, next) {
		isns_timer_t *tm = isns_list_item(isns_timer_t, it_list, pos);

		if (tm->it_func == fn
		 && (data == NULL || tm->it_data == data)) {
			isns_list_del(pos);
			isns_free(tm);
		}
	}
}

time_t
isns_run_timers(void)
{

	while (!isns_list_empty(&timers)) {
		isns_timer_t *tm = isns_list_item(isns_timer_t, it_list, timers.next);
		isns_timer_callback_t *func;
		time_t expire;
		void *data;

		expire = tm->it_when;
		if (time(NULL) < expire)
			return expire;

		isns_list_del(&tm->it_list);
		func = tm->it_func;
		data = tm->it_data;
		expire = 0;

		/* If it's a periodic timer, rearm it now. This allows
		 * the timer callback to cancel the timer. */
		if (tm->it_period) {
			tm->it_when = time(NULL) + tm->it_period;
			__isns_arm_timer(tm);
		} else {
			isns_free(tm);
		}

		func(data);
	}

	return 0;
}
