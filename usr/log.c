/*
 * Copyright (C) 2002-2003 Ardis Technolgies <roman@ardistech.com>
 *
 * Released under the terms of the GNU GPL v2.0.
 */

#include <ctype.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>
#include <sys/shm.h>
#include <sys/ipc.h>
#include <sys/types.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "iscsi_util.h"
#include "log.h"

#define SEMKEY	0xA7L
#define LOGDBG 0

#if LOGDBG
#define logdbg(file, fmt, args...) fprintf(file, fmt, ##args)
#else
#define logdbg(file, fmt, args...) do {} while (0)
#endif

char *log_name;
int log_level = 0;

static int log_stop_daemon = 0;
static void (*log_func)(int prio, void *priv, const char *fmt, va_list ap);
static void *log_func_priv;

static void free_logarea (void)
{
	int shmid;

	if (!la)
		return;

	if (la->semid != -1)
		semctl(la->semid, 0, IPC_RMID, la->semarg);
	if (la->buff) {
		shmdt(la->buff);
		shmctl(la->shmid_buff, IPC_RMID, NULL);
		la->buff = NULL;
		la->shmid_buff = -1;
	}
	if (la->start) {
		shmdt(la->start);
		shmctl(la->shmid_msg, IPC_RMID, NULL);
		la->start = NULL;
		la->shmid_msg = -1;
	}
	shmid = la->shmid;
	shmdt(la);
	shmctl(shmid, IPC_RMID, NULL);
	la = NULL;
}

static int logarea_init (int size)
{
	int shmid;

	logdbg(stderr,"enter logarea_init\n");

	if ((shmid = shmget(IPC_PRIVATE, sizeof(struct logarea),
			    0644 | IPC_CREAT | IPC_EXCL)) == -1) {
		syslog(LOG_ERR, "shmget logarea failed %d", errno);
		return 1;
	}

	la = shmat(shmid, NULL, 0);
	if (!la) {
		syslog(LOG_ERR, "shmat logarea failed %d", errno);
		shmctl(shmid, IPC_RMID, NULL);
		return 1;
	}
	la->shmid = shmid;
	la->start = NULL;
	la->buff = NULL;
	la->semid = -1;

	if (size < MAX_MSG_SIZE)
		size = DEFAULT_AREA_SIZE;

	if ((shmid = shmget(IPC_PRIVATE, size,
			    0644 | IPC_CREAT | IPC_EXCL)) == -1) {
		syslog(LOG_ERR, "shmget msg failed %d", errno);
		free_logarea();
		return 1;
	}
	la->shmid_msg = shmid;

	la->start = shmat(la->shmid_msg, NULL, 0);
	if (!la->start) {
		syslog(LOG_ERR, "shmat msg failed %d", errno);
		free_logarea();
		return 1;
	}
	memset(la->start, 0, size);

	la->empty = 1;
	la->end = la->start + size;
	la->head = la->start;
	la->tail = la->start;

	if ((shmid = shmget(IPC_PRIVATE, MAX_MSG_SIZE + sizeof(struct logmsg),
			    0644 | IPC_CREAT | IPC_EXCL)) == -1) {
		syslog(LOG_ERR, "shmget logmsg failed %d", errno);
		free_logarea();
		return 1;
	}
	la->buff = shmat(shmid, NULL, 0);
	if (!la->buff) {
		syslog(LOG_ERR, "shmat logmsgfailed %d", errno);
		free_logarea();
		return 1;
	}

	if ((la->semid = semget(SEMKEY, 1, 0600 | IPC_CREAT)) < 0) {
		syslog(LOG_ERR, "semget failed %d", errno);
		free_logarea();
		return 1;
	}

	la->semarg.val=1;
	if (semctl(la->semid, 0, SETVAL, la->semarg) < 0) {
		syslog(LOG_ERR, "semctl failed %d", errno);
		free_logarea();
		return 1;
	}

	la->shmid_buff = shmid;
	la->ops[0].sem_num = 0;
	la->ops[0].sem_flg = 0;

	return 0;

}

#if LOGDBG
static void dump_logarea (void)
{
	struct logmsg * msg;

	logdbg(stderr, "\n==== area: start addr = %p, end addr = %p ====\n",
		la->start, la->end);
	logdbg(stderr, "|addr     |next     |prio|msg\n");

	for (msg = (struct logmsg *)la->head; (void *)msg != la->tail;
	     msg = msg->next)
		logdbg(stderr, "|%p |%p |%i   |%s\n", (void *)msg, msg->next,
				msg->prio, (char *)&msg->str);

	logdbg(stderr, "|%p |%p |%i   |%s\n", (void *)msg, msg->next,
			msg->prio, (char *)&msg->str);

	logdbg(stderr, "\n\n");
}
#endif

int log_enqueue (int prio, const char * fmt, va_list ap)
{
	int len, fwd;
	char buff[MAX_MSG_SIZE];
	struct logmsg * msg;
	struct logmsg * lastmsg;

	lastmsg = (struct logmsg *)la->tail;

	if (!la->empty) {
		fwd = sizeof(struct logmsg) +
		      strlen((char *)&lastmsg->str) * sizeof(char) + 1;
		la->tail += fwd;
	}
	vsnprintf(buff, MAX_MSG_SIZE, fmt, ap);
	len = strlen(buff) * sizeof(char) + 1;

	/* not enough space on tail : rewind */
	if (la->head <= la->tail &&
	    (len + sizeof(struct logmsg)) > (la->end - la->tail)) {
		logdbg(stderr, "enqueue: rewind tail to %p\n", la->tail);
			la->tail = la->start;
	}

	/* not enough space on head : drop msg */
	if (la->head > la->tail &&
	    (len + sizeof(struct logmsg)) > (la->head - la->tail)) {
		logdbg(stderr, "enqueue: log area overrun, drop msg\n");

		if (!la->empty)
			la->tail = lastmsg;

		return 1;
	}

	/* ok, we can stage the msg in the area */
	la->empty = 0;
	msg = (struct logmsg *)la->tail;
	msg->prio = prio;
	memcpy((void *)&msg->str, buff, len);
	lastmsg->next = la->tail;
	msg->next = la->head;

	logdbg(stderr, "enqueue: %p, %p, %i, %s\n", (void *)msg, msg->next,
		msg->prio, (char *)&msg->str);

#if LOGDBG
	dump_logarea();
#endif
	return 0;
}

int log_dequeue (void * buff)
{
	struct logmsg * src = (struct logmsg *)la->head;
	struct logmsg * dst = (struct logmsg *)buff;
	struct logmsg * lst = (struct logmsg *)la->tail;
	int len;

	if (la->empty)
		return 0;

	len = strlen((char *)&src->str) * sizeof(char) +
	      sizeof(struct logmsg) + 1;

	dst->prio = src->prio;
	memcpy(dst, src,  len);

	if (la->tail == la->head)
		la->empty = 1; /* purge the last log msg */
	else {
		la->head = src->next;
		lst->next = la->head;
	}
	logdbg(stderr, "dequeue: %p, %p, %i, %s\n",
	       (void *)src, src->next, src->prio, (char *)&src->str);

	memset((void *)src, 0, len);

	return len;
}

/*
 * this one can block under memory pressure
 */
static void log_syslog (void * buff)
{
	struct logmsg * msg = (struct logmsg *)buff;

	syslog(msg->prio, "%s", (char *)&msg->str);
}

void log_do_log_daemon(int prio, void *priv, const char *fmt, va_list ap)
{
	struct sembuf ops[1];

	ops[0].sem_num = la->ops[0].sem_num;
	ops[0].sem_flg = la->ops[0].sem_flg;

	ops[0].sem_op = -1;
	if (semop(la->semid, ops, 1) < 0) {
		syslog(LOG_ERR, "semop down failed %d", errno);
		return;
	}

	log_enqueue(prio, fmt, ap);

	ops[0].sem_op = 1;
	if (semop(la->semid, ops, 1) < 0)
		syslog(LOG_ERR, "semop up failed");
}

void log_do_log_std(int prio, void *priv, const char *fmt, va_list ap)
{
	if (prio == LOG_INFO) {
		vfprintf(stdout, fmt, ap);
		fprintf(stdout, "\n");
	} else {
		fprintf(stderr, "%s: ", log_name);
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
		fflush(stderr);
	}
}

void log_warning(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	log_func(LOG_WARNING, log_func_priv, fmt, ap);
	va_end(ap);
}

void log_error(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	log_func(LOG_ERR, log_func_priv, fmt, ap);
	va_end(ap);
}

void log_debug(int level, const char *fmt, ...)
{
	if (log_level > level) {
		va_list ap;
		va_start(ap, fmt);
		log_func(LOG_DEBUG, log_func_priv, fmt, ap);
		va_end(ap);
	}
}

void log_info(const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	log_func(LOG_INFO, log_func_priv, fmt, ap);
	va_end(ap);
}

static void __dump_line(int level, unsigned char *buf, int *cp)
{
	char line[16*3+5], *lp = line;
	int i, cnt;

	cnt = *cp;
	if (!cnt)
		return;
	for (i = 0; i < 16; i++) {
		if (i < cnt)
			lp += sprintf(lp, " %02x", buf[i]);
		else
			lp += sprintf(lp, "   ");
		if ((i % 4) == 3)
			lp += sprintf(lp, " |");
		if (i >= cnt || !isprint(buf[i]))
			buf[i] =  ' ';
	}
	log_debug(level, "%s %.16s |", line, buf);
	*cp = 0;
}

static void __dump_char(int level, unsigned char *buf, int *cp, int ch)
{
	int cnt = (*cp)++;

	buf[cnt] = ch;
	if (cnt == 15)
		__dump_line(level, buf, cp);
}

#define dump_line() __dump_line(level, char_buf, &char_cnt)
#define dump_char(ch) __dump_char(level, char_buf, &char_cnt, ch)

static void log_flush(void)
{
	int msglen;
	struct sembuf ops[1];

	ops[0].sem_num = la->ops[0].sem_num;
	ops[0].sem_flg = la->ops[0].sem_flg;


	while (!la->empty) {
		ops[0].sem_op = -1;
		if (semop(la->semid, ops, 1) < 0) {
			syslog(LOG_ERR, "semop down failed %d", errno);
			exit(1);
		}
		msglen = log_dequeue(la->buff);
		ops[0].sem_op = 1;
		if (semop(la->semid, ops, 1) < 0) {
			syslog(LOG_ERR, "semop up failed");
			exit(1);
		}
		if (msglen)
			log_syslog(la->buff);
	}
}

static void catch_signal(int signo)
{
	switch (signo) {
	case SIGSEGV:
		log_flush();
		break;
	case SIGTERM:
		log_stop_daemon = 1;
		break;
	}

	log_debug(1, "pid %d caught signal -%d", getpid(), signo);
}

static void __log_close(void)
{
	if (log_func == log_do_log_daemon) {
		log_flush();
		closelog();
		free_logarea();
	}
}

int log_init(char *program_name, int size,
	void (*func)(int prio, void *priv, const char *fmt, va_list ap),
	void *priv)
{
	logdbg(stderr,"enter log_init\n");
	log_name = program_name;
	log_func = func;
	log_func_priv = priv;

	if (log_func == log_do_log_daemon) {
		struct sigaction sa_old;
		struct sigaction sa_new;
		pid_t pid;

		openlog(log_name, 0, LOG_DAEMON);
		setlogmask (LOG_UPTO (LOG_DEBUG));

		if (logarea_init(size)) {
			syslog(LOG_ERR, "logarea init failed");
			return -1;
		}

		pid = fork();
		if (pid < 0) {
			syslog(LOG_ERR, "starting logger failed");
			exit(1);
		} else if (pid) {
			syslog(LOG_WARNING,
			       "iSCSI logger with pid=%d started!", pid);
			return pid;
		}

		daemon_init();

		/* flush on daemon's crash */
		sa_new.sa_handler = (void*)catch_signal;
		sigemptyset(&sa_new.sa_mask);
		sa_new.sa_flags = 0;
		sigaction(SIGSEGV, &sa_new, &sa_old );
		sigaction(SIGTERM, &sa_new, &sa_old );

		while(1) {
			log_flush();
			sleep(1);

			if (log_stop_daemon)
				break;
		}

		__log_close();
		exit(0);
	}

	return 0;
}

void log_close(pid_t pid)
{
	int status;

	if (log_func != log_do_log_daemon || pid < 0) {
		__log_close();
		return;
	}

	kill(pid, SIGTERM);
	waitpid(pid, &status, 0);
}
