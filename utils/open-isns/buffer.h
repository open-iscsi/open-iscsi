/*
 * Buffer handling functions
 *
 * Copyright (C) 2003-2006, Olaf Kirch <olaf.kirch@oracle.com>
 */

#ifndef BUFFER_H
#define BUFFER_H

#include <sys/types.h>
#include <sys/socket.h>
#include <stdint.h>

typedef struct isns_buf {
	struct isns_buf *	next;
	unsigned char *		base;
	unsigned int		head, tail, size, max_size;
	unsigned int		write_mode : 1,
				allocated  : 1;
	int			fd;

	/* Anonymous union for misc stuff */
	union {
		struct {
			struct sockaddr_storage addr;
			socklen_t addrlen;
		};
	};
} buf_t;

extern buf_t *		buf_open(const char *, int);
extern buf_t *		buf_alloc(size_t);
extern buf_t *		buf_dup(const buf_t *);
extern void		buf_init(buf_t *, void *, size_t);
extern void		buf_init_empty(buf_t *, size_t);
extern void		buf_set(buf_t *, void *, size_t);

extern void		buf_clear(buf_t *);
extern void		buf_close(buf_t *);
extern void		buf_destroy(buf_t *);
extern void		buf_free(buf_t *);
extern void		buf_list_free(buf_t *);

extern int		buf_get(buf_t *, void *, size_t);
extern int		buf_get32(buf_t *, uint32_t *);
extern int		buf_get64(buf_t *, uint64_t *);
extern int		buf_gets(buf_t *, char *, size_t);
extern int		buf_put(buf_t *, const void *, size_t);
extern int		buf_put32(buf_t *, uint32_t);
extern int		buf_put64(buf_t *, uint64_t);
extern int		buf_puts(buf_t *, const char *);
extern int		buf_putc(buf_t *, int);
extern int		buf_read(buf_t *, int);
extern int		buf_seek(buf_t *bp, off_t offset);
extern int		buf_truncate(buf_t *, size_t);
extern void		buf_compact(buf_t *);
extern buf_t *		buf_split(buf_t **to_split, size_t len);
extern int		__buf_resize(buf_t *, size_t);

extern void		buf_list_append(buf_t **, buf_t *);

static inline size_t
buf_avail(const buf_t *bp)
{
	return bp->tail - bp->head;
}

static inline size_t
buf_tailroom(const buf_t *bp)
{
	return bp->max_size - bp->tail;
}

static inline size_t
buf_size(const buf_t *bp)
{
	return bp->size;
}

static inline void *
buf_head(const buf_t *bp)
{
	return bp->base + bp->head;
}

static inline void *
buf_tail(const buf_t *bp)
{
	return bp->base + bp->tail;
}

static inline int
buf_reserve(buf_t *bp, size_t len)
{
	if (bp->head != bp->tail)
		return 0;
	if (bp->max_size - bp->head < len)
		return 0;
	bp->head += len;
	bp->tail += len;
	return 1;
}

static inline int
buf_pull(buf_t *bp, size_t len)
{
	if (len > buf_avail(bp))
		return 0;
	bp->head += len;
	return 1;
}

static inline void *
buf_push(buf_t *bp, size_t len)
{
	if (bp->max_size - bp->tail < len)
		return NULL;

	if (bp->tail + len > bp->size
	 && !__buf_resize(bp, bp->tail + len))
		return NULL;

	bp->tail += len;
	return bp->base + bp->tail - len;
}

static inline void *
buf_push_head(buf_t *bp, size_t len)
{
	if (bp->head < len)
		return NULL;

	if (bp->tail > bp->size
	 && !__buf_resize(bp, bp->tail))
		return NULL;

	bp->head -= len;
	return bp->base + bp->head;
}

#endif /* BUFFER_H */
