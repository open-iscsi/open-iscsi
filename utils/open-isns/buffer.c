/*
 * Buffer handling functions
 *
 * Copyright (C) 2003-2007, Olaf Kirch <olaf.kirch@oracle.com>
 */

#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <errno.h>
#include <err.h>
#include <unistd.h>
#include <netinet/in.h> /* ntohl&htonl */
#include "buffer.h"
#include "util.h"	/* htonll */

static int	buf_drain(buf_t *bp);

buf_t *
buf_alloc(size_t size)
{
	buf_t	*bp;

	bp = isns_calloc(1, sizeof(*bp));
	buf_init_empty(bp, size);

	return bp;
}

buf_t *
buf_open(const char *filename, int flags)
{
	static const unsigned int buflen = 4096;
	buf_t		*bp;
	int		oerr;

	if (!(bp = isns_calloc(1, sizeof(*bp) + buflen)))
		return NULL;
	buf_init(bp, (bp + 1), buflen);

	switch (flags & O_ACCMODE) {
	case O_RDONLY:
		bp->write_mode = 0;
		break;

	case O_WRONLY:
		bp->write_mode = 1;
		break;

	default:
		errno = EINVAL;
		goto failed;
	}

	if (!filename || !strcmp(filename, "-")) {
		bp->fd = dup(bp->write_mode? 1 : 0);
	} else {
		bp->fd = open(filename, flags, 0666);
	}

	if (bp->fd < 0)
		goto failed;

	return bp;

failed:	oerr = errno;
	isns_free(bp);
	errno = oerr;
	return NULL;
}

buf_t *
buf_dup(const buf_t *src)
{
	buf_t	*bp;

	bp = buf_alloc(src->max_size);
	buf_put(bp, src->base + src->head, src->tail - src->head);

	bp->addr = src->addr;
	bp->addrlen = src->addrlen;
	return bp;
}

void
buf_close(buf_t *bp)
{
	if (bp->write_mode)
		buf_drain(bp);
	if (bp->fd >= 0)
		close(bp->fd);
	bp->fd = -1;
	isns_free(bp);
}

void
buf_free(buf_t *bp)
{
	if (!bp)
		return;
	if (bp->allocated)
		isns_free(bp->base);
	isns_free(bp);
}

void
buf_list_free(buf_t *bp)
{
	buf_t	*next;

	while (bp) {
		next = bp->next;
		buf_free(bp);
		bp = next;
	}
}

void
buf_init(buf_t *bp, void *mem, size_t len)
{
	memset(bp, 0, sizeof(*bp));
	bp->base = (unsigned char *) mem;
	bp->size = len;
	bp->max_size = len;
	bp->fd = -1;
}

void
buf_init_empty(buf_t *bp, size_t len)
{
	memset(bp, 0, sizeof(*bp));
	bp->max_size = len;
	bp->fd = -1;
}

void
buf_set(buf_t *bp, void *mem, size_t len)
{
	buf_init(bp, mem, len);
	bp->tail = len;
}

void
buf_clear(buf_t *bp)
{
	bp->head = bp->tail = 0;
}

int
buf_fill(buf_t *bp)
{
	int	n;

	if (bp->head || bp->tail)
		buf_compact(bp);

	if (bp->write_mode || bp->fd < 0)
		return 0;

	n = read(bp->fd, bp->base + bp->tail, buf_tailroom(bp));
	if (n < 0) {
		warn("read error");
		return 0;
	}

	bp->tail += n;
	return n;
}

int
buf_drain(buf_t *bp)
{
	int	n;

	if (!bp->write_mode || bp->fd < 0)
		return 0;

	n = write(bp->fd, bp->base + bp->head, buf_avail(bp));
	if (n < 0) {
		warn("write error");
		return 0;
	}

	bp->head += n;
	return n;
}

int
__buf_resize(buf_t *bp, size_t new_size)
{
	void *new_base;

	if (new_size > bp->max_size)
		return 0;
	isns_assert(bp->allocated || bp->base == NULL);

	new_size = (new_size + 127) & ~127;
	if (new_size > bp->max_size)
		new_size = bp->max_size;

	new_base = isns_realloc(bp->base, new_size);
	if (new_base == NULL)
		return 0;

	bp->base = new_base;
	bp->size = new_size;
	bp->allocated = 1;
	return new_size;
}

buf_t *
buf_split(buf_t **to_split, size_t size)
{
	buf_t *old = *to_split, *new;
	size_t avail;

	avail = buf_avail(old);
	if (size > avail)
		return NULL;

	if (size == avail) {
		*to_split = NULL;
		return old;
	}

	new = buf_alloc(size);
	buf_put(new, buf_head(old), size);
	buf_pull(old, size);

	return new;
}

int
buf_seek(buf_t *bp, off_t offset)
{
	if (bp->write_mode && !buf_drain(bp))
		return 0;
	if (lseek(bp->fd, offset, SEEK_SET) < 0) {
		warn("cannot seek to offset %ld", (long) offset);
		return 0;
	}
	return 1;
}

int
buf_get(buf_t *bp, void *mem, size_t len)
{
	caddr_t		dst = (caddr_t) mem;
	unsigned int	total = len, copy;

	while (len) {
		if ((copy = buf_avail(bp)) > len)
			copy = len;
		if (copy == 0) {
			if (!buf_fill(bp))
				return 0;
			continue;
		}
		if (dst) {
			memcpy(dst, bp->base + bp->head, copy);
			dst += copy;
		}
		bp->head += copy;
		len -= copy;
	}
	return total;
}

int
buf_get32(buf_t *bp, uint32_t *vp)
{
	if (!buf_get(bp, vp, 4))
		return 0;
	*vp = ntohl(*vp);
	return 1;
}

int
buf_get64(buf_t *bp, uint64_t *vp)
{
	if (!buf_get(bp, vp, 8))
		return 0;
	*vp = ntohll(*vp);
	return 1;
}

int
buf_gets(buf_t *bp, char *stringbuf, size_t size)
{
	uint32_t	len, copy;

	if (size == 0)
		return 0;

	if (!buf_get32(bp, &len))
		return 0;

	if ((copy = len) >= size)
		copy = size - 1;

	if (!buf_get(bp, stringbuf, copy))
		return 0;
	stringbuf[copy] = '\0';

	/* Pull remaining bytes */
	if (copy != len && !buf_pull(bp, len - copy))
		return 0;

	return copy + 1;
}

int
buf_put(buf_t *bp, const void *mem, size_t len)
{
	caddr_t		src = (caddr_t) mem;
	unsigned int	total = len, copy;

	while (len) {
		if ((copy = bp->size - bp->tail) > len)
			copy = len;
		if (copy == 0) {
			if (buf_drain(bp)) {
				buf_compact(bp);
				continue;
			}
			if (__buf_resize(bp, bp->tail + len)) {
				buf_compact(bp);
				continue;
			}
			return 0;
		}
		if (src) {
			memcpy(bp->base + bp->tail, src, copy);
			src += copy;
		}
		bp->tail += copy;
		len -= copy;
	}
	return total;
}

int
buf_putc(buf_t *bp, int byte)
{
	unsigned char	c = byte;

	return buf_put(bp, &c, 1);
}

int
buf_put32(buf_t *bp, uint32_t val)
{
	val = htonl(val);
	if (!buf_put(bp, &val, 4))
		return 0;
	return 1;
}

int
buf_put64(buf_t *bp, uint64_t val)
{
	val = htonll(val);
	return buf_put(bp, &val, 8);
}

int
buf_puts(buf_t *bp, const char *sp)
{
	uint32_t	len = 0;

	if (sp)
		len = strlen(sp);
	return buf_put32(bp, len) && buf_put(bp, sp, len);
}

void
buf_compact(buf_t *bp)
{
	unsigned int	count;

	if (bp->head == 0)
		return;

	count = bp->tail - bp->head;
	memmove(bp->base, bp->base + bp->head, count);
	bp->tail -= bp->head;
	bp->head  = 0;
}

void
buf_list_append(buf_t **list, buf_t *bp)
{
	bp->next = NULL;
	while (*list)
		list = &(*list)->next;
	*list = bp;
}

int
buf_truncate(buf_t *bp, size_t len)
{
	if (bp->head + len > bp->tail)
		return 0;

	bp->tail = bp->head + len;
	return 1;
}
