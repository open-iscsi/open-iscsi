/*
 * Utility functions
 *
 * Copyright (C) 2006, 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#ifndef UTIL_H
#define UTIL_H

#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <string.h>	// for strdup
#include "types.h"

#define array_num_elements(a) (sizeof(a) / sizeof((a)[0]))

const char *	isns_dirname(const char *);
int		isns_mkdir_recursive(const char *);

extern const char *parser_separators;
char *		parser_get_next_line(FILE *);
char *		parser_get_next_word(char **);
char *		parser_get_rest_of_line(char **);
int		parser_split_line(char *, unsigned int, char **);

unsigned long	parse_size(const char *);
unsigned int	parse_count(const char *);
int		parse_int(const char *);
long long	parse_longlong(const char *);
double		parse_double(const char *);
unsigned int	parse_timeout(const char *);

char *		print_size(unsigned long);

/*
 * Very simple and stupid string array.
 */
struct string_array {
	unsigned int	count;
	char **		list;
};

void		isns_string_array_append(struct string_array *, const char *);
void		isns_string_array_destroy(struct string_array *);

void		isns_assign_string(char **, const char *);

void		isns_write_pidfile(const char *);
void		isns_update_pidfile(const char *);
void		isns_remove_pidfile(const char *);

extern void	isns_log_background(void);
extern void	isns_assert_failed(const char *,
			const char *, unsigned int);
extern void	isns_fatal(const char *, ...);
extern void	isns_warning(const char *, ...);
extern void	isns_error(const char *, ...);
extern void	isns_notice(const char *, ...);
extern void	isns_debug_general(const char *, ...);
extern void	isns_debug_socket(const char *, ...);
extern void	isns_debug_protocol(const char *, ...);
extern void	isns_debug_message(const char *, ...);
extern void	isns_debug_state(const char *, ...);
extern void	isns_debug_auth(const char *, ...);
extern void	isns_debug_scn(const char *, ...);
extern void	isns_debug_esi(const char *, ...);
extern void	isns_enable_debugging(const char *);
extern int	isns_debug_enabled(int);

enum {
	DBG_GENERAL = 0,
	DBG_SOCKET,
	DBG_PROTOCOL,
	DBG_MESSAGE,
	DBG_STATE,
	DBG_AUTH,
	DBG_SCN,
	DBG_ESI,
};

/*
 * There's no htonll yet
 */
#ifndef htonll
# include <endian.h>
# include <byteswap.h>
# if __BYTE_ORDER == __BIG_ENDIAN
#  define htonll(x)	(x)
#  define ntohll(x)	(x)
# elif __BYTE_ORDER == __LITTLE_ENDIAN
#  define htonll(x)	__bswap_64(x)
#  define ntohll(x)	__bswap_64(x)
# endif
#endif

/*
 * One of the those eternal staples of C coding:
 */
#ifndef MIN
# define MIN(a, b)	((a) < (b)? (a) : (b))
# define MAX(a, b)	((a) > (b)? (a) : (b))
#endif

#define DECLARE_BITMAP(name, NBITS) \
	uint32_t	name[(NBITS+31) >> 5] = { 0 }

#define __BIT_INDEX(nr)	(nr >> 5)
#define __BIT_MASK(nr)	(1 << (nr & 31))

static inline void
set_bit(uint32_t *map, unsigned int nr)
{
	map[__BIT_INDEX(nr)] |= __BIT_MASK(nr);
}

static inline void
clear_bit(uint32_t *map, unsigned int nr)
{
	map[__BIT_INDEX(nr)] &= ~__BIT_MASK(nr);
}

static inline int
test_bit(const uint32_t *map, unsigned int nr)
{
	return !!(map[__BIT_INDEX(nr)] & __BIT_MASK(nr));
}

/*
 * Dynamically sized bit vector
 */
extern isns_bitvector_t *isns_bitvector_alloc(void);
extern void	isns_bitvector_init(isns_bitvector_t *);
extern void	isns_bitvector_destroy(isns_bitvector_t *);
extern void	isns_bitvector_free(isns_bitvector_t *);
extern int	isns_bitvector_test_bit(const isns_bitvector_t *, unsigned int);
extern int	isns_bitvector_set_bit(isns_bitvector_t *, unsigned int);
extern int	isns_bitvector_clear_bit(isns_bitvector_t *, unsigned int);
extern int	isns_bitvector_is_empty(const isns_bitvector_t *);
extern int	isns_bitvector_intersect(const isns_bitvector_t *a,
				const isns_bitvector_t *b,
				isns_bitvector_t *result);
extern void	isns_bitvector_print(const isns_bitvector_t *,
				isns_print_fn_t *);
extern void	isns_bitvector_foreach(const isns_bitvector_t *bv,
				int (*cb)(uint32_t, void *),
				void *user_data);

/*
 * List manipulation primites
 */
typedef struct isns_list isns_list_t;
struct isns_list {
	isns_list_t *	next;
	isns_list_t *	prev;
};

#define ISNS_LIST_DECLARE(list) \
	isns_list_t list = { &list, &list }

static inline void
isns_list_init(isns_list_t *head)
{
	head->next = head->prev = head;
}

static inline void
__isns_list_insert(isns_list_t *prev, isns_list_t *item, isns_list_t *next)
{
	item->next = next;
	item->prev = prev;
	next->prev = item;
	prev->next = item;
}

static inline void
isns_list_append(isns_list_t *head, isns_list_t *item)
{
	__isns_list_insert(head->prev, item, head);
}

static inline void
isns_list_insert(isns_list_t *head, isns_list_t *item)
{
	__isns_list_insert(head, item, head->next);
}

static inline void
isns_item_insert_before(isns_list_t *where, isns_list_t *item)
{
	__isns_list_insert(where->prev, item, where);
}

static inline void
isns_item_insert_after(isns_list_t *where, isns_list_t *item)
{
	__isns_list_insert(where, item, where->next);
}

static inline void
isns_list_del(isns_list_t *item)
{
	isns_list_t	*prev = item->prev;
	isns_list_t	*next = item->next;

	prev->next = next;
	next->prev = prev;
	item->next = item->prev = item;
}

static inline int
isns_list_empty(const isns_list_t *head)
{
	return head == head->next;
}

static inline void
isns_list_move(isns_list_t *dst, isns_list_t *src)
{
	isns_list_t	*prev, *next;
	isns_list_t	*head, *tail;

	if (isns_list_empty(src))
		return;

	prev = dst->prev;
	next = dst;

	head = src->next;
	tail = src->prev;

	next->prev = tail;
	prev->next = head;
	head->prev = prev;
	tail->next = next;

	src->next = src->prev = src;
}

#define isns_list_item(type, member, ptr) \
	container_of(type, member, ptr)

#define isns_list_foreach(list, __pos, __next) \
	for (__pos = (list)->next; \
	     (__pos != list) && (__next = __pos->next, 1); \
	     __pos = __next) 

#if 0
/* This is defined in stddef */
#define offsetof(type, member)		((unsigned long) &(((type *) 0)->member))
#endif
#define container_of(type, member, ptr) \
	((type *) (((unsigned char *) ptr) - offsetof(type, member)))

/*
 * Use isns_assert instead of libc's assert, so that the
 * message can be captured and sent to syslog.
 */
#define isns_assert(condition) do { \
	if (!(condition))			\
		isns_assert_failed(#condition,	\
			__FILE__, __LINE__);	\
} while (0)

#ifndef MDEBUG
# define isns_malloc(size)		malloc(size)
# define isns_calloc(n, size)		calloc(n, size)
# define isns_realloc(p, size)		realloc(p, size)
# define isns_strdup(s)			strdup(s)
# define isns_free(p)			free(p)
#else
# define isns_malloc(size)		isns_malloc_fn(size, __FILE__, __LINE__)
# define isns_calloc(n, size)		isns_calloc_fn(n, size, __FILE__, __LINE__)
# define isns_realloc(p, size)		isns_realloc_fn(p, size, __FILE__, __LINE__)
# define isns_strdup(s)			isns_strdup_fn(s, __FILE__, __LINE__)
# define isns_free(p)			isns_free_fn(p, __FILE__, __LINE__)

extern void *		(*isns_malloc_fn)(size_t, const char *, unsigned int);
extern void *		(*isns_calloc_fn)(unsigned int, size_t,
				const char *, unsigned int);
extern void *		(*isns_realloc_fn)(void *, size_t,
				const char *, unsigned int);
extern char *		(*isns_strdup_fn)(const char *, const char *, unsigned int);
extern void		(*isns_free_fn)(void *, const char *, unsigned int);
#endif

#endif /* UTIL_H */
