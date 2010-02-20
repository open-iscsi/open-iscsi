/*
 * Stupid malloc debugger. I think I wrote something like
 * this a couple of times already. Where does all the old
 * source code go?
 */

#ifdef MDEBUG

#include <stdlib.h>
#include <string.h>
#include "util.h"

static void *		isns_malloc_default(size_t, const char *, unsigned int);
static void *		isns_calloc_default(unsigned int, size_t,
				const char *, unsigned int);
static void *		isns_realloc_default(void *, size_t,
				const char *, unsigned int);
static char *		isns_strdup_default(const char *, const char *, unsigned int);
static void		isns_free_default(void *, const char *, unsigned int);

/*
 * These are the function pointers used to redirect malloc and such.
 */
void *			(*isns_malloc_fn)(size_t, const char *, unsigned int) = isns_malloc_default;
void *			(*isns_calloc_fn)(unsigned int, size_t,
				const char *, unsigned int) = isns_calloc_default;
void *			(*isns_realloc_fn)(void *, size_t,
				const char *, unsigned int) = isns_realloc_default;
char *			(*isns_strdup_fn)(const char *, const char *, unsigned int) = isns_strdup_default;
void			(*isns_free_fn)(void *, const char *, unsigned int) = isns_free_default;

#define H_MAGIC		0xfeedbeef
#define T_MAGIC		0xbadf00d
#define CHUNK_OVERHEAD	(sizeof(struct m_header) + sizeof(struct m_trailer))

struct m_header {
	struct isns_list	h_list;
	uint32_t		h_magic;
	size_t			h_size;

	const char *		h_file;
	unsigned int		h_line;
};

struct m_trailer {
	uint32_t		t_magic[8];
	size_t			t_size;
};

static ISNS_LIST_DECLARE(m_list);
static void *			m_low_addr;
static void *			m_high_addr;
static int			m_init = 0;

static void
__isns_check_chunk(const struct m_header *head)
{
	const struct m_trailer *tail;
	int		i;

	if ((void *) head < m_low_addr
	 || (void *) head > m_high_addr) {
		isns_error("%s: m_list corrupted!\n", __FUNCTION__);
		abort();
	}

	if (head->h_magic != H_MAGIC) {
		isns_error("%s: m_list item %p with bad header magic %08x\n",
				__FUNCTION__, head, head->h_magic);
		isns_error("    Allocated from %s:%u\n",
				head->h_file, head->h_line);
		abort();
	}

	tail = ((void *) head) + sizeof(*head) + head->h_size;
	for (i = 0; i < 8; ++i) {
		if (tail->t_magic[i] == T_MAGIC)
			continue;

		isns_error("%s: m_list item %p with bad trailer magic[%d] %08x\n",
				__FUNCTION__, head, i, tail->t_magic[i]);
		isns_error("    Allocated from %s:%u\n",
				head->h_file, head->h_line);
		abort();
	}

	if (tail->t_size != head->h_size) {
		isns_error("%s: m_list item %p size mismatch; head=%u tail=%u\n",
				__FUNCTION__, head,
				head->h_size, tail->t_size);
		isns_error("    Allocated from %s:%u\n",
				head->h_file, head->h_line);
		abort();
	}
}

static void
__isns_verify_all(void)
{
	struct isns_list	*pos, *next;

	isns_list_foreach(&m_list, pos, next) {
		__isns_check_chunk(isns_list_item(struct m_header, h_list, pos));
	}
}

void *
__isns_malloc(size_t size, const char *file, unsigned int line)
{
	struct m_header	*head;
	struct m_trailer *tail;
	size_t		true_size;
	void		*ptr;
	int		i;

	__isns_verify_all();

	true_size = size + sizeof(*head) + sizeof(*tail);
	isns_assert(size < true_size);

	ptr = malloc(true_size);
	if (!ptr)
		return NULL;

	if (!m_low_addr) {
		m_low_addr = m_high_addr = ptr;
	} else if (ptr < m_low_addr) {
		m_low_addr = ptr;
	} else if (ptr > m_high_addr) {
		m_high_addr = ptr;
	}

	head = ptr;
	head->h_magic = H_MAGIC;
	head->h_size = size;
	head->h_file = file;
	head->h_line = line;
	isns_list_append(&m_list, &head->h_list);

	ptr += sizeof(*head);

	tail = ptr + size;
	for (i = 0; i < 8; ++i)
		tail->t_magic[i] = T_MAGIC;
	tail->t_size = size;

	return ptr;
}

void *
__isns_calloc(unsigned int nele, size_t size,
		const char *file, unsigned int line)
{
	void	*ptr;

	ptr = __isns_malloc(nele * size, file, line);
	if (ptr)
		memset(ptr, 0, nele * size);
	return ptr;
}

void *
__isns_realloc(void *old, size_t new_size,
		const char *file, unsigned int line)
{
	struct m_header *old_head = NULL;
	void	*new;

	if (old) {
		old_head = (old - sizeof(struct m_header));
		__isns_check_chunk(old_head);
	}

	new = __isns_malloc(new_size, file, line);
	if (new && old) {
		memcpy(new, old, old_head->h_size);
		isns_free_fn(old, file, line);
	}

	return new;
}


char *
__isns_strdup(const char *s, const char *file, unsigned int line)
{
	size_t	len;
	char	*ptr;

	len = s? strlen(s) : 0;
	ptr = __isns_malloc(len + 1, file, line);
	if (ptr) {
		memcpy(ptr, s, len);
		ptr[len] = '\0';
	}
	return ptr;
}

void
__isns_free(void *ptr, const char *file, unsigned int line)
{
	struct m_header	*head;
	size_t	true_size;

	if (ptr == NULL)
		return;

	head = ptr - sizeof(struct m_header);
	__isns_check_chunk(head);

	/*
	printf("__isns_free(%u from %s:%u): freed by %s:%u\n",
			head->h_size, head->h_file, head->h_line,
			file, line);
	   */
	true_size = head->h_size + CHUNK_OVERHEAD;
	isns_list_del(&head->h_list);

	memset(head, 0xa5, true_size);
	free(head);

	__isns_verify_all();
}

/*
 * Enable memory debugging
 */
static void
__isns_mdebug_init(void)
{
	const char	*tracefile;

	tracefile = getenv("ISNS_MTRACE");
	if (tracefile)
		isns_error("MTRACE not yet supported\n");

	if (getenv("ISNS_MDEBUG")) {
		isns_malloc_fn = __isns_malloc;
		isns_calloc_fn = __isns_calloc;
		isns_realloc_fn = __isns_realloc;
		isns_strdup_fn = __isns_strdup;
		isns_free_fn = __isns_free;
		isns_notice("Enabled memory debugging\n");
	}

	m_init = 1;
}

static inline void
isns_mdebug_init(void)
{
	if (!m_init)
		__isns_mdebug_init();
}

/*
 * Default implementations of malloc and friends
 */
static void *
isns_malloc_default(size_t size, const char *file, unsigned int line)
{
	isns_mdebug_init();
	return malloc(size);
}

static void *
isns_calloc_default(unsigned int nele, size_t size,
				const char *file, unsigned int line)
{
	isns_mdebug_init();
	return calloc(nele, size);
}

static void *
isns_realloc_default(void *old, size_t size,
				const char *file, unsigned int line)
{
	isns_mdebug_init();
	return realloc(old, size);
}

static char *
isns_strdup_default(const char *s, const char *file, unsigned int line)
{
	isns_mdebug_init();
	return strdup(s);
}

static void
isns_free_default(void *ptr, const char *file, unsigned int line)
{
	isns_mdebug_init();
	return free(ptr);
}
#endif
