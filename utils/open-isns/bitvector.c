/*
 * Handle bit vector as a run length encoded array of
 * 32bit words.
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#include <stdlib.h>
#include <string.h>
#include "isns.h"
#include "util.h"

struct isns_bitvector {
	unsigned int	ib_count;
	uint32_t *	ib_words;
};

void
isns_bitvector_init(isns_bitvector_t *bv)
{
	memset(bv, 0, sizeof(*bv));
}

void
isns_bitvector_destroy(isns_bitvector_t *bv)
{
	isns_free(bv->ib_words);
	memset(bv, 0, sizeof(*bv));
}

isns_bitvector_t *
isns_bitvector_alloc(void)
{
	return isns_calloc(1, sizeof(isns_bitvector_t));
}

void
isns_bitvector_free(isns_bitvector_t *bv)
{
	if (bv) {
		isns_free(bv->ib_words);
		memset(bv, 0xa5, sizeof(*bv));
		isns_free(bv);
	}
}

/*
 * Helper function to locate bit
 */
uint32_t *
__isns_bitvector_find_word(const isns_bitvector_t *bv, unsigned int bit)
{
	uint32_t	*wp, *end;

	if (bv->ib_words == NULL)
		return NULL;

	wp = bv->ib_words;
	end = wp + bv->ib_count;
	while (wp < end) {
		unsigned int	base, rlen;

		base = wp[0];
		rlen = wp[1];

		isns_assert(!(base % 32));
		if (base <= bit && bit < base + rlen * 32)
			return wp + 2 + ((bit - base) / 32);

		wp += 2 + rlen;
		isns_assert(wp <= end);
	}

	return NULL;
}

/*
 * Insert words in the middle of the array
 */
static inline void
__isns_bitvector_insert_words(isns_bitvector_t *bv,
		unsigned int offset, unsigned int count)
{
	bv->ib_words = isns_realloc(bv->ib_words,
			(bv->ib_count + count) * sizeof(uint32_t));

	/* If we insert in the middle, shift out the tail
	 * to make room for the new range. */
	isns_assert(offset <= bv->ib_count);
	if (offset < bv->ib_count) {
		memmove(bv->ib_words + offset + count,
			bv->ib_words + offset,
			(bv->ib_count - offset) * sizeof(uint32_t));
	}

	memset(bv->ib_words + offset, 0, count * sizeof(uint32_t));
	bv->ib_count += count;
}

/*
 * Insert a new range
 */
static inline uint32_t *
__isns_bitvector_insert_range(isns_bitvector_t *bv,
		unsigned int offset, unsigned int base)
{
	uint32_t	*pos;

	__isns_bitvector_insert_words(bv, offset, 3);

	pos = bv->ib_words + offset;

	*pos++ = base & ~31;
	*pos++ = 1;

	return pos;
}

/*
 * Extend an existing range
 * @offset marks the beginning of the existing range.
 */
static inline uint32_t *
__isns_bitvector_extend_range(isns_bitvector_t *bv,
		unsigned int offset, unsigned int count)
{
	uint32_t	*pos, rlen;

	/* Find the end of the range */
	pos = bv->ib_words + offset;
	rlen = pos[1];

	__isns_bitvector_insert_words(bv, offset + 2 + rlen, count);

	pos = bv->ib_words + offset;
	pos[1] += count;

	/* Return pointer to the last word of the new range. */
	return pos + 2 + rlen + count - 1;
}

/*
 * Find a suitable range for insertion
 */
static uint32_t *
__isns_bitvector_find_insert_word(isns_bitvector_t *bv, unsigned int bit)
{
	uint32_t	*wp, *end;

	if (bv->ib_words == NULL)
		return __isns_bitvector_insert_range(bv, 0, bit);

	wp = bv->ib_words;
	end = wp + bv->ib_count;
	while (wp < end) {
		unsigned int	base, rlen, distance;

		base = wp[0];
		rlen = wp[1];

		isns_assert(!(base % 32));

		if (bit < base) {
			return __isns_bitvector_insert_range(bv,
					wp - bv->ib_words, bit);
		}

		distance = (bit - base) / 32;
		if (distance < rlen) {
			/* This bit is within range */
			return wp + 2 + distance;
		}

		/* Is it efficient to extend this range?
		 * The break even point is if we have to add
		 * 3 words to extend the range, because a new
		 * range would be at least that much.
		 */
		if (distance + 1 <= rlen + 3) {
			return __isns_bitvector_extend_range(bv,
					wp - bv->ib_words,
					distance + 1 - rlen);
		}

		wp += 2 + rlen;
		isns_assert(wp <= end);
	}

	/* No suitable range found. Append one at the end */
	return __isns_bitvector_insert_range(bv,
			bv->ib_count, bit);
}

/*
 * After clearing a bit, check if the bitvector can be
 * compacted.
 */
static void
__isns_bitvector_compact(isns_bitvector_t *bv)
{
	uint32_t	*src, *dst, *end;
	unsigned int	dst_base = 0, dst_len = 0;

	if (bv->ib_words == NULL)
		return;

	src = dst = bv->ib_words;
	end = src + bv->ib_count;
	while (src < end) {
		unsigned int	base, rlen;

		base = *src++;
		rlen = *src++;

		/* Consume leading NUL words */
		while (rlen && *src == 0) {
			base += 32;
			src++;
			rlen--;
		}

		/* Consume trailing NUL words */
		while (rlen && src[rlen-1] == 0)
			rlen--;

		if (rlen != 0) {
			if (dst_len && dst_base + 32 * dst_len == base) {
				/* We can extend the previous run */
			} else {
				/* New run. Close off the previous one,
				 * if we had one. */
				if (dst_len != 0) {
					dst[0] = dst_base;
					dst[1] = dst_len;
					dst += 2 + dst_len;
				}

				dst_base = base;
				dst_len = 0;
			}

			while (rlen--)
				dst[2 + dst_len++] = *src++;
		}

		isns_assert(src <= end);
	}


	if (dst_len != 0) {
		dst[0] = dst_base;
		dst[1] = dst_len;
		dst += 2 + dst_len;
	}

	bv->ib_count = dst - bv->ib_words;
	if (bv->ib_count == 0)
		isns_bitvector_destroy(bv);
}

/*
 * Test the value of a single bit
 */
int
isns_bitvector_test_bit(const isns_bitvector_t *bv, unsigned int bit)
{
	const uint32_t	*pos;
	uint32_t	mask;

	pos = __isns_bitvector_find_word(bv, bit);
	if (pos == NULL)
		return 0;

	mask = 1 << (bit % 32);
	return !!(*pos & mask);
}

int
isns_bitvector_clear_bit(isns_bitvector_t *bv, unsigned int bit)
{
	uint32_t	*pos, oldval, mask;

	pos = __isns_bitvector_find_word(bv, bit);
	if (pos == NULL)
		return 0;

	mask = 1 << (bit % 32);
	oldval = *pos;
	*pos &= ~mask;

	__isns_bitvector_compact(bv);
	return !!(oldval & mask);
}

int
isns_bitvector_set_bit(isns_bitvector_t *bv, unsigned int bit)
{
	uint32_t	*pos, oldval = 0, mask;

	mask = 1 << (bit % 32);

	pos = __isns_bitvector_find_insert_word(bv, bit);
	if (pos != NULL) {
		oldval = *pos;
		*pos |= mask;

		return !!(oldval & mask);
	}

	return 0;
}

int
isns_bitvector_is_empty(const isns_bitvector_t *bv)
{
	uint32_t	*wp, *end;

	if (bv == NULL || bv->ib_count == 0)
		return 1;

	/* In theory, we should never have a non-compacted
	 * empty bitvector, as the only way to get one
	 * is through clear_bit.
	 * Better safe than sorry...
	 */

	wp = bv->ib_words;
	end = wp + bv->ib_count;
	while (wp < end) {
		unsigned int	base, rlen;

		base = *wp++;
		rlen = *wp++;

		while (rlen--) {
			if (*wp++)
				return 0;
		}
		isns_assert(wp <= end);
	}

	return 1;
}

int
isns_bitvector_intersect(const isns_bitvector_t *a,
			const isns_bitvector_t *b,
			isns_bitvector_t *result)
{
	const uint32_t	*runa, *runb, *enda, *endb;
	const uint32_t	*wpa = NULL, *wpb = NULL;
	uint32_t	bita = 0, lena = 0, bitb = 0, lenb = 0;
	int		found = -1;

	if (a == NULL || b == NULL)
		return -1;

	/* Returning the intersect is not implemented yet. */
	isns_assert(result == NULL);

	runa = a->ib_words;
	enda = runa + a->ib_count;
	runb = b->ib_words;
	endb = runb + b->ib_count;

	while (1) {
		unsigned int	skip;

		if (lena == 0) {
next_a:
			if (runa >= enda)
				break;
			bita = *runa++;
			lena = *runa++;
			wpa  = runa;
			runa += lena;
			lena *= 32;
		}

		if (lenb == 0) {
next_b:
			if (runb >= endb)
				break;
			bitb = *runb++;
			lenb = *runb++;
			wpb  = runb;
			runb += lenb;
			lenb *= 32;
		}

		if (bita < bitb) {
			skip = bitb - bita;

			/* range A ends before range B starts.
			 * Proceed to next run in vector A. */
			if (skip >= lena)
				goto next_a;

			bita += skip;
			lena -= skip;
			wpa  += skip / 32;
		} else
		if (bitb < bita) {
			skip = bita - bitb;

			/* range B ends before range A starts.
			 * Proceed to next run in vector B. */
			if (skip >= lenb)
				goto next_b;

			bitb += skip;
			lenb -= skip;
			wpb  += skip / 32;
		}

		isns_assert(bita == bitb);

		while (lena && lenb) {
			uint32_t intersect;

			intersect = *wpa & *wpb;

			if (!intersect)
				goto next_word;

			/* Find the bit */
			if (found < 0) {
				uint32_t mask = intersect;

				found = bita;
				while (!(mask & 1)) {
					found++;
					mask >>= 1;
				}
			}

			if (result == NULL)
				return found;

			/* Append to result vector */
			/* FIXME: TBD */

next_word:
			bita += 32; lena -= 32; wpa++;
			bitb += 32; lenb -= 32; wpb++;
		}
	}

	return found;
}

/*
 * Iterate over the bit vector
 */
void
isns_bitvector_foreach(const isns_bitvector_t *bv,
		int (*cb)(uint32_t, void *),
		void *user_data)
{
	uint32_t	*wp, *end;

	wp = bv->ib_words;
	end = wp + bv->ib_count;
	while (wp < end) {
		unsigned int	base, rlen, bits;

		base = wp[0];
		rlen = wp[1];
		bits = rlen * 32;
		wp += 2;

		while (rlen--) {
			uint32_t	mask, word;

			word = *wp++;
			for (mask = 1; mask; mask <<= 1, ++base) {
				if (word & mask)
					cb(base, user_data);
			}
		}
		isns_assert(wp <= end);
	}
}

void
isns_bitvector_dump(const isns_bitvector_t *bv, isns_print_fn_t *fn)
{
	uint32_t	*wp, *end;

	fn("Bit Vector %p (%u words):", bv, bv->ib_count);

	wp = bv->ib_words;
	end = wp + bv->ib_count;
	while (wp < end) {
		unsigned int	base, rlen, bits;

		base = wp[0];
		rlen = wp[1];
		bits = rlen * 32;
		wp += 2;

		fn(" <%u:", base);
		while (rlen--)
			fn(" 0x%x", *wp++);
		fn(">");

		isns_assert(wp <= end);
	}

	if (bv->ib_count == 0)
		fn("<empty>");
	fn("\n");
}

static inline void
__isns_bitvector_print_next(uint32_t first, uint32_t last,
		isns_print_fn_t *fn)
{
	switch (last - first) {
	case 0:
		return;
	case 1:
		fn(", %u", last);
		break;
	default:
		fn("-%u", last);
		break;
	}
}

void
isns_bitvector_print(const isns_bitvector_t *bv,
		isns_print_fn_t *fn)
{
	uint32_t	*wp, *end, first = 0, next = 0;
	const char	*sepa = "";

	wp = bv->ib_words;
	end = wp + bv->ib_count;
	while (wp < end) {
		unsigned int	base, rlen, bits;

		base = wp[0];
		rlen = wp[1];
		bits = rlen * 32;
		wp += 2;

		while (rlen--) {
			uint32_t	mask, word;

			word = *wp++;
			for (mask = 1; mask; mask <<= 1, ++base) {
				if (word & mask) {
					if (next++)
						continue;
					fn("%s%u", sepa, base);
					sepa = ", ";
					first = base;
					next = base + 1;
				} else {
					if (next)
						__isns_bitvector_print_next(first, next - 1, fn);
					first = next = 0;
				}
			}
		}
		isns_assert(wp <= end);
	}

	if (next)
		__isns_bitvector_print_next(first, next - 1, fn);

	if (*sepa == '\0')
		fn("<empty>");
	fn("\n");
}

#ifdef TEST
int
main(void)
{
	isns_bitvector_t	a, b;
	int	i;

	isns_bitvector_init(&a);
	isns_bitvector_set_bit(&a, 0);
	isns_bitvector_dump(&a, isns_print_stdout);
	isns_bitvector_set_bit(&a, 1);
	isns_bitvector_set_bit(&a, 16);
	isns_bitvector_set_bit(&a, 32);
	isns_bitvector_set_bit(&a, 64);
	isns_bitvector_dump(&a, isns_print_stdout);
	isns_bitvector_set_bit(&a, 8192);
	isns_bitvector_set_bit(&a, 8196);
	isns_bitvector_set_bit(&a, 8194);
	isns_bitvector_dump(&a, isns_print_stdout);
	isns_bitvector_set_bit(&a, 2052);
	isns_bitvector_set_bit(&a, 2049);
	isns_bitvector_set_bit(&a, 2051);
	isns_bitvector_set_bit(&a, 2050);
	isns_bitvector_dump(&a, isns_print_stdout);
	isns_bitvector_print(&a, isns_print_stdout);
	isns_bitvector_destroy(&a);

	isns_bitvector_init(&a);
	for (i = 127; i >= 0; --i)
		isns_bitvector_set_bit(&a, i);
	isns_bitvector_dump(&a, isns_print_stdout);
	printf("[Compacting]\n");
	__isns_bitvector_compact(&a);
	isns_bitvector_dump(&a, isns_print_stdout);
	isns_bitvector_print(&a, isns_print_stdout);
	isns_bitvector_destroy(&a);

	isns_bitvector_init(&a);
	for (i = 0; i < 128; ++i)
		isns_bitvector_set_bit(&a, i);
	isns_bitvector_dump(&a, isns_print_stdout);
	isns_bitvector_print(&a, isns_print_stdout);
	isns_bitvector_destroy(&a);

	isns_bitvector_init(&a);
	isns_bitvector_init(&b);
	isns_bitvector_set_bit(&a, 0);
	isns_bitvector_set_bit(&a, 77);
	isns_bitvector_set_bit(&a, 249);
	isns_bitvector_set_bit(&a, 102);

	isns_bitvector_set_bit(&b, 1);
	isns_bitvector_set_bit(&b, 76);
	isns_bitvector_set_bit(&b, 250);
	isns_bitvector_set_bit(&b, 102);
	i = isns_bitvector_intersect(&a, &b, NULL);
	if (i != 102)
		fprintf(stderr, "*** BAD: Intersect should return 102 (got %d)! ***\n", i);
	else
		printf("Intersect okay: %d\n", i);
	isns_bitvector_destroy(&a);
	isns_bitvector_destroy(&b);

	isns_bitvector_init(&a);
	isns_bitvector_set_bit(&a, 0);
	isns_bitvector_set_bit(&a, 1);
	isns_bitvector_clear_bit(&a, 1);
	isns_bitvector_clear_bit(&a, 0);
	isns_bitvector_dump(&a, isns_print_stdout);
	isns_bitvector_print(&a, isns_print_stdout);
	isns_bitvector_destroy(&a);
	return 0;
}
#endif
