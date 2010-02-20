/*
 * iSNS authentication functions
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#include <stdlib.h>
#include <string.h>
#include "isns.h"
#include "attrs.h"
#include "message.h"
#include "util.h"

/* We impose an artificial limit on the size of
 * the size of the authenticator
 */
#define ISNS_SPISTR_MAX         512

int
isns_authblock_decode(buf_t *bp, struct isns_authblk *auth)
{
	unsigned int	avail = buf_avail(bp);

	if (!buf_get32(bp, &auth->iab_bsd)
	 || !buf_get32(bp, &auth->iab_length)
	 || !buf_get64(bp, &auth->iab_timestamp)
	 || !buf_get32(bp, &auth->iab_spi_len))
		 return 0;

	/* Make sure the length specified by the auth block
	 * is reasonable. */
	if (auth->iab_length < ISNS_AUTHBLK_SIZE
	 || auth->iab_length > avail)
		return 0;

	/* This chops off any data trailing the auth block.
	 * It also makes sure that we detect if iab_length
	 * exceeds the amount of available data. */
	if (!buf_truncate(bp, auth->iab_length - ISNS_AUTHBLK_SIZE))
		return 0;

	auth->iab_spi = buf_head(bp);
	if (!buf_pull(bp, auth->iab_spi_len))
		return 0;

	auth->iab_sig = buf_head(bp);
	auth->iab_sig_len = buf_avail(bp);
	return 1;
}

int
isns_authblock_encode(buf_t *bp, const struct isns_authblk *auth)
{
	if (!buf_put32(bp, auth->iab_bsd)
	 || !buf_put32(bp, auth->iab_length)
	 || !buf_put64(bp, auth->iab_timestamp)
	 || !buf_put32(bp, auth->iab_spi_len)
	 || !buf_put(bp, auth->iab_spi, auth->iab_spi_len)
	 || !buf_put(bp, auth->iab_sig, auth->iab_sig_len))
		return 0;
	return 1;
}
