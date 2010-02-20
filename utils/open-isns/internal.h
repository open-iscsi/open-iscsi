/*
 * iSNS implementation - internal functions and types
 *
 * Copyright (C) 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#ifndef ISNS_INTERNAL_H
#define ISNS_INTERNAL_H

extern char *	isns_slp_build_url(uint16_t);
extern int	isns_slp_register(const char *);
extern int	isns_slp_unregister(const char *);
extern char *	isns_slp_find(void);

#endif /* ISNS_INTERNAL_H */

