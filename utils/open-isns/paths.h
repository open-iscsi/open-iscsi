/*
 * Compile time configuration.
 * For now, let's keep it simple and ignore autoconf...
 *
 * Copyright (C) 2006, 2007 Olaf Kirch <olaf.kirch@oracle.com>
 */

#ifndef ISNS_CONFIG_H
#define ISNS_CONFIG_H

#define __OPENISNS_MKVERSION(maj, min)	(((maj) << 8) + (min))
#define OPENISNS_VERSION		__OPENISNS_MKVERSION(0, 90);
#define OPENISNS_VERSION_STRING		"0.90"

#define ISNS_ETCDIR			"/etc/isns"
#define ISNS_RUNDIR			"/var/run"
#define ISNS_DEFAULT_ISNSD_CONFIG	ISNS_ETCDIR "/isnsd.conf"
#define ISNS_DEFAULT_ISNSDD_CONFIG	ISNS_ETCDIR "/isnsdd.conf"
#define ISNS_DEFAULT_ISNSADM_CONFIG	ISNS_ETCDIR "/isnsadm.conf"
#define ISNS_DEFAULT_LOCAL_REGISTRY	ISNS_RUNDIR "/isns.registry"

#endif /* ISNS_CONFIG_H */
