/*
 * iSCSI Administration Utility
 *
 * Copyright (C) 2004 Dmitry Yusupov, Alex Aizman
 * maintained by open-iscsi@@googlegroups.com
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * See the file COPYING included with this distribution for more details.
 */
#ifndef ISCSIADM_H
#define ISCSIADM_H

#include "types.h"
#include "strings.h"
#include "config.h"

extern char initiator_name[];
extern char initiator_alias[];

/* discovery.c */
extern int sendtargets_discovery(struct iscsi_sendtargets_config *config,
				 struct string_buffer *info);
extern int slp_discovery(struct iscsi_slp_config *config);
extern int add_target_record(struct string_buffer *info, char *name, char *end,
			     int lun_inventory_changed, char *default_address,
			     char *default_port);
extern int add_portal(struct string_buffer *info, char *address, char *port,
		      char *tag);

#endif /* ISCSIADM_H */
