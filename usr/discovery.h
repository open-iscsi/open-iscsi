#ifndef ISCSI_DISCOVERY_H_
#define ISCSI_DISCOVERY_H_

#include "iscsid.h"		/* for process types */
#include "string-buffer.h"

/* functions */
extern void discovery_process(struct iscsi_discovery_process *discovery);

/* functions useful for implementing other types of discovery processes */
extern int add_target_record(struct string_buffer *info, char *name, char *end,
			     int lun_inventory_changed, char *default_address,
			     char *default_port, int fd);
extern int add_portal(struct string_buffer *info, char *address, char *port,
		      char *tag);

#endif
