#ifndef SESSION_INFO_H
#define SESSION_INFO_H
#include <sys/types.h>

#include "sysfs.h"
#include "types.h"
#include "iscsi_proto.h"
#include "config.h"

struct list;

struct session_info {
	struct list_head list;
	/* local info */
	struct iface_rec iface;
	int sid;

	/* remote info */
	char targetname[TARGET_NAME_MAXLEN + 1];
	int tpgt;
	char address[NI_MAXHOST + 1];
	int port;
	char persistent_address[NI_MAXHOST + 1];
	int persistent_port;
};

typedef int (session_match_info_fn_t)(void *data, struct session_info *info);

struct session_link_info {
	struct list_head *list;
	session_match_info_fn_t *match_fn;
	void *data;
};

#define SESSION_INFO_IFACE		0x1
#define SESSION_INFO_ISCSI_PARAMS	0x2
#define SESSION_INFO_ISCSI_STATE	0x4
#define SESSION_INFO_SCSI_DEVS		0x8
#define SESSION_INFO_HOST_DEVS		0x10

extern int session_info_create_list(void *data, struct session_info *info);
extern void session_info_free_list(struct list_head *list);
extern int session_info_print(int info_level, struct session_info *match_info);
extern void session_info_print_tree(struct list_head *list, char *prefix,
				    unsigned int flags);

#endif
