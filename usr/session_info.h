#ifndef SESSION_INFO_H
#define SESSION_INFO_H
#include <sys/types.h>

#include "sysfs.h"
#include "types.h"
#include "iscsi_proto.h"
#include "config.h"

struct list;

struct session_timeout {
	int abort_tmo;
	int lu_reset_tmo;
	int recovery_tmo;
	int tgt_reset_tmo;
};

struct session_CHAP {
	char username[AUTH_STR_MAX_LEN];
	char password[AUTH_STR_MAX_LEN];
	char username_in[AUTH_STR_MAX_LEN];
	char password_in[AUTH_STR_MAX_LEN];
};

struct session_info {
	struct list_head list;
	/* local info */
	struct iface_rec iface;
	int sid;

	struct session_timeout tmo;
	struct session_CHAP chap;

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
#define SESSION_INFO_ISCSI_TIM          0x20
#define SESSION_INFO_ISCSI_AUTH         0x40

extern int session_info_create_list(void *data, struct session_info *info);
extern void session_info_free_list(struct list_head *list);
extern int session_info_print(int info_level, struct session_info *match_info,
				int do_show);
extern void session_info_print_tree(struct list_head *list, char *prefix,
				    unsigned int flags, int do_show);

#endif
