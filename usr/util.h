#ifndef ISCSI_UTIL_H
#define ISCSI_UTIL_H

#include <stdint.h>

struct iscsiadm_req;
struct iscsiadm_rsp;
struct node_rec;
struct iface_rec;
struct session_info;

extern int oom_adjust(void);
extern void daemon_init(void);

extern int do_iscsid(struct iscsiadm_req *req,  struct iscsiadm_rsp *rsp);
extern void iscsid_handle_error(int err);

extern char *str_to_ipport(char *str, int *port, int *tgpt);
extern void idbm_node_setup_defaults(struct node_rec *rec);

extern int iscsi_match_session(void *data, struct session_info *info);
extern int __iscsi_match_session(struct node_rec *rec, char *targetname,
				 char *address, int port,
				 struct iface_rec *iface);

#endif
