#ifndef ISCSI_UTIL_H
#define ISCSI_UTIL_H

#include <stdint.h>

struct iscsiadm_req;
struct iscsiadm_rsp;
struct node_rec;

extern int oom_adjust(void);
extern void daemon_init(void);

extern int do_iscsid(int *ipc_fd, struct iscsiadm_req *req,
		     struct iscsiadm_rsp *rsp);
extern void iscsid_handle_error(int err);

extern char *str_to_ipport(char *str, int *port, int delim);
extern void idbm_node_setup_defaults(struct node_rec *rec);

#endif
