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
extern int increase_max_files(void);

extern int do_iscsid(struct iscsiadm_req *req, struct iscsiadm_rsp *rsp);
extern void iscsid_handle_error(int err);
extern int iscsid_request(int *fd, struct iscsiadm_req *req);
extern int iscsid_response(int fd, int cmd, struct iscsiadm_rsp *rsp);
extern int iscsid_req_wait(int cmd, int fd);
extern int iscsid_req_by_rec_async(int cmd, struct node_rec *rec, int *fd);
extern int iscsid_req_by_rec(int cmd, struct node_rec *rec);
extern int iscsid_req_by_sid_async(int cmd, int sid, int *fd);
extern int iscsid_req_by_sid(int cmd, int sid);

extern char *str_to_ipport(char *str, int *port, int *tgpt);
extern void idbm_node_setup_defaults(struct node_rec *rec);

extern int iscsi_match_session(void *data, struct session_info *info);
extern int __iscsi_match_session(struct node_rec *rec, char *targetname,
				 char *address, int port,
				 struct iface_rec *iface);

#endif
