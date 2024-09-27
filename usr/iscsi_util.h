#ifndef ISCSI_UTIL_H
#define ISCSI_UTIL_H

#include <stdint.h>

struct node_rec;
struct iface_rec;
struct session_info;

extern int oom_adjust(void);
extern void daemon_init(void);
extern int increase_max_files(void);

extern char *str_to_ipport(char *str, int *port, int *tgpt);

extern int iscsi_match_session(void *data, struct session_info *info);
extern int iscsi_match_target(void *data, struct session_info *info);
extern int iscsi_match_session_count(void *data, struct session_info *info);
extern int __iscsi_match_session(struct node_rec *rec, char *targetname,
				 char *address, int port,
				 struct iface_rec *iface,
				 unsigned sid);
extern int set_thread_io_flusher(int val);

#define MATCH_ANY_SID 0

extern char *strstrip(char *s);
extern char *cfg_get_string_param(char *pathname, const char *key);

struct sockaddr_un;
extern int setup_abstract_addr(struct sockaddr_un *addr, char *unix_sock_name);

extern int iscsi_addr_match(const char *address1, const char *address2);

#endif
