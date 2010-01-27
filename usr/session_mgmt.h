#ifndef _SESSION_MGMT_H_
#define _SESSION_MGMT_H_

struct node_rec;
struct list_head;
struct session_info;

extern int iscsi_login_portal(void *data, struct list_head *list,
			      struct node_rec *rec);
extern int iscsi_login_portals(void *data, int *nr_found,
			       struct list_head *rec_list,
			       int (* login_fn)(void *, struct list_head *,
						struct node_rec *));
extern int iscsi_logout_portal(struct session_info *info,
			       struct list_head *list);
extern int iscsi_logout_portals(void *data, int *nr_found,
				int (*logout_fn)(void *, struct list_head *,
						 struct session_info *));
extern int iscsi_check_for_running_session(struct node_rec *rec);

#endif
