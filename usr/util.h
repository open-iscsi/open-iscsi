struct iscsi_ipc;
struct iscsiadm_req;
struct iscsiadm_rsp;
struct mgmt_ipc_db;
struct node_rec;

extern int oom_adjust(void);
extern void daemon_init(void);

extern int do_iscsid(int *ipc_fd, struct iscsiadm_req *req,
		     struct iscsiadm_rsp *rsp);
extern void iscsid_handle_error(int err);

extern void idbm_node_setup_defaults(struct node_rec *rec);
