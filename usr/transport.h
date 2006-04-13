struct iscsi_conn;

struct iscsi_uspace_transport {
	const char *name;
	uint8_t rdma;
	int (*ep_connect) (iscsi_conn_t *conn, int non_blocking);
	int (*ep_poll) (iscsi_conn_t *conn, int timeout_ms);
	void (*ep_disconnect) (iscsi_conn_t *conn);
};

extern int sync_transports(void);
