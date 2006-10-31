#ifndef ISCSI_SYSFS_H
#define ISCSI_SYSFS_H

#include <search.h>
#include <sys/types.h>

struct iscsi_session;
struct iscsi_conn;

extern void check_class_version(void);
extern int get_sessioninfo_by_sysfs_id(int *sid, char *targetname,
				      char *addr, int *port, int *tpgt,
				      char *sys_session);
extern int read_sysfs_file(char *filename, void *value, char *format);
extern int sysfs_for_each_session(void *data, int *nr_found,
			int (* fn)(void *, char *, int, char *, int, int));
extern uint32_t get_host_no_from_sid(uint32_t sid, int *err);
extern int set_exp_statsn(struct iscsi_conn *conn);
extern pid_t scan_host(struct iscsi_session *session);
extern void set_device_online(int hostno, int lun);
extern void delete_device(int hostno, int lun);
extern int sysfs_for_each_device(int host_no, uint32_t sid,
				 void (* fn)(int host_no, int lun));
extern struct iscsi_provider_t *get_transport_by_hba(long host_no);
extern struct iscsi_provider_t *get_transport_by_session(char *sys_session);
extern struct iscsi_provider_t *get_transport_by_sid(uint32_t sid);
extern struct iscsi_provider_t *get_transport_by_name(char *transport_name);
extern void init_providers(void);

extern struct qelem providers;
extern int num_providers;

#endif
