#ifndef ISCSI_HOST_H
#define ISCSI_HOST_H
#include <sys/types.h>

#include <libopeniscsiusr/libopeniscsiusr.h>

#include "types.h"
#include "config.h"

#define MAX_HOST_NO UINT32_MAX

#define MAX_CHAP_ENTRIES 2048
#define MAX_CHAP_BUF_SZ 4096
#define REQ_CHAP_BUF_SZ (MAX_CHAP_BUF_SZ + sizeof(struct iscsi_uevent))

struct host_info {
        struct iface_rec iface;
        uint32_t host_no;
};

extern int host_info_print(int info_level, uint32_t host_no,
			   struct iscsi_session **ses, uint32_t se_count);
extern int chap_build_config(struct iscsi_chap_rec *crec, struct iovec *iovs);

#endif
