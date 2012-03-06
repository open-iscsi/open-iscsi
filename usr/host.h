#ifndef ISCSI_HOST_H
#define ISCSI_HOST_H
#include <sys/types.h>

#include "types.h"
#include "config.h"

#define MAX_CHAP_BUF_SZ 4096
#define REQ_CHAP_BUF_SZ (MAX_CHAP_BUF_SZ + sizeof(struct iscsi_uevent))

struct host_info {
        struct iface_rec iface;
        uint32_t host_no;
};

extern int host_info_print(int info_level, uint32_t host_no);

#endif
