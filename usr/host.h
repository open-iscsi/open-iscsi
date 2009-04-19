#ifndef ISCSI_HOST_H
#define ISCSI_HOST_H
#include <sys/types.h>

#include "types.h"
#include "config.h"

struct host_info {
        struct iface_rec iface;
        uint32_t host_no;
};

extern int host_info_print(int info_level, uint32_t host_no);

#endif
