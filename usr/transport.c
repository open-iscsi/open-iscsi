#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>

#include "initiator.h"
#include "transport.h"
#include "log.h"
#include "util.h"
#include "iscsi_sysfs.h"

struct iscsi_uspace_transport iscsi_tcp = {
	.name		= "tcp",
	.rdma		= 0,
	.ep_connect	= iscsi_io_tcp_connect,
	.ep_poll	= iscsi_io_tcp_poll,
	.ep_disconnect	= iscsi_io_tcp_disconnect
};

struct iscsi_uspace_transport iscsi_iser = {
	.name		= "iser",
	.rdma		= 1,
	.ep_connect	= ktransport_ep_connect,
	.ep_poll	= ktransport_ep_poll,
	.ep_disconnect	= ktransport_ep_disconnect
};

struct iscsi_uspace_transport *iscsi_utransports[] = {
	&iscsi_tcp,
	&iscsi_iser,
	NULL
};

int set_uspace_transport(iscsi_provider_t *p)
{
	struct iscsi_uspace_transport *utransport;
	int j;

	for (j = 0; iscsi_utransports[j] != NULL; j++) {
		utransport = iscsi_utransports[j];

		if (!strcmp(utransport->name, p->name)) {
			p->utransport = utransport;
			log_debug(3, "Matched transport %s\n", p->name);
			return 0;
		}
	}

	log_error("Could not fund uspace transport for %s\n", p->name);
	return -ENOSYS;
}
