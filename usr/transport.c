#include <stdlib.h>
#include <string.h>

#include "initiator.h"
#include "transport.h"
#include "iscsi_ipc.h"
#include "log.h"

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

static void set_uspace_transport(iscsi_provider_t *provider)
{
	int i;
	struct iscsi_uspace_transport *utransport;

	provider->utransport = NULL;
	for (i = 0; iscsi_utransports[i] != NULL; i++) {
		utransport = iscsi_utransports[i];
		if (!strcmp(utransport->name,provider->name)) {
			provider->utransport = utransport;
			break;
		}
	}

	if (provider->utransport)
		log_debug(7, "set utransport %p for transport %s\n",
			  provider->utransport, provider->name);
	else
		log_error("could not find utransport for transport %s\n",
			  provider->name);
}

/*
 * synchronyze registered transports
 */
int sync_transports(void)
{
	int i, found = 0;

	if (ipc->trans_list())
		return -1;

	for (i = 0; i < num_providers; i++) {
		if (provider[i].handle) {
			provider[i].sessions.q_forw = &provider[i].sessions;
			provider[i].sessions.q_back = &provider[i].sessions;
			set_uspace_transport(&provider[i]);

			found++;
		}
	}

	if (!found) {
		log_error("no registered transports found!");
		return -1;
	}
	log_debug(1, "synced %d transport(s)", found);

	return 0;
}
