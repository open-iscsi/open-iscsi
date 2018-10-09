/*
 * iSCSI transport
 *
 * Copyright (C) 2006 Mike Christie
 * Copyright (C) 2006 Red Hat, Inc. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 */
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <libkmod.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "sysdeps.h"
#include "iscsi_err.h"
#include "initiator.h"
#include "transport.h"
#include "log.h"
#include "iscsi_util.h"
#include "iscsi_sysfs.h"
#include "uip_mgmt_ipc.h"
#include "cxgbi.h"
#include "be2iscsi.h"
#include "iser.h"

struct iscsi_transport_template iscsi_tcp = {
	.name		= "tcp",
	.ep_connect	= iscsi_io_tcp_connect,
	.ep_poll	= iscsi_io_tcp_poll,
	.ep_disconnect	= iscsi_io_tcp_disconnect,
};

struct iscsi_transport_template iscsi_iser = {
	.name		= "iser",
	.rdma		= 1,
	.ep_connect	= ktransport_ep_connect,
	.ep_poll	= ktransport_ep_poll,
	.ep_disconnect	= ktransport_ep_disconnect,
	.create_conn	= iser_create_conn,
};

struct iscsi_transport_template cxgb3i = {
	.name		= "cxgb3i",
	.set_host_ip	= SET_HOST_IP_OPT,
        .bind_ep_required = 1,
	.ep_connect	= ktransport_ep_connect,
	.ep_poll	= ktransport_ep_poll,
	.ep_disconnect	= ktransport_ep_disconnect,
	.create_conn	= cxgbi_create_conn,
};

struct iscsi_transport_template cxgb4i = {
	.name		= "cxgb4i",
	.set_host_ip	= SET_HOST_IP_NOT_REQ,
        .bind_ep_required = 1,
	.ep_connect	= ktransport_ep_connect,
	.ep_poll	= ktransport_ep_poll,
	.ep_disconnect	= ktransport_ep_disconnect,
	.create_conn	= cxgbi_create_conn,
};

struct iscsi_transport_template bnx2i = {
	.name		= "bnx2i",
	.set_host_ip	= SET_HOST_IP_REQ,
	.use_boot_info	= 1,
        .bind_ep_required = 1,
	.ep_connect	= ktransport_ep_connect,
	.ep_poll	= ktransport_ep_poll,
	.ep_disconnect	= ktransport_ep_disconnect,
	.set_net_config = uip_broadcast_params,
	.exec_ping	= uip_broadcast_ping_req,
};

struct iscsi_transport_template be2iscsi = {
	.name		= "be2iscsi",
        .bind_ep_required = 1,
	.sync_vlan_settings = 1,
	.create_conn	= be2iscsi_create_conn,
	.ep_connect	= ktransport_ep_connect,
	.ep_poll	= ktransport_ep_poll,
	.ep_disconnect	= ktransport_ep_disconnect,
};

struct iscsi_transport_template qla4xxx = {
	.name		= "qla4xxx",
	.set_host_ip	= SET_HOST_IP_NOT_REQ,
        .bind_ep_required = 1,
	.ep_connect	= ktransport_ep_connect,
	.ep_poll	= ktransport_ep_poll,
	.ep_disconnect	= ktransport_ep_disconnect,
};

struct iscsi_transport_template ocs = {
	.name		= "ocs",
        .bind_ep_required = 1,
	.ep_connect	= ktransport_ep_connect,
	.ep_poll	= ktransport_ep_poll,
	.ep_disconnect	= ktransport_ep_disconnect,
};

struct iscsi_transport_template qedi = {
	.name		= "qedi",
	.set_host_ip	= SET_HOST_IP_REQ,
	.use_boot_info	= 1,
	.bind_ep_required = 1,
	.no_netdev = 1,
	.ep_connect	= ktransport_ep_connect,
	.ep_poll	= ktransport_ep_poll,
	.ep_disconnect	= ktransport_ep_disconnect,
	.set_net_config = uip_broadcast_params,
	.exec_ping	= uip_broadcast_ping_req,
};

static struct iscsi_transport_template *iscsi_transport_templates[] = {
	&iscsi_tcp,
	&iscsi_iser,
	&cxgb3i,
	&cxgb4i,
	&bnx2i,
	&qla4xxx,
	&be2iscsi,
	&ocs,
	&qedi,
	NULL
};

int transport_probe_for_offload(void)
{
	struct if_nameindex *ifni;
	char transport_name[ISCSI_TRANSPORT_NAME_MAXLEN];
	int i, sockfd;
	struct ifreq if_hwaddr;

	ifni = if_nameindex();
	if (!ifni) {
		log_error("Could not search for transport modules: %s",
			  strerror(errno));
		return ISCSI_ERR_TRANS_NOT_FOUND;
	}

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0) {
		log_error("Could not open socket for ioctl: %s",
			  strerror(errno));
		goto free_ifni;
	}

	for (i = 0; ifni[i].if_index && ifni[i].if_name; i++) {
		struct if_nameindex *n = &ifni[i];

		log_debug(6, "kmod probe found %s", n->if_name);

		strlcpy(if_hwaddr.ifr_name, n->if_name, IFNAMSIZ);
		if (ioctl(sockfd, SIOCGIFHWADDR, &if_hwaddr) < 0)
			continue;

		/* check for ARPHRD_ETHER (ethernet) */
		if (if_hwaddr.ifr_hwaddr.sa_family != 1)
			continue;

		if (net_get_transport_name_from_netdev(n->if_name,
						       transport_name))
			continue;

		transport_load_kmod(transport_name);
	}
	close(sockfd);

free_ifni:
	if_freenameindex(ifni);
	return 0;
}

/*
 * Most distros still do not have wide libkmod use, so
 * use modprobe for now
 */
int transport_load_kmod(char *transport_name)
{
	struct kmod_ctx *ctx;
	struct kmod_module *mod;
	int rc;

	ctx = kmod_new(NULL, NULL);
	if (!ctx) {
		log_error("Could not load transport module %s. Out of "
			  "memory.", transport_name);
		return ISCSI_ERR_NOMEM;
	}

	kmod_load_resources(ctx);

	/*
	 * dumb dumb dumb - named iscsi_tcp and ib_iser differently from
	 * transport name
	 */
	if (!strcmp(transport_name, "tcp"))
		rc = kmod_module_new_from_name(ctx, "iscsi_tcp", &mod);
	else if (!strcmp(transport_name, "iser"))
		rc = kmod_module_new_from_name(ctx, "ib_iser", &mod);
	else
		rc = kmod_module_new_from_name(ctx, transport_name, &mod);
	if (rc) {
		log_error("Failed to load module %s.", transport_name);
		rc = ISCSI_ERR_TRANS_NOT_FOUND;
		goto unref_mod;
	}

	rc = kmod_module_probe_insert_module(mod, KMOD_PROBE_APPLY_BLACKLIST,
					     NULL, NULL, NULL, NULL);
	if (rc) {
		log_error("Could not insert module %s. Kmod error %d",
			  transport_name, rc);
		rc = ISCSI_ERR_TRANS_NOT_FOUND;
	}
	kmod_module_unref(mod);

unref_mod:
	kmod_unref(ctx);
	return rc;
}

int set_transport_template(struct iscsi_transport *t)
{
	struct iscsi_transport_template *tmpl;
	int j;

	for (j = 0; iscsi_transport_templates[j] != NULL; j++) {
		tmpl = iscsi_transport_templates[j];

		if (!strcmp(tmpl->name, t->name)) {
			t->template = tmpl;
			log_debug(3, "Matched transport %s", t->name);
			return 0;
		}
	}

	log_error("Could not find template for %s. An updated iscsiadm "
		  "is probably needed.", t->name);
	return ENOSYS;
}
