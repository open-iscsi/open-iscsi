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

#include "iscsi_err.h"
#include "initiator.h"
#include "transport.h"
#include "log.h"
#include "iscsi_util.h"
#include "iscsi_sysfs.h"
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
	.set_host_ip	= 1,
	.ep_connect	= ktransport_ep_connect,
	.ep_poll	= ktransport_ep_poll,
	.ep_disconnect	= ktransport_ep_disconnect,
	.create_conn	= cxgbi_create_conn,
};

struct iscsi_transport_template cxgb4i = {
	.name		= "cxgb4i",
	.set_host_ip	= 1,
	.ep_connect	= ktransport_ep_connect,
	.ep_poll	= ktransport_ep_poll,
	.ep_disconnect	= ktransport_ep_disconnect,
	.create_conn	= cxgbi_create_conn,
};

struct iscsi_transport_template bnx2i = {
	.name		= "bnx2i",
	.set_host_ip	= 1,
	.ep_connect	= ktransport_ep_connect,
	.ep_poll	= ktransport_ep_poll,
	.ep_disconnect	= ktransport_ep_disconnect,
};

struct iscsi_transport_template be2iscsi = {
	.name		= "be2iscsi",
	.create_conn	= be2iscsi_create_conn,
	.ep_connect	= ktransport_ep_connect,
	.ep_poll	= ktransport_ep_poll,
	.ep_disconnect	= ktransport_ep_disconnect,
};

struct iscsi_transport_template qla4xxx = {
	.name		= "qla4xxx",
	.set_host_ip	= 0,
	.ep_connect	= ktransport_ep_connect,
	.ep_poll	= ktransport_ep_poll,
	.ep_disconnect	= ktransport_ep_disconnect,
};

static struct iscsi_transport_template *iscsi_transport_templates[] = {
	&iscsi_tcp,
	&iscsi_iser,
	&cxgb3i,
	&cxgb4i,
	&bnx2i,
	&qla4xxx,
	&be2iscsi,
	NULL
};

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
			log_debug(3, "Matched transport %s\n", t->name);
			return 0;
		}
	}

	log_error("Could not find template for %s. An updated iscsiadm "
		  "is probably needed.\n", t->name);
	return ENOSYS;
}
