/*
 * Copyright (C) IBM Corporation. 2007
 * Author: Doug Maxey <dwm@austin.ibm.com>
 * based on code written by "Prasanna Mumbai" <mumbai.prasanna@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "fw_context.h"
#include "fwparam.h"

/**
 * fw_get_entry - return boot context of portal used for boot
 * @context: firmware info of portal
 * @filepath: CURRENTLY NOT USED
 *
 * Returns non-zero if no portal was used for boot.
 *
 * This function is not thread safe.
 */
int fw_get_entry(struct boot_context *context, const char *filepath)
{
	int ret;

	ret = fwparam_ppc_boot_info(context);
	if (ret)
		ret = fwparam_ibft_sysfs_boot_info(context);

	return ret;
}

/**
 * fw_get_targets - get a boot_context struct for each target
 * @list: list to add entires on.
 *
 * Returns zero if entries were found that can be traversed with the
 * list.h helpers, or non-zero if no entries are found.
 *
 * fw_free_targets should be called to free the list.
 *
 * This function is not thread safe.
 */
int fw_get_targets(struct list_head *list)
{
	int ret;

	ret = fwparam_ppc_get_targets(list);
	if (ret)
		ret = fwparam_ibft_sysfs_get_targets(list);

	return ret;
}

void fw_free_targets(struct list_head *list)
{
	struct boot_context *curr, *tmp;

	if (!list || list_empty(list))
		return;

	list_for_each_entry_safe(curr, tmp, list, list) {
		list_del(&curr->list);
		free(curr);
	}
}

static void dump_initiator(struct boot_context *context)
{
	if (strlen(context->initiatorname))
		printf("iface.initiatorname = %s\n", context->initiatorname);

	if (strlen(context->isid))
		printf("iface.isid = %s\n", context->isid);
}

static void dump_target(struct boot_context *context)
{

	if (strlen(context->targetname))
		printf("node.name = %s\n", context->targetname);

	if (strlen(context->target_ipaddr))
		printf("node.conn[0].address = %s\n", context->target_ipaddr);
	printf("node.conn[0].port = %d\n", context->target_port);

	if (strlen(context->chap_name))
		printf("node.session.auth.username = %s\n", context->chap_name);
	if (strlen(context->chap_password))
		printf("node.session.auth.password = %s\n",
		       context->chap_password);
	if (strlen(context->chap_name_in))
		printf("node.session.auth.username_in = %s\n",
		       context->chap_name_in);
	if (strlen(context->chap_password_in))
		printf("node.session.auth.password_in = %s\n",
		       context->chap_password_in);

	if (strlen(context->lun))
		printf("node.boot_lun = %s\n", context->lun);
}

/* TODO: add defines for all the idbm strings in this file and add a macro */
static void dump_network(struct boot_context *context)
{
	/* Dump the 8 byte mac address (not iser support) */
	if (strlen(context->mac))
		printf("iface.hwaddress = %s\n", context->mac);
	/*
	 * If this has a valid address then DHCP was used (broadcom sends
	 * 0.0.0.0).
	 */
	if (strlen(context->dhcp) && strcmp(context->dhcp, "0.0.0.0"))
		printf("iface.bootproto = DHCP\n");
	else
		printf("iface.bootproto = STATIC\n");
	if (strlen(context->ipaddr))
		printf("iface.ipaddress = %s\n", context->ipaddr);
	if (strlen(context->mask))
		printf("iface.subnet_mask = %s\n", context->mask);
	if (strlen(context->gateway))
		printf("iface.gateway = %s\n", context->gateway);
	if (strlen(context->primary_dns))
		printf("iface.primary_dns = %s\n", context->primary_dns);
	if (strlen(context->secondary_dns))
		printf("iface.secondary_dns = %s\n", context->secondary_dns);
	if (strlen(context->vlan))
		printf("iface.vlan = %s\n", context->vlan);
	if (strlen(context->iface))
		printf("iface.net_ifacename = %s\n", context->iface);
}

/**
 * fw_print_entry - print boot context info of portal used for boot
 * @context: firmware info of portal
 *
 * Does not print anything if no portal was used for boot.
 *
 * TODO: Merge this in with idbm.c helpers.
 */
void fw_print_entry(struct boot_context *context)
{
	printf("# BEGIN RECORD\n");
	dump_initiator(context);
	dump_network(context);
	dump_target(context);
	printf("# END RECORD\n");
}
