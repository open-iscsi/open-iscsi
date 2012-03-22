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
#include <unistd.h>
#include <stddef.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/route.h>

#include "fw_context.h"
#include "fwparam.h"
#include "idbm_fields.h"
#include "iscsi_net_util.h"
#include "iscsi_err.h"
#include "config.h"
#include "iface.h"

/**
 * fw_setup_nics - setup nics (ethXs) based on ibft net info
 *
 * Currently does not support vlans.
 *
 * If this is a offload card, this function does nothing. The
 * net info is used by the iscsi iface settings for the iscsi
 * function.
 */
int fw_setup_nics(void)
{
	struct boot_context *context;
	struct list_head targets;
	char *iface_prev = NULL, transport[16];
	int needs_bringup = 0, ret = 0, err;

	INIT_LIST_HEAD(&targets);

	ret = fw_get_targets(&targets);
	if (ret || list_empty(&targets)) {
		printf("Could not setup fw entries.\n");
		return ISCSI_ERR_NO_OBJS_FOUND;
	}

	/*
	 * For each target in iBFT bring up required NIC and use routing
	 * to force iSCSI traffic through correct NIC
	 */
	list_for_each_entry(context, &targets, list) {			
	        /* if it is a offload nic ignore it */
	        if (!net_get_transport_name_from_netdev(context->iface,
							transport))
			continue;

		if (iface_prev == NULL || strcmp(context->iface, iface_prev)) {
			/* Note: test above works because there is a
 			 * maximum of two targets in the iBFT
 			 */
			iface_prev = context->iface;
			needs_bringup = 1;
		}

		err = net_setup_netdev(context->iface, context->ipaddr,
				       context->mask, context->gateway,
				       context->target_ipaddr, needs_bringup);
		if (err)
			ret = err;
	}

	fw_free_targets(&targets);
	if (ret)
		return ISCSI_ERR;
	else
		return 0;
}

/**
 * fw_get_entry - return boot context of portal used for boot
 * @context: firmware info of portal
 *
 * Returns non-zero if no portal was used for boot.
 *
 * This function is not thread safe.
 */
int fw_get_entry(struct boot_context *context)
{
	int ret;

	ret = fwparam_ppc_boot_info(context);
	if (ret)
		ret = fwparam_sysfs_boot_info(context);
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
		ret = fwparam_sysfs_get_targets(list);
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
	struct iface_rec iface;

	memset(&iface, 0, sizeof(iface));
	iface_setup_defaults(&iface);
	iface_setup_from_boot_context(&iface, context);

	if (strlen(context->initiatorname))
		printf("%s = %s\n", IFACE_INAME, context->initiatorname);

	if (strlen(context->isid))
		printf("%s = %s\n", IFACE_ISID, context->isid);

	printf("%s = %s\n", IFACE_TRANSPORTNAME, iface.transport_name);
}

static void dump_target(struct boot_context *context)
{
	if (strlen(context->targetname))
		printf("%s = %s\n", NODE_NAME, context->targetname);

	if (strlen(context->target_ipaddr))
		printf(CONN_ADDR" = %s\n", 0, context->target_ipaddr);
	printf(CONN_PORT" = %d\n", 0, context->target_port);

	if (strlen(context->chap_name))
		printf("%s = %s\n", SESSION_USERNAME, context->chap_name);
	if (strlen(context->chap_password))
		printf("%s = %s\n", SESSION_PASSWORD, context->chap_password);
	if (strlen(context->chap_name_in))
		printf("%s = %s\n", SESSION_USERNAME_IN, context->chap_name_in);
	if (strlen(context->chap_password_in))
		printf("%s = %s\n", SESSION_PASSWORD_IN,
		       context->chap_password_in);

	if (strlen(context->lun))
		printf("%s = %s\n", NODE_BOOT_LUN, context->lun);
}

static void dump_network(struct boot_context *context)
{
	/* Dump the 8 byte mac address (not iser support) */
	if (strlen(context->mac))
		printf("%s = %s\n", IFACE_HWADDR, context->mac);
	/*
	 * If this has a valid address then DHCP was used (broadcom sends
	 * 0.0.0.0).
	 */
	if (strlen(context->dhcp) && strcmp(context->dhcp, "0.0.0.0"))
		printf("%s = DHCP\n", IFACE_BOOT_PROTO);
	else
		printf("%s = STATIC\n", IFACE_BOOT_PROTO);
	if (strlen(context->ipaddr))
		printf("%s = %s\n", IFACE_IPADDR, context->ipaddr);
	if (strlen(context->mask))
		printf("%s = %s\n", IFACE_SUBNET_MASK, context->mask);
	if (strlen(context->gateway))
		printf("%s = %s\n", IFACE_GATEWAY, context->gateway);
	if (strlen(context->primary_dns))
		printf("%s = %s\n", IFACE_PRIMARY_DNS, context->primary_dns);
	if (strlen(context->secondary_dns))
		printf("%s = %s\n", IFACE_SEC_DNS, context->secondary_dns);
	if (strlen(context->vlan))
		printf("%s = %s\n", IFACE_VLAN_ID, context->vlan);
	if (strlen(context->iface))
		printf("%s = %s\n", IFACE_NETNAME, context->iface);
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
	printf("%s\n", ISCSI_BEGIN_REC);
	dump_initiator(context);
	dump_network(context);
	dump_target(context);
	printf("%s\n", ISCSI_END_REC);
}
