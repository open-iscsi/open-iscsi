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
#include "fw_context.h"
#include "fwparam_ibft.h"

int fw_get_entry(struct boot_context *context, const char *filepath)
{
	int ret;

	ret = fwparam_ppc(context, filepath);
	if (ret)
		ret = fwparam_ibft(context, filepath);
	return ret;
}

/*
 * Dump the 8 byte mac address
 */
static void dump_mac(struct boot_context *context)
{
	int i;

	if (!strlen(context->mac))
		return;

	printf("iface.hwaddress = %s\n", context->mac);
}

static void dump_initiator(struct boot_context *context)
{
	if (!strlen(context->initiatorname))
		return;
	printf("iface.initiatorname = %s\n", context->initiatorname);
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
}

void fw_print_entry(struct boot_context *context)
{
	dump_initiator(context);
	dump_mac(context);
	dump_target(context);
}
