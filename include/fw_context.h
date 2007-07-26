/*
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * Copyright (C) IBM Corporation. 2007
 * Author: Doug Maxey <dwm@austin.ibm.com>
 *         "Prasanna Mumbai" <mumbai.prasanna@gmail.com>
 *
 */
#ifndef FWPARAM_CONTEXT_H_
#define FWPARAM_CONTEXT_H_

struct boot_context {
#define IQNSZ (223+1)
	int target_port;
	char initiatorname[IQNSZ];
	char targetname[IQNSZ];
	char target_ipaddr[32];
	char chap_name[127];
	char chap_password[16];
	char chap_name_in[127];
	char chap_password_in[16];
	char iface[42];
	char mac[18];
	char ipaddr[18];
	char mask[18];
	char lun[17];
	char vlan[15];
	char isid[10];
};

extern int fw_get_entry(struct boot_context *context, const char *filepath);
extern void fw_print_entry(struct boot_context *context);

#endif /* FWPARAM_CONTEXT_H_ */
