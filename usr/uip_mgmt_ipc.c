/*
 * uIP iSCSI Daemon/Admin Management IPC
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
 *
 * See the file COPYING included with this distribution for more details.
 */

#include <string.h>

#include "log.h"
#include "uip_mgmt_ipc.h"
#include "iscsid_req.h"

int uip_broadcast_params(struct iscsi_transport *t,
			 struct iface_rec *iface,
			 struct iscsi_session *session)
{
	struct iscsid_uip_broadcast broadcast;

	log_debug(3, "broadcasting to uip\n");

	memset(&broadcast, 0, sizeof(broadcast));

	broadcast.header.command = ISCSID_UIP_IPC_GET_IFACE;
	broadcast.header.payload_len = sizeof(*iface);

	memcpy(&broadcast.u.iface_rec, iface, sizeof(*iface));

	return uip_broadcast(&broadcast,
			     sizeof(iscsid_uip_broadcast_header_t) +
			     sizeof(*iface));
}
