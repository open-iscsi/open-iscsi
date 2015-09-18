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
#include <fcntl.h>

#include "log.h"
#include "uip_mgmt_ipc.h"
#include "iscsid_req.h"
#include "iscsi_err.h"

int uip_broadcast_params(struct iscsi_transport *t,
			 struct iface_rec *iface,
			 struct iscsi_session *session)
{
	struct iscsid_uip_broadcast broadcast;

	log_debug(3, "broadcasting to uip");

	memset(&broadcast, 0, sizeof(broadcast));

	broadcast.header.command = ISCSID_UIP_IPC_GET_IFACE;
	broadcast.header.payload_len = sizeof(*iface);

	memcpy(&broadcast.u.iface_rec, iface, sizeof(*iface));

	return uip_broadcast(&broadcast,
			     sizeof(iscsid_uip_broadcast_header_t) +
			     sizeof(*iface), O_NONBLOCK, NULL);
}

int uip_broadcast_ping_req(struct iscsi_transport *t,
			   struct iface_rec *iface, int datalen,
			   struct sockaddr_storage *dst_addr, uint32_t *status)
{
	struct iscsid_uip_broadcast broadcast;
	int len = 0;

	log_debug(3, "broadcasting ping request to uip\n");

	memset(&broadcast, 0, sizeof(broadcast));

	broadcast.header.command = ISCSID_UIP_IPC_PING;
	len = sizeof(*iface) + sizeof(*dst_addr) + sizeof(datalen);
	broadcast.header.payload_len = len;

	memcpy(&broadcast.u.ping_rec.ifrec, iface, sizeof(*iface));

	if (dst_addr->ss_family == PF_INET) {
		len = sizeof(struct sockaddr_in);
	} else if (dst_addr->ss_family == PF_INET6) {
		len = sizeof(struct sockaddr_in6);
	} else {
		log_error("%s unknown addr family %d\n",
			  __FUNCTION__, dst_addr->ss_family);
		return ISCSI_ERR_INVAL;
	}

	memcpy(&broadcast.u.ping_rec.ipaddr, dst_addr, len);
	broadcast.u.ping_rec.datalen = datalen;

	return uip_broadcast(&broadcast,
			     sizeof(iscsid_uip_broadcast_header_t) +
			     broadcast.header.payload_len, 0, status);
}
