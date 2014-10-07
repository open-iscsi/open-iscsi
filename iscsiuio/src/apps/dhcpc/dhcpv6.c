/*
 * Copyright (c) 2011, Broadcom Corporation
 * Copyright (c) 2014, QLogic Corporation
 *
 * Written by:  Eddie Wai <eddie.wai@broadcom.com>
 *              Based on code from Kevin Tran's iSCSI boot code
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Adam Dunkels.
 * 4. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * dhcpv6.c - DHCPv6 engine
 *
 */
#include <stdio.h>
#include <string.h>

#include "ipv6.h"
#include "ipv6_pkt.h"
#include "dhcpv6.h"
#include "logger.h"

/* Local function prototypes */
static int dhcpv6_send_solicit_packet(struct dhcpv6_context *context);
static int dhcpv6_send_request_packet(struct dhcpv6_context *context);
static u16_t dhcpv6_init_packet(struct dhcpv6_context *context, u8_t type);
static void dhcpv6_init_dhcpv6_server_addr(struct ipv6_addr *addr);
static void dhcpv6_handle_advertise(struct dhcpv6_context *context,
				    u16_t dhcpv6_len);
static void dhcpv6_handle_reply(struct dhcpv6_context *context,
				u16_t dhcpv6_len);
static int dhcpv6_process_opt_ia_na(struct dhcpv6_context *context,
				    struct dhcpv6_opt_hdr *opt_hdr);
static void dhcpv6_process_opt_dns_servers(struct dhcpv6_context *context,
					   struct dhcpv6_opt_hdr *opt_hdr);
static void dhcpv6_parse_vendor_option(struct dhcpv6_context *context,
				       u8_t *option, int len);

void dhcpv6_init(struct dhcpv6_context *context)
{
	context->seconds = 0;
	context->our_mac_addr =
	    ipv6_get_link_addr(context->ipv6_context);

	/* Use the last four bytes of MAC address as base of the transaction
	   ID */
	context->dhcpv6_transaction_id = context->our_mac_addr->last_4_bytes;

	context->dhcpv6_done = FALSE;
	strcpy(context->dhcp_vendor_id, "BRCM ISAN");
}

int dhcpv6_do_discovery(struct dhcpv6_context *context)
{
	int retc = ISCSI_FAILURE;

	context->eth =
	    (struct eth_hdr *)context->ipv6_context->ustack->data_link_layer;
	context->ipv6 =
	    (struct ipv6_hdr *)context->ipv6_context->ustack->network_layer;
	context->udp =
	    (struct udp_hdr *)((u8_t *)context->ipv6 + sizeof(struct ipv6_hdr));

	/* Send out DHCPv6 Solicit packet. */
	dhcpv6_send_solicit_packet(context);

	return retc;
}

static int dhcpv6_send_solicit_packet(struct dhcpv6_context *context)
{
	u16_t packet_len;

	LOG_DEBUG("DHCPV6: Send solicit");
	packet_len = dhcpv6_init_packet(context, DHCPV6_SOLICIT);
	context->dhcpv6_state = DHCPV6_STATE_SOLICIT_SENT;
	ipv6_send_udp_packet(context->ipv6_context, packet_len);

	return 0;
}

static int dhcpv6_send_request_packet(struct dhcpv6_context *context)
{
	u16_t packet_len;

	LOG_DEBUG("DHCPV6: Send request");
	packet_len = dhcpv6_init_packet(context, DHCPV6_REQUEST);

	context->dhcpv6_state = DHCPV6_STATE_REQ_SENT;
	ipv6_send_udp_packet(context->ipv6_context, packet_len);

	return 0;
}

static u16_t dhcpv6_init_packet(struct dhcpv6_context *context, u8_t type)
{
	u16_t pkt_len;
	struct udp_hdr *udp = context->udp;
	union dhcpv6_hdr *dhcpv6;
	struct dhcpv6_option *opt;
	u16_t len;

	/* Initialize dest IP with well-known DHCP server address */
	dhcpv6_init_dhcpv6_server_addr(&context->ipv6->ipv6_dst);
	/* Initialize dest MAC based on MC dest IP */
	ipv6_mc_init_dest_mac(context->eth, context->ipv6);

	/* Initialize UDP header */
	udp->src_port = HOST_TO_NET16(DHCPV6_CLIENT_PORT);
	udp->dest_port = HOST_TO_NET16(DHCPV6_SERVER_PORT);

	/*
	 * DHCPv6 section has the following format per RFC 3315
	 *
	 *  0                   1                   2                   3
	 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |    msg-type   |               transaction-id                  |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 * |                                                               |
	 * .                            options                            .
	 * .                           (variable)                          .
	 * |                                                               |
	 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
	 */
	dhcpv6 = (union dhcpv6_hdr *)((u8_t *)udp + sizeof(struct udp_hdr));

	if (dhcpv6->dhcpv6_type != type)
		context->dhcpv6_transaction_id++;

	dhcpv6->dhcpv6_trans_id = context->dhcpv6_transaction_id;
	dhcpv6->dhcpv6_type = type;

	/* Keep track of length of all DHCP options. */
	pkt_len = sizeof(union dhcpv6_hdr);

	if (dhcpv6->dhcpv6_type == DHCPV6_REQUEST) {
		/* We will send back whatever DHCPv6 sent us */
		return ((u8_t *)udp - (u8_t *)context->eth +
			NET_TO_HOST16(udp->length));
	}

	opt = (struct dhcpv6_option *)((u8_t *)dhcpv6 +
	      sizeof(union dhcpv6_hdr));
	/* Add client ID option */
	opt->hdr.type = HOST_TO_NET16(DHCPV6_OPT_CLIENTID);
	opt->hdr.length = HOST_TO_NET16(sizeof(struct dhcpv6_opt_client_id));
	opt->type.client_id.duid_type =
	    HOST_TO_NET16(DHCPV6_DUID_TYPE_LINK_LAYER_AND_TIME);
	opt->type.client_id.hw_type = HOST_TO_NET16(DHCPV6_HW_TYPE_ETHERNET);
	opt->type.client_id.time = HOST_TO_NET32(clock_time()/1000 -
						 0x3A4FC880);
	memcpy((char *)&opt->type.client_id.link_layer_addr,
	       (char *)context->our_mac_addr, sizeof(struct mac_address));
	pkt_len += sizeof(struct dhcpv6_opt_client_id) +
		   sizeof(struct dhcpv6_opt_hdr);
	opt = (struct dhcpv6_option *)((u8_t *)opt +
					sizeof(struct dhcpv6_opt_client_id) +
					sizeof(struct dhcpv6_opt_hdr));

	/* Add Vendor Class option if it's configured */
	len = strlen(context->dhcp_vendor_id);
	if (len > 0) {
		opt->hdr.type = HOST_TO_NET16(DHCPV6_OPT_VENDOR_CLASS);
		opt->hdr.length =
				HOST_TO_NET16(sizeof(struct dhcpv6_vendor_class)
					      + len - 1);
		opt->type.vendor_class.enterprise_number =
		    HOST_TO_NET32(IANA_ENTERPRISE_NUM_BROADCOM);
		opt->type.vendor_class.vendor_class_length = HOST_TO_NET16(len);
		memcpy((char *)&opt->type.vendor_class.
		       vendor_class_data[0],
		       (char *)context->dhcp_vendor_id, len);
		pkt_len +=
		    sizeof(struct dhcpv6_vendor_class) - 1 + len +
		    sizeof(struct dhcpv6_opt_hdr);
		opt =
		    (struct dhcpv6_option *)((u8_t *)opt +
			      sizeof(struct dhcpv6_vendor_class) - 1 + len +
			      sizeof(struct dhcpv6_opt_hdr));
	}

	/* Add IA_NA option */
	opt->hdr.type = HOST_TO_NET16(DHCPV6_OPT_IA_NA);
	opt->hdr.length = HOST_TO_NET16(sizeof(struct dhcpv6_opt_id_assoc_na));
	opt->type.ida_na.iaid = htonl(context->our_mac_addr->last_4_bytes);
	opt->type.ida_na.t1 = 0;
	opt->type.ida_na.t2 = 0;
	pkt_len += sizeof(struct dhcpv6_opt_id_assoc_na) +
		   sizeof(struct dhcpv6_opt_hdr);
	opt = (struct dhcpv6_option *)((u8_t *)opt +
					sizeof(struct dhcpv6_opt_id_assoc_na) +
					sizeof(struct dhcpv6_opt_hdr));
	/* Add Elapsed Time option */
	opt->hdr.type = HOST_TO_NET16(DHCPV6_OPT_ELAPSED_TIME);
	opt->hdr.length = HOST_TO_NET16(sizeof(struct dhcpv6_opt_elapse_time));
	opt->type.elapsed_time.time = HOST_TO_NET16(context->seconds);
	pkt_len += sizeof(struct dhcpv6_opt_elapse_time) +
		   sizeof(struct dhcpv6_opt_hdr);

	/* Add Option Request List */
	opt = (struct dhcpv6_option *)((u8_t *)opt +
					sizeof(struct dhcpv6_opt_elapse_time) +
					sizeof(struct dhcpv6_opt_hdr));
	opt->hdr.type = HOST_TO_NET16(DHCPV6_OPT_ORO);
	opt->hdr.length = HOST_TO_NET16(3 *
					sizeof(struct dhcpv6_opt_request_list));
	opt->type.list.request_code[0] = HOST_TO_NET16(DHCPV6_OPT_VENDOR_CLASS);
	opt->type.list.request_code[1] = HOST_TO_NET16(DHCPV6_OPT_VENDOR_OPTS);
	opt->type.list.request_code[2] = HOST_TO_NET16(DHCPV6_OPT_DNS_SERVERS);
	pkt_len += 3 * sizeof(struct dhcpv6_opt_request_list) +
		   sizeof(struct dhcpv6_opt_hdr);

	udp->length = HOST_TO_NET16(sizeof(struct udp_hdr) + pkt_len);

	pkt_len +=
	    ((u8_t *)udp - (u8_t *)context->eth) + sizeof(struct udp_hdr);

	return pkt_len;
}

static void dhcpv6_init_dhcpv6_server_addr(struct ipv6_addr *addr)
{
	/* Well-known DHCPv6 server address is ff02::1:2 */
	memset((char *)addr, 0, sizeof(struct ipv6_addr));
	addr->addr8[0] = 0xff;
	addr->addr8[1] = 0x02;
	addr->addr8[13] = 0x01;
	addr->addr8[15] = 0x02;
}

void ipv6_udp_handle_dhcp(struct dhcpv6_context *context)
{
	union dhcpv6_hdr *dhcpv6;
	u16_t dhcpv6_len;

	if (context->dhcpv6_done == TRUE)
		return;

	dhcpv6 = (union dhcpv6_hdr *)((u8_t *)context->udp +
					sizeof(struct udp_hdr));

	if (dhcpv6->dhcpv6_trans_id != context->dhcpv6_transaction_id)
		return;

	dhcpv6_len =
	    NET_TO_HOST16(context->udp->length) - sizeof(struct udp_hdr);

	switch (dhcpv6->dhcpv6_type) {
	case DHCPV6_ADVERTISE:
		dhcpv6_handle_advertise(context, dhcpv6_len);
		break;

	case DHCPV6_REPLY:
		dhcpv6_handle_reply(context, dhcpv6_len);
		break;

	default:
		break;
	}
}

static void dhcpv6_handle_advertise(struct dhcpv6_context *context,
				    u16_t dhcpv6_len)
{
	union dhcpv6_hdr *dhcpv6 =
	    (union dhcpv6_hdr *)((u8_t *)context->udp +
				  sizeof(struct udp_hdr));
	struct dhcpv6_opt_hdr *opt;
	u16_t type;
	int i;
	int opt_len;
	u8_t *vendor_id = NULL;
	u16_t vendor_id_len = 0;
	u8_t *vendor_opt_data = NULL;
	int vendor_opt_len = 0;
	int addr_cnt = 0;

	/* We only handle DHCPv6 advertise if we recently sent DHCPv6 solicit */
	if (context->dhcpv6_state != DHCPV6_STATE_SOLICIT_SENT)
		return;

	LOG_DEBUG("DHCPV6: handle advertise");
	context->dhcpv6_state = DHCPV6_STATE_ADV_RCVD;

	i = 0;
	while (i < (dhcpv6_len - sizeof(union dhcpv6_hdr))) {
		opt = (struct dhcpv6_opt_hdr *)((u8_t *)dhcpv6 +
						sizeof(union dhcpv6_hdr) + i);
		opt_len = NET_TO_HOST16(opt->length);

		type = NET_TO_HOST16(opt->type);

		/* We only care about some of the options */
		switch (type) {
		case DHCPV6_OPT_IA_NA:
			if (context->
			    dhcpv6_task & DHCPV6_TASK_GET_IP_ADDRESS) {
				addr_cnt +=
				    dhcpv6_process_opt_ia_na(context, opt);
			}
			break;

		case DHCPV6_OPT_VENDOR_CLASS:
			vendor_id_len =
			    NET_TO_HOST16(((struct dhcpv6_option *)opt)->type.
					  vendor_class.vendor_class_length);
			vendor_id =
			    &((struct dhcpv6_option *)opt)->type.vendor_class.
			    vendor_class_data[0];
			break;

		case DHCPV6_OPT_VENDOR_OPTS:
			vendor_opt_len = opt_len - 4;
			vendor_opt_data =
			    &((struct dhcpv6_option *)opt)->type.vendor_opts.
			    vendor_opt_data[0];
			break;

		case DHCPV6_OPT_DNS_SERVERS:
			if (context->dhcpv6_task & DHCPV6_TASK_GET_OTHER_PARAMS)
				dhcpv6_process_opt_dns_servers(context, opt);
			break;

		default:
			break;
		}

		i += NET_TO_HOST16(opt->length) + sizeof(struct dhcpv6_opt_hdr);
	}

	if (context->dhcpv6_task & DHCPV6_TASK_GET_OTHER_PARAMS) {
		if ((vendor_id_len > 0) &&
		    (strncmp((char *)vendor_id,
			     (char *)context->dhcp_vendor_id,
			     vendor_id_len) == 0)) {
			dhcpv6_parse_vendor_option(context,
						   vendor_opt_data,
						   vendor_opt_len);
			context->dhcpv6_done = TRUE;
		}
	}

	if (context->dhcpv6_task & DHCPV6_TASK_GET_IP_ADDRESS) {
		if (addr_cnt > 0) {
			/*
			 * If we need to acquire IP address from the server,
			 * we need to send Request to server to confirm.
			 */
			dhcpv6_send_request_packet(context);
			context->dhcpv6_done = TRUE;
		}
	}

	if (context->dhcpv6_done) {
		/* Keep track of IPv6 address of DHCHv6 server */
		memcpy((char *)&context->dhcp_server,
		       (char *)&context->ipv6->ipv6_src,
		       sizeof(struct ipv6_addr));
	}
}

static int dhcpv6_process_opt_ia_na(struct dhcpv6_context *context,
				    struct dhcpv6_opt_hdr *opt_hdr)
{
	int i;
	int opt_len;
	struct dhcpv6_option *opt;
	int len;
	int addr_cnt;
	opt_len = NET_TO_HOST16(opt_hdr->length) -
		  sizeof(struct dhcpv6_opt_id_assoc_na);

	i = 0;
	addr_cnt = 0;
	while (i < opt_len) {
		opt =
		    (struct dhcpv6_option *)((u8_t *)opt_hdr +
				     sizeof(struct dhcpv6_opt_hdr) +
				     sizeof(struct dhcpv6_opt_id_assoc_na) + i);

		len = NET_TO_HOST16(opt->hdr.length);
		switch (NET_TO_HOST16(opt->hdr.type)) {
		case DHCPV6_OPT_IAADDR:
			if (len >
			    (sizeof(struct dhcpv6_opt_hdr) +
			     sizeof(struct dhcpv6_opt_iaa_addr))) {
				struct dhcpv6_option *in_opt;

				in_opt = (struct dhcpv6_option *)((u8_t *)opt +
					  sizeof(struct dhcpv6_opt_hdr) +
					  sizeof(struct dhcpv6_opt_iaa_addr));
				if (in_opt->hdr.type ==
				    HOST_TO_NET16(DHCPV6_OPT_STATUS_CODE)) {
					/* This entry has error! */
					if (in_opt->type.sts.status != 0)
						break;
				}
			}
			LOG_INFO("DHCPv6: Got IP Addr");
			/* Status is OK, let's add this addr to our address
			   list */
			ipv6_add_prefix_entry(context->ipv6_context,
					      &opt->type.iaa_addr.addr, 64);

			/* Add multicast address for this address */
			ipv6_add_solit_node_address(context->
						    ipv6_context,
						    &opt->type.iaa_addr.addr);
			addr_cnt++;
			break;

		default:
			break;
		}

		i += len + sizeof(struct dhcpv6_opt_hdr);
	}

	return addr_cnt;
}

static void dhcpv6_process_opt_dns_servers(struct dhcpv6_context *context,
					   struct dhcpv6_opt_hdr *opt_hdr)
{
	int opt_len;

	opt_len = NET_TO_HOST16(opt_hdr->length);

	if (opt_len >= sizeof(struct ipv6_addr))
		memcpy((char *)&context->primary_dns_server,
		       (char *)&((struct dhcpv6_option *)opt_hdr)->type.dns.
				 primary_addr, sizeof(struct ipv6_addr));

	if (opt_len >= 2 * sizeof(struct ipv6_addr))
		memcpy((char *)&context->secondary_dns_server,
		       (char *)&((struct dhcpv6_option *)opt_hdr)->type.dns.
				 secondary_addr, sizeof(struct ipv6_addr));
}

static void dhcpv6_handle_reply(struct dhcpv6_context *context,
				u16_t dhcpv6_len)
{
	if (context->dhcpv6_state != DHCPV6_STATE_REQ_SENT)
		return;

	context->dhcpv6_done = TRUE;
}

static void dhcpv6_parse_vendor_option(struct dhcpv6_context *context,
				       u8_t *option, int len)
{
	struct dhcpv6_option *opt;
	u16_t type;
	int opt_len;
	int data_len;
	int i;
	u8_t *data;

	for (i = 0; i < len; i += opt_len + sizeof(struct dhcpv6_opt_hdr)) {
		opt = (struct dhcpv6_option *)((u8_t *)option + i);
		type = HOST_TO_NET16(opt->hdr.type);
		opt_len = HOST_TO_NET16(opt->hdr.length);
		data = &opt->type.data[0];
		data_len = strlen((char *)data);

		switch (type) {
		case 201:
			/* iSCSI target 1 */
			break;

		case 202:
			/* iSCSI target 2 */
			break;

		case 203:
			if (data_len > ISCSI_MAX_ISCSI_NAME_LENGTH)
				data_len = ISCSI_MAX_ISCSI_NAME_LENGTH;
			data[data_len] = '\0';
			strcpy(context->initiatorName, (char *)data);
			break;

		default:
			break;
		}
	}
}
