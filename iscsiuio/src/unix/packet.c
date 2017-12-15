/*
 * Copyright (c) 2009-2011, Broadcom Corporation
 * Copyright (c) 2014, QLogic Corporation
 *
 * Written by:  Benjamin Li  (benli@broadcom.com)
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
 * packet.c - packet management
 *
 */
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "logger.h"
#include "packet.h"
#include "nic.h"

/**
 * alloc_packet() - Function used to allocate memory for a packet
 * @param max_buf_size - max packet size
 * @param priv_size    - size of the assoicated private data
 * @return NULL if failed, on success return a pointer to the packet
 */
struct packet *alloc_packet(size_t max_buf_size, size_t priv_size)
{
	struct packet *pkt;
	void *priv;

	pkt = malloc(max_buf_size + sizeof(struct packet));
	if (pkt == NULL) {
		LOG_ERR("Could not allocate any memory for packet");
		return NULL;
	}
	memset(pkt, 0, max_buf_size + sizeof(struct packet));

	priv = malloc(priv_size);
	if (priv == NULL) {
		LOG_ERR("Could not allocate any memory for private structure");
		goto free_pkt;
	}
	memset(priv, 0, priv_size);
	pkt->max_buf_size = max_buf_size;
	pkt->priv = priv;

	return pkt;

free_pkt:
	free(pkt);

	return NULL;
}

void free_packet(struct packet *pkt)
{
	if (pkt->priv != NULL)
		free(pkt->priv);

	free(pkt);
}

/**
 *  reset_packet() - This will reset the packet fields to default values
 *  @param pkt - the packet to reset
 */
void reset_packet(packet_t *pkt)
{
	pkt->next = NULL;

	pkt->flags = 0;
	pkt->vlan_tag = 0;

	pkt->buf_size = 0;

	pkt->data_link_layer = NULL;
	pkt->network_layer = NULL;
}

int alloc_free_queue(nic_t *nic, size_t num_of_packets)
{
	int i;

	pthread_mutex_lock(&nic->free_packet_queue_mutex);
	for (i = 0; i < num_of_packets; i++) {
		packet_t *pkt;

		pkt = alloc_packet(STD_MTU_SIZE, STD_MTU_SIZE);
		if (pkt == NULL) {
			goto done;
		}

		reset_packet(pkt);

		pkt->next = nic->free_packet_queue;
		nic->free_packet_queue = pkt;
	}

done:
	pthread_mutex_unlock(&nic->free_packet_queue_mutex);

	return i;
}

void free_free_queue(nic_t *nic)
{
	packet_t *pkt, *pkt_next;

	pthread_mutex_lock(&nic->free_packet_queue_mutex);
	pkt = nic->free_packet_queue;
	while (pkt) {
		pkt_next = pkt->next;
		free_packet(pkt);
		pkt = pkt_next;
	}
	nic->free_packet_queue = NULL;
	pthread_mutex_unlock(&nic->free_packet_queue_mutex);
}
