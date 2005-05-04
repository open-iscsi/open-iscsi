/*
 * iSCSI Initiator over TCP/IP Data-Path
 *
 * Copyright (C) 2004 Dmitry Yusupov, Alex Aizman
 * maintained by open-iscsi@googlegroups.com
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
 *
 * Credits:
 * Christoph Hellwig	: For reviewing the code, for comments and suggestions.
 * Mike Christie	: For reviewing the code, for comments and suggestions.
 */

#include <linux/types.h>
#include <linux/list.h>
#include <linux/inet.h>
#include <linux/blkdev.h>
#include <linux/crypto.h>
#include <linux/delay.h>
#include <linux/kfifo.h>
#include <linux/scatterlist.h>
#include <net/tcp.h>
#include <scsi/scsi_cmnd.h>
#include <scsi/scsi_device.h>
#include <scsi/scsi_eh.h>
#include <scsi/scsi_request.h>
#include <scsi/scsi_tcq.h>
#include <scsi/scsi_host.h>
#include <scsi/scsi.h>

#include "iscsi_tcp.h"

MODULE_AUTHOR("Dmitry Yusupov <dmitry_yus@yahoo.com>, "
	      "Alex Aizman <itn780@yahoo.com>");
MODULE_DESCRIPTION("iSCSI/TCP data-path");
MODULE_LICENSE("GPL");

/* #define DEBUG_TCP */
/* #define DEBUG_SCSI */
#define DEBUG_ASSERT

#ifdef DEBUG_TCP
#define debug_tcp(fmt...) printk("tcp: " fmt)
#else
#define debug_tcp(fmt...)
#endif

#ifdef DEBUG_SCSI
#define debug_scsi(fmt...) printk("scsi: " fmt)
#else
#define debug_scsi(fmt...)
#endif

#ifndef DEBUG_ASSERT
#ifdef BUG_ON
#undef BUG_ON
#endif
#define BUG_ON(expr)
#endif

/* global data */
static kmem_cache_t *taskcache;

static inline void
iscsi_buf_init_virt(struct iscsi_buf *ibuf, char *vbuf, int size)
{
	sg_init_one(&ibuf->sg, (u8 *)vbuf, size);
	ibuf->sent = 0;
}

static inline void
iscsi_buf_init_sg(struct iscsi_buf *ibuf, struct scatterlist *sg)
{
	ibuf->sg.page = sg->page;
	ibuf->sg.offset = sg->offset;
	ibuf->sg.length = sg->length;
	ibuf->sent = 0;
}

static inline int
iscsi_buf_left(struct iscsi_buf *ibuf)
{
	int rc;

	rc = ibuf->sg.length - ibuf->sent;
	BUG_ON(rc < 0);
	return rc;
}

static inline void
iscsi_buf_init_hdr(struct iscsi_conn *conn, struct iscsi_buf *ibuf,
		   char *vbuf, u8 *crc)
{
	iscsi_buf_init_virt(ibuf, vbuf, sizeof(struct iscsi_hdr));
	if (conn->hdrdgst_en) {
		crypto_digest_digest(conn->tx_tfm, &ibuf->sg, 1, crc);
		ibuf->sg.length += sizeof(uint32_t);
	}
}

static int
iscsi_hdr_extract(struct iscsi_conn *conn)
{
	struct sk_buff *skb = conn->in.skb;

	if (conn->in.copy >= conn->hdr_size &&
	    conn->in_progress != IN_PROGRESS_HEADER_GATHER) {
		/*
		 * Zero-copy PDU Header: using connection context
		 * to store header pointer.
		 */
		if (skb_shinfo(skb)->frag_list == NULL &&
		    !skb_shinfo(skb)->nr_frags) {
			conn->in.hdr = (struct iscsi_hdr *)
				((char*)skb->data + conn->in.offset);
		} else {
			/* ignoring return code since we checked
			 * in.copy before */
			skb_copy_bits(skb, conn->in.offset,
				&conn->hdr, conn->hdr_size);
			conn->in.hdr = &conn->hdr;
		}
		conn->in.offset += conn->hdr_size;
		conn->in.copy -= conn->hdr_size;
		conn->in.hdr_offset = 0;
	} else {
		int copylen;

		/*
		 * PDU header scattered across SKB's,
		 * copying it... This'll happen quite rarely.
		 */
		if (conn->in_progress == IN_PROGRESS_WAIT_HEADER) {
			skb_copy_bits(skb, conn->in.offset,
				&conn->hdr, conn->in.copy);
			conn->in_progress = IN_PROGRESS_HEADER_GATHER;
			conn->in.hdr_offset = conn->in.copy;
			conn->in.offset += conn->in.copy;
			conn->in.copy = 0;
			debug_tcp("PDU gather #1 %d bytes!\n",
			       conn->in.hdr_offset);
			return -EAGAIN;
		}

		copylen = conn->hdr_size - conn->in.hdr_offset;
		if (copylen > conn->in.copy) {
			printk("iscsi_tcp: PDU gather failed! "
			       "copylen %d conn->in.copy %d\n",
			       copylen, conn->in.copy);
			iscsi_cnx_error(iscsi_handle(conn),
					ISCSI_ERR_PDU_GATHER_FAILED);
			return 0;
		}
		debug_tcp("PDU gather #2 %d bytes!\n", copylen);

		skb_copy_bits(skb, conn->in.offset,
		    (char*)&conn->hdr + conn->in.hdr_offset, copylen);
		conn->in.offset += copylen;
		conn->in.copy -= copylen;
		conn->in.hdr_offset = 0;
		conn->in.hdr = &conn->hdr;
		conn->in_progress = IN_PROGRESS_WAIT_HEADER;
		conn->discontiguous_hdr_cnt++;
	}

	return 0;
}

static void
iscsi_ctask_cleanup(struct iscsi_conn *conn, struct iscsi_cmd_task *ctask)
{
	struct scsi_cmnd *sc = ctask->sc;
	struct iscsi_session *session = conn->session;

	spin_lock(&session->lock);
	if (ctask->in_progress == IN_PROGRESS_IDLE) {
		spin_unlock(&session->lock);
		return;
	}
	if (sc->sc_data_direction == DMA_TO_DEVICE) {
		struct iscsi_data_task *dtask, *n;
		/* WRITE: cleanup Data-Out's if any */
		spin_lock(&conn->lock);
		list_for_each_entry_safe(dtask, n, &ctask->dataqueue, item) {
			list_del(&dtask->item);
			mempool_free(dtask, ctask->datapool);
		}
		spin_unlock(&conn->lock);
	}
	sc->SCp.Status = SUCCESS;
	ctask->in_progress = IN_PROGRESS_IDLE;
	__kfifo_put(session->cmdpool.queue, (void*)&ctask, sizeof(void*));
	spin_unlock(&session->lock);
	conn->scsirsp_pdus_cnt++;
}

/*
 * SCSI Command Response processing
 */
static int
iscsi_cmd_rsp(struct iscsi_conn *conn, struct iscsi_cmd_task *ctask)
{
	int rc = 0;
	struct iscsi_cmd_rsp *rhdr = (struct iscsi_cmd_rsp *)conn->in.hdr;
	struct iscsi_session *session = conn->session;
	struct scsi_cmnd *sc = ctask->sc;
	int max_cmdsn = be32_to_cpu(rhdr->max_cmdsn);
	int exp_cmdsn = be32_to_cpu(rhdr->exp_cmdsn);

	if (max_cmdsn < exp_cmdsn - 1) {
		rc = ISCSI_ERR_MAX_CMDSN;
		sc->result = (DID_ERROR << 16);
		goto fault;
	}
	session->max_cmdsn = max_cmdsn;
	session->exp_cmdsn = exp_cmdsn;
	conn->exp_statsn = be32_to_cpu(rhdr->statsn) + 1;

	sc->result = (DID_OK << 16) | rhdr->cmd_status;

	if (rhdr->response == ISCSI_STATUS_CMD_COMPLETED) {
		if (rhdr->cmd_status == SAM_STAT_CHECK_CONDITION &&
		    conn->senselen) {
			int sensecopy = min(conn->senselen,
					    SCSI_SENSE_BUFFERSIZE);
			memcpy(sc->sense_buffer, conn->data + 2, sensecopy);
			debug_scsi("copied %d bytes of sense\n", sensecopy);
		}

		if (sc->sc_data_direction != DMA_TO_DEVICE ) {
			if (rhdr->flags & ISCSI_FLAG_CMD_UNDERFLOW) {
				int res_count =
					be32_to_cpu(rhdr->residual_count);
				if (res_count > 0 &&
				    res_count <= sc->request_bufflen) {
					sc->resid = res_count;
				} else {
					sc->result = (DID_BAD_TARGET << 16) |
						     rhdr->cmd_status;
				}
			} else if (rhdr->flags& ISCSI_FLAG_CMD_BIDI_UNDERFLOW) {
				sc->result = (DID_BAD_TARGET << 16) |
					     rhdr->cmd_status;
			} else if (rhdr->flags & ISCSI_FLAG_CMD_OVERFLOW) {
				sc->resid = be32_to_cpu(rhdr->residual_count);
			}
		}
	} else {
		sc->result = (DID_ERROR << 16);
	}

fault:
	debug_scsi("done [sc %lx res %d itt 0x%x]\n",
		   (long)sc, sc->result, ctask->itt);
	iscsi_ctask_cleanup(conn, ctask);
	sc->scsi_done(sc);
	return rc;
}

/*
 * SCSI Data-In Response processing
 */
static int
iscsi_data_rsp(struct iscsi_conn *conn, struct iscsi_cmd_task *ctask)
{
	struct iscsi_data_rsp *rhdr = (struct iscsi_data_rsp *)conn->in.hdr;
	struct iscsi_session *session = conn->session;
	int datasn = be32_to_cpu(rhdr->datasn);
	int max_cmdsn = be32_to_cpu(rhdr->max_cmdsn);
	int exp_cmdsn = be32_to_cpu(rhdr->exp_cmdsn);

	/*
	 * setup Data-In byte counter (gets decremented..)
	 */
	ctask->data_count = conn->in.datalen;

	if (conn->in.datalen == 0)
		return 0;

	if (max_cmdsn < exp_cmdsn -1)
		return ISCSI_ERR_MAX_CMDSN;

	session->max_cmdsn = max_cmdsn;
	session->exp_cmdsn = exp_cmdsn;

	if (ctask->datasn != datasn)
		return ISCSI_ERR_DATASN;

	ctask->datasn++;

	ctask->data_offset = be32_to_cpu(rhdr->offset);
	if (ctask->data_offset + conn->in.datalen > ctask->total_length)
		return ISCSI_ERR_DATA_OFFSET;

	if (rhdr->flags & ISCSI_FLAG_DATA_STATUS) {
		struct scsi_cmnd *sc = ctask->sc;
		conn->exp_statsn = be32_to_cpu(rhdr->statsn) + 1;
		if (rhdr->flags & ISCSI_FLAG_CMD_UNDERFLOW) {
			int res_count = be32_to_cpu(rhdr->residual_count);
			if (res_count > 0 &&
			    res_count <= sc->request_bufflen) {
				sc->resid = res_count;
				sc->result = (DID_OK << 16) | rhdr->cmd_status;
			} else {
				sc->result = (DID_BAD_TARGET << 16) |
					rhdr->cmd_status;
			}
		} else if (rhdr->flags & ISCSI_FLAG_CMD_BIDI_UNDERFLOW) {
			sc->result = (DID_BAD_TARGET << 16) | rhdr->cmd_status;
		} else if (rhdr->flags & ISCSI_FLAG_CMD_OVERFLOW) {
			sc->resid = be32_to_cpu(rhdr->residual_count);
			sc->result = (DID_OK << 16) | rhdr->cmd_status;
		} else {
			sc->result = (DID_OK << 16) | rhdr->cmd_status;
		}
	}

	conn->datain_pdus_cnt++;
	return 0;
}

/*
 * iscsi_solicit_data_init - initialize first Data-Out
 *
 * Initialize first Data-Out within this R2T sequence and finds
 * proper data_offset within this SCSI command.
 *
 * This function is called with connection lock taken.
 */
static void
iscsi_solicit_data_init(struct iscsi_conn *conn, struct iscsi_cmd_task *ctask,
			struct iscsi_r2t_info *r2t)
{
	struct iscsi_data *hdr;
	struct iscsi_data_task *dtask;
	struct scsi_cmnd *sc = ctask->sc;

	dtask = mempool_alloc(ctask->datapool, GFP_ATOMIC);
	BUG_ON(!dtask);
	hdr = &dtask->hdr;
	memset(hdr, 0, sizeof(struct iscsi_data));
	hdr->ttt = r2t->ttt;
	hdr->datasn = cpu_to_be32(r2t->solicit_datasn);
	r2t->solicit_datasn++;
	hdr->opcode = ISCSI_OP_SCSI_DATA_OUT;
	hdr->lun[1] = ctask->hdr.lun[1];
	hdr->itt = ctask->hdr.itt;
	hdr->exp_statsn = r2t->exp_statsn;
	hdr->offset = cpu_to_be32(r2t->data_offset);
	if (r2t->data_length > conn->max_xmit_dlength) {
		hton24(hdr->dlength, conn->max_xmit_dlength);
		r2t->data_count = conn->max_xmit_dlength;
		hdr->flags = 0;
	} else {
		hton24(hdr->dlength, r2t->data_length);
		r2t->data_count = r2t->data_length;
		hdr->flags = ISCSI_FLAG_CMD_FINAL;
	}
	conn->dataout_pdus_cnt++;

	r2t->sent = 0;

	iscsi_buf_init_hdr(conn, &r2t->headbuf, (char*)hdr,
			   (u8 *)dtask->hdrext);

	if (sc->use_sg) {
		int i, sg_count = 0;
		struct scatterlist *sg = sc->request_buffer;

		r2t->sg = NULL;
		for (i = 0; i < sc->use_sg; i++, sg += 1) {
			/* FIXME: prefetch ? */
			if (sg_count + sg->length > r2t->data_offset) {
				int page_offset;

				/* sg page found! */

				/* offset within this page */
				page_offset = r2t->data_offset - sg_count;

				/* fill in this buffer */
				iscsi_buf_init_sg(&r2t->sendbuf, sg);
				r2t->sendbuf.sg.offset += page_offset;
				r2t->sendbuf.sg.length -= page_offset;

				/* xmit logic will continue with next one */
				r2t->sg = sg + 1;
				break;
			}
			sg_count += sg->length;
		}
		BUG_ON(r2t->sg == NULL);
	} else {
		iscsi_buf_init_virt(&ctask->sendbuf,
			    (char*)sc->request_buffer + r2t->data_offset,
			    r2t->data_count);
	}

	list_add(&dtask->item, &ctask->dataqueue);
}

/*
 * iSCSI R2T Response processing
 */
static int
iscsi_r2t_rsp(struct iscsi_conn *conn, struct iscsi_cmd_task *ctask)
{
	struct iscsi_r2t_info *r2t;
	struct iscsi_session *session = conn->session;
	struct iscsi_r2t_rsp *rhdr = (struct iscsi_r2t_rsp *)conn->in.hdr;
	uint32_t max_cmdsn = be32_to_cpu(rhdr->max_cmdsn);
	uint32_t exp_cmdsn = be32_to_cpu(rhdr->exp_cmdsn);
	int r2tsn = be32_to_cpu(rhdr->r2tsn);
	int rc;

	if (conn->in.ahslen)
		return ISCSI_ERR_AHSLEN;

	if (conn->in.datalen)
		return ISCSI_ERR_DATALEN;

	if (ctask->exp_r2tsn && ctask->exp_r2tsn != r2tsn)
		return ISCSI_ERR_R2TSN;

	if (max_cmdsn < exp_cmdsn - 1)
		return ISCSI_ERR_MAX_CMDSN;

	session->max_cmdsn = max_cmdsn;
	session->exp_cmdsn = exp_cmdsn;

	/* FIXME: use R2TSN to detect missing R2T */

	/* fill-in new R2T associated with the task */
	rc = __kfifo_get(ctask->r2tpool.queue, (void*)&r2t, sizeof(void*));
	BUG_ON(!rc);

	r2t->exp_statsn = rhdr->statsn;
	r2t->data_length = be32_to_cpu(rhdr->data_length);
	if (r2t->data_length == 0 ||
	    r2t->data_length > session->max_burst)
		return ISCSI_ERR_DATALEN;

	r2t->data_offset = be32_to_cpu(rhdr->data_offset);
	if (r2t->data_offset + r2t->data_length > ctask->total_length)
		return ISCSI_ERR_DATALEN;

	r2t->ttt = rhdr->ttt; /* no flip */
	r2t->solicit_datasn = 0;

	iscsi_solicit_data_init(conn, ctask, r2t);

	ctask->exp_r2tsn = r2tsn + 1;
	ctask->xmstate |= XMSTATE_SOL_HDR;
	__kfifo_put(ctask->r2tqueue, (void*)&r2t, sizeof(void*));
	__kfifo_put(conn->writequeue, (void*)&ctask, sizeof(void*));

	schedule_work(&conn->xmitwork);
	conn->r2t_pdus_cnt++;
	return 0;
}

static int
iscsi_hdr_recv(struct iscsi_conn *conn)
{
	int rc = 0;
	struct iscsi_hdr *hdr;
	struct iscsi_cmd_task *ctask;
	struct iscsi_session *session = conn->session;
	uint32_t cdgst, rdgst = 0;

	hdr = conn->in.hdr;

	/* verify PDU length */
	conn->in.datalen = ntoh24(hdr->dlength);
	if (conn->in.datalen > conn->max_recv_dlength) {
		printk("iscsi_tcp: datalen %d > %d\n", conn->in.datalen,
		       conn->max_recv_dlength);
		return ISCSI_ERR_DATALEN;
	}
	conn->data_copied = 0;

	/* read AHS */
	conn->in.ahslen = hdr->hlength*(4*sizeof(__u16));
	conn->in.offset += conn->in.ahslen;
	conn->in.copy -= conn->in.ahslen;
	if (conn->in.copy < 0) {
		printk("iscsi_tcp: can't handle AHS with length %d bytes\n",
		       conn->in.ahslen);
		return ISCSI_ERR_AHSLEN;
	}

	/* calculate read padding */
	conn->in.padding = conn->in.datalen & (ISCSI_PAD_LEN-1);
	if (conn->in.padding) {
		conn->in.padding = ISCSI_PAD_LEN - conn->in.padding;
		debug_scsi("read padding %d bytes\n", conn->in.padding);
	}

	if (conn->hdrdgst_en) {
		struct scatterlist sg;

		sg_init_one(&sg, (u8 *)hdr,
			    sizeof(struct iscsi_hdr) + conn->in.ahslen);
		crypto_digest_digest(conn->rx_tfm, &sg, 1, (u8 *)&cdgst);
		rdgst = *(uint32_t*)((char*)hdr + sizeof(struct iscsi_hdr) +
				     conn->in.ahslen);
	}

	/* save opcode & itt for later */
	conn->in.opcode = hdr->opcode;
	conn->in.itt = be32_to_cpu(hdr->itt);

	debug_tcp("opcode 0x%x offset %d copy %d ahslen %d datalen %d\n",
		  hdr->opcode, conn->in.offset, conn->in.copy,
		  conn->in.ahslen, conn->in.datalen);

	if (conn->in.itt < session->cmds_max) {
		if (conn->hdrdgst_en && cdgst != rdgst) {
			printk("iscsi_tcp: itt %x: hdrdgst error recv 0x%x "
			       "calc 0x%x\n", conn->in.itt, rdgst, cdgst);
			return ISCSI_ERR_HDR_DGST;
		}

		ctask = (struct iscsi_cmd_task *)session->cmds[conn->in.itt];
		conn->in.ctask = ctask;

		debug_scsi("rsp [op 0x%x cid %d sc %lx itt 0x%x len %d]\n",
			   hdr->opcode, conn->id, (long)ctask->sc, ctask->itt,
			   conn->in.datalen);

		switch(conn->in.opcode) {
		case ISCSI_OP_SCSI_CMD_RSP:
			BUG_ON((void*)ctask != ctask->sc->SCp.ptr);
			if (ctask->in_progress == IN_PROGRESS_READ) {
				if (!conn->in.datalen) {
					rc = iscsi_cmd_rsp(conn, ctask);
				} else {
					/* got sense or response data;
					 * copying PDU Header to the
					 * connection's header
					 * placeholder */
					memcpy(&conn->hdr, hdr,
					       sizeof(struct iscsi_hdr));
				}
			} else if (ctask->in_progress == IN_PROGRESS_WRITE) {
				rc = iscsi_cmd_rsp(conn, ctask);
			}
			break;
		case ISCSI_OP_SCSI_DATA_IN:
			BUG_ON((void*)ctask != ctask->sc->SCp.ptr);
			/* save flags for non-exceptional status */
			conn->in.flags = hdr->flags;
			/* save cmd_status for sense data */
			conn->in.cmd_status =
				((struct iscsi_data_rsp*)hdr)->cmd_status;
			rc = iscsi_data_rsp(conn, ctask);
			break;
		case ISCSI_OP_R2T:
			BUG_ON((void*)ctask != ctask->sc->SCp.ptr);
			rc = iscsi_r2t_rsp(conn, ctask);
			break;
		case ISCSI_OP_NOOP_IN:
		case ISCSI_OP_TEXT_RSP:
		case ISCSI_OP_LOGOUT_RSP:
		case ISCSI_OP_ASYNC_EVENT:
		case ISCSI_OP_REJECT:
			/* update ExpStatSN */
			conn->exp_statsn = be32_to_cpu(hdr->statsn) + 1;
			if (!conn->in.datalen) {
				struct iscsi_mgmt_task *mtask;

				rc = iscsi_recv_pdu(iscsi_handle(conn), hdr,
						    NULL, 0);
				mtask = (struct iscsi_mgmt_task *)
					session->mgmt_cmds[conn->in.itt -
						ISCSI_MGMT_ITT_OFFSET];
				if (conn->login_mtask != mtask) {
					spin_lock(&session->lock);
					__kfifo_put(session->mgmtpool.queue,
					    (void*)&mtask, sizeof(void*));
					spin_unlock(&session->lock);
				}
			}
			break;
		default:
			rc = ISCSI_ERR_BAD_OPCODE;
			break;
		}
	} else if (conn->in.itt >= ISCSI_MGMT_ITT_OFFSET &&
		   conn->in.itt < ISCSI_MGMT_ITT_OFFSET +
					session->mgmtpool_max) {
		struct iscsi_mgmt_task *mtask = (struct iscsi_mgmt_task *)
					session->mgmt_cmds[conn->in.itt -
						ISCSI_MGMT_ITT_OFFSET];

		debug_scsi("immrsp [op 0x%x cid %d itt 0x%x len %d]\n",
			   conn->in.opcode, conn->id, mtask->itt,
			   conn->in.datalen);

		switch(conn->in.opcode) {
		case ISCSI_OP_LOGIN_RSP:
		case ISCSI_OP_TEXT_RSP:
			if (!conn->in.datalen) {
				rc = iscsi_recv_pdu(iscsi_handle(conn), hdr,
						    NULL, 0);
				if (conn->login_mtask != mtask) {
					spin_lock(&session->lock);
					__kfifo_put(session->mgmtpool.queue,
					    (void*)&mtask, sizeof(void*));
					spin_unlock(&session->lock);
				}
			}
			break;
		case ISCSI_OP_SCSI_TMFUNC_RSP:
			if (conn->in.datalen || conn->in.ahslen) {
				rc = ISCSI_ERR_PROTO;
				break;
			}
			conn->tmfrsp_pdus_cnt++;
			spin_lock(&session->lock);
			__kfifo_put(session->mgmtpool.queue, (void*)&mtask,
				    sizeof(void*));
			spin_unlock(&session->lock);
			del_timer_sync(&conn->tmabort_timer);
			conn->tmabort_state = ((struct iscsi_tm_rsp *)hdr)->
				response == SCSI_TCP_TM_RESP_COMPLETE ?
					TMABORT_SUCCESS : TMABORT_FAILED;
			/* unblock eh_abort() and proceed with next command */
			wake_up(&conn->ehwait);
			break;
		default:
			rc = ISCSI_ERR_BAD_OPCODE;
			break;
		}
	} else if (conn->in.itt == ISCSI_RESERVED_TAG) {
		if (conn->in.opcode == ISCSI_OP_NOOP_IN &&
		    !conn->in.datalen) {
			rc = iscsi_recv_pdu(iscsi_handle(conn), hdr, NULL, 0);
		} else {
			rc = ISCSI_ERR_BAD_OPCODE;
		}
	} else {
		rc = ISCSI_ERR_BAD_ITT;
	}

	return rc;
}

/*
 * iscsi_ctask_copy - copy skb bits to the destanation cmd task
 *
 * The function calls skb_copy_bits() and updates per-connection and
 * per-cmd byte counters.
 */
static inline int
iscsi_ctask_copy(struct iscsi_conn *conn, struct iscsi_cmd_task *ctask,
		void *buf, int buf_size)
{
	int buf_left = buf_size - conn->data_copied;
	int size = min(conn->in.copy, buf_left);
	int rc;

	/*
	 * Read counters (in bytes):
	 *
	 *	conn->in.offset		offset within in progress SKB
	 *	conn->in.copy		left to copy from in progress SKB
	 *				including padding
	 *	conn->in.copied		copied already from in progress SKB
	 *	conn->data_copied	copied already from in progress buffer
	 *	ctask->sent		total bytes sent up to the MidLayer
	 *	ctask->data_count	left to copy from in progress Data-In
	 *	buf_left		left to copy from in progress buffer
	 */

	size = min(size, ctask->data_count);

	debug_tcp("ctask_copy %d bytes at offset %d copied %d\n",
	       size, conn->in.offset, conn->in.copied);

	BUG_ON(size <= 0);
	BUG_ON(ctask->sent + size > ctask->total_length);

	rc = skb_copy_bits(conn->in.skb, conn->in.offset,
			   (char*)buf + conn->data_copied, size);
	/* must fit into skb->len */
	BUG_ON(rc);

	conn->in.offset += size;
	conn->in.copy -= size;
	conn->in.copied += size;
	conn->data_copied += size;
	ctask->sent += size;
	ctask->data_count -= size;

	BUG_ON(conn->in.copy < 0);
	BUG_ON(ctask->data_count < 0);

	if (buf_size != conn->data_copied) {
		if (!ctask->data_count) {
			BUG_ON(buf_size - conn->data_copied < 0);
			/* done with this PDU */
			return buf_size - conn->data_copied;
		}
		return -EAGAIN;
	}

	/* done with this buffer or with both - PDU and buffer */
	conn->data_copied = 0;
	return 0;
}

/*
 * iscsi_tcp_copy - copy skb bits to the destanation buffer
 *
 * The function calls skb_copy_bits() and updates per-connection byte counters.
 */
static inline int
iscsi_tcp_copy(struct iscsi_conn *conn, void *buf, int buf_size)
{
	int buf_left = buf_size - conn->data_copied;
	int size = min(conn->in.copy, buf_left);
	int rc;

	debug_tcp("tcp_copy %d bytes at offset %d copied %d\n",
	       size, conn->in.offset, conn->data_copied);
	BUG_ON(size <= 0);

	rc = skb_copy_bits(conn->in.skb, conn->in.offset,
			   (char*)buf + conn->data_copied, size);
	BUG_ON(rc);

	conn->in.offset += size;
	conn->in.copy -= size;
	conn->in.copied += size;
	conn->data_copied += size;

	if (buf_size != conn->data_copied)
		return -EAGAIN;

	return 0;
}

static int
iscsi_data_recv(struct iscsi_conn *conn)
{
	struct iscsi_session *session = conn->session;
	int rc = 0;

	switch(conn->in.opcode) {
	case ISCSI_OP_SCSI_DATA_IN: {
	    struct iscsi_cmd_task *ctask = conn->in.ctask;
	    struct scsi_cmnd *sc = ctask->sc;
	    BUG_ON(!(ctask->in_progress & IN_PROGRESS_READ &&
		     conn->in_progress == IN_PROGRESS_DATA_RECV));
	    BUG_ON((void*)ctask != sc->SCp.ptr);

	    /*
	     * copying Data-In into the Scsi_Cmnd
	     */
	    if (sc->use_sg) {
		int i;
		struct scatterlist *sg = sc->request_buffer;

		for (i = ctask->sg_count; i < sc->use_sg; i++) {
			char *dest;

			dest = kmap_atomic(sg[i].page, KM_USER0);
			rc = iscsi_ctask_copy(conn, ctask, dest + sg[i].offset,
					      sg->length);
			kunmap_atomic(dest, KM_USER0);
			if (rc == -EAGAIN)
				/* continue with the next SKB/PDU */
				goto exit;
			if (!rc)
				ctask->sg_count++;
			if (!ctask->data_count) {
				rc = 0;
				break;
			}
			if (!conn->in.copy) {
				rc = -EAGAIN;
				goto exit;
			}
		}
	    } else {
		rc = iscsi_ctask_copy(conn, ctask, sc->request_buffer,
				      sc->request_bufflen);
		if (rc == -EAGAIN)
			goto exit;
		rc = 0;
	    }

	    /* check for non-exceptional status */
	    if (conn->in.flags & ISCSI_FLAG_DATA_STATUS) {
		    debug_scsi("done [sc %lx res %d itt 0x%x]\n",
			       (long)sc, sc->result, ctask->itt);
		    iscsi_ctask_cleanup(conn, ctask);
		    sc->scsi_done(sc);
	    }
	}
	break;
	case ISCSI_OP_SCSI_CMD_RSP: {
		/*
		 * SCSI Sense Data:
		 * copying the entire Data Segment.
		 */
		if (iscsi_tcp_copy(conn, conn->data, conn->in.datalen)) {
			rc = -EAGAIN;
			goto exit;
		}

		/*
		 * check for sense
		 */
		conn->in.hdr = &conn->hdr;
		conn->senselen = (conn->data[0] << 8) | conn->data[1];
		rc = iscsi_cmd_rsp(conn, conn->in.ctask);
	}
	break;
	case ISCSI_OP_TEXT_RSP:
	case ISCSI_OP_LOGIN_RSP:
	case ISCSI_OP_NOOP_IN: {
		struct iscsi_mgmt_task *mtask = NULL;

		if (conn->in.itt != ISCSI_RESERVED_TAG) {
			mtask = (struct iscsi_mgmt_task *)
				session->mgmt_cmds[conn->in.itt -
					ISCSI_MGMT_ITT_OFFSET];
		}

		/*
		 * Collect data segment to the connection's data
		 * placeholder
		 */
		if (iscsi_tcp_copy(conn, conn->data, conn->in.datalen)) {
			rc = -EAGAIN;
			goto exit;
		}

		rc = iscsi_recv_pdu(iscsi_handle(conn), conn->in.hdr,
				    conn->data, conn->in.datalen);

		if (mtask && conn->login_mtask != mtask) {
			spin_lock(&session->lock);
			__kfifo_put(session->mgmtpool.queue, (void*)&mtask,
				    sizeof(void*));
			spin_unlock(&session->lock);
		}
	}
	break;
	default:
		BUG_ON(1);
	}
exit:
	return rc;
}

/*
 * TCP receive
 */
static int
iscsi_tcp_data_recv(read_descriptor_t *rd_desc, struct sk_buff *skb,
		unsigned int offset, size_t len)
{
	int rc;
	struct iscsi_conn *conn = rd_desc->arg.data;
	int start = skb_headlen(skb);
	int processed;

	/*
	 * Save current SKB and its offset in the corresponding
	 * connection context.
	 */
	conn->in.copy = start - offset;
	conn->in.offset = offset;
	conn->in.skb = skb;
	conn->in.len = conn->in.copy;
	BUG_ON(conn->in.copy <= 0);
	debug_tcp("in %d bytes\n", conn->in.copy);

more:
	conn->in.copied = 0;
	rc = 0;

	if (conn->in_progress == IN_PROGRESS_WAIT_HEADER ||
	    conn->in_progress == IN_PROGRESS_HEADER_GATHER) {
		rc = iscsi_hdr_extract(conn);
		if (rc) {
		       if (rc == -EAGAIN)
				goto nomore;
		       else {
				iscsi_cnx_error(iscsi_handle(conn), rc);
				return 0;
		       }
		}

		/*
		 * Verify and process incoming PDU header.
		 */
		rc = iscsi_hdr_recv(conn);
		if (!rc && conn->in.datalen) {
			conn->in_progress = IN_PROGRESS_DATA_RECV;
		} else if (rc) {
			iscsi_cnx_error(iscsi_handle(conn), rc);
			return 0;
		}
	}

	if (conn->in_progress == IN_PROGRESS_DATA_RECV &&
	    conn->in.copy) {

		debug_tcp("data_recv offset %d copy %d\n",
		       conn->in.offset, conn->in.copy);

		rc = iscsi_data_recv(conn);
		if (rc) {
			if (rc == -EAGAIN) {
				rd_desc->count = conn->in.datalen -
							conn->in.ctask->sent;
				goto again;
			}
			iscsi_cnx_error(iscsi_handle(conn), rc);
			return 0;
		}
		conn->in.copy -= conn->in.padding;
		conn->in.offset += conn->in.padding;
		conn->in_progress = IN_PROGRESS_WAIT_HEADER;
	}

	debug_tcp("f, processed %d from out of %d padding %d\n",
	       conn->in.offset - offset, (int)len, conn->in.padding);
	BUG_ON(conn->in.offset - offset > len);

	if (conn->in.offset - offset != len) {
		debug_tcp("continue to process %d bytes\n",
		       (int)len - (conn->in.offset - offset));
		goto more;
	}

nomore:
	processed = conn->in.offset - offset;
	BUG_ON(processed == 0);
	return processed;

again:
	processed = conn->in.offset - offset;
	debug_tcp("c, processed %d from out of %d rd_desc_cnt %d\n",
	          processed, (int)len, (int)rd_desc->count);
	BUG_ON(processed == 0);
	BUG_ON(processed > len);

	conn->rxdata_octets += processed;
	return processed;
}

static void
iscsi_tcp_data_ready(struct sock *sk, int flag)
{
	struct iscsi_conn *conn = sk->sk_user_data;
	read_descriptor_t rd_desc;

	read_lock(&sk->sk_callback_lock);

	/* use rd_desc to pass 'conn' to iscsi_tcp_data_recv */
	rd_desc.arg.data = conn;
	rd_desc.count = 0;
	tcp_read_sock(sk, &rd_desc, iscsi_tcp_data_recv);

	read_unlock(&sk->sk_callback_lock);
}

static void
iscsi_tcp_state_change(struct sock *sk)
{
	struct iscsi_conn *conn;
	struct iscsi_session *session;
	void (*old_state_change)(struct sock *);

	read_lock(&sk->sk_callback_lock);

	conn = (struct iscsi_conn*)sk->sk_user_data;
	session = conn->session;

	if (sk->sk_state == TCP_CLOSE_WAIT ||
	    sk->sk_state == TCP_CLOSE) {
		debug_tcp("iscsi_tcp_state_change: TCP_CLOSE|TCP_CLOSE_WAIT\n");
		conn->c_stage = ISCSI_CNX_CLEANUP_WAIT;
		spin_lock_bh(&session->conn_lock);
		if (session->conn_cnt == 1 ||
		    session->leadconn == conn) {
			session->state = ISCSI_STATE_FAILED;
		}
		spin_unlock_bh(&session->conn_lock);
		iscsi_cnx_error(iscsi_handle(conn), ISCSI_ERR_CNX_FAILED);
	}

	old_state_change = conn->old_state_change;

	read_unlock(&sk->sk_callback_lock);

	old_state_change(sk);
}

/*
 * Called when more output buffer space is available for this socket.
 */
static void
iscsi_write_space(struct sock *sk)
{
	struct iscsi_conn *conn = (struct iscsi_conn*)sk->sk_user_data;
	conn->old_write_space(sk);
	debug_tcp("iscsi_write_space: cid %d\n", conn->id);
	conn->suspend = 0;
	schedule_work(&conn->xmitwork);
}

static void
iscsi_conn_set_callbacks(struct iscsi_conn *conn)
{
	struct sock *sk = conn->sock->sk;

	/* assign new callbacks */
	write_lock_bh(&sk->sk_callback_lock);
	sk->sk_user_data = conn;
	conn->old_data_ready = sk->sk_data_ready;
	conn->old_state_change = sk->sk_state_change;
	conn->old_write_space = sk->sk_write_space;
	sk->sk_data_ready = iscsi_tcp_data_ready;
	sk->sk_state_change = iscsi_tcp_state_change;
	sk->sk_write_space = iscsi_write_space;
	write_unlock_bh(&sk->sk_callback_lock);
}

static void
iscsi_conn_restore_callbacks(struct iscsi_conn *conn)
{
	struct sock *sk = conn->sock->sk;

	/* restore socket callbacks, see also: iscsi_conn_set_callbacks() */
	write_lock_bh(&sk->sk_callback_lock);
	sk->sk_user_data    = NULL;
	sk->sk_data_ready   = conn->old_data_ready;
	sk->sk_state_change = conn->old_state_change;
	sk->sk_write_space  = conn->old_write_space;
	sk->sk_no_check	 = 0;
	write_unlock_bh(&sk->sk_callback_lock);
}

/*
 * iscsi_sendhdr - send PDU Header via tcp_sendpage()
 * (Tx, Fast Path)
 */
static inline int
iscsi_sendhdr(struct iscsi_conn *conn, struct iscsi_buf *buf, int datalen)
{
	struct socket *sk = conn->sock;
	int flags = 0; /* MSG_DONTWAIT; */
	int res, offset, size;

	offset = buf->sg.offset + buf->sent;
	size = buf->sg.length - buf->sent;
	BUG_ON(buf->sent + size > buf->sg.length);
	if (buf->sent + size != buf->sg.length || datalen)
		flags |= MSG_MORE;

	/* sendpage */
	res = sk->ops->sendpage(sk, buf->sg.page, offset, size, flags);
	debug_tcp("sendhdr %p %d bytes at offset %d sent %d res %d\n",
		page_address(buf->sg.page), size, offset, buf->sent, res);
	if (res >= 0) {
		conn->txdata_octets += res;
		buf->sent += res;
		if (size != res)
			return -EAGAIN;
		return 0;
	} else if (res == -EAGAIN) {
		conn->sendpage_failures_cnt++;
		conn->suspend = 1;
	} else if (res == -EPIPE) {
		conn->suspend = 1;
		iscsi_cnx_error(iscsi_handle(conn), ISCSI_ERR_CNX_FAILED);
	}

	return res;
}

/*
 * iscsi_sendpage - send one page of iSCSI Data-Out.
 * (Tx, Fast Path)
 */
static inline int
iscsi_sendpage(struct iscsi_conn *conn, struct iscsi_buf *buf,
	       int *count, int *sent)
{
	ssize_t (*sendpage)(struct socket *, struct page *, int, size_t, int);
	struct socket *sk = conn->sock;
	int flags = 0; /* MSG_DONTWAIT; */
	int res, offset, size;

	size = buf->sg.length - buf->sent;
	BUG_ON(buf->sent + size > buf->sg.length);
	if (size > *count)
		size = *count;
	if (buf->sent + size != buf->sg.length)
		flags |= MSG_MORE;

	offset = buf->sg.offset + buf->sent;

	/* tcp_sendpage */
	sendpage = sk->ops->sendpage ? : sock_no_sendpage;

	res = sendpage(sk, buf->sg.page, offset, size, flags);
	debug_tcp("sendpage %p %d bytes, boff %d bsent %d "
		  "left %d sent %d res %d\n",
		  page_address(buf->sg.page), size, offset,
		  buf->sent, *count, *sent, res);
	if (res >= 0) {
		conn->txdata_octets += res;
		buf->sent += res;
		*count -= res;
		*sent += res;
		if (size != res)
			return -EAGAIN;
		return 0;
	} else if (res == -EAGAIN) {
		conn->sendpage_failures_cnt++;
		conn->suspend = 1;
	} else if (res == -EPIPE) {
		conn->suspend = 1;
		iscsi_cnx_error(iscsi_handle(conn), ISCSI_ERR_CNX_FAILED);
	}

	return res;
}

/*
 * iscsi_solicit_data_cont - initialize next Data-Out
 *
 * Initialize next Data-Out within this R2T sequence and continue
 * to process next Scatter-Gather element(if any) of this SCSI command.
 *
 * Called under connection lock.
 */
static void
iscsi_solicit_data_cont(struct iscsi_conn *conn, struct iscsi_cmd_task *ctask,
			struct iscsi_r2t_info *r2t, int left)
{
	struct iscsi_data *hdr;
	struct iscsi_data_task *dtask;
	struct scsi_cmnd *sc = ctask->sc;
	int new_offset;

	dtask = mempool_alloc(ctask->datapool, GFP_ATOMIC);
	BUG_ON(!dtask);
	hdr = &dtask->hdr;
	memset(hdr, 0, sizeof(struct iscsi_data));
	hdr->ttt = r2t->ttt;
	hdr->datasn = cpu_to_be32(r2t->solicit_datasn);
	r2t->solicit_datasn++;
	hdr->opcode = ISCSI_OP_SCSI_DATA_OUT;
	hdr->lun[1] = ctask->hdr.lun[1];
	hdr->itt = ctask->hdr.itt;
	hdr->exp_statsn = r2t->exp_statsn;
	new_offset = r2t->data_offset + r2t->sent;
	hdr->offset = cpu_to_be32(new_offset);
	if (left > conn->max_xmit_dlength) {
		hton24(hdr->dlength, conn->max_xmit_dlength);
		r2t->data_count = conn->max_xmit_dlength;
	} else {
		hton24(hdr->dlength, left);
		r2t->data_count = left;
		hdr->flags = ISCSI_FLAG_CMD_FINAL;
	}
	conn->dataout_pdus_cnt++;

	iscsi_buf_init_hdr(conn, &r2t->headbuf, (char*)hdr,
			   (u8 *)dtask->hdrext);

	if (sc->use_sg) {
		if (!iscsi_buf_left(&r2t->sendbuf)) {
			BUG_ON(ctask->bad_sg == r2t->sg);
			iscsi_buf_init_sg(&r2t->sendbuf, r2t->sg);
			r2t->sg += 1;
		}
	} else {
		iscsi_buf_init_virt(&ctask->sendbuf,
			    (char*)sc->request_buffer + new_offset,
			    r2t->data_count);
	}

	list_add(&dtask->item, &ctask->dataqueue);
}

static void
iscsi_unsolicit_data_init(struct iscsi_conn *conn, struct iscsi_cmd_task *ctask)
{
	struct iscsi_data *hdr;
	struct iscsi_data_task *dtask;

	dtask = mempool_alloc(ctask->datapool, GFP_ATOMIC);
	BUG_ON(!dtask);
	hdr = &dtask->hdr;
	memset(hdr, 0, sizeof(struct iscsi_data));
	hdr->ttt = cpu_to_be32(ISCSI_RESERVED_TAG);
	hdr->datasn = cpu_to_be32(ctask->unsol_datasn);
	ctask->unsol_datasn++;
	hdr->opcode = ISCSI_OP_SCSI_DATA_OUT;
	hdr->lun[1] = ctask->hdr.lun[1];
	hdr->itt = ctask->hdr.itt;
	hdr->exp_statsn = cpu_to_be32(conn->exp_statsn);
	hdr->offset = cpu_to_be32(ctask->total_length -
				  ctask->r2t_data_count -
				  ctask->unsol_count);
	if (ctask->unsol_count > conn->max_xmit_dlength) {
		hton24(hdr->dlength, conn->max_xmit_dlength);
		ctask->data_count = conn->max_xmit_dlength;
		hdr->flags = 0;
	} else {
		hton24(hdr->dlength, ctask->unsol_count);
		ctask->data_count = ctask->unsol_count;
		hdr->flags = ISCSI_FLAG_CMD_FINAL;
	}

	iscsi_buf_init_hdr(conn, &ctask->headbuf, (char*)hdr,
			   (u8 *)dtask->hdrext);

	list_add(&dtask->item, &ctask->dataqueue);
}

/*
 * Initialize iSCSI SCSI_READ or SCSI_WRITE commands
 */
static void
iscsi_cmd_init(struct iscsi_conn *conn, struct iscsi_cmd_task *ctask,
		struct scsi_cmnd *sc)
{
	struct iscsi_session *session = conn->session;

	ctask->sc = sc;
	ctask->conn = conn;
	ctask->hdr.opcode = ISCSI_OP_SCSI_CMD;
	ctask->hdr.flags = ISCSI_ATTR_SIMPLE;
	ctask->hdr.lun[1] = sc->device->lun;
	ctask->hdr.itt = cpu_to_be32(ctask->itt);
	ctask->hdr.data_length = cpu_to_be32(sc->request_bufflen);
	ctask->hdr.cmdsn = cpu_to_be32(session->cmdsn); session->cmdsn++;
	ctask->hdr.exp_statsn = cpu_to_be32(conn->exp_statsn);
	memcpy(ctask->hdr.cdb, sc->cmnd, sc->cmd_len);
	memset(&ctask->hdr.cdb[sc->cmd_len], 0, MAX_COMMAND_SIZE - sc->cmd_len);

	ctask->in_progress = IN_PROGRESS_IDLE;
	ctask->sent = 0;
	ctask->sg_count = 0;

	ctask->total_length = sc->request_bufflen;

	if (sc->sc_data_direction == DMA_TO_DEVICE) {
		ctask->exp_r2tsn = 0;
		ctask->hdr.flags |= ISCSI_FLAG_CMD_WRITE;
		ctask->in_progress = IN_PROGRESS_WRITE;
		BUG_ON(ctask->total_length == 0);
		if (sc->use_sg) {
			struct scatterlist *sg = sc->request_buffer;

			iscsi_buf_init_sg(&ctask->sendbuf,
					  &sg[ctask->sg_count++]);
			ctask->sg = sg;
			ctask->bad_sg = sg + sc->use_sg;
		} else {
			iscsi_buf_init_virt(&ctask->sendbuf, sc->request_buffer,
					sc->request_bufflen);
			BUG_ON(sc->request_bufflen > PAGE_SIZE);
		}

		/*
		 * Write counters:
		 *
		 *	imm_count	bytes to be sent right after
		 *			SCSI PDU Header
		 *
		 *	unsol_count	bytes(as Data-Out) to be sent
		 *			without	R2T ack right after
		 *			immediate data
		 *
		 *	r2t_data_count	bytes to be sent via R2T ack's
		 *
		 *      pad_count       bytes to be sent as zero-padding
		 */
		ctask->imm_count = 0;
		ctask->unsol_count = 0;
		ctask->unsol_datasn = 0;
		ctask->xmstate = XMSTATE_W_HDR;
		/* calculate write padding */
		ctask->pad_count = ctask->total_length & (ISCSI_PAD_LEN-1);
		if (ctask->pad_count) {
			ctask->pad_count = ISCSI_PAD_LEN - ctask->pad_count;
			debug_scsi("write padding %d bytes\n",
				ctask->pad_count);
			ctask->xmstate |= XMSTATE_W_PAD;
		}
		if (session->imm_data_en) {
			if (ctask->total_length >= session->first_burst) {
				ctask->imm_count = min(session->first_burst,
							conn->max_xmit_dlength);
			} else {
				ctask->imm_count = min(ctask->total_length,
							conn->max_xmit_dlength);
			}
			hton24(ctask->hdr.dlength, ctask->imm_count);
			ctask->xmstate |= XMSTATE_IMM_DATA;
		} else {
			zero_data(ctask->hdr.dlength);
		}
		if (!session->initial_r2t_en)
			ctask->unsol_count = min(session->first_burst,
				ctask->total_length) - ctask->imm_count;
		if (!ctask->unsol_count) {
			/* No unsolicit Data-Out's */
			ctask->hdr.flags |= ISCSI_FLAG_CMD_FINAL;
		} else {
			ctask->xmstate |= XMSTATE_UNS_HDR | XMSTATE_UNS_INIT;
		}
		ctask->r2t_data_count = ctask->total_length -
				    ctask->imm_count -
				    ctask->unsol_count;

		debug_scsi("cmd [itt %x total %d imm %d imm_data %d "
			   "r2t_data %d]\n",
			   ctask->itt, ctask->total_length, ctask->imm_count,
			   ctask->unsol_count, ctask->r2t_data_count);
	} else {
		ctask->hdr.flags |= ISCSI_FLAG_CMD_FINAL;
		if (sc->sc_data_direction == DMA_FROM_DEVICE)
			ctask->hdr.flags |= ISCSI_FLAG_CMD_READ;
		ctask->datasn = 0;
		ctask->in_progress = IN_PROGRESS_READ;
		ctask->xmstate = XMSTATE_R_HDR;
		zero_data(ctask->hdr.dlength);
	}

	iscsi_buf_init_hdr(conn, &ctask->headbuf, (char*)&ctask->hdr,
			    (u8 *)ctask->hdrext);
	conn->scsicmd_pdus_cnt++;
}

/*
 * iscsi_mtask_xmit - xmit management(immediate) task
 *
 * The function can return -EAGAIN in which case caller must
 * call it again later, or recover. '0' return code means successful
 * xmit.
 *
 * Management xmit state machine consists of two states:
 *	IN_PROGRESS_IMM_HEAD - PDU Header xmit in progress
 *	IN_PROGRESS_IMM_DATA - PDU Data xmit in progress
 */
static int
iscsi_mtask_xmit(struct iscsi_conn *conn, struct iscsi_mgmt_task *mtask)
{

	debug_scsi("mtask deq [cid %d state %x itt 0x%x]\n",
		conn->id, mtask->xmstate, mtask->itt);

	if (mtask->xmstate & XMSTATE_IMM_HDR) {
		mtask->xmstate &= ~XMSTATE_IMM_HDR;
		if (mtask->data_count)
			mtask->xmstate |= XMSTATE_IMM_DATA;
		if (iscsi_sendhdr(conn, &mtask->headbuf, mtask->data_count)) {
			mtask->xmstate |= XMSTATE_IMM_HDR;
			if (mtask->data_count)
				mtask->xmstate &= ~XMSTATE_IMM_DATA;
			return -EAGAIN;
		}
	}

	if (mtask->xmstate & XMSTATE_IMM_DATA) {
		BUG_ON(!mtask->data_count);
		mtask->xmstate &= ~XMSTATE_IMM_DATA;
		/* FIXME: implement.
		 * Virtual buffer could be spreaded across multiple pages...
		 */
		do {
			if (iscsi_sendpage(conn, &mtask->sendbuf,
				   &mtask->data_count, &mtask->sent)) {
				mtask->xmstate |= XMSTATE_IMM_DATA;
				return -EAGAIN;
			}
		} while (mtask->data_count);
	}

	BUG_ON(mtask->xmstate != XMSTATE_IDLE);
	return 0;
}

static int
iscsi_ctask_xmit(struct iscsi_conn *conn, struct iscsi_cmd_task *ctask)
{
	struct iscsi_r2t_info *r2t = NULL;

	debug_scsi("ctask deq [cid %d xmstate %x itt 0x%x]\n",
		conn->id, ctask->xmstate, ctask->itt);

	if (ctask->xmstate & XMSTATE_R_HDR) {
		ctask->xmstate &= ~XMSTATE_R_HDR;
		if (!iscsi_sendhdr(conn, &ctask->headbuf, 0)) {
			BUG_ON(ctask->xmstate != XMSTATE_IDLE);
			return 0; /* wait for Data-In */
		}
		ctask->xmstate |= XMSTATE_R_HDR;
		return -EAGAIN;
	}

	if (ctask->xmstate & XMSTATE_W_HDR) {
		ctask->xmstate &= ~XMSTATE_W_HDR;
		if (iscsi_sendhdr(conn, &ctask->headbuf, ctask->imm_count)) {
			ctask->xmstate |= XMSTATE_W_HDR;
			return -EAGAIN;
		}
	}

	if (ctask->xmstate & XMSTATE_IMM_DATA) {
		BUG_ON(!ctask->imm_count);
		ctask->xmstate &= ~XMSTATE_IMM_DATA;
		for (;;) {
			if (iscsi_sendpage(conn, &ctask->sendbuf,
					   &ctask->imm_count, &ctask->sent)) {
				ctask->xmstate |= XMSTATE_IMM_DATA;
				return -EAGAIN;
			}
			if (!ctask->imm_count)
				break;
			iscsi_buf_init_sg(&ctask->sendbuf,
					  &ctask->sg[ctask->sg_count++]);
		}
	}

	if (ctask->xmstate & XMSTATE_UNS_HDR) {
		BUG_ON(!ctask->unsol_count);
		ctask->xmstate &= ~XMSTATE_UNS_HDR;
_unsolicit_head_again:
		ctask->xmstate |= XMSTATE_UNS_DATA;
		if (ctask->xmstate & XMSTATE_UNS_INIT) {
			iscsi_unsolicit_data_init(conn, ctask);
			ctask->xmstate &= ~XMSTATE_UNS_INIT;
		}
		if (iscsi_sendhdr(conn, &ctask->headbuf, ctask->data_count)) {
			ctask->xmstate &= ~XMSTATE_UNS_DATA;
			ctask->xmstate |= XMSTATE_UNS_HDR;
			return -EAGAIN;
		}

		debug_scsi("uns dout [itt 0x%x dlen %d sent %d]\n",
			ctask->itt, ctask->unsol_count, ctask->sent);
	}

	if (ctask->xmstate & XMSTATE_UNS_DATA) {
		BUG_ON(!ctask->data_count);
		ctask->xmstate &= ~XMSTATE_UNS_DATA;
		for (;;) {
			int start = ctask->sent;
			if (iscsi_sendpage(conn, &ctask->sendbuf,
					   &ctask->data_count,
					   &ctask->sent)) {
				ctask->unsol_count -= ctask->sent - start;
				ctask->xmstate |= XMSTATE_UNS_DATA;
				/* will continue with this ctask later.. */
				return -EAGAIN;
			}
			BUG_ON(ctask->sent > ctask->total_length);
			ctask->unsol_count -= ctask->sent - start;
			if (!ctask->data_count)
				break;
			iscsi_buf_init_sg(&ctask->sendbuf,
					  &ctask->sg[ctask->sg_count++]);
		}
		BUG_ON(ctask->unsol_count < 0);

		/*
		 * Done with the Data-Out. Next, check if we need
		 * to send another unsolicited Data-Out.
		 */
		if (ctask->unsol_count) {
			ctask->xmstate |= XMSTATE_UNS_INIT;
			goto _unsolicit_head_again;
		}

		goto _done;
	}

	if (ctask->xmstate & XMSTATE_SOL_HDR) {
		ctask->xmstate &= ~XMSTATE_SOL_HDR;
		ctask->xmstate |= XMSTATE_SOL_DATA;
		if (!ctask->r2t) {
			__kfifo_get(ctask->r2tqueue, (void*)&r2t,
				    sizeof(void*));
			ctask->r2t = r2t;
		}
_solicit_head_again:
		BUG_ON(r2t == NULL);
		if (iscsi_sendhdr(conn, &r2t->headbuf, r2t->data_count)) {
			ctask->xmstate &= ~XMSTATE_SOL_DATA;
			ctask->xmstate |= XMSTATE_SOL_HDR;
			return -EAGAIN;
		}

		debug_scsi("sol dout [dsn %d itt 0x%x dlen %d sent %d]\n",
			r2t->solicit_datasn - 1, ctask->itt, r2t->data_count,
			r2t->sent);
	}

	if (ctask->xmstate & XMSTATE_SOL_DATA) {
		int left;

		ctask->xmstate &= ~XMSTATE_SOL_DATA;
		r2t = ctask->r2t;
_solicit_again:
		/*
		 * send Data-Out whitnin this R2T sequence.
		 */
		if (r2t->data_count) {
			if (iscsi_sendpage(conn, &r2t->sendbuf,
					   &r2t->data_count,
					   &r2t->sent)) {
				ctask->xmstate |= XMSTATE_SOL_DATA;
				/* will continue with this ctask later.. */
				return -EAGAIN;
			}
			BUG_ON(r2t->data_count < 0);
			if (r2t->data_count) {
				BUG_ON(ctask->sc->use_sg == 0);
				if (!iscsi_buf_left(&r2t->sendbuf)) {
					BUG_ON(ctask->bad_sg == r2t->sg);
					iscsi_buf_init_sg(&r2t->sendbuf,
							  r2t->sg);
					r2t->sg += 1;
				}
				goto _solicit_again;
			}
		}

		/*
		 * Done with this Data-Out. Next, check if we have
		 * to send another Data-Out for this R2T.
		 */
		BUG_ON(r2t->data_length - r2t->sent < 0);
		left = r2t->data_length - r2t->sent;
		if (left) {
			iscsi_solicit_data_cont(conn, ctask, r2t, left);
			ctask->xmstate |= XMSTATE_SOL_DATA;
			ctask->xmstate &= ~XMSTATE_SOL_HDR;
			goto _solicit_head_again;
		}

		/*
		 * Done with this R2T. Check if there are more
		 * outstanding R2Ts ready to be processed.
		 */
		BUG_ON(ctask->r2t_data_count - r2t->data_length < 0);
		ctask->r2t_data_count -= r2t->data_length;
		ctask->r2t = NULL;
		__kfifo_put(ctask->r2tpool.queue, (void*)&r2t, sizeof(void*));
		if (__kfifo_get(ctask->r2tqueue, (void*)&r2t, sizeof(void*))) {
			ctask->r2t = r2t;
			ctask->xmstate |= XMSTATE_SOL_DATA;
			ctask->xmstate &= ~XMSTATE_SOL_HDR;
			goto _solicit_head_again;
		}
	}

_done:
	/*
	 * Last thing to check is whether we need to send write
	 * padding. Note that we check for xmstate equality, not just the bit.
	 */
	if (ctask->xmstate == XMSTATE_W_PAD) {
		int sent;
		ctask->xmstate &= ~XMSTATE_W_PAD;
		iscsi_buf_init_virt(&ctask->sendbuf, (char*)&ctask->pad,
				    ctask->pad_count);
		if (iscsi_sendpage(conn, &ctask->sendbuf, &ctask->pad_count,
				&sent)) {
			ctask->xmstate |= XMSTATE_W_PAD;
			return -EAGAIN;
		}
	}
	return 0;
}

/*
 * iscsi_data_xmit - xmit any command into the scheduled connection
 *
 * The function can return -EAGAIN in which case the caller must
 * re-schedule it again later or recover. '0' return code means successful
 * xmit.
 */
static int
iscsi_data_xmit(struct iscsi_conn *conn)
{
	/*
	 * Transmit in the following order:
	 *
	 * 1) un-finished xmit (ctask or mtask)
	 * 2) immediate control PDUs
	 * 3) write data
	 * 4) SCSI commands
	 * 5) non-immediate control PDUs
	 *
	 * No need to lock around __kfifo_get as long as
	 * there's one producer and one consumer.
	 */

	BUG_ON(conn->ctask && conn->mtask);

	if (conn->ctask) {
		if (iscsi_ctask_xmit(conn, conn->ctask))
			return -EAGAIN;
		/* done with this in-progress ctask */
		conn->ctask = NULL;
	}
	if (conn->mtask) {
	        if (iscsi_mtask_xmit(conn, conn->mtask))
		        return -EAGAIN;
		/* done with this in-progress mtask */
		conn->mtask = NULL;
	}

	/* process immediate first */
        if (unlikely(__kfifo_len(conn->immqueue))) {
		struct iscsi_session *session = conn->session;
	        while (__kfifo_get(conn->immqueue, (void*)&conn->mtask,
			           sizeof(void*))) {
		        if (iscsi_mtask_xmit(conn, conn->mtask))
			        return -EAGAIN;

		        if (conn->mtask->hdr.itt ==
					cpu_to_be32(ISCSI_RESERVED_TAG)) {
			        spin_lock_bh(&session->lock);
			        __kfifo_put(session->mgmtpool.queue,
					    (void*)&conn->mtask, sizeof(void*));
			        spin_unlock_bh(&session->lock);
		        }
	        }
		/* done with this mtask */
		conn->mtask = NULL;
	}

	/* process write queue */
	while (__kfifo_get(conn->writequeue, (void*)&conn->ctask,
			   sizeof(void*))) {
		if (iscsi_ctask_xmit(conn, conn->ctask))
			return -EAGAIN;
	}

	/* process command queue */
	while (__kfifo_get(conn->xmitqueue, (void*)&conn->ctask,
			   sizeof(void*))) {
		if (iscsi_ctask_xmit(conn, conn->ctask))
			return -EAGAIN;
	}
	/* done with this ctask */
	conn->ctask = NULL;

	/* process the rest control plane PDUs, if any */
        if (unlikely(__kfifo_len(conn->mgmtqueue))) {
		struct iscsi_session *session = conn->session;
	        while (__kfifo_get(conn->mgmtqueue, (void*)&conn->mtask,
			           sizeof(void*))) {
		        if (iscsi_mtask_xmit(conn, conn->mtask))
			        return -EAGAIN;

		        if (conn->mtask->hdr.itt ==
					cpu_to_be32(ISCSI_RESERVED_TAG)) {
			        spin_lock_bh(&session->lock);
			        __kfifo_put(session->mgmtpool.queue,
					    (void*)&conn->mtask,
				            sizeof(void*));
			        spin_unlock_bh(&session->lock);
		        }
	        }
		/* done with this mtask */
		conn->mtask = NULL;
	}

	return 0;
}

static inline int
iscsi_data_xmit_more(struct iscsi_conn *conn)
{
	int rc;

	if (unlikely(conn->suspend))
		return 0;
	rc = iscsi_data_xmit(conn);
	if (rc) {
		if (conn->stop_stage != STOP_CNX_RECOVER &&
		    (conn->c_stage == ISCSI_CNX_CLEANUP_WAIT ||
		     conn->c_stage == ISCSI_CNX_STOPPED ||
		     conn->suspend))
			return 0;
	}
	return rc;
}

static void
iscsi_xmitworker(void *data)
{
	struct iscsi_conn *conn = data;

	/*
	 * serialize Xmit worker on a per-connection basis.
	 */
	down(&conn->xmitsema);
	if (iscsi_data_xmit_more(conn))
		schedule_work(&conn->xmitwork);
	up(&conn->xmitsema);
}

#define FAILURE_BAD_HOST		1
#define FAILURE_SESSION_FAILED		2
#define FAILURE_SESSION_FREED		3
#define FAILURE_WINDOW_CLOSED		4
#define FAILURE_SESSION_TERMINATE	5

static int
iscsi_queuecommand(struct scsi_cmnd *sc, void (*done)(struct scsi_cmnd *))
{
	struct Scsi_Host *host;
	int reason = 0;
	struct iscsi_session *session;
	struct iscsi_conn *conn = NULL;
	struct iscsi_cmd_task *ctask = NULL;

	sc->scsi_done = done;
	sc->result = 0;

	host = sc->device->host;
	session = iscsi_hostdata(host->hostdata);
	BUG_ON(host != session->host);

	spin_lock(&session->lock);

	if (session->state != ISCSI_STATE_LOGGED_IN) {
		if (session->state == ISCSI_STATE_FAILED) {
			reason = FAILURE_SESSION_FAILED;
			goto reject;
		} else if (session->state == ISCSI_STATE_TERMINATE) {
			reason = FAILURE_SESSION_TERMINATE;
			goto fault;
		}
		reason = FAILURE_SESSION_FREED;
		goto fault;
	}

	/*
	 * Check for iSCSI window and take care of CmdSN wrap-around
	 */
	if ((int)(session->max_cmdsn - session->cmdsn) < 0) {
		reason = FAILURE_WINDOW_CLOSED;
		goto reject;
	}

	conn = session->leadconn;

	if (unlikely(session->conn_cnt > 1)) {
		struct iscsi_conn *cnx;
		int cpu = smp_processor_id();

		spin_lock(&session->conn_lock);
		list_for_each_entry(cnx, &session->connections, item) {
			if (cnx->cpu == cpu && cpu_online(cpu)) {
				conn = cnx;
				break;
			}
		}
		spin_unlock(&session->conn_lock);
	}

	__kfifo_get(session->cmdpool.queue, (void*)&ctask, sizeof(void*));
	sc->SCp.Status = QUEUED;
	sc->SCp.phase = session->generation;
	spin_unlock(&session->lock);

	BUG_ON(!ctask);
	BUG_ON(ctask->in_progress = IN_PROGRESS_IDLE);

	sc->SCp.ptr = (char*)ctask;
	iscsi_cmd_init(conn, ctask, sc);

	__kfifo_put(conn->xmitqueue, (void*)&ctask, sizeof(void*));
	debug_scsi(
	       "ctask enq [%s cid %d sc %lx itt 0x%x len %d cmdsn %d win %d]\n",
		sc->sc_data_direction == DMA_TO_DEVICE ? "write" : "read",
		conn->id, (long)sc, ctask->itt, sc->request_bufflen,
		session->cmdsn, session->max_cmdsn - session->exp_cmdsn + 1);

        if (!in_interrupt() && !down_trylock(&conn->xmitsema)) {
		spin_unlock_irq(host->host_lock);
		if (iscsi_data_xmit_more(conn))
			schedule_work(&conn->xmitwork);
		up(&conn->xmitsema);
		spin_lock_irq(host->host_lock);
	} else
		schedule_work(&conn->xmitwork);

	return 0;

reject:
	spin_unlock(&session->lock);
	debug_scsi("cmd 0x%x rejected (%d)\n", sc->cmnd[0], reason);
	return SCSI_MLQUEUE_HOST_BUSY;

fault:
	spin_unlock(&session->lock);
	printk("iscsi_tcp: cmd 0x%x is not queued (%d)\n", sc->cmnd[0], reason);
	sc->sense_buffer[0] = 0x70;
	sc->sense_buffer[2] = NOT_READY;
	sc->sense_buffer[7] = 0x6;
	sc->sense_buffer[12] = 0x08;
	sc->sense_buffer[13] = 0x00;
	sc->result = (DID_NO_CONNECT << 16);
	sc->resid = sc->request_bufflen;
	sc->scsi_done(sc);
	return 0;
}

static int
iscsi_pool_init(struct iscsi_queue *q, int max, void ***items, int item_size)
{
	int i;

	*items = kmalloc(max * sizeof(void*), GFP_KERNEL);
	if (*items == NULL)
		return -ENOMEM;

	q->max = max;
	q->pool = kmalloc(max * sizeof(void*), GFP_KERNEL);
	if (q->pool == NULL) {
		kfree(*items);
		return -ENOMEM;
	}

	q->queue = kfifo_init((void*)q->pool, max * sizeof(void*),
			      GFP_KERNEL, NULL);
	if (q->queue == ERR_PTR(-ENOMEM)) {
		kfree(q->pool);
		kfree(*items);
		return -ENOMEM;
	}

	for (i = 0; i < max; i++) {
		q->pool[i] = kmalloc(item_size, GFP_KERNEL);
		if (q->pool[i] == NULL) {
			int j;
			for (j = 0; j < i; j++) {
				kfree(q->pool[j]);
			}
			kfifo_free(q->queue);
			kfree(q->pool);
			kfree(*items);
			return -ENOMEM;
		}
		memset(q->pool[i], 0, item_size);
		(*items)[i] = q->pool[i];
		__kfifo_put(q->queue, (void*)&q->pool[i], sizeof(void*));
	}
	return 0;
}

static void
iscsi_pool_free(struct iscsi_queue *q, void **items)
{
	int i;

	for (i = 0; i < q->max; i++)
		kfree(items[i]);
	kfree(q->pool);
	kfree(items);
}

/*
 * Allocate a new connection within the session and bind it to
 * the given socket.
 */
static iscsi_cnx_t
iscsi_conn_create(iscsi_snx_t snxh, uint32_t conn_idx)
{
	struct iscsi_session *session = iscsi_ptr(snxh);
	struct iscsi_conn *conn = NULL;

	conn = kmalloc(sizeof(struct iscsi_conn), GFP_KERNEL);
	if (conn == NULL)
		goto conn_alloc_fail;
	memset(conn, 0, sizeof(struct iscsi_conn));

	conn->c_stage = ISCSI_CNX_INITIAL_STAGE;
	conn->in_progress = IN_PROGRESS_WAIT_HEADER;
	conn->id = conn_idx;
	conn->exp_statsn = 0;
	conn->tmabort_state = TMABORT_INITIAL;

	/* initial operational parameters */
	conn->hdr_size = sizeof(struct iscsi_hdr);
	conn->data_size = DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH;
	conn->max_recv_dlength = DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH;

	spin_lock_init(&conn->lock);

	/* initialize general xmit PDU commands queue */
	conn->xmitqueue = kfifo_alloc(session->cmds_max * sizeof(void*),
					GFP_KERNEL, NULL);
	if (conn->xmitqueue == ERR_PTR(-ENOMEM))
		goto xmitqueue_alloc_fail;

	/* initialize write response PDU commands queue */
	conn->writequeue = kfifo_alloc(session->cmds_max * sizeof(void*),
					GFP_KERNEL, NULL);
	if (conn->writequeue == ERR_PTR(-ENOMEM))
		goto writequeue_alloc_fail;

	/* initialize general immediate & non-immediate PDU commands queue */
	conn->immqueue = kfifo_alloc(session->mgmtpool_max * sizeof(void*),
			                GFP_KERNEL, NULL);
	if (conn->immqueue == ERR_PTR(-ENOMEM))
		goto immqueue_alloc_fail;

	conn->mgmtqueue = kfifo_alloc(session->mgmtpool_max * sizeof(void*),
			                GFP_KERNEL, NULL);
	if (conn->mgmtqueue == ERR_PTR(-ENOMEM))
		goto mgmtqueue_alloc_fail;

	INIT_WORK(&conn->xmitwork, iscsi_xmitworker, conn);

	/* allocate login_mtask used for the login/text sequences */
	spin_lock_bh(&session->lock);
	if (!__kfifo_get(session->mgmtpool.queue,
                         (void*)&conn->login_mtask,
			 sizeof(void*))) {
		spin_unlock_bh(&session->lock);
		goto login_mtask_alloc_fail;
	}
	spin_unlock_bh(&session->lock);

	/* allocate initial PDU receive place holder */
	if (conn->data_size <= PAGE_SIZE)
		conn->data = kmalloc(conn->data_size, GFP_KERNEL);
	else
		conn->data = (void*)__get_free_pages(GFP_KERNEL,
					get_order(conn->data_size));
	if (!conn->data)
		goto max_recv_dlenght_alloc_fail;

	init_timer(&conn->tmabort_timer);
	init_MUTEX(&conn->xmitsema);
	init_waitqueue_head(&conn->ehwait);

	return iscsi_handle(conn);

max_recv_dlenght_alloc_fail:
	spin_lock_bh(&session->lock);
	__kfifo_put(session->mgmtpool.queue, (void*)&conn->login_mtask,
		    sizeof(void*));
	spin_unlock_bh(&session->lock);
login_mtask_alloc_fail:
	kfifo_free(conn->mgmtqueue);
mgmtqueue_alloc_fail:
	kfifo_free(conn->immqueue);
immqueue_alloc_fail:
	kfifo_free(conn->writequeue);
writequeue_alloc_fail:
	kfifo_free(conn->xmitqueue);
xmitqueue_alloc_fail:
	kfree(conn);
conn_alloc_fail:
	return iscsi_handle(NULL);
}

/*
 * Terminate connection queues, free all associated resources.
 */
static void
iscsi_conn_destroy(iscsi_cnx_t cnxh)
{
	struct iscsi_conn *conn = iscsi_ptr(cnxh);
	struct iscsi_session *session = conn->session;

	if (conn->c_stage == ISCSI_CNX_INITIAL_STAGE) {
		/*
		 * conn_start() was never been called!
		 * we must cleanup socket.
		 */
		sock_hold(conn->sock->sk);
		iscsi_conn_restore_callbacks(conn);
		sock_put(conn->sock->sk);
		sock_release(conn->sock);
	}

	del_timer_sync(&conn->tmabort_timer);
	if (session->leadconn == conn) {
		/*
		 * Control plane decided to destroy leading connection?
		 * Its a signal for us to give up on recovery.
		 */
		session->state = ISCSI_STATE_TERMINATE;
		wake_up(&conn->ehwait);
	}

	/*
	 * Block control plane caller (a thread coming from
	 * a user space) until all the in-progress commands for this connection
	 * time out or fail.
	 * We must serialize with xmitwork recv pathes.
	 */
	down(&conn->xmitsema);
	conn->c_stage = ISCSI_CNX_CLEANUP_WAIT;
	for (;;) {
		spin_lock_bh(&conn->lock);
		if (!session->host->host_busy) { /* OK for ERL == 0 */
			spin_unlock_bh(&conn->lock);
			break;
		}
		spin_unlock_bh(&conn->lock);
		msleep_interruptible(500);
		debug_scsi("destroy_cnx(): host_busy %d host_failed %d\n",
			   session->host->host_busy,
			   session->host->host_failed);
	}
	up(&conn->xmitsema);

	/* now free crypto */
	if (conn->hdrdgst_en || conn->datadgst_en) {
		if (conn->tx_tfm)
			crypto_free_tfm(conn->tx_tfm);
		if (conn->rx_tfm)
			crypto_free_tfm(conn->rx_tfm);
	}

	/* free conn->data, size = MaxRecvDataSegmentLength */
	if (conn->data_size <= PAGE_SIZE)
		kfree(conn->data);
	else
		free_pages((unsigned long)conn->data,
					get_order(conn->data_size));

	spin_lock_bh(&session->lock);
	__kfifo_put(session->mgmtpool.queue, (void*)&conn->login_mtask,
		    sizeof(void*));
	spin_unlock_bh(&session->lock);

	kfifo_free(conn->xmitqueue);
	kfifo_free(conn->writequeue);
	kfifo_free(conn->immqueue);
	kfifo_free(conn->mgmtqueue);

	spin_lock_bh(&session->conn_lock);
	list_del(&conn->item);
	if (list_empty(&session->connections))
		session->leadconn = NULL;
	if (session->leadconn && session->leadconn == conn)
		session->leadconn = container_of(session->connections.next,
			struct iscsi_conn, item);
	spin_unlock_bh(&session->conn_lock);

	if (session->leadconn == NULL)
		/* non connections exits.. reset sequencing */
		session->cmdsn = session->max_cmdsn = session->exp_cmdsn = 1;

	kfree(conn);
}

static int
iscsi_conn_bind(iscsi_snx_t snxh, iscsi_cnx_t cnxh, uint32_t transport_fd,
		int is_leading)
{
	struct iscsi_session *session = iscsi_ptr(snxh);
	struct iscsi_conn *cnx = ERR_PTR(-EEXIST), *conn = iscsi_ptr(cnxh);
	struct sock *sk;
	struct socket *sock;
	int err;

	/* lookup for existing socket */
	if (!(sock = sockfd_lookup(transport_fd, &err))) {
		printk("iscsi_tcp: sockfd_lookup failed %d\n", err);
		return -EEXIST;
	}

	/* lookup for existing connection */
	spin_lock_bh(&session->conn_lock);
	list_for_each_entry(cnx, &session->connections, item) {
		if (cnx == conn) {
			if (conn->c_stage != ISCSI_CNX_STOPPED ||
			    conn->stop_stage == STOP_CNX_TERM) {
				printk("iscsi_tcp: can't bind non-stopped "
				       "connection (%d:%d)\n", conn->c_stage,
				       conn->stop_stage);
				spin_unlock_bh(&session->conn_lock);
				return -EIO;
			}
			break;
		}
	}
	spin_unlock_bh(&session->conn_lock);
	if (cnx != conn) {
		/* bind new iSCSI connection to session */
		conn->session = session;

		spin_lock_bh(&session->conn_lock);
		list_add(&conn->item, &session->connections);
		spin_unlock_bh(&session->conn_lock);
	}

	if (conn->stop_stage != STOP_CNX_SUSPEND) {
		/* bind iSCSI connection and socket */
		conn->sock = sock;

		/* setup Socket parameters */
		sk = sock->sk;
		sk->sk_reuse = 1;
		sk->sk_sndtimeo = 15 * HZ; /* FIXME: make it configurable */
		sk->sk_allocation = GFP_ATOMIC;

		/* FIXME: disable Nagle's algorithm */

		/*
		 * Intercept TCP callbacks for sendfile like receive
		 * processing.
		 */
		iscsi_conn_set_callbacks(conn);
	}

	if (is_leading)
		session->leadconn = conn;

	/*
	 * Unblock xmitworker().
	 * Login Phase will pass through.
	 */
	conn->suspend = 0;

	return 0;
}

static int
iscsi_conn_start(iscsi_cnx_t cnxh)
{
	struct iscsi_conn *conn = iscsi_ptr(cnxh);
	struct iscsi_session *session = conn->session;

	/* FF phase warming up... */

	if (session == NULL) {
		printk("iscsi_tcp: can't start not-binded connection\n");
		return -EPERM;
	}

	spin_lock_bh(&session->lock);
	conn->c_stage = ISCSI_CNX_STARTED;
	conn->cpu = session->conn_cnt % num_online_cpus();
	session->state = ISCSI_STATE_LOGGED_IN;
	session->conn_cnt++;

	if (conn->stop_stage == STOP_CNX_RECOVER) {
		/*
		 * unblock eh_abort() if it is blocked. re-try all
		 * commands after successful recovery
		 */
		conn->stop_stage = 0;
		session->generation++;
		wake_up(&conn->ehwait);
	} else
		conn->stop_stage = 0;
	spin_unlock_bh(&session->lock);

	return 0;
}

static void
iscsi_conn_stop(iscsi_cnx_t cnxh, int flag)
{
	struct iscsi_conn *conn = iscsi_ptr(cnxh);
	struct iscsi_session *session = conn->session;

	conn->stop_stage = flag;

	spin_lock_bh(&session->lock);
	conn->c_stage = ISCSI_CNX_STOPPED;
	session->conn_cnt--;
	conn->suspend = 1;

	if (session->conn_cnt == 0 || session->leadconn == conn)
		session->state = ISCSI_STATE_FAILED;

	spin_unlock_bh(&session->lock);

	if (flag == STOP_CNX_TERM || flag == STOP_CNX_RECOVER) {
		BUG_ON(!conn->sock);

		/*
		 * Socket must go now.
		 */
		sock_hold(conn->sock->sk);
		iscsi_conn_restore_callbacks(conn);
		sock_put(conn->sock->sk);

		/*
		 * flush xmit queues.
		 */
		down(&conn->xmitsema);
		spin_lock_bh(&session->lock);
		while (__kfifo_get(conn->writequeue, (void*)&conn->ctask,
			    sizeof(void*)) ||
			__kfifo_get(conn->xmitqueue, (void*)&conn->ctask,
			    sizeof(void*))) {
			__kfifo_put(session->cmdpool.queue, (void*)&conn->ctask,
				    sizeof(void*));
		}
		conn->ctask = NULL;
		while (__kfifo_get(conn->immqueue, (void*)&conn->mtask,
			   sizeof(void*)) ||
			__kfifo_get(conn->mgmtqueue, (void*)&conn->mtask,
			   sizeof(void*))) {
			__kfifo_put(session->mgmtpool.queue,
				    (void*)&conn->mtask, sizeof(void*));
		}
		spin_unlock_bh(&session->lock);
		conn->mtask = NULL;
		up(&conn->xmitsema);

		/*
		 * release socket only after we stopped data_xmit()
		 * activity and flushed all outstandings
		 */
		sock_release(conn->sock);

		/*
		 * for connection level recovery we should not calculate
		 * header digest. conn->hdr_size used for optimization
		 * in hdr_extract() and will be re-negotiated at
		 * set_param() time.
		 */
		if (flag == STOP_CNX_RECOVER)
			conn->hdr_size = sizeof(struct iscsi_hdr);
	}
}

static int
iscsi_conn_send_pdu(iscsi_cnx_t cnxh, struct iscsi_hdr *hdr, char *data,
		  uint32_t data_size)
{
	struct iscsi_conn *conn = iscsi_ptr(cnxh);
	struct iscsi_session *session = conn->session;
	struct iscsi_nopout *nop = (struct iscsi_nopout *)hdr;
	struct iscsi_mgmt_task *mtask;

	spin_lock_bh(&session->lock);
	if (hdr->opcode == (ISCSI_OP_LOGIN | ISCSI_OP_IMMEDIATE) ||
	    hdr->opcode == (ISCSI_OP_TEXT | ISCSI_OP_IMMEDIATE)) {
		/*
		 * Login and Text are sent serially, in
		 * request-followed-by-response sequence.
		 * Same mtask can be used. Same ITT must be used.
		 * Note that login_mtask is preallocated at cnx_create().
		 */
		mtask = conn->login_mtask;
	} else {
	        BUG_ON(conn->c_stage == ISCSI_CNX_INITIAL_STAGE);
	        BUG_ON(conn->c_stage == ISCSI_CNX_STOPPED);

		if (!__kfifo_get(session->mgmtpool.queue,
				 (void*)&mtask, sizeof(void*))) {
			spin_unlock_bh(&session->lock);
			return -ENOSPC;
		}
	}

	/*
	 * pre-format CmdSN and ExpStatSN for outgoing PDU.
	 */
	if (hdr->itt != cpu_to_be32(ISCSI_RESERVED_TAG)) {
		hdr->itt = cpu_to_be32(mtask->itt);
		nop->cmdsn = cpu_to_be32(session->cmdsn);
		if (conn->c_stage == ISCSI_CNX_STARTED)
			session->cmdsn++;
	} else {
		/* do not advance CmdSN */
		nop->cmdsn = cpu_to_be32(session->cmdsn);
	}

	nop->exp_statsn = cpu_to_be32(conn->exp_statsn);

	memcpy(&mtask->hdr, hdr, sizeof(struct iscsi_hdr));

	if (conn->c_stage == ISCSI_CNX_INITIAL_STAGE ||
	    conn->stop_stage == STOP_CNX_RECOVER) {
		iscsi_buf_init_virt(&mtask->headbuf, (char*)&mtask->hdr,
				    sizeof(struct iscsi_hdr));
	} else {
		/* this will update header digest */
		iscsi_buf_init_hdr(conn, &mtask->headbuf, (char*)&mtask->hdr,
				    (u8 *)mtask->hdrext);
	}
	spin_unlock_bh(&session->lock);

	if (data_size) {
		memcpy(mtask->data, data, data_size);
		mtask->data_count = data_size;
	} else
		mtask->data_count = 0;

	mtask->xmstate = XMSTATE_IMM_HDR;

	if (mtask->data_count) {
		iscsi_buf_init_virt(&mtask->sendbuf, (char*)mtask->data,
				    mtask->data_count);
		/* FIXME: implement: convertion of mtask->data into 1st
		 *        mtask->sendbuf. Keep in mind that virtual buffer
		 *        could be spreaded across multiple pages... */
		if(mtask->sendbuf.sg.offset + mtask->data_count > PAGE_SIZE) {
			if (conn->c_stage == ISCSI_CNX_STARTED) {
				spin_lock_bh(&session->lock);
				__kfifo_put(session->mgmtpool.queue,
					    (void*)&mtask, sizeof(void*));
				spin_unlock_bh(&session->lock);
			}
			return -ENOMEM;
		}
	}

	debug_scsi("mgmtpdu [op 0x%x itt 0x%x datalen %d]\n",
		   hdr->opcode, be32_to_cpu(hdr->itt), data_size);

        if (hdr->opcode & ISCSI_OP_IMMEDIATE)
	        __kfifo_put(conn->immqueue, (void*)&mtask, sizeof(void*));
	else
	        __kfifo_put(conn->mgmtqueue, (void*)&mtask, sizeof(void*));

	schedule_work(&conn->xmitwork);

	return 0;
}

static void
iscsi_tmabort_timedout(unsigned long data)
{
	struct iscsi_cmd_task *ctask = (struct iscsi_cmd_task *)data;
	struct iscsi_conn *conn = ctask->conn;

	conn->tmabort_state = TMABORT_TIMEDOUT;
	debug_scsi("tmabort timedout [sc %lx itt 0x%x]\n", (long)ctask->sc,
		   ctask->itt);

	/* unblock eh_abort() */
	wake_up(&conn->ehwait);
}

static int
iscsi_eh_abort(struct scsi_cmnd *sc)
{
	int rc;
	struct iscsi_cmd_task *ctask = (struct iscsi_cmd_task *)sc->SCp.ptr;
	struct iscsi_conn *conn = ctask->conn;
	struct iscsi_session *session = conn->session;

	spin_unlock_irq(session->host->host_lock);

	debug_scsi("aborting [sc %lx itt 0x%x]\n", (long)sc, ctask->itt);

	/*
	 * two cases for ERL=0 here:
	 *
	 * 1) connection-level failure;
	 * 2) recovery due protocol error;
	 */
	if (session->state != ISCSI_STATE_LOGGED_IN) {
		if (session->state == ISCSI_STATE_TERMINATE)
			goto failed;
	} else {
		struct iscsi_tm *hdr = &conn->tmhdr;

		/*
		 * Still LOGGED_IN...
		 */

		spin_lock_bh(&session->lock);
		if (sc->SCp.Status == SUCCESS ||
		    sc->SCp.phase != session->generation) {
			/*
			 * 1) ctask completed before time out. But session
			 *    is still ok => Happy Retry.
			 * 2) session was re-open during time out of ctask.
			 */
			spin_unlock_bh(&session->lock);
			goto success;
		}
		spin_unlock_bh(&session->lock);

		/*
		 * ctask timed out but session is OK
		 * ERL=0 requires task mgmt abort to be issued on each
		 * failed command. requests must be serialized.
		 */
		memset(hdr, 0, sizeof(struct iscsi_tm));
		hdr->opcode = ISCSI_OP_SCSI_TMFUNC | ISCSI_OP_IMMEDIATE;
		hdr->flags = ISCSI_TM_FUNC_ABORT_TASK;
		hdr->flags |= ISCSI_FLAG_CMD_FINAL;
		memcpy(hdr->lun, ctask->hdr.lun, 8);
		hdr->rtt = ctask->hdr.itt;
		hdr->refcmdsn = ctask->hdr.cmdsn;

		conn->tmabort_state = TMABORT_INITIAL;

		rc = iscsi_conn_send_pdu(iscsi_handle(conn),
			    (struct iscsi_hdr *)hdr, NULL, 0);
		if (rc) {
			session->state = ISCSI_STATE_FAILED;
			iscsi_cnx_error(iscsi_handle(conn),
					ISCSI_ERR_CNX_FAILED);
			debug_scsi("abort sent failure [itt 0x%x]", ctask->itt);
		} else {
			conn->tmfcmd_pdus_cnt++;
			conn->tmabort_timer.expires = 3*HZ + jiffies; /*3 secs*/
			conn->tmabort_timer.function = iscsi_tmabort_timedout;
			conn->tmabort_timer.data = (unsigned long)ctask;
			add_timer(&conn->tmabort_timer);
			debug_scsi("abort sent [itt 0x%x]", ctask->itt);
		}
	}


	/*
	 * block eh thread until:
	 *
	 * 1) abort response;
	 * 2) abort timeout;
	 * 3) session re-opened;
	 * 4) session terminated;
	 */
	for (;;) {
		int p_state = session->state;
		rc = wait_event_interruptible(conn->ehwait,
			(p_state == ISCSI_STATE_LOGGED_IN ?
			 (session->state == ISCSI_STATE_TERMINATE ||
			  conn->tmabort_state != TMABORT_INITIAL) :
			 (session->state == ISCSI_STATE_TERMINATE ||
			  session->state == ISCSI_STATE_LOGGED_IN)));
		if (rc) {
			/* shutdown.. */
			session->state = ISCSI_STATE_TERMINATE;
			goto failed;
		}

		if (signal_pending(current))
			flush_signals(current);

		if (session->state == ISCSI_STATE_TERMINATE)
			goto failed;

		if (conn->tmabort_state == TMABORT_TIMEDOUT ||
		    conn->tmabort_state == TMABORT_FAILED) {
			conn->tmabort_state = TMABORT_INITIAL;
			spin_lock_bh(&session->lock);
			if (sc->SCp.Status == SUCCESS) {
				/*
				 * ctask completed before tmf abort response or
				 * time out.
				 * But session is still ok => Happy Retry.
				 */
				spin_unlock_bh(&session->lock);
				break;
			}
			spin_unlock_bh(&session->lock);
			session->state = ISCSI_STATE_FAILED;
			iscsi_cnx_error(iscsi_handle(conn),
					ISCSI_ERR_CNX_FAILED);
			continue;
		}

		break;
	}

success:
	debug_scsi("abort success [sc %lx itt 0x%x]\n", (long)sc, ctask->itt);
	BUG_ON(session->state != ISCSI_STATE_LOGGED_IN);
	spin_lock_irq(session->host->host_lock);
	return SUCCESS;
failed:
	iscsi_ctask_cleanup(conn, ctask);
	debug_scsi("abort failed [sc %lx itt 0x%x]\n", (long)sc, ctask->itt);
	spin_lock_irq(session->host->host_lock);
	return FAILED;
}

static int
iscsi_r2tpool_alloc(struct iscsi_session *session)
{
	int i;
	int cmd_i;

	/*
	 * initialize per-task: R2T pool and xmit queue
	 */
	for (cmd_i = 0; cmd_i < session->cmds_max; cmd_i++) {
	        struct iscsi_cmd_task *ctask = session->cmds[cmd_i];

		/*
		 * pre-allocated twice as much r2ts to handle race when
		 * target acks DataOut faster than we data_xmit() queues
		 * could replenish r2tqueue.
		 */

		/* R2T pool */
		if (iscsi_pool_init(&ctask->r2tpool, session->max_r2t * 2,
			(void***)&ctask->r2ts, sizeof(struct iscsi_r2t_info))) {
			goto r2t_alloc_fail;
		}

		/* R2T xmit queue */
		ctask->r2tqueue = kfifo_alloc(
		      session->max_r2t * 2 * sizeof(void*), GFP_KERNEL, NULL);
		if (ctask->r2tqueue == ERR_PTR(-ENOMEM)) {
			iscsi_pool_free(&ctask->r2tpool, (void**)ctask->r2ts);
			goto r2t_alloc_fail;
		}

		/*
		 * number of
		 * Data-Out PDU's within R2T-sequence can be quite big;
		 * using mempool
		 */
		ctask->datapool = mempool_create(ISCSI_DTASK_DEFAULT_MAX,
			 mempool_alloc_slab, mempool_free_slab, taskcache);
		if (ctask->datapool == NULL) {
			kfifo_free(ctask->r2tqueue);
			iscsi_pool_free(&ctask->r2tpool, (void**)ctask->r2ts);
			goto r2t_alloc_fail;
		}
		INIT_LIST_HEAD(&ctask->dataqueue);
	}

	return 0;

r2t_alloc_fail:
	for (i = 0; i < cmd_i; i++) {
		mempool_destroy(session->cmds[i]->datapool);
		kfifo_free(session->cmds[i]->r2tqueue);
		iscsi_pool_free(&session->cmds[i]->r2tpool,
				(void**)session->cmds[i]->r2ts);
	}
	return -ENOMEM;
}

static void
iscsi_r2tpool_free(struct iscsi_session *session)
{
	int i;

	for (i = 0; i < session->cmds_max; i++) {
		mempool_destroy(session->cmds[i]->datapool);
		kfifo_free(session->cmds[i]->r2tqueue);
		iscsi_pool_free(&session->cmds[i]->r2tpool,
				(void**)session->cmds[i]->r2ts);
	}
}

static struct scsi_host_template iscsi_sht = {
	.name			= "iSCSI Initiator over TCP/IP, v."
				  ISCSI_VERSION_STR,
        .queuecommand           = iscsi_queuecommand,
	.can_queue		= ISCSI_XMIT_CMDS_MAX - 1,
	.sg_tablesize		= ISCSI_SG_TABLESIZE,
	.cmd_per_lun		= ISCSI_CMD_PER_LUN,
        .eh_abort_handler       = iscsi_eh_abort,
        .use_clustering         = DISABLE_CLUSTERING,
	.proc_name		= "iscsi_tcp",
	.this_id		= -1,
};

static iscsi_snx_t
iscsi_session_create(uint32_t initial_cmdsn, struct Scsi_Host *host)
{
	int cmd_i;
	struct iscsi_session *session;

	session = iscsi_hostdata(host->hostdata);
	memset(session, 0, sizeof(struct iscsi_session));

	session->host = host;
	session->id = host->host_no;
	session->state = ISCSI_STATE_LOGGED_IN;
	session->mgmtpool_max = ISCSI_MGMT_CMDS_MAX;
	session->cmds_max = ISCSI_XMIT_CMDS_MAX;
	session->cmdsn = initial_cmdsn;
	session->exp_cmdsn = initial_cmdsn + 1;
	session->max_cmdsn = initial_cmdsn + 1;
	session->max_r2t = 1;

	/* initialize SCSI PDU commands pool */
	if (iscsi_pool_init(&session->cmdpool, session->cmds_max,
		(void***)&session->cmds, sizeof(struct iscsi_cmd_task)))
		goto cmdpool_alloc_fail;

	/* pre-format cmds pool with ITT */
	for (cmd_i = 0; cmd_i < session->cmds_max; cmd_i++) {
		session->cmds[cmd_i]->itt = cmd_i;
	}

	spin_lock_init(&session->lock);
	spin_lock_init(&session->conn_lock);
	INIT_LIST_HEAD(&session->connections);

	/* initialize immediate command pool */
	if (iscsi_pool_init(&session->mgmtpool, session->mgmtpool_max,
		(void***)&session->mgmt_cmds, sizeof(struct iscsi_mgmt_task)))
		goto mgmtpool_alloc_fail;


	/* pre-format immediate cmds pool with ITT */
	for (cmd_i = 0; cmd_i < session->mgmtpool_max; cmd_i++) {
		session->mgmt_cmds[cmd_i]->itt = ISCSI_MGMT_ITT_OFFSET + cmd_i;
		session->mgmt_cmds[cmd_i]->data = kmalloc(
			DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH, GFP_KERNEL);
		if (!session->mgmt_cmds[cmd_i]->data) {
			int j;
			for (j = 0; j < cmd_i; j++)
				kfree(session->mgmt_cmds[j]->data);
			goto immdata_alloc_fail;
		}
	}

	if (iscsi_r2tpool_alloc(session))
		goto r2tpool_alloc_fail;

	if (!try_module_get(THIS_MODULE)) {
		printk("iscsi_tcp: can not reserve module\n");
		goto module_get_fault;
	}

	return iscsi_handle(session);

module_get_fault:
	iscsi_r2tpool_free(session);
r2tpool_alloc_fail:
	for (cmd_i = 0; cmd_i < session->mgmtpool_max; cmd_i++)
		kfree(session->mgmt_cmds[cmd_i]->data);
	iscsi_pool_free(&session->mgmtpool, (void**)session->mgmt_cmds);
immdata_alloc_fail:
mgmtpool_alloc_fail:
	iscsi_pool_free(&session->cmdpool, (void**)session->cmds);
cmdpool_alloc_fail:
	return iscsi_handle(NULL);
}

static void
iscsi_session_destroy(iscsi_snx_t snxh)
{
	int cmd_i;
	struct iscsi_data_task *dtask, *n;
	struct iscsi_session *session = iscsi_ptr(snxh);

	for (cmd_i = 0; cmd_i < session->cmds_max; cmd_i++) {
		struct iscsi_cmd_task *ctask = session->cmds[cmd_i];
		list_for_each_entry_safe(dtask, n, &ctask->dataqueue, item) {
			list_del(&dtask->item);
			mempool_free(dtask, ctask->datapool);
		}
	}

	for (cmd_i = 0; cmd_i < session->mgmtpool_max; cmd_i++)
		kfree(session->mgmt_cmds[cmd_i]->data);

	iscsi_r2tpool_free(session);
	iscsi_pool_free(&session->mgmtpool, (void**)session->mgmt_cmds);
	iscsi_pool_free(&session->cmdpool, (void**)session->cmds);
	module_put(THIS_MODULE);
}

static int
iscsi_conn_set_param(iscsi_cnx_t cnxh, enum iscsi_param param, uint32_t value)
{
	struct iscsi_conn *conn = iscsi_ptr(cnxh);
	struct iscsi_session *session = conn->session;

	if (conn->c_stage == ISCSI_CNX_INITIAL_STAGE ||
	    conn->stop_stage == STOP_CNX_RECOVER) {
		switch(param) {
		case ISCSI_PARAM_MAX_RECV_DLENGTH: {
			char *saveptr = conn->data;
			int flags = GFP_KERNEL;

			if (conn->data_size >= value) {
				conn->max_recv_dlength = value;
				break;
			}

			if (conn->stop_stage == STOP_CNX_RECOVER)
				flags = GFP_ATOMIC;

			if (value <= PAGE_SIZE)
				conn->data = kmalloc(value, flags);
			else
				conn->data = (void*)__get_free_pages(flags,
					get_order(value));
			if (conn->data == NULL) {
				conn->data = saveptr;
				return -ENOMEM;
			}
			if (conn->data_size <= PAGE_SIZE)
				kfree(saveptr);
			else
				free_pages((unsigned long)saveptr,
					get_order(conn->data_size));
			conn->max_recv_dlength = value;
			conn->data_size = value;
		}
		break;
		case ISCSI_PARAM_MAX_XMIT_DLENGTH:
			conn->max_xmit_dlength =  value;
			break;
		case ISCSI_PARAM_HDRDGST_EN:
			conn->hdrdgst_en = value;
			conn->hdr_size = sizeof(struct iscsi_hdr);
			if (conn->hdrdgst_en) {
				conn->hdr_size += sizeof(__u32);
				if (!conn->tx_tfm)
					conn->tx_tfm =
						crypto_alloc_tfm("crc32c", 0);
				if (!conn->tx_tfm)
					return -ENOMEM;
				if (!conn->rx_tfm)
					conn->rx_tfm =
						crypto_alloc_tfm("crc32c", 0);
				if (!conn->rx_tfm) {
					crypto_free_tfm(conn->tx_tfm);
					return -ENOMEM;
				}
			} else {
				if (conn->tx_tfm)
					crypto_free_tfm(conn->tx_tfm);
				if (conn->rx_tfm)
					crypto_free_tfm(conn->rx_tfm);
			}
			break;
		case ISCSI_PARAM_DATADGST_EN:
			if (conn->datadgst_en)
				return -EPERM;
			conn->datadgst_en = value;
			break;
		case ISCSI_PARAM_INITIAL_R2T_EN:
			session->initial_r2t_en = value;
			break;
		case ISCSI_PARAM_MAX_R2T:
			if (session->max_r2t == roundup_pow_of_two(value))
				break;
			iscsi_r2tpool_free(session);
			session->max_r2t = value;
			if (session->max_r2t & (session->max_r2t - 1)) {
				session->max_r2t =
					roundup_pow_of_two(session->max_r2t);
			}
			if (iscsi_r2tpool_alloc(session))
				return -ENOMEM;
			break;
		case ISCSI_PARAM_IMM_DATA_EN:
			session->imm_data_en = value;
			break;
		case ISCSI_PARAM_FIRST_BURST:
			session->first_burst = value;
			break;
		case ISCSI_PARAM_MAX_BURST:
			session->max_burst = value;
			break;
		case ISCSI_PARAM_PDU_INORDER_EN:
			session->pdu_inorder_en = value;
			break;
		case ISCSI_PARAM_DATASEQ_INORDER_EN:
			session->dataseq_inorder_en = value;
			break;
		case ISCSI_PARAM_ERL:
			session->erl = value;
			break;
		case ISCSI_PARAM_IFMARKER_EN:
			session->ifmarker_en = value;
			break;
		case ISCSI_PARAM_OFMARKER_EN:
			session->ifmarker_en = value;
			break;
		default:
			break;
		}
	} else {
		printk("iscsi_tcp: can not change parameter [%d]\n", param);
	}

	return 0;
}

static int
iscsi_conn_get_param(iscsi_cnx_t cnxh, enum iscsi_param param, uint32_t *value)
{
	struct iscsi_conn *conn = iscsi_ptr(cnxh);
	struct iscsi_session *session = conn->session;

	switch(param) {
	case ISCSI_PARAM_MAX_RECV_DLENGTH:
		*value = conn->max_recv_dlength;
		break;
	case ISCSI_PARAM_MAX_XMIT_DLENGTH:
		*value = conn->max_xmit_dlength;
		break;
	case ISCSI_PARAM_HDRDGST_EN:
		*value = conn->hdrdgst_en;
		break;
	case ISCSI_PARAM_DATADGST_EN:
		*value = conn->datadgst_en;
		break;
	case ISCSI_PARAM_INITIAL_R2T_EN:
		*value = session->initial_r2t_en;
		break;
	case ISCSI_PARAM_MAX_R2T:
		*value = session->max_r2t;
		break;
	case ISCSI_PARAM_IMM_DATA_EN:
		*value = session->imm_data_en;
		break;
	case ISCSI_PARAM_FIRST_BURST:
		*value = session->first_burst;
		break;
	case ISCSI_PARAM_MAX_BURST:
		*value = session->max_burst;
		break;
	case ISCSI_PARAM_PDU_INORDER_EN:
		*value = session->pdu_inorder_en;
		break;
	case ISCSI_PARAM_DATASEQ_INORDER_EN:
		*value = session->dataseq_inorder_en;
		break;
	case ISCSI_PARAM_ERL:
		*value = session->erl;
		break;
	case ISCSI_PARAM_IFMARKER_EN:
		*value = session->ifmarker_en;
		break;
	case ISCSI_PARAM_OFMARKER_EN:
		*value = session->ifmarker_en;
		break;
	default:
		return ISCSI_ERR_PARAM_NOT_FOUND;
	}

	return 0;
}

static void
iscsi_conn_get_stats(iscsi_cnx_t cnxh, struct iscsi_stats *stats)
{
	struct iscsi_conn *conn = iscsi_ptr(cnxh);

	stats->txdata_octets = conn->txdata_octets;
	stats->rxdata_octets = conn->rxdata_octets;
	stats->scsicmd_pdus = conn->scsicmd_pdus_cnt;
	stats->dataout_pdus = conn->dataout_pdus_cnt;
	stats->scsirsp_pdus = conn->scsirsp_pdus_cnt;
	stats->datain_pdus = conn->datain_pdus_cnt;
	stats->r2t_pdus = conn->r2t_pdus_cnt;
	stats->tmfcmd_pdus = conn->tmfcmd_pdus_cnt;
	stats->tmfrsp_pdus = conn->tmfrsp_pdus_cnt;
	stats->custom_length = 2;
	strcpy(stats->custom[0].desc, "tx_sendpage_failures");
	stats->custom[0].value = conn->sendpage_failures_cnt;
	strcpy(stats->custom[1].desc, "rx_discontiguous_hdr");
	stats->custom[1].value = conn->discontiguous_hdr_cnt;
}

static struct iscsi_transport iscsi_tcp_transport = {
	.owner			= THIS_MODULE,
	.name                   = "tcp",
	.caps                   = CAP_RECOVERY_L0 | CAP_MULTI_R2T | CAP_HDRDGST,
	.host_template		= &iscsi_sht,
	.hostdata_size		= sizeof(struct iscsi_session),
	.max_lun		= ISCSI_TCP_MAX_LUN,
	.max_cmd_len		= ISCSI_TCP_MAX_CMD_LEN,
	.create_session         = iscsi_session_create,
	.destroy_session        = iscsi_session_destroy,
	.create_cnx             = iscsi_conn_create,
	.bind_cnx               = iscsi_conn_bind,
	.destroy_cnx            = iscsi_conn_destroy,
	.set_param              = iscsi_conn_set_param,
	.get_param              = iscsi_conn_get_param,
	.start_cnx              = iscsi_conn_start,
	.stop_cnx               = iscsi_conn_stop,
	.send_pdu               = iscsi_conn_send_pdu,
	.get_stats		= iscsi_conn_get_stats,
};

static int __init
iscsi_tcp_init(void)
{
	int error;

	taskcache = kmem_cache_create("iscsi_taskcache",
			sizeof(struct iscsi_data_task), 0,
			SLAB_HWCACHE_ALIGN | SLAB_NO_REAP, NULL, NULL);
	if (!taskcache)
		return -ENOMEM;

	error = iscsi_register_transport(&iscsi_tcp_transport);
	if (error)
		kmem_cache_destroy(taskcache);

	return error;
}

static void __exit
iscsi_tcp_exit(void)
{
	iscsi_unregister_transport(&iscsi_tcp_transport);
	kmem_cache_destroy(taskcache);
}

module_init(iscsi_tcp_init);
module_exit(iscsi_tcp_exit);
