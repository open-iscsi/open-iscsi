/*
 * iSCSI Initiator TCP Data-Path (IDP/TCP)
 * Copyright (C) 2004 Dmitry Yusupov, Alex Aizman
 * maintained by open-iscsi@@googlegroups.com
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

#include <iscsi_tcp.h>

MODULE_AUTHOR("Dmitry Yusupov <dmitry_yus@yahoo.com>, "
	      "Alex Aizman <itn780@yahoo.com>");
MODULE_DESCRIPTION("iSCSI/TCP data-path");
MODULE_LICENSE("GPL");

#define DEBUG_PREV_PDU
//#define DEBUG_TCP
//#define DEBUG_SCSI
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

#ifdef DEBUG_ASSERT
#define __BUG_ON BUG_ON
#else
#define __BUG_ON(expr)
#endif

/* global data */
static kmem_cache_t *taskcache;

/* socket management */
static int iscsi_tcp_data_recv(read_descriptor_t *rd_desc, struct sk_buff *skb,
			       unsigned int offset, size_t len);
static void iscsi_tcp_data_ready(struct sock *sk, int flag);
static void iscsi_tcp_state_change(struct sock *sk);
static void iscsi_write_space(struct sock *sk);
static void iscsi_conn_set_callbacks(iscsi_conn_t *conn);

/* data-path */
static int iscsi_hdr_extract(iscsi_conn_t *conn);
static int iscsi_hdr_recv(iscsi_conn_t *conn);
static int iscsi_data_recv(iscsi_conn_t *conn);
static void iscsi_cmd_init(iscsi_conn_t *conn, iscsi_cmd_task_t *ctask,
		     struct scsi_cmnd *sc);
static int iscsi_unsolicit_data_init(iscsi_conn_t *conn,
			iscsi_cmd_task_t *ctask);
static int iscsi_solicit_data_init(iscsi_conn_t *conn,
			iscsi_cmd_task_t *ctask, iscsi_r2t_info_t *r2t);
static int iscsi_solicit_data_cont(iscsi_conn_t *conn,
		iscsi_cmd_task_t *ctask, iscsi_r2t_info_t *r2t, int left);
static int iscsi_cmd_rsp(iscsi_conn_t *conn, iscsi_cmd_task_t *ctask);
static int iscsi_data_rsp(iscsi_conn_t *conn, iscsi_cmd_task_t *ctask);
static int iscsi_r2t_rsp(iscsi_conn_t *conn, iscsi_cmd_task_t *ctask);
static void iscsi_xmitworker(void *data);

/* page management */
static inline void iscsi_buf_init_virt(iscsi_buf_t *ibuf, char *vbuf, int size);
static inline void iscsi_buf_init_sg(iscsi_buf_t *ibuf, struct scatterlist *sg);

/* SCSI Midlayer glue */
static const char *iscsi_info(struct Scsi_Host *host);
static int iscsi_proc_info(struct Scsi_Host *host, char *buffer, char **start,
		off_t offset, int length,  int inout);


/******************************************************************************
 *                                                                            *
 *                              G E N E R I C                                 *
 *                     Q U E U E   M A N A G E M E N T                        *
 *                                                                            *
 ******************************************************************************/

/*
 * Insert before consumer pointer
 */
static void
__insert(iscsi_queue_t *queue, void *data)
{
	if (queue->cons - 1 < 0) {
		if (queue->max > 1)
			queue->cons = queue->max - 1;
		else {
			queue->cons = 1;
			queue->prod = 1;
		}
	}
	queue->pool[--queue->cons] = data;
}

static void
__enqueue(iscsi_queue_t *queue, void *data)
{
	if (queue->prod == queue->max) {
		queue->prod = 0;
	}
	__BUG_ON(queue->prod + 1 == queue->cons);
	queue->pool[queue->prod++] = data;
}

/*
 * Enqueue back to the queue using producer pointer
 */
static void
iscsi_enqueue(iscsi_queue_t *queue, void *data)
{
	spin_lock_bh(queue->lock);
	__enqueue(queue, data);
	spin_unlock_bh(queue->lock);
}

static void*
__dequeue(iscsi_queue_t *queue)
{
	void *data;

	if (queue->cons == queue->prod) {
		return NULL;
	}
	if (queue->cons == queue->max) {
		queue->cons = 0;
	}
	data = queue->pool[queue->cons];
	if (queue->max > 1)
		queue->cons++;
	else
		queue->prod = 0;
	return data;
}

/*
 * Dequeue from the queue using consumer pointer
 *
 * Returns void* or NULL on empty queue
 */
static void*
iscsi_dequeue(iscsi_queue_t *queue)
{
	void *data;

	spin_lock_bh(queue->lock);
	data = __dequeue(queue);
	spin_unlock_bh(queue->lock);

	return data;
}


/******************************************************************************
 *                                                                            *
 *                              T C P / I P                                   *
 *                     S O C K E T   M A N A G E M E N T                      *
 *                                                                            *
 ******************************************************************************/

#define iscsi_conn_get(rdd) (iscsi_conn_t*)(rdd)->arg.data
#define iscsi_conn_set(rdd, conn) (rdd)->arg.data = conn

/*
 * TCP record receive routine
 */
static int
iscsi_tcp_data_recv(read_descriptor_t *rd_desc, struct sk_buff *skb,
		unsigned int offset, size_t len)
{
	int rc;
	iscsi_conn_t *conn = iscsi_conn_get(rd_desc);
	int start = skb_headlen(skb);

	if ((conn->in.copy = start - offset) <= 0) {
		printk("iSCSI: in %d < 0!!!\n", conn->in.copy);
		__BUG_ON(1);
		return len;
	}
	debug_tcp("in %d bytes\n", conn->in.copy);

	/*
	 * Save current SKB and its offset in the corresponding
	 * connection context.
	 */
	conn->in.offset = offset;
	conn->in.skb = skb;
	conn->in.len = conn->in.copy;

more:
	conn->in.copied = 0;
	rc = 0;

	if (conn->in_progress == IN_PROGRESS_WAIT_HEADER ||
	    conn->in_progress == IN_PROGRESS_HEADER_GATHER) {
		/*
		 * Extract PDU Header. It will be Zero-Copy in most
		 * cases but in some cases it will be memcpy. For example
		 * when PDU Header will be scattered across SKB's.
		 */
		rc = iscsi_hdr_extract(conn);
		if (rc == -EAGAIN) {
			goto nomore;
		}

		/*
		 * Incomming PDU Header processing.
		 * At this stage we process only common parts, like ITT,
		 * DataSegmentLength, etc.
		 */
		rc = iscsi_hdr_recv(conn);
		if (!rc && conn->in.datalen) {
			conn->in_progress = IN_PROGRESS_DATA_RECV;
		} else if (rc) {
			/* FIXME: recover error */
			printk("iSCSI: bad hdr rc (%d)\n", rc);
			__BUG_ON(1);
			return 0;
		}
	}

	if (conn->in_progress == IN_PROGRESS_DATA_RECV &&
	    conn->in.copy) {

		debug_tcp("data_recv offset %d copy %d\n",
		       conn->in.offset, conn->in.copy);

		if ((rc = iscsi_data_recv(conn))) {
			if (rc == -EAGAIN) {
				rd_desc->count = conn->in.datalen -
							conn->in.ctask->sent;
				goto again;
			}
			/* FIXME: recover error */
			printk("iSCSI: bad data rc (%d)\n", rc);
			__BUG_ON(1);
			return 0;
		}
		conn->in.copy -= conn->in.padding;
		conn->in.offset += conn->in.padding;
		conn->in_progress = IN_PROGRESS_WAIT_HEADER;
	}

	debug_tcp("f, processed %d from out of %d padding %d\n",
	       conn->in.offset - offset, len, conn->in.padding);
	__BUG_ON(conn->in.offset - offset > len);

	if (conn->in.offset - offset != len) {
		debug_tcp("continue to process %d bytes\n",
		       len - (conn->in.offset - offset));
		goto more;
	}

nomore:
	__BUG_ON(conn->in.offset - offset == 0);
	return conn->in.offset - offset;

again:
	debug_tcp("c, processed %d from out of %d rd_desc_cnt %d\n",
	          conn->in.offset - offset, len, rd_desc->count);
	__BUG_ON(conn->in.offset - offset == 0);
	__BUG_ON(conn->in.offset - offset > len);

	return conn->in.offset - offset;
}

static void
iscsi_tcp_data_ready(struct sock *sk, int flag)
{
	iscsi_conn_t *conn = (iscsi_conn_t*)sk->sk_user_data;
	read_descriptor_t rd_desc;

	read_lock(&sk->sk_callback_lock);

	/* We use rd_desc to pass 'conn' to iscsi_tcp_data_recv */
	iscsi_conn_set(&rd_desc, conn);
	rd_desc.count = 0;
	tcp_read_sock(sk, &rd_desc, iscsi_tcp_data_recv);

	read_unlock(&sk->sk_callback_lock);
}

static void
iscsi_tcp_state_change(struct sock *sk)
{
	iscsi_conn_t *conn = (iscsi_conn_t*)sk->sk_user_data;
	iscsi_session_t *session = conn->session;
	unsigned long flags;

	if (sk->sk_state == TCP_CLOSE_WAIT ||
	    sk->sk_state == TCP_CLOSE) {
		debug_tcp("iscsi_tcp_state_change: TCP_CLOSE\n");
		spin_lock_irqsave(session->host->host_lock, flags);
		conn->c_stage = ISCSI_CNX_CLEANUP_WAIT;
		if (session->conn_cnt == 1 ||
		    session->leadconn == conn) {
			session->state = ISCSI_STATE_FAILED;
		}
		spin_unlock_irqrestore(session->host->host_lock, flags);
		iscsi_control_cnx_error(conn->handle, ISCSI_ERR_CNX_FAILED);
	}
	conn->old_state_change(sk);
}

/*
 * Called when more output buffer space is available for this socket.
 */
static void
iscsi_write_space(struct sock *sk)
{
	iscsi_conn_t *conn = (iscsi_conn_t*)sk->sk_user_data;
	conn->old_write_space(sk);
	debug_tcp("iscsi_write_space\n");
	conn->suspend = 0; wmb();
}

static void
iscsi_conn_set_callbacks(iscsi_conn_t *conn)
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
iscsi_conn_restore_callbacks(iscsi_conn_t *conn)
{
	struct sock *sk = conn->sock->sk;

	/* restore old callbacks */
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
 *
 * This function used for fast path send. Outgoing data presents
 * as iscsi_buf_t helper structure. This function is just light version
 * of iscsi_sendpage.
 */
static inline int
iscsi_sendhdr(iscsi_conn_t *conn, iscsi_buf_t *buf)
{
	struct socket *sk = conn->sock;
	int flags = MSG_DONTWAIT;
	int res, offset, size;

	offset = buf->sg.offset + buf->sent;
	size = buf->sg.length - buf->sent;
	__BUG_ON(buf->sent + size > buf->sg.length);
	if (buf->sent + size != buf->sg.length) {
		flags |= MSG_MORE;
	}

	// tcp_sendpage, do_tcp_sendpages, tcp_sendmsg
	res = sk->ops->sendpage(sk, buf->sg.page, offset, size, flags);
	debug_tcp("sendhdr %lx %d bytes at offset %d sent %d res %d\n",
		  (long)page_address(buf->sg.page), size, offset, buf->sent, res);
	if (res >= 0) {
		buf->sent += res;
		if (size != res) {
			return -EAGAIN;
		}
		return 0;
	} else if (res == -EAGAIN) {
		conn->suspend = 1;
	}

	return res;
}

/*
 * iscsi_sendpage - send one page of iSCSI Data-Out buffer
 *
 * This function used for fast path send. Outgoing data presents
 * as iscsi_buf_t helper structure.
 */
static inline int
iscsi_sendpage(iscsi_conn_t *conn, iscsi_buf_t *buf, int *count, int *sent)
{
	ssize_t (*sendpage)(struct socket *, struct page *, int, size_t, int);
	struct socket *sk = conn->sock;
	int flags = MSG_DONTWAIT;
	int res, offset, size;

	size = buf->sg.length - buf->sent;
	__BUG_ON(buf->sent + size > buf->sg.length);
	if (size > *count) {
		size = *count;
	}
	if (buf->sent + size != buf->sg.length) {
		flags |= MSG_MORE;
	}

	offset = buf->sg.offset + buf->sent;

	/* tcp_sendpage */
	sendpage = sk->ops->sendpage ? : sock_no_sendpage;

	/* Hmm... We might be dealing with highmem pages */
	if (PageHighMem(buf->page))
		sendpage = sock_no_sendpage;

	res = sendpage(sk, buf->sg.page, offset, size, flags);
	debug_tcp("sendpage %lx %d bytes, boff %d bsent %d "
		  "left %d sent %d res %d\n",
		  (long)page_address(buf->page), size, offset,
		  buf->sent, *count, *sent, res);
	if (res >= 0) {
		buf->sent += res;
		*count -= res;
		*sent += res;
		if (size != res) {
			return -EAGAIN;
		}
		return 0;
	} else if (res == -EAGAIN) {
		conn->suspend = 1;
	}

	return res;
}

/*
 * iscsi_tcp_copy - copy skb bits to the destanation buffer
 *
 * Function using iSCSI connection to keep copy counters and states.
 */
static inline int
iscsi_tcp_copy(iscsi_conn_t *conn, void *buf, int buf_size)
{
	int buf_left = buf_size - conn->data_copied;
	int size = min(conn->in.copy, buf_left);
	int rc;

	debug_tcp("tcp_copy %d bytes at offset %d copied %d\n",
	       size, conn->in.offset, conn->data_copied);

	rc = skb_copy_bits(conn->in.skb, conn->in.offset,
			   (char*)buf + conn->data_copied, size);
	__BUG_ON(rc);

	conn->in.offset += size;
	conn->in.copy -= size;
	conn->in.copied += size;
	conn->data_copied += size;

	if (buf_size != conn->data_copied) {
		return -EAGAIN;
	}

	return 0;
}

/*
 * iscsi_ctask_copy - copy skb bits to the destanation cmd task
 *
 * Function using iSCSI connection to keep copy counters and states.
 * In addition, cmd task keeps total "sent" counter across multiple Data-In's.
 */
static inline int
iscsi_ctask_copy(iscsi_conn_t *conn, iscsi_cmd_task_t *ctask,
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
	__BUG_ON(size <= 0);
	__BUG_ON(ctask->sent + size > ctask->total_length);

	debug_tcp("ctask_copy %d bytes at offset %d copied %d\n",
	       size, conn->in.offset, conn->in.copied);

	rc = skb_copy_bits(conn->in.skb, conn->in.offset,
			   (char*)buf + conn->data_copied, size);
	__BUG_ON(rc);

#ifdef DEBUG_PREV_PDU
	if (conn->in.opcode == ISCSI_OP_SCSI_DATA_IN) {
		memcpy(conn->data + (conn->in.datalen - ctask->data_count),
		       buf, size);
	}
#endif

	conn->in.offset += size;
	conn->in.copy -= size;
	conn->in.copied += size;
	conn->data_copied += size;
	ctask->sent += size;
	ctask->data_count -= size;

	__BUG_ON(conn->in.copy < 0);
	__BUG_ON(ctask->data_count < 0);

	if (buf_size != conn->data_copied) {
		if (!ctask->data_count) {
			__BUG_ON(buf_size - conn->data_copied < 0);
			/* done with this PDU */
			return buf_size - conn->data_copied;
		}
		return -EAGAIN;
	}

	/* done with this buffer or with both - PDU and buffer */
	conn->data_copied = 0;
	return 0;
}


/******************************************************************************
 *                                                                            *
 *                      i S C S I   D A T A - P A T H                         *
 *                                                                            *
 ******************************************************************************/

static inline void
iscsi_buf_init_virt(iscsi_buf_t *ibuf, char *vbuf, int size)
{
	ibuf->sg.page = virt_to_page(vbuf);
	ibuf->sg.offset = offset_in_page(vbuf);
	ibuf->sg.length = size;
	ibuf->sent = 0;
}

static inline void
iscsi_buf_init_sg(iscsi_buf_t *ibuf, struct scatterlist *sg)
{
	ibuf->sg.page = sg->page;
	ibuf->sg.offset = sg->offset;
	ibuf->sg.length = sg->length;
	ibuf->sent = 0;
}

static inline void
iscsi_buf_init_hdr(iscsi_conn_t *conn, iscsi_buf_t *ibuf, char *vbuf, u8 *crc)
{
	iscsi_buf_init_virt(ibuf, vbuf, sizeof(iscsi_hdr_t));
	if (conn->hdrdgst_en) {
		crypto_digest_init(conn->tx_tfm);
		crypto_digest_update(conn->tx_tfm, &ibuf->sg, 1);
		crypto_digest_final(conn->tx_tfm, crc);
		ibuf->sg.length += sizeof(uint32_t);
	}
}

/*
 * iscsi_solicit_data_cont - initialize next Data-Out
 *
 * Initialize next Data-Out within this R2T sequence and continue
 * to process next Scatter-Gather element(if any) of this SCSI command.
 *
 * This function called when connection lock taken.
 */
static int
iscsi_solicit_data_cont(iscsi_conn_t *conn, iscsi_cmd_task_t *ctask,
			iscsi_r2t_info_t *r2t, int left)
{
	iscsi_data_t *hdr;
	iscsi_data_task_t *dtask;
	struct scsi_cmnd *sc = ctask->sc;
	int new_offset;

	dtask = mempool_alloc(ctask->datapool, GFP_ATOMIC);
	if (dtask == NULL) {
		printk("iSCSI: datapool: out of memory itt 0x%x\n",
		       ctask->itt);
		return -ENOMEM;
	}
	hdr = &dtask->hdr;
	hdr->flags = 0;
	hdr->rsvd2[0] = hdr->rsvd2[1] = hdr->rsvd3 =
		hdr->rsvd4 = hdr->rsvd5 = hdr->rsvd6 = 0;
	hdr->ttt = r2t->ttt;
	hdr->datasn = htonl(r2t->solicit_datasn);
	r2t->solicit_datasn++;
	hdr->opcode = ISCSI_OP_SCSI_DATA_OUT;
	memset(hdr->lun, 0, 8);
	hdr->lun[1] = ctask->hdr.lun[1];
	hdr->itt = ctask->hdr.itt;
	hdr->exp_statsn = r2t->exp_statsn;
	new_offset = r2t->data_offset + r2t->sent;
	hdr->offset = htonl(new_offset);
	if (left > conn->max_xmit_dlength) {
		hton24(hdr->dlength, conn->max_xmit_dlength);
		r2t->data_count = conn->max_xmit_dlength;
	} else {
		hton24(hdr->dlength, left);
		r2t->data_count = left;
		hdr->flags = ISCSI_FLAG_CMD_FINAL;
	}

	iscsi_buf_init_hdr(conn, &r2t->headbuf, (char*)hdr,
			   (u8 *)dtask->hdrext);

	if (sc->use_sg) {
		__BUG_ON(ctask->bad_sg == r2t->sg);
		iscsi_buf_init_sg(&r2t->sendbuf, r2t->sg);
		r2t->sg += 1;
	} else {
		iscsi_buf_init_virt(&ctask->sendbuf,
			    (char*)sc->request_buffer + new_offset,
			    r2t->data_count);
	}

	list_add(&dtask->item, &ctask->dataqueue);
	return 0;
}

/*
 * iscsi_solicit_data_init - initialize first Data-Out
 *
 * Initialize first Data-Out within this R2T sequence and finds
 * proper data_offset within this SCSI command.
 *
 * This function called when connection lock taken.
 */
static int
iscsi_solicit_data_init(iscsi_conn_t *conn, iscsi_cmd_task_t *ctask,
			iscsi_r2t_info_t *r2t)
{
	iscsi_data_t *hdr;
	iscsi_data_task_t *dtask;
	struct scsi_cmnd *sc = ctask->sc;

	dtask = mempool_alloc(ctask->datapool, GFP_ATOMIC);
	if (dtask == NULL) {
		printk("iSCSI: datapool: out of memory itt 0x%x\n",
		       ctask->itt);
		return -ENOMEM;
	}
	hdr = &dtask->hdr;
	hdr->rsvd2[0] = hdr->rsvd2[1] = hdr->rsvd3 =
		hdr->rsvd4 = hdr->rsvd5 = hdr->rsvd6 = 0;
	hdr->ttt = r2t->ttt;
	hdr->datasn = htonl(r2t->solicit_datasn);
	r2t->solicit_datasn++;
	hdr->opcode = ISCSI_OP_SCSI_DATA_OUT;
	memset(hdr->lun, 0, 8);
	hdr->lun[1] = ctask->hdr.lun[1];
	hdr->itt = ctask->hdr.itt;
	hdr->exp_statsn = r2t->exp_statsn;
	hdr->offset = htonl(r2t->data_offset);
	if (r2t->data_length > conn->max_xmit_dlength) {
		hton24(hdr->dlength, conn->max_xmit_dlength);
		r2t->data_count = conn->max_xmit_dlength;
		hdr->flags = 0;
	} else {
		hton24(hdr->dlength, r2t->data_length);
		r2t->data_count = r2t->data_length;
		hdr->flags = ISCSI_FLAG_CMD_FINAL;
	}

	r2t->sent = 0;

	iscsi_buf_init_hdr(conn, &r2t->headbuf, (char*)hdr,
			   (u8 *)dtask->hdrext);

	if (sc->use_sg) {
		int i, sg_count = 0;
		struct scatterlist *sg = (struct scatterlist *)
			sc->request_buffer;
		r2t->sg = NULL;
		for (i=0; i<sc->use_sg; i++, sg += 1) { /* FIXME: prefetch ? */
			if (sg_count + sg->length > r2t->data_offset) {
				int page_offset = r2t->data_offset - sg_count;
				/* sg page found! */
				iscsi_buf_init_sg(&r2t->sendbuf, sg);
				r2t->sendbuf.sg.offset += page_offset;
				r2t->sendbuf.sg.length -= page_offset;
				r2t->sg = sg + 1;
				break;
			}
			sg_count += sg->length;
		}
		__BUG_ON(r2t->sg == NULL);
	} else {
		iscsi_buf_init_virt(&ctask->sendbuf,
			    (char*)sc->request_buffer + r2t->data_offset,
			    r2t->data_count);
	}

	list_add(&dtask->item, &ctask->dataqueue);
	return 0;
}

static int
iscsi_unsolicit_data_init(iscsi_conn_t *conn, iscsi_cmd_task_t *ctask)
{
	iscsi_data_t *hdr;
	iscsi_data_task_t *dtask;

	dtask = mempool_alloc(ctask->datapool, GFP_ATOMIC);
	if (dtask == NULL) {
		printk("iSCSI: datapool: out of memory itt 0x%x\n",
		       ctask->itt);
		return -ENOMEM;
	}
	hdr = &dtask->hdr;
	hdr->rsvd2[0] = hdr->rsvd2[1] = hdr->rsvd3 =
		hdr->rsvd4 = hdr->rsvd5 = hdr->rsvd6 = 0;
	hdr->ttt = ISCSI_RESERVED_TAG;
	hdr->datasn = htonl(ctask->unsolicit_datasn);
	ctask->unsolicit_datasn++;
	hdr->opcode = ISCSI_OP_SCSI_DATA_OUT;
	memset(hdr->lun, 0, 8);
	hdr->lun[1] = ctask->hdr.lun[1];
	hdr->itt = ctask->hdr.itt;
	hdr->exp_statsn = htonl(conn->exp_statsn);
	hdr->offset = htonl(ctask->total_length - ctask->r2t_data_count -
			    ctask->imm_data_count);
	if (ctask->imm_data_count > conn->max_xmit_dlength) {
		hton24(hdr->dlength, conn->max_xmit_dlength);
		ctask->data_count = conn->max_xmit_dlength;
		hdr->flags = 0;
	} else {
		hton24(hdr->dlength, ctask->imm_data_count);
		ctask->data_count = ctask->imm_data_count;
		hdr->flags = ISCSI_FLAG_CMD_FINAL;
	}

	iscsi_buf_init_hdr(conn, &ctask->headbuf, (char*)hdr,
			   (u8 *)dtask->hdrext);

	list_add(&dtask->item, &ctask->dataqueue);
	return 0;
}

/*
 * Initialize iSCSI SCSI_READ or SCSI_WRITE commands
 */
static void
iscsi_cmd_init(iscsi_conn_t *conn, iscsi_cmd_task_t *ctask,
		struct scsi_cmnd *sc)
{
	iscsi_session_t *session = conn->session;

	/*
	 * R2T's protected by the owner - connection.
	 */
	ctask->r2tpool.lock = &conn->lock;
	ctask->r2tqueue.lock = &conn->lock;

	ctask->sc = sc;
	ctask->conn = conn;
	ctask->hdr.opcode = ISCSI_OP_SCSI_CMD;
	ctask->hdr.flags = ISCSI_ATTR_SIMPLE;
	ctask->hdr.lun[1] = sc->device->lun;
	ctask->hdr.itt = htonl(ctask->itt);
	ctask->hdr.data_length = htonl(sc->request_bufflen);
	ctask->hdr.cmdsn = htonl(session->cmdsn); session->cmdsn++;
	ctask->hdr.exp_statsn = htonl(conn->exp_statsn);
	memcpy(ctask->hdr.cdb, sc->cmnd, sc->cmd_len);
	memset(&ctask->hdr.cdb[sc->cmd_len], 0, MAX_COMMAND_SIZE - sc->cmd_len);

	ctask->in_progress = IN_PROGRESS_IDLE;
	ctask->sent = 0;
	ctask->sg_count = 0;

	ctask->total_length = sc->request_bufflen;

	if (sc->sc_data_direction == DMA_FROM_DEVICE) {
		ctask->datasn = 0;
		ctask->hdr.flags |= ISCSI_FLAG_CMD_READ | ISCSI_FLAG_CMD_FINAL;
		ctask->in_progress = IN_PROGRESS_READ;
		zero_data(ctask->hdr.dlength);
	} else if (sc->sc_data_direction == DMA_TO_DEVICE) {
		ctask->exp_r2tsn = 0;
		ctask->hdr.flags |= ISCSI_FLAG_CMD_WRITE;
		ctask->in_progress = IN_PROGRESS_WRITE;
		/* TODO: check that zero-writes are allowed by spec. */
		__BUG_ON(ctask->total_length == 0);
		if (sc->use_sg) {
			struct scatterlist *sg = (struct scatterlist *)
							sc->request_buffer;
			iscsi_buf_init_sg(&ctask->sendbuf, &sg[0]);
			ctask->sg = sg + 1;
			ctask->bad_sg = sg + sc->use_sg;
		} else {
			iscsi_buf_init_virt(&ctask->sendbuf, sc->request_buffer,
					sc->request_bufflen);
			__BUG_ON(sc->request_bufflen > PAGE_SIZE);
		}

		/*
		 * Write counters:
		 *
		 *	imm_count	bytes to be sent right after
		 *			SCSI PDU Header
		 *
		 *	imm_data_count	bytes(as Data-Out) to be sent
		 *			without	R2T ack right after
		 *			immediate data
		 *
		 *	data_count	bytes to be sent via R2T ack's
		 */
		ctask->imm_count = 0;
		ctask->imm_data_count = 0;
		ctask->unsolicit_datasn = 0;
		if (session->imm_data_en) {
			if (ctask->total_length >= session->first_burst) {
				ctask->imm_count = min(session->first_burst,
							conn->max_xmit_dlength);
			} else {
				ctask->imm_count = min(ctask->total_length,
							conn->max_xmit_dlength);
			}
			hton24(ctask->hdr.dlength, ctask->imm_count);
			ctask->in_progress |= IN_PROGRESS_BEGIN_WRITE_IMM;
		} else {
			zero_data(ctask->hdr.dlength);
			ctask->in_progress |= IN_PROGRESS_BEGIN_WRITE;
		}
		if (!session->initial_r2t_en) {
			ctask->imm_data_count=min(session->first_burst,
				ctask->total_length) - ctask->imm_count;
		}
		if (!ctask->imm_data_count) {
			/* No unsolicit Data-Out's */
			ctask->hdr.flags |= ISCSI_FLAG_CMD_FINAL;
		}
		ctask->r2t_data_count = ctask->total_length -
				    ctask->imm_count -
				    ctask->imm_data_count;
		debug_scsi("itt %d total %d imm %d imm_data %d r2t_data %d\n",
			   ctask->itt, ctask->total_length, ctask->imm_count,
			   ctask->imm_data_count, ctask->r2t_data_count);
	} else {
		/* assume read op */
		ctask->hdr.flags |= ISCSI_FLAG_CMD_FINAL;
		ctask->in_progress = IN_PROGRESS_READ;
		zero_data(ctask->hdr.dlength);
	}

	iscsi_buf_init_hdr(conn, &ctask->headbuf, (char*)&ctask->hdr,
			    (u8 *)ctask->hdrext);

	ctask->in_progress |= IN_PROGRESS_HEAD;
}

static int
iscsi_hdr_extract(iscsi_conn_t *conn)
{
	struct sk_buff *skb = conn->in.skb;

	if (conn->in.copy >= conn->hdr_size &&
	    conn->in_progress != IN_PROGRESS_HEADER_GATHER) {
		/*
		 * Zero-copy PDU Header. Using connection's context
		 * to store pointer for incomming PDU Header.
		 */
		if (skb_shinfo(skb)->frag_list == NULL &&
		    !skb_shinfo(skb)->nr_frags) {
			conn->in.hdr = (iscsi_hdr_t *)
				((char*)skb->data + conn->in.offset);
		} else {
			(void)skb_copy_bits(skb, conn->in.offset,
				&conn->hdr, conn->hdr_size);
			conn->in.hdr = &conn->hdr;
		}
		conn->in.offset += conn->hdr_size;
		conn->in.copy -= conn->hdr_size;
		conn->in.hdr_offset = 0;
	} else {
		int copylen;

		/*
		 * Oops... got PDU Header scattered accross SKB's.
		 * Not much we can do but only copy Header into
		 * the connection PDU Header placeholder.
		 */
		if (conn->in_progress == IN_PROGRESS_WAIT_HEADER) {
			(void)skb_copy_bits(skb, conn->in.offset,
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
			/* FIXME: recover error */
			printk("iSCSI: PDU gather failed! "
			       "copylen %d conn->in.copy %d\n",
			       copylen, conn->in.copy);
			__BUG_ON(1);
			return 0;
		}
		debug_tcp("PDU gather #2 %d bytes!\n", copylen);

		(void)skb_copy_bits(skb, conn->in.offset,
		    (char*)&conn->hdr + conn->in.hdr_offset, copylen);
		conn->in.offset += copylen;
		conn->in.copy -= copylen;
		conn->in.hdr_offset = 0;
		conn->in.hdr = &conn->hdr;
		conn->in_progress = IN_PROGRESS_WAIT_HEADER;
	}

	return 0;
}

static int
iscsi_hdr_recv(iscsi_conn_t *conn)
{
	int rc = 0;
	iscsi_hdr_t *hdr;
	iscsi_cmd_task_t *ctask;
	iscsi_session_t *session = conn->session;
	uint32_t cdgst, rdgst = 0;

	hdr = conn->in.hdr;

	/* check for malformed pdu */
	conn->in.datalen = ntoh24(hdr->dlength);
	if (conn->in.datalen > conn->max_recv_dlength) {
		/* FIXME: recover error */
		printk("iSCSI: datalen %d > %d\n", conn->in.datalen,
		       conn->max_recv_dlength);
		__BUG_ON(1);
		return 0;
	}
	conn->data_copied = 0;

	/* calculate padding */
	conn->in.padding = conn->in.datalen & (ISCSI_PAD_LEN-1);
	if (conn->in.padding) {
		conn->in.padding = ISCSI_PAD_LEN - conn->in.padding;
		debug_scsi("padding %d bytes\n", conn->in.padding);
	}

	/* respect AHS */
	conn->in.ahslen = hdr->hlength*(4*sizeof(__u16));
	conn->in.offset += conn->in.ahslen;
	conn->in.copy -= conn->in.ahslen;
	/* FIXME: if ahslen too big... need special case to handle */
	__BUG_ON(conn->in.copy < 0);

	if (conn->hdrdgst_en) {
		struct scatterlist sg;

		sg.page = virt_to_page(hdr);
		sg.offset = offset_in_page(hdr);
		sg.length = sizeof(iscsi_hdr_t) + conn->in.ahslen;
		crypto_digest_init(conn->rx_tfm);
		crypto_digest_update(conn->rx_tfm, &sg, 1);
		crypto_digest_final(conn->rx_tfm, (u8 *)&cdgst);
		rdgst = *(uint32_t*)((char*)hdr + sizeof(iscsi_hdr_t) +
				     conn->in.ahslen);
	}

	/* save opcode & itt for later processing */
	conn->in.opcode = hdr->opcode;
	conn->in.itt = ntohl(hdr->itt);

	debug_tcp("opcode 0x%x offset %d copy %d ahslen %d datalen %d\n",
		  hdr->opcode, conn->in.offset, conn->in.copy,
		  conn->in.ahslen, conn->in.datalen);

	if (conn->in.itt < session->cmds_max) {
		int cstate;

		if (conn->hdrdgst_en && cdgst != rdgst) {
			/* FIXME: recover error */
			printk("iSCSI: itt %x: hdrdgst error recv 0x%x "
			       "calc 0x%x\n", conn->in.itt, rdgst, cdgst);
			return 0;
		}

		ctask = (iscsi_cmd_task_t *)session->cmds[conn->in.itt];
		conn->in.ctask = ctask;
		cstate = ctask->in_progress & IN_PROGRESS_OP_MASK;

		debug_scsi("rsp [op 0x%x cid %d sc %lx itt 0x%x len %d]\n",
			   hdr->opcode, conn->id, (long)ctask->sc, ctask->itt,
			   conn->in.datalen);

		switch(conn->in.opcode) {
		case ISCSI_OP_SCSI_CMD_RSP:
			if (conn->prev_itt == conn->in.itt) {
				/* FIXME: recover error */
				printk("iSCSI: dup rsp [itt 0x%x]\n",
					conn->in.itt);
				//__BUG_ON(1);
				//return 0;
			}
			if (cstate == IN_PROGRESS_READ) {
				if (!conn->in.datalen) {
					rc = iscsi_cmd_rsp(conn, ctask);
				} else {
					/* have sense or response data
					 * copying PDU Header to the
					 * connection's header
					 * placeholder */
					memcpy(&conn->hdr, conn->in.hdr,
					       sizeof(iscsi_hdr_t));
				}
			} else if (cstate == IN_PROGRESS_WRITE) {
				rc = iscsi_cmd_rsp(conn, ctask);
			}
			conn->prev_itt = conn->in.itt;
			break;
		case ISCSI_OP_SCSI_DATA_IN:
			/* save flags for nonexception status */
			conn->in.flags = hdr->flags;
			/* save cmd_status for sense data */
			conn->in.cmd_status =
				((iscsi_data_rsp_t*)hdr)->cmd_status;
			rc = iscsi_data_rsp(conn, ctask);
			break;
		case ISCSI_OP_R2T:
			rc = iscsi_r2t_rsp(conn, ctask);
			break;
		case ISCSI_OP_NOOP_IN:
		case ISCSI_OP_TEXT_RSP:
		case ISCSI_OP_LOGOUT_RSP:
		case ISCSI_OP_ASYNC_EVENT:
		case ISCSI_OP_REJECT:
			if (!conn->in.datalen) {
				iscsi_mgmt_task_t *mtask;

				rc = iscsi_control_recv_pdu(
					conn->handle, hdr, NULL, 0);
				mtask = (iscsi_mgmt_task_t *)
					session->imm_cmds[conn->in.itt -
						ISCSI_IMM_ITT_OFFSET];
				if (conn->login_mtask != mtask) {
					iscsi_enqueue(&session->immpool, mtask);
				}
			}
			break;
		default:
			rc = ISCSI_ERR_BAD_OPCODE;
			break;
		}
	} else if (conn->in.itt >= ISCSI_IMM_ITT_OFFSET &&
		   conn->in.itt < ISCSI_IMM_ITT_OFFSET +
					session->imm_max) {
		iscsi_mgmt_task_t *mtask = (iscsi_mgmt_task_t *)
					session->imm_cmds[conn->in.itt -
						ISCSI_IMM_ITT_OFFSET];

		debug_scsi("immrsp [op 0x%x cid %d itt 0x%x len %d]\n",
			   conn->in.opcode, conn->id, mtask->itt,
			   conn->in.datalen);

		switch(conn->in.opcode) {
		case ISCSI_OP_LOGIN_RSP:
		case ISCSI_OP_TEXT_RSP:
			if (!conn->in.datalen) {
				rc = iscsi_control_recv_pdu(
					conn->handle, hdr, NULL, 0);
				if (conn->login_mtask != mtask) {
					iscsi_enqueue(&session->immpool, mtask);
				}
			}
			break;
		default:
			rc = ISCSI_ERR_BAD_OPCODE;
			break;
		}
	} else if (conn->in.itt == ISCSI_RESERVED_TAG) {
		if (conn->in.opcode == ISCSI_OP_NOOP_IN &&
		    !conn->in.datalen) {
			rc = iscsi_control_recv_pdu(
					conn->handle, hdr, NULL, 0);
		} else {
			rc = ISCSI_ERR_BAD_OPCODE;
		}
	} else {
		rc = ISCSI_ERR_BAD_ITT;
	}

#ifdef DEBUG_PREV_PDU
	memcpy(&conn->prev_hdr, hdr, conn->hdr_size);
#endif

	return rc;
}

static int
iscsi_data_recv(iscsi_conn_t *conn)
{
	iscsi_session_t *session = conn->session;
	int rc = 0;

	switch(conn->in.opcode) {
	case ISCSI_OP_SCSI_DATA_IN: {
	    iscsi_cmd_task_t *ctask = conn->in.ctask;
	    struct scsi_cmnd *sc = ctask->sc;
	    __BUG_ON(!(ctask->in_progress & IN_PROGRESS_READ &&
		     conn->in_progress == IN_PROGRESS_DATA_RECV));
	    /*
	     * Copying Data-In to the Scsi_Cmnd
	     */
	    if (sc->use_sg) {
		int i;
		struct scatterlist *sg = (struct scatterlist *)
						sc->request_buffer;
		for (i=ctask->sg_count; i<sc->use_sg; i++) {
			char *dest =(char*)page_address(sg[i].page) +
						sg[i].offset;
			if ((rc = iscsi_ctask_copy(conn, ctask, dest,
					     sg->length)) == -EAGAIN) {
				/* continue with next SKB/PDU */
				goto exit;
			}
			if (!rc) {
				ctask->sg_count++;
			}
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
		if ((rc = iscsi_ctask_copy(conn, ctask, sc->request_buffer,
				   sc->request_bufflen)) == -EAGAIN) {
			goto exit;
		}
		rc = 0;
	    }

	    /* check for nonexceptional status */
	    if (conn->in.flags & ISCSI_FLAG_DATA_STATUS) {
		unsigned long flags;
		ctask->in_progress = IN_PROGRESS_IDLE;
		sc->result = conn->in.cmd_status;
		debug_scsi("done [sc %lx res %d itt 0x%x]\n",
			   (long)sc, sc->result, ctask->itt);
		spin_lock_irqsave(session->host->host_lock, flags);
		__enqueue(&session->cmdpool, ctask);
		sc->scsi_done(sc);
		spin_unlock_irqrestore(session->host->host_lock, flags);
	    }
	}
	break;
	case ISCSI_OP_SCSI_CMD_RSP: {
		/*
		 * SCSI Sense Data.
		 * copying the whole Data Segment to the connection's data
		 * placeholder.
		 */
		if (iscsi_tcp_copy(conn, conn->data, conn->in.datalen)) {
			rc = -EAGAIN;
			goto exit;
		}

		/*
		 * Check for sense data
		 */
		conn->in.hdr = &conn->hdr;
		conn->senselen = ntohs(*(__u16*)conn->data);
		rc = iscsi_cmd_rsp(conn, conn->in.ctask);
	}
	break;
	case ISCSI_OP_TEXT_RSP:
	case ISCSI_OP_LOGIN_RSP:
	case ISCSI_OP_NOOP_IN: {
		iscsi_mgmt_task_t *mtask = NULL;

		if (conn->in.itt != ISCSI_RESERVED_TAG) {
			mtask = (iscsi_mgmt_task_t *)
				session->imm_cmds[conn->in.itt -
					ISCSI_IMM_ITT_OFFSET];
		}

		/*
		 * Collect data segment to the connection's data
		 * placeholder
		 */
		if (iscsi_tcp_copy(conn, conn->data, conn->in.datalen)) {
			rc = -EAGAIN;
			goto exit;
		}

		rc = iscsi_control_recv_pdu(conn->handle,
				conn->in.hdr, conn->data, conn->in.datalen);

		if (mtask && conn->login_mtask != mtask) {
			iscsi_enqueue(&session->immpool, mtask);
		}
	}
	break;
	default:
		__BUG_ON(1);
	}
exit:
	return rc;
}

/*
 * iSCSI R2T Response processing
 */
static int
iscsi_r2t_rsp(iscsi_conn_t *conn, iscsi_cmd_task_t *ctask)
{
	int rc;
	iscsi_r2t_info_t *r2t;
	iscsi_session_t *session = conn->session;
	iscsi_r2t_rsp_t *rhdr = (iscsi_r2t_rsp_t *)conn->in.hdr;
	uint32_t max_cmdsn = ntohl(rhdr->max_cmdsn);
	uint32_t exp_cmdsn = ntohl(rhdr->exp_cmdsn);
	int r2tsn = ntohl(rhdr->r2tsn);

	if (conn->in.ahslen) {
		return ISCSI_ERR_AHSLEN;
	}
	if (conn->in.datalen) {
		return ISCSI_ERR_DATALEN;
	}

	if (ctask->exp_r2tsn && ctask->exp_r2tsn != r2tsn) {
		return ISCSI_ERR_R2TSN;
	}

	if (max_cmdsn < exp_cmdsn - 1) {
		return ISCSI_ERR_MAX_CMDSN;
	}
	session->max_cmdsn = max_cmdsn;
	session->exp_cmdsn = exp_cmdsn;

	/* FIXME: detect missing R2T by using R2TSN */

	/* fill-in new R2T associated with the task */
	spin_lock(&conn->lock);
	r2t = __dequeue(&ctask->r2tpool);
	if (r2t == NULL) {
		spin_unlock(&conn->lock);
		return ISCSI_ERR_PROTO;
	}
	r2t->exp_statsn = rhdr->statsn;
	r2t->data_length = ntohl(rhdr->data_length);
	if (r2t->data_length == 0 ||
	    r2t->data_length > session->max_burst) {
		__enqueue(&ctask->r2tpool, r2t);
		spin_unlock(&conn->lock);
		return ISCSI_ERR_DATALEN;
	}
	if (ctask->hdr.lun[1] != rhdr->lun[1]) {
		__enqueue(&ctask->r2tpool, r2t);
		spin_unlock(&conn->lock);
		return ISCSI_ERR_LUN;
	}
	r2t->data_offset = ntohl(rhdr->data_offset);
	if (r2t->data_offset + r2t->data_length > ctask->total_length) {
		__enqueue(&ctask->r2tpool, r2t);
		spin_unlock(&conn->lock);
		return ISCSI_ERR_DATALEN;
	}
	r2t->ttt = rhdr->ttt; /* no flip */
	r2t->solicit_datasn = 0;

	if ((rc = iscsi_solicit_data_init(conn, ctask, r2t))) {
		__enqueue(&ctask->r2tpool, r2t);
		spin_unlock(&conn->lock);
		return rc;
	}

	ctask->exp_r2tsn = r2tsn + 1;
	ctask->in_progress = IN_PROGRESS_WRITE |
			     IN_PROGRESS_SOLICIT_HEAD;
	__enqueue(&ctask->r2tqueue, r2t);
	__enqueue(&conn->xmitqueue, ctask);

	schedule_work(&conn->xmitwork);

	spin_unlock(&conn->lock);

	return 0;
}

/*
 * SCSI Command Response processing
 */
static int
iscsi_cmd_rsp(iscsi_conn_t *conn, iscsi_cmd_task_t *ctask)
{
	int rc = 0;
	iscsi_cmd_rsp_t *rhdr = (iscsi_cmd_rsp_t *)conn->in.hdr;
	iscsi_session_t *session = conn->session;
	struct scsi_cmnd *sc = ctask->sc;
	int max_cmdsn = ntohl(rhdr->max_cmdsn);
	int exp_cmdsn = ntohl(rhdr->exp_cmdsn);

	if (max_cmdsn < exp_cmdsn - 1) {
		rc = ISCSI_ERR_MAX_CMDSN;
		sc->result = host_byte(DID_ERROR);
		goto fault;
	}
	session->max_cmdsn = max_cmdsn;
	session->exp_cmdsn = exp_cmdsn;
	conn->exp_statsn = ntohl(rhdr->statsn) + 1;

	sc->result = host_byte(DID_OK) | status_byte(rhdr->cmd_status);

	if (rhdr->response == ISCSI_STATUS_CMD_COMPLETED) {
		if (status_byte(rhdr->cmd_status) == CHECK_CONDITION &&
		    conn->senselen) {
			int sensecopy = min(conn->senselen,
					    SCSI_SENSE_BUFFERSIZE);
			memcpy(sc->sense_buffer, conn->data, sensecopy);
			debug_scsi("copied %d bytes of sense\n", sensecopy);
		}

		if (sc->sc_data_direction != DMA_TO_DEVICE ) {
			if (rhdr->flags & ISCSI_FLAG_CMD_UNDERFLOW) {
				int res_count = ntohl(rhdr->residual_count);
				if( res_count > 0 &&
				    res_count <= sc->request_bufflen ) {
					sc->resid = res_count;
				} else {
					sc->result =
						host_byte(DID_BAD_TARGET) |
						status_byte(rhdr->cmd_status);
					rc = ISCSI_ERR_BAD_TARGET;
					goto fault;
				}
			} else if (rhdr->flags& ISCSI_FLAG_CMD_BIDI_UNDERFLOW) {
				sc->result = host_byte(DID_BAD_TARGET) |
					     status_byte(rhdr->cmd_status);
				rc = ISCSI_ERR_BAD_TARGET;
				goto fault;
			} else if (rhdr->flags & ISCSI_FLAG_CMD_OVERFLOW) {
				sc->resid = ntohl(rhdr->residual_count);
			}
		}
	} else {
		sc->result = host_byte(DID_ERROR);
		rc = ISCSI_ERR_BAD_TARGET;
		goto fault;
	}

fault:
	debug_scsi("done [sc %lx res %d itt 0x%x]\n",
		   (long)sc, sc->result, ctask->itt);
	if (sc->sc_data_direction == DMA_TO_DEVICE) {
		struct list_head *lh, *n;
		/* for WRITE, clean up Data-Out's if any */
		spin_lock(&conn->lock);
		list_for_each_safe(lh, n, &ctask->dataqueue) {
			iscsi_data_task_t *dtask;
			dtask = list_entry(lh, iscsi_data_task_t, item);
			if (dtask) {
				list_del(&dtask->item);
				mempool_free(dtask, ctask->datapool);
			}
		}
		spin_unlock(&conn->lock);
	}
	ctask->in_progress = IN_PROGRESS_IDLE;
	__enqueue(&session->cmdpool, ctask);
	sc->scsi_done(sc);
	return rc;
}

/*
 * SCSI Data-In Response processing
 */
static int
iscsi_data_rsp(iscsi_conn_t *conn, iscsi_cmd_task_t *ctask)
{
	iscsi_data_rsp_t *rhdr = (iscsi_data_rsp_t *)conn->in.hdr;
	iscsi_session_t *session = conn->session;
	int datasn = ntohl(rhdr->datasn);
	int max_cmdsn = ntohl(rhdr->max_cmdsn);
	int exp_cmdsn = ntohl(rhdr->exp_cmdsn);

	/*
	 * setup Data-In decrimental counter
	 */
	ctask->data_count = conn->in.datalen;

	if (conn->in.datalen == 0) {
		return 0;
	}

	if (max_cmdsn < exp_cmdsn -1) {
		return ISCSI_ERR_MAX_CMDSN;
	}
	session->max_cmdsn = max_cmdsn;
	session->exp_cmdsn = exp_cmdsn;

	if (ctask->datasn != datasn) {
		return ISCSI_ERR_DATASN;
	}
	ctask->datasn++;

	ctask->data_offset = ntohl(rhdr->offset);
	if (ctask->data_offset + conn->in.datalen > ctask->total_length) {
		return ISCSI_ERR_DATA_OFFSET;
	}

	if (rhdr->flags & ISCSI_FLAG_DATA_STATUS) {
		struct scsi_cmnd *sc = ctask->sc;
		conn->exp_statsn = ntohl(rhdr->statsn) + 1;
		if (rhdr->flags & ISCSI_FLAG_CMD_UNDERFLOW) {
			int res_count = ntohl(rhdr->residual_count);
			if( res_count > 0 &&
			    res_count <= sc->request_bufflen ) {
				sc->resid = res_count;
			} else {
				sc->result = (DID_BAD_TARGET << 16) |
					rhdr->cmd_status;
				return ISCSI_ERR_BAD_TARGET;
			}
		} else if (rhdr->flags& ISCSI_FLAG_CMD_BIDI_UNDERFLOW) {
			sc->result = (DID_BAD_TARGET << 16) |
				rhdr->cmd_status;
			return ISCSI_ERR_BAD_TARGET;
		} else if (rhdr->flags & ISCSI_FLAG_CMD_OVERFLOW) {
			sc->resid = ntohl(rhdr->residual_count);
		}
	}

	return 0;
}

/*
 * iscsi_mtask_xmit - xmit management(immediate) task
 *
 * The function can return -EAGAIN in which case caller must
 * call it again later or recover. '0' return code means successful
 * xmit.
 *
 * Management xmit state machine consists of two states:
 *	IN_PROGRESS_IMM_HEAD - PDU Header xmit in progress
 *	IN_PROGRESS_IMM_DATA - PDU Data xmit in progress
 */
static int
iscsi_mtask_xmit(iscsi_conn_t *conn, iscsi_mgmt_task_t *mtask)
{
	if (mtask->in_progress & IN_PROGRESS_IMM_HEAD) {
		if (iscsi_sendhdr(conn, &mtask->headbuf)) {
			return -EAGAIN;
		}
		if (mtask->data_count == 0 &&
		    mtask->hdr.itt == ISCSI_RESERVED_TAG) {
			up(&mtask->xmitsema);
			return 0;
		} else if (mtask->data_count) {
			mtask->in_progress = IN_PROGRESS_IMM_DATA;
		}
	}

	if (mtask->in_progress == IN_PROGRESS_IMM_DATA) {
		/* FIXME: implement.
		 *        Keep in mind that virtual buffer
		 *        spreaded accross multiple pages... */
		do {
			if (iscsi_sendpage(conn, &mtask->sendbuf,
					   &mtask->data_count,
					   &mtask->sent)) {
				return -EAGAIN;
			}
		} while (mtask->data_count);
	}

	up(&mtask->xmitsema);
	return 0;
}

/*
 * iscsi_ctask_xmit - xmit SCSI command task
 *
 * The function can return -EAGAIN in which case caller must
 * call it again later or recover. '0' return code means successful
 * xmit.
 */
static int
iscsi_ctask_xmit(iscsi_conn_t *conn, iscsi_cmd_task_t *ctask)
{
	iscsi_r2t_info_t *r2t;

	debug_scsi("dequeued [cid %d state %x itt 0x%x]\n",
		conn->id, ctask->in_progress, ctask->itt);

	/*
	 * make sure state machine is not screwed.
	 */
	__BUG_ON(!(ctask->in_progress & IN_PROGRESS_HEAD) &&
		 !(ctask->in_progress & IN_PROGRESS_BEGIN_WRITE_IMM) &&
		 !(ctask->in_progress & IN_PROGRESS_BEGIN_WRITE) &&
		 !(ctask->in_progress & IN_PROGRESS_UNSOLICIT_HEAD) &&
		 !(ctask->in_progress & IN_PROGRESS_UNSOLICIT_WRITE) &&
		 !(ctask->in_progress & IN_PROGRESS_SOLICIT_HEAD) &&
		 !(ctask->in_progress & IN_PROGRESS_SOLICIT_WRITE));

	if (ctask->in_progress & IN_PROGRESS_HEAD) {
		if (iscsi_sendhdr(conn, &ctask->headbuf)) {
			return -EAGAIN;
		}
		if (ctask->hdr.flags & ISCSI_FLAG_CMD_READ) {
			/* wait for DATA_RSP */
			return 0;
		}
	}

	if (ctask->in_progress & IN_PROGRESS_BEGIN_WRITE_IMM) {
		while (ctask->imm_count) {
			if (iscsi_sendpage(conn, &ctask->sendbuf,
					   &ctask->imm_count,
					   &ctask->sent)) {
				return -EAGAIN;
			}
			if (!ctask->imm_count) {
				break;
			}
			iscsi_buf_init_sg(&ctask->sendbuf,
				 &ctask->sg[ctask->sg_count++]);
		}
		if (ctask->imm_data_count) {
			if (iscsi_unsolicit_data_init(conn, ctask)) {
				return -EAGAIN;
			}
			ctask->in_progress = IN_PROGRESS_WRITE |
					     IN_PROGRESS_UNSOLICIT_HEAD;
		} else if (ctask->r2t_data_count) {
			ctask->in_progress = IN_PROGRESS_WRITE |
					     IN_PROGRESS_R2T_WAIT;
			return 0;
		}
	} else if (ctask->in_progress & IN_PROGRESS_BEGIN_WRITE) {
		if (ctask->imm_data_count) {
			if (iscsi_unsolicit_data_init(conn, ctask)) {
				return -EAGAIN;
			}
			ctask->in_progress = IN_PROGRESS_WRITE |
					     IN_PROGRESS_UNSOLICIT_HEAD;
		} else if (ctask->r2t_data_count) {
			ctask->in_progress = IN_PROGRESS_WRITE |
					     IN_PROGRESS_R2T_WAIT;
			return 0;
		}
	}

	if (ctask->in_progress & IN_PROGRESS_UNSOLICIT_HEAD) {
_unsolicit_head_again:
		if (iscsi_sendhdr(conn, &ctask->headbuf)) {
			return -EAGAIN;
		}
		ctask->in_progress = IN_PROGRESS_WRITE |
				     IN_PROGRESS_UNSOLICIT_WRITE;
	}

	if (ctask->in_progress & IN_PROGRESS_UNSOLICIT_WRITE) {
		while (ctask->data_count) {
			int start = ctask->sent;
			if (iscsi_sendpage(conn, &ctask->sendbuf,
					   &ctask->data_count,
					   &ctask->sent)) {
				ctask->imm_data_count -= ctask->sent - start;
				return -EAGAIN;
			}
			ctask->imm_data_count -= ctask->sent - start;
			if (!ctask->data_count) {
				break;
			}
			iscsi_buf_init_sg(&ctask->sendbuf,
				 &ctask->sg[ctask->sg_count++]);
		}

		/*
		 * done with Data-Out's payload. Check if we have
		 * to send another unsolicit Data-Out.
		 */
		__BUG_ON(ctask->imm_data_count < 0);
		if (ctask->imm_data_count) {
			if (iscsi_unsolicit_data_init(conn, ctask)) {
				return -EAGAIN;
			}
			ctask->in_progress = IN_PROGRESS_WRITE |
					     IN_PROGRESS_UNSOLICIT_HEAD;
			goto _unsolicit_head_again;
		}
		if (ctask->r2t_data_count) {
			ctask->in_progress = IN_PROGRESS_WRITE |
					     IN_PROGRESS_R2T_WAIT;
		} else {
			ctask->in_progress = IN_PROGRESS_WRITE |
					     IN_PROGRESS_UNSOLICIT_DONE;
		}
		return 0;
	}

	if (ctask->in_progress & IN_PROGRESS_SOLICIT_HEAD) {
		r2t = __dequeue(&ctask->r2tqueue);
_solicit_head_again:
		__BUG_ON(r2t == NULL);
		if (r2t->cont_bit) {
			__BUG_ON(r2t->data_length - r2t->sent <= 0);
			/*
			 * we failed to fill-in Data-Out last time
			 * due to memory allocation failure most likely
			 * try it again until we succeed. Once we
			 * succeed, reset cont_bit.
			 */
			if (iscsi_solicit_data_cont(conn, ctask, r2t,
				r2t->data_length - r2t->sent)) {
				__insert(&ctask->r2tqueue, r2t);
				return -EAGAIN;
			}
			r2t->cont_bit = 0;
		}
		if (iscsi_sendhdr(conn, &r2t->headbuf)) {
			__insert(&ctask->r2tqueue, r2t);
			return -EAGAIN;
		}
		ctask->r2t = r2t;
		ctask->in_progress = IN_PROGRESS_WRITE |
				     IN_PROGRESS_SOLICIT_WRITE;
	}

	if (ctask->in_progress & IN_PROGRESS_SOLICIT_WRITE) {
		int left;
		r2t = ctask->r2t;
_solicit_again:
		/*
		 * send Data-Out's payload whitnin this R2T sequence.
		 */
		if (r2t->data_count) {
			if (iscsi_sendpage(conn, &r2t->sendbuf,
					   &r2t->data_count,
					   &r2t->sent)) {
				/* do not insert back to the queue.
				 * ctask will continue from current! r2t */
				return -EAGAIN;
			}
			if (r2t->data_count) {
				__BUG_ON(ctask->bad_sg == r2t->sg);
				__BUG_ON(ctask->sc->use_sg == 0);
				iscsi_buf_init_sg(&r2t->sendbuf, r2t->sg);
				r2t->sg += 1;
				goto _solicit_again;
			}
		}

		/*
		 * done with Data-Out's payload. Check if we have
		 * to send another Data-Out whithin this R2T sequence.
		 */
		__BUG_ON(r2t->data_length - r2t->sent < 0);
		left = r2t->data_length - r2t->sent;
		if (left) {
			ctask->in_progress = IN_PROGRESS_WRITE |
					     IN_PROGRESS_SOLICIT_HEAD;
			if (iscsi_solicit_data_cont(conn,
					    ctask, r2t, left)) {
				r2t->cont_bit = 1;
				__insert(&ctask->r2tqueue, r2t);
				return -EAGAIN;
			}
			goto _solicit_head_again;
		}

		/*
		 * done with this R2T sequence. Check if we have
		 * more outstanding R2T's ready to send.
		 */
		__BUG_ON(ctask->r2t_data_count - r2t->data_length < 0);
		ctask->r2t_data_count -= r2t->data_length;
		__enqueue(&ctask->r2tpool, r2t);
		if ((r2t = __dequeue(&ctask->r2tqueue))) {
			ctask->in_progress = IN_PROGRESS_WRITE |
					     IN_PROGRESS_SOLICIT_HEAD;
			goto _solicit_head_again;
		} else {
			if (ctask->r2t_data_count) {
				ctask->in_progress = IN_PROGRESS_WRITE |
						     IN_PROGRESS_R2T_WAIT;
			}
		}
		ctask->in_progress = IN_PROGRESS_WRITE |
				     IN_PROGRESS_SOLICIT_DONE;
		return 0;
	}

	return 0;
}

/*
 * iscsi_data_xmit - xmit any command into the scheduled connection
 *
 * The function can return -EAGAIN in which case caller must
 * re-schedule it again later or recover. '0' return code means successful
 * xmit.
 *
 * Common data xmit state machine consists of two states:
 *	IN_PROGRESS_XMIT_IMM - xmit of Immediate PDU in progress
 *	IN_PROGRESS_XMIT_SCSI - xmit of SCSI command PDU in progress
 */
static int
iscsi_data_xmit(iscsi_conn_t *conn)
{
	iscsi_cmd_task_t *ctask;
	iscsi_mgmt_task_t *mtask;

	/* process non-immediate(command) queue */
	spin_lock_bh(&conn->lock);
	while (conn->in_progress_xmit == IN_PROGRESS_XMIT_SCSI &&
	       (ctask = __dequeue(&conn->xmitqueue)) != NULL) {

		if (iscsi_ctask_xmit(conn, ctask)) {
			__insert(&conn->xmitqueue, ctask);
			spin_unlock_bh(&conn->lock);
			return -EAGAIN;
		}

		/* check if we have something for immediate delivery */
		if (conn->immqueue.cons != conn->immqueue.prod) {
			break;
		}
	}

	/* process immediate queue */
	while ((mtask = __dequeue(&conn->immqueue)) != NULL) {
		iscsi_session_t *session = conn->session;

		conn->in_progress_xmit = IN_PROGRESS_XMIT_IMM;

		if (iscsi_mtask_xmit(conn, mtask)) {
			__insert(&conn->immqueue, mtask);
			spin_unlock_bh(&conn->lock);
			return -EAGAIN;
		}

		if (mtask->itt == ISCSI_RESERVED_TAG)
			__enqueue(&session->immpool, mtask);

		/* re-schedule xmitqueue. have to do that in case
		 * when immediate PDU interrupts xmitqueue loop */
		if (conn->xmitqueue.cons != conn->xmitqueue.prod) {
			schedule_work(&conn->xmitwork);
		}
	}
	spin_unlock_bh(&conn->lock);

	conn->in_progress_xmit = IN_PROGRESS_XMIT_SCSI;

	return 0;
}

static void
iscsi_xmitworker(void *data)
{
	iscsi_conn_t *conn = (iscsi_conn_t*)data;

	/*
	 * We don't want to run this connection on any other CPU.
	 */
	if (conn->cpu != smp_processor_id()) {
		schedule_delayed_work_on(conn->id, &conn->xmitwork, 0);
		return;
	}

	/*
	 * We serialize Xmit worker on per-connection basis.
	 */
	while (iscsi_data_xmit(conn)) {
		if (conn->c_stage == ISCSI_CNX_CLEANUP_WAIT ||
		    conn->c_stage == ISCSI_CNX_STOPPED)
			return;
		if (conn->suspend) {
			schedule_work(&conn->xmitwork);
			return;
		}
		yield();
	}
}

#define FAILURE_BAD_HOST		1
#define FAILURE_BAD_SESSION		2
#define FAILURE_BAD_SESSID		3
#define FAILURE_SESSION_FAILED		4
#define FAILURE_SESSION_FREED		5
#define FAILURE_WINDOW_CLOSED		6

int
iscsi_queuecommand(struct scsi_cmnd *sc, void (*done)(struct scsi_cmnd *))
{
	struct Scsi_Host *host;
	int reason = 0;
	iscsi_session_t *session;
	iscsi_conn_t *conn = NULL;
	iscsi_cmd_task_t *ctask;
	struct list_head *lh;

	sc->scsi_done = done;
	sc->result = 0;

	if (!(host = sc->device->host)) {
		reason = FAILURE_BAD_HOST;
		goto fault;
	}

	if (!(session = (iscsi_session_t*)*host->hostdata)) {
		reason = FAILURE_BAD_SESSION;
		goto fault;
	}

	if (host->host_no != session->id) {
		reason = FAILURE_BAD_SESSID;
		goto fault;
	}

	if (session->state != ISCSI_STATE_LOGGED_IN) {
		if (session->state == ISCSI_STATE_FAILED) {
			reason = FAILURE_SESSION_FAILED;
			goto fault;
		}
		reason = FAILURE_SESSION_FREED;
		goto fault;
	}

	/*
	 * Check for iSCSI window and taking care of CmdSN wrap-around
	 * issue. Assuming that running platform will guarantee atomic
	 * double-word memory write operation.
	 */
	if ((int)(session->max_cmdsn - session->cmdsn) < 0) {
		reason = FAILURE_WINDOW_CLOSED;
		goto reject;
	}

	if (session->conn_cnt > 1) {
		int cpu = smp_processor_id();

		spin_lock(&session->conn_lock);
		list_for_each(lh, &session->connections) {
			iscsi_conn_t *cnx;

			cnx = list_entry(lh, iscsi_conn_t, item);
			if (cnx->busy) {
				conn = cnx;
				conn->busy--;
				break;
			}
			if (cnx->cpu == cpu && cpu_online(cpu) &&
			    !cnx->busy) {
				conn = cnx;
				conn->busy = 16;
				break;
			}
		}
		spin_unlock(&session->conn_lock);
		if (conn == NULL)
			conn = session->leadconn;
	} else {
		conn = session->leadconn;
	}

	ctask = __dequeue(&session->cmdpool);
	__BUG_ON(ctask->in_progress = IN_PROGRESS_IDLE);

	sc->SCp.ptr = (char*)ctask;
	iscsi_cmd_init(conn, ctask, sc);

	spin_lock(&conn->lock);
	__enqueue(&conn->xmitqueue, ctask);
	spin_unlock(&conn->lock);

	debug_scsi(
		"queued [%s cid %d sc %lx itt 0x%x len %d cmdsn %d win %d]\n",
		sc->sc_data_direction == DMA_TO_DEVICE ? "write" : "read",
		conn->id, (long)sc, ctask->itt, sc->request_bufflen,
		session->cmdsn, session->max_cmdsn - session->exp_cmdsn + 1);

	schedule_work(&conn->xmitwork);

	return 0;

reject:
	debug_scsi("cmd 0x%x rejected (%d)\n", sc->cmnd[0], reason);
	return SCSI_MLQUEUE_HOST_BUSY;

fault:
	printk("iSCSI: cmd 0x%x is not queued (%d)\n", sc->cmnd[0], reason);
	sc->sense_buffer[0] = 0x70;
	sc->sense_buffer[2] = NOT_READY;
	sc->sense_buffer[7] = 0x6;
	sc->sense_buffer[12] = 0x08;
	sc->sense_buffer[13] = 0x00;
	sc->result = DID_NO_CONNECT << 16;
	switch (sc->cmnd[0]) {
	case INQUIRY:
	case REQUEST_SENSE:
		sc->resid = sc->cmnd[4];
	case REPORT_LUNS:
		sc->resid = sc->cmnd[6] << 24;
		sc->resid |= sc->cmnd[7] << 16;
		sc->resid |= sc->cmnd[8] << 8;
		sc->resid |= sc->cmnd[9];
	default:
		sc->resid = sc->request_bufflen;
	}
	sc->scsi_done(sc);
	return 0;
}

static int
iscsi_eh_abort(struct scsi_cmnd *sc)
{
#ifdef DEBUG_SCSI
	iscsi_cmd_task_t *ctask = (iscsi_cmd_task_t *)sc->SCp.ptr;
#endif

	debug_scsi("abort [sc %lx itt 0x%x]\n", (long)sc, ctask->itt);

#if 0
	iscsi_conn_t *conn = ctask->conn;
	if (iscsi_control_recv_pdu(conn->handle,
			(iscsi_hdr_t*)&ctask->hdr, NULL, 0)) {
		return FAILED;
	}
	iscsi_mgmt_task_t *mtask;
	iscsi_session_t *session = conn->session;

	debug_scsi("abort [sc %lx itt 0x%x]\n", (long)sc, ctask->itt);

	mtask = iscsi_dequeue(&session->immpool);

	mtask->hdr.itt = htonl(mtask->itt);
	mtask->hdr.exp_statsn = htonl(conn->exp_statsn);
	mtask->data_count = 0;
	mtask->in_progress = IN_PROGRESS_IMM_HEAD;

	iscsi_buf_init_virt(&mtask->headbuf, (char*)&mtask->hdr,
			    sizeof(iscsi_hdr_t));

	iscsi_enqueue(&conn->immqueue, mtask);
	schedule_work(&conn->xmitwork);

	down(&mtask->xmitsema);
#endif
	return SUCCESS;
}

static const char *
iscsi_info(struct Scsi_Host *host)
{
	return "iSCSI/TCP bridge, v." ISCSI_DRV_VERSION;
}

static int
iscsi_proc_info(struct Scsi_Host *host, char *buffer, char **start,
		off_t offset, int length,  int inout)
{
	return length;
}

static int
iscsi_queue_init(iscsi_queue_t *q, int max, spinlock_t *lock)
{
	q->lock = lock;
	q->max = max;
	q->pool = kmalloc(max * sizeof(void*), GFP_KERNEL);
	if (q->pool == NULL) {
		return -ENOMEM;
	}
	/* queue's pool is empty initially */
	q->cons = 0;
	q->prod = 0;
	return 0;
}

static void
iscsi_queue_free(iscsi_queue_t *q)
{
	kfree(q->pool);
}

static int
iscsi_pool_init(iscsi_queue_t *q, int max, void ***items, int item_size,
		spinlock_t *lock)
{
	int i;

	*items = kmalloc(max * sizeof(void*), GFP_KERNEL);
	if (*items == NULL) {
		return -ENOMEM;
	}

	q->lock = lock;
	q->max = max;
	q->pool = kmalloc(max * sizeof(void*), GFP_KERNEL);
	if (q->pool == NULL) {
		kfree(*items);
		return -ENOMEM;
	}
	for (i=0; i<max; i++) {
		q->pool[i] = kmalloc(item_size, GFP_KERNEL);
		if (q->pool[i] == NULL) {
			int j;
			for (j=0; j<i; j++) {
				kfree(q->pool[j]);
			}
			kfree(q->pool);
			return -ENOMEM;
		}
		memset(q->pool[i], 0, item_size);
		(*items)[i] = q->pool[i];
	}
	/* queue's pool is full initially */
	q->cons = 1;
	q->prod = 0;
	return 0;
}

static void
iscsi_pool_free(iscsi_queue_t *q, void **items)
{
	int i;

	for (i=0; i<q->max; i++) {
		kfree(items[i]);
	}
	kfree(q->pool);
	kfree(items);
}

/*
 * Allocate new connection within the session and bind it to
 * the provided socket
 */
static iscsi_cnx_h
iscsi_conn_create(iscsi_snx_h snxh, iscsi_cnx_h handle,
			struct socket *sock, int conn_idx)
{
	iscsi_session_t *session = snxh;
	struct tcp_opt *tp;
	struct sock *sk;
	iscsi_conn_t *conn;

	conn = kmalloc(sizeof(iscsi_conn_t), GFP_KERNEL);
	if (conn == NULL) {
		return NULL;
	}
	memset(conn, 0, sizeof(iscsi_conn_t));

	/* bind iSCSI connection and socket */
	conn->sock = sock;

	/* setup Socket parameters */
	sk = sock->sk;
	sk->sk_reuse = 1;
	sk->sk_sndtimeo = 15 * HZ; /* FIXME: make it configurable */
	sk->sk_allocation |= GFP_ATOMIC;

	/* disable Nagle's algorithm */
	tp = tcp_sk(sk);
	tp->nonagle = 1;

	if (!(sk->sk_route_caps & NETIF_F_SG)) {
		printk("iSCSI/TCP: PHY do not support "
		       "HW scatter-gather!\n");
	}
	if (!(sk->sk_route_caps & (NETIF_F_IP_CSUM |
				   NETIF_F_NO_CSUM |
				   NETIF_F_HW_CSUM))) {
		printk("iSCSI/TCP: PHY do not support "
		       "HW checksumming!\n");
	}


	/* Intercepts TCP callbacks for sendfile like receive processing. */
	iscsi_conn_set_callbacks(conn);

	conn->c_stage = ISCSI_CNX_INITIAL_STAGE;
	conn->in_progress = IN_PROGRESS_WAIT_HEADER;
	conn->in_progress_xmit = IN_PROGRESS_XMIT_SCSI;
	conn->id = conn_idx;
	conn->exp_statsn = 0;
	conn->handle = handle;

	/* some initial operational parameters */
	conn->hdr_size = sizeof(iscsi_hdr_t);
	conn->max_recv_dlength = DEFAULT_MAX_RECV_DATA_SEGMENT_LENGTH;

	spin_lock_init(&conn->lock);

	/* initialize xmit PDU commands queue */
	if (iscsi_queue_init(&conn->xmitqueue, session->cmds_max,
			     &conn->lock)) {
		kfree(conn);
		return NULL;
	}
	/* initialize immediate xmit queue */
	if (iscsi_queue_init(&conn->immqueue, session->imm_max,
			     &conn->lock)) {
		iscsi_queue_free(&conn->xmitqueue);
		kfree(conn);
		return NULL;
	}
	INIT_WORK(&conn->xmitwork, iscsi_xmitworker, conn);

	/* allocate login_mtask used for initial login/text sequence */
	conn->login_mtask = iscsi_dequeue(&session->immpool);
	if (conn->login_mtask == NULL) {
		iscsi_queue_free(&conn->immqueue);
		iscsi_queue_free(&conn->xmitqueue);
		kfree(conn);
		return NULL;
	}

	/* allocate initial PDU receive place holder */
	if (conn->max_recv_dlength <= PAGE_SIZE)
		conn->data = kmalloc(conn->max_recv_dlength, GFP_KERNEL);
	else
		conn->data = (void*)__get_free_pages(GFP_KERNEL,
					get_order(conn->max_recv_dlength));
	if (conn->data == NULL) {
		iscsi_enqueue(&session->immpool, conn->login_mtask);
		iscsi_queue_free(&conn->immqueue);
		iscsi_queue_free(&conn->xmitqueue);
		kfree(conn);
		return NULL;
	}

	return conn;
}

/*
 * Terminate connection queues, free all associated resources
 */
static void
iscsi_conn_destroy(iscsi_cnx_h cnxh)
{
	iscsi_conn_t *conn = cnxh;
	iscsi_session_t *session = conn->session;
	struct list_head *lh, *n;
	unsigned long flags;
	iscsi_cmd_task_t *ctask;

	__BUG_ON(conn->sock == NULL);

	sock_hold(conn->sock->sk);
	iscsi_conn_restore_callbacks(conn);
	sock_put(conn->sock->sk);
	sock_release(conn->sock);

	spin_lock_irqsave(session->host->host_lock, flags);
	spin_lock(&conn->lock);
	while ((ctask = __dequeue(&conn->xmitqueue)) != NULL) {
		list_for_each_safe(lh, n, &ctask->dataqueue) {
			iscsi_data_task_t *dtask;
			dtask = list_entry(lh, iscsi_data_task_t, item);
			if (dtask) {
				list_del(&dtask->item);
				mempool_free(dtask, ctask->datapool);
			}
		}
	}
	spin_unlock(&conn->lock);
	spin_unlock_irqrestore(session->host->host_lock, flags);

	/* now free crypto */
	if (conn->hdrdgst_en || conn->datadgst_en) {
		if (conn->tx_tfm)
			crypto_free_tfm(conn->tx_tfm);
		if (conn->rx_tfm)
			crypto_free_tfm(conn->rx_tfm);
	}

	/* now free MaxRecvDataSegmentLength */
	if (conn->max_recv_dlength <= PAGE_SIZE)
		kfree(conn->data);
	else
		free_pages((unsigned long)conn->data,
					get_order(conn->max_recv_dlength));

	iscsi_enqueue(&session->immpool, conn->login_mtask);

	iscsi_queue_free(&conn->xmitqueue);
	iscsi_queue_free(&conn->immqueue);

	spin_lock_bh(&session->conn_lock);
	list_del(&conn->item);
	if (list_empty(&session->connections))
		session->leadconn = NULL;
	if (session->leadconn && session->leadconn == conn)
		session->leadconn = container_of(session->connections.next,
			struct iscsi_conn, item);
	spin_unlock_bh(&session->conn_lock);

	if (session->leadconn == NULL) {
		/* non connections exits.. reset sequencing */
		session->cmdsn = session->max_cmdsn = session->exp_cmdsn = 1;
	}

	kfree(conn);
}

static int
iscsi_conn_bind(iscsi_snx_h snxh, iscsi_cnx_h cnxh, int is_leading)
{
	iscsi_session_t *session = snxh;
	iscsi_conn_t *conn = cnxh;

	/*
	 * Bind iSCSI connection and session
	 */
	conn->session = session;

	spin_lock_bh(&session->conn_lock);
	list_add(&conn->item, &session->connections);
	spin_unlock_bh(&session->conn_lock);

	if (is_leading) {
		session->leadconn = conn;
	}

	return 0;
}

static int
iscsi_conn_start(iscsi_cnx_h cnxh)
{
	iscsi_conn_t *conn = cnxh;
	iscsi_session_t *session = conn->session;
	unsigned long flags;

	if (session == NULL) {
		printk("iSCSI: can't start not-binded connection\n");
		return -EPERM;
	}

	if (session->state == ISCSI_STATE_LOGGED_IN &&
	    session->leadconn == conn) {
		scsi_scan_host(session->host);
	}

	spin_lock_irqsave(session->host->host_lock, flags);
	conn->c_stage = ISCSI_CNX_STARTED;
	conn->cpu = session->conn_cnt % num_online_cpus();
	session->state = ISCSI_STATE_LOGGED_IN;
	session->conn_cnt++;
	spin_unlock_irqrestore(session->host->host_lock, flags);

	return 0;
}

static void
iscsi_conn_stop(iscsi_cnx_h cnxh)
{
	iscsi_conn_t *conn = cnxh;
	iscsi_session_t *session = conn->session;
	unsigned long flags;

	spin_lock_irqsave(session->host->host_lock, flags);
	conn->c_stage = ISCSI_CNX_STOPPED;
	session->conn_cnt--;

	if (session->conn_cnt == 0 ||
	    session->leadconn == conn) {
		session->state = ISCSI_STATE_FAILED;
	}
	spin_unlock_irqrestore(session->host->host_lock, flags);
}

static int
iscsi_send_immpdu(iscsi_cnx_h cnxh, iscsi_hdr_t *hdr, char *data,
		  int data_size)
{
	iscsi_conn_t *conn = cnxh;
	iscsi_session_t *session = conn->session;
	iscsi_mgmt_task_t *mtask;
	unsigned long flags;

	if (conn->c_stage != ISCSI_CNX_INITIAL_STAGE) {
		mtask = iscsi_dequeue(&session->immpool);
	} else {
		/*
		 * If connection is about to start but not started yet
		 * than we preserve ITT for all requests within this
		 * login and text negotiation sequence. mtask is
		 * preallocated at cnx_create() and will be released
		 * at cnx_start() or cnx_destroy().
		 */
		mtask = conn->login_mtask;
	}

	/*
	 * pre-format CmdSN and ExpStatSN for outgoing PDU's.
	 */
	spin_lock_irqsave(session->host->host_lock, flags);
	if (hdr->itt != ISCSI_RESERVED_TAG) {
		hdr->itt = htonl(mtask->itt);
		((iscsi_nopout_t*)hdr)->cmdsn = htonl(session->cmdsn);
		if (conn->c_stage == ISCSI_CNX_STARTED) {
			session->cmdsn++;
		}
	} else {
		/* do not advance CmdSN */
		((iscsi_nopout_t*)hdr)->cmdsn = htonl(session->cmdsn);
	}
	((iscsi_nopout_t*)hdr)->exp_statsn = htonl(conn->exp_statsn);

	memcpy(&mtask->hdr, hdr, sizeof(iscsi_hdr_t));

	if (conn->c_stage != ISCSI_CNX_INITIAL_STAGE) {
		iscsi_buf_init_hdr(conn, &mtask->headbuf, (char*)&mtask->hdr,
				    (u8 *)mtask->hdrext);
	} else {
		iscsi_buf_init_virt(&mtask->headbuf, (char*)&mtask->hdr,
				    sizeof(iscsi_hdr_t));
	}
	spin_unlock_irqrestore(session->host->host_lock, flags);

	mtask->data = data;
	mtask->data_count = data_size;
	mtask->in_progress = IN_PROGRESS_IMM_HEAD;

	if (mtask->data_count) {
		iscsi_buf_init_virt(&mtask->sendbuf, (char*)mtask->data,
				    mtask->data_count);
		/* FIXME: implement convertion of mtask->data into 1st
		 *        mtask->sendbuf. Keep in mind that virtual buffer
		 *        spreaded accross multiple pages... */
		if(mtask->sendbuf.sg.offset + mtask->data_count > PAGE_SIZE) {
			if (conn->c_stage == ISCSI_CNX_STARTED) {
				iscsi_enqueue(&session->immpool, mtask);
			}
			return -ENOMEM;
		}
	}

	debug_scsi("immpdu [op 0x%x itt 0x%x datalen %d]\n",
		   hdr->opcode, ntohl(hdr->itt), data_size);

	iscsi_enqueue(&conn->immqueue, mtask);
	schedule_work(&conn->xmitwork);
	down(&mtask->xmitsema);

	return 0;
}

static void
iscsi_r2tpool_free(iscsi_session_t *session)
{
	int i;

	for (i=0; i<session->cmds_max; i++) {
		mempool_destroy(session->cmds[i]->datapool);
		kfree(session->cmds[i]->r2tqueue.pool);
		iscsi_pool_free(&session->cmds[i]->r2tpool,
				(void**)session->cmds[i]->r2ts);
	}
}

static int
iscsi_r2tpool_alloc(iscsi_session_t *session)
{
	int i;
	int cmd_i;

	/* initialize per-task R2T queue with size based on
	 * session's login result MaxOutstandingR2T */
	for (cmd_i=0; cmd_i<session->cmds_max; cmd_i++) {
		iscsi_cmd_task_t *ctask = session->cmds[cmd_i];

		/* now initialize per-task R2T pool */
		if (iscsi_pool_init(&ctask->r2tpool, session->max_r2t,
			(void***)&ctask->r2ts, sizeof(iscsi_r2t_info_t),
			NULL)) {
			goto r2t_alloc_fault;
		}

		/* now initialize per-task R2T queue */
		if (iscsi_queue_init(&ctask->r2tqueue, session->max_r2t,
				     NULL)) {
			iscsi_pool_free(&ctask->r2tpool, (void**)ctask->r2ts);
			goto r2t_alloc_fault;
		}

		/*
		 * since under some configurations number of
		 * Data-Out PDU's within R2T-sequence can be quite big
		 * we are using mempool
		 */
		ctask->datapool = mempool_create(ISCSI_CMD_DATAPOOL_SIZE,
						 mempool_alloc_slab,
						 mempool_free_slab,
						 taskcache);
		if (ctask->datapool == NULL) {
			kfree(ctask->r2tqueue.pool);
			iscsi_pool_free(&ctask->r2tpool, (void**)ctask->r2ts);
			goto r2t_alloc_fault;
		}
		INIT_LIST_HEAD(&ctask->dataqueue);
	}

	return 0;

r2t_alloc_fault:
	for (i=0; i<cmd_i; i++) {
		mempool_destroy(session->cmds[i]->datapool);
		kfree(session->cmds[i]->r2tqueue.pool);
		iscsi_pool_free(&session->cmds[i]->r2tpool,
				(void**)session->cmds[i]->r2ts);
	}
	return -ENOMEM;
}

static iscsi_snx_h
iscsi_session_create(iscsi_snx_h handle, int host_no, int initial_cmdsn)
{
	int cmd_i;
	iscsi_session_t *session;
	struct Scsi_Host *host;
	int res;

	host = scsi_host_lookup(host_no);
	if (host != ERR_PTR(-ENXIO)) {
		printk("host_no %d already exists\n", host_no);
		return NULL;
	}

	session = kmalloc(sizeof(iscsi_session_t), GFP_KERNEL);
	if (session == NULL) {
		printk("not enough memory to allocate host_no %d\n",
			host_no);
		return NULL;
	}
	memset(session, 0, sizeof(iscsi_session_t));

	/* fill-in SCSI Host Template */
	session->sht.name = "iSCSI Initiator";
	session->sht.proc_info = iscsi_proc_info;
	session->sht.info = iscsi_info;
	session->sht.queuecommand = iscsi_queuecommand;
	session->sht.can_queue = 128;
	session->sht.sg_tablesize = 128;
	session->sht.max_sectors = 128;
	session->sht.cmd_per_lun = 128;
	session->sht.this_id = (uint32_t)(unsigned long)session;
	session->sht.use_clustering = DISABLE_CLUSTERING;
	session->sht.eh_abort_handler = iscsi_eh_abort;
	session->sht.proc_name = kmalloc(10, GFP_KERNEL);
	snprintf(session->sht.proc_name, 10, "iscsi%d", host_no);

	if ((host = scsi_host_alloc(&session->sht, sizeof(void*))) == NULL) {
		printk("can not allocate host_no %d\n", host_no);
		goto host_alloc_fault;
	}
	host->host_no = session->id = host_no;
	host->max_id = 1;
	host->max_channel  = 0;
	*(unsigned long*)host->hostdata = (unsigned long)session;
	session->host = host;
	session->state = ISCSI_STATE_LOGGED_IN;
	session->imm_max = ISCSI_IMM_CMDS_MAX;
	session->cmds_max = session->sht.can_queue + 1;
	session->cmdsn = initial_cmdsn;
	session->exp_cmdsn = initial_cmdsn + 1;
	session->max_cmdsn = initial_cmdsn + 1;
	session->handle = handle;

	session->max_r2t = 1;

	if ((res=scsi_add_host(host, NULL))) {
		printk("can not add host_no %d (%d)\n", host_no, res);
		goto add_host_fault;
	}

	/* initialize SCSI PDU commands pool */
	if (iscsi_pool_init(&session->cmdpool, session->cmds_max,
		(void***)&session->cmds, sizeof(iscsi_cmd_task_t),
		session->host->host_lock)) {
		goto cmdpool_alloc_fault;
	}
	/* pre-format cmds pool with ITT */
	for (cmd_i=0; cmd_i<session->cmds_max; cmd_i++) {
		session->cmds[cmd_i]->itt = cmd_i;
	}

	spin_lock_init(&session->conn_lock);
	INIT_LIST_HEAD(&session->connections);

	/* initialize immediate commands pool */
	if (iscsi_pool_init(&session->immpool, session->imm_max,
		(void***)&session->imm_cmds, sizeof(iscsi_mgmt_task_t),
		session->host->host_lock)) {
		goto immpool_alloc_fault;
	}
	/* pre-format immediate cmds pool with ITT */
	for (cmd_i=0; cmd_i<session->imm_max; cmd_i++) {
		session->imm_cmds[cmd_i]->itt = ISCSI_IMM_ITT_OFFSET + cmd_i;
		init_MUTEX_LOCKED(&session->imm_cmds[cmd_i]->xmitsema);
	}

	if (iscsi_r2tpool_alloc(session)) {
		goto r2tpool_alloc_fault;
	}

	return session;

r2tpool_alloc_fault:
	iscsi_pool_free(&session->immpool, (void**)session->imm_cmds);
immpool_alloc_fault:
	iscsi_pool_free(&session->cmdpool, (void**)session->cmds);
cmdpool_alloc_fault:
	scsi_remove_host(host);
add_host_fault:
	scsi_host_put(host);
host_alloc_fault:
	kfree(session->sht.proc_name);
	kfree(session);
	return NULL;
}

static void
iscsi_session_destroy(iscsi_snx_h snxh)
{
	int cmd_i;
	struct list_head *lh, *n;
	iscsi_session_t *session = snxh;

	for (cmd_i=0; cmd_i<session->cmds_max; cmd_i++) {
		iscsi_cmd_task_t *ctask = session->cmds[cmd_i];
		list_for_each_safe(lh, n, &ctask->dataqueue) {
			iscsi_data_task_t *dtask;
			dtask = list_entry(lh, iscsi_data_task_t, item);
			if (dtask) {
				list_del(&dtask->item);
				mempool_free(dtask, ctask->datapool);
			}
		}
	}

	iscsi_r2tpool_free(session);
	iscsi_pool_free(&session->cmdpool, (void**)session->cmds);
	scsi_remove_host(session->host);
	scsi_host_put(session->host);
	kfree(session->sht.proc_name);
	kfree(session);
}

static int
iscsi_set_param(iscsi_cnx_h cnxh, iscsi_param_e param, int value)
{
	iscsi_conn_t *conn = cnxh;
	iscsi_session_t *session = conn->session;

	if (conn->c_stage == ISCSI_CNX_INITIAL_STAGE) {
		switch(param) {
		case ISCSI_PARAM_MAX_RECV_DLENGTH: {
			char *saveptr = conn->data;

			if (value <= PAGE_SIZE)
				conn->data = kmalloc(value, GFP_KERNEL);
			else
				conn->data = (void*)__get_free_pages(GFP_KERNEL,
					get_order(value));
			if (conn->data == NULL) {
				conn->data = saveptr;
				return -ENOMEM;
			}
			if (conn->max_recv_dlength <= PAGE_SIZE)
				kfree(saveptr);
			else
				free_pages((unsigned long)saveptr,
					get_order(conn->max_recv_dlength));
			conn->max_recv_dlength = value;
		}
		break;
		case ISCSI_PARAM_MAX_XMIT_DLENGTH:
			conn->max_xmit_dlength = value;
			break;
		case ISCSI_PARAM_HDRDGST_EN:
			conn->hdrdgst_en = value;
			conn->hdr_size = sizeof(iscsi_hdr_t);
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
			if (conn->datadgst_en) {
				return -EPERM;
			}
			conn->datadgst_en = value;
			break;
		case ISCSI_PARAM_INITIAL_R2T_EN:
			session->initial_r2t_en = value;
			break;
		case ISCSI_PARAM_MAX_R2T:
			session->max_r2t = value;
			iscsi_r2tpool_free(session);
			if (iscsi_r2tpool_alloc(session)) {
				return -ENOMEM;
			}
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
		printk("iSCSI: can not change parameter [%d]\n", param);
	}

	return 0;
}

int
iscsi_tcp_register(iscsi_ops_t *ops, iscsi_caps_t *caps)
{
	taskcache = kmem_cache_create("iscsi_taskcache",
			sizeof(iscsi_union_task_t), 0, 0, NULL, NULL);
	if (taskcache == NULL) {
		printk("not enough memory to allocate iscsi_taskcache\n");
		return -ENOMEM;
	}

	ops->create_session = iscsi_session_create;
	ops->destroy_session = iscsi_session_destroy;
	ops->create_cnx = iscsi_conn_create;
	ops->bind_cnx = iscsi_conn_bind;
	ops->destroy_cnx = iscsi_conn_destroy;
	ops->set_param = iscsi_set_param;
	ops->start_cnx = iscsi_conn_start;
	ops->stop_cnx = iscsi_conn_stop;
	ops->send_immpdu = iscsi_send_immpdu;

	caps->flags = CAP_RECOVERY_L0 | CAP_MULTI_R2T;

	return 0;
}

void
iscsi_tcp_unregister(void)
{
	kmem_cache_destroy(taskcache);
}
