/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019 Cisco Systems, Inc.  All rights reserved.
 */

#include <unistd.h>
#include <errno.h>

#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_eal_memconfig.h>
#include <rte_ethdev_vdev.h>
#include <rte_mbuf.h>

#include <rte_prefetch.h>

#include "rte_eth_memif.h"
#include "memif_rxtx.h"

static void *
memif_get_buffer(struct pmd_process_private *proc_private, memif_desc_t *d)
{
	return ((uint8_t *)proc_private->regions[d->region]->addr + d->offset);
}

/* Free mbufs received by master */
static void
memif_free_stored_mbufs(struct pmd_process_private *proc_private, struct memif_queue *mq)
{
	uint16_t mask = (1 << mq->log2_ring_size) - 1;
	memif_ring_t *ring = memif_get_ring_from_queue(proc_private, mq);

	/* FIXME: improve performance */
	while (mq->last_tail != ring->tail) {
		RTE_MBUF_PREFETCH_TO_FREE(mq->buffers[(mq->last_tail + 1) & mask]);
		/* Decrement refcnt and free mbuf. (current segment) */
		rte_mbuf_refcnt_update(mq->buffers[mq->last_tail & mask], -1);
		rte_pktmbuf_free_seg(mq->buffers[mq->last_tail & mask]);
		mq->last_tail++;
	}
}

static int
memif_pktmbuf_chain(struct rte_mbuf *head, struct rte_mbuf *cur_tail,
		    struct rte_mbuf *tail)
{
	/* Check for number-of-segments-overflow */
	if (unlikely(head->nb_segs + tail->nb_segs > RTE_MBUF_MAX_NB_SEGS))
		return -EOVERFLOW;

	/* Chain 'tail' onto the old tail */
	cur_tail->next = tail;

	/* accumulate number of segments and total length. */
	head->nb_segs = (uint16_t)(head->nb_segs + tail->nb_segs);

	tail->pkt_len = tail->data_len;
	head->pkt_len += tail->pkt_len;

	return 0;
}

uint16_t
eth_memif_rx(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts)
{
	struct memif_queue *mq = queue;
	struct pmd_internals *pmd = rte_eth_devices[mq->in_port].data->dev_private;
	struct pmd_process_private *proc_private =
		rte_eth_devices[mq->in_port].process_private;
	memif_ring_t *ring = memif_get_ring_from_queue(proc_private, mq);
	uint16_t cur_slot, last_slot, n_slots, ring_size, mask, s0;
	uint16_t n_rx_pkts = 0;
	uint16_t mbuf_size = rte_pktmbuf_data_room_size(mq->mempool) -
		RTE_PKTMBUF_HEADROOM;
	uint16_t src_len, src_off, dst_len, dst_off, cp_len;
	memif_ring_type_t type = mq->type;
	memif_desc_t *d0;
	struct rte_mbuf *mbuf, *mbuf_head, *mbuf_tail;
	uint64_t b;
	ssize_t size __rte_unused;
	uint16_t head;
	int ret;
	struct rte_eth_link link;

	if (unlikely((pmd->flags & ETH_MEMIF_FLAG_CONNECTED) == 0))
		return 0;
	if (unlikely(ring == NULL)) {
		/* Secondary process will attempt to request regions. */
		rte_eth_link_get(mq->in_port, &link);
		return 0;
	}

	/* consume interrupt */
	if ((ring->flags & MEMIF_RING_FLAG_MASK_INT) == 0)
		size = read(mq->intr_handle.fd, &b, sizeof(b));

	ring_size = 1 << mq->log2_ring_size;
	mask = ring_size - 1;

	cur_slot = (type == MEMIF_RING_S2M) ? mq->last_head : mq->last_tail;
	last_slot = (type == MEMIF_RING_S2M) ? ring->head : ring->tail;
	if (cur_slot == last_slot)
		goto refill;
	n_slots = last_slot - cur_slot;

	while (n_slots && n_rx_pkts < nb_pkts) {
		mbuf_head = rte_pktmbuf_alloc(mq->mempool);
		if (unlikely(mbuf_head == NULL))
			goto no_free_bufs;
		mbuf = mbuf_head;
		mbuf->port = mq->in_port;

next_slot:
		s0 = cur_slot & mask;
		d0 = &ring->desc[s0];

		src_len = d0->length;
		dst_off = 0;
		src_off = 0;

		do {
			dst_len = mbuf_size - dst_off;
			if (dst_len == 0) {
				dst_off = 0;
				dst_len = mbuf_size;

				/* store pointer to tail */
				mbuf_tail = mbuf;
				mbuf = rte_pktmbuf_alloc(mq->mempool);
				if (unlikely(mbuf == NULL))
					goto no_free_bufs;
				mbuf->port = mq->in_port;
				ret = memif_pktmbuf_chain(mbuf_head, mbuf_tail, mbuf);
				if (unlikely(ret < 0)) {
					MIF_LOG(ERR, "number-of-segments-overflow");
					rte_pktmbuf_free(mbuf);
					goto no_free_bufs;
				}
			}
			cp_len = RTE_MIN(dst_len, src_len);

			rte_pktmbuf_data_len(mbuf) += cp_len;
			rte_pktmbuf_pkt_len(mbuf) = rte_pktmbuf_data_len(mbuf);
			if (mbuf != mbuf_head)
				rte_pktmbuf_pkt_len(mbuf_head) += cp_len;

			memcpy(rte_pktmbuf_mtod_offset(mbuf, void *, dst_off),
			       (uint8_t *)memif_get_buffer(proc_private, d0) + src_off,
			       cp_len);

			src_off += cp_len;
			dst_off += cp_len;
			src_len -= cp_len;
		} while (src_len);

		cur_slot++;
		n_slots--;

		if (d0->flags & MEMIF_DESC_FLAG_NEXT)
			goto next_slot;

		mq->n_bytes += rte_pktmbuf_pkt_len(mbuf_head);
		*bufs++ = mbuf_head;
		n_rx_pkts++;
	}

no_free_bufs:
	if (type == MEMIF_RING_S2M) {
		rte_mb();
		ring->tail = cur_slot;
		mq->last_head = cur_slot;
	} else {
		mq->last_tail = cur_slot;
	}

refill:
	if (type == MEMIF_RING_M2S) {
		head = ring->head;
		n_slots = ring_size - head + mq->last_tail;

		while (n_slots--) {
			s0 = head++ & mask;
			d0 = &ring->desc[s0];
			d0->length = pmd->run.pkt_buffer_size;
		}
		rte_mb();
		ring->head = head;
	}

	mq->n_pkts += n_rx_pkts;
	return n_rx_pkts;
}

uint16_t
eth_memif_rx_zc(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts)
{
	struct memif_queue *mq = queue;
	struct pmd_internals *pmd = rte_eth_devices[mq->in_port].data->dev_private;
	struct pmd_process_private *proc_private =
		rte_eth_devices[mq->in_port].process_private;
	memif_ring_t *ring = memif_get_ring_from_queue(proc_private, mq);
	uint16_t cur_slot, last_slot, n_slots, ring_size, mask, s0, head;
	uint16_t n_rx_pkts = 0;
	memif_desc_t *d0;
	struct rte_mbuf *mbuf, *mbuf_tail;
	struct rte_mbuf *mbuf_head = NULL;
	int ret;
	struct rte_eth_link link;

	if (unlikely((pmd->flags & ETH_MEMIF_FLAG_CONNECTED) == 0))
		return 0;
	if (unlikely(ring == NULL)) {
		/* Secondary process will attempt to request regions. */
		rte_eth_link_get(mq->in_port, &link);
		return 0;
	}

	/* consume interrupt */
	if ((ring->flags & MEMIF_RING_FLAG_MASK_INT) == 0) {
		uint64_t b;
		ssize_t size __rte_unused;
		size = read(mq->intr_handle.fd, &b, sizeof(b));
	}

	ring_size = 1 << mq->log2_ring_size;
	mask = ring_size - 1;

	cur_slot = mq->last_tail;
	last_slot = ring->tail;
	if (cur_slot == last_slot)
		goto refill;
	n_slots = last_slot - cur_slot;

	while (n_slots && n_rx_pkts < nb_pkts) {
		s0 = cur_slot & mask;

		d0 = &ring->desc[s0];
		mbuf_head = mq->buffers[s0];
		mbuf = mbuf_head;

next_slot:
		/* prefetch next descriptor */
		if (n_rx_pkts + 1 < nb_pkts)
			rte_prefetch0(&ring->desc[(cur_slot + 1) & mask]);

		mbuf->port = mq->in_port;
		rte_pktmbuf_data_len(mbuf) = d0->length;
		rte_pktmbuf_pkt_len(mbuf) = rte_pktmbuf_data_len(mbuf);

		mq->n_bytes += rte_pktmbuf_data_len(mbuf);

		cur_slot++;
		n_slots--;
		if (d0->flags & MEMIF_DESC_FLAG_NEXT) {
			s0 = cur_slot & mask;
			d0 = &ring->desc[s0];
			mbuf_tail = mbuf;
			mbuf = mq->buffers[s0];
			ret = memif_pktmbuf_chain(mbuf_head, mbuf_tail, mbuf);
			if (unlikely(ret < 0)) {
				MIF_LOG(ERR, "number-of-segments-overflow");
				goto refill;
			}
			goto next_slot;
		}

		*bufs++ = mbuf_head;
		n_rx_pkts++;
	}

	mq->last_tail = cur_slot;

/* Supply master with new buffers */
refill:
	head = ring->head;
	n_slots = ring_size - head + mq->last_tail;

	if (n_slots < 32)
		goto no_free_mbufs;

	ret = rte_pktmbuf_alloc_bulk(mq->mempool, &mq->buffers[head & mask], n_slots);
	if (unlikely(ret < 0))
		goto no_free_mbufs;

	while (n_slots--) {
		s0 = head++ & mask;
		if (n_slots > 0)
			rte_prefetch0(mq->buffers[head & mask]);
		d0 = &ring->desc[s0];
		/* store buffer header */
		mbuf = mq->buffers[s0];
		/* populate descriptor */
		d0->length = rte_pktmbuf_data_room_size(mq->mempool) -
				RTE_PKTMBUF_HEADROOM;
		d0->region = 1;
		d0->offset = rte_pktmbuf_mtod(mbuf, uint8_t *) -
			(uint8_t *)proc_private->regions[d0->region]->addr;
	}
no_free_mbufs:
	rte_mb();
	ring->head = head;

	mq->n_pkts += n_rx_pkts;

	return n_rx_pkts;
}

uint16_t
eth_memif_tx(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts)
{
	struct memif_queue *mq = queue;
	struct pmd_internals *pmd = rte_eth_devices[mq->in_port].data->dev_private;
	struct pmd_process_private *proc_private =
		rte_eth_devices[mq->in_port].process_private;
	memif_ring_t *ring = memif_get_ring_from_queue(proc_private, mq);
	uint16_t slot, saved_slot, n_free, ring_size, mask, n_tx_pkts = 0;
	uint16_t src_len, src_off, dst_len, dst_off, cp_len;
	memif_ring_type_t type = mq->type;
	memif_desc_t *d0;
	struct rte_mbuf *mbuf;
	struct rte_mbuf *mbuf_head;
	uint64_t a;
	ssize_t size;
	struct rte_eth_link link;

	if (unlikely((pmd->flags & ETH_MEMIF_FLAG_CONNECTED) == 0))
		return 0;
	if (unlikely(ring == NULL)) {
		/* Secondary process will attempt to request regions. */
		rte_eth_link_get(mq->in_port, &link);
		return 0;
	}

	ring_size = 1 << mq->log2_ring_size;
	mask = ring_size - 1;

	n_free = ring->tail - mq->last_tail;
	mq->last_tail += n_free;
	slot = (type == MEMIF_RING_S2M) ? ring->head : ring->tail;

	if (type == MEMIF_RING_S2M)
		n_free = ring_size - ring->head + mq->last_tail;
	else
		n_free = ring->head - ring->tail;

	while (n_tx_pkts < nb_pkts && n_free) {
		mbuf_head = *bufs++;
		mbuf = mbuf_head;

		saved_slot = slot;
		d0 = &ring->desc[slot & mask];
		dst_off = 0;
		dst_len = (type == MEMIF_RING_S2M) ?
			pmd->run.pkt_buffer_size : d0->length;

next_in_chain:
		src_off = 0;
		src_len = rte_pktmbuf_data_len(mbuf);

		while (src_len) {
			if (dst_len == 0) {
				if (n_free) {
					slot++;
					n_free--;
					d0->flags |= MEMIF_DESC_FLAG_NEXT;
					d0 = &ring->desc[slot & mask];
					dst_off = 0;
					dst_len = (type == MEMIF_RING_S2M) ?
					    pmd->run.pkt_buffer_size : d0->length;
					d0->flags = 0;
				} else {
					slot = saved_slot;
					goto no_free_slots;
				}
			}
			cp_len = RTE_MIN(dst_len, src_len);

			memcpy((uint8_t *)memif_get_buffer(proc_private, d0) + dst_off,
			       rte_pktmbuf_mtod_offset(mbuf, void *, src_off),
			       cp_len);

			mq->n_bytes += cp_len;
			src_off += cp_len;
			dst_off += cp_len;
			src_len -= cp_len;
			dst_len -= cp_len;

			d0->length = dst_off;
		}

		if (rte_pktmbuf_is_contiguous(mbuf) == 0) {
			mbuf = mbuf->next;
			goto next_in_chain;
		}

		n_tx_pkts++;
		slot++;
		n_free--;
		rte_pktmbuf_free(mbuf_head);
	}

no_free_slots:
	rte_mb();
	if (type == MEMIF_RING_S2M)
		ring->head = slot;
	else
		ring->tail = slot;

	if ((ring->flags & MEMIF_RING_FLAG_MASK_INT) == 0) {
		a = 1;
		size = write(mq->intr_handle.fd, &a, sizeof(a));
		if (unlikely(size < 0)) {
			MIF_LOG(WARNING,
				"Failed to send interrupt. %s", strerror(errno));
		}
	}

	mq->n_err += nb_pkts - n_tx_pkts;
	mq->n_pkts += n_tx_pkts;
	return n_tx_pkts;
}

static inline int
memif_tx_one_zc(struct pmd_process_private *proc_private, struct memif_queue *mq,
		memif_ring_t *ring, struct rte_mbuf *mbuf, const uint16_t mask,
		uint16_t slot, uint16_t n_free)
{
	memif_desc_t *d0;
	int used_slots = 1;

next_in_chain:
	/* store pointer to mbuf to free it later */
	mq->buffers[slot & mask] = mbuf;
	/* Increment refcnt to make sure the buffer is not freed before master
	 * receives it. (current segment)
	 */
	rte_mbuf_refcnt_update(mbuf, 1);
	/* populate descriptor */
	d0 = &ring->desc[slot & mask];
	d0->length = rte_pktmbuf_data_len(mbuf);
	/* FIXME: get region index */
	d0->region = 1;
	d0->offset = rte_pktmbuf_mtod(mbuf, uint8_t *) -
		(uint8_t *)proc_private->regions[d0->region]->addr;
	d0->flags = 0;

	/* check if buffer is chained */
	if (rte_pktmbuf_is_contiguous(mbuf) == 0) {
		if (n_free < 2)
			return 0;
		/* mark buffer as chained */
		d0->flags |= MEMIF_DESC_FLAG_NEXT;
		/* advance mbuf */
		mbuf = mbuf->next;
		/* update counters */
		used_slots++;
		slot++;
		n_free--;
		goto next_in_chain;
	}
	return used_slots;
}

uint16_t
eth_memif_tx_zc(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts)
{
	struct memif_queue *mq = queue;
	struct pmd_internals *pmd = rte_eth_devices[mq->in_port].data->dev_private;
	struct pmd_process_private *proc_private =
		rte_eth_devices[mq->in_port].process_private;
	memif_ring_t *ring = memif_get_ring_from_queue(proc_private, mq);
	uint16_t slot, n_free, ring_size, mask, n_tx_pkts = 0;
	memif_ring_type_t type = mq->type;
	struct rte_eth_link link;

	if (unlikely((pmd->flags & ETH_MEMIF_FLAG_CONNECTED) == 0))
		return 0;
	if (unlikely(ring == NULL)) {
		/* Secondary process will attempt to request regions. */
		rte_eth_link_get(mq->in_port, &link);
		return 0;
	}

	ring_size = 1 << mq->log2_ring_size;
	mask = ring_size - 1;

	/* free mbufs received by master */
	memif_free_stored_mbufs(proc_private, mq);

	/* ring type always MEMIF_RING_S2M */
	slot = ring->head;
	n_free = ring_size - ring->head + mq->last_tail;

	int used_slots;

	while (n_free && (n_tx_pkts < nb_pkts)) {
		while ((n_free > 4) && ((nb_pkts - n_tx_pkts) > 4)) {
			if ((nb_pkts - n_tx_pkts) > 8) {
				rte_prefetch0(*bufs + 4);
				rte_prefetch0(*bufs + 5);
				rte_prefetch0(*bufs + 6);
				rte_prefetch0(*bufs + 7);
			}
			used_slots = memif_tx_one_zc(proc_private, mq, ring, *bufs++,
				mask, slot, n_free);
			if (unlikely(used_slots < 1))
				goto no_free_slots;
			n_tx_pkts++;
			slot += used_slots;
			n_free -= used_slots;

			used_slots = memif_tx_one_zc(proc_private, mq, ring, *bufs++,
				mask, slot, n_free);
			if (unlikely(used_slots < 1))
				goto no_free_slots;
			n_tx_pkts++;
			slot += used_slots;
			n_free -= used_slots;

			used_slots = memif_tx_one_zc(proc_private, mq, ring, *bufs++,
				mask, slot, n_free);
			if (unlikely(used_slots < 1))
				goto no_free_slots;
			n_tx_pkts++;
			slot += used_slots;
			n_free -= used_slots;

			used_slots = memif_tx_one_zc(proc_private, mq, ring, *bufs++,
				mask, slot, n_free);
			if (unlikely(used_slots < 1))
				goto no_free_slots;
			n_tx_pkts++;
			slot += used_slots;
			n_free -= used_slots;
		}
		used_slots = memif_tx_one_zc(proc_private, mq, ring, *bufs++,
			mask, slot, n_free);
		if (unlikely(used_slots < 1))
			goto no_free_slots;
		n_tx_pkts++;
		slot += used_slots;
		n_free -= used_slots;
	}

no_free_slots:
	rte_mb();
	/* update ring pointers */
	if (type == MEMIF_RING_S2M)
		ring->head = slot;
	else
		ring->tail = slot;

	/* Send interrupt, if enabled. */
	if ((ring->flags & MEMIF_RING_FLAG_MASK_INT) == 0) {
		uint64_t a = 1;
		ssize_t size = write(mq->intr_handle.fd, &a, sizeof(a));
		if (unlikely(size < 0)) {
			MIF_LOG(WARNING,
				"Failed to send interrupt. %s", strerror(errno));
		}
	}

	/* increment queue counters */
	mq->n_err += nb_pkts - n_tx_pkts;
	mq->n_pkts += n_tx_pkts;

	return n_tx_pkts;
}
