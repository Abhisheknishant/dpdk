/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <rte_net.h>

#include "virtio_logs.h"
#include "virtio_ethdev.h"
#include "virtio_pci.h"
#include "virtqueue.h"

#define REF_CNT_OFFSET 16
#define SEG_NUM_OFFSET 32
#define BATCH_REARM_DATA (1ULL << SEG_NUM_OFFSET | \
			  1ULL << REF_CNT_OFFSET | \
			  RTE_PKTMBUF_HEADROOM)
#define PACKED_FLAGS_MASK (1ULL << 55 | 1ULL << 63)

#define PACKED_BATCH_SIZE (RTE_CACHE_LINE_SIZE / \
	sizeof(struct vring_packed_desc))
#define PACKED_BATCH_MASK (PACKED_BATCH_SIZE - 1)

#ifdef VIRTIO_GCC_UNROLL_PRAGMA
#define virtio_for_each_try_unroll(iter, val, size) _Pragma("GCC unroll 4") \
	for (iter = val; iter < size; iter++)
#endif

#ifdef VIRTIO_CLANG_UNROLL_PRAGMA
#define virtio_for_each_try_unroll(iter, val, size) _Pragma("unroll 4") \
	for (iter = val; iter < size; iter++)
#endif

#ifdef VIRTIO_ICC_UNROLL_PRAGMA
#define virtio_for_each_try_unroll(iter, val, size) _Pragma("unroll (4)") \
	for (iter = val; iter < size; iter++)
#endif

#ifndef virtio_for_each_try_unroll
#define virtio_for_each_try_unroll(iter, val, num) \
	for (iter = val; iter < num; iter++)
#endif

static void
virtio_xmit_cleanup_packed_vec(struct virtqueue *vq)
{
	struct vring_packed_desc *desc = vq->vq_packed.ring.desc;
	struct vq_desc_extra *dxp;
	uint16_t used_idx, id, curr_id, free_cnt = 0;
	uint16_t size = vq->vq_nentries;
	struct rte_mbuf *mbufs[size];
	uint16_t nb_mbuf = 0, i;

	used_idx = vq->vq_used_cons_idx;

	if (desc_is_used(&desc[used_idx], vq))
		id = desc[used_idx].id;
	else
		return;

	do {
		curr_id = used_idx;
		dxp = &vq->vq_descx[used_idx];
		used_idx += dxp->ndescs;
		free_cnt += dxp->ndescs;

		if (dxp->cookie != NULL) {
			mbufs[nb_mbuf] = dxp->cookie;
			dxp->cookie = NULL;
			nb_mbuf++;
		}

		if (used_idx >= size) {
			used_idx -= size;
			vq->vq_packed.used_wrap_counter ^= 1;
		}
	} while (curr_id != id);

	for (i = 0; i < nb_mbuf; i++)
		rte_pktmbuf_free(mbufs[i]);

	vq->vq_used_cons_idx = used_idx;
	vq->vq_free_cnt += free_cnt;
}

static inline void
virtio_update_batch_stats(struct virtnet_stats *stats,
			  uint16_t pkt_len1,
			  uint16_t pkt_len2,
			  uint16_t pkt_len3,
			  uint16_t pkt_len4)
{
	stats->bytes += pkt_len1;
	stats->bytes += pkt_len2;
	stats->bytes += pkt_len3;
	stats->bytes += pkt_len4;
}

static inline int
virtqueue_enqueue_batch_packed_vec(struct virtnet_tx *txvq,
				   struct rte_mbuf **tx_pkts)
{
	struct virtqueue *vq = txvq->vq;
	uint16_t head_size = vq->hw->vtnet_hdr_size;
	struct vq_desc_extra *dxps[PACKED_BATCH_SIZE];
	uint16_t idx = vq->vq_avail_idx;
	uint64_t descs[PACKED_BATCH_SIZE];
	struct virtio_net_hdr *hdrs[PACKED_BATCH_SIZE];
	uint16_t i;

	if (vq->vq_avail_idx & PACKED_BATCH_MASK)
		return -1;

	/* Load four mbufs rearm data */
	__m256i mbufs = _mm256_set_epi64x(
			*tx_pkts[3]->rearm_data,
			*tx_pkts[2]->rearm_data,
			*tx_pkts[1]->rearm_data,
			*tx_pkts[0]->rearm_data);

	/* hdr_room=128, refcnt=1 and nb_segs=1 */
	__m256i mbuf_ref = _mm256_set_epi64x(
			BATCH_REARM_DATA, BATCH_REARM_DATA,
			BATCH_REARM_DATA, BATCH_REARM_DATA);

	/* Check hdr_room,refcnt and nb_segs */
	uint16_t cmp = _mm256_cmpneq_epu16_mask(mbufs, mbuf_ref);
	if (cmp & 0x7777)
		return -1;

	virtio_for_each_try_unroll(i, 0, PACKED_BATCH_SIZE) {
		dxps[i] = &vq->vq_descx[idx + i];
		dxps[i]->ndescs = 1;
		dxps[i]->cookie = tx_pkts[i];
	}

	virtio_for_each_try_unroll(i, 0, PACKED_BATCH_SIZE) {
		rte_pktmbuf_prepend(tx_pkts[i], head_size);
		tx_pkts[i]->pkt_len -= head_size;
	}

	virtio_for_each_try_unroll(i, 0, PACKED_BATCH_SIZE)
		descs[i] = (uint64_t)tx_pkts[i]->data_len |
		(uint64_t)(idx + i) << 32 |
		(uint64_t)vq->vq_packed.cached_flags << 48;

	__m512i new_descs = _mm512_set_epi64(
			descs[3], VIRTIO_MBUF_DATA_DMA_ADDR(tx_pkts[3], vq),
			descs[2], VIRTIO_MBUF_DATA_DMA_ADDR(tx_pkts[2], vq),
			descs[1], VIRTIO_MBUF_DATA_DMA_ADDR(tx_pkts[1], vq),
			descs[0], VIRTIO_MBUF_DATA_DMA_ADDR(tx_pkts[0], vq));

	virtio_for_each_try_unroll(i, 0, PACKED_BATCH_SIZE)
		hdrs[i] = rte_pktmbuf_mtod_offset(tx_pkts[i],
				struct virtio_net_hdr *, -head_size);

	if (!vq->hw->has_tx_offload) {
		virtio_for_each_try_unroll(i, 0, PACKED_BATCH_SIZE)
			virtqueue_clear_net_hdr(hdrs[i]);
	} else {
		virtio_for_each_try_unroll(i, 0, PACKED_BATCH_SIZE)
			virtqueue_xmit_offload(hdrs[i], tx_pkts[i], true);
	}

	/* Enqueue Packet buffers */
	rte_smp_wmb();
	_mm512_storeu_si512((void *)&vq->vq_packed.ring.desc[idx], new_descs);

	virtio_update_batch_stats(&txvq->stats, tx_pkts[0]->pkt_len,
			tx_pkts[1]->pkt_len, tx_pkts[2]->pkt_len,
			tx_pkts[3]->pkt_len);

	vq->vq_avail_idx += PACKED_BATCH_SIZE;
	vq->vq_free_cnt -= PACKED_BATCH_SIZE;

	if (vq->vq_avail_idx >= vq->vq_nentries) {
		vq->vq_avail_idx -= vq->vq_nentries;
		vq->vq_packed.cached_flags ^=
			VRING_PACKED_DESC_F_AVAIL_USED;
	}

	return 0;
}

static inline int
virtqueue_enqueue_single_packed_vec(struct virtnet_tx *txvq,
				    struct rte_mbuf *txm)
{
	struct virtqueue *vq = txvq->vq;
	struct virtio_hw *hw = vq->hw;
	uint16_t hdr_size = hw->vtnet_hdr_size;
	uint16_t slots, can_push;
	int16_t need;

	/* How many main ring entries are needed to this Tx?
	 * any_layout => number of segments
	 * default    => number of segments + 1
	 */
	can_push = rte_mbuf_refcnt_read(txm) == 1 &&
		   RTE_MBUF_DIRECT(txm) &&
		   txm->nb_segs == 1 &&
		   rte_pktmbuf_headroom(txm) >= hdr_size;

	slots = txm->nb_segs + !can_push;
	need = slots - vq->vq_free_cnt;

	/* Positive value indicates it need free vring descriptors */
	if (unlikely(need > 0)) {
		virtio_xmit_cleanup_packed_vec(vq);
		need = slots - vq->vq_free_cnt;
		if (unlikely(need > 0)) {
			PMD_TX_LOG(ERR,
				   "No free tx descriptors to transmit");
			return -1;
		}
	}

	/* Enqueue Packet buffers */
	virtqueue_enqueue_xmit_packed(txvq, txm, slots, can_push, 1);

	txvq->stats.bytes += txm->pkt_len;
	return 0;
}

uint16_t
virtio_xmit_pkts_packed_vec(void *tx_queue, struct rte_mbuf **tx_pkts,
			uint16_t nb_pkts)
{
	struct virtnet_tx *txvq = tx_queue;
	struct virtqueue *vq = txvq->vq;
	struct virtio_hw *hw = vq->hw;
	uint16_t nb_tx = 0;
	uint16_t remained;

	if (unlikely(hw->started == 0 && tx_pkts != hw->inject_pkts))
		return nb_tx;

	if (unlikely(nb_pkts < 1))
		return nb_pkts;

	PMD_TX_LOG(DEBUG, "%d packets to xmit", nb_pkts);

	if (vq->vq_free_cnt <= vq->vq_nentries - vq->vq_free_thresh)
		virtio_xmit_cleanup_packed_vec(vq);

	remained = RTE_MIN(nb_pkts, vq->vq_free_cnt);

	while (remained) {
		if (remained >= PACKED_BATCH_SIZE) {
			if (!virtqueue_enqueue_batch_packed_vec(txvq,
						&tx_pkts[nb_tx])) {
				nb_tx += PACKED_BATCH_SIZE;
				remained -= PACKED_BATCH_SIZE;
				continue;
			}
		}
		if (!virtqueue_enqueue_single_packed_vec(txvq,
					tx_pkts[nb_tx])) {
			nb_tx++;
			remained--;
			continue;
		}
		break;
	};

	txvq->stats.packets += nb_tx;

	if (likely(nb_tx)) {
		if (unlikely(virtqueue_kick_prepare_packed(vq))) {
			virtqueue_notify(vq);
			PMD_TX_LOG(DEBUG, "Notified backend after xmit");
		}
	}

	return nb_tx;
}

/* Optionally fill offload information in structure */
static inline int
virtio_vec_rx_offload(struct rte_mbuf *m, struct virtio_net_hdr *hdr)
{
	struct rte_net_hdr_lens hdr_lens;
	uint32_t hdrlen, ptype;
	int l4_supported = 0;

	/* nothing to do */
	if (hdr->flags == 0)
		return 0;

	/* GSO not support in vec path, skip check */
	m->ol_flags |= PKT_RX_IP_CKSUM_UNKNOWN;

	ptype = rte_net_get_ptype(m, &hdr_lens, RTE_PTYPE_ALL_MASK);
	m->packet_type = ptype;
	if ((ptype & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_TCP ||
	    (ptype & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_UDP ||
	    (ptype & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_SCTP)
		l4_supported = 1;

	if (hdr->flags & VIRTIO_NET_HDR_F_NEEDS_CSUM) {
		hdrlen = hdr_lens.l2_len + hdr_lens.l3_len + hdr_lens.l4_len;
		if (hdr->csum_start <= hdrlen && l4_supported) {
			m->ol_flags |= PKT_RX_L4_CKSUM_NONE;
		} else {
			/* Unknown proto or tunnel, do sw cksum. We can assume
			 * the cksum field is in the first segment since the
			 * buffers we provided to the host are large enough.
			 * In case of SCTP, this will be wrong since it's a CRC
			 * but there's nothing we can do.
			 */
			uint16_t csum = 0, off;

			rte_raw_cksum_mbuf(m, hdr->csum_start,
				rte_pktmbuf_pkt_len(m) - hdr->csum_start,
				&csum);
			if (likely(csum != 0xffff))
				csum = ~csum;
			off = hdr->csum_offset + hdr->csum_start;
			if (rte_pktmbuf_data_len(m) >= off + 1)
				*rte_pktmbuf_mtod_offset(m, uint16_t *,
					off) = csum;
		}
	} else if (hdr->flags & VIRTIO_NET_HDR_F_DATA_VALID && l4_supported) {
		m->ol_flags |= PKT_RX_L4_CKSUM_GOOD;
	}

	return 0;
}

static uint16_t
virtqueue_dequeue_batch_packed_vec(struct virtnet_rx *rxvq,
				   struct rte_mbuf **rx_pkts)
{
	struct virtqueue *vq = rxvq->vq;
	struct virtio_hw *hw = vq->hw;
	uint16_t hdr_size = hw->vtnet_hdr_size;
	struct virtio_net_hdr *hdrs[PACKED_BATCH_SIZE];
	uint64_t addrs[PACKED_BATCH_SIZE << 1];
	uint16_t id = vq->vq_used_cons_idx;
	uint8_t desc_stats;
	uint16_t i;
	void *desc_addr;

	if (id & PACKED_BATCH_MASK)
		return -1;

	/* only care avail/used bits */
	__m512i desc_flags = _mm512_set_epi64(
			PACKED_FLAGS_MASK, 0x0,
			PACKED_FLAGS_MASK, 0x0,
			PACKED_FLAGS_MASK, 0x0,
			PACKED_FLAGS_MASK, 0x0);

	desc_addr = &vq->vq_packed.ring.desc[id];
	rte_smp_rmb();
	__m512i packed_desc = _mm512_loadu_si512(desc_addr);
	__m512i flags_mask  = _mm512_maskz_and_epi64(0xff, packed_desc,
			desc_flags);

	__m512i used_flags;
	if (vq->vq_packed.used_wrap_counter) {
		used_flags = _mm512_set_epi64(
				PACKED_FLAGS_MASK, 0x0,
				PACKED_FLAGS_MASK, 0x0,
				PACKED_FLAGS_MASK, 0x0,
				PACKED_FLAGS_MASK, 0x0);
	} else {
		used_flags = _mm512_set_epi64(
				0x0, 0x0,
				0x0, 0x0,
				0x0, 0x0,
				0x0, 0x0);
	}

	/* Check all descs are used */
	desc_stats = _mm512_cmp_epu64_mask(flags_mask, used_flags,
			_MM_CMPINT_EQ);
	if (desc_stats != 0xff)
		return -1;

	virtio_for_each_try_unroll(i, 0, PACKED_BATCH_SIZE) {
		rx_pkts[i] = (struct rte_mbuf *)vq->vq_descx[id + i].cookie;
		rte_packet_prefetch(rte_pktmbuf_mtod(rx_pkts[i], void *));

		addrs[i << 1] = (uint64_t)rx_pkts[i]->rx_descriptor_fields1;
		addrs[(i << 1) + 1] =
			(uint64_t)rx_pkts[i]->rx_descriptor_fields1 + 8;
	}

	virtio_for_each_try_unroll(i, 0, PACKED_BATCH_SIZE) {
		char *addr = (char *)rx_pkts[i]->buf_addr +
			RTE_PKTMBUF_HEADROOM - hdr_size;
		hdrs[i] = (struct virtio_net_hdr *)addr;
	}

	/* addresses of pkt_len and data_len */
	__m512i vindex = _mm512_set_epi64(
			addrs[7], addrs[6],
			addrs[5], addrs[4],
			addrs[3], addrs[2],
			addrs[1], addrs[0]);

	/*
	 * select 0x10   load 32bit from packed_desc[95:64]
	 * mmask  0x0110 save 32bit into pkt_len and data_len
	 */
	__m512i value = _mm512_maskz_shuffle_epi32(0x6666, packed_desc, 0xAA);

	__m512i mbuf_len_offset = _mm512_set_epi32(
			0, (uint32_t)-hdr_size, (uint32_t)-hdr_size, 0,
			0, (uint32_t)-hdr_size, (uint32_t)-hdr_size, 0,
			0, (uint32_t)-hdr_size, (uint32_t)-hdr_size, 0,
			0, (uint32_t)-hdr_size, (uint32_t)-hdr_size, 0);

	value = _mm512_add_epi32(value, mbuf_len_offset);
	/* batch store into mbufs */
	_mm512_i64scatter_epi64(0, vindex, value, 1);

	if (hw->has_rx_offload) {
		virtio_for_each_try_unroll(i, 0, PACKED_BATCH_SIZE)
			virtio_vec_rx_offload(rx_pkts[i], hdrs[i]);
	}

	virtio_update_batch_stats(&rxvq->stats, rx_pkts[0]->pkt_len,
			rx_pkts[1]->pkt_len, rx_pkts[2]->pkt_len,
			rx_pkts[3]->pkt_len);

	vq->vq_free_cnt += PACKED_BATCH_SIZE;

	vq->vq_used_cons_idx += PACKED_BATCH_SIZE;
	if (vq->vq_used_cons_idx >= vq->vq_nentries) {
		vq->vq_used_cons_idx -= vq->vq_nentries;
		vq->vq_packed.used_wrap_counter ^= 1;
	}

	return 0;
}

static uint16_t
virtqueue_dequeue_single_packed_vec(struct virtnet_rx *rxvq,
				    struct rte_mbuf **rx_pkts)
{
	uint16_t used_idx, id;
	uint32_t len;
	struct virtqueue *vq = rxvq->vq;
	struct virtio_hw *hw = vq->hw;
	uint32_t hdr_size = hw->vtnet_hdr_size;
	struct virtio_net_hdr *hdr;
	struct vring_packed_desc *desc;
	struct rte_mbuf *cookie;

	desc = vq->vq_packed.ring.desc;
	used_idx = vq->vq_used_cons_idx;
	if (!desc_is_used(&desc[used_idx], vq))
		return -1;

	len = desc[used_idx].len;
	id = desc[used_idx].id;
	cookie = (struct rte_mbuf *)vq->vq_descx[id].cookie;
	if (unlikely(cookie == NULL)) {
		PMD_DRV_LOG(ERR, "vring descriptor with no mbuf cookie at %u",
				vq->vq_used_cons_idx);
		return -1;
	}
	rte_prefetch0(cookie);
	rte_packet_prefetch(rte_pktmbuf_mtod(cookie, void *));

	cookie->data_off = RTE_PKTMBUF_HEADROOM;
	cookie->ol_flags = 0;
	cookie->pkt_len = (uint32_t)(len - hdr_size);
	cookie->data_len = (uint32_t)(len - hdr_size);

	hdr = (struct virtio_net_hdr *)((char *)cookie->buf_addr +
					RTE_PKTMBUF_HEADROOM - hdr_size);
	if (hw->has_rx_offload)
		virtio_vec_rx_offload(cookie, hdr);

	*rx_pkts = cookie;

	rxvq->stats.bytes += cookie->pkt_len;

	vq->vq_free_cnt++;
	vq->vq_used_cons_idx++;
	if (vq->vq_used_cons_idx >= vq->vq_nentries) {
		vq->vq_used_cons_idx -= vq->vq_nentries;
		vq->vq_packed.used_wrap_counter ^= 1;
	}

	return 0;
}

static inline void
virtio_recv_refill_packed_vec(struct virtnet_rx *rxvq,
			      struct rte_mbuf **cookie,
			      uint16_t num)
{
	struct virtqueue *vq = rxvq->vq;
	struct vring_packed_desc *start_dp = vq->vq_packed.ring.desc;
	uint16_t flags = vq->vq_packed.cached_flags;
	struct virtio_hw *hw = vq->hw;
	struct vq_desc_extra *dxp;
	uint16_t idx, i;
	uint16_t total_num = 0;
	uint16_t head_idx = vq->vq_avail_idx;
	uint16_t head_flag = vq->vq_packed.cached_flags;
	uint64_t addr;

	do {
		idx = vq->vq_avail_idx;
		virtio_for_each_try_unroll(i, 0, PACKED_BATCH_SIZE) {
			dxp = &vq->vq_descx[idx + i];
			dxp->cookie = (void *)cookie[total_num + i];

			addr = VIRTIO_MBUF_ADDR(cookie[total_num + i], vq) +
				RTE_PKTMBUF_HEADROOM - hw->vtnet_hdr_size;
			start_dp[idx + i].addr = addr;
			start_dp[idx + i].len = cookie[total_num + i]->buf_len
				- RTE_PKTMBUF_HEADROOM + hw->vtnet_hdr_size;
			if (total_num || i) {
				virtqueue_store_flags_packed(&start_dp[idx + i],
						flags, hw->weak_barriers);
			}
		}

		vq->vq_avail_idx += PACKED_BATCH_SIZE;
		if (vq->vq_avail_idx >= vq->vq_nentries) {
			vq->vq_avail_idx -= vq->vq_nentries;
			vq->vq_packed.cached_flags ^=
				VRING_PACKED_DESC_F_AVAIL_USED;
			flags = vq->vq_packed.cached_flags;
		}
		total_num += PACKED_BATCH_SIZE;
	} while (total_num < num);

	virtqueue_store_flags_packed(&start_dp[head_idx], head_flag,
				hw->weak_barriers);
	vq->vq_free_cnt = (uint16_t)(vq->vq_free_cnt - num);
}

uint16_t
virtio_recv_pkts_packed_vec(void *rx_queue,
			    struct rte_mbuf **rx_pkts,
			    uint16_t nb_pkts)
{
	struct virtnet_rx *rxvq = rx_queue;
	struct virtqueue *vq = rxvq->vq;
	struct virtio_hw *hw = vq->hw;
	uint16_t num, nb_rx = 0;
	uint32_t nb_enqueued = 0;
	uint16_t free_cnt = vq->vq_free_thresh;

	if (unlikely(hw->started == 0))
		return nb_rx;

	num = RTE_MIN(VIRTIO_MBUF_BURST_SZ, nb_pkts);
	if (likely(num > PACKED_BATCH_SIZE))
		num = num - ((vq->vq_used_cons_idx + num) % PACKED_BATCH_SIZE);

	while (num) {
		if (!virtqueue_dequeue_batch_packed_vec(rxvq,
					&rx_pkts[nb_rx])) {
			nb_rx += PACKED_BATCH_SIZE;
			num -= PACKED_BATCH_SIZE;
			continue;
		}
		if (!virtqueue_dequeue_single_packed_vec(rxvq,
					&rx_pkts[nb_rx])) {
			nb_rx++;
			num--;
			continue;
		}
		break;
	};

	PMD_RX_LOG(DEBUG, "dequeue:%d", num);

	rxvq->stats.packets += nb_rx;

	if (likely(vq->vq_free_cnt >= free_cnt)) {
		struct rte_mbuf *new_pkts[free_cnt];
		if (likely(rte_pktmbuf_alloc_bulk(rxvq->mpool, new_pkts,
						free_cnt) == 0)) {
			virtio_recv_refill_packed_vec(rxvq, new_pkts,
					free_cnt);
			nb_enqueued += free_cnt;
		} else {
			struct rte_eth_dev *dev =
				&rte_eth_devices[rxvq->port_id];
			dev->data->rx_mbuf_alloc_failed += free_cnt;
		}
	}

	if (likely(nb_enqueued)) {
		if (unlikely(virtqueue_kick_prepare_packed(vq))) {
			virtqueue_notify(vq);
			PMD_RX_LOG(DEBUG, "Notified");
		}
	}

	return nb_rx;
}
