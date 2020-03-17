#include <stdint.h>
#include <stdbool.h>
#include <linux/virtio_net.h>

#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_sctp.h>
#include <rte_vhost.h>
#include <rte_rawdev.h>
#include <rte_ioat_rawdev.h>

#include "virtio_net.h"

#define BUF_VECTOR_MAX 256
#define MAX_BATCH_LEN 256

struct buf_vector {
	uint64_t buf_iova;
	uint64_t buf_addr;
	uint32_t buf_len;
	uint32_t desc_idx;
};

static __rte_always_inline int
vhost_need_event(uint16_t event_idx, uint16_t new_idx, uint16_t old)
{
	return (uint16_t)(new_idx - event_idx - 1) < (uint16_t)(new_idx - old);
}

static __rte_always_inline void
vhost_vring_call_split(struct pmd_internal *dev, struct dma_vring *dma_vr)
{
	struct rte_vhost_vring *vr = &dma_vr->vr;

	/* flush used->idx update before we read avail->flags. */
	rte_smp_mb();

	if (dev->features & (1ULL << VIRTIO_RING_F_EVENT_IDX)) {
		uint16_t old = dma_vr->signalled_used;
		uint16_t new = dma_vr->copy_done_used;
		bool signalled_used_valid = dma_vr->signalled_used_valid;

		dma_vr->signalled_used = new;
		dma_vr->signalled_used_valid = true;

		VHOST_LOG(DEBUG, "%s: used_event_idx=%d, old=%d, new=%d\n",
			  __func__, vhost_used_event(vr), old, new);

		if ((vhost_need_event(vhost_used_event(vr), new, old) &&
		     (vr->callfd >= 0)) || unlikely(!signalled_used_valid))
			eventfd_write(vr->callfd, (eventfd_t)1);
	} else {
		if (!(vr->avail->flags & VRING_AVAIL_F_NO_INTERRUPT) &&
		    (vr->callfd >= 0))
			eventfd_write(vr->callfd, (eventfd_t)1);
	}
}

/* notify front-end of enqueued packets */
static __rte_always_inline void
vhost_dma_vring_call(struct pmd_internal *dev, struct dma_vring *dma_vr)
{
	vhost_vring_call_split(dev, dma_vr);
}

int
free_dma_done(void *dev, void *dma_vr)
{
	uintptr_t flags[255], tmps[255];
	int dma_done, i;
	uint16_t used_idx;
	struct pmd_internal *device = dev;
	struct dma_vring *dma_vring = dma_vr;

	dma_done = rte_ioat_completed_copies(dma_vring->dev_id, 255, flags,
					     tmps);
	if (unlikely(dma_done <= 0))
		return dma_done;

	dma_vring->nr_inflight -= dma_done;
	for (i = 0; i < dma_done; i++) {
		if ((uint64_t)flags[i] >= dma_vring->max_indices) {
			struct rte_mbuf *pkt = (struct rte_mbuf *)flags[i];

			/**
			 * the DMA completes a packet copy job, we
			 * decrease the refcnt or free the mbuf segment.
			 */
			rte_pktmbuf_free_seg(pkt);
		} else {
			uint16_t id = flags[i];

			/**
			 * the DMA completes updating index of the
			 * used ring.
			 */
			used_idx = dma_vring->indices[id].data;
			VHOST_LOG(DEBUG, "The DMA finishes updating index %u "
				  "for the used ring.\n", used_idx);

			dma_vring->copy_done_used = used_idx;
			vhost_dma_vring_call(device, dma_vring);
			put_used_index(dma_vring->indices,
				       dma_vring->max_indices, id);
		}
	}
	return dma_done;
}

static  __rte_always_inline bool
rxvq_is_mergeable(struct pmd_internal *dev)
{
	return dev->features & (1ULL << VIRTIO_NET_F_MRG_RXBUF);
}

static __rte_always_inline void
do_flush_shadow_used_ring_split(struct dma_vring *dma_vr, uint16_t to,
				uint16_t from, uint16_t size)
{
	rte_memcpy(&dma_vr->vr.used->ring[to],
		   &dma_vr->shadow_used_split[from],
		   size * sizeof(struct vring_used_elem));
}

static __rte_always_inline void
flush_shadow_used_ring_split(struct pmd_internal *dev,
			     struct dma_vring *dma_vr)
{
	uint16_t used_idx = dma_vr->last_used_idx & (dma_vr->vr.size - 1);

	if (used_idx + dma_vr->shadow_used_idx <= dma_vr->vr.size) {
		do_flush_shadow_used_ring_split(dma_vr, used_idx, 0,
						dma_vr->shadow_used_idx);
	} else {
		uint16_t size;

		/* update used ring interval [used_idx, vr->size] */
		size = dma_vr->vr.size - used_idx;
		do_flush_shadow_used_ring_split(dma_vr, used_idx, 0, size);

		/* update the left half used ring interval [0, left_size] */
		do_flush_shadow_used_ring_split(dma_vr, 0, size,
						dma_vr->shadow_used_idx -
						size);
	}
	dma_vr->last_used_idx += dma_vr->shadow_used_idx;

	rte_smp_wmb();

	if (dma_vr->nr_inflight > 0) {
		struct ring_index *index;

		index = get_empty_index(dma_vr->indices, dma_vr->max_indices);
		index->data = dma_vr->last_used_idx;
		while (unlikely(rte_ioat_enqueue_copy(dma_vr->dev_id,
						      index->pa,
						      dma_vr->used_idx_hpa,
						      sizeof(uint16_t),
						      index->idx, 0, 0) ==
				0)) {
			int ret;

			do {
				ret = dma_vr->dma_done_fn(dev, dma_vr);
			} while (ret <= 0);
		}
		dma_vr->nr_batching++;
		dma_vr->nr_inflight++;
	} else {
		/**
		 * we update index of used ring when all previous copy
		 * jobs are completed.
		 *
		 * When enabling DMA copy, if there are outstanding copy
		 * jobs of the DMA, to avoid the DMA overwriting the
		 * write of the CPU, the DMA is in charge of updating
		 * the index of used ring.
		 */
		*(volatile uint16_t *)&dma_vr->vr.used->idx +=
			dma_vr->shadow_used_idx;
		dma_vr->copy_done_used += dma_vr->shadow_used_idx;
	}

	dma_vr->shadow_used_idx = 0;
}

static __rte_always_inline void
update_shadow_used_ring_split(struct dma_vring *dma_vr,
			      uint16_t desc_idx, uint32_t len)
{
	uint16_t i = dma_vr->shadow_used_idx++;

	dma_vr->shadow_used_split[i].id  = desc_idx;
	dma_vr->shadow_used_split[i].len = len;
}

static inline void
do_data_copy(struct dma_vring *dma_vr)
{
	struct batch_copy_elem *elem = dma_vr->batch_copy_elems;
	uint16_t count = dma_vr->batch_copy_nb_elems;
	int i;

	for (i = 0; i < count; i++)
		rte_memcpy(elem[i].dst, elem[i].src, elem[i].len);

	dma_vr->batch_copy_nb_elems = 0;
}

#define ASSIGN_UNLESS_EQUAL(var, val) do {	\
	if ((var) != (val))			\
		(var) = (val);			\
} while (0)

static __rte_always_inline void
virtio_enqueue_offload(struct rte_mbuf *m_buf, struct virtio_net_hdr *net_hdr)
{
	uint64_t csum_l4 = m_buf->ol_flags & PKT_TX_L4_MASK;

	if (m_buf->ol_flags & PKT_TX_TCP_SEG)
		csum_l4 |= PKT_TX_TCP_CKSUM;

	if (csum_l4) {
		net_hdr->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;
		net_hdr->csum_start = m_buf->l2_len + m_buf->l3_len;

		switch (csum_l4) {
		case PKT_TX_TCP_CKSUM:
			net_hdr->csum_offset = (offsetof(struct rte_tcp_hdr,
						cksum));
			break;
		case PKT_TX_UDP_CKSUM:
			net_hdr->csum_offset = (offsetof(struct rte_udp_hdr,
						dgram_cksum));
			break;
		case PKT_TX_SCTP_CKSUM:
			net_hdr->csum_offset = (offsetof(struct rte_sctp_hdr,
						cksum));
			break;
		}
	} else {
		ASSIGN_UNLESS_EQUAL(net_hdr->csum_start, 0);
		ASSIGN_UNLESS_EQUAL(net_hdr->csum_offset, 0);
		ASSIGN_UNLESS_EQUAL(net_hdr->flags, 0);
	}

	/* IP cksum verification cannot be bypassed, then calculate here */
	if (m_buf->ol_flags & PKT_TX_IP_CKSUM) {
		struct rte_ipv4_hdr *ipv4_hdr;

		ipv4_hdr = rte_pktmbuf_mtod_offset(m_buf, struct rte_ipv4_hdr *,
						   m_buf->l2_len);
		ipv4_hdr->hdr_checksum = rte_ipv4_cksum(ipv4_hdr);
	}

	if (m_buf->ol_flags & PKT_TX_TCP_SEG) {
		if (m_buf->ol_flags & PKT_TX_IPV4)
			net_hdr->gso_type = VIRTIO_NET_HDR_GSO_TCPV4;
		else
			net_hdr->gso_type = VIRTIO_NET_HDR_GSO_TCPV6;
		net_hdr->gso_size = m_buf->tso_segsz;
		net_hdr->hdr_len = m_buf->l2_len + m_buf->l3_len
					+ m_buf->l4_len;
	} else if (m_buf->ol_flags & PKT_TX_UDP_SEG) {
		net_hdr->gso_type = VIRTIO_NET_HDR_GSO_UDP;
		net_hdr->gso_size = m_buf->tso_segsz;
		net_hdr->hdr_len = m_buf->l2_len + m_buf->l3_len +
			m_buf->l4_len;
	} else {
		ASSIGN_UNLESS_EQUAL(net_hdr->gso_type, 0);
		ASSIGN_UNLESS_EQUAL(net_hdr->gso_size, 0);
		ASSIGN_UNLESS_EQUAL(net_hdr->hdr_len, 0);
	}
}

static __rte_always_inline void *
vhost_alloc_copy_ind_table(struct pmd_internal *dev, uint64_t desc_addr,
			   uint64_t desc_len)
{
	void *idesc;
	uint64_t src, dst;
	uint64_t len, remain = desc_len;

	idesc = rte_malloc(NULL, desc_len, 0);
	if (unlikely(!idesc))
		return NULL;

	dst = (uint64_t)(uintptr_t)idesc;

	while (remain) {
		len = remain;
		src = rte_vhost_va_from_guest_pa(dev->mem, desc_addr, &len);
		if (unlikely(!src || !len)) {
			rte_free(idesc);
			return NULL;
		}

		rte_memcpy((void *)(uintptr_t)dst, (void *)(uintptr_t)src,
			   len);

		remain -= len;
		dst += len;
		desc_addr += len;
	}

	return idesc;
}

static __rte_always_inline void
free_ind_table(void *idesc)
{
	rte_free(idesc);
}

static __rte_always_inline int
map_one_desc(struct pmd_internal *dev, struct buf_vector *buf_vec,
	     uint16_t *vec_idx, uint64_t desc_iova, uint64_t desc_len)
{
	uint16_t vec_id = *vec_idx;

	while (desc_len) {
		uint64_t desc_addr;
		uint64_t desc_chunck_len = desc_len;

		if (unlikely(vec_id >= BUF_VECTOR_MAX))
			return -1;

		desc_addr = rte_vhost_va_from_guest_pa(dev->mem, desc_iova,
						       &desc_chunck_len);
		if (unlikely(!desc_addr))
			return -1;

		rte_prefetch0((void *)(uintptr_t)desc_addr);

		buf_vec[vec_id].buf_iova = desc_iova;
		buf_vec[vec_id].buf_addr = desc_addr;
		buf_vec[vec_id].buf_len  = desc_chunck_len;

		desc_len -= desc_chunck_len;
		desc_iova += desc_chunck_len;
		vec_id++;
	}
	*vec_idx = vec_id;

	return 0;
}

static __rte_always_inline int
fill_vec_buf_split(struct pmd_internal *dev, struct dma_vring *dma_vr,
		   uint32_t avail_idx, uint16_t *vec_idx,
		   struct buf_vector *buf_vec, uint16_t *desc_chain_head,
		   uint32_t *desc_chain_len)
{
	struct rte_vhost_vring *vr = &dma_vr->vr;
	uint16_t idx = vr->avail->ring[avail_idx & (vr->size - 1)];
	uint16_t vec_id = *vec_idx;
	uint32_t len    = 0;
	uint64_t dlen;
	uint32_t nr_descs = vr->size;
	uint32_t cnt    = 0;
	struct vring_desc *descs = vr->desc;
	struct vring_desc *idesc = NULL;

	if (unlikely(idx >= vr->size))
		return -1;

	*desc_chain_head = idx;

	if (vr->desc[idx].flags & VRING_DESC_F_INDIRECT) {
		dlen = vr->desc[idx].len;
		nr_descs = dlen / sizeof(struct vring_desc);
		if (unlikely(nr_descs > vr->size))
			return -1;

		descs = (struct vring_desc *)(uintptr_t)
			rte_vhost_va_from_guest_pa(dev->mem,
						   vr->desc[idx].addr, &dlen);
		if (unlikely(!descs))
			return -1;

		if (unlikely(dlen < vr->desc[idx].len)) {
			/**
			 * the indirect desc table is not contiguous
			 * in process VA space, we have to copy it.
			 */
			idesc = vhost_alloc_copy_ind_table(dev,
							   vr->desc[idx].addr,
							   vr->desc[idx].len);
			if (unlikely(!idesc))
				return -1;

			descs = idesc;
		}

		idx = 0;
	}

	while (1) {
		if (unlikely(idx >= nr_descs || cnt++ >= nr_descs)) {
			free_ind_table(idesc);
			return -1;
		}

		len += descs[idx].len;

		if (unlikely(map_one_desc(dev, buf_vec, &vec_id,
					  descs[idx].addr, descs[idx].len))) {
			free_ind_table(idesc);
			return -1;
		}

		if ((descs[idx].flags & VRING_DESC_F_NEXT) == 0)
			break;

		idx = descs[idx].next;
	}

	*desc_chain_len = len;
	*vec_idx = vec_id;

	if (unlikely(!!idesc))
		free_ind_table(idesc);

	return 0;
}

static inline int
reserve_avail_buf_split(struct pmd_internal *dev, struct dma_vring *dma_vr,
			uint32_t size, struct buf_vector *buf_vec,
			uint16_t *num_buffers, uint16_t avail_head,
			uint16_t *nr_vec)
{
	struct rte_vhost_vring *vr = &dma_vr->vr;

	uint16_t cur_idx;
	uint16_t vec_idx = 0;
	uint16_t max_tries, tries = 0;

	uint16_t head_idx = 0;
	uint32_t len = 0;

	*num_buffers = 0;
	cur_idx = dma_vr->last_avail_idx;

	if (rxvq_is_mergeable(dev))
		max_tries = vr->size - 1;
	else
		max_tries = 1;

	while (size > 0) {
		if (unlikely(cur_idx == avail_head))
			return -1;
		/**
		 * if we tried all available ring items, and still
		 * can't get enough buf, it means something abnormal
		 * happened.
		 */
		if (unlikely(++tries > max_tries))
			return -1;

		if (unlikely(fill_vec_buf_split(dev, dma_vr, cur_idx,
						&vec_idx, buf_vec,
						&head_idx, &len) < 0))
			return -1;
		len = RTE_MIN(len, size);
		update_shadow_used_ring_split(dma_vr, head_idx, len);
		size -= len;

		cur_idx++;
		*num_buffers += 1;
	}

	*nr_vec = vec_idx;

	return 0;
}

static __rte_noinline void
copy_vnet_hdr_to_desc(struct pmd_internal *dev, struct buf_vector *buf_vec,
		      struct virtio_net_hdr_mrg_rxbuf *hdr)
{
	uint64_t len;
	uint64_t remain = dev->hdr_len;
	uint64_t src = (uint64_t)(uintptr_t)hdr, dst;
	uint64_t iova = buf_vec->buf_iova;

	while (remain) {
		len = RTE_MIN(remain, buf_vec->buf_len);
		dst = buf_vec->buf_addr;
		rte_memcpy((void *)(uintptr_t)dst, (void *)(uintptr_t)src,
			   len);

		remain -= len;
		iova += len;
		src += len;
		buf_vec++;
	}
}

static __rte_always_inline int
copy_mbuf_to_desc(struct pmd_internal *dev, struct dma_vring *dma_vr,
		  struct rte_mbuf *m, struct buf_vector *buf_vec,
		  uint16_t nr_vec, uint16_t num_buffers)
{
	uint32_t vec_idx = 0;
	uint32_t mbuf_offset, mbuf_avail;
	uint32_t buf_offset, buf_avail;
	uint64_t buf_addr, buf_iova, buf_len;
	uint32_t cpy_len;
	uint64_t hdr_addr;
	struct rte_mbuf *hdr_mbuf;
	struct batch_copy_elem *batch_copy = dma_vr->batch_copy_elems;
	struct virtio_net_hdr_mrg_rxbuf tmp_hdr, *hdr = NULL;
	uint64_t dst, src;
	int error = 0;

	if (unlikely(m == NULL)) {
		error = -1;
		goto out;
	}

	buf_addr = buf_vec[vec_idx].buf_addr;
	buf_iova = buf_vec[vec_idx].buf_iova;
	buf_len = buf_vec[vec_idx].buf_len;

	if (unlikely(buf_len < dev->hdr_len && nr_vec <= 1)) {
		error = -1;
		goto out;
	}

	hdr_mbuf = m;
	hdr_addr = buf_addr;
	if (unlikely(buf_len < dev->hdr_len))
		hdr = &tmp_hdr;
	else
		hdr = (struct virtio_net_hdr_mrg_rxbuf *)(uintptr_t)hdr_addr;

	VHOST_LOG(DEBUG, "(%d) RX: num merge buffers %d\n", dev->vid,
		  num_buffers);

	if (unlikely(buf_len < dev->hdr_len)) {
		buf_offset = dev->hdr_len - buf_len;
		vec_idx++;
		buf_addr = buf_vec[vec_idx].buf_addr;
		buf_iova = buf_vec[vec_idx].buf_iova;
		buf_len = buf_vec[vec_idx].buf_len;
		buf_avail = buf_len - buf_offset;
	} else {
		buf_offset = dev->hdr_len;
		buf_avail = buf_len - dev->hdr_len;
	}

	mbuf_avail = rte_pktmbuf_data_len(m);
	mbuf_offset = 0;
	while (mbuf_avail != 0 || m->next != NULL) {
		bool dma_copy = false;

		/* done with current buf, get the next one */
		if (buf_avail == 0) {
			vec_idx++;
			if (unlikely(vec_idx >= nr_vec)) {
				error = -1;
				goto out;
			}

			buf_addr = buf_vec[vec_idx].buf_addr;
			buf_iova = buf_vec[vec_idx].buf_iova;
			buf_len = buf_vec[vec_idx].buf_len;

			buf_offset = 0;
			buf_avail  = buf_len;
		}

		/* done with current mbuf, get the next one */
		if (mbuf_avail == 0) {
			m = m->next;
			mbuf_offset = 0;
			mbuf_avail = rte_pktmbuf_data_len(m);
		}

		if (hdr_addr) {
			virtio_enqueue_offload(hdr_mbuf, &hdr->hdr);
			if (rxvq_is_mergeable(dev))
				ASSIGN_UNLESS_EQUAL(hdr->num_buffers,
						    num_buffers);

			if (unlikely(hdr == &tmp_hdr))
				copy_vnet_hdr_to_desc(dev, buf_vec, hdr);
			hdr_addr = 0;
		}

		cpy_len = RTE_MIN(buf_avail, mbuf_avail);
		if (cpy_len >= DMA_COPY_LENGTH_THRESHOLD) {
			dst = gpa_to_hpa(dev, buf_iova + buf_offset, cpy_len);
			dma_copy = (dst != 0);
		}

		if (dma_copy) {
			src = rte_pktmbuf_iova_offset(m, mbuf_offset);
			/**
			 * if DMA enqueue fails, we wait until there are
			 * available DMA descriptors.
			 */
			while (unlikely(rte_ioat_enqueue_copy(dma_vr->dev_id,
							      src, dst, cpy_len,
							      (uintptr_t)
							      m, 0, 0) ==
					0)) {
				int ret;

				do {
					ret = free_dma_done(dev, dma_vr);
				} while (ret <= 0);
			}

			dma_vr->nr_batching++;
			dma_vr->nr_inflight++;
			rte_mbuf_refcnt_update(m, 1);
		} else if (likely(cpy_len > MAX_BATCH_LEN ||
				  dma_vr->batch_copy_nb_elems >=
				  dma_vr->vr.size)) {
			rte_memcpy((void *)((uintptr_t)(buf_addr + buf_offset)),
				   rte_pktmbuf_mtod_offset(m, void *,
							   mbuf_offset),
				   cpy_len);
		} else {
			batch_copy[dma_vr->batch_copy_nb_elems].dst =
				(void *)((uintptr_t)(buf_addr + buf_offset));
			batch_copy[dma_vr->batch_copy_nb_elems].src =
				rte_pktmbuf_mtod_offset(m, void *, mbuf_offset);
			batch_copy[dma_vr->batch_copy_nb_elems].len = cpy_len;
			dma_vr->batch_copy_nb_elems++;
		}

		mbuf_avail  -= cpy_len;
		mbuf_offset += cpy_len;
		buf_avail  -= cpy_len;
		buf_offset += cpy_len;
	}

out:
	return error;
}

static __rte_always_inline uint16_t
vhost_dma_enqueue_split(struct pmd_internal *dev, struct dma_vring *dma_vr,
			 struct rte_mbuf **pkts, uint32_t count)
{
	struct rte_vhost_vring *vr = &dma_vr->vr;

	uint32_t pkt_idx = 0;
	uint16_t num_buffers;
	struct buf_vector buf_vec[BUF_VECTOR_MAX];
	uint16_t avail_head;

	if (dma_vr->nr_inflight > 0)
		free_dma_done(dev, dma_vr);

	avail_head = *((volatile uint16_t *)&vr->avail->idx);

	/**
	 * the ordering between avail index and
	 * desc reads needs to be enforced.
	 */
	rte_smp_rmb();

	rte_prefetch0(&vr->avail->ring[dma_vr->last_avail_idx &
			(vr->size - 1)]);

	for (pkt_idx = 0; pkt_idx < count; pkt_idx++) {
		uint32_t pkt_len = pkts[pkt_idx]->pkt_len + dev->hdr_len;
		uint16_t nr_vec = 0;

		if (unlikely(reserve_avail_buf_split(dev, dma_vr, pkt_len,
						     buf_vec, &num_buffers,
						     avail_head, &nr_vec) <
			     0)) {
			VHOST_LOG(INFO,
				  "(%d) failed to get enough desc from vring\n",
				  dev->vid);
			dma_vr->shadow_used_idx -= num_buffers;
			break;
		}

		VHOST_LOG(DEBUG, "(%d) current index %d | end index %d\n",
			  dev->vid, dma_vr->last_avail_idx,
			  dma_vr->last_avail_idx + num_buffers);

		if (copy_mbuf_to_desc(dev, dma_vr, pkts[pkt_idx],
				      buf_vec, nr_vec, num_buffers) < 0) {
			dma_vr->shadow_used_idx -= num_buffers;
			break;
		}

		if (unlikely(dma_vr->nr_batching >= DMA_BATCHING_SIZE)) {
			/**
			 * kick the DMA to do copy once the number of
			 * batching jobs reaches the batching threshold.
			 */
			rte_ioat_do_copies(dma_vr->dev_id);
			dma_vr->nr_batching = 0;
		}

		dma_vr->last_avail_idx += num_buffers;
	}

	do_data_copy(dma_vr);

	if (dma_vr->shadow_used_idx) {
		flush_shadow_used_ring_split(dev, dma_vr);
		vhost_dma_vring_call(dev, dma_vr);
	}

	if (dma_vr->nr_batching > 0) {
		rte_ioat_do_copies(dma_vr->dev_id);
		dma_vr->nr_batching = 0;
	}

	return pkt_idx;
}

uint16_t
vhost_dma_enqueue_burst(struct pmd_internal *dev, struct dma_vring *dma_vr,
			 struct rte_mbuf **pkts, uint32_t count)
{
	return vhost_dma_enqueue_split(dev, dma_vr, pkts, count);
}

int
vhost_dma_setup(struct pmd_internal *dev)
{
	struct dma_vring *dma_vr;
	int vid = dev->vid;
	int ret;
	uint16_t i, j, size;

	rte_vhost_get_negotiated_features(vid, &dev->features);

	if (dev->features & (1 << VIRTIO_NET_F_MRG_RXBUF))
		dev->hdr_len = sizeof(struct virtio_net_hdr_mrg_rxbuf);
	else
		dev->hdr_len = sizeof(struct virtio_net_hdr);

	dev->nr_vrings = rte_vhost_get_vring_num(vid);

	if (rte_vhost_get_mem_table(vid, &dev->mem) < 0) {
		VHOST_LOG(ERR, "Failed to get guest memory regions\n");
		return -1;
	}

	/* set up gpa and hpa mappings */
	if (setup_guest_pages(dev, dev->mem) < 0) {
		VHOST_LOG(ERR, "Failed to set up hpa and gpa mappings\n");
		free(dev->mem);
		return -1;
	}

	for (i = 0; i < dev->nr_vrings; i++) {
		dma_vr = &dev->dma_vrings[i];

		ret = rte_vhost_get_vring_base(vid, i, &dma_vr->last_avail_idx,
					       &dma_vr->last_used_idx);
		if (ret < 0) {
			VHOST_LOG(ERR, "Failed to get vring index.\n");
			goto err;
		}

		ret = rte_vhost_get_vhost_vring(vid, i, &dma_vr->vr);
		if (ret < 0) {
			VHOST_LOG(ERR, "Failed to get vring address.\n");
			goto err;
		}

		size = dma_vr->vr.size;
		dma_vr->shadow_used_split =
			rte_malloc(NULL, size * sizeof(struct vring_used_elem),
				   RTE_CACHE_LINE_SIZE);
		if (dma_vr->shadow_used_split == NULL)
			goto err;

		dma_vr->batch_copy_elems =
			rte_malloc(NULL, size * sizeof(struct batch_copy_elem),
				   RTE_CACHE_LINE_SIZE);
		if (dma_vr->batch_copy_elems == NULL)
			goto err;

		/* get HPA of used ring's index */
		dma_vr->used_idx_hpa =
			rte_mem_virt2iova(&dma_vr->vr.used->idx);

		dma_vr->max_indices = dma_vr->vr.size;
		setup_ring_index(&dma_vr->indices, dma_vr->max_indices);

		dma_vr->copy_done_used = dma_vr->last_used_idx;
		dma_vr->signalled_used = dma_vr->last_used_idx;
		dma_vr->signalled_used_valid = false;
		dma_vr->shadow_used_idx = 0;
		dma_vr->batch_copy_nb_elems = 0;
	}

	return 0;

err:
	for (j = 0; j <= i; j++) {
		dma_vr = &dev->dma_vrings[j];
		rte_free(dma_vr->shadow_used_split);
		rte_free(dma_vr->batch_copy_elems);
		destroy_ring_index(&dma_vr->indices);
		dma_vr->shadow_used_split = NULL;
		dma_vr->batch_copy_elems = NULL;
		dma_vr->used_idx_hpa = 0;
	}

	free(dev->mem);
	dev->mem = NULL;
	free(dev->guest_pages);
	dev->guest_pages = NULL;

	return -1;
}

void
vhost_dma_remove(struct pmd_internal *dev)
{
	struct dma_vring *dma_vr;
	uint16_t i;

	for (i = 0; i < dev->nr_vrings; i++) {
		dma_vr = &dev->dma_vrings[i];
		if (dma_vr->dma_enabled) {
			while (dma_vr->nr_inflight > 0)
				dma_vr->dma_done_fn(dev, dma_vr);

			VHOST_LOG(INFO, "Wait for outstanding DMA jobs "
				  "of vring %u completion\n", i);
			rte_rawdev_stop(dma_vr->dev_id);
			dma_vr->dma_enabled = false;
			dma_vr->nr_batching = 0;
			dma_vr->dev_id = -1;
		}

		rte_free(dma_vr->shadow_used_split);
		rte_free(dma_vr->batch_copy_elems);
		dma_vr->shadow_used_split = NULL;
		dma_vr->batch_copy_elems = NULL;
		dma_vr->signalled_used_valid = false;
		dma_vr->used_idx_hpa = 0;
		destroy_ring_index(&dma_vr->indices);
		dma_vr->max_indices = 0;
	}

	free(dev->mem);
	dev->mem = NULL;
	free(dev->guest_pages);
	dev->guest_pages = NULL;
}
