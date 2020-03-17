/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */
#ifndef _VIRTIO_NET_H_
#define _VIRTIO_NET_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "internal.h"

#ifndef VIRTIO_F_RING_PACKED
#define VIRTIO_F_RING_PACKED 34
#endif

/* batching size before invoking the DMA to perform transfers */
#define DMA_BATCHING_SIZE 8
/**
 * copy length threshold for the DMA engine. We offload copy jobs whose
 * lengths are greater than DMA_COPY_LENGTH_THRESHOLD to the DMA; for
 * small copies, we still use the CPU to perform copies, due to startup
 * overheads associated with the DMA.
 *
 * As DMA copying is asynchronous with CPU computations, we can
 * dynamically increase or decrease the value if the DMA is busier or
 * idler than the CPU.
 */
#define DMA_COPY_LENGTH_THRESHOLD 1024

#define vhost_used_event(vr) \
	(*(volatile uint16_t*)&(vr)->avail->ring[(vr)->size])

struct ring_index {
	/* physical address of 'data' */
	uintptr_t pa;
	uintptr_t idx;
	uint16_t data;
	bool in_use;
} __rte_cache_aligned;

static __rte_always_inline int
setup_ring_index(struct ring_index **indices, uint16_t num)
{
	struct ring_index *array;
	uint16_t i;

	array = rte_zmalloc(NULL, sizeof(struct ring_index) * num, 0);
	if (!array) {
		*indices = NULL;
		return -1;
	}

	for (i = 0; i < num; i++) {
		array[i].pa = rte_mem_virt2iova(&array[i].data);
		array[i].idx = i;
	}

	*indices = array;
	return 0;
}

static __rte_always_inline void
destroy_ring_index(struct ring_index **indices)
{
	if (!indices)
		return;
	rte_free(*indices);
	*indices = NULL;
}

static __rte_always_inline struct ring_index *
get_empty_index(struct ring_index *indices, uint16_t num)
{
	uint16_t i;

	for (i = 0; i < num; i++)
		if (!indices[i].in_use)
			break;

	if (unlikely(i == num))
		return NULL;

	indices[i].in_use = true;
	return &indices[i];
}

static __rte_always_inline void
put_used_index(struct ring_index *indices, uint16_t num, uint16_t idx)
{
	if (unlikely(idx >= num))
		return;
	indices[idx].in_use = false;
}

static uint64_t
get_blk_size(int fd)
{
	struct stat stat;
	int ret;

	ret = fstat(fd, &stat);
	return ret == -1 ? (uint64_t)-1 : (uint64_t)stat.st_blksize;
}

static __rte_always_inline int
add_one_guest_page(struct pmd_internal *dev, uint64_t guest_phys_addr,
		   uint64_t host_phys_addr, uint64_t size)
{
	struct guest_page *page, *last_page;
	struct guest_page *old_pages;

	if (dev->nr_guest_pages == dev->max_guest_pages) {
		dev->max_guest_pages *= 2;
		old_pages = dev->guest_pages;
		dev->guest_pages = realloc(dev->guest_pages,
					   dev->max_guest_pages *
					   sizeof(*page));
		if (!dev->guest_pages) {
			VHOST_LOG(ERR, "Cannot realloc guest_pages\n");
			free(old_pages);
			return -1;
		}
	}

	if (dev->nr_guest_pages > 0) {
		last_page = &dev->guest_pages[dev->nr_guest_pages - 1];
		/* merge if the two pages are continuous */
		if (host_phys_addr == last_page->host_phys_addr +
		    last_page->size) {
			last_page->size += size;
			return 0;
		}
	}

	page = &dev->guest_pages[dev->nr_guest_pages++];
	page->guest_phys_addr = guest_phys_addr;
	page->host_phys_addr  = host_phys_addr;
	page->size = size;

	return 0;
}

static __rte_always_inline int
add_guest_page(struct pmd_internal *dev, struct rte_vhost_mem_region *reg)
{
	uint64_t reg_size = reg->size;
	uint64_t host_user_addr  = reg->host_user_addr;
	uint64_t guest_phys_addr = reg->guest_phys_addr;
	uint64_t host_phys_addr;
	uint64_t size, page_size;

	page_size = get_blk_size(reg->fd);
	if (page_size == (uint64_t)-1) {
		VHOST_LOG(ERR, "Cannot get hugepage size through fstat\n");
		return -1;
	}

	host_phys_addr = rte_mem_virt2iova((void *)(uintptr_t)host_user_addr);
	size = page_size - (guest_phys_addr & (page_size - 1));
	size = RTE_MIN(size, reg_size);

	if (add_one_guest_page(dev, guest_phys_addr, host_phys_addr, size) < 0)
		return -1;

	host_user_addr  += size;
	guest_phys_addr += size;
	reg_size -= size;

	while (reg_size > 0) {
		size = RTE_MIN(reg_size, page_size);
		host_phys_addr = rte_mem_virt2iova((void *)(uintptr_t)
						   host_user_addr);
		if (add_one_guest_page(dev, guest_phys_addr, host_phys_addr,
				       size) < 0)
			return -1;

		host_user_addr  += size;
		guest_phys_addr += size;
		reg_size -= size;
	}

	return 0;
}

static __rte_always_inline int
setup_guest_pages(struct pmd_internal *dev, struct rte_vhost_memory *mem)
{
	uint32_t nr_regions = mem->nregions;
	uint32_t i;

	dev->nr_guest_pages = 0;
	dev->max_guest_pages = 8;

	dev->guest_pages = malloc(dev->max_guest_pages *
				  sizeof(struct guest_page));
	if (dev->guest_pages == NULL) {
		VHOST_LOG(ERR, "(%d) failed to allocate memory "
			  "for dev->guest_pages\n", dev->vid);
		return -1;
	}

	for (i = 0; i < nr_regions; i++) {
		if (add_guest_page(dev, &mem->regions[i]) < 0)
			return -1;
	}

	return 0;
}

static __rte_always_inline rte_iova_t
gpa_to_hpa(struct pmd_internal *dev, uint64_t gpa, uint64_t size)
{
	uint32_t i;
	struct guest_page *page;

	for (i = 0; i < dev->nr_guest_pages; i++) {
		page = &dev->guest_pages[i];

		if (gpa >= page->guest_phys_addr &&
		    gpa + size < page->guest_phys_addr + page->size) {
			return gpa - page->guest_phys_addr +
			       page->host_phys_addr;
		}
	}

	return 0;
}

/**
 * This function checks if packed rings are enabled.
 */
static __rte_always_inline bool
vhost_dma_vring_is_packed(struct pmd_internal *dev)
{
	return dev->features & (1ULL << VIRTIO_F_RING_PACKED);
}

/**
 * This function gets front end's memory and vrings information.
 * In addition, it sets up necessary data structures for enqueue
 * and dequeue operations.
 */
int vhost_dma_setup(struct pmd_internal *dev);

/**
 * This function destroys front end's information and frees data
 * structures for enqueue and dequeue operations.
 */
void vhost_dma_remove(struct pmd_internal *dev);

/**
 * This function frees DMA copy-done pktmbufs for the enqueue operation.
 *
 * @return
 *  the number of packets that are completed by the DMA engine
 */
int free_dma_done(void *dev, void *dma_vr);

/**
 * This function sends packet buffers to front end's RX vring.
 * It will free the mbufs of successfully transmitted packets.
 *
 * @param dev
 *  vhost-dma device
 * @param dma_vr
 *  a front end's RX vring
 * @param pkts
 *  packets to send
 * @param count
 *  the number of packets to send
 *
 * @return
 *  the number of packets successfully sent
 */
uint16_t vhost_dma_enqueue_burst(struct pmd_internal *dev,
				  struct dma_vring *dma_vr,
				  struct rte_mbuf **pkts, uint32_t count);

#ifdef __cplusplus
}
#endif

#endif /* _VIRTIO_NET_H_ */
