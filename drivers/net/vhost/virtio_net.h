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

#ifdef __cplusplus
}
#endif

#endif /* _VIRTIO_NET_H_ */
