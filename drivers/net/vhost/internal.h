/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */
#ifndef _INTERNAL_H_
#define _INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

#include <rte_pci.h>
#include <rte_vhost.h>
#include <rte_log.h>

extern int vhost_logtype;

#define VHOST_LOG(level, ...) \
	rte_log(RTE_LOG_ ## level, vhost_logtype, __VA_ARGS__)

enum vhost_xstats_pkts {
	VHOST_UNDERSIZE_PKT = 0,
	VHOST_64_PKT,
	VHOST_65_TO_127_PKT,
	VHOST_128_TO_255_PKT,
	VHOST_256_TO_511_PKT,
	VHOST_512_TO_1023_PKT,
	VHOST_1024_TO_1522_PKT,
	VHOST_1523_TO_MAX_PKT,
	VHOST_BROADCAST_PKT,
	VHOST_MULTICAST_PKT,
	VHOST_UNICAST_PKT,
	VHOST_ERRORS_PKT,
	VHOST_ERRORS_FRAGMENTED,
	VHOST_ERRORS_JABBER,
	VHOST_UNKNOWN_PROTOCOL,
	VHOST_XSTATS_MAX,
};

struct vhost_stats {
	uint64_t pkts;
	uint64_t bytes;
	uint64_t missed_pkts;
	uint64_t xstats[VHOST_XSTATS_MAX];
};

struct batch_copy_elem {
	void *dst;
	void *src;
	uint32_t len;
};

struct guest_page {
	uint64_t guest_phys_addr;
	uint64_t host_phys_addr;
	uint64_t size;
};

struct dma_vring {
	struct rte_vhost_vring  vr;

	uint16_t last_avail_idx;
	uint16_t last_used_idx;

	/* the last used index that front end can consume */
	uint16_t copy_done_used;

	uint16_t signalled_used;
	bool signalled_used_valid;

	struct vring_used_elem *shadow_used_split;
	uint16_t shadow_used_idx;

	struct batch_copy_elem  *batch_copy_elems;
	uint16_t batch_copy_nb_elems;

	bool dma_enabled;
	/**
	 * DMA ID. Currently, we only support I/OAT,
	 * so it's I/OAT rawdev ID.
	 */
	uint16_t dev_id;
	/* DMA address */
	struct rte_pci_addr dma_addr;
	/**
	 * the number of copy jobs that are submitted to the DMA
	 * but may not be completed.
	 */
	uint64_t nr_inflight;
	int nr_batching;

	/**
	 * host physical address of used ring index,
	 * used by the DMA.
	 */
	phys_addr_t used_idx_hpa;
};

struct vhost_queue {
	int vid;
	rte_atomic32_t allow_queuing;
	rte_atomic32_t while_queuing;
	struct pmd_internal *internal;
	struct rte_mempool *mb_pool;
	uint16_t port;
	uint16_t virtqueue_id;
	struct vhost_stats stats;
	struct dma_vring *dma_vring;
};

struct pmd_internal {
	rte_atomic32_t dev_attached;
	char *iface_name;
	uint64_t flags;
	uint64_t disable_flags;
	uint16_t max_queues;
	int vid;
	rte_atomic32_t started;
	uint8_t vlan_strip;

	/* guest's memory regions */
	struct rte_vhost_memory *mem;
	/* guest and host physical address mapping table */
	struct guest_page *guest_pages;
	uint32_t nr_guest_pages;
	uint32_t max_guest_pages;
	/* guest's vrings */
	struct dma_vring dma_vrings[RTE_MAX_QUEUES_PER_PORT * 2];
	uint16_t nr_vrings;
	/* negotiated features */
	uint64_t features;
	size_t hdr_len;
};

#ifdef __cplusplus
}
#endif

#endif /* _INTERNAL_H_ */
