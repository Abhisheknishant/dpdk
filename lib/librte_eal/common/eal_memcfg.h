/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Intel Corporation
 */

#ifndef EAL_MEMCFG_H
#define EAL_MEMCFG_H

#include <rte_config.h>
#include <rte_eal_memconfig.h>
#include <rte_malloc_heap.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_pause.h>
#include <rte_rwlock.h>
#include <rte_tailq.h>

/**
 * the structure for the memory configuration for the RTE.
 * Used by the rte_config structure. It is separated out, as for multi-process
 * support, the memory details should be shared across instances
 */
struct rte_mem_config {
	volatile uint32_t magic;   /**< Magic number - Sanity check. */

	/* memory topology */
	uint32_t nchannel;    /**< Number of channels (0 if unknown). */
	uint32_t nrank;       /**< Number of ranks (0 if unknown). */

	/**
	 * current lock nest order
	 *  - qlock->mlock (ring/hash/lpm)
	 *  - mplock->qlock->mlock (mempool)
	 * Notice:
	 *  *ALWAYS* obtain qlock first if having to obtain both qlock and mlock
	 */
	rte_rwlock_t mlock;   /**< only used by memzone LIB for thread-safe. */
	rte_rwlock_t qlock;   /**< used for tailq operation for thread safe. */
	rte_rwlock_t mplock;  /**< only used by mempool LIB for thread-safe. */

	rte_rwlock_t memory_hotplug_lock;
	/**< indicates whether memory hotplug request is in progress. */

	/* memory segments and zones */
	struct rte_fbarray memzones; /**< Memzone descriptors. */

	struct rte_memseg_list memsegs[RTE_MAX_MEMSEG_LISTS];
	/**< list of dynamic arrays holding memsegs */

	struct rte_tailq_head tailq_head[RTE_MAX_TAILQ];
	/**< Tailqs for objects */

	/* Heaps of Malloc */
	struct malloc_heap malloc_heaps[RTE_MAX_HEAPS];

	/* next socket ID for external malloc heap */
	int next_socket_id;

	/* address of mem_config in primary process. used to map shared config
	 * into exact same address the primary process maps it.
	 */
	uint64_t mem_cfg_addr;

	/* legacy mem and single file segments options are shared */
	uint32_t legacy_mem;
	uint32_t single_file_segments;

	/* keeps the more restricted dma mask */
	uint8_t dma_maskbits;
} __attribute__((packed));

static inline void
rte_eal_mcfg_wait_complete(struct rte_mem_config *mcfg)
{
	/* wait until shared mem_config finish initialising */
	while (mcfg->magic != RTE_MAGIC)
		rte_pause();
}

#endif /* EAL_MEMCFG_H */
