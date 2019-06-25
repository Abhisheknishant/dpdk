/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#ifndef _RTE_EAL_MEMCONFIG_H_
#define _RTE_EAL_MEMCONFIG_H_

/**
 * @file
 *
 * This API allows access to EAL shared memory configuration through an API.
 */

#include <rte_fbarray.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * memseg list is a special case as we need to store a bunch of other data
 * together with the array itself.
 */
struct rte_memseg_list {
	RTE_STD_C11
	union {
		void *base_va;
		/**< Base virtual address for this memseg list. */
		uint64_t addr_64;
		/**< Makes sure addr is always 64-bits */
	};
	uint64_t page_sz; /**< Page size for all memsegs in this list. */
	int socket_id; /**< Socket ID for all memsegs in this list. */
	volatile uint32_t version; /**< version number for multiprocess sync. */
	size_t len; /**< Length of memory area covered by this memseg list. */
	unsigned int external; /**< 1 if this list points to external memory */
	struct rte_fbarray memseg_arr;
};

/**
 * Lock the internal EAL shared memory configuration for shared access.
 */
void
rte_mcfg_mem_read_lock(void);

/**
 * Unlock the internal EAL shared memory configuration for shared access.
 */
void
rte_mcfg_mem_read_unlock(void);

/**
 * Lock the internal EAL shared memory configuration for exclusive access.
 */
void
rte_mcfg_mem_write_lock(void);

/**
 * Unlock the internal EAL shared memory configuration for exclusive access.
 */
void
rte_mcfg_mem_write_unlock(void);

/**
 * Lock the internal EAL TAILQ list for shared access.
 */
void
rte_mcfg_tailq_read_lock(void);

/**
 * Unlock the internal EAL TAILQ list for shared access.
 */
void
rte_mcfg_tailq_read_unlock(void);

/**
 * Lock the internal EAL TAILQ list for exclusive access.
 */
void
rte_mcfg_tailq_write_lock(void);

/**
 * Unlock the internal EAL TAILQ list for exclusive access.
 */
void
rte_mcfg_tailq_write_unlock(void);

/**
 * Lock the internal EAL Mempool list for shared access.
 */
void
rte_mcfg_mempool_read_lock(void);

/**
 * Unlock the internal EAL Mempool list for shared access.
 */
void
rte_mcfg_mempool_read_unlock(void);

/**
 * Lock the internal EAL Mempool list for exclusive access.
 */
void
rte_mcfg_mempool_write_lock(void);

/**
 * Unlock the internal EAL Mempool list for exclusive access.
 */
void
rte_mcfg_mempool_write_unlock(void);

#ifdef __cplusplus
}
#endif

#endif /*__RTE_EAL_MEMCONFIG_H_*/
