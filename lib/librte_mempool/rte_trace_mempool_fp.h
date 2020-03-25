/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell International Ltd.
 */

#ifndef _RTE_TRACE_MEMPOOL_FP_H_
#define _RTE_TRACE_MEMPOOL_FP_H_

/**
 * @file
 *
 * Mempool fast path API for trace support
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_trace.h>

RTE_TRACE_POINT_DP(
	rte_trace_lib_mempool_ops_dequeue_bulk,
	RTE_TRACE_POINT_ARGS(void *mempool, void **obj_table,
			     uint32_t nb_objs),
	rte_trace_ctf_ptr(mempool); rte_trace_ctf_ptr(obj_table);
	rte_trace_ctf_u32(nb_objs);
)

RTE_TRACE_POINT_DP(
	rte_trace_lib_mempool_ops_dequeue_contig_blocks,
	RTE_TRACE_POINT_ARGS(void *mempool, void **first_obj_table,
			     uint32_t nb_objs),
	rte_trace_ctf_ptr(mempool); rte_trace_ctf_ptr(first_obj_table);
	rte_trace_ctf_u32(nb_objs);
)

RTE_TRACE_POINT_DP(
	rte_trace_lib_mempool_ops_enqueue_bulk,
	RTE_TRACE_POINT_ARGS(void *mempool, void * const *obj_table,
			     uint32_t nb_objs),
	rte_trace_ctf_ptr(mempool); rte_trace_ctf_ptr(obj_table);
	rte_trace_ctf_u32(nb_objs);
)

RTE_TRACE_POINT_DP(
	rte_trace_lib_mempool_generic_put,
	RTE_TRACE_POINT_ARGS(void *mempool, void * const *obj_table,
			     uint32_t nb_objs, void *cache),
	rte_trace_ctf_ptr(mempool); rte_trace_ctf_ptr(obj_table);
	rte_trace_ctf_u32(nb_objs); rte_trace_ctf_ptr(cache);
)

RTE_TRACE_POINT_DP(
	rte_trace_lib_mempool_put_bulk,
	RTE_TRACE_POINT_ARGS(void *mempool, void * const *obj_table,
			     uint32_t nb_objs, void *cache),
	rte_trace_ctf_ptr(mempool); rte_trace_ctf_ptr(obj_table);
	rte_trace_ctf_u32(nb_objs); rte_trace_ctf_ptr(cache);
)

RTE_TRACE_POINT_DP(
	rte_trace_lib_mempool_generic_get,
	RTE_TRACE_POINT_ARGS(void *mempool, void * const *obj_table,
			     uint32_t nb_objs, void *cache),
	rte_trace_ctf_ptr(mempool); rte_trace_ctf_ptr(obj_table);
	rte_trace_ctf_u32(nb_objs); rte_trace_ctf_ptr(cache);
)

RTE_TRACE_POINT_DP(
	rte_trace_lib_mempool_get_bulk,
	RTE_TRACE_POINT_ARGS(void *mempool, void **obj_table,
			     uint32_t nb_objs, void *cache),
	rte_trace_ctf_ptr(mempool); rte_trace_ctf_ptr(obj_table);
	rte_trace_ctf_u32(nb_objs); rte_trace_ctf_ptr(cache);
)

RTE_TRACE_POINT_DP(
	rte_trace_lib_mempool_get_contig_blocks,
	RTE_TRACE_POINT_ARGS(void *mempool, void **first_obj_table,
			     uint32_t nb_objs),
	rte_trace_ctf_ptr(mempool); rte_trace_ctf_ptr(first_obj_table);
	rte_trace_ctf_u32(nb_objs);
)

RTE_TRACE_POINT_DP(
	rte_trace_lib_mempool_default_cache,
	RTE_TRACE_POINT_ARGS(void *mempool, uint32_t lcore_id,
			     void *default_cache),
	rte_trace_ctf_ptr(mempool); rte_trace_ctf_u32(lcore_id);
	rte_trace_ctf_ptr(default_cache);
)

RTE_TRACE_POINT_DP(
	rte_trace_lib_mempool_cache_flush,
	RTE_TRACE_POINT_ARGS(void *cache, void *mempool),
	rte_trace_ctf_ptr(cache); rte_trace_ctf_ptr(mempool);
)

#ifdef __cplusplus
}
#endif

#endif /* _RTE_TRACE_MEMPOOL_FP_H_ */
