/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell International Ltd.
 */

#define RTE_TRACE_POINT_REGISTER_SELECT /* Select trace point register macros */

#include "rte_trace_mempool.h"

RTE_TRACE_POINT_DEFINE(rte_trace_lib_mempool_ops_dequeue_bulk);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_mempool_ops_dequeue_contig_blocks);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_mempool_ops_enqueue_bulk);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_mempool_generic_put);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_mempool_put_bulk);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_mempool_generic_get);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_mempool_get_bulk);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_mempool_get_contig_blocks);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_mempool_create);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_mempool_create_empty);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_mempool_free);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_mempool_populate_iova);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_mempool_populate_virt);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_mempool_populate_default);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_mempool_populate_anon);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_mempool_cache_create);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_mempool_cache_free);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_mempool_default_cache);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_mempool_get_page_size);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_mempool_cache_flush);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_mempool_ops_populate);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_mempool_ops_alloc);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_mempool_ops_free);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_mempool_set_ops_byname);

RTE_INIT(mempool_trace_init)
{
	RTE_TRACE_POINT_REGISTER(rte_trace_lib_mempool_ops_dequeue_bulk,
				 lib.mempool.ops.deq.bulk, INFO);

	RTE_TRACE_POINT_REGISTER(
		rte_trace_lib_mempool_ops_dequeue_contig_blocks,
				 lib.mempool.ops.deq.contig, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_mempool_ops_enqueue_bulk,
				 lib.mempool.ops.enq.bulk, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_mempool_generic_put,
				 lib.mempool.generic.put, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_mempool_put_bulk,
				 lib.mempool.put.bulk, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_mempool_generic_get,
				 lib.mempool.generic.get, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_mempool_get_bulk,
				 lib.mempool.get.bulk, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_mempool_get_contig_blocks,
				 lib.mempool.get.blocks, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_mempool_create,
				 lib.mempool.create, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_mempool_create_empty,
				 lib.mempool.create.empty, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_mempool_free,
				 lib.mempool.free, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_mempool_populate_iova,
				 lib.mempool.populate.iova, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_mempool_populate_virt,
				 lib.mempool.populate.virt, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_mempool_populate_default,
				 lib.mempool.populate.default, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_mempool_populate_anon,
				 lib.mempool.populate.anon, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_mempool_cache_create,
				 lib.mempool.cache_create, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_mempool_cache_free,
				 lib.mempool.cache.free, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_mempool_default_cache,
				 lib.mempool.default.cache, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_mempool_get_page_size,
				 lib.mempool.get.page.size, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_mempool_cache_flush,
				 lib.mempool.cache.flush, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_mempool_ops_populate,
				 lib.mempool.ops.populate, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_mempool_ops_alloc,
				 lib.mempool.ops.alloc, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_mempool_ops_free,
				 lib.mempool.ops.free, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_mempool_set_ops_byname,
				 lib.mempool.set.ops.byname, INFO);
}
