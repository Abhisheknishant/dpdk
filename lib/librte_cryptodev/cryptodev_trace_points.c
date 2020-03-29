/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell International Ltd.
 */

#define RTE_TRACE_POINT_REGISTER_SELECT /* Select trace point register macros */

#include "rte_trace_cryptodev.h"

RTE_TRACE_POINT_DEFINE(rte_trace_lib_cryptodev_configure);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_cryptodev_start);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_cryptodev_stop);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_cryptodev_close);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_cryptodev_queue_pair_setup);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_cryptodev_sym_session_pool_create);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_cryptodev_sym_session_create);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_cryptodev_asym_session_create);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_cryptodev_sym_session_free);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_cryptodev_asym_session_free);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_cryptodev_sym_session_init);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_cryptodev_asym_session_init);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_cryptodev_sym_session_clear);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_cryptodev_asym_session_clear);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_cryptodev_enqueue_burst);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_cryptodev_dequeue_burst);

RTE_INIT(cryptodev_trace_init)
{
	RTE_TRACE_POINT_REGISTER(rte_trace_lib_cryptodev_configure,
				 lib.cryptodev.configure, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_cryptodev_start,
				 lib.cryptodev.start, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_cryptodev_stop,
				 lib.cryptodev.stop, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_cryptodev_close,
				 lib.cryptodev.close, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_cryptodev_queue_pair_setup,
				 lib.cryptodev.queue.pair.setup, INFO);

	RTE_TRACE_POINT_REGISTER(
			rte_trace_lib_cryptodev_sym_session_pool_create,
			lib.cryptodev.sym.pool.create, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_cryptodev_sym_session_create,
				 lib.cryptodev.sym.create, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_cryptodev_asym_session_create,
				 lib.cryptodev.asym.create, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_cryptodev_sym_session_free,
				 lib.cryptodev.sym.free, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_cryptodev_asym_session_free,
				 lib.cryptodev.asym.free, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_cryptodev_sym_session_init,
				 lib.cryptodev.sym.init, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_cryptodev_asym_session_init,
				 lib.cryptodev.asym.init, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_cryptodev_enqueue_burst,
				 lib.cryptodev.enq.burst, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_cryptodev_dequeue_burst,
				 lib.cryptodev.deq.burst, INFO);
}
