/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell International Ltd.
 */

#define RTE_TRACE_POINT_REGISTER_SELECT /* Select trace point register macros */

#include <rte_trace_ethdev.h>

RTE_TRACE_POINT_DEFINE(rte_trace_lib_ethdev_configure);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_ethdev_rxq_setup);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_ethdev_txq_setup);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_ethdev_start);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_ethdev_stop);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_ethdev_close);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_ethdev_rx_burst);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_ethdev_tx_burst);

RTE_INIT(ethdev_trace_init)
{
	RTE_TRACE_POINT_REGISTER(rte_trace_lib_ethdev_configure,
				 lib.ethdev.configure, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_ethdev_rxq_setup,
				 lib.ethdev.rxq.setup, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_ethdev_txq_setup,
				 lib.ethdev.txq.setup, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_ethdev_start,
				 lib.ethdev.start, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_ethdev_stop,
				 lib.ethdev.stop, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_ethdev_close,
				 lib.ethdev.close, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_ethdev_rx_burst,
				 lib.ethdev.rx.burst, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_ethdev_tx_burst,
				 lib.ethdev.tx.burst, INFO);
}
