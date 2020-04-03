/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell International Ltd.
 */

#define RTE_TRACE_POINT_REGISTER_SELECT /* Select trace point register macros */

#include "rte_trace_eventdev.h"

/* Eventdev trace points */
RTE_TRACE_POINT_DEFINE(rte_trace_lib_eventdev_configure);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_event_queue_setup);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_event_port_setup);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_event_port_link);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_event_port_unlink);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_eventdev_start);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_eventdev_stop);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_eventdev_close);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_event_enq_burst);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_event_deq_burst);

/* Eventdev Rx adapter trace points */
RTE_TRACE_POINT_DEFINE(rte_trace_lib_event_eth_rx_adapter_create);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_event_eth_rx_adapter_free);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_event_eth_rx_adapter_queue_add);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_event_eth_rx_adapter_queue_del);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_event_eth_rx_adapter_start);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_event_eth_rx_adapter_stop);

/* Eventdev Tx adapter trace points */
RTE_TRACE_POINT_DEFINE(rte_trace_lib_event_eth_tx_adapter_create);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_event_eth_tx_adapter_free);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_event_eth_tx_adapter_queue_add);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_event_eth_tx_adapter_queue_del);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_event_eth_tx_adapter_start);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_event_eth_tx_adapter_stop);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_event_eth_tx_adapter_enqueue);

/* Eventdev Timer adapter trace points */
RTE_TRACE_POINT_DEFINE(rte_trace_lib_event_timer_adapter_create);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_event_timer_adapter_start);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_event_timer_adapter_stop);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_event_timer_adapter_free);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_event_timer_arm_burst);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_event_timer_arm_tmo_tick_burst);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_event_timer_cancel_burst);

/* Eventdev Crypto adapter trace points */
RTE_TRACE_POINT_DEFINE(rte_trace_lib_event_crypto_adapter_create);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_event_crypto_adapter_free);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_event_crypto_adapter_queue_pair_add);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_event_crypto_adapter_queue_pair_del);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_event_crypto_adapter_start);
RTE_TRACE_POINT_DEFINE(rte_trace_lib_event_crypto_adapter_stop);

RTE_INIT(eventdev_trace_init)
{
	/* Eventdev trace points */
	RTE_TRACE_POINT_REGISTER(rte_trace_lib_eventdev_configure,
				 lib.eventdev.configure, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_event_queue_setup,
				 lib.eventdev.queue.setup, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_event_port_setup,
				 lib.eventdev.port.setup, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_event_port_link,
				 lib.eventdev.port.link, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_event_port_unlink,
				 lib.eventdev.port.unlink, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_eventdev_start,
				 lib.eventdev.start, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_eventdev_stop,
				 lib.eventdev.stop, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_eventdev_close,
				 lib.eventdev.close, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_event_enq_burst,
				 lib.eventdev.enq.burst, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_event_deq_burst,
				 lib.eventdev.deq.burst, INFO);


	/* Eventdev Rx adapter trace points */
	RTE_TRACE_POINT_REGISTER(rte_trace_lib_event_eth_rx_adapter_create,
				 lib.eventdev.rx.adapter.create, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_event_eth_rx_adapter_free,
				 lib.eventdev.rx.adapter.free, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_event_eth_rx_adapter_queue_add,
				 lib.eventdev.rx.adapter.queue.add, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_event_eth_rx_adapter_queue_del,
				 lib.eventdev.rx.adapter.queue.del, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_event_eth_rx_adapter_start,
				 lib.eventdev.rx.adapter.start, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_event_eth_rx_adapter_stop,
				 lib.eventdev.rx.adapter.stop, INFO);

	/* Eventdev Tx adapter trace points */
	RTE_TRACE_POINT_REGISTER(rte_trace_lib_event_eth_tx_adapter_create,
				 lib.eventdev.tx.adapter.create, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_event_eth_tx_adapter_free,
				 lib.eventdev.tx.adapter.free, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_event_eth_tx_adapter_queue_add,
				 lib.eventdev.tx.adapter.queue.add, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_event_eth_tx_adapter_queue_del,
				 lib.eventdev.tx.adapter.queue.del, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_event_eth_tx_adapter_start,
				 lib.eventdev.tx.adapter.start, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_event_eth_tx_adapter_stop,
				 lib.eventdev.tx.adapter.stop, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_event_eth_tx_adapter_enqueue,
				 lib.eventdev.tx.adapter.enq, INFO);


	/* Eventdev Timer adapter trace points */
	RTE_TRACE_POINT_REGISTER(rte_trace_lib_event_timer_adapter_create,
				 lib.eventdev.timer.create, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_event_timer_adapter_start,
				 lib.eventdev.timer.start, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_event_timer_adapter_stop,
				 lib.eventdev.timer.stop, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_event_timer_adapter_free,
				 lib.eventdev.timer.free, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_event_timer_arm_burst,
				 lib.eventdev.timer.burst, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_event_timer_arm_tmo_tick_burst,
				 lib.eventdev.timer.tick.burst, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_event_timer_cancel_burst,
				 lib.eventdev.timer.cancel, INFO);

	/* Eventdev Crypto adapter trace points */
	RTE_TRACE_POINT_REGISTER(rte_trace_lib_event_crypto_adapter_create,
				 lib.eventdev.crypto.create, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_event_crypto_adapter_free,
				 lib.eventdev.crypto.free, INFO);

	RTE_TRACE_POINT_REGISTER(
			rte_trace_lib_event_crypto_adapter_queue_pair_add,
			lib.eventdev.crypto.queue.add, INFO);

	RTE_TRACE_POINT_REGISTER(
			rte_trace_lib_event_crypto_adapter_queue_pair_del,
			lib.eventdev.crypto.queue.del, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_event_crypto_adapter_start,
				 lib.eventdev.crypto.start, INFO);

	RTE_TRACE_POINT_REGISTER(rte_trace_lib_event_crypto_adapter_stop,
				 lib.eventdev.crypto.stop, INFO);
}
