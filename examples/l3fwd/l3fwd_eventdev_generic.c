/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2019 Marvell International Ltd.
 */

#include "l3fwd.h"
#include "l3fwd_eventdev.h"

static void
l3fwd_event_port_setup_generic(void)
{
	struct l3fwd_eventdev_resources *evdev_rsrc = l3fwd_get_eventdev_rsrc();
	uint8_t event_d_id = evdev_rsrc->event_d_id;
	struct rte_event_port_conf event_p_conf = {
		.dequeue_depth = 32,
		.enqueue_depth = 32,
		.new_event_threshold = 4096
	};
	struct rte_event_port_conf def_p_conf;
	uint8_t event_p_id;
	int32_t ret;

	evdev_rsrc->evp.event_p_id = (uint8_t *)malloc(sizeof(uint8_t) *
					evdev_rsrc->evp.nb_ports);
	if (!evdev_rsrc->evp.event_p_id)
		rte_exit(EXIT_FAILURE, " No space is available");

	memset(&def_p_conf, 0, sizeof(struct rte_event_port_conf));
	rte_event_port_default_conf_get(event_d_id, 0, &def_p_conf);

	if (def_p_conf.new_event_threshold < event_p_conf.new_event_threshold)
		event_p_conf.new_event_threshold =
			def_p_conf.new_event_threshold;

	if (def_p_conf.dequeue_depth < event_p_conf.dequeue_depth)
		event_p_conf.dequeue_depth = def_p_conf.dequeue_depth;

	if (def_p_conf.enqueue_depth < event_p_conf.enqueue_depth)
		event_p_conf.enqueue_depth = def_p_conf.enqueue_depth;

	event_p_conf.disable_implicit_release =
		evdev_rsrc->disable_implicit_release;
	evdev_rsrc->deq_depth = def_p_conf.dequeue_depth;

	for (event_p_id = 0; event_p_id < evdev_rsrc->evp.nb_ports;
								event_p_id++) {
		ret = rte_event_port_setup(event_d_id, event_p_id,
					   &event_p_conf);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				 "Error in configuring event port %d\n",
				 event_p_id);
		}

		ret = rte_event_port_link(event_d_id, event_p_id,
					  evdev_rsrc->evq.event_q_id,
					  NULL,
					  evdev_rsrc->evq.nb_queues - 1);
		if (ret != (evdev_rsrc->evq.nb_queues - 1)) {
			rte_exit(EXIT_FAILURE, "Error in linking event port %d "
				 "to event queue", event_p_id);
		}
		evdev_rsrc->evp.event_p_id[event_p_id] = event_p_id;
	}
	/* init spinlock */
	rte_spinlock_init(&evdev_rsrc->evp.lock);

	evdev_rsrc->def_p_conf = event_p_conf;
}

static void
l3fwd_event_queue_setup_generic(uint16_t ethdev_count,
				uint32_t event_queue_cfg)
{
	struct l3fwd_eventdev_resources *evdev_rsrc = l3fwd_get_eventdev_rsrc();
	uint8_t event_d_id = evdev_rsrc->event_d_id;
	struct rte_event_queue_conf event_q_conf = {
		.nb_atomic_flows = 1024,
		.nb_atomic_order_sequences = 1024,
		.event_queue_cfg = event_queue_cfg,
		.priority = RTE_EVENT_DEV_PRIORITY_NORMAL
	};
	struct rte_event_queue_conf def_q_conf;
	uint8_t event_q_id;
	int32_t ret;

	event_q_conf.schedule_type = evdev_rsrc->sync_mode;
	evdev_rsrc->evq.nb_queues = ethdev_count + 1;
	evdev_rsrc->evq.event_q_id = (uint8_t *)malloc(sizeof(uint8_t) *
					evdev_rsrc->evq.nb_queues);
	if (!evdev_rsrc->evq.event_q_id)
		rte_exit(EXIT_FAILURE, "Memory allocation failure");

	rte_event_queue_default_conf_get(event_d_id, 0, &def_q_conf);
	if (def_q_conf.nb_atomic_flows < event_q_conf.nb_atomic_flows)
		event_q_conf.nb_atomic_flows = def_q_conf.nb_atomic_flows;

	for (event_q_id = 0; event_q_id < (evdev_rsrc->evq.nb_queues - 1);
								event_q_id++) {
		ret = rte_event_queue_setup(event_d_id, event_q_id,
					    &event_q_conf);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				 "Error in configuring event queue");
		}
		evdev_rsrc->evq.event_q_id[event_q_id] = event_q_id;
	}

	event_q_conf.event_queue_cfg |= RTE_EVENT_QUEUE_CFG_SINGLE_LINK;
	event_q_conf.priority = RTE_EVENT_DEV_PRIORITY_HIGHEST,
	ret = rte_event_queue_setup(event_d_id, event_q_id, &event_q_conf);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE,
			 "Error in configuring event queue for Tx adapter");
	}
	evdev_rsrc->evq.event_q_id[event_q_id] = event_q_id;
}

static void
l3fwd_rx_tx_adapter_setup_generic(uint16_t ethdev_count)
{
	struct l3fwd_eventdev_resources *evdev_rsrc = l3fwd_get_eventdev_rsrc();
	struct rte_event_eth_rx_adapter_queue_conf eth_q_conf = {
		.rx_queue_flags = 0,
		.ev = {
			.queue_id = 0,
			.priority = RTE_EVENT_DEV_PRIORITY_NORMAL,
		}
	};
	uint8_t event_d_id = evdev_rsrc->event_d_id;
	uint8_t rx_adptr_id = 0;
	uint8_t tx_adptr_id = 0;
	uint8_t tx_port_id = 0;
	int32_t ret, i;

	/* Rx adapter setup */
	evdev_rsrc->rx_adptr.nb_rx_adptr = 1;
	evdev_rsrc->rx_adptr.rx_adptr = (uint8_t *)malloc(sizeof(uint8_t) *
					evdev_rsrc->rx_adptr.nb_rx_adptr);
	if (!evdev_rsrc->rx_adptr.rx_adptr) {
		free(evdev_rsrc->evp.event_p_id);
		free(evdev_rsrc->evq.event_q_id);
		rte_exit(EXIT_FAILURE,
			 "failed to allocate memery for Rx adapter");
	}

	ret = rte_event_eth_rx_adapter_create(rx_adptr_id, event_d_id,
					      &evdev_rsrc->def_p_conf);
	if (ret)
		rte_exit(EXIT_FAILURE, "failed to create rx adapter");

	eth_q_conf.ev.sched_type = evdev_rsrc->sync_mode;
	for (i = 0; i < ethdev_count; i++) {
		/* Configure user requested sync mode */
		eth_q_conf.ev.queue_id = evdev_rsrc->evq.event_q_id[i];
		ret = rte_event_eth_rx_adapter_queue_add(rx_adptr_id, i, -1,
							 &eth_q_conf);
		if (ret)
			rte_exit(EXIT_FAILURE,
				 "Failed to add queues to Rx adapter");
	}

	ret = rte_event_eth_rx_adapter_start(rx_adptr_id);
	if (ret)
		rte_exit(EXIT_FAILURE, "Rx adapter[%d] start failed",
			 rx_adptr_id);

	evdev_rsrc->rx_adptr.rx_adptr[0] = rx_adptr_id;

	/* Tx adapter setup */
	evdev_rsrc->tx_adptr.nb_tx_adptr = 1;
	evdev_rsrc->tx_adptr.tx_adptr = (uint8_t *)malloc(sizeof(uint8_t) *
					evdev_rsrc->tx_adptr.nb_tx_adptr);
	if (!evdev_rsrc->tx_adptr.tx_adptr) {
		free(evdev_rsrc->rx_adptr.rx_adptr);
		free(evdev_rsrc->evp.event_p_id);
		free(evdev_rsrc->evq.event_q_id);
		rte_exit(EXIT_FAILURE,
			 "failed to allocate memery for Rx adapter");
	}

	ret = rte_event_eth_tx_adapter_create(tx_adptr_id, event_d_id,
					      &evdev_rsrc->def_p_conf);
	if (ret)
		rte_exit(EXIT_FAILURE, "failed to create tx adapter[%d]",
			 tx_adptr_id);

	for (i = 0; i < ethdev_count; i++) {
		ret = rte_event_eth_tx_adapter_queue_add(tx_adptr_id, i, -1);
		if (ret)
			rte_exit(EXIT_FAILURE,
				 "failed to add queues to Tx adapter");
	}

	ret = rte_event_eth_tx_adapter_event_port_get(tx_adptr_id, &tx_port_id);
	if (ret)
		rte_exit(EXIT_FAILURE,
			 "Failed to get Tx adapter port id: %d\n", ret);

	ret = rte_event_port_link(event_d_id, tx_port_id,
				  &evdev_rsrc->evq.event_q_id[
					evdev_rsrc->evq.nb_queues - 1],
				  NULL, 1);
	if (ret != 1)
		rte_exit(EXIT_FAILURE,
			 "Unable to link Tx adapter port to Tx queue:err = %d",
			 ret);

	ret = rte_event_eth_tx_adapter_start(tx_adptr_id);
	if (ret)
		rte_exit(EXIT_FAILURE, "Tx adapter[%d] start failed",
			 tx_adptr_id);

	evdev_rsrc->tx_adptr.tx_adptr[0] = tx_adptr_id;
}

void
l3fwd_eventdev_set_generic_ops(struct l3fwd_eventdev_setup_ops *ops)
{
	ops->event_queue_setup = l3fwd_event_queue_setup_generic;
	ops->event_port_setup = l3fwd_event_port_setup_generic;
	ops->adapter_setup = l3fwd_rx_tx_adapter_setup_generic;
}
