/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2019 Marvell International Ltd.
 */

#include <stdbool.h>
#include <getopt.h>

#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_eventdev.h>
#include <rte_event_eth_rx_adapter.h>
#include <rte_event_eth_tx_adapter.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_spinlock.h>

#include "l2fwd_common.h"
#include "l2fwd_eventdev.h"

static uint32_t
eventdev_setup_internal_port(uint16_t ethdev_count)
{
	struct eventdev_resources *eventdev_rsrc = get_eventdev_rsrc();
	struct rte_event_dev_config event_d_conf = {
		.nb_events_limit  = 4096,
		.nb_event_queue_flows = 1024,
		.nb_event_port_dequeue_depth = 128,
		.nb_event_port_enqueue_depth = 128
	};
	struct rte_event_dev_info dev_info;
	uint8_t disable_implicit_release;
	const uint8_t event_d_id = 0; /* Always use first event device only */
	uint32_t event_queue_cfg = 0;
	uint16_t num_workers = 0;
	int ret;

	/* Event device configurtion */
	rte_event_dev_info_get(event_d_id, &dev_info);

	disable_implicit_release = !!(dev_info.event_dev_cap &
				    RTE_EVENT_DEV_CAP_IMPLICIT_RELEASE_DISABLE);
	eventdev_rsrc->disable_implicit_release =
						disable_implicit_release;

	if (dev_info.event_dev_cap & RTE_EVENT_DEV_CAP_QUEUE_ALL_TYPES)
		event_queue_cfg |= RTE_EVENT_QUEUE_CFG_ALL_TYPES;

	event_d_conf.nb_event_queues = ethdev_count;
	if (dev_info.max_event_queues < event_d_conf.nb_event_queues)
		event_d_conf.nb_event_queues = dev_info.max_event_queues;

	if (dev_info.max_num_events < event_d_conf.nb_events_limit)
		event_d_conf.nb_events_limit = dev_info.max_num_events;

	if (dev_info.max_event_queue_flows < event_d_conf.nb_event_queue_flows)
		event_d_conf.nb_event_queue_flows =
						dev_info.max_event_queue_flows;

	if (dev_info.max_event_port_dequeue_depth <
				event_d_conf.nb_event_port_dequeue_depth)
		event_d_conf.nb_event_port_dequeue_depth =
				dev_info.max_event_port_dequeue_depth;

	if (dev_info.max_event_port_enqueue_depth <
				event_d_conf.nb_event_port_enqueue_depth)
		event_d_conf.nb_event_port_enqueue_depth =
				dev_info.max_event_port_enqueue_depth;

	num_workers = rte_lcore_count();
	if (dev_info.max_event_ports < num_workers)
		num_workers = dev_info.max_event_ports;

	event_d_conf.nb_event_ports = num_workers;
	eventdev_rsrc->evp.nb_ports = num_workers;
	eventdev_rsrc->has_burst = !!(dev_info.event_dev_cap &
				    RTE_EVENT_DEV_CAP_BURST_MODE);

	ret = rte_event_dev_configure(event_d_id, &event_d_conf);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error in configuring event device");

	eventdev_rsrc->event_d_id = event_d_id;
	return event_queue_cfg;
}

static void
event_port_setup_internal_port(void)
{
	struct eventdev_resources *eventdev_rsrc = get_eventdev_rsrc();
	uint8_t event_d_id = eventdev_rsrc->event_d_id;
	struct rte_event_port_conf event_p_conf = {
		.dequeue_depth = 32,
		.enqueue_depth = 32,
		.new_event_threshold = 4096
	};
	struct rte_event_port_conf def_p_conf;
	uint8_t event_p_id;
	int32_t ret;

	eventdev_rsrc->evp.event_p_id = (uint8_t *)malloc(sizeof(uint8_t) *
					eventdev_rsrc->evp.nb_ports);
	if (!eventdev_rsrc->evp.event_p_id)
		rte_exit(EXIT_FAILURE,
			 "Failed to allocate memory for Event Ports");

	rte_event_port_default_conf_get(event_d_id, 0, &def_p_conf);
	if (def_p_conf.new_event_threshold < event_p_conf.new_event_threshold)
		event_p_conf.new_event_threshold =
						def_p_conf.new_event_threshold;

	if (def_p_conf.dequeue_depth < event_p_conf.dequeue_depth)
		event_p_conf.dequeue_depth = def_p_conf.dequeue_depth;

	if (def_p_conf.enqueue_depth < event_p_conf.enqueue_depth)
		event_p_conf.enqueue_depth = def_p_conf.enqueue_depth;

	event_p_conf.disable_implicit_release =
		eventdev_rsrc->disable_implicit_release;

	for (event_p_id = 0; event_p_id < eventdev_rsrc->evp.nb_ports;
								event_p_id++) {
		ret = rte_event_port_setup(event_d_id, event_p_id,
					   &event_p_conf);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				 "Error in configuring event port %d\n",
				 event_p_id);
		}

		ret = rte_event_port_link(event_d_id, event_p_id, NULL,
					  NULL, 0);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE, "Error in linking event port %d "
				 "to event queue", event_p_id);
		}
		eventdev_rsrc->evp.event_p_id[event_p_id] = event_p_id;

		/* init spinlock */
		rte_spinlock_init(&eventdev_rsrc->evp.lock);
	}

	eventdev_rsrc->def_p_conf = event_p_conf;
}

static void
event_queue_setup_internal_port(uint16_t ethdev_count, uint32_t event_queue_cfg)
{
	struct eventdev_resources *eventdev_rsrc = get_eventdev_rsrc();
	uint8_t event_d_id = eventdev_rsrc->event_d_id;
	struct rte_event_queue_conf event_q_conf = {
		.nb_atomic_flows = 1024,
		.nb_atomic_order_sequences = 1024,
		.event_queue_cfg = event_queue_cfg,
		.priority = RTE_EVENT_DEV_PRIORITY_NORMAL
	};
	struct rte_event_queue_conf def_q_conf;
	uint8_t event_q_id = 0;
	int32_t ret;

	rte_event_queue_default_conf_get(event_d_id, event_q_id, &def_q_conf);

	if (def_q_conf.nb_atomic_flows < event_q_conf.nb_atomic_flows)
		event_q_conf.nb_atomic_flows = def_q_conf.nb_atomic_flows;

	if (def_q_conf.nb_atomic_order_sequences <
					event_q_conf.nb_atomic_order_sequences)
		event_q_conf.nb_atomic_order_sequences =
					def_q_conf.nb_atomic_order_sequences;

	event_q_conf.event_queue_cfg = event_queue_cfg;
	event_q_conf.schedule_type = eventdev_rsrc->sync_mode;
	eventdev_rsrc->evq.nb_queues = ethdev_count;
	eventdev_rsrc->evq.event_q_id = (uint8_t *)malloc(sizeof(uint8_t) *
					eventdev_rsrc->evq.nb_queues);
	if (!eventdev_rsrc->evq.event_q_id)
		rte_exit(EXIT_FAILURE, "Memory allocation failure");

	for (event_q_id = 0; event_q_id < ethdev_count; event_q_id++) {
		ret = rte_event_queue_setup(event_d_id, event_q_id,
					    &event_q_conf);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				 "Error in configuring event queue");
		}
		eventdev_rsrc->evq.event_q_id[event_q_id] = event_q_id;
	}
}

static void
rx_tx_adapter_setup_internal_port(uint16_t ethdev_count)
{
	struct eventdev_resources *eventdev_rsrc = get_eventdev_rsrc();
	struct rte_event_eth_rx_adapter_queue_conf eth_q_conf = {
		.rx_queue_flags = 0,
		.ev = {
			.queue_id = 0,
			.priority = RTE_EVENT_DEV_PRIORITY_NORMAL,
		}
	};
	uint8_t event_d_id = eventdev_rsrc->event_d_id;
	int32_t ret, i;

	eventdev_rsrc->rx_adptr.nb_rx_adptr = ethdev_count;
	eventdev_rsrc->rx_adptr.rx_adptr = (uint8_t *)malloc(sizeof(uint8_t) *
					eventdev_rsrc->rx_adptr.nb_rx_adptr);
	if (!eventdev_rsrc->rx_adptr.rx_adptr) {
		free(eventdev_rsrc->evp.event_p_id);
		free(eventdev_rsrc->evq.event_q_id);
		rte_exit(EXIT_FAILURE,
			 "failed to allocate memery for Rx adapter");
	}

	for (i = 0; i < ethdev_count; i++) {
		ret = rte_event_eth_rx_adapter_create(i, event_d_id,
						&eventdev_rsrc->def_p_conf);
		if (ret)
			rte_exit(EXIT_FAILURE,
				 "failed to create rx adapter[%d]", i);

		/* Configure user requested sync mode */
		eth_q_conf.ev.queue_id = eventdev_rsrc->evq.event_q_id[i];
		eth_q_conf.ev.sched_type = eventdev_rsrc->sync_mode;
		ret = rte_event_eth_rx_adapter_queue_add(i, i, -1, &eth_q_conf);
		if (ret)
			rte_exit(EXIT_FAILURE,
				 "Failed to add queues to Rx adapter");

		ret = rte_event_eth_rx_adapter_start(i);
		if (ret)
			rte_exit(EXIT_FAILURE,
				 "Rx adapter[%d] start failed", i);

		eventdev_rsrc->rx_adptr.rx_adptr[i] = i;
	}

	eventdev_rsrc->tx_adptr.nb_tx_adptr = ethdev_count;
	eventdev_rsrc->tx_adptr.tx_adptr = (uint8_t *)malloc(sizeof(uint8_t) *
					eventdev_rsrc->tx_adptr.nb_tx_adptr);
	if (!eventdev_rsrc->tx_adptr.tx_adptr) {
		free(eventdev_rsrc->rx_adptr.rx_adptr);
		free(eventdev_rsrc->evp.event_p_id);
		free(eventdev_rsrc->evq.event_q_id);
		rte_exit(EXIT_FAILURE,
			 "failed to allocate memery for Rx adapter");
	}

	for (i = 0; i < ethdev_count; i++) {
		ret = rte_event_eth_tx_adapter_create(i, event_d_id,
						&eventdev_rsrc->def_p_conf);
		if (ret)
			rte_exit(EXIT_FAILURE,
				 "failed to create tx adapter[%d]", i);

		ret = rte_event_eth_tx_adapter_queue_add(i, i, -1);
		if (ret)
			rte_exit(EXIT_FAILURE,
				 "failed to add queues to Tx adapter");

		ret = rte_event_eth_tx_adapter_start(i);
		if (ret)
			rte_exit(EXIT_FAILURE,
				 "Tx adapter[%d] start failed", i);

		eventdev_rsrc->tx_adptr.tx_adptr[i] = i;
	}
}

void
eventdev_set_internal_port_ops(struct eventdev_setup_ops *ops)
{
	ops->eventdev_setup = eventdev_setup_internal_port;
	ops->event_queue_setup = event_queue_setup_internal_port;
	ops->event_port_setup = event_port_setup_internal_port;
	ops->adapter_setup = rx_tx_adapter_setup_internal_port;
}
