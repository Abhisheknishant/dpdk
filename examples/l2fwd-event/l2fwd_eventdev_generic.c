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
eventdev_setup_generic(uint16_t ethdev_count)
{
	struct eventdev_resources *eventdev_rsrc = get_eventdev_rsrc();
	struct rte_event_dev_config event_d_conf = {
		.nb_events_limit  = 4096,
		.nb_event_queue_flows = 1024,
		.nb_event_port_dequeue_depth = 128,
		.nb_event_port_enqueue_depth = 128
	};
	struct rte_event_dev_info dev_info;
	const uint8_t event_d_id = 0; /* Always use first event device only */
	uint32_t event_queue_cfg = 0;
	uint16_t num_workers = 0;
	int ret;

	/* Event device configurtion */
	rte_event_dev_info_get(event_d_id, &dev_info);
	eventdev_rsrc->disable_implicit_release = !!(dev_info.event_dev_cap &
				    RTE_EVENT_DEV_CAP_IMPLICIT_RELEASE_DISABLE);

	if (dev_info.event_dev_cap & RTE_EVENT_DEV_CAP_QUEUE_ALL_TYPES)
		event_queue_cfg |= RTE_EVENT_QUEUE_CFG_ALL_TYPES;

	/* One queue for each ethdev port + one Tx adapter Single link queue. */
	event_d_conf.nb_event_queues = ethdev_count + 1;
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

	num_workers = rte_lcore_count() - rte_service_lcore_count();
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
event_port_setup_generic(void)
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

	/* Service cores are not used to run worker thread */
	eventdev_rsrc->evp.nb_ports = eventdev_rsrc->evp.nb_ports;
	eventdev_rsrc->evp.event_p_id = (uint8_t *)malloc(sizeof(uint8_t) *
					eventdev_rsrc->evp.nb_ports);
	if (!eventdev_rsrc->evp.event_p_id)
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
		eventdev_rsrc->disable_implicit_release;
	eventdev_rsrc->deq_depth = def_p_conf.dequeue_depth;

	for (event_p_id = 0; event_p_id < eventdev_rsrc->evp.nb_ports;
								event_p_id++) {
		ret = rte_event_port_setup(event_d_id, event_p_id,
					   &event_p_conf);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				 "Error in configuring event port %d\n",
				 event_p_id);
		}

		ret = rte_event_port_link(event_d_id, event_p_id,
					  eventdev_rsrc->evq.event_q_id,
					  NULL,
					  eventdev_rsrc->evq.nb_queues - 1);
		if (ret != (eventdev_rsrc->evq.nb_queues - 1)) {
			rte_exit(EXIT_FAILURE, "Error in linking event port %d "
				 "to event queue", event_p_id);
		}
		eventdev_rsrc->evp.event_p_id[event_p_id] = event_p_id;
	}
	/* init spinlock */
	rte_spinlock_init(&eventdev_rsrc->evp.lock);

	eventdev_rsrc->def_p_conf = event_p_conf;
}

static void
event_queue_setup_generic(uint16_t ethdev_count, uint32_t event_queue_cfg)
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
	uint8_t event_q_id;
	int32_t ret;

	event_q_conf.schedule_type = eventdev_rsrc->sync_mode;
	eventdev_rsrc->evq.nb_queues = ethdev_count + 1;
	eventdev_rsrc->evq.event_q_id = (uint8_t *)malloc(sizeof(uint8_t) *
					eventdev_rsrc->evq.nb_queues);
	if (!eventdev_rsrc->evq.event_q_id)
		rte_exit(EXIT_FAILURE, "Memory allocation failure");

	rte_event_queue_default_conf_get(event_d_id, 0, &def_q_conf);
	if (def_q_conf.nb_atomic_flows < event_q_conf.nb_atomic_flows)
		event_q_conf.nb_atomic_flows = def_q_conf.nb_atomic_flows;

	for (event_q_id = 0; event_q_id < (eventdev_rsrc->evq.nb_queues - 1);
								event_q_id++) {
		ret = rte_event_queue_setup(event_d_id, event_q_id,
					    &event_q_conf);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				 "Error in configuring event queue");
		}
		eventdev_rsrc->evq.event_q_id[event_q_id] = event_q_id;
	}

	event_q_conf.event_queue_cfg |= RTE_EVENT_QUEUE_CFG_SINGLE_LINK;
	event_q_conf.priority = RTE_EVENT_DEV_PRIORITY_HIGHEST,
	ret = rte_event_queue_setup(event_d_id, event_q_id, &event_q_conf);
	if (ret < 0) {
		rte_exit(EXIT_FAILURE,
			 "Error in configuring event queue for Tx adapter");
	}
	eventdev_rsrc->evq.event_q_id[event_q_id] = event_q_id;
}

static void
rx_tx_adapter_setup_generic(uint16_t ethdev_count)
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
	uint8_t rx_adptr_id = 0;
	uint8_t tx_adptr_id = 0;
	uint8_t tx_port_id = 0;
	uint32_t service_id;
	int32_t ret, i;

	/* Rx adapter setup */
	eventdev_rsrc->rx_adptr.nb_rx_adptr = 1;
	eventdev_rsrc->rx_adptr.rx_adptr = (uint8_t *)malloc(sizeof(uint8_t) *
					eventdev_rsrc->rx_adptr.nb_rx_adptr);
	if (!eventdev_rsrc->rx_adptr.rx_adptr) {
		free(eventdev_rsrc->evp.event_p_id);
		free(eventdev_rsrc->evq.event_q_id);
		rte_exit(EXIT_FAILURE,
			 "failed to allocate memery for Rx adapter");
	}

	ret = rte_event_eth_rx_adapter_create(rx_adptr_id, event_d_id,
					      &eventdev_rsrc->def_p_conf);
	if (ret)
		rte_exit(EXIT_FAILURE, "failed to create rx adapter");

	eth_q_conf.ev.sched_type = eventdev_rsrc->sync_mode;
	for (i = 0; i < ethdev_count; i++) {
		/* Configure user requested sync mode */
		eth_q_conf.ev.queue_id = eventdev_rsrc->evq.event_q_id[i];
		ret = rte_event_eth_rx_adapter_queue_add(rx_adptr_id, i, -1,
							 &eth_q_conf);
		if (ret)
			rte_exit(EXIT_FAILURE,
				 "Failed to add queues to Rx adapter");
	}

	ret = rte_event_eth_rx_adapter_service_id_get(rx_adptr_id, &service_id);
	if (ret != -ESRCH && ret != 0) {
		rte_exit(EXIT_FAILURE,
			"Error getting the service ID for rx adptr\n");
	}

	rte_service_runstate_set(service_id, 1);
	rte_service_set_runstate_mapped_check(service_id, 0);
	eventdev_rsrc->rx_adptr.service_id = service_id;

	ret = rte_event_eth_rx_adapter_start(rx_adptr_id);
	if (ret)
		rte_exit(EXIT_FAILURE, "Rx adapter[%d] start failed",
			 rx_adptr_id);

	eventdev_rsrc->rx_adptr.rx_adptr[0] = rx_adptr_id;

	/* Tx adapter setup */
	eventdev_rsrc->tx_adptr.nb_tx_adptr = 1;
	eventdev_rsrc->tx_adptr.tx_adptr = (uint8_t *)malloc(sizeof(uint8_t) *
					eventdev_rsrc->tx_adptr.nb_tx_adptr);
	if (!eventdev_rsrc->tx_adptr.tx_adptr) {
		free(eventdev_rsrc->rx_adptr.rx_adptr);
		free(eventdev_rsrc->evp.event_p_id);
		free(eventdev_rsrc->evq.event_q_id);
		rte_exit(EXIT_FAILURE,
			 "failed to allocate memery for Rx adapter");
	}

	ret = rte_event_eth_tx_adapter_create(tx_adptr_id, event_d_id,
					      &eventdev_rsrc->def_p_conf);
	if (ret)
		rte_exit(EXIT_FAILURE, "failed to create tx adapter");

	for (i = 0; i < ethdev_count; i++) {
		ret = rte_event_eth_tx_adapter_queue_add(tx_adptr_id, i, -1);
		if (ret)
			rte_exit(EXIT_FAILURE,
				 "failed to add queues to Tx adapter");
	}

	ret = rte_event_eth_tx_adapter_service_id_get(tx_adptr_id, &service_id);
	if (ret != -ESRCH && ret != 0)
		rte_exit(EXIT_FAILURE, "Failed to get Tx adapter service ID");

	rte_service_runstate_set(service_id, 1);
	rte_service_set_runstate_mapped_check(service_id, 0);
	eventdev_rsrc->tx_adptr.service_id = service_id;

	ret = rte_event_eth_tx_adapter_event_port_get(tx_adptr_id, &tx_port_id);
	if (ret)
		rte_exit(EXIT_FAILURE,
			 "Failed to get Tx adapter port id: %d\n", ret);

	ret = rte_event_port_link(event_d_id, tx_port_id,
				  &eventdev_rsrc->evq.event_q_id[
					eventdev_rsrc->evq.nb_queues - 1],
				  NULL, 1);
	if (ret != 1)
		rte_exit(EXIT_FAILURE,
			 "Unable to link Tx adapter port to Tx queue:err = %d",
			 ret);

	ret = rte_event_eth_tx_adapter_start(tx_adptr_id);
	if (ret)
		rte_exit(EXIT_FAILURE, "Tx adapter[%d] start failed",
			 tx_adptr_id);

	eventdev_rsrc->tx_adptr.tx_adptr[0] = tx_adptr_id;
}

void
eventdev_set_generic_ops(struct eventdev_setup_ops *ops)
{
	ops->eventdev_setup = eventdev_setup_generic;
	ops->event_queue_setup = event_queue_setup_generic;
	ops->event_port_setup = event_port_setup_generic;
	ops->adapter_setup = rx_tx_adapter_setup_generic;
}
