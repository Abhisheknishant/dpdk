/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2019 Marvell International Ltd.
 */

#include "l3fwd.h"
#include "l3fwd_eventdev.h"

static void
l3fwd_event_port_setup_internal_port(void)
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
		evdev_rsrc->disable_implicit_release;

	for (event_p_id = 0; event_p_id < evdev_rsrc->evp.nb_ports;
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
		evdev_rsrc->evp.event_p_id[event_p_id] = event_p_id;

		/* init spinlock */
		rte_spinlock_init(&evdev_rsrc->evp.lock);
	}

	evdev_rsrc->def_p_conf = event_p_conf;
}

static void
l3fwd_event_queue_setup_internal_port(uint16_t ethdev_count,
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
	event_q_conf.schedule_type = evdev_rsrc->sync_mode;
	evdev_rsrc->evq.nb_queues = ethdev_count;
	evdev_rsrc->evq.event_q_id = (uint8_t *)malloc(sizeof(uint8_t) *
					evdev_rsrc->evq.nb_queues);
	if (!evdev_rsrc->evq.event_q_id)
		rte_exit(EXIT_FAILURE, "Memory allocation failure");

	for (event_q_id = 0; event_q_id < ethdev_count; event_q_id++) {
		ret = rte_event_queue_setup(event_d_id, event_q_id,
					    &event_q_conf);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				 "Error in configuring event queue");
		}
		evdev_rsrc->evq.event_q_id[event_q_id] = event_q_id;
	}
}

void
l3fwd_eventdev_set_internal_port_ops(struct l3fwd_eventdev_setup_ops *ops)
{
	ops->event_queue_setup = l3fwd_event_queue_setup_internal_port;
	ops->event_port_setup = l3fwd_event_port_setup_internal_port;
}
