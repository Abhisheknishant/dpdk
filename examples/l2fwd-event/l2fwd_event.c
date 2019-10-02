/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2019 Marvell International Ltd.
 */

#include <stdbool.h>
#include <getopt.h>

#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_eventdev.h>
#include <rte_event_eth_rx_adapter.h>
#include <rte_event_eth_tx_adapter.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_spinlock.h>

#include "l2fwd_event.h"

static inline int
l2fwd_event_service_enable(uint32_t service_id)
{
	uint8_t min_service_count = UINT8_MAX;
	uint32_t slcore_array[RTE_MAX_LCORE];
	unsigned int slcore = 0;
	uint8_t service_count;
	int32_t slcore_count;

	if (!rte_service_lcore_count())
		return -ENOENT;

	slcore_count = rte_service_lcore_list(slcore_array, RTE_MAX_LCORE);
	if (slcore_count < 0)
		return -ENOENT;
	/* Get the core which has least number of services running. */
	while (slcore_count--) {
		/* Reset default mapping */
		rte_service_map_lcore_set(service_id,
				slcore_array[slcore_count], 0);
		service_count = rte_service_lcore_count_services(
				slcore_array[slcore_count]);
		if (service_count < min_service_count) {
			slcore = slcore_array[slcore_count];
			min_service_count = service_count;
		}
	}
	if (rte_service_map_lcore_set(service_id, slcore, 1))
		return -ENOENT;
	rte_service_lcore_start(slcore);

	return 0;
}

void
l2fwd_event_service_setup(struct l2fwd_resources *l2fwd_rsrc)
{
	struct l2fwd_event_resources *event_rsrc = l2fwd_rsrc->event_rsrc;
	struct rte_event_dev_info evdev_info;
	uint32_t service_id, caps;
	int ret, i;

	rte_event_dev_info_get(event_rsrc->event_d_id, &evdev_info);
	if (evdev_info.event_dev_cap  & RTE_EVENT_DEV_CAP_DISTRIBUTED_SCHED) {
		ret = rte_event_dev_service_id_get(event_rsrc->event_d_id,
				&service_id);
		if (ret != -ESRCH && ret != 0)
			rte_exit(EXIT_FAILURE,
					"Error in starting eventdev service\n");
		l2fwd_event_service_enable(service_id);
	}

	for (i = 0; i < event_rsrc->rx_adptr.nb_rx_adptr; i++) {
		ret = rte_event_eth_rx_adapter_caps_get(event_rsrc->event_d_id,
				event_rsrc->rx_adptr.rx_adptr[i], &caps);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
					"Failed to get Rx adapter[%d] caps\n",
					event_rsrc->rx_adptr.rx_adptr[i]);
		ret = rte_event_eth_rx_adapter_service_id_get(
				event_rsrc->event_d_id,
				&service_id);
		if (ret != -ESRCH && ret != 0)
			rte_exit(EXIT_FAILURE,
					"Error in starting Rx adapter[%d] service\n",
					event_rsrc->rx_adptr.rx_adptr[i]);
		l2fwd_event_service_enable(service_id);
	}

	for (i = 0; i < event_rsrc->tx_adptr.nb_tx_adptr; i++) {
		ret = rte_event_eth_tx_adapter_caps_get(event_rsrc->event_d_id,
				event_rsrc->tx_adptr.tx_adptr[i], &caps);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
					"Failed to get Rx adapter[%d] caps\n",
					event_rsrc->tx_adptr.tx_adptr[i]);
		ret = rte_event_eth_tx_adapter_service_id_get(
				event_rsrc->event_d_id,
				&service_id);
		if (ret != -ESRCH && ret != 0)
			rte_exit(EXIT_FAILURE,
					"Error in starting Rx adapter[%d] service\n",
					event_rsrc->tx_adptr.tx_adptr[i]);
		l2fwd_event_service_enable(service_id);
	}
}

static void
l2fwd_event_capability_setup(struct l2fwd_event_resources *event_rsrc)
{
	uint32_t caps = 0;
	uint16_t i;
	int ret;

	RTE_ETH_FOREACH_DEV(i) {
		ret = rte_event_eth_tx_adapter_caps_get(0, i, &caps);
		if (ret)
			rte_exit(EXIT_FAILURE,
				 "Invalid capability for Tx adptr port %d\n",
				 i);

		event_rsrc->tx_mode_q |= !(caps &
				   RTE_EVENT_ETH_TX_ADAPTER_CAP_INTERNAL_PORT);
	}

	if (event_rsrc->tx_mode_q)
		l2fwd_event_set_generic_ops(&event_rsrc->ops);
	else
		l2fwd_event_set_internal_port_ops(&event_rsrc->ops);
}

void
l2fwd_event_resource_setup(struct l2fwd_resources *l2fwd_rsrc)
{
	struct l2fwd_event_resources *event_rsrc;
	uint32_t event_queue_cfg;

	if (!rte_event_dev_count())
		rte_exit(EXIT_FAILURE, "No Eventdev found\n");

	event_rsrc = rte_zmalloc("l2fwd_event",
				 sizeof(struct l2fwd_event_resources), 0);
	if (event_rsrc == NULL)
		rte_exit(EXIT_FAILURE, "failed to allocate memory\n");

	l2fwd_rsrc->event_rsrc = event_rsrc;

	/* Setup eventdev capability callbacks */
	l2fwd_event_capability_setup(event_rsrc);

	/* Event device configuration */
	event_queue_cfg = event_rsrc->ops.event_device_setup(l2fwd_rsrc);

	/* Event queue configuration */
	event_rsrc->ops.event_queue_setup(l2fwd_rsrc, event_queue_cfg);

	/* Event port configuration */
	event_rsrc->ops.event_port_setup(l2fwd_rsrc);

	/* Rx/Tx adapters configuration */
	event_rsrc->ops.adapter_setup(l2fwd_rsrc);
}
