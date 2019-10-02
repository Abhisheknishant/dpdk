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
