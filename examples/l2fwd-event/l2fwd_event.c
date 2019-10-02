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

void
l2fwd_event_resource_setup(struct l2fwd_resources *l2fwd_rsrc)
{
	struct l2fwd_event_resources *event_rsrc;

	if (!rte_event_dev_count())
		rte_exit(EXIT_FAILURE, "No Eventdev found\n");

	event_rsrc = rte_zmalloc("l2fwd_event",
				 sizeof(struct l2fwd_event_resources), 0);
	if (event_rsrc == NULL)
		rte_exit(EXIT_FAILURE, "failed to allocate memory\n");

	l2fwd_rsrc->event_rsrc = event_rsrc;
}
