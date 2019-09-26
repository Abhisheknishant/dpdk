/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2019 Marvell International Ltd.
 */

#include <stdbool.h>
#include <getopt.h>

#include "l3fwd.h"
#include "l3fwd_eventdev.h"

static void
parse_mode(const char *optarg)
{
	struct l3fwd_eventdev_resources *evdev_rsrc = l3fwd_get_eventdev_rsrc();

	if (!strncmp(optarg, "poll", 4))
		evdev_rsrc->enabled = false;
	else if (!strncmp(optarg, "eventdev", 8))
		evdev_rsrc->enabled = true;
}

static void
parse_eventq_sync(const char *optarg)
{
	struct l3fwd_eventdev_resources *evdev_rsrc = l3fwd_get_eventdev_rsrc();

	if (!strncmp(optarg, "ordered", 7))
		evdev_rsrc->sync_mode = RTE_SCHED_TYPE_ORDERED;
	else if (!strncmp(optarg, "atomic", 6))
		evdev_rsrc->sync_mode = RTE_SCHED_TYPE_ATOMIC;
}

static int
l3fwd_parse_eventdev_args(char **argv, int argc)
{
	const struct option eventdev_lgopts[] = {
		{CMD_LINE_OPT_MODE, 1, 0, CMD_LINE_OPT_MODE_NUM},
		{CMD_LINE_OPT_EVENTQ_SYNC, 1, 0, CMD_LINE_OPT_EVENTQ_SYNC_NUM},
		{NULL, 0, 0, 0}
	};
	char **argvopt = argv;
	int32_t option_index;
	int32_t opt;

	while ((opt = getopt_long(argc, argvopt, "", eventdev_lgopts,
					&option_index)) != EOF) {
		switch (opt) {
		case CMD_LINE_OPT_MODE_NUM:
			parse_mode(optarg);
			break;

		case CMD_LINE_OPT_EVENTQ_SYNC_NUM:
			parse_eventq_sync(optarg);
			break;

		case '?':
			/* skip other parameters except eventdev specific */
			break;

		default:
			printf("Invalid eventdev parameter\n");
			return -1;
		}
	}

	return 0;
}

static void
l3fwd_eventdev_capability_setup(void)
{
	struct l3fwd_eventdev_resources *evdev_rsrc = l3fwd_get_eventdev_rsrc();
	uint32_t caps = 0;
	uint16_t i;
	int ret;

	RTE_ETH_FOREACH_DEV(i) {
		ret = rte_event_eth_tx_adapter_caps_get(0, i, &caps);
		if (ret)
			rte_exit(EXIT_FAILURE,
				 "Invalid capability for Tx adptr port %d\n",
				 i);

		evdev_rsrc->tx_mode_q |= !(caps &
				   RTE_EVENT_ETH_TX_ADAPTER_CAP_INTERNAL_PORT);
	}

	if (evdev_rsrc->tx_mode_q)
		l3fwd_eventdev_set_generic_ops(&evdev_rsrc->ops);
	else
		l3fwd_eventdev_set_internal_port_ops(&evdev_rsrc->ops);
}

void
l3fwd_eventdev_resource_setup(void)
{
	struct l3fwd_eventdev_resources *evdev_rsrc = l3fwd_get_eventdev_rsrc();
	int32_t ret;

	/* Parse eventdev command line options */
	ret = l3fwd_parse_eventdev_args(evdev_rsrc->args, evdev_rsrc->nb_args);
	if (ret < 0 || !evdev_rsrc->enabled)
		return;

	if (!rte_event_dev_count())
		rte_exit(EXIT_FAILURE, "No Eventdev found");

	/* Setup eventdev capability callbacks */
	l3fwd_eventdev_capability_setup();
}
