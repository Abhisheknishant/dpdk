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
#include <rte_log.h>
#include <rte_spinlock.h>

#include "l2fwd_common.h"
#include "l2fwd_eventdev.h"

static void
parse_mode(const char *optarg)
{
	struct eventdev_resources *eventdev_rsrc = get_eventdev_rsrc();

	if (!strncmp(optarg, "poll", 4))
		eventdev_rsrc->enabled = false;
	else if (!strncmp(optarg, "eventdev", 8))
		eventdev_rsrc->enabled = true;
}

static void
parse_eventq_sync(const char *optarg)
{
	struct eventdev_resources *eventdev_rsrc = get_eventdev_rsrc();

	if (!strncmp(optarg, "ordered", 7))
		eventdev_rsrc->sync_mode = RTE_SCHED_TYPE_ORDERED;
	else if (!strncmp(optarg, "atomic", 6))
		eventdev_rsrc->sync_mode = RTE_SCHED_TYPE_ATOMIC;
}

static int
parse_eventdev_args(char **argv, int argc)
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

void
eventdev_resource_setup(void)
{
	struct eventdev_resources *eventdev_rsrc = get_eventdev_rsrc();
	uint32_t service_id;
	int32_t ret;

	/* Parse eventdev command line options */
	ret = parse_eventdev_args(eventdev_rsrc->args, eventdev_rsrc->nb_args);
	if (ret < 0)
		return;

	if (!rte_event_dev_count())
		rte_exit(EXIT_FAILURE, "No Eventdev found");
	/* Start event device service */
	ret = rte_event_dev_service_id_get(eventdev_rsrc->event_d_id,
			&service_id);
	if (ret != -ESRCH && ret != 0)
		rte_exit(EXIT_FAILURE, "Error in starting eventdev");

	rte_service_runstate_set(service_id, 1);
	rte_service_set_runstate_mapped_check(service_id, 0);
	eventdev_rsrc->service_id = service_id;

	/* Start event device */
	ret = rte_event_dev_start(eventdev_rsrc->event_d_id);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error in starting eventdev");
}
