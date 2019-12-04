/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2019 Marvell International Ltd.
 */

#include <stdbool.h>
#include <getopt.h>

#include "l3fwd.h"
#include "l3fwd_event.h"

static void
parse_mode(const char *optarg)
{
	struct l3fwd_event_resources *evt_rsrc = l3fwd_get_eventdev_rsrc();

	if (!strncmp(optarg, "poll", 4))
		evt_rsrc->enabled = false;
	else if (!strncmp(optarg, "eventdev", 8))
		evt_rsrc->enabled = true;
}

static void
parse_eventq_sync(const char *optarg)
{
	struct l3fwd_event_resources *evt_rsrc = l3fwd_get_eventdev_rsrc();

	if (!strncmp(optarg, "ordered", 7))
		evt_rsrc->sched_type = RTE_SCHED_TYPE_ORDERED;
	if (!strncmp(optarg, "atomic", 6))
		evt_rsrc->sched_type = RTE_SCHED_TYPE_ATOMIC;
	if (!strncmp(optarg, "parallel", 8))
		evt_rsrc->sched_type = RTE_SCHED_TYPE_PARALLEL;
}

static void
l3fwd_parse_eventdev_args(char **argv, int argc)
{
	const struct option eventdev_lgopts[] = {
		{CMD_LINE_OPT_MODE, 1, 0, CMD_LINE_OPT_MODE_NUM},
		{CMD_LINE_OPT_EVENTQ_SYNC, 1, 0, CMD_LINE_OPT_EVENTQ_SYNC_NUM},
		{NULL, 0, 0, 0}
	};
	char *prgname = argv[0];
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

		default:
			print_usage(prgname);
			exit(1);
		}
	}
}

void
l3fwd_event_resource_setup(void)
{
	struct l3fwd_event_resources *evt_rsrc = l3fwd_get_eventdev_rsrc();

	/* Parse eventdev command line options */
	l3fwd_parse_eventdev_args(evt_rsrc->args, evt_rsrc->nb_args);
	if (!evt_rsrc->enabled)
		return;
}
