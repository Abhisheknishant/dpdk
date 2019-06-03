/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2019 Marvell International Ltd.
 */
#include <getopt.h>

#include <rte_ethdev.h>
#include <rte_eventdev.h>
#include <rte_eventmode_helper.h>
#include <rte_malloc.h>

#include "rte_eventmode_helper_internal.h"

#define CMD_LINE_OPT_TRANSFER_MODE	"transfer-mode"

static const char short_options[] =
	""
	;

enum {
	/* long options mapped to a short option */

	/* first long only option value must be >= 256, so that we won't
	 * conflict with short options
	 */
	CMD_LINE_OPT_MIN_NUM = 256,
	CMD_LINE_OPT_TRANSFER_MODE_NUM,
};

static const struct option lgopts[] = {
	{CMD_LINE_OPT_TRANSFER_MODE, 1, 0, CMD_LINE_OPT_TRANSFER_MODE_NUM},
	{NULL, 0, 0, 0}
};

/* Internal functions */

static int32_t
internal_parse_decimal(const char *str)
{
	char *end = NULL;
	unsigned long num;

	num = strtoul(str, &end, 10);
	if ((str[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	return num;
}

/* Global functions */

void __rte_experimental
rte_eventmode_helper_print_options_list(void)
{
	fprintf(stderr, " --"
		" [--transfer-mode MODE]"
		);
}

void __rte_experimental
rte_eventmode_helper_print_options_description(void)
{
	fprintf(stderr,
		"  --transfer-mode MODE\n"
		"               0: Packet transfer via polling (default)\n"
		"               1: Packet transfer via eventdev\n"
		"\n");
}

static int
em_parse_transfer_mode(struct rte_eventmode_helper_conf *conf,
		const char *optarg)
{
	int32_t parsed_dec;

	parsed_dec = internal_parse_decimal(optarg);
	if (parsed_dec != RTE_EVENTMODE_HELPER_PKT_TRANSFER_MODE_POLL &&
	    parsed_dec != RTE_EVENTMODE_HELPER_PKT_TRANSFER_MODE_EVENT) {
		RTE_EM_HLPR_LOG_ERR("Unsupported packet transfer mode");
		return -1;
	}
	conf->mode = parsed_dec;
	return 0;
}

static void
em_initialize_helper_conf(struct rte_eventmode_helper_conf *conf)
{
	struct eventmode_conf *em_conf = NULL;

	/* Set default conf */

	/* Packet transfer mode: poll */
	conf->mode = RTE_EVENTMODE_HELPER_PKT_TRANSFER_MODE_POLL;

	/* Keep all ethernet ports enabled by default */
	conf->eth_portmask = -1;

	/* Get eventmode conf */
	em_conf = (struct eventmode_conf *)(conf->mode_params);

	/* Schedule type: ordered */
	/* FIXME */
	em_conf->ext_params.sched_type = RTE_SCHED_TYPE_ORDERED;
}

struct rte_eventmode_helper_conf * __rte_experimental
rte_eventmode_helper_parse_args(int argc, char **argv)
{
	int32_t opt, ret;
	struct rte_eventmode_helper_conf *conf = NULL;
	struct eventmode_conf *em_conf = NULL;

	/* Allocate memory for conf */
	conf = rte_zmalloc("eventmode-helper-conf",
			sizeof(struct rte_eventmode_helper_conf),
			RTE_CACHE_LINE_SIZE);
	if (conf == NULL) {
		RTE_EM_HLPR_LOG_ERR(
			"Failed allocating memory for eventmode helper conf");
			goto err;
	}

	/* Allocate memory for event mode params */
	conf->mode_params = rte_zmalloc("eventmode-helper-mode-params",
			sizeof(struct eventmode_conf),
			RTE_CACHE_LINE_SIZE);
	if (conf->mode_params == NULL) {
		RTE_EM_HLPR_LOG_ERR(
			"Failed allocating memory for event mode params");
		goto err;
	}

	/* Initialize conf with default values */
	em_initialize_helper_conf(conf);

	em_conf = (struct eventmode_conf *)(conf->mode_params);

	while ((opt = getopt_long(argc, argv, short_options,
				lgopts, NULL)) != EOF) {
		switch (opt) {

		/* Packet transfer mode */
		case CMD_LINE_OPT_TRANSFER_MODE_NUM:
			ret = em_parse_transfer_mode(conf, optarg);
			if (ret < 0) {
				RTE_EM_HLPR_LOG_ERR(
					"Invalid packet transfer mode");
				goto err;
			}
			break;
		default:
			goto err;
		}
	}
	return conf;

err:
	if (em_conf != NULL)
		rte_free(em_conf);

	if (conf != NULL)
		rte_free(conf);

	return NULL;
}

/* Setup eventmode devs */

static int
rte_eventmode_helper_initialize_eventdev(struct eventmode_conf *em_conf)
{
	int ret = -1;
	uint8_t i, j;
	struct rte_event_dev_config eventdev_conf;
	struct rte_event_dev_info evdev_default_conf;
	struct rte_event_queue_conf eventq_conf = {0};
	struct rte_eventmode_helper_event_link_info *link;
	struct eventdev_params *eventdev_config;
	int nb_eventdev = em_conf->nb_eventdev;
	int nb_eventqueue;
	uint8_t eventdev_id;
	uint8_t *queue = NULL;

	for (i = 0; i < nb_eventdev; i++) {

		/* Get eventdev config */
		eventdev_config = &(em_conf->eventdev_config[i]);

		/* Get event dev ID */
		eventdev_id = eventdev_config->eventdev_id;

		/* Get the number of queues */
		nb_eventqueue = eventdev_config->nb_eventqueue;

		/* One queue is reserved for the final stage (doing eth tx) */
		/* TODO handles only one Tx adapter. Fix this */
		nb_eventqueue += 1;

		/* Reset the default conf */
		memset(&evdev_default_conf, 0,
			sizeof(struct rte_event_dev_info));

		/* Get default conf of eventdev */
		ret = rte_event_dev_info_get(eventdev_id, &evdev_default_conf);
		if (ret < 0) {
			RTE_EM_HLPR_LOG_ERR(
				"Error in getting event device info[devID:%d]",
				eventdev_id);
			return ret;
		}

		memset(&eventdev_conf, 0, sizeof(struct rte_event_dev_config));
		eventdev_conf.nb_events_limit =
				evdev_default_conf.max_num_events;
		eventdev_conf.nb_event_queues = nb_eventqueue;
		eventdev_conf.nb_event_ports =
				eventdev_config->nb_eventport;
		eventdev_conf.nb_event_queue_flows =
				evdev_default_conf.max_event_queue_flows;
		eventdev_conf.nb_event_port_dequeue_depth =
				evdev_default_conf.max_event_port_dequeue_depth;
		eventdev_conf.nb_event_port_enqueue_depth =
				evdev_default_conf.max_event_port_enqueue_depth;

		/* Configure event device */
		ret = rte_event_dev_configure(eventdev_id, &eventdev_conf);
		if (ret < 0) {
			RTE_EM_HLPR_LOG_ERR(
				"Error in configuring event device");
			return ret;
		}

		/* Configure event queues */
		for (j = 0; j < nb_eventqueue; j++) {

			memset(&eventq_conf, 0,
					sizeof(struct rte_event_queue_conf));

			/* Read the requested conf */

			/* Per event dev queues can be ATQ or SINGLE LINK */
			eventq_conf.event_queue_cfg =
					eventdev_config->ev_queue_mode;

			/*
			 * All queues need to be set with sched_type as
			 * schedule type for the application stage. One queue
			 * would be reserved for the final eth tx stage. This
			 * will be an atomic queue.
			 */
			if (j == nb_eventqueue-1) {
				eventq_conf.schedule_type =
					RTE_SCHED_TYPE_ATOMIC;
			} else {
				eventq_conf.schedule_type =
					em_conf->ext_params.sched_type;
			}

			/* Set max atomic flows to 1024 */
			eventq_conf.nb_atomic_flows = 1024;
			eventq_conf.nb_atomic_order_sequences = 1024;

			/* Setup the queue */
			ret = rte_event_queue_setup(eventdev_id, j,
					&eventq_conf);
			if (ret < 0) {
				RTE_EM_HLPR_LOG_ERR(
					"Error in event queue setup");
				return ret;
			}
		}

		/* Configure event ports */
		for (j = 0; j <  eventdev_config->nb_eventport; j++) {
			ret = rte_event_port_setup(eventdev_id, j, NULL);
			if (ret < 0) {
				RTE_EM_HLPR_LOG_ERR(
					"Error setting up event port");
				return ret;
			}
		}
	}

	/* Make event queue - event port link */
	for (j = 0; j <  em_conf->nb_link; j++) {

		/* Get link info */
		link = &(em_conf->link[j]);

		/* Get event dev ID */
		eventdev_id = link->eventdev_id;

		queue = &(link->eventq_id);

		/* Link queue to port */
		ret = rte_event_port_link(eventdev_id, link->event_portid,
				queue, NULL, 1);
		if (ret < 0) {
			RTE_EM_HLPR_LOG_ERR("Error in event port linking");
			return ret;
		}
	}

	/* Start event devices */
	for (i = 0; i < nb_eventdev; i++) {

		/* Get eventdev config */
		eventdev_config = &(em_conf->eventdev_config[i]);

		ret = rte_event_dev_start(eventdev_config->eventdev_id);
		if (ret < 0) {
			RTE_EM_HLPR_LOG_ERR(
				"Error in starting event device[devID: %d]",
				eventdev_config->eventdev_id);
			return ret;
		}
	}
	return 0;
}

static int
rte_eventmode_helper_initialize_ethdev(struct eventmode_conf *em_conf)
{
	RTE_SET_USED(em_conf);

	return 0;
}

int32_t __rte_experimental
rte_eventmode_helper_initialize_devs(
		struct rte_eventmode_helper_conf *mode_conf)
{
	int ret;
	uint16_t portid;
	struct eventmode_conf *em_conf;

	if (mode_conf == NULL) {
		RTE_EM_HLPR_LOG_ERR("Invalid conf");
		return -1;
	}

	if (mode_conf->mode != RTE_EVENTMODE_HELPER_PKT_TRANSFER_MODE_EVENT)
		return 0;

	if (mode_conf->mode_params == NULL) {
		RTE_EM_HLPR_LOG_ERR("Invalid mode params");
		return -1;
	}

	/* Get eventmode conf */
	em_conf = (struct eventmode_conf *)(mode_conf->mode_params);

	/* Stop eth devices before setting up adapter */
	RTE_ETH_FOREACH_DEV(portid) {

		/* Use only the ports enabled */
		if ((mode_conf->eth_portmask & (1 << portid)) == 0)
			continue;

		rte_eth_dev_stop(portid);
	}

	/* Setup eventdev */
	ret = rte_eventmode_helper_initialize_eventdev(em_conf);
	if (ret != 0)
		return ret;

	/* Setup ethdev */
	ret = rte_eventmode_helper_initialize_ethdev(em_conf);
	if (ret != 0)
		return ret;

	/* Start eth devices after setting up adapter */
	RTE_ETH_FOREACH_DEV(portid) {

		/* Use only the ports enabled */
		if ((mode_conf->eth_portmask & (1 << portid)) == 0)
			continue;

		ret = rte_eth_dev_start(portid);
		if (ret < 0) {
			RTE_EM_HLPR_LOG_ERR(
				"Error starting eth dev %d", portid);
			return -1;
		}
	}

	return 0;
}
