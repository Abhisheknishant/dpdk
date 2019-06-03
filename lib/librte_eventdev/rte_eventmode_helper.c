/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2019 Marvell International Ltd.
 */
#include <getopt.h>

#include <rte_ethdev.h>
#include <rte_eventdev.h>
#include <rte_eventmode_helper.h>
#include <rte_event_eth_rx_adapter.h>
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

static inline unsigned int
internal_get_next_rx_core(struct eventmode_conf *em_conf,
		unsigned int prev_core)
{
	unsigned int next_core;

get_next_core:
	/* Get the next core */
	next_core = rte_get_next_lcore(prev_core, 0, 0);

	/* Check if we have reached max lcores */
	if (next_core == RTE_MAX_LCORE)
		return next_core;

	/* Only some cores would be marked as rx cores. Skip others */
	if (!(em_conf->eth_core_mask & (1 << next_core))) {
		prev_core = next_core;
		goto get_next_core;
	}

	return next_core;
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
	unsigned int rx_core_id;

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
	/* Set rx core. Use first core other than master core as Rx core */
	rx_core_id = rte_get_next_lcore(0, /* curr core */
					1, /* skip master core */
					0  /* wrap */);

	em_conf->eth_core_mask = (1 << rx_core_id);
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

/* Pre-process conf before using for init*/

static int
rte_eventmode_validate_user_params(struct eventmode_conf *em_conf)
{
	/* TODO */
	/* Check sanity of the conf requested by user */

	RTE_SET_USED(em_conf);

	return 0;
}

static int
rte_eventmode_helper_set_default_conf_eventdev(struct eventmode_conf *em_conf)
{
	int i, ret;
	int nb_eventdev;
	struct eventdev_params *eventdev_config;
	struct rte_event_dev_info dev_info;

	/* Get the number of event devices */
	nb_eventdev = rte_event_dev_count();

	if (nb_eventdev == 0) {
		RTE_EM_HLPR_LOG_ERR("No event devices detected");
		return -1;
	}

	for (i = 0; i < nb_eventdev; i++) {

		/* Get the event dev conf */
		eventdev_config = &(em_conf->eventdev_config[i]);

		/* Read event device info */
		ret = rte_event_dev_info_get(i, &dev_info);

		if (ret < 0) {
			RTE_EM_HLPR_LOG_ERR(
				"Failed reading event device info (err:%d)",
				ret);
			return ret;
		}

		/* Check if enough ports are available */
		if (dev_info.max_event_ports < 2) {
			RTE_EM_HLPR_LOG_ERR("Not enough ports available");
			return -1;
		}

		/* Save number of queues & ports available */
		eventdev_config->eventdev_id = i;
		eventdev_config->nb_eventqueue = dev_info.max_event_queues;
		eventdev_config->nb_eventport = dev_info.max_event_ports;
		eventdev_config->ev_queue_mode =
				RTE_EVENT_QUEUE_CFG_SINGLE_LINK;

		/* One port is required for eth Rx adapter */
		eventdev_config->nb_eventport -= 1;

		/* One port is reserved for eth Tx adapter */
		eventdev_config->nb_eventport -= 1;

		/* Update the number of eventdevs */
		em_conf->nb_eventdev++;
	}

	return 0;
}

static int
rte_eventmode_helper_set_default_conf_rx_adapter(struct eventmode_conf *em_conf)
{
	int nb_eth_dev;
	int i;
	int adapter_id;
	int eventdev_id;
	int conn_id;
	struct rx_adapter_conf *adapter;
	struct adapter_connection_info *conn;
	struct eventdev_params *eventdev_config;

	/* Create one adapter with all eth queues mapped to event queues 1:1 */

	if (em_conf->nb_eventdev == 0) {
		RTE_EM_HLPR_LOG_ERR("No event devs registered");
		return -1;
	}

	/* Get the number of eth devs */
	nb_eth_dev = rte_eth_dev_count_avail();

	/* Use the first event dev */
	eventdev_config = &(em_conf->eventdev_config[0]);

	/* Get eventdev ID */
	eventdev_id = eventdev_config->eventdev_id;
	adapter_id = 0;

	/* Get adapter conf */
	adapter = &(em_conf->rx_adapter[adapter_id]);

	/* Set adapter conf */
	adapter->eventdev_id = eventdev_id;
	adapter->adapter_id = adapter_id;
	adapter->rx_core_id = internal_get_next_rx_core(em_conf, -1);

	/*
	 * All queues of one eth device (port) will be mapped to one event
	 * queue. Each port will have an individual connection.
	 *
	 */

	/* Make sure there is enough event queues for 1:1 mapping */
	if (nb_eth_dev > eventdev_config->nb_eventqueue) {
		RTE_EM_HLPR_LOG_ERR(
			"Not enough event queues for 1:1 mapping "
			"[eth devs: %d, event queues: %d]\n",
			nb_eth_dev,
			eventdev_config->nb_eventqueue);
		return -1;
	}

	for (i = 0; i < nb_eth_dev; i++) {

		/* Use only the ports enabled */
		if ((em_conf->eth_portmask & (1 << i)) == 0)
			continue;

		/* Get the connection id */
		conn_id = adapter->nb_connections;

		/* Get the connection */
		conn = &(adapter->conn[conn_id]);

		/* Set 1:1 mapping between eth ports & event queues*/
		conn->ethdev_id = i;
		conn->eventq_id = i;

		/* Add all eth queues of one eth port to one event queue */
		conn->ethdev_rx_qid = -1;

		/* Update no of connections */
		adapter->nb_connections++;

	}

	/* We have setup one adapter */
	em_conf->nb_rx_adapter = 1;

	return 0;
}

static int
rte_eventmode_helper_validate_conf(struct eventmode_conf *em_conf)
{
	int ret;

	/* After parsing all args, verify that the conf can be allowed */
	ret = rte_eventmode_validate_user_params(em_conf);
	if (ret != 0)
		return ret;

	/*
	 * See if event devs are specified. Else probe the event devices
	 * and initialize the conf with all ports & queues available
	 */
	if (em_conf->nb_eventdev == 0) {
		ret = rte_eventmode_helper_set_default_conf_eventdev(em_conf);
		if (ret != 0)
			return ret;
	}

	/*
	 * See if rx adapters are specified. Else generate a default conf
	 * with one rx adapter and all eth queue - event queue mapped.
	 */
	if (em_conf->nb_rx_adapter == 0) {
		ret = rte_eventmode_helper_set_default_conf_rx_adapter(em_conf);
		if (ret != 0)
			return ret;
	}

	return 0;
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

static int
rx_adapter_configure(struct eventmode_conf *em_conf,
	struct rx_adapter_conf *adapter)
{
	int j;
	int ret;
	uint8_t eventdev_id;
	uint32_t service_id;
	struct adapter_connection_info *conn;
	struct rte_event_port_conf port_conf = {0};
	struct rte_event_eth_rx_adapter_queue_conf queue_conf = {0};
	struct rte_event_dev_info evdev_default_conf = {0};

	/* Get event dev ID */
	eventdev_id = adapter->eventdev_id;

	/* Create rx_adapter */

	/* Get default configuration of event dev */
	ret = rte_event_dev_info_get(eventdev_id, &evdev_default_conf);
	if (ret < 0) {
		RTE_EM_HLPR_LOG_ERR(
			"Error in getting event device info[devID:%d]",
			eventdev_id);
		return ret;
	}

	/* Setup port conf */
	port_conf.new_event_threshold = 1200;
	port_conf.dequeue_depth =
			evdev_default_conf.max_event_port_dequeue_depth;
	port_conf.enqueue_depth =
			evdev_default_conf.max_event_port_enqueue_depth;

	/* Create Rx adapter */
	ret = rte_event_eth_rx_adapter_create(adapter->adapter_id,
			adapter->eventdev_id,
			&port_conf);
	if (ret < 0) {
		RTE_EM_HLPR_LOG_ERR("Error in rx adapter creation");
		return ret;
	}

	/* Setup various connections in the adapter */

	queue_conf.rx_queue_flags =
			RTE_EVENT_ETH_RX_ADAPTER_QUEUE_FLOW_ID_VALID;

	for (j = 0; j < adapter->nb_connections; j++) {
		/* Get connection */
		conn = &(adapter->conn[j]);

		/* Setup queue conf */
		queue_conf.ev.queue_id = conn->eventq_id;
		queue_conf.ev.sched_type = em_conf->ext_params.sched_type;

		/* Set flow ID as ethdev ID */
		queue_conf.ev.flow_id = conn->ethdev_id;

		/* Add queue to the adapter */
		ret = rte_event_eth_rx_adapter_queue_add(
				adapter->adapter_id,
				conn->ethdev_id,
				conn->ethdev_rx_qid,
				&queue_conf);
		if (ret < 0) {
			RTE_EM_HLPR_LOG_ERR(
				"Error in adding eth queue in Rx adapter");
			return ret;
		}
	}

	/* Get the service ID used by rx adapter */
	ret = rte_event_eth_rx_adapter_service_id_get(adapter->adapter_id,
						      &service_id);
	if (ret != -ESRCH && ret != 0) {
		RTE_EM_HLPR_LOG_ERR(
			"Error getting service ID used by Rx adapter");
		return ret;
	}

	/*
	 * TODO
	 * Rx core will invoke the service when required. The runstate check
	 * is not required.
	 *
	 */
	rte_service_set_runstate_mapped_check(service_id, 0);

	/* Start adapter */
	ret = rte_event_eth_rx_adapter_start(adapter->adapter_id);
	if (ret) {
		RTE_EM_HLPR_LOG_ERR("Error in starting rx adapter");
		return ret;
	}

	return 0;
}

static int
rte_eventmode_helper_initialize_rx_adapter(struct eventmode_conf *em_conf)
{
	int i, ret;
	struct rx_adapter_conf *adapter;

	/* Configure rx adapters */
	for (i = 0; i < em_conf->nb_rx_adapter; i++) {
		adapter = &(em_conf->rx_adapter[i]);
		ret = rx_adapter_configure(em_conf, adapter);
		if (ret < 0) {
			RTE_EM_HLPR_LOG_ERR("Rx adapter configuration failed");
			return ret;
		}
	}
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

	/* Eventmode conf would need eth portmask */
	em_conf->eth_portmask = mode_conf->eth_portmask;

	/* Validate the conf requested */
	if (rte_eventmode_helper_validate_conf(em_conf) != 0) {
		RTE_EM_HLPR_LOG_ERR(
			"Failed while validating the conf requested");
		return -1;
	}

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

	/* Setup Rx adapter */
	ret = rte_eventmode_helper_initialize_rx_adapter(em_conf);
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
