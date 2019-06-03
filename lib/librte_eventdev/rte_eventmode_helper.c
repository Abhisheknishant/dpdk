/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2019 Marvell International Ltd.
 */
#include <getopt.h>
#include <stdbool.h>

#include <rte_ethdev.h>
#include <rte_eventdev.h>
#include <rte_eventmode_helper.h>
#include <rte_event_eth_rx_adapter.h>
#include <rte_event_eth_tx_adapter.h>
#include <rte_malloc.h>

#include "rte_eventmode_helper_internal.h"

#define CMD_LINE_OPT_TRANSFER_MODE	"transfer-mode"

static volatile bool eth_core_running;

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

static int
internal_get_enabled_cores(unsigned int core_mask)
{
	int i;
	int count = 0;

	RTE_LCORE_FOREACH(i) {
		/* Check if this core is enabled in core_mask*/
		if (core_mask & (1 << i)) {
			/* We have enabled core */
			count++;
		}
	}
	return count;
}

static inline unsigned int
internal_get_next_eth_core(struct eventmode_conf *em_conf)
{
	unsigned int next_core;
	static unsigned int prev_core = -1;

	/*
	 * Make sure we have atleast one eth core running, else the following
	 * logic would lead to an infinite loop.
	 */
	if (internal_get_enabled_cores(em_conf->eth_core_mask) == 0) {
		RTE_EM_HLPR_LOG_INFO("No enabled eth core found");
		return RTE_MAX_LCORE;
	}

get_next_core:
	/* Get the next core */
	next_core = rte_get_next_lcore(prev_core, 0, 1);

	/* Check if we have reached max lcores */
	if (next_core == RTE_MAX_LCORE)
		return next_core;

	/* Update prev_core */
	prev_core = next_core;

	/* Only some cores would be marked as rx cores. Skip others */
	if (!(em_conf->eth_core_mask & (1 << next_core)))
		goto get_next_core;

	return next_core;
}

static inline unsigned int
internal_get_next_active_core(struct eventmode_conf *em_conf,
		unsigned int prev_core)
{
	unsigned int next_core;

get_next_core:
	/* Get the next core */
	next_core = rte_get_next_lcore(prev_core, 0, 0);

	/* Check if we have reached max lcores */
	if (next_core == RTE_MAX_LCORE)
		return next_core;

	/* Some cores would be reserved as rx cores. Skip them */
	if (em_conf->eth_core_mask & (1 << next_core)) {
		prev_core = next_core;
		goto get_next_core;
	}

	return next_core;
}

static struct eventdev_params *
internal_get_eventdev_params(struct eventmode_conf *em_conf,
		uint8_t eventdev_id)
{
	int i;

	for (i = 0; i < em_conf->nb_eventdev; i++) {
		if (em_conf->eventdev_config[i].eventdev_id == eventdev_id)
			break;
	}

	/* No match */
	if (i == em_conf->nb_eventdev)
		return NULL;

	return &(em_conf->eventdev_config[i]);
}

static inline bool
internal_dev_has_rx_internal_port(uint8_t eventdev_id)
{
	int j;
	bool flag = true;

	RTE_ETH_FOREACH_DEV(j) {
		uint32_t caps = 0;

		rte_event_eth_rx_adapter_caps_get(eventdev_id, j, &caps);
		if (!(caps & RTE_EVENT_ETH_RX_ADAPTER_CAP_INTERNAL_PORT))
			flag = false;
	}
	return flag;
}

static inline bool
internal_dev_has_tx_internal_port(uint8_t eventdev_id)
{
	int j;
	bool flag = true;

	RTE_ETH_FOREACH_DEV(j) {
		uint32_t caps = 0;

		rte_event_eth_tx_adapter_caps_get(eventdev_id, j, &caps);
		if (!(caps & RTE_EVENT_ETH_TX_ADAPTER_CAP_INTERNAL_PORT))
			flag = false;
	}
	return flag;
}

static inline bool
internal_dev_has_burst_mode(uint8_t dev_id)
{
	struct rte_event_dev_info dev_info;

	rte_event_dev_info_get(dev_id, &dev_info);
	return (dev_info.event_dev_cap & RTE_EVENT_DEV_CAP_BURST_MODE) ?
			true : false;
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
	unsigned int eth_core_id;

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
	/* Set two cores as eth cores for Rx & Tx */

	/* Use first core other than master core as Rx core */
	eth_core_id = rte_get_next_lcore(0,	/* curr core */
					 1,	/* skip master core */
					 0	/* wrap */);

	em_conf->eth_core_mask = (1 << eth_core_id);

	/* Use next core as Tx core */
	eth_core_id = rte_get_next_lcore(eth_core_id,	/* curr core */
					 1,		/* skip master core */
					 0		/* wrap */);

	em_conf->eth_core_mask |= (1 << eth_core_id);
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
	int nb_eth_dev;
	int lcore_count;
	struct eventdev_params *eventdev_config;
	struct rte_event_dev_info dev_info;

	/* Get the number of event devices */
	nb_eventdev = rte_event_dev_count();

	if (nb_eventdev == 0) {
		RTE_EM_HLPR_LOG_ERR("No event devices detected");
		return -1;
	}

	/* Get the number of eth devs */
	nb_eth_dev = rte_eth_dev_count_avail();

	if (nb_eth_dev == 0) {
		RTE_EM_HLPR_LOG_ERR("No eth devices detected");
		return -1;
	}

	/* Get the number of lcores */
	lcore_count = rte_lcore_count();

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
				RTE_EVENT_QUEUE_CFG_ALL_TYPES;

		/* Check if there are more queues than required */
		if (eventdev_config->nb_eventqueue > nb_eth_dev + 1) {
			/* One queue is reserved for Tx */
			eventdev_config->nb_eventqueue = nb_eth_dev + 1;
		}

		/* Check if there are more ports than required */
		if (eventdev_config->nb_eventport > lcore_count) {
			/* One port per lcore is enough */
			eventdev_config->nb_eventport = lcore_count;
		}

		/* Update the number of eventdevs */
		em_conf->nb_eventdev++;
	}

	return 0;
}

static void
rte_eventmode_helper_do_capability_check(struct eventmode_conf *em_conf)
{
	struct eventdev_params *eventdev_config;
	uint32_t eventdev_id;
	int all_internal_ports = 1;
	int i;

	for (i = 0; i < em_conf->nb_eventdev; i++) {

		/* Get the event dev conf */
		eventdev_config = &(em_conf->eventdev_config[i]);
		eventdev_id = eventdev_config->eventdev_id;

		/* Check if event device has internal port for Rx & Tx */
		if (internal_dev_has_rx_internal_port(eventdev_id) &&
		    internal_dev_has_tx_internal_port(eventdev_id)) {
			eventdev_config->all_internal_ports = 1;
		} else {
			all_internal_ports = 0;
		}
	}

	/*
	 * If Rx & Tx internal ports are supported by all event devices then
	 * eth cores won't be required. Override the eth core mask requested.
	 */
	if (all_internal_ports)
		em_conf->eth_core_mask = 0;
}

static int
rte_eventmode_helper_set_default_conf_rx_adapter(struct eventmode_conf *em_conf)
{
	int nb_eth_dev;
	int i;
	int adapter_id;
	int eventdev_id;
	int conn_id;
	int nb_eventqueue;
	struct rx_adapter_conf *adapter;
	struct adapter_connection_info *conn;
	struct eventdev_params *eventdev_config;
	bool rx_internal_port = true;
	uint32_t caps = 0;

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

	/*
	 * If event device does not have internal ports for passing
	 * packets then one queue is reserved for Tx path
	 */
	nb_eventqueue = eventdev_config->all_internal_ports ?
			eventdev_config->nb_eventqueue :
			eventdev_config->nb_eventqueue - 1;

	/*
	 * All queues of one eth device (port) will be mapped to one event
	 * queue. Each port will have an individual connection.
	 *
	 */

	/* Make sure there is enough event queues for 1:1 mapping */
	if (nb_eth_dev > nb_eventqueue) {
		RTE_EM_HLPR_LOG_ERR(
			"Not enough event queues for 1:1 mapping "
			"[eth devs: %d, event queues: %d]\n",
			nb_eth_dev, nb_eventqueue);
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

		/* Get Rx adapter capabilities */
		rte_event_eth_rx_adapter_caps_get(eventdev_id, i, &caps);
		if (!(caps & RTE_EVENT_ETH_RX_ADAPTER_CAP_INTERNAL_PORT))
			rx_internal_port = false;

		/* Update no of connections */
		adapter->nb_connections++;

	}

	if (rx_internal_port) {
		/* Rx core is not required */
		adapter->rx_core_id = -1;
	} else {
		/* Rx core is required */
		adapter->rx_core_id = internal_get_next_eth_core(em_conf);
	}

	/* We have setup one adapter */
	em_conf->nb_rx_adapter = 1;

	return 0;
}

static int
rte_eventmode_helper_set_default_conf_tx_adapter(struct eventmode_conf *em_conf)
{
	int nb_eth_dev;
	int eventdev_id;
	int adapter_id;
	int i;
	int conn_id;
	struct eventdev_params *eventdev_config;
	struct tx_adapter_conf *tx_adapter;
	struct tx_adapter_connection_info *conn;
	bool tx_internal_port = true;
	uint32_t caps = 0;

	/*
	 * Create one Tx adapter with all eth queues mapped to event queues
	 * 1:1.
	 */

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
	tx_adapter = &(em_conf->tx_adapter[adapter_id]);

	/* Set adapter conf */
	tx_adapter->eventdev_id = eventdev_id;
	tx_adapter->adapter_id = adapter_id;

	/*
	 * All Tx queues of the eth device (port) will be mapped to the event
	 * device.
	 */

	/* Set defaults for connections */

	/*
	 * One eth device (port) would be one connection. All Tx queues of
	 * the device would be mapped to the Tx adapter.
	 */

	for (i = 0; i < nb_eth_dev; i++) {

		/* Use only the ports enabled */
		if ((em_conf->eth_portmask & (1 << i)) == 0)
			continue;

		/* Get the connection id */
		conn_id = tx_adapter->nb_connections;

		/* Get the connection */
		conn = &(tx_adapter->conn[conn_id]);

		/* Add ethdev to connections */
		conn->ethdev_id = i;

		/* Add all eth tx queues to adapter */
		conn->ethdev_tx_qid = -1;

		/* Get Rx adapter capabilities */
		rte_event_eth_tx_adapter_caps_get(eventdev_id, i, &caps);
		if (!(caps & RTE_EVENT_ETH_TX_ADAPTER_CAP_INTERNAL_PORT))
			tx_internal_port = false;

		/* Update no of connections */
		tx_adapter->nb_connections++;
	}

	if (tx_internal_port) {
		/* Tx core is not required */
		tx_adapter->tx_core_id = -1;
	} else {
		/* Tx core is required */
		tx_adapter->tx_core_id = internal_get_next_eth_core(em_conf);

		/*
		 * Application would need to use one event queue per adapter for
		 * submitting packets for Tx. Reserving the last queue available
		 */
		/* Queue numbers start at 0 */
		tx_adapter->tx_ev_queue = eventdev_config->nb_eventqueue - 1;
	}

	/* We have setup one adapter */
	em_conf->nb_tx_adapter = 1;
	return 0;
}

static int
rte_eventmode_helper_set_default_conf_link(struct eventmode_conf *em_conf)
{
	int i, j;
	struct eventdev_params *eventdev_config;
	unsigned int lcore_id = -1;
	int link_index;
	struct rte_eventmode_helper_event_link_info *link;

	/*
	 * Create a 1:1 mapping from event ports to cores. If the number
	 * of event ports is lesser than the cores, some cores won't
	 * execute worker. If event ports are more, then some ports won't
	 * be used.
	 *
	 */

	/*
	 * The event queue-port mapping is done according to the link. Since
	 * we are falling back to the default link conf, enabling
	 * "all_ev_queue_to_ev_port" mode flag. This will map all queues to the
	 * port.
	 */
	em_conf->ext_params.all_ev_queue_to_ev_port = 1;

	for (i = 0; i < em_conf->nb_eventdev; i++) {

		/* Get event dev conf */
		eventdev_config = &(em_conf->eventdev_config[i]);

		/* Loop through the ports */
		for (j = 0; j < eventdev_config->nb_eventport; j++) {

			/* Get next active core id */
			lcore_id = internal_get_next_active_core(em_conf,
					lcore_id);

			if (lcore_id == RTE_MAX_LCORE) {
				/* Reached max cores */
				return 0;
			}

			/* Save the current combination as one link */

			/* Get the index */
			link_index = em_conf->nb_link;

			/* Get the corresponding link */
			link = &(em_conf->link[link_index]);

			/* Save link */
			link->eventdev_id = eventdev_config->eventdev_id;
			link->event_portid = j;
			link->lcore_id = lcore_id;

			/*
			 * Not setting eventq_id as by default all queues
			 * need to be mapped to the port, and is controlled
			 * by the operating mode.
			 */

			/* Update number of links */
			em_conf->nb_link++;
		}
	}
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

	/* Perform capability check for the selected event devices*/
	rte_eventmode_helper_do_capability_check(em_conf);

	/*
	 * See if rx adapters are specified. Else generate a default conf
	 * with one rx adapter and all eth queue - event queue mapped.
	 */
	if (em_conf->nb_rx_adapter == 0) {
		ret = rte_eventmode_helper_set_default_conf_rx_adapter(em_conf);
		if (ret != 0)
			return ret;
	}

	/*
	 * See if tx adapters are specified. Else generate a default conf
	 * with one tx adapter.
	 */
	if (em_conf->nb_tx_adapter == 0) {
		ret = rte_eventmode_helper_set_default_conf_tx_adapter(em_conf);
		if (ret != 0)
			return ret;
	}

	/*
	 * See if links are specified. Else generate a default conf for
	 * the event ports used.
	 */
	if (em_conf->nb_link == 0) {
		ret = rte_eventmode_helper_set_default_conf_link(em_conf);
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
			 * schedule type for the application stage. One
			 * queue would be reserved for the final eth tx
			 * stage if event device does not have internal
			 * ports. This will be an atomic queue.
			 */
			if (!eventdev_config->all_internal_ports &&
			    j == nb_eventqueue-1) {
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

		/*
		 * If "all_ev_queue_to_ev_port" params flag is selected, all
		 * queues need to be mapped to the port.
		 */
		if (em_conf->ext_params.all_ev_queue_to_ev_port)
			queue = NULL;
		else
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

#ifdef UNSELECT
	queue_conf.rx_queue_flags =
			RTE_EVENT_ETH_RX_ADAPTER_QUEUE_FLOW_ID_VALID;
#endif /* UNSELECT */

	for (j = 0; j < adapter->nb_connections; j++) {
		/* Get connection */
		conn = &(adapter->conn[j]);

		/* Setup queue conf */
		queue_conf.ev.queue_id = conn->eventq_id;
		queue_conf.ev.sched_type = em_conf->ext_params.sched_type;
		queue_conf.ev.event_type = RTE_EVENT_TYPE_ETHDEV;

#ifdef UNSELECT
		/* Set flow ID as ethdev ID */
		queue_conf.ev.flow_id = conn->ethdev_id;
#endif /* UNSELECT */

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

static int
tx_adapter_configure(struct eventmode_conf *em_conf,
	struct tx_adapter_conf *adapter)
{
	int ret, j;
	uint8_t tx_port_id = 0;
	uint32_t service_id;
	uint8_t eventdev_id;
	struct rte_event_port_conf port_conf = {0};
	struct rte_event_dev_info evdev_default_conf = {0};
	struct tx_adapter_connection_info *conn;
	struct eventdev_params *eventdev_config;

	/* Get event dev ID */
	eventdev_id = adapter->eventdev_id;

	/* Get event device conf */
	eventdev_config = internal_get_eventdev_params(em_conf, eventdev_id);

	/* Create Tx adapter */

	/* Get default configuration of event dev */
	ret = rte_event_dev_info_get(eventdev_id, &evdev_default_conf);
	if (ret < 0) {
		RTE_EM_HLPR_LOG_ERR(
			"Error in getting event device info[devID:%d]",
			eventdev_id);
		return ret;
	}

	/* Setup port conf */
	port_conf.new_event_threshold =
			evdev_default_conf.max_num_events;
	port_conf.dequeue_depth =
			evdev_default_conf.max_event_port_dequeue_depth;
	port_conf.enqueue_depth =
			evdev_default_conf.max_event_port_enqueue_depth;

	/* Create Tx adapter */
	ret = rte_event_eth_tx_adapter_create(adapter->adapter_id,
			adapter->eventdev_id,
			&port_conf);
	if (ret < 0) {
		RTE_EM_HLPR_LOG_ERR("Error in Tx adapter creation");
		return ret;
	}

	/* Setup various connections in the adapter */
	for (j = 0; j < adapter->nb_connections; j++) {

		/* Get connection */
		conn = &(adapter->conn[j]);

		/* Add queue to the adapter */
		ret = rte_event_eth_tx_adapter_queue_add(
				adapter->adapter_id,
				conn->ethdev_id,
				conn->ethdev_tx_qid);
		if (ret < 0) {
			RTE_EM_HLPR_LOG_ERR(
				"Error in adding eth queue in Tx adapter");
			return ret;
		}
	}

	/*
	 * Check if Tx core is assigned. If Tx core is not assigned, then
	 * the adapter would be having internal port for submitting packets
	 * for Tx and so Tx event queue & port setup is not required
	 */
	if (adapter->tx_core_id == (uint32_t) (-1)) {
		/* Internal port is present */
		goto skip_tx_queue_port_setup;
	}

	/* Setup Tx queue & port */

	/* Get event port used by the adapter */
	ret = rte_event_eth_tx_adapter_event_port_get(
			adapter->adapter_id,
			&tx_port_id);
	if (ret) {
		RTE_EM_HLPR_LOG_ERR("Failed to get Tx adapter port ID");
		return ret;
	}

	/*
	 * Tx event queue would be reserved for Tx adapter. Need to unlink
	 * this queue from all other ports
	 *
	 */
	for (j = 0; j < eventdev_config->nb_eventport; j++) {
		rte_event_port_unlink(eventdev_id, j,
				      &(adapter->tx_ev_queue), 1);
	}

	/* Link Tx event queue to Tx port */
	ret = rte_event_port_link(
			eventdev_id,
			tx_port_id,
			&(adapter->tx_ev_queue),
			NULL, 1);
	if (ret != 1) {
		RTE_EM_HLPR_LOG_ERR("Failed to link event queue to port");
		return ret;
	}

	/* Get the service ID used by Tx adapter */
	ret = rte_event_eth_tx_adapter_service_id_get(adapter->adapter_id,
						      &service_id);
	if (ret != -ESRCH && ret != 0) {
		RTE_EM_HLPR_LOG_ERR(
			"Error getting service ID used by adapter");
		return ret;
	}

	/*
	 * TODO
	 * Tx core will invoke the service when required. The runstate check
	 * is not required.
	 *
	 */
	rte_service_set_runstate_mapped_check(service_id, 0);

skip_tx_queue_port_setup:

	/* Start adapter */
	ret = rte_event_eth_tx_adapter_start(adapter->adapter_id);
	if (ret) {
		RTE_EM_HLPR_LOG_ERR("Error in starting Tx adapter");
		return ret;
	}

	return 0;
}

static int
rte_eventmode_helper_initialize_tx_adapter(struct eventmode_conf *em_conf)
{
	int i, ret;
	struct tx_adapter_conf *adapter;

	/* Configure Tx adapters */
	for (i = 0; i < em_conf->nb_tx_adapter; i++) {
		adapter = &(em_conf->tx_adapter[i]);
		ret = tx_adapter_configure(em_conf, adapter);
		if (ret < 0) {
			RTE_EM_HLPR_LOG_ERR("Tx adapter configuration failed");
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

	/* Display the current conf */
	rte_eventmode_helper_display_conf(mode_conf);

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

	/* Setup Tx adapter */
	ret = rte_eventmode_helper_initialize_tx_adapter(em_conf);
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

/* Helper functions for eventmode workers */

uint8_t __rte_experimental
rte_eventmode_helper_get_event_lcore_links(uint32_t lcore_id,
		struct rte_eventmode_helper_conf *mode_conf,
		struct rte_eventmode_helper_event_link_info **links)
{
	int i;
	int index = 0;
	uint8_t lcore_nb_link = 0;
	struct rte_eventmode_helper_event_link_info *link;
	struct rte_eventmode_helper_event_link_info *link_cache;
	struct eventmode_conf *em_conf = NULL;
	size_t cache_size;
	size_t single_link_size;

	if (mode_conf == NULL || links == NULL) {
		RTE_EM_HLPR_LOG_ERR("Invalid args");
		return 0;
	}

	/* Get eventmode conf */
	em_conf = (struct eventmode_conf *)(mode_conf->mode_params);

	if (em_conf == NULL) {
		RTE_EM_HLPR_LOG_ERR("Invalid event mode conf");
		return 0;
	}

	/* Get the number of links registered */
	for (i = 0; i < em_conf->nb_link; i++) {

		/* Get link */
		link = &(em_conf->link[i]);

		/* Check if we have link intended for this lcore */
		if (link->lcore_id == lcore_id) {

			/* Update the number of links for this core */
			lcore_nb_link++;

		}
	}

	/* Compute size of one entry to be copied */
	single_link_size = sizeof(struct rte_eventmode_helper_event_link_info);

	/* Compute size of the buffer required */
	cache_size = lcore_nb_link *
			sizeof(struct rte_eventmode_helper_event_link_info);

	/* Allocate memory for caching the links */
	link_cache = rte_zmalloc("eventmode-event-lcore-links", cache_size,
			RTE_CACHE_LINE_SIZE);

	/* Get the number of links registered */
	for (i = 0; i < em_conf->nb_link; i++) {

		/* Get link */
		link = &(em_conf->link[i]);

		/* Check if we have link intended for this lcore */
		if (link->lcore_id == lcore_id) {

			/* Cache the link */
			memcpy(&link_cache[index], link, single_link_size);

			/* Update index */
			index++;
		}
	}

	/* Update the links for application to use the cached links */
	*links = link_cache;

	/* Return the number of cached links */
	return lcore_nb_link;
}

uint8_t __rte_experimental
rte_eventmode_helper_get_tx_queue(struct rte_eventmode_helper_conf *mode_conf,
		uint8_t eventdev_id)
{
	struct eventdev_params *eventdev_config;
	struct eventmode_conf *em_conf;

	if (mode_conf == NULL) {
		RTE_EM_HLPR_LOG_ERR("Invalid conf");
		return (uint8_t)(-1);
	}

	if (mode_conf->mode_params == NULL) {
		RTE_EM_HLPR_LOG_ERR("Invalid mode params");
		return (uint8_t)(-1);
	}

	/* Get eventmode conf */
	em_conf = (struct eventmode_conf *)(mode_conf->mode_params);

	/* Get event device conf */
	eventdev_config = internal_get_eventdev_params(em_conf, eventdev_id);

	if (eventdev_config == NULL) {
		RTE_EM_HLPR_LOG_ERR("Error reading eventdev conf");
		return (uint8_t)(-1);
	}

	/*
	 * The last queue would be reserved to be used as atomic queue for the
	 * last stage (eth packet tx stage)
	 */
	return eventdev_config->nb_eventqueue - 1;
}

/* Helper functions for launching workers */

static int32_t
rte_eventmode_helper_start_worker_eth_core(struct eventmode_conf *em_conf,
		uint32_t lcore_id)
{
	uint32_t service_id[EVENT_MODE_MAX_ADAPTERS_PER_RX_CORE];
	struct rx_adapter_conf *rx_adapter;
	struct tx_adapter_conf *tx_adapter;
	int service_count = 0;
	int adapter_id;
	int32_t ret;
	int i;

	RTE_EM_HLPR_LOG_INFO(
		"Entering eth_core processing on lcore %u", lcore_id);

	/*
	 * Need to parse adapter conf to see which of all Rx adapters need
	 * to be handled by this core.
	 */
	for (i = 0; i < em_conf->nb_rx_adapter; i++) {
		/* Check if we have exceeded the max allowed */
		if (service_count > EVENT_MODE_MAX_ADAPTERS_PER_RX_CORE) {
			RTE_EM_HLPR_LOG_ERR(
				"Exceeded the max allowed adapters per rx core");
			break;
		}

		rx_adapter = &(em_conf->rx_adapter[i]);
		if (rx_adapter->rx_core_id != lcore_id)
			continue;

		/* Adapter need to be handled by this core */
		adapter_id = rx_adapter->adapter_id;

		/* Get the service ID for the adapters */
		ret = rte_event_eth_rx_adapter_service_id_get(adapter_id,
				&(service_id[service_count]));

		if (ret != -ESRCH && ret != 0) {
			RTE_EM_HLPR_LOG_ERR(
				"Error getting service ID used by Rx adapter");
			return ret;
		}

		/* Update service count */
		service_count++;
	}

	/*
	 * Need to parse adapter conf to see which all Tx adapters need to be
	 * handled this core.
	 */
	for (i = 0; i < em_conf->nb_tx_adapter; i++) {
		/* Check if we have exceeded the max allowed */
		if (service_count > EVENT_MODE_MAX_ADAPTERS_PER_TX_CORE) {
			RTE_EM_HLPR_LOG_ERR(
				"Exceeded the max allowed adapters per Tx core");
			break;
		}

		tx_adapter = &(em_conf->tx_adapter[i]);
		if (tx_adapter->tx_core_id != lcore_id)
			continue;

		/* Adapter need to be handled by this core */
		adapter_id = tx_adapter->adapter_id;

		/* Get the service ID for the adapters */
		ret = rte_event_eth_tx_adapter_service_id_get(adapter_id,
				&(service_id[service_count]));

		if (ret != -ESRCH && ret != 0) {
			RTE_EM_HLPR_LOG_ERR(
				"Error getting service ID used by Tx adapter");
			return ret;
		}

		/* Update service count */
		service_count++;
	}

	eth_core_running = true;

	while (eth_core_running) {
		for (i = 0; i < service_count; i++) {
			/* Initiate adapter service */
			rte_service_run_iter_on_app_lcore(service_id[i], 0);
		}
	}

	return 0;
}

static int32_t
rte_eventmode_helper_stop_worker_eth_core(void)
{
	if (eth_core_running) {
		RTE_EM_HLPR_LOG_INFO("Stopping rx cores\n");
		eth_core_running = false;
	}
	return 0;
}

static struct rte_eventmode_helper_app_worker_params *
rte_eventmode_helper_find_worker(uint32_t lcore_id,
		struct eventmode_conf *em_conf,
		struct rte_eventmode_helper_app_worker_params *app_wrkrs,
		uint8_t nb_wrkr_param)
{
	struct rte_eventmode_helper_event_link_info *link = NULL;
	uint8_t eventdev_id;
	struct eventdev_params *eventdev_config;
	int i;
	struct rte_eventmode_helper_app_worker_params curr_conf = {
			{{0} }, NULL};
	struct rte_eventmode_helper_app_worker_params *tmp_wrkr;

	/*
	 * Event device to be used will be derived from the first lcore-event
	 * link.
	 *
	 * Assumption: All lcore-event links tied to a core would be using the
	 * same event device. in other words, one core would be polling on
	 * queues of a single event device only.
	 */

	/* Get a link for this lcore */
	for (i = 0; i < em_conf->nb_link; i++) {
		link = &(em_conf->link[i]);
		if (link->lcore_id == lcore_id)
			break;
	}

	if (link == NULL) {
		RTE_EM_HLPR_LOG_ERR(
			"No valid link found for lcore(%d)", lcore_id);
		return NULL;
	}

	/* Get event dev ID */
	eventdev_id = link->eventdev_id;

	/* Get the corresponding eventdev config */
	eventdev_config = internal_get_eventdev_params(em_conf, eventdev_id);

	/* Populate the curr_conf with the capabilities */

	/* Check for burst mode */
	if (internal_dev_has_burst_mode(eventdev_id))
		curr_conf.cap.burst = RTE_EVENTMODE_HELPER_RX_TYPE_BURST;
	else
		curr_conf.cap.burst = RTE_EVENTMODE_HELPER_RX_TYPE_NON_BURST;

	/* Check for Tx internal port */
	if (internal_dev_has_tx_internal_port(eventdev_id))
		curr_conf.cap.tx_internal_port =
				RTE_EVENTMODE_HELPER_TX_TYPE_INTERNAL_PORT;
	else
		curr_conf.cap.tx_internal_port =
				RTE_EVENTMODE_HELPER_TX_TYPE_NO_INTERNAL_PORT;

	/* Now parse the passed list and see if we have matching capabilities */

	/* Initialize the pointer used to traverse the list */
	tmp_wrkr = app_wrkrs;

	for (i = 0; i < nb_wrkr_param; i++, tmp_wrkr++) {

		/* Skip this if capabilities are not matching */
		if (tmp_wrkr->cap.u64 != curr_conf.cap.u64)
			continue;

		/* If the checks pass, we have a match */
		return tmp_wrkr;
	}

	/* TODO required for ATQ */
	RTE_SET_USED(eventdev_config);

	return NULL;
}

static int
rte_eventmode_helper_verify_match_worker(
	struct rte_eventmode_helper_app_worker_params *match_wrkr)
{
	/* Verify registered worker */
	if (match_wrkr->worker_thread == NULL) {
		RTE_EM_HLPR_LOG_ERR("No worker registered for second stage");
		return 0;
	}

	/* Success */
	return 1;
}

void __rte_experimental
rte_eventmode_helper_launch_worker(struct rte_eventmode_helper_conf *mode_conf,
		struct rte_eventmode_helper_app_worker_params *app_wrkr,
		uint8_t nb_wrkr_param)
{
	struct rte_eventmode_helper_app_worker_params *match_wrkr;
	uint32_t lcore_id;
	struct eventmode_conf *em_conf;

	if (mode_conf == NULL) {
		RTE_EM_HLPR_LOG_ERR("Invalid conf");
		return;
	}

	if (mode_conf->mode_params == NULL) {
		RTE_EM_HLPR_LOG_ERR("Invalid mode params");
		return;
	}

	/* Get eventmode conf */
	em_conf = (struct eventmode_conf *)(mode_conf->mode_params);

	/* Get core ID */
	lcore_id = rte_lcore_id();

	/* TODO check capability for rx core */

	/* Check if this is rx core */
	if (em_conf->eth_core_mask & (1 << lcore_id)) {
		rte_eventmode_helper_start_worker_eth_core(em_conf, lcore_id);
		return;
	}

	if (app_wrkr == NULL || nb_wrkr_param == 0) {
		RTE_EM_HLPR_LOG_ERR("Invalid args");
		return;
	}

	/*
	 * This is a regular worker thread. The application would be
	 * registering multiple workers with various capabilities. The
	 * worker to be run will be selected by the capabilities of the
	 * event device configured.
	 */

	/* Get the first matching worker for the event device */
	match_wrkr = rte_eventmode_helper_find_worker(lcore_id,
			em_conf,
			app_wrkr,
			nb_wrkr_param);

	if (match_wrkr == NULL) {
		RTE_EM_HLPR_LOG_ERR(
			"No matching worker registered for lcore %d", lcore_id);
		goto clean_and_exit;
	}

	/* Verify sanity of the matched worker */
	if (rte_eventmode_helper_verify_match_worker(match_wrkr) != 1) {
		RTE_EM_HLPR_LOG_ERR("Error in validating the matched worker");
		goto clean_and_exit;
	}

	/* Launch the worker thread */
	match_wrkr->worker_thread(mode_conf);

clean_and_exit:

	/* Flag eth_cores to stop, if started */
	rte_eventmode_helper_stop_worker_eth_core();
}
