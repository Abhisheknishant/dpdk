/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2019 Marvell International Ltd.
 */

#include <stdbool.h>
#include <getopt.h>

#include <rte_ethdev.h>
#include <rte_eventdev.h>
#include <rte_event_eth_rx_adapter.h>
#include <rte_event_eth_tx_adapter.h>
#include <rte_lcore.h>
#include <rte_spinlock.h>

#include "l3fwd.h"

enum {
	CMD_LINE_OPT_MODE_NUM = 265,
	CMD_LINE_OPT_EVENTQ_SYNC_NUM,
};

static const struct option eventdev_lgopts[] = {
	{CMD_LINE_OPT_MODE, 1, 0, CMD_LINE_OPT_MODE_NUM},
	{CMD_LINE_OPT_EVENTQ_SYNC, 1, 0, CMD_LINE_OPT_EVENTQ_SYNC_NUM},
	{NULL, 0, 0, 0}
};

/* Eventdev command line options */
int evd_argc;
char *evd_argv[3];

/* Default configurations */
int pkt_transfer_mode = PACKET_TRANSFER_MODE_POLL;
int eventq_sync_mode = RTE_SCHED_TYPE_ATOMIC;
uint32_t num_workers = RTE_MAX_LCORE;
struct eventdev_resources eventdev_rsrc;

static struct rte_eth_conf port_config = {
	.rxmode = {
		.mq_mode = ETH_MQ_RX_RSS,
		.max_rx_pkt_len = RTE_ETHER_MAX_LEN,
		.split_hdr_size = 0,
		.offloads = DEV_RX_OFFLOAD_CHECKSUM,
	},
	.rx_adv_conf = {
		.rss_conf = {
			.rss_key = NULL,
			.rss_hf = ETH_RSS_IP,
		},
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
};

struct rte_event_dev_config event_d_conf = {
	.nb_event_queues = 1,
	.nb_event_ports = RTE_MAX_LCORE,
	.nb_events_limit  = 4096,
	.nb_event_queue_flows = 1024,
	.nb_event_port_dequeue_depth = 128,
	.nb_event_port_enqueue_depth = 128,
};

static struct rte_event_port_conf event_p_conf = {
	.dequeue_depth = 32,
	.enqueue_depth = 32,
	.new_event_threshold = 4096,
};

static struct rte_event_queue_conf event_q_conf = {
	.nb_atomic_flows = 1024,
	.nb_atomic_order_sequences = 1024,
	.event_queue_cfg = 0,
	.schedule_type = RTE_SCHED_TYPE_ATOMIC,
	.priority = RTE_EVENT_DEV_PRIORITY_HIGHEST,
};

static struct rte_event_eth_rx_adapter_queue_conf eth_q_conf = {
	.rx_queue_flags = 0,
	.servicing_weight = 1,
	.ev = {
		.queue_id = 0,
		.priority = RTE_EVENT_DEV_PRIORITY_HIGHEST,
		.sched_type = RTE_SCHED_TYPE_ATOMIC,
	},
};

static void parse_mode(const char *optarg)
{
	if (!strncmp(optarg, "poll", 4))
		pkt_transfer_mode = PACKET_TRANSFER_MODE_POLL;
	else if (!strncmp(optarg, "eventdev", 8))
		pkt_transfer_mode = PACKET_TRANSFER_MODE_EVENTDEV;
}

static void parse_eventq_sync(const char *optarg)
{
	if (!strncmp(optarg, "ordered", 7))
		eventq_sync_mode = RTE_SCHED_TYPE_ORDERED;
	else if (!strncmp(optarg, "atomic", 6))
		eventq_sync_mode = RTE_SCHED_TYPE_ATOMIC;
}

static int parse_eventdev_args(int argc, char **argv)
{
	char **argvopt = argv;
	int32_t opt, ret = -1;
	int32_t option_index;

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

	if (pkt_transfer_mode == PACKET_TRANSFER_MODE_EVENTDEV)
		ret = EVENT_DEV_PARAM_PRESENT;

	return ret;
}

/* Send burst of packets on an output interface */
static inline int send_burst_eventdev_generic(struct rte_mbuf *m[], uint16_t n,
					      uint16_t port)
{
	struct rte_event events[MAX_PKT_BURST];
	uint8_t event_d_id;
	int ret, i;

	event_d_id = eventdev_rsrc.event_d_id;

	for (i = 0; i < n; i++) {
		events[i].queue_id = 0;
		events[i].op = RTE_EVENT_OP_FORWARD;
		events[i].mbuf = m[i];
	}

	ret = rte_event_enqueue_burst(event_d_id, port, events, n);
	if (unlikely(ret < n)) {
		do {
			rte_pktmbuf_free(m[ret]);
		} while (++ret < n);
	}

	return 0;
}

/* Send burst of packets on an output interface */
static inline int send_burst_eventdev_adapter(struct rte_mbuf *m[], uint16_t n,
					      uint16_t port)
{
	struct rte_event events[MAX_PKT_BURST];
	uint8_t event_d_id;
	int32_t ret, i;

	event_d_id = eventdev_rsrc.event_d_id;

	for (i = 0; i < n; i++) {
		events[i].queue_id = 0;
		events[i].op = RTE_EVENT_OP_FORWARD;
		events[i].mbuf = m[i];
		rte_event_eth_tx_adapter_txq_set(events[i].mbuf, 0);
	}

	ret = rte_event_eth_tx_adapter_enqueue(event_d_id, port, events, n);
	if (unlikely(ret < n)) {
		do {
			rte_pktmbuf_free(m[ret]);
		} while (++ret < n);
	}

	return 0;
}

static uint32_t event_dev_setup(uint16_t ethdev_count)
{
	struct rte_event_dev_info dev_info;
	const uint8_t event_d_id = 0; /* Always use first event device only */
	uint32_t event_queue_cfg = 0;
	int ret;

	/* Event device configurtion */
	rte_event_dev_info_get(event_d_id, &dev_info);

	if (dev_info.event_dev_cap & RTE_EVENT_DEV_CAP_QUEUE_ALL_TYPES)
		event_queue_cfg |= RTE_EVENT_QUEUE_CFG_ALL_TYPES;

	event_d_conf.nb_event_queues = ethdev_count;
	if (dev_info.max_event_queues < event_d_conf.nb_event_queues)
		event_d_conf.nb_event_queues = dev_info.max_event_queues;

	if (dev_info.max_num_events < event_d_conf.nb_events_limit)
		event_d_conf.nb_events_limit = dev_info.max_num_events;

	if (dev_info.max_event_port_dequeue_depth <
				event_d_conf.nb_event_port_dequeue_depth)
		event_d_conf.nb_event_port_dequeue_depth =
				dev_info.max_event_port_dequeue_depth;

	if (dev_info.max_event_port_enqueue_depth <
				event_d_conf.nb_event_port_enqueue_depth)
		event_d_conf.nb_event_port_enqueue_depth =
				dev_info.max_event_port_enqueue_depth;

	num_workers = rte_lcore_count();
	if (dev_info.max_event_ports < num_workers)
		num_workers = dev_info.max_event_ports;

	event_d_conf.nb_event_ports = num_workers;

	ret = rte_event_dev_configure(event_d_id, &event_d_conf);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error in configuring event device");

	eventdev_rsrc.event_d_id = event_d_id;
	return event_queue_cfg;
}

static void event_port_setup(void)
{
	uint8_t event_d_id = eventdev_rsrc.event_d_id;
	struct rte_event_port_conf evp_conf;
	uint8_t event_p_id;
	int32_t ret;

	eventdev_rsrc.evp.nb_ports = num_workers;
	eventdev_rsrc.evp.event_p_id = (uint8_t *)malloc(sizeof(uint8_t) *
					eventdev_rsrc.evp.nb_ports);
	if (!eventdev_rsrc.evp.event_p_id)
		rte_exit(EXIT_FAILURE, " No space is available");

	for (event_p_id = 0; event_p_id < num_workers; event_p_id++) {
		rte_event_port_default_conf_get(event_d_id, event_p_id,
						&evp_conf);

		if (evp_conf.new_event_threshold <
					event_p_conf.new_event_threshold)
			event_p_conf.new_event_threshold =
					evp_conf.new_event_threshold;

		if (evp_conf.dequeue_depth < event_p_conf.dequeue_depth)
			event_p_conf.dequeue_depth = evp_conf.dequeue_depth;

		if (evp_conf.enqueue_depth < event_p_conf.enqueue_depth)
			event_p_conf.enqueue_depth = evp_conf.enqueue_depth;

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
		eventdev_rsrc.evp.event_p_id[event_p_id] = event_p_id;

		/* init spinlock */
		rte_spinlock_init(&eventdev_rsrc.evp.lock);
	}
}

static void event_queue_setup(uint16_t ethdev_count, uint32_t event_queue_cfg)
{
	uint8_t event_d_id = eventdev_rsrc.event_d_id;
	struct rte_event_queue_conf evq_conf;
	uint8_t event_q_id = 0;
	int32_t ret;

	rte_event_queue_default_conf_get(event_d_id, event_q_id, &evq_conf);

	if (evq_conf.nb_atomic_flows < event_q_conf.nb_atomic_flows)
		event_q_conf.nb_atomic_flows = evq_conf.nb_atomic_flows;

	if (evq_conf.nb_atomic_order_sequences <
					event_q_conf.nb_atomic_order_sequences)
		event_q_conf.nb_atomic_order_sequences =
					evq_conf.nb_atomic_order_sequences;

	event_q_conf.event_queue_cfg = event_queue_cfg;
	event_q_conf.schedule_type = eventq_sync_mode;
	eventdev_rsrc.evq.nb_queues = ethdev_count;
	eventdev_rsrc.evq.event_q_id = (uint8_t *)malloc(sizeof(uint8_t) *
					eventdev_rsrc.evq.nb_queues);
	if (!eventdev_rsrc.evq.event_q_id)
		rte_exit(EXIT_FAILURE, "Memory allocation failure");

	for (event_q_id = 0; event_q_id < ethdev_count; event_q_id++) {
		ret = rte_event_queue_setup(event_d_id, event_q_id,
					    &event_q_conf);
		if (ret < 0) {
			rte_exit(EXIT_FAILURE,
				 "Error in configuring event queue");
		}
		eventdev_rsrc.evq.event_q_id[event_q_id] = event_q_id;
	}
}

static void rx_tx_adapter_setup(uint16_t ethdev_count)
{
	uint8_t event_d_id = eventdev_rsrc.event_d_id;
	uint32_t service_id;
	uint32_t cap = 0;
	int32_t ret, i;

	eventdev_rsrc.rx_adptr.nb_rx_adptr = ethdev_count;
	eventdev_rsrc.rx_adptr.rx_adptr = (uint8_t *)malloc(sizeof(uint8_t) *
					eventdev_rsrc.rx_adptr.nb_rx_adptr);
	if (!eventdev_rsrc.rx_adptr.rx_adptr) {
		free(eventdev_rsrc.evp.event_p_id);
		free(eventdev_rsrc.evq.event_q_id);
		rte_exit(EXIT_FAILURE,
			 "failed to allocate memery for Rx adapter");
	}

	for (i = 0; i < ethdev_count; i++) {
		ret = rte_event_eth_rx_adapter_create(i, event_d_id,
						      &event_p_conf);
		if (ret)
			rte_exit(EXIT_FAILURE,
				 "failed to create rx adapter[%d]", i);

		ret = rte_event_eth_rx_adapter_caps_get(event_d_id, i, &cap);
		if (ret)
			rte_exit(EXIT_FAILURE,
				 "failed to get event rx adapter capabilities");

		/* Configure user requested sync mode */
		eth_q_conf.ev.queue_id = eventdev_rsrc.evq.event_q_id[i];
		eth_q_conf.ev.sched_type = eventq_sync_mode;
		ret = rte_event_eth_rx_adapter_queue_add(i, i, -1, &eth_q_conf);
		if (ret)
			rte_exit(EXIT_FAILURE,
				 "Failed to add queues to Rx adapter");

		if (!(cap & RTE_EVENT_ETH_RX_ADAPTER_CAP_INTERNAL_PORT)) {
			ret = rte_event_eth_rx_adapter_service_id_get(i,
								&service_id);
			if (ret != -ESRCH && ret != 0) {
				rte_exit(EXIT_FAILURE,
				"Error getting the service ID for rx adptr\n");
			}

			rte_service_runstate_set(service_id, 1);
			rte_service_set_runstate_mapped_check(service_id, 1);
		}

		ret = rte_event_eth_rx_adapter_start(i);
		if (ret)
			rte_exit(EXIT_FAILURE,
				 "Rx adapter[%d] start failed", i);

		eventdev_rsrc.rx_adptr.rx_adptr[i] = i;
	}

	eventdev_rsrc.tx_adptr.nb_tx_adptr = ethdev_count;
	eventdev_rsrc.tx_adptr.tx_adptr = (uint8_t *)malloc(sizeof(uint8_t) *
					eventdev_rsrc.tx_adptr.nb_tx_adptr);
	if (!eventdev_rsrc.tx_adptr.tx_adptr) {
		free(eventdev_rsrc.rx_adptr.rx_adptr);
		free(eventdev_rsrc.evp.event_p_id);
		free(eventdev_rsrc.evq.event_q_id);
		rte_exit(EXIT_FAILURE,
			 "failed to allocate memery for Rx adapter");
	}

	eventdev_rsrc.send_burst_eventdev = send_burst_eventdev_adapter;
	for (i = 0; i < ethdev_count; i++) {
		ret = rte_event_eth_tx_adapter_create(i, event_d_id,
						      &event_p_conf);
		if (ret)
			rte_exit(EXIT_FAILURE,
				 "failed to create tx adapter[%d]", i);

		ret = rte_event_eth_tx_adapter_caps_get(event_d_id, i, &cap);
		if (ret)
			rte_exit(EXIT_FAILURE,
				 "Failed to get event tx adapter capabilities");

		if (!(cap & RTE_EVENT_ETH_TX_ADAPTER_CAP_INTERNAL_PORT)) {
			ret = rte_event_eth_tx_adapter_service_id_get(i,
								   &service_id);
			if (ret != -ESRCH && ret != 0) {
				rte_exit(EXIT_FAILURE,
					 "Failed to get Tx adapter service ID");
			}

			rte_service_runstate_set(service_id, 1);
			rte_service_set_runstate_mapped_check(service_id, 1);
			eventdev_rsrc.send_burst_eventdev =
						send_burst_eventdev_generic;
		}

		ret = rte_event_eth_tx_adapter_queue_add(i, i, -1);
		if (ret)
			rte_exit(EXIT_FAILURE,
				 "failed to add queues to Tx adapter");

		ret = rte_event_eth_tx_adapter_start(i);
		if (ret)
			rte_exit(EXIT_FAILURE,
				 "Tx adapter[%d] start failed", i);

		eventdev_rsrc.tx_adptr.tx_adptr[i] = i;
	}
}

static void eth_dev_port_setup(uint16_t ethdev_count)
{
	struct rte_eth_conf local_port_conf = port_config;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;
	struct rte_eth_rxconf rxconf;
	uint16_t nb_rx_queue = 1;
	uint16_t n_tx_queue = 1;
	uint16_t nb_rxd = 1024;
	uint16_t nb_txd = 1024;
	uint32_t nb_lcores;
	uint16_t portid;
	int32_t ret;

	nb_lcores = rte_lcore_count();

	/* initialize all ports */
	RTE_ETH_FOREACH_DEV(portid) {
		/* skip ports that are not enabled */
		if ((enabled_port_mask & (1 << portid)) == 0) {
			printf("\nSkipping disabled port %d\n", portid);
			continue;
		}

		/* init port */
		printf("Initializing port %d ... ", portid);
		fflush(stdout);
		printf("Creating queues: nb_rxq=%d nb_txq=%u... ",
			nb_rx_queue, n_tx_queue);

		rte_eth_dev_info_get(portid, &dev_info);
		if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
			local_port_conf.txmode.offloads |=
						DEV_TX_OFFLOAD_MBUF_FAST_FREE;

		local_port_conf.rx_adv_conf.rss_conf.rss_hf &=
						dev_info.flow_type_rss_offloads;
		if (local_port_conf.rx_adv_conf.rss_conf.rss_hf !=
				port_config.rx_adv_conf.rss_conf.rss_hf) {
			printf("Port %u modified RSS hash function "
			       "based on hardware support,"
			       "requested:%#"PRIx64" configured:%#"PRIx64"\n",
			       portid,
			       port_config.rx_adv_conf.rss_conf.rss_hf,
			       local_port_conf.rx_adv_conf.rss_conf.rss_hf);
		}

		ret = rte_eth_dev_configure(portid, nb_rx_queue, n_tx_queue,
					    &local_port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "Cannot configure device: err=%d, port=%d\n",
				 ret, portid);

		ret = rte_eth_dev_adjust_nb_rx_tx_desc(portid, &nb_rxd,
						       &nb_txd);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "Cannot adjust number of descriptors: err=%d, "
				 "port=%d\n", ret, portid);

		rte_eth_macaddr_get(portid, &ports_eth_addr[portid]);
		print_ethaddr(" Address:", &ports_eth_addr[portid]);
		printf(", ");
		print_ethaddr("Destination:",
			(const struct rte_ether_addr *)&dest_eth_addr[portid]);
		printf(", ");

		/* prepare source MAC for each port. */
		rte_ether_addr_copy(&ports_eth_addr[portid],
			(struct rte_ether_addr *)(val_eth + portid) + 1);

		/* init memory */
		ret = init_mem(portid, NUM_MBUF(ethdev_count));
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "init_mem failed\n");

		/* init one Rx queue per port */
		rxconf = dev_info.default_rxconf;
		rxconf.offloads = local_port_conf.rxmode.offloads;
		ret = rte_eth_rx_queue_setup(portid, 0, nb_rxd, 0, &rxconf,
					     pktmbuf_pool[portid][0]);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "rte_eth_rx_queue_setup: err=%d, "
				 "port=%d\n", ret, portid);

		/* init one Tx queue per port */
		txconf = dev_info.default_txconf;
		txconf.offloads = local_port_conf.txmode.offloads;
		ret = rte_eth_tx_queue_setup(portid, 0, nb_txd, 0, &txconf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "rte_eth_tx_queue_setup: err=%d, "
				 "port=%d\n", ret, portid);
	}
}

int get_free_event_port(void)
{
	static int index;
	int port_id;

	rte_spinlock_lock(&eventdev_rsrc.evp.lock);
	if (index >= eventdev_rsrc.evp.nb_ports) {
		printf("No free event port is available\n");
		return -1;
	}

	port_id = eventdev_rsrc.evp.event_p_id[index];
	index++;
	rte_spinlock_unlock(&eventdev_rsrc.evp.lock);

	return port_id;
}

int eventdev_resource_setup(int argc, char **argv)
{
	uint16_t ethdev_count = rte_eth_dev_count_avail();
	uint32_t event_queue_cfg = 0;
	uint32_t service_id;
	int32_t ret;

	/* Parse eventdev command line options */
	ret = parse_eventdev_args(argc, argv);
	if (ret < 0)
		return ret;

	if (rte_event_dev_count() < 1)
		rte_exit(EXIT_FAILURE, "No Eventdev found");

	/* Setup function pointers for lookup method */
	setup_l3fwd_lookup_tables();

	/* Ethernet device configuration */
	eth_dev_port_setup(ethdev_count);

	/* Event device configuration */
	event_queue_cfg = event_dev_setup(ethdev_count);

	/* Event queue configuration */
	event_queue_setup(ethdev_count, event_queue_cfg);

	/* Event port configuration */
	event_port_setup();

	/* Rx/Tx adapters configuration */
	rx_tx_adapter_setup(ethdev_count);

	/* Start event device service */
	ret = rte_event_dev_service_id_get(eventdev_rsrc.event_d_id,
					   &service_id);
	if (ret != -ESRCH && ret != 0)
		rte_exit(EXIT_FAILURE, "Error in starting eventdev");

	rte_service_runstate_set(service_id, 1);
	rte_service_set_runstate_mapped_check(service_id, 1);

	/* Start event device */
	ret = rte_event_dev_start(eventdev_rsrc.event_d_id);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error in starting eventdev");

	return EVENT_DEV_PARAM_PRESENT;
}
