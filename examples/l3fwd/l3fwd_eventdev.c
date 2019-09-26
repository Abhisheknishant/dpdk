/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2019 Marvell International Ltd.
 */

#include <stdbool.h>
#include <getopt.h>

#include "l3fwd.h"
#include "l3fwd_eventdev.h"

static void
print_ethaddr(const char *name, const struct rte_ether_addr *eth_addr)
{
	char buf[RTE_ETHER_ADDR_FMT_SIZE];
	rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s%s", name, buf);
}

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
l3fwd_eth_dev_port_setup(struct rte_eth_conf *port_conf)
{
	struct l3fwd_eventdev_resources *evdev_rsrc = l3fwd_get_eventdev_rsrc();
	uint16_t nb_ports = rte_eth_dev_count_avail();
	uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
	uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;
	unsigned int nb_lcores = rte_lcore_count();
	struct rte_eth_conf local_port_conf;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;
	struct rte_eth_rxconf rxconf;
	unsigned int nb_mbuf;
	uint16_t port_id;
	int32_t ret;

	/* initialize all ports */
	RTE_ETH_FOREACH_DEV(port_id) {
		local_port_conf = *port_conf;
		/* skip ports that are not enabled */
		if ((evdev_rsrc->port_mask & (1 << port_id)) == 0) {
			printf("\nSkipping disabled port %d\n", port_id);
			continue;
		}

		/* init port */
		printf("Initializing port %d ... ", port_id);
		fflush(stdout);
		printf("Creating queues: nb_rxq=1 nb_txq=1...\n");

		rte_eth_dev_info_get(port_id, &dev_info);
		if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
			local_port_conf.txmode.offloads |=
						DEV_TX_OFFLOAD_MBUF_FAST_FREE;

		local_port_conf.rx_adv_conf.rss_conf.rss_hf &=
						dev_info.flow_type_rss_offloads;
		if (local_port_conf.rx_adv_conf.rss_conf.rss_hf !=
				port_conf->rx_adv_conf.rss_conf.rss_hf) {
			printf("Port %u modified RSS hash function "
			       "based on hardware support,"
			       "requested:%#"PRIx64" configured:%#"PRIx64"\n",
			       port_id,
			       port_conf->rx_adv_conf.rss_conf.rss_hf,
			       local_port_conf.rx_adv_conf.rss_conf.rss_hf);
		}

		ret = rte_eth_dev_configure(port_id, 1, 1, &local_port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "Cannot configure device: err=%d, port=%d\n",
				 ret, port_id);

		ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd,
						       &nb_txd);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "Cannot adjust number of descriptors: err=%d, "
				 "port=%d\n", ret, port_id);

		rte_eth_macaddr_get(port_id, &ports_eth_addr[port_id]);
		print_ethaddr(" Address:", &ports_eth_addr[port_id]);
		printf(", ");
		print_ethaddr("Destination:",
			(const struct rte_ether_addr *)&dest_eth_addr[port_id]);
		printf(", ");

		/* prepare source MAC for each port. */
		rte_ether_addr_copy(&ports_eth_addr[port_id],
			(struct rte_ether_addr *)(val_eth + port_id) + 1);

		/* init memory */
		if (!evdev_rsrc->per_port_pool) {
			/* port_id = 0; this is *not* signifying the first port,
			 * rather, it signifies that port_id is ignored.
			 */
			nb_mbuf = RTE_MAX(nb_ports * nb_rxd +
					  nb_ports * nb_txd +
					  nb_ports * nb_lcores *
							MAX_PKT_BURST +
					  nb_lcores * MEMPOOL_CACHE_SIZE,
					  8192u);
			ret = init_mem(0, nb_mbuf);
		} else {
			nb_mbuf = RTE_MAX(nb_rxd + nb_rxd +
					  nb_lcores * MAX_PKT_BURST +
					  nb_lcores * MEMPOOL_CACHE_SIZE,
					  8192u);
			ret = init_mem(port_id, nb_mbuf);
		}
		/* init one Rx queue per port */
		rxconf = dev_info.default_rxconf;
		rxconf.offloads = local_port_conf.rxmode.offloads;
		if (!evdev_rsrc->per_port_pool)
			ret = rte_eth_rx_queue_setup(port_id, 0, nb_rxd, 0,
					&rxconf, evdev_rsrc->pkt_pool[0][0]);
		else
			ret = rte_eth_rx_queue_setup(port_id, 0, nb_rxd, 0,
					&rxconf,
					evdev_rsrc->pkt_pool[port_id][0]);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "rte_eth_rx_queue_setup: err=%d, "
				 "port=%d\n", ret, port_id);

		/* init one Tx queue per port */
		txconf = dev_info.default_txconf;
		txconf.offloads = local_port_conf.txmode.offloads;
		ret = rte_eth_tx_queue_setup(port_id, 0, nb_txd, 0, &txconf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "rte_eth_tx_queue_setup: err=%d, "
				 "port=%d\n", ret, port_id);
	}
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

static uint32_t
l3fwd_eventdev_setup(uint16_t ethdev_count)
{
	struct l3fwd_eventdev_resources *evdev_rsrc = l3fwd_get_eventdev_rsrc();
	struct rte_event_dev_config event_d_conf = {
		.nb_events_limit  = 4096,
		.nb_event_queue_flows = 1024,
		.nb_event_port_dequeue_depth = 128,
		.nb_event_port_enqueue_depth = 128
	};
	struct rte_event_dev_info dev_info;
	const uint8_t event_d_id = 0; /* Always use first event device only */
	uint32_t event_queue_cfg = 0;
	uint16_t num_workers = 0;
	int ret;

	/* Event device configurtion */
	rte_event_dev_info_get(event_d_id, &dev_info);
	evdev_rsrc->disable_implicit_release = !!(dev_info.event_dev_cap &
				    RTE_EVENT_DEV_CAP_IMPLICIT_RELEASE_DISABLE);

	if (dev_info.event_dev_cap & RTE_EVENT_DEV_CAP_QUEUE_ALL_TYPES)
		event_queue_cfg |= RTE_EVENT_QUEUE_CFG_ALL_TYPES;

	event_d_conf.nb_event_queues = ethdev_count +
			(evdev_rsrc->tx_mode_q ? 1 : 0);
	if (dev_info.max_event_queues < event_d_conf.nb_event_queues)
		event_d_conf.nb_event_queues = dev_info.max_event_queues;

	if (dev_info.max_num_events < event_d_conf.nb_events_limit)
		event_d_conf.nb_events_limit = dev_info.max_num_events;

	if (dev_info.max_event_queue_flows < event_d_conf.nb_event_queue_flows)
		event_d_conf.nb_event_queue_flows =
						dev_info.max_event_queue_flows;

	if (dev_info.max_event_port_dequeue_depth <
				event_d_conf.nb_event_port_dequeue_depth)
		event_d_conf.nb_event_port_dequeue_depth =
				dev_info.max_event_port_dequeue_depth;

	if (dev_info.max_event_port_enqueue_depth <
				event_d_conf.nb_event_port_enqueue_depth)
		event_d_conf.nb_event_port_enqueue_depth =
				dev_info.max_event_port_enqueue_depth;

	num_workers = rte_lcore_count() - rte_service_lcore_count();
	if (dev_info.max_event_ports < num_workers)
		num_workers = dev_info.max_event_ports;

	event_d_conf.nb_event_ports = num_workers;
	evdev_rsrc->evp.nb_ports = num_workers;
	evdev_rsrc->has_burst = !!(dev_info.event_dev_cap &
				    RTE_EVENT_DEV_CAP_BURST_MODE);

	ret = rte_event_dev_configure(event_d_id, &event_d_conf);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error in configuring event device");

	evdev_rsrc->event_d_id = event_d_id;
	return event_queue_cfg;
}

int
l3fwd_get_free_event_port(struct l3fwd_eventdev_resources *evdev_rsrc)
{
	static int index;
	int port_id;

	rte_spinlock_lock(&evdev_rsrc->evp.lock);
	if (index >= evdev_rsrc->evp.nb_ports) {
		printf("No free event port is available\n");
		return -1;
	}

	port_id = evdev_rsrc->evp.event_p_id[index];
	index++;
	rte_spinlock_unlock(&evdev_rsrc->evp.lock);

	return port_id;
}

void
l3fwd_eventdev_resource_setup(struct rte_eth_conf *port_conf)
{
	struct l3fwd_eventdev_resources *evdev_rsrc = l3fwd_get_eventdev_rsrc();
	uint16_t ethdev_count = rte_eth_dev_count_avail();
	uint32_t event_queue_cfg;
	int32_t ret;

	/* Parse eventdev command line options */
	ret = l3fwd_parse_eventdev_args(evdev_rsrc->args, evdev_rsrc->nb_args);
	if (ret < 0 || !evdev_rsrc->enabled)
		return;

	if (!rte_event_dev_count())
		rte_exit(EXIT_FAILURE, "No Eventdev found");

	/* Setup eventdev capability callbacks */
	l3fwd_eventdev_capability_setup();

	/* Ethernet device configuration */
	l3fwd_eth_dev_port_setup(port_conf);

	/* Event device configuration */
	event_queue_cfg = l3fwd_eventdev_setup(ethdev_count);

	/* Event queue configuration */
	evdev_rsrc->ops.event_queue_setup(ethdev_count, event_queue_cfg);

	/* Event port configuration */
	evdev_rsrc->ops.event_port_setup();

	/* Rx/Tx adapters configuration */
	evdev_rsrc->ops.adapter_setup(ethdev_count);
}
