#include "l2fwd_common.h"

/* Print out statistics on packets dropped */
void
print_stats(struct l2fwd_resources *l2fwd_rsrc)
{
	uint64_t total_packets_dropped, total_packets_tx, total_packets_rx;
	uint32_t port_id;

	total_packets_dropped = 0;
	total_packets_tx = 0;
	total_packets_rx = 0;

	const char clr[] = {27, '[', '2', 'J', '\0' };
	const char topLeft[] = {27, '[', '1', ';', '1', 'H', '\0' };

		/* Clear screen and move to top left */
	printf("%s%s", clr, topLeft);

	printf("\nPort statistics ====================================");

	for (port_id = 0; port_id < RTE_MAX_ETHPORTS; port_id++) {
		/* skip disabled ports */
		if ((l2fwd_rsrc->enabled_port_mask & (1 << port_id)) == 0)
			continue;
		printf("\nStatistics for port %u ------------------------------"
			   "\nPackets sent: %24"PRIu64
			   "\nPackets received: %20"PRIu64
			   "\nPackets dropped: %21"PRIu64,
			   port_id,
			   l2fwd_rsrc->port_stats[port_id].tx,
			   l2fwd_rsrc->port_stats[port_id].rx,
			   l2fwd_rsrc->port_stats[port_id].dropped);

		total_packets_dropped +=
					l2fwd_rsrc->port_stats[port_id].dropped;
		total_packets_tx += l2fwd_rsrc->port_stats[port_id].tx;
		total_packets_rx += l2fwd_rsrc->port_stats[port_id].rx;
	}
	printf("\nAggregate statistics ==============================="
		   "\nTotal packets sent: %18"PRIu64
		   "\nTotal packets received: %14"PRIu64
		   "\nTotal packets dropped: %15"PRIu64,
		   total_packets_tx,
		   total_packets_rx,
		   total_packets_dropped);
	printf("\n====================================================\n");
}

int
l2fwd_event_init_ports(struct l2fwd_resources *l2fwd_rsrc)
{
	uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
	uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;
	struct rte_eth_conf port_conf = {
		.rxmode = {
			.max_rx_pkt_len = RTE_ETHER_MAX_LEN,
			.split_hdr_size = 0,
		},
		.txmode = {
			.mq_mode = ETH_MQ_TX_NONE,
		},
	};
	uint16_t nb_ports_available = 0;
	uint16_t port_id;
	int ret;

	if (l2fwd_rsrc->event_mode) {
		port_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
		port_conf.rx_adv_conf.rss_conf.rss_key = NULL;
		port_conf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_IP;
	}

	/* Initialise each port */
	RTE_ETH_FOREACH_DEV(port_id) {
		struct rte_eth_conf local_port_conf = port_conf;
		struct rte_eth_dev_info dev_info;
		struct rte_eth_rxconf rxq_conf;
		struct rte_eth_txconf txq_conf;

		/* skip ports that are not enabled */
		if ((l2fwd_rsrc->enabled_port_mask & (1 << port_id)) == 0) {
			printf("Skipping disabled port %u\n", port_id);
			continue;
		}
		nb_ports_available++;

		/* init port */
		printf("Initializing port %u... ", port_id);
		fflush(stdout);
		rte_eth_dev_info_get(port_id, &dev_info);
		if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
			local_port_conf.txmode.offloads |=
				DEV_TX_OFFLOAD_MBUF_FAST_FREE;
		ret = rte_eth_dev_configure(port_id, 1, 1, &local_port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "Cannot configure device: err=%d, port=%u\n",
				 ret, port_id);

		ret = rte_eth_dev_adjust_nb_rx_tx_desc(port_id, &nb_rxd,
						       &nb_txd);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "Cannot adjust number of descriptors: err=%d, port=%u\n",
				 ret, port_id);

		rte_eth_macaddr_get(port_id, &l2fwd_rsrc->eth_addr[port_id]);

		/* init one RX queue */
		fflush(stdout);
		rxq_conf = dev_info.default_rxconf;
		rxq_conf.offloads = local_port_conf.rxmode.offloads;
		ret = rte_eth_rx_queue_setup(port_id, 0, nb_rxd,
					     rte_eth_dev_socket_id(port_id),
					     &rxq_conf,
					     l2fwd_rsrc->pktmbuf_pool);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "rte_eth_rx_queue_setup:err=%d, port=%u\n",
				 ret, port_id);

		/* init one TX queue on each port */
		fflush(stdout);
		txq_conf = dev_info.default_txconf;
		txq_conf.offloads = local_port_conf.txmode.offloads;
		ret = rte_eth_tx_queue_setup(port_id, 0, nb_txd,
				rte_eth_dev_socket_id(port_id),
				&txq_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				 "rte_eth_tx_queue_setup:err=%d, port=%u\n",
				 ret, port_id);

		rte_eth_promiscuous_enable(port_id);

		printf("Port %u,MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
			port_id,
			l2fwd_rsrc->eth_addr[port_id].addr_bytes[0],
			l2fwd_rsrc->eth_addr[port_id].addr_bytes[1],
			l2fwd_rsrc->eth_addr[port_id].addr_bytes[2],
			l2fwd_rsrc->eth_addr[port_id].addr_bytes[3],
			l2fwd_rsrc->eth_addr[port_id].addr_bytes[4],
			l2fwd_rsrc->eth_addr[port_id].addr_bytes[5]);
	}

	return nb_ports_available;
}
