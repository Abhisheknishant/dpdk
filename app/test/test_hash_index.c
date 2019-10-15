/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2019 Marvell International Ltd.
 */


#include <stdio.h>
#include <inttypes.h>
#include <signal.h>
#include <unistd.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_malloc.h>
#include "packet_burst_generator.h"
#include "test.h"

#define NB_ETHPORTS_USED         1
#define MAX_PKT_BURST            32
#define MAX_TRAFFIC_BURST        128
#define MEMPOOL_CACHE_SIZE       32
#define MAX_TEST_QUEUES_PER_PORT  4

#define DEF_RETA_SIZE   RTE_RETA_GROUP_SIZE

#define NB_MBUF RTE_MAX(						\
		(uint32_t)(nb_ports*nb_rx_queue*nb_rxd +		\
			   nb_ports*MAX_PKT_BURST +			\
			   nb_ports*nb_tx_queue*nb_txd +		\
			   1*MEMPOOL_CACHE_SIZE +			\
			   nb_ports*MAX_TRAFFIC_BURST),			\
			(uint32_t)4096)

static struct rte_mempool *mbufpool;
static struct rte_eth_rss_reta_entry64 reta_conf;

static struct rte_eth_conf port_conf = {
	.rxmode = {
		.mq_mode = ETH_MQ_RX_RSS,
		.max_rx_pkt_len = RTE_ETHER_MAX_LEN,
		.split_hdr_size = 0,
	},
	.txmode = {
		.mq_mode = ETH_MQ_TX_NONE,
	},
	.lpbk_mode = 1,  /* enable loopback */
	.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_IP,
};

static struct rte_eth_rxconf rx_conf = {
	.rx_free_thresh = 32,
};

static struct rte_eth_txconf tx_conf = {
	.tx_free_thresh = 32, /* Use PMD default values */
	.tx_rs_thresh = 32, /* Use PMD default values */
};

static uint64_t link_mbps;

static void
check_all_ports_link_status(uint16_t port_num, uint32_t port_mask)
{
#define CHECK_INTERVAL 100 /* 100ms */
#define MAX_CHECK_TIME 30 /* 3s (30 * 100ms) in total */
	uint8_t count, all_ports_up, print_flag = 0;
	struct rte_eth_link link;
	uint16_t portid;

	printf("Checking link statuses...\n");
	fflush(stdout);
	for (count = 0; count <= MAX_CHECK_TIME; count++) {
		all_ports_up = 1;
		for (portid = 0; portid < port_num; portid++) {
			if ((port_mask & (1 << portid)) == 0)
				continue;
			memset(&link, 0, sizeof(link));
			rte_eth_link_get_nowait(portid, &link);
			/* print link status if flag set */
			if (print_flag == 1) {
				if (link.link_status) {
					printf(
					"Port%d Link Up. Speed %u Mbps - %s\n",
						portid, link.link_speed,
				(link.link_duplex == ETH_LINK_FULL_DUPLEX) ?
					("full-duplex") : ("half-duplex\n"));
					if (link_mbps == 0)
						link_mbps = link.link_speed;
				} else
					printf("Port %d Link Down\n", portid);
				continue;
			}
			/* clear all_ports_up flag if any link down */
			if (link.link_status == ETH_LINK_DOWN) {
				all_ports_up = 0;
				break;
			}
		}
		/* after finally printing all link status, get out */
		if (print_flag == 1)
			break;

		if (all_ports_up == 0) {
			fflush(stdout);
			rte_delay_ms(CHECK_INTERVAL);
		}

		/* set the print_flag if all ports up or timeout */
		if (all_ports_up == 1 || count == (MAX_CHECK_TIME - 1))
			print_flag = 1;
	}
}

static inline void
copy_buf_to_pkt(void *buf, uint32_t len, struct rte_mbuf *pkt, uint32_t offset)
{
	rte_memcpy(rte_pktmbuf_mtod_offset(pkt, char *, offset), buf,
		   (size_t) len);
}

static int
init_traffic(struct rte_mempool *mp,
	     struct rte_mbuf **pkts_burst, uint32_t burst_size)
{
	static uint8_t src_mac[] = { 0x00, 0xFF, 0xAA, 0xFF, 0xAA, 0xFF };
	static uint8_t dst_mac[] = { 0x00, 0xAA, 0xFF, 0xAA, 0xFF, 0xAA };
	struct rte_ether_hdr pkt_eth_hdr;
	struct rte_ipv4_hdr pkt_ipv4_hdr;
	struct rte_udp_hdr pkt_udp_hdr;
	struct rte_mbuf *pkt;
	size_t eth_hdr_size;
	uint32_t nb_pkt;

	initialize_eth_header(&pkt_eth_hdr,
		(struct rte_ether_addr *)src_mac,
		(struct rte_ether_addr *)dst_mac, RTE_ETHER_TYPE_IPV4, 0, 0);

	eth_hdr_size = sizeof(struct rte_ether_hdr);

	initialize_udp_header(&pkt_udp_hdr, 0, 0, 18);

	for (nb_pkt = 0; nb_pkt < burst_size; nb_pkt++) {
		pkt = rte_pktmbuf_alloc(mp);
		if (pkt == NULL)
			break;

		pkt->data_len = PACKET_BURST_GEN_PKT_LEN;

		copy_buf_to_pkt(&pkt_eth_hdr, eth_hdr_size, pkt, 0);

		initialize_ipv4_header(&pkt_ipv4_hdr,
				       IPV4_ADDR(10, 0, 0, 1) + nb_pkt,
				       IPV4_ADDR(10, 0, 0, 2), 26);

		copy_buf_to_pkt(&pkt_ipv4_hdr, sizeof(struct rte_ipv4_hdr),
				pkt, eth_hdr_size);
		copy_buf_to_pkt(&pkt_udp_hdr, sizeof(struct rte_udp_hdr), pkt,
				eth_hdr_size + sizeof(struct rte_ipv4_hdr));

		pkt->pkt_len = PACKET_BURST_GEN_PKT_LEN;
		pkt->l2_len = eth_hdr_size;
		pkt->l3_len = sizeof(struct rte_ipv4_hdr);

		pkts_burst[nb_pkt] = pkt;
	}

	return 0;
}

struct rte_mbuf **tx_burst;

static int
start_hash_index_verify(int portid)
{
	uint64_t end_cycles = rte_get_timer_hz() * 5; /* 5 Sec */
	struct rte_mbuf *rx_burst[MAX_PKT_BURST];
	uint32_t hash, hash_idx, count = 0, rxq;
	uint32_t nb_rx = 0, nb_tx = 0;
	int idx = 0, rc, mismatch = 0;
	int num = MAX_TRAFFIC_BURST;
	uint64_t start_cycles;

	printf("inject %d packet to port %d\n", num, portid);
	while (num) {
		nb_tx = RTE_MIN(MAX_PKT_BURST, num);
		nb_tx = rte_eth_tx_burst(portid, 0,
					&tx_burst[idx], nb_tx);
		num -= nb_tx;
		idx += nb_tx;
	}

	printf("Total packets inject to port = %u\n", idx);

	start_cycles = rte_get_timer_cycles();

	while (count < MAX_TRAFFIC_BURST) {
		for (rxq = 0 ; rxq < MAX_TEST_QUEUES_PER_PORT; rxq++) {
			nb_rx = rte_eth_rx_burst(portid, rxq, rx_burst, 1);
			if (nb_rx) {
				hash = rx_burst[0]->hash.rss;
				rc = rte_eth_dev_rss_hash_index_get(portid,
								    hash,
								    &hash_idx);
				if (rc < 0)
					hash_idx  = hash % DEF_RETA_SIZE;

				if (rxq != reta_conf.reta[hash_idx])
					mismatch++;

				rte_pktmbuf_free(rx_burst[0]);
				count += nb_rx;
			}
		}
		if (rte_get_timer_cycles() - start_cycles > end_cycles)
			break;
	}

	printf("Total packets received = %u\n", count);

	if (mismatch) {
		printf("hash index mismatch in %d pkts\n", mismatch);
		return -1;
	}

	printf("Hash index verified on %u pkts\n", count);

	return 0;
}

static int
test_hash_index(void)
{
	uint16_t nb_rx_queue = MAX_TEST_QUEUES_PER_PORT;
	uint16_t nb_tx_queue = MAX_TEST_QUEUES_PER_PORT;
	uint16_t reta_size = RTE_RETA_GROUP_SIZE;
	uint16_t nb_rxd = MAX_TRAFFIC_BURST;
	uint16_t nb_txd = MAX_TRAFFIC_BURST;
	struct rte_eth_dev_info dev_info;
	uint16_t portid = 0;
	int socketid = -1;
	uint16_t nb_ports;
	int ret = 0;
	uint16_t i;

	printf("Start hash index verify test.\n");

	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports < NB_ETHPORTS_USED) {
		printf("At least %u port(s) used for the test\n",
		       NB_ETHPORTS_USED);
		return -1;
	}

	nb_ports = NB_ETHPORTS_USED;

	mbufpool = rte_pktmbuf_pool_create("pkt mempool", NB_MBUF,
					   MEMPOOL_CACHE_SIZE, 0,
					   RTE_MBUF_DEFAULT_BUF_SIZE, 0);
	if (mbufpool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot alloc mbuf pool\n");

	rte_eth_dev_info_get(portid, &dev_info);

	if (nb_rx_queue > dev_info.max_rx_queues)
		nb_rx_queue = dev_info.max_rx_queues;

	if (nb_tx_queue > dev_info.max_tx_queues)
		nb_tx_queue = dev_info.max_tx_queues;

	if (reta_size > dev_info.reta_size)
		reta_size = dev_info.reta_size;

	/* port configure */
	ret = rte_eth_dev_configure(portid, nb_rx_queue,
				    nb_tx_queue, &port_conf);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
			"Cannot configure device: err=%d, port=%d\n",
			 ret, portid);

	for (i = 0; i < nb_tx_queue; i++) {
		/* tx queue setup */
		ret = rte_eth_tx_queue_setup(portid, i, nb_txd,
					     socketid, &tx_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				"rte_eth_tx_queue_setup: err=%d, "
				"port=%d\n", ret, portid);
	}

	for (i = 0; i < nb_rx_queue; i++) {
		/* rx queue steup */
		ret = rte_eth_rx_queue_setup(portid, i, nb_rxd,
						socketid, &rx_conf, mbufpool);
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup: err=%d,"
				 "port=%d\n", ret, portid);
	}

	for (i = 0; i < reta_size; i++) {
		reta_conf.reta[i] = i % nb_rx_queue;
		reta_conf.mask |= (1ULL << i);
	}
	rte_eth_dev_rss_reta_update(portid, &reta_conf, reta_size);

	/* Start device */
	ret = rte_eth_dev_start(portid);
	if (ret < 0)
		rte_exit(EXIT_FAILURE,
			"rte_eth_dev_start: err=%d, port=%d\n",
			ret, portid);

	/* always eanble promiscuous */
	rte_eth_promiscuous_enable(portid);

	check_all_ports_link_status(1, 1);

	if (tx_burst == NULL) {
		tx_burst = (struct rte_mbuf **)
			rte_calloc_socket("tx_buff",
					  MAX_TRAFFIC_BURST * nb_ports,
					  sizeof(void *),
					  RTE_CACHE_LINE_SIZE, socketid);
		if (!tx_burst)
			return -1;
	}

	init_traffic(mbufpool,
		     tx_burst, MAX_TRAFFIC_BURST * nb_ports);

	printf("Generate %d packets @socket %d\n",
	       MAX_TRAFFIC_BURST * nb_ports, socketid);

	ret = start_hash_index_verify(portid);

	/* port tear down */
	rte_eth_dev_stop(portid);
	rte_eth_dev_close(portid);

	if (tx_burst)
		rte_free(tx_burst);

	if (mbufpool)
		rte_mempool_free(mbufpool);

	return ret;
}

REGISTER_TEST_COMMAND(hash_index_verify_autotest, test_hash_index);
