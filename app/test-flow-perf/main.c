/* SPDX-License-Identifier: BSD-3-Clause
 *
 * This file contain the application main file
 * This application provides the user the ability to test the
 * insertion rate for specific rte_flow rule under stress state ~4M rule/
 *
 * Then it will also provide packet per second measurement after installing
 * all rules, the user may send traffic to test the PPS that match the rules
 * after all rules are installed, to check performance or functionality after
 * the stress.
 *
 * The flows insertion will go for all ports first, then it will print the
 * results, after that the application will go into forwarding packets mode
 * it will start receiving traffic if any and then forwarding it back and
 * gives packet per second measurement.
 *
 * Copyright 2020 Mellanox Technologies, Ltd
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <setjmp.h>
#include <stdarg.h>
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <assert.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>


#include <rte_eal.h>
#include <rte_common.h>
#include <rte_malloc.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_net.h>
#include <rte_flow.h>
#include <rte_cycles.h>
#include <rte_memory.h>

#include "user_parameters.h"

static uint32_t nb_lcores;
static struct rte_mempool *mbuf_mp;

static void usage(char *progname)
{
	printf("\nusage: %s", progname);
}

static void
args_parse(int argc, char **argv)
{
	char **argvopt;
	int opt;
	int opt_idx;
	static struct option lgopts[] = {
		/* Control */
		{ "help",                       0, 0, 0 },
	};

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, "",
				lgopts, &opt_idx)) != EOF) {
		switch (opt) {
		case 0:
			if (!strcmp(lgopts[opt_idx].name, "help")) {
				usage(argv[0]);
				rte_exit(EXIT_SUCCESS, "Displayed help\n");
			}
			break;
		default:
			usage(argv[0]);
			printf("Invalid option: %s\n", argv[optind]);
			rte_exit(EXIT_SUCCESS, "Invalid option\n");
			break;
		}
	}
}

static void
init_port(void)
{
	int ret;
	uint16_t i, j;
	uint16_t port_id;
	uint16_t nr_ports = rte_eth_dev_count_avail();
	struct rte_eth_hairpin_conf hairpin_conf = {
			.peer_count = 1,
	};
	struct rte_eth_conf port_conf = {
		.rxmode = {
			.split_hdr_size = 0,
		},
		.rx_adv_conf = {
			.rss_conf.rss_hf =
					ETH_RSS_IP  |
					ETH_RSS_UDP |
					ETH_RSS_TCP,
		}
	};
	struct rte_eth_txconf txq_conf;
	struct rte_eth_rxconf rxq_conf;
	struct rte_eth_dev_info dev_info;

	if (nr_ports == 0)
		rte_exit(EXIT_FAILURE, "Error: no port detected\n");
	mbuf_mp = rte_pktmbuf_pool_create("mbuf_pool",
					TOTAL_MBUF_NUM, MBUF_CACHE_SIZE,
					0, MBUF_SIZE,
					rte_socket_id());

	if (mbuf_mp == NULL)
		rte_exit(EXIT_FAILURE, "Error: can't init mbuf pool\n");

	for (port_id = 0; port_id < nr_ports; port_id++) {
		ret = rte_eth_dev_info_get(port_id, &dev_info);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
					"Error during getting device (port %u) info: %s\n",
					port_id, strerror(-ret));

		port_conf.txmode.offloads &= dev_info.tx_offload_capa;
		printf(":: initializing port: %d\n", port_id);
		ret = rte_eth_dev_configure(port_id, RXQs + HAIRPIN_QUEUES,
				TXQs + HAIRPIN_QUEUES, &port_conf);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
					":: cannot configure device: err=%d, port=%u\n",
					ret, port_id);

		rxq_conf = dev_info.default_rxconf;
		rxq_conf.offloads = port_conf.rxmode.offloads;
		for (i = 0; i < RXQs; i++) {
			ret = rte_eth_rx_queue_setup(port_id, i, NR_RXD,
						rte_eth_dev_socket_id(port_id),
						&rxq_conf,
						mbuf_mp);
			if (ret < 0)
				rte_exit(EXIT_FAILURE,
						":: Rx queue setup failed: err=%d, port=%u\n",
						ret, port_id);
		}

		txq_conf = dev_info.default_txconf;
		txq_conf.offloads = port_conf.txmode.offloads;

		for (i = 0; i < TXQs; i++) {
			ret = rte_eth_tx_queue_setup(port_id, i, NR_TXD,
						rte_eth_dev_socket_id(port_id),
						&txq_conf);
			if (ret < 0)
				rte_exit(EXIT_FAILURE,
						":: Tx queue setup failed: err=%d, port=%u\n",
						ret, port_id);
		}

		ret = rte_eth_promiscuous_enable(port_id);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
					":: promiscuous mode enable failed: err=%s, port=%u\n",
					rte_strerror(-ret), port_id);

		for (i = RXQs, j = 0; i < RXQs + HAIRPIN_QUEUES; i++, j++) {
			hairpin_conf.peers[0].port = port_id;
			hairpin_conf.peers[0].queue = j + TXQs;
			ret = rte_eth_rx_hairpin_queue_setup(port_id, i,
							NR_RXD, &hairpin_conf);
			if (ret != 0)
				rte_exit(EXIT_FAILURE,
					":: Hairpin rx queue setup failed: err=%d, port=%u\n",
					ret, port_id);
		}

		for (i = TXQs, j = 0; i < TXQs + HAIRPIN_QUEUES; i++, j++) {
			hairpin_conf.peers[0].port = port_id;
			hairpin_conf.peers[0].queue = j + RXQs;
			ret = rte_eth_tx_hairpin_queue_setup(port_id, i,
							NR_TXD, &hairpin_conf);
			if (ret != 0)
				rte_exit(EXIT_FAILURE,
					":: Hairpin tx queue setup failed: err=%d, port=%u\n",
					ret, port_id);
		}

		ret = rte_eth_dev_start(port_id);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				"rte_eth_dev_start:err=%d, port=%u\n",
				ret, port_id);

		printf(":: initializing port: %d done\n", port_id);
	}
}

int
main(int argc, char **argv)
{
	uint16_t lcore_id;
	uint16_t port;
	uint16_t nr_ports;
	int ret;
	struct rte_flow_error error;

	nr_ports = rte_eth_dev_count_avail();
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "EAL init failed\n");

	argc -= ret;
	argv += ret;

	if (argc > 1)
		args_parse(argc, argv);

	init_port();

	nb_lcores = rte_lcore_count();

	if (nb_lcores <= 1)
		rte_exit(EXIT_FAILURE, "This app needs at least two cores\n");

	RTE_LCORE_FOREACH_SLAVE(lcore_id)

	if (rte_eal_wait_lcore(lcore_id) < 0)
		break;

	for (port = 0; port < nr_ports; port++) {
		rte_flow_flush(port, &error);
		rte_eth_dev_stop(port);
		rte_eth_dev_close(port);
	}
	return 0;
}
