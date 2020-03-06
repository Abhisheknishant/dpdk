/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Marvell International Ltd.
 */

#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <sys/types.h>
#include <string.h>
#include <sys/queue.h>
#include <stdarg.h>
#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdbool.h>

#include <rte_byteorder.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_string_fns.h>
#include <rte_cpuflags.h>
#include <rte_if_proxy.h>

#include <cmdline_parse.h>
#include <cmdline_parse_etheraddr.h>

#include "l3fwd.h"

/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024

#define MAX_TX_QUEUE_PER_PORT RTE_MAX_ETHPORTS
#define MAX_RX_QUEUE_PER_PORT 128

#define MAX_LCORE_PARAMS 1024

/* Static global variables used within this file. */
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;

/**< Ports set in promiscuous mode off by default. */
static int promiscuous_on;

/* Global variables. */

static int parse_ptype; /**< Parse packet type using rx callback, and */
			/**< disabled by default */

volatile bool force_quit;

/* mask of enabled/active ports */
uint32_t enabled_port_mask;
uint32_t active_port_mask;

struct lcore_conf lcore_conf[RTE_MAX_LCORE];

struct lcore_params {
	uint16_t port_id;
	uint8_t queue_id;
	uint8_t lcore_id;
} __rte_cache_aligned;

static struct lcore_params lcore_params[MAX_LCORE_PARAMS];
static struct lcore_params lcore_params_default[] = {
	{0, 0, 2},
	{0, 1, 2},
	{0, 2, 2},
	{1, 0, 2},
	{1, 1, 2},
	{1, 2, 2},
	{2, 0, 2},
	{3, 0, 3},
	{3, 1, 3},
};

static uint16_t nb_lcore_params;

static struct rte_eth_conf port_conf = {
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

static struct rte_mempool *pktmbuf_pool;

static int
check_lcore_params(void)
{
	uint8_t queue, lcore;
	uint16_t i, port_id;
	int socketid;

	for (i = 0; i < nb_lcore_params; ++i) {
		queue = lcore_params[i].queue_id;
		if (queue >= MAX_RX_QUEUE_PER_PORT) {
			RTE_LOG(ERR, L3FWD, "Invalid queue number: %hhu\n",
				queue);
			return -1;
		}
		lcore = lcore_params[i].lcore_id;
		if (!rte_lcore_is_enabled(lcore)) {
			RTE_LOG(ERR, L3FWD, "lcore %hhu is not enabled "
					    "in lcore mask\n", lcore);
			return -1;
		}
		port_id = lcore_params[i].port_id;
		if ((enabled_port_mask & (1 << port_id)) == 0) {
			RTE_LOG(ERR, L3FWD, "port %u is not enabled "
					    "in port mask\n", port_id);
			return -1;
		}
		if (!rte_eth_dev_is_valid_port(port_id)) {
			RTE_LOG(ERR, L3FWD, "port %u is not present "
					    "on the board\n", port_id);
			return -1;
		}
		if ((socketid = rte_lcore_to_socket_id(lcore)) != 0) {
			RTE_LOG(WARNING, L3FWD, "lcore %hhu is on socket %d with "
						"numa off\n", lcore, socketid);
		}
	}
	return 0;
}

static int
add_proxies(void)
{
	uint16_t i, p, port_id, proxy_id;

	for (i = 0, p = nb_lcore_params; i < nb_lcore_params; ++i) {
		if (p >= RTE_DIM(lcore_params)) {
			RTE_LOG(ERR, L3FWD, "Not enough room in lcore_params "
					    "to add proxy\n");
			return -1;
		}
		port_id = lcore_params[i].port_id;
		if (rte_ifpx_proxy_get(port_id) != RTE_MAX_ETHPORTS)
			continue;

		proxy_id = rte_ifpx_proxy_create(RTE_IFPX_DEFAULT);
		if (proxy_id == RTE_MAX_ETHPORTS) {
			RTE_LOG(ERR, L3FWD, "Failed to crate proxy\n");
			return -1;
		}
		rte_ifpx_port_bind(port_id, proxy_id);
		/* mark proxy as enabled - the corresponding port is, since we
		 * are after checking of lcore_params
		 */
		enabled_port_mask |= 1 << proxy_id;
		lcore_params[p].port_id = proxy_id;
		lcore_params[p].lcore_id = lcore_params[i].lcore_id;
		lcore_params[p].queue_id = lcore_params[i].queue_id;
		++p;
	}

	nb_lcore_params = p;
	return 0;
}

static uint8_t
get_port_n_rx_queues(const uint16_t port)
{
	int queue = -1;
	uint16_t i;

	for (i = 0; i < nb_lcore_params; ++i) {
		if (lcore_params[i].port_id == port) {
			if (lcore_params[i].queue_id == queue+1)
				queue = lcore_params[i].queue_id;
			else
				rte_exit(EXIT_FAILURE, "queue ids of the port %d must be"
						" in sequence and must start with 0\n",
						lcore_params[i].port_id);
		}
	}
	return (uint8_t)(++queue);
}

static int
init_lcore_rx_queues(void)
{
	uint16_t i, p, nb_rx_queue;
	uint8_t lcore;
	struct lcore_rx_queue *rq;

	for (i = 0; i < nb_lcore_params; ++i) {
		lcore = lcore_params[i].lcore_id;
		nb_rx_queue = lcore_conf[lcore].n_rx_queue;
		if (nb_rx_queue >= MAX_RX_QUEUE_PER_LCORE) {
			RTE_LOG(ERR, L3FWD, "too many queues (%u) for lcore: %u\n",
				(unsigned)nb_rx_queue + 1, (unsigned)lcore);
			return -1;
		}
		rq = &lcore_conf[lcore].rx_queue_list[nb_rx_queue];
		rq->port_id = lcore_params[i].port_id;
		rq->queue_id = lcore_params[i].queue_id;
		if (rte_ifpx_is_proxy(lcore_params[i].port_id)) {
			if (rte_ifpx_port_get(lcore_params[i].port_id, &p, 1) > 0)
				rq->dst_port = p;
			else
				RTE_LOG(WARNING, L3FWD,
					"Found proxy that has no port bound\n");
		} else
			rq->dst_port = RTE_MAX_ETHPORTS;
		lcore_conf[lcore].n_rx_queue++;
	}
	return 0;
}

/* display usage */
static void
print_usage(const char *prgname)
{
	fprintf(stderr, "%s [EAL options] --"
		" -p PORTMASK"
		" [-P]"
		" --config (port,queue,lcore)[,(port,queue,lcore)]"
		" [--ipv6]"
		" [--parse-ptype]"

		"  -p PORTMASK: Hexadecimal bitmask of ports to configure\n"
		"  -P : Enable promiscuous mode\n"
		"  --config (port,queue,lcore): Rx queue configuration\n"
		"  --ipv6: Set if running ipv6 packets\n"
		"  --parse-ptype: Set to use software to analyze packet type\n",
		prgname);
}

static int
parse_portmask(const char *portmask)
{
	char *end = NULL;
	unsigned long pm;

	/* parse hexadecimal string */
	pm = strtoul(portmask, &end, 16);
	if ((portmask[0] == '\0') || (end == NULL) || (*end != '\0'))
		return -1;

	if (pm == 0)
		return -1;

	return pm;
}

static int
parse_config(const char *q_arg)
{
	char s[256];
	const char *p, *p0 = q_arg;
	char *end;
	enum fieldnames {
		FLD_PORT = 0,
		FLD_QUEUE,
		FLD_LCORE,
		_NUM_FLD
	};
	unsigned long int_fld[_NUM_FLD];
	char *str_fld[_NUM_FLD];
	int i;
	unsigned size;

	nb_lcore_params = 0;

	while ((p = strchr(p0,'(')) != NULL) {
		++p;
		if((p0 = strchr(p,')')) == NULL)
			return -1;

		size = p0 - p;
		if(size >= sizeof(s))
			return -1;

		snprintf(s, sizeof(s), "%.*s", size, p);
		if (rte_strsplit(s, sizeof(s), str_fld, _NUM_FLD, ',') != _NUM_FLD)
			return -1;
		for (i = 0; i < _NUM_FLD; i++){
			errno = 0;
			int_fld[i] = strtoul(str_fld[i], &end, 0);
			if (errno != 0 || end == str_fld[i] || int_fld[i] > 255)
				return -1;
		}
		if (nb_lcore_params >= MAX_LCORE_PARAMS) {
			RTE_LOG(ERR, L3FWD, "exceeded max number of lcore "
					    "params: %hu\n", nb_lcore_params);
			return -1;
		}
		lcore_params[nb_lcore_params].port_id =
			(uint8_t)int_fld[FLD_PORT];
		lcore_params[nb_lcore_params].queue_id =
			(uint8_t)int_fld[FLD_QUEUE];
		lcore_params[nb_lcore_params].lcore_id =
			(uint8_t)int_fld[FLD_LCORE];
		++nb_lcore_params;
	}
	return 0;
}

#define MAX_JUMBO_PKT_LEN  9600
#define MEMPOOL_CACHE_SIZE 256

static const char short_options[] =
	"p:"  /* portmask */
	"P"   /* promiscuous */
	"L"   /* enable long prefix match */
	"E"   /* enable exact match */
	;

#define CMD_LINE_OPT_CONFIG "config"
#define CMD_LINE_OPT_IPV6 "ipv6"
#define CMD_LINE_OPT_PARSE_PTYPE "parse-ptype"
enum {
	/* long options mapped to a short option */

	/* first long only option value must be >= 256, so that we won't
	 * conflict with short options */
	CMD_LINE_OPT_MIN_NUM = 256,
	CMD_LINE_OPT_CONFIG_NUM,
	CMD_LINE_OPT_PARSE_PTYPE_NUM,
};

static const struct option lgopts[] = {
	{CMD_LINE_OPT_CONFIG, 1, 0, CMD_LINE_OPT_CONFIG_NUM},
	{CMD_LINE_OPT_PARSE_PTYPE, 0, 0, CMD_LINE_OPT_PARSE_PTYPE_NUM},
	{NULL, 0, 0, 0}
};

/*
 * This expression is used to calculate the number of mbufs needed
 * depending on user input, taking  into account memory for rx and
 * tx hardware rings, cache per lcore and mtable per port per lcore.
 * RTE_MAX is used to ensure that NB_MBUF never goes below a minimum
 * value of 8192
 */
#define NB_MBUF(nports) RTE_MAX(	\
	(nports*nb_rx_queue*nb_rxd +		\
	nports*nb_lcores*MAX_PKT_BURST +	\
	nports*n_tx_queue*nb_txd +		\
	nb_lcores*MEMPOOL_CACHE_SIZE),		\
	(unsigned)8192)

/* Parse the argument given in the command line of the application */
static int
parse_args(int argc, char **argv)
{
	int opt, ret;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];

	argvopt = argv;

	/* Error or normal output strings. */
	while ((opt = getopt_long(argc, argvopt, short_options,
				lgopts, &option_index)) != EOF) {

		switch (opt) {
		/* portmask */
		case 'p':
			enabled_port_mask = parse_portmask(optarg);
			if (enabled_port_mask == 0) {
				RTE_LOG(ERR, L3FWD, "Invalid portmask\n");
				print_usage(prgname);
				return -1;
			}
			break;

		case 'P':
			promiscuous_on = 1;
			break;

		/* long options */
		case CMD_LINE_OPT_CONFIG_NUM:
			ret = parse_config(optarg);
			if (ret) {
				RTE_LOG(ERR, L3FWD, "Invalid config\n");
				print_usage(prgname);
				return -1;
			}
			break;

		case CMD_LINE_OPT_PARSE_PTYPE_NUM:
			RTE_LOG(INFO, L3FWD, "soft parse-ptype is enabled\n");
			parse_ptype = 1;
			break;

		default:
			print_usage(prgname);
			return -1;
		}
	}

	if (nb_lcore_params == 0) {
		memcpy(lcore_params, lcore_params_default,
		       sizeof(lcore_params_default));
		nb_lcore_params = RTE_DIM(lcore_params_default);
	}

	if (optind >= 0)
		argv[optind-1] = prgname;

	ret = optind-1;
	optind = 1; /* reset getopt lib */
	return ret;
}

static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		RTE_LOG(NOTICE, L3FWD, "\n\n"
		        "Signal %d received, preparing to exit...\n", signum);
		force_quit = true;
	}
}

static int
prepare_ptype_parser(uint16_t portid, uint16_t queueid)
{
	if (parse_ptype) {
		RTE_LOG(INFO, L3FWD, "Port %d: softly parse packet type info\n",
			portid);
		if (rte_eth_add_rx_callback(portid, queueid,
					    lpm_cb_parse_ptype,
					    NULL))
			return 1;

		RTE_LOG(ERR, L3FWD, "Failed to add rx callback: port=%d\n",
			portid);
		return 0;
	}

	if (lpm_check_ptype(portid))
		return 1;

	RTE_LOG(ERR, L3FWD, "port %d cannot parse packet type, please add --%s\n",
	       portid, CMD_LINE_OPT_PARSE_PTYPE);
	return 0;
}

int
main(int argc, char **argv)
{
	struct lcore_conf *lconf;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf *txconf;
	int ret;
	unsigned nb_ports;
	uint32_t nb_mbufs;
	uint16_t queueid, portid;
	unsigned lcore_id;
	uint32_t nb_tx_queue, nb_lcores;
	uint8_t nb_rx_queue, queue;

	/* init EAL */
	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");
	argc -= ret;
	argv += ret;

	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);

	/* parse application arguments (after the EAL ones) */
	ret = parse_args(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Invalid L3FWD parameters\n");

	if (check_lcore_params() < 0)
		rte_exit(EXIT_FAILURE, "check_lcore_params failed\n");

	if (add_proxies() < 0)
		rte_exit(EXIT_FAILURE, "add_proxies failed\n");

	ret = init_lcore_rx_queues();
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "init_lcore_rx_queues failed\n");

	nb_ports = rte_eth_dev_count_avail();

	nb_lcores = rte_lcore_count();

	/* Initial number of mbufs in pool - the amount required for hardware
	 * rx/tx rings will be added during configuration of ports.
	 */
	nb_mbufs = nb_ports * nb_lcores * MAX_PKT_BURST + /* mbuf tables */
			nb_lcores * MEMPOOL_CACHE_SIZE;  /* mempool per lcore cache */

	/* Init the lookup structures. */
	setup_lpm();

	/* initialize all ports (including proxies) */
	RTE_ETH_FOREACH_DEV(portid) {
		struct rte_eth_conf local_port_conf = port_conf;

		/* skip ports that are not enabled */
		if ((enabled_port_mask & (1 << portid)) == 0) {
			RTE_LOG(INFO, L3FWD, "Skipping disabled port %d\n",
				portid);
			continue;
		}

		/* init port */
		RTE_LOG(INFO, L3FWD, "Initializing port %d ...\n", portid);

		nb_rx_queue = get_port_n_rx_queues(portid);
		nb_tx_queue = nb_lcores;

		ret = rte_eth_dev_info_get(portid, &dev_info);
		if (ret != 0)
			rte_exit(EXIT_FAILURE,
				"Error during getting device (port %u) info: %s\n",
				portid, strerror(-ret));
		if (nb_rx_queue > dev_info.max_rx_queues ||
		    nb_tx_queue > dev_info.max_tx_queues)
			rte_exit(EXIT_FAILURE,
				"Port %d cannot configure enough queues\n",
				portid);

		RTE_LOG(INFO, L3FWD, "Creating queues: nb_rxq=%d nb_txq=%u...\n",
			nb_rx_queue, nb_tx_queue);

		if (dev_info.tx_offload_capa & DEV_TX_OFFLOAD_MBUF_FAST_FREE)
			local_port_conf.txmode.offloads |=
				DEV_TX_OFFLOAD_MBUF_FAST_FREE;

		local_port_conf.rx_adv_conf.rss_conf.rss_hf &=
			dev_info.flow_type_rss_offloads;
		if (local_port_conf.rx_adv_conf.rss_conf.rss_hf !=
				port_conf.rx_adv_conf.rss_conf.rss_hf) {
			RTE_LOG(INFO, L3FWD,
				"Port %u modified RSS hash function based on hardware support,"
				"requested:%#"PRIx64" configured:%#"PRIx64"\n",
				portid, port_conf.rx_adv_conf.rss_conf.rss_hf,
				local_port_conf.rx_adv_conf.rss_conf.rss_hf);
		}

		ret = rte_eth_dev_configure(portid, nb_rx_queue,
					(uint16_t)nb_tx_queue, &local_port_conf);
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

		nb_mbufs += nb_rx_queue * nb_rxd + nb_tx_queue * nb_txd;
		/* init one TX queue per couple (lcore,port) */
		queueid = 0;
		for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
			if (rte_lcore_is_enabled(lcore_id) == 0)
				continue;

			RTE_LOG(INFO, L3FWD, "\ttxq=%u,%d\n", lcore_id, queueid);

			txconf = &dev_info.default_txconf;
			txconf->offloads = local_port_conf.txmode.offloads;
			ret = rte_eth_tx_queue_setup(portid, queueid, nb_txd,
						     SOCKET_ID_ANY, txconf);
			if (ret < 0)
				rte_exit(EXIT_FAILURE,
					"rte_eth_tx_queue_setup: err=%d, "
					"port=%d\n", ret, portid);

			lconf = &lcore_conf[lcore_id];
			lconf->tx_queue_id[portid] = queueid;
			queueid++;

			lconf->tx_port_id[lconf->n_tx_port] = portid;
			lconf->n_tx_port++;
		}
		RTE_LOG(INFO, L3FWD, "\n");
	}

	/* Init pkt pool. */
	pktmbuf_pool = rte_pktmbuf_pool_create("mbuf_pool",
			       rte_align32prevpow2(nb_mbufs), MEMPOOL_CACHE_SIZE,
			       0, RTE_MBUF_DEFAULT_BUF_SIZE, SOCKET_ID_ANY);
	if (pktmbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot init mbuf pool\n");

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;
		lconf = &lcore_conf[lcore_id];
		RTE_LOG(INFO, L3FWD, "Initializing rx queues on lcore %u ...\n",
			lcore_id );
		/* init RX queues */
		for(queue = 0; queue < lconf->n_rx_queue; ++queue) {
			struct rte_eth_rxconf rxq_conf;

			portid = lconf->rx_queue_list[queue].port_id;
			queueid = lconf->rx_queue_list[queue].queue_id;

			RTE_LOG(INFO, L3FWD, "\trxq=%d,%d\n", portid, queueid);

			ret = rte_eth_dev_info_get(portid, &dev_info);
			if (ret != 0)
				rte_exit(EXIT_FAILURE,
					"Error during getting device (port %u) info: %s\n",
					portid, strerror(-ret));

			rxq_conf = dev_info.default_rxconf;
			rxq_conf.offloads = port_conf.rxmode.offloads;
			ret = rte_eth_rx_queue_setup(portid, queueid,
			                             nb_rxd, SOCKET_ID_ANY,
			                             &rxq_conf,
			                             pktmbuf_pool);
			if (ret < 0)
				rte_exit(EXIT_FAILURE,
				"rte_eth_rx_queue_setup: err=%d, port=%d\n",
				ret, portid);
		}
	}

	RTE_LOG(INFO, L3FWD, "\n");

	/* start ports */
	RTE_ETH_FOREACH_DEV(portid) {
		if ((enabled_port_mask & (1 << portid)) == 0) {
			continue;
		}
		/* Start device */
		ret = rte_eth_dev_start(portid);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
				"rte_eth_dev_start: err=%d, port=%d\n",
				ret, portid);

		/*
		 * If enabled, put device in promiscuous mode.
		 * This allows IO forwarding mode to forward packets
		 * to itself through 2 cross-connected  ports of the
		 * target machine.
		 */
		if (promiscuous_on) {
			ret = rte_eth_promiscuous_enable(portid);
			if (ret != 0)
				rte_exit(EXIT_FAILURE,
					"rte_eth_promiscuous_enable: err=%s, port=%u\n",
					rte_strerror(-ret), portid);
		}
	}
	/* we've managed to start all enabled ports so active == enabled */
	active_port_mask = enabled_port_mask;

	RTE_LOG(INFO, L3FWD, "\n");

	for (lcore_id = 0; lcore_id < RTE_MAX_LCORE; lcore_id++) {
		if (rte_lcore_is_enabled(lcore_id) == 0)
			continue;
		lconf = &lcore_conf[lcore_id];
		for (queue = 0; queue < lconf->n_rx_queue; ++queue) {
			portid = lconf->rx_queue_list[queue].port_id;
			queueid = lconf->rx_queue_list[queue].queue_id;
			if (prepare_ptype_parser(portid, queueid) == 0)
				rte_exit(EXIT_FAILURE, "ptype check fails\n");
		}
	}

	if (init_if_proxy() < 0)
		rte_exit(EXIT_FAILURE, "Failed to configure proxy lib\n");
	wait_for_config_done();

	ret = 0;
	/* launch per-lcore init on every lcore */
	rte_eal_mp_remote_launch(lpm_main_loop, NULL, CALL_MASTER);
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		if (rte_eal_wait_lcore(lcore_id) < 0) {
			ret = -1;
			break;
		}
	}

	/* stop ports */
	RTE_ETH_FOREACH_DEV(portid) {
		if ((enabled_port_mask & (1 << portid)) == 0)
			continue;
		RTE_LOG(INFO, L3FWD, "Closing port %d...", portid);
		rte_eth_dev_stop(portid);
		rte_eth_dev_close(portid);
		rte_log(RTE_LOG_INFO, RTE_LOGTYPE_L3FWD, " Done\n");
	}

	close_if_proxy();
	RTE_LOG(INFO, L3FWD, "Bye...\n");

	return ret;
}
