/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2019 Marvell International Ltd.
 */

#include <stdbool.h>
#include <getopt.h>

#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_ethdev.h>
#include <rte_eventdev.h>
#include <rte_event_eth_rx_adapter.h>
#include <rte_event_eth_tx_adapter.h>
#include <rte_lcore.h>
#include <rte_log.h>
#include <rte_spinlock.h>

#include "l2fwd_common.h"
#include "l2fwd_eventdev.h"

#define L2FWD_EVENT_SINGLE	0x1
#define L2FWD_EVENT_BURST	0x2
#define L2FWD_EVENT_TX_DIRECT	0x4
#define L2FWD_EVENT_TX_ENQ	0x8
#define L2FWD_EVENT_UPDT_MAC	0x10

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
	struct eventdev_resources *eventdev_rsrc = get_eventdev_rsrc();

	if (!strncmp(optarg, "poll", 4))
		eventdev_rsrc->enabled = false;
	else if (!strncmp(optarg, "eventdev", 8))
		eventdev_rsrc->enabled = true;
}

static void
parse_eventq_sync(const char *optarg)
{
	struct eventdev_resources *eventdev_rsrc = get_eventdev_rsrc();

	if (!strncmp(optarg, "ordered", 7))
		eventdev_rsrc->sync_mode = RTE_SCHED_TYPE_ORDERED;
	else if (!strncmp(optarg, "atomic", 6))
		eventdev_rsrc->sync_mode = RTE_SCHED_TYPE_ATOMIC;
}

static int
parse_eventdev_args(char **argv, int argc)
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
eth_dev_port_setup(uint16_t ethdev_count __rte_unused)
{
	struct eventdev_resources *eventdev_rsrc = get_eventdev_rsrc();
	static struct rte_eth_conf port_config = {
		.rxmode = {
			.mq_mode = ETH_MQ_RX_RSS,
			.max_rx_pkt_len = RTE_ETHER_MAX_LEN,
			.split_hdr_size = 0,
			.offloads = DEV_RX_OFFLOAD_CHECKSUM
		},
		.rx_adv_conf = {
			.rss_conf = {
				.rss_key = NULL,
				.rss_hf = ETH_RSS_IP,
			}
		},
		.txmode = {
			.mq_mode = ETH_MQ_TX_NONE,
		}
	};
	struct rte_eth_conf local_port_conf;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;
	struct rte_eth_rxconf rxconf;
	uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
	uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;
	uint16_t port_id;
	int32_t ret;

	/* initialize all ports */
	RTE_ETH_FOREACH_DEV(port_id) {
		local_port_conf = port_config;
		/* skip ports that are not enabled */
		if ((eventdev_rsrc->port_mask & (1 << port_id)) == 0) {
			printf("\nSkipping disabled port %d\n", port_id);
			continue;
		}

		/* init port */
		printf("Initializing port %d ... ", port_id);
		fflush(stdout);
		rte_eth_dev_info_get(port_id, &dev_info);
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
			       port_id,
			       port_config.rx_adv_conf.rss_conf.rss_hf,
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

		rte_eth_macaddr_get(port_id,
				    &eventdev_rsrc->ports_eth_addr[port_id]);
		print_ethaddr(" Address:",
			      &eventdev_rsrc->ports_eth_addr[port_id]);
		printf("\n");


		/* init one Rx queue per port */
		rxconf = dev_info.default_rxconf;
		rxconf.offloads = local_port_conf.rxmode.offloads;
		ret = rte_eth_rx_queue_setup(port_id, 0, nb_rxd, 0, &rxconf,
					     eventdev_rsrc->pkt_pool);
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

		rte_eth_promiscuous_enable(port_id);
	}
}

static void
eventdev_capability_setup(void)
{
	struct eventdev_resources *eventdev_rsrc = get_eventdev_rsrc();
	uint32_t caps = 0;
	uint16_t i;
	int ret;

	RTE_ETH_FOREACH_DEV(i) {
		ret = rte_event_eth_tx_adapter_caps_get(0, i, &caps);
		if (ret)
			rte_exit(EXIT_FAILURE,
				 "Invalid capability for Tx adptr port %d\n",
				 i);

		eventdev_rsrc->tx_mode_q |= !(caps &
				   RTE_EVENT_ETH_TX_ADAPTER_CAP_INTERNAL_PORT);
	}

	if (eventdev_rsrc->tx_mode_q)
		eventdev_set_generic_ops(&eventdev_rsrc->ops);
	else
		eventdev_set_internal_port_ops(&eventdev_rsrc->ops);
}

static __rte_noinline int
get_free_event_port(struct eventdev_resources *eventdev_rsrc)
{
	static int index;
	int port_id;

	rte_spinlock_lock(&eventdev_rsrc->evp.lock);
	if (index >= eventdev_rsrc->evp.nb_ports) {
		printf("No free event port is available\n");
		return -1;
	}

	port_id = eventdev_rsrc->evp.event_p_id[index];
	index++;
	rte_spinlock_unlock(&eventdev_rsrc->evp.lock);

	return port_id;
}

static __rte_always_inline void
l2fwd_event_updt_mac(struct rte_mbuf *m, const struct rte_ether_addr *dst_mac,
		     uint8_t dst_port)
{
	struct rte_ether_hdr *eth;
	void *tmp;

	eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

	/* 02:00:00:00:00:xx */
	tmp = &eth->d_addr.addr_bytes[0];
	*((uint64_t *)tmp) = 0x000000000002 + ((uint64_t)dst_port << 40);

	/* src addr */
	rte_ether_addr_copy(dst_mac, &eth->s_addr);
}

static __rte_always_inline void
l2fwd_event_loop_single(struct eventdev_resources *eventdev_rsrc,
		      const uint32_t flags)
{
	const uint8_t is_master = rte_get_master_lcore() == rte_lcore_id();
	const uint64_t timer_period = eventdev_rsrc->timer_period;
	uint64_t prev_tsc = 0, diff_tsc, cur_tsc, timer_tsc = 0;
	const int port_id = get_free_event_port(eventdev_rsrc);
	const uint8_t tx_q_id = eventdev_rsrc->evq.event_q_id[
					eventdev_rsrc->evq.nb_queues - 1];
	const uint8_t event_d_id = eventdev_rsrc->event_d_id;
	volatile bool *done = eventdev_rsrc->done;
	struct rte_mbuf *mbuf;
	uint16_t dst_port;
	struct rte_event ev;

	if (port_id < 0)
		return;

	printf("%s(): entering eventdev main loop on lcore %u\n", __func__,
		rte_lcore_id());

	while (!*done) {
		/* if timer is enabled */
		if (is_master && timer_period > 0) {
			cur_tsc = rte_rdtsc();
			diff_tsc = cur_tsc - prev_tsc;

			/* advance the timer */
			timer_tsc += diff_tsc;

			/* if timer has reached its timeout */
			if (unlikely(timer_tsc >= timer_period)) {
				print_stats();
				/* reset the timer */
				timer_tsc = 0;
			}
			prev_tsc = cur_tsc;
		}

		/* Read packet from eventdev */
		if (!rte_event_dequeue_burst(event_d_id, port_id, &ev, 1, 0))
			continue;


		mbuf = ev.mbuf;
		dst_port = eventdev_rsrc->dst_ports[mbuf->port];
		rte_prefetch0(rte_pktmbuf_mtod(mbuf, void *));

		if (timer_period > 0)
			__atomic_fetch_add(&eventdev_rsrc->stats[mbuf->port].rx,
					   1, __ATOMIC_RELAXED);

		mbuf->port = dst_port;
		if (flags & L2FWD_EVENT_UPDT_MAC)
			l2fwd_event_updt_mac(mbuf,
				&eventdev_rsrc->ports_eth_addr[dst_port],
				dst_port);

		if (flags & L2FWD_EVENT_TX_ENQ) {
			ev.queue_id = tx_q_id;
			ev.op = RTE_EVENT_OP_FORWARD;
			while (rte_event_enqueue_burst(event_d_id, port_id,
						       &ev, 1) && !*done)
				;
		}

		if (flags & L2FWD_EVENT_TX_DIRECT) {
			rte_event_eth_tx_adapter_txq_set(mbuf, 0);
			while (!rte_event_eth_tx_adapter_enqueue(event_d_id,
								port_id,
								&ev, 1) &&
					!*done)
				;
		}

		if (timer_period > 0)
			__atomic_fetch_add(&eventdev_rsrc->stats[mbuf->port].tx,
					   1, __ATOMIC_RELAXED);
	}
}

static __rte_always_inline void
l2fwd_event_loop_burst(struct eventdev_resources *eventdev_rsrc,
		       const uint32_t flags)
{
	const uint8_t is_master = rte_get_master_lcore() == rte_lcore_id();
	const uint64_t timer_period = eventdev_rsrc->timer_period;
	uint64_t prev_tsc = 0, diff_tsc, cur_tsc, timer_tsc = 0;
	const int port_id = get_free_event_port(eventdev_rsrc);
	const uint8_t tx_q_id = eventdev_rsrc->evq.event_q_id[
					eventdev_rsrc->evq.nb_queues - 1];
	const uint8_t event_d_id = eventdev_rsrc->event_d_id;
	const uint8_t deq_len = eventdev_rsrc->deq_depth;
	volatile bool *done = eventdev_rsrc->done;
	struct rte_event ev[MAX_PKT_BURST];
	struct rte_mbuf *mbuf;
	uint16_t nb_rx, nb_tx;
	uint16_t dst_port;
	uint8_t i;

	if (port_id < 0)
		return;

	printf("%s(): entering eventdev main loop on lcore %u\n", __func__,
		rte_lcore_id());

	while (!*done) {
		/* if timer is enabled */
		if (is_master && timer_period > 0) {
			cur_tsc = rte_rdtsc();
			diff_tsc = cur_tsc - prev_tsc;

			/* advance the timer */
			timer_tsc += diff_tsc;

			/* if timer has reached its timeout */
			if (unlikely(timer_tsc >= timer_period)) {
				print_stats();
				/* reset the timer */
				timer_tsc = 0;
			}
			prev_tsc = cur_tsc;
		}

		/* Read packet from eventdev */
		nb_rx = rte_event_dequeue_burst(event_d_id, port_id, ev,
						deq_len, 0);
		if (nb_rx == 0)
			continue;


		for (i = 0; i < nb_rx; i++) {
			mbuf = ev[i].mbuf;
			dst_port = eventdev_rsrc->dst_ports[mbuf->port];
			rte_prefetch0(rte_pktmbuf_mtod(mbuf, void *));

			if (timer_period > 0) {
				__atomic_fetch_add(
					&eventdev_rsrc->stats[mbuf->port].rx,
					1, __ATOMIC_RELAXED);
				__atomic_fetch_add(
					&eventdev_rsrc->stats[mbuf->port].tx,
					1, __ATOMIC_RELAXED);
			}
			mbuf->port = dst_port;
			if (flags & L2FWD_EVENT_UPDT_MAC)
				l2fwd_event_updt_mac(mbuf,
						&eventdev_rsrc->ports_eth_addr[
								dst_port],
						dst_port);

			if (flags & L2FWD_EVENT_TX_ENQ) {
				ev[i].queue_id = tx_q_id;
				ev[i].op = RTE_EVENT_OP_FORWARD;
			}

			if (flags & L2FWD_EVENT_TX_DIRECT)
				rte_event_eth_tx_adapter_txq_set(mbuf, 0);

		}

		if (flags & L2FWD_EVENT_TX_ENQ) {
			nb_tx = rte_event_enqueue_burst(event_d_id, port_id,
							ev, nb_rx);
			while (nb_tx < nb_rx && !*done)
				nb_tx += rte_event_enqueue_burst(event_d_id,
						port_id, ev + nb_tx,
						nb_rx - nb_tx);
		}

		if (flags & L2FWD_EVENT_TX_DIRECT) {
			nb_tx = rte_event_eth_tx_adapter_enqueue(event_d_id,
								 port_id, ev,
								 nb_rx);
			while (nb_tx < nb_rx && !*done)
				nb_tx += rte_event_eth_tx_adapter_enqueue(
						event_d_id, port_id,
						ev + nb_tx, nb_rx - nb_tx);
		}
	}
}

static __rte_always_inline void
l2fwd_event_loop(struct eventdev_resources *eventdev_rsrc,
			const uint32_t flags)
{
	if (flags & L2FWD_EVENT_SINGLE)
		l2fwd_event_loop_single(eventdev_rsrc, flags);
	if (flags & L2FWD_EVENT_BURST)
		l2fwd_event_loop_burst(eventdev_rsrc, flags);
}

#define L2FWD_EVENT_MODE						\
FP(tx_d,	0, 0, 0, L2FWD_EVENT_TX_DIRECT | L2FWD_EVENT_SINGLE)	\
FP(tx_d_burst,	0, 0, 1, L2FWD_EVENT_TX_DIRECT | L2FWD_EVENT_BURST)	\
FP(tx_q,	0, 1, 0, L2FWD_EVENT_TX_ENQ | L2FWD_EVENT_SINGLE)	\
FP(tx_q_burst,	0, 1, 1, L2FWD_EVENT_TX_ENQ | L2FWD_EVENT_BURST)	\
FP(tx_d_mac,	1, 0, 0, L2FWD_EVENT_UPDT_MAC | L2FWD_EVENT_TX_DIRECT | \
			 L2FWD_EVENT_SINGLE)				\
FP(tx_d_brst_mac, 1, 0, 1, L2FWD_EVENT_UPDT_MAC | L2FWD_EVENT_TX_DIRECT | \
				L2FWD_EVENT_BURST)			\
FP(tx_q_mac,	  1, 1, 0, L2FWD_EVENT_UPDT_MAC | L2FWD_EVENT_TX_ENQ |	\
				L2FWD_EVENT_SINGLE)			\
FP(tx_q_brst_mac, 1, 1, 1, L2FWD_EVENT_UPDT_MAC | L2FWD_EVENT_TX_ENQ |	\
				L2FWD_EVENT_BURST)


#define FP(_name, _f3, _f2, _f1, flags)					\
static void __rte_noinline						\
l2fwd_event_main_loop_ ## _name(void)					\
{									\
	struct eventdev_resources *eventdev_rsrc = get_eventdev_rsrc();	\
	l2fwd_event_loop(eventdev_rsrc, flags);				\
}

L2FWD_EVENT_MODE
#undef FP

void
eventdev_resource_setup(void)
{
	struct eventdev_resources *eventdev_rsrc = get_eventdev_rsrc();
	/* [MAC_UPDT][TX_MODE][BURST] */
	const event_loop_cb event_loop[2][2][2] = {
#define FP(_name, _f3, _f2, _f1, flags) \
		[_f3][_f2][_f1] = l2fwd_event_main_loop_ ## _name,
		L2FWD_EVENT_MODE
#undef FP
	};
	uint16_t ethdev_count = rte_eth_dev_count_avail();
	uint32_t event_queue_cfg = 0;
	uint32_t service_id;
	int32_t ret;

	/* Parse eventdev command line options */
	ret = parse_eventdev_args(eventdev_rsrc->args, eventdev_rsrc->nb_args);
	if (ret < 0)
		return;

	if (!rte_event_dev_count())
		rte_exit(EXIT_FAILURE, "No Eventdev found");

	/* Setup eventdev capability callbacks */
	eventdev_capability_setup();

	/* Ethernet device configuration */
	eth_dev_port_setup(ethdev_count);

	/* Event device configuration */
	event_queue_cfg = eventdev_rsrc->ops.eventdev_setup(ethdev_count);

	/* Event queue configuration */
	eventdev_rsrc->ops.event_queue_setup(ethdev_count, event_queue_cfg);

	/* Event port configuration */
	eventdev_rsrc->ops.event_port_setup();

	/* Rx/Tx adapters configuration */
	eventdev_rsrc->ops.adapter_setup(ethdev_count);

	/* Start event device service */
	ret = rte_event_dev_service_id_get(eventdev_rsrc->event_d_id,
			&service_id);
	if (ret != -ESRCH && ret != 0)
		rte_exit(EXIT_FAILURE, "Error in starting eventdev");

	rte_service_runstate_set(service_id, 1);
	rte_service_set_runstate_mapped_check(service_id, 0);
	eventdev_rsrc->service_id = service_id;

	/* Start event device */
	ret = rte_event_dev_start(eventdev_rsrc->event_d_id);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error in starting eventdev");

	eventdev_rsrc->ops.l2fwd_event_loop = event_loop
					[eventdev_rsrc->mac_updt]
					[eventdev_rsrc->tx_mode_q]
					[eventdev_rsrc->has_burst];
}
