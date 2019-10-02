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
#include <rte_malloc.h>
#include <rte_spinlock.h>

#include "l2fwd_event.h"

#define L2FWD_EVENT_SINGLE	0x1
#define L2FWD_EVENT_BURST	0x2
#define L2FWD_EVENT_TX_DIRECT	0x4
#define L2FWD_EVENT_TX_ENQ	0x8
#define L2FWD_EVENT_UPDT_MAC	0x10

static inline int
l2fwd_event_service_enable(uint32_t service_id)
{
	uint8_t min_service_count = UINT8_MAX;
	uint32_t slcore_array[RTE_MAX_LCORE];
	unsigned int slcore = 0;
	uint8_t service_count;
	int32_t slcore_count;

	if (!rte_service_lcore_count())
		return -ENOENT;

	slcore_count = rte_service_lcore_list(slcore_array, RTE_MAX_LCORE);
	if (slcore_count < 0)
		return -ENOENT;
	/* Get the core which has least number of services running. */
	while (slcore_count--) {
		/* Reset default mapping */
		rte_service_map_lcore_set(service_id,
				slcore_array[slcore_count], 0);
		service_count = rte_service_lcore_count_services(
				slcore_array[slcore_count]);
		if (service_count < min_service_count) {
			slcore = slcore_array[slcore_count];
			min_service_count = service_count;
		}
	}
	if (rte_service_map_lcore_set(service_id, slcore, 1))
		return -ENOENT;
	rte_service_lcore_start(slcore);

	return 0;
}

void
l2fwd_event_service_setup(struct l2fwd_resources *l2fwd_rsrc)
{
	struct l2fwd_event_resources *event_rsrc = l2fwd_rsrc->event_rsrc;
	struct rte_event_dev_info evdev_info;
	uint32_t service_id, caps;
	int ret, i;

	rte_event_dev_info_get(event_rsrc->event_d_id, &evdev_info);
	if (evdev_info.event_dev_cap  & RTE_EVENT_DEV_CAP_DISTRIBUTED_SCHED) {
		ret = rte_event_dev_service_id_get(event_rsrc->event_d_id,
				&service_id);
		if (ret != -ESRCH && ret != 0)
			rte_exit(EXIT_FAILURE,
					"Error in starting eventdev service\n");
		l2fwd_event_service_enable(service_id);
	}

	for (i = 0; i < event_rsrc->rx_adptr.nb_rx_adptr; i++) {
		ret = rte_event_eth_rx_adapter_caps_get(event_rsrc->event_d_id,
				event_rsrc->rx_adptr.rx_adptr[i], &caps);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
					"Failed to get Rx adapter[%d] caps\n",
					event_rsrc->rx_adptr.rx_adptr[i]);
		ret = rte_event_eth_rx_adapter_service_id_get(
				event_rsrc->event_d_id,
				&service_id);
		if (ret != -ESRCH && ret != 0)
			rte_exit(EXIT_FAILURE,
					"Error in starting Rx adapter[%d] service\n",
					event_rsrc->rx_adptr.rx_adptr[i]);
		l2fwd_event_service_enable(service_id);
	}

	for (i = 0; i < event_rsrc->tx_adptr.nb_tx_adptr; i++) {
		ret = rte_event_eth_tx_adapter_caps_get(event_rsrc->event_d_id,
				event_rsrc->tx_adptr.tx_adptr[i], &caps);
		if (ret < 0)
			rte_exit(EXIT_FAILURE,
					"Failed to get Rx adapter[%d] caps\n",
					event_rsrc->tx_adptr.tx_adptr[i]);
		ret = rte_event_eth_tx_adapter_service_id_get(
				event_rsrc->event_d_id,
				&service_id);
		if (ret != -ESRCH && ret != 0)
			rte_exit(EXIT_FAILURE,
					"Error in starting Rx adapter[%d] service\n",
					event_rsrc->tx_adptr.tx_adptr[i]);
		l2fwd_event_service_enable(service_id);
	}
}

static void
l2fwd_event_capability_setup(struct l2fwd_event_resources *event_rsrc)
{
	uint32_t caps = 0;
	uint16_t i;
	int ret;

	RTE_ETH_FOREACH_DEV(i) {
		ret = rte_event_eth_tx_adapter_caps_get(0, i, &caps);
		if (ret)
			rte_exit(EXIT_FAILURE,
				 "Invalid capability for Tx adptr port %d\n",
				 i);

		event_rsrc->tx_mode_q |= !(caps &
				   RTE_EVENT_ETH_TX_ADAPTER_CAP_INTERNAL_PORT);
	}

	if (event_rsrc->tx_mode_q)
		l2fwd_event_set_generic_ops(&event_rsrc->ops);
	else
		l2fwd_event_set_internal_port_ops(&event_rsrc->ops);
}

static __rte_noinline int
l2fwd_get_free_event_port(struct l2fwd_event_resources *event_rsrc)
{
	static int index;
	int port_id;

	rte_spinlock_lock(&event_rsrc->evp.lock);
	if (index >= event_rsrc->evp.nb_ports) {
		printf("No free event port is available\n");
		return -1;
	}

	port_id = event_rsrc->evp.event_p_id[index];
	index++;
	rte_spinlock_unlock(&event_rsrc->evp.lock);

	return port_id;
}

static __rte_always_inline void
l2fwd_event_loop_single(struct l2fwd_resources *l2fwd_rsrc,
			const uint32_t flags)
{
	const uint8_t is_master = rte_get_master_lcore() == rte_lcore_id();
	struct l2fwd_event_resources *event_rsrc = l2fwd_rsrc->event_rsrc;
	const int port_id = l2fwd_get_free_event_port(event_rsrc);
	uint64_t prev_tsc = 0, diff_tsc, cur_tsc, timer_tsc = 0;
	const uint64_t timer_period = l2fwd_rsrc->timer_period;
	const uint8_t tx_q_id = event_rsrc->evq.event_q_id[
					event_rsrc->evq.nb_queues - 1];
	const uint8_t event_d_id = event_rsrc->event_d_id;
	struct rte_mbuf *mbuf;
	uint16_t dst_port;
	struct rte_event ev;

	if (port_id < 0)
		return;

	printf("%s(): entering eventdev main loop on lcore %u\n", __func__,
		rte_lcore_id());

	while (!l2fwd_rsrc->force_quit) {
		/* if timer is enabled */
		if (is_master && timer_period > 0) {
			cur_tsc = rte_rdtsc();
			diff_tsc = cur_tsc - prev_tsc;

			/* advance the timer */
			timer_tsc += diff_tsc;

			/* if timer has reached its timeout */
			if (unlikely(timer_tsc >= timer_period)) {
				print_stats(l2fwd_rsrc);
				/* reset the timer */
				timer_tsc = 0;
			}
			prev_tsc = cur_tsc;
		}

		/* Read packet from eventdev */
		if (!rte_event_dequeue_burst(event_d_id, port_id, &ev, 1, 0))
			continue;


		mbuf = ev.mbuf;
		dst_port = l2fwd_rsrc->dst_ports[mbuf->port];
		rte_prefetch0(rte_pktmbuf_mtod(mbuf, void *));

		if (timer_period > 0)
			__atomic_fetch_add(
					&l2fwd_rsrc->port_stats[mbuf->port].rx,
					1, __ATOMIC_RELAXED);

		mbuf->port = dst_port;
		if (flags & L2FWD_EVENT_UPDT_MAC)
			l2fwd_mac_updating(mbuf, dst_port,
					   &l2fwd_rsrc->eth_addr[dst_port]);

		if (flags & L2FWD_EVENT_TX_ENQ) {
			ev.queue_id = tx_q_id;
			ev.op = RTE_EVENT_OP_FORWARD;
			while (rte_event_enqueue_burst(event_d_id, port_id,
						       &ev, 1) &&
					!l2fwd_rsrc->force_quit)
				;
		}

		if (flags & L2FWD_EVENT_TX_DIRECT) {
			rte_event_eth_tx_adapter_txq_set(mbuf, 0);
			while (!rte_event_eth_tx_adapter_enqueue(event_d_id,
								port_id,
								&ev, 1) &&
					!l2fwd_rsrc->force_quit)
				;
		}

		if (timer_period > 0)
			__atomic_fetch_add(
					&l2fwd_rsrc->port_stats[mbuf->port].tx,
					1, __ATOMIC_RELAXED);
	}
}

static __rte_always_inline void
l2fwd_event_loop_burst(struct l2fwd_resources *l2fwd_rsrc,
		       const uint32_t flags)
{
	const uint8_t is_master = rte_get_master_lcore() == rte_lcore_id();
	struct l2fwd_event_resources *event_rsrc = l2fwd_rsrc->event_rsrc;
	const int port_id = l2fwd_get_free_event_port(event_rsrc);
	uint64_t prev_tsc = 0, diff_tsc, cur_tsc, timer_tsc = 0;
	const uint64_t timer_period = l2fwd_rsrc->timer_period;
	const uint8_t tx_q_id = event_rsrc->evq.event_q_id[
					event_rsrc->evq.nb_queues - 1];
	const uint8_t event_d_id = event_rsrc->event_d_id;
	const uint8_t deq_len = event_rsrc->deq_depth;
	struct rte_event ev[MAX_PKT_BURST];
	struct rte_mbuf *mbuf;
	uint16_t nb_rx, nb_tx;
	uint16_t dst_port;
	uint8_t i;

	if (port_id < 0)
		return;

	printf("%s(): entering eventdev main loop on lcore %u\n", __func__,
		rte_lcore_id());

	while (!l2fwd_rsrc->force_quit) {
		/* if timer is enabled */
		if (is_master && timer_period > 0) {
			cur_tsc = rte_rdtsc();
			diff_tsc = cur_tsc - prev_tsc;

			/* advance the timer */
			timer_tsc += diff_tsc;

			/* if timer has reached its timeout */
			if (unlikely(timer_tsc >= timer_period)) {
				print_stats(l2fwd_rsrc);
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
			dst_port = l2fwd_rsrc->dst_ports[mbuf->port];
			rte_prefetch0(rte_pktmbuf_mtod(mbuf, void *));

			if (timer_period > 0) {
				__atomic_fetch_add(
					&l2fwd_rsrc->port_stats[mbuf->port].rx,
					1, __ATOMIC_RELAXED);
				__atomic_fetch_add(
					&l2fwd_rsrc->port_stats[mbuf->port].tx,
					1, __ATOMIC_RELAXED);
			}
			mbuf->port = dst_port;
			if (flags & L2FWD_EVENT_UPDT_MAC)
				l2fwd_mac_updating(mbuf, dst_port,
						   &l2fwd_rsrc->eth_addr[
								dst_port]);

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
			while (nb_tx < nb_rx && !l2fwd_rsrc->force_quit)
				nb_tx += rte_event_enqueue_burst(event_d_id,
						port_id, ev + nb_tx,
						nb_rx - nb_tx);
		}

		if (flags & L2FWD_EVENT_TX_DIRECT) {
			nb_tx = rte_event_eth_tx_adapter_enqueue(event_d_id,
								 port_id, ev,
								 nb_rx);
			while (nb_tx < nb_rx && !l2fwd_rsrc->force_quit)
				nb_tx += rte_event_eth_tx_adapter_enqueue(
						event_d_id, port_id,
						ev + nb_tx, nb_rx - nb_tx);
		}
	}
}

static __rte_always_inline void
l2fwd_event_loop(struct l2fwd_resources *l2fwd_rsrc,
			const uint32_t flags)
{
	if (flags & L2FWD_EVENT_SINGLE)
		l2fwd_event_loop_single(l2fwd_rsrc, flags);
	if (flags & L2FWD_EVENT_BURST)
		l2fwd_event_loop_burst(l2fwd_rsrc, flags);
}

static void __rte_noinline
l2fwd_event_main_loop_tx_d(struct l2fwd_resources *l2fwd_rsrc)
{
	l2fwd_event_loop(l2fwd_rsrc,
			 L2FWD_EVENT_TX_DIRECT | L2FWD_EVENT_SINGLE);
}

static void __rte_noinline
l2fwd_event_main_loop_tx_d_brst(struct l2fwd_resources *l2fwd_rsrc)
{
	l2fwd_event_loop(l2fwd_rsrc, L2FWD_EVENT_TX_DIRECT | L2FWD_EVENT_BURST);
}

static void __rte_noinline
l2fwd_event_main_loop_tx_q(struct l2fwd_resources *l2fwd_rsrc)
{
	l2fwd_event_loop(l2fwd_rsrc, L2FWD_EVENT_TX_ENQ | L2FWD_EVENT_SINGLE);
}

static void __rte_noinline
l2fwd_event_main_loop_tx_q_brst(struct l2fwd_resources *l2fwd_rsrc)
{
	l2fwd_event_loop(l2fwd_rsrc, L2FWD_EVENT_TX_ENQ | L2FWD_EVENT_BURST);
}

static void __rte_noinline
l2fwd_event_main_loop_tx_d_mac(struct l2fwd_resources *l2fwd_rsrc)
{
	l2fwd_event_loop(l2fwd_rsrc, L2FWD_EVENT_UPDT_MAC |
			L2FWD_EVENT_TX_DIRECT | L2FWD_EVENT_SINGLE);
}

static void __rte_noinline
l2fwd_event_main_loop_tx_d_brst_mac(struct l2fwd_resources *l2fwd_rsrc)
{
	l2fwd_event_loop(l2fwd_rsrc, L2FWD_EVENT_UPDT_MAC |
			L2FWD_EVENT_TX_DIRECT | L2FWD_EVENT_BURST);
}

static void __rte_noinline
l2fwd_event_main_loop_tx_q_mac(struct l2fwd_resources *l2fwd_rsrc)
{
	l2fwd_event_loop(l2fwd_rsrc, L2FWD_EVENT_UPDT_MAC |
			L2FWD_EVENT_TX_ENQ | L2FWD_EVENT_SINGLE);
}

static void __rte_noinline
l2fwd_event_main_loop_tx_q_brst_mac(struct l2fwd_resources *l2fwd_rsrc)
{
	l2fwd_event_loop(l2fwd_rsrc, L2FWD_EVENT_UPDT_MAC |
			L2FWD_EVENT_TX_ENQ | L2FWD_EVENT_BURST);
}

void
l2fwd_event_resource_setup(struct l2fwd_resources *l2fwd_rsrc)
{
	/* [MAC_UPDT][TX_MODE][BURST] */
	const event_loop_cb event_loop[2][2][2] = {
		[0][0][0] = l2fwd_event_main_loop_tx_d,
		[0][0][1] = l2fwd_event_main_loop_tx_d_brst,
		[0][1][0] = l2fwd_event_main_loop_tx_q,
		[0][1][1] = l2fwd_event_main_loop_tx_q_brst,
		[1][0][0] = l2fwd_event_main_loop_tx_d_mac,
		[1][0][1] = l2fwd_event_main_loop_tx_d_brst_mac,
		[1][1][0] = l2fwd_event_main_loop_tx_q_mac,
		[1][1][1] = l2fwd_event_main_loop_tx_q_brst_mac,
	};
	struct l2fwd_event_resources *event_rsrc;
	uint32_t event_queue_cfg;
	int ret;

	if (!rte_event_dev_count())
		rte_exit(EXIT_FAILURE, "No Eventdev found\n");

	event_rsrc = rte_zmalloc("l2fwd_event",
				 sizeof(struct l2fwd_event_resources), 0);
	if (event_rsrc == NULL)
		rte_exit(EXIT_FAILURE, "failed to allocate memory\n");

	l2fwd_rsrc->event_rsrc = event_rsrc;

	/* Setup eventdev capability callbacks */
	l2fwd_event_capability_setup(event_rsrc);

	/* Event device configuration */
	event_queue_cfg = event_rsrc->ops.event_device_setup(l2fwd_rsrc);

	/* Event queue configuration */
	event_rsrc->ops.event_queue_setup(l2fwd_rsrc, event_queue_cfg);

	/* Event port configuration */
	event_rsrc->ops.event_port_setup(l2fwd_rsrc);

	/* Rx/Tx adapters configuration */
	event_rsrc->ops.adapter_setup(l2fwd_rsrc);

	/* Start event device */
	ret = rte_event_dev_start(event_rsrc->event_d_id);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error in starting eventdev");

	event_rsrc->ops.l2fwd_event_loop = event_loop
					[l2fwd_rsrc->mac_updating]
					[event_rsrc->tx_mode_q]
					[event_rsrc->has_burst];
}
