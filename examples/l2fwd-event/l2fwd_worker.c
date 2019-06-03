/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2016 Intel Corporation
 * Copyright (C) 2019 Marvell International Ltd.
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
#include <stdbool.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_memcpy.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_eventdev.h>
#include <rte_eventmode_helper.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>

#include "l2fwd_common.h"
#include "l2fwd_worker.h"

/* Reset eth stats */
static void
reset_eth_stats(int is_master_core)
{
	int portid;

	/* Only master core need to do this */
	if (!is_master_core)
		return;

	/* Reset stats */
	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
		/* skip disabled ports */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;
		rte_eth_stats_reset(portid);
	}
}

/* Print out statistics on packets dropped */
static void
print_stats(void)
{
	struct rte_eth_stats stats;
	uint64_t total_packets_dropped, total_packets_tx, total_packets_rx;
	unsigned int portid;

	total_packets_dropped = 0;
	total_packets_tx = 0;
	total_packets_rx = 0;

	const char clr[] = { 27, '[', '2', 'J', '\0' };
	const char topLeft[] = { 27, '[', '1', ';', '1', 'H', '\0' };

		/* Clear screen and move to top left */
	printf("%s%s", clr, topLeft);

	printf("\nPort statistics ====================================");

	for (portid = 0; portid < RTE_MAX_ETHPORTS; portid++) {
		/* skip disabled ports */
		if ((l2fwd_enabled_port_mask & (1 << portid)) == 0)
			continue;
		rte_eth_stats_get(portid, &stats);
		printf("\nStatistics for port %u ------------------------------"
			   "\nPackets sent: %24"PRIu64
			   "\nPackets received: %20"PRIu64
			   "\nPackets dropped: %21"PRIu64,
			   portid,
			   stats.opackets,
			   stats.ipackets,
			   stats.oerrors);

		total_packets_dropped += stats.oerrors;
		total_packets_tx += stats.opackets;
		total_packets_rx += stats.ipackets;
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

static inline void
l2fwd_drain_buffers(struct lcore_queue_conf *qconf)
{
	unsigned int i, sent;
	unsigned int portid;
	struct rte_eth_dev_tx_buffer *buffer;

	for (i = 0; i < qconf->n_rx_port; i++) {

		portid = l2fwd_dst_ports[qconf->rx_port_list[i]];
		buffer = tx_buffer[portid];

		sent = rte_eth_tx_buffer_flush(portid, 0, buffer);
		if (sent)
			port_statistics[portid].tx += sent;
	}
}

static inline void
l2fwd_periodic_drain_stats_monitor(struct lcore_queue_conf *qconf,
		struct tsc_tracker *t, int is_master_core)
{
	uint64_t diff_tsc, cur_tsc;

	cur_tsc = rte_rdtsc();

	/*
	 * TX burst queue drain
	 */
	diff_tsc = cur_tsc - t->prev_tsc;
	if (unlikely(diff_tsc > t->drain_tsc)) {

		/* Drain buffers */
		l2fwd_drain_buffers(qconf);

		t->prev_tsc = cur_tsc;

		/* Skip the timer based stats prints if not master core */
		if (!is_master_core)
			return;

		/* On master core */

		/* if timer is enabled */
		if (timer_period > 0) {

			/* advance the timer */
			t->timer_tsc += diff_tsc;

			/* if timer has reached its timeout */
			if (unlikely(t->timer_tsc >= timer_period)) {

				/* Print stats */
				print_stats();

				/* reset the timer */
				t->timer_tsc = 0;
			}
		}
	}
}

static inline void
l2fwd_drain_loop(struct lcore_queue_conf *qconf, struct tsc_tracker *t,
		int is_master_core)
{
	while (!force_quit) {
		/* Do periodic operations (buffer drain & stats monitor) */
		l2fwd_periodic_drain_stats_monitor(qconf, t, is_master_core);
	}
}

static void
l2fwd_mac_updating(struct rte_mbuf *m, unsigned int dest_portid)
{
	struct rte_ether_hdr *eth;
	void *tmp;

	eth = rte_pktmbuf_mtod(m, struct rte_ether_hdr *);

	/* 02:00:00:00:00:xx */
	tmp = &eth->d_addr.addr_bytes[0];
	*((uint64_t *)tmp) = 0x000000000002 + ((uint64_t)dest_portid << 40);

	/* src addr */
	rte_ether_addr_copy(&l2fwd_ports_eth_addr[dest_portid], &eth->s_addr);
}

static inline void
l2fwd_send_pkt(struct rte_mbuf *tx_pkt, unsigned int port_id)
{
	int sent;
	struct rte_eth_dev_tx_buffer *buffer;

	buffer = tx_buffer[port_id];
	sent = rte_eth_tx_buffer(port_id, 0, buffer, tx_pkt);
	if (sent)
		port_statistics[port_id].tx += sent;
}

static void
l2fwd_simple_forward(struct rte_mbuf *m, unsigned int portid)
{
	unsigned int dst_port;

	dst_port = l2fwd_dst_ports[portid];

	if (mac_updating)
		l2fwd_mac_updating(m, dst_port);

	/* Send packet */
	l2fwd_send_pkt(m, dst_port);
}

static inline void
l2fwd_event_pre_forward(struct rte_event *ev, unsigned int portid)
{
	unsigned int dst_port;
	struct rte_mbuf *m;

	/* Get the mbuf */
	m = ev->mbuf;

	/* Get the destination port from the tables */
	dst_port = l2fwd_dst_ports[portid];

	/* Save the destination port in the mbuf */
	m->port = dst_port;

	/* Use tx queue 0 */
	rte_event_eth_tx_adapter_txq_set(m, 0);

	/* Perform work */
	if (mac_updating)
		l2fwd_mac_updating(m, dst_port);
}

static inline void
l2fwd_event_switch_to_tx_queue(struct rte_event *ev, uint8_t tx_queue_id)
{
	ev->event_type = RTE_EVENT_TYPE_CPU;
	ev->op = RTE_EVENT_OP_FORWARD;
	ev->queue_id = tx_queue_id;
}

/* poll mode processing loop */
static void
l2fwd_poll_mode_worker(void)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	struct rte_mbuf *m;
	unsigned int lcore_id;
	unsigned int i, j, portid, nb_rx;
	struct lcore_queue_conf *qconf;
	int is_master_core;
	struct tsc_tracker tsc = {0};

	lcore_id = rte_lcore_id();
	qconf = &lcore_queue_conf[lcore_id];

	/* Set drain tsc */
	tsc.drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) /
			US_PER_S * BURST_TX_DRAIN_US;

	if (qconf->n_rx_port == 0) {
		RTE_LOG(INFO, L2FWD, "lcore %u has nothing to do\n", lcore_id);
		return;
	}

	RTE_LOG(INFO, L2FWD, "entering main loop on lcore %u\n", lcore_id);

	for (i = 0; i < qconf->n_rx_port; i++) {

		portid = qconf->rx_port_list[i];
		RTE_LOG(INFO, L2FWD, " -- lcoreid=%u portid=%u\n", lcore_id,
			portid);

	}

	/* Set the flag if master core */
	is_master_core = (lcore_id == rte_get_master_lcore()) ? 1 : 0;

	while (!force_quit) {

		/* Do periodic operations (buffer drain & stats monitor) */
		l2fwd_periodic_drain_stats_monitor(qconf, &tsc, is_master_core);

		/*
		 * Read packet from RX queues
		 */
		for (i = 0; i < qconf->n_rx_port; i++) {

			portid = qconf->rx_port_list[i];
			nb_rx = rte_eth_rx_burst(portid, 0,
						 pkts_burst, MAX_PKT_BURST);

			port_statistics[portid].rx += nb_rx;

			for (j = 0; j < nb_rx; j++) {
				m = pkts_burst[j];
				rte_prefetch0(rte_pktmbuf_mtod(m, void *));
				l2fwd_simple_forward(m, portid);
			}
		}
	}
}

/*
 * Event mode exposes various operating modes depending on the
 * capabilities of the event device and the operating mode
 * selected.
 */

/* Workers registered */
#define L2FWD_EVENTMODE_WORKERS		3

/*
 * Event mode worker
 * Operating mode : non-burst no internal port (regular tx worker)
 */
static void
l2fwd_eventmode_non_burst_no_internal_port(void *args)
{
	struct rte_event ev;
	struct rte_mbuf *pkt;
	struct rte_eventmode_helper_conf *mode_conf;
	struct rte_eventmode_helper_event_link_info *links = NULL;
	unsigned int lcore_nb_link = 0;
	uint32_t lcore_id;
	unsigned int i, nb_rx = 0;
	unsigned int portid;
	struct lcore_queue_conf *qconf;
	int is_master_core;
	struct tsc_tracker tsc = {0};
	uint8_t tx_queue;

	/* Get core ID */
	lcore_id = rte_lcore_id();

	RTE_LOG(INFO, L2FWD,
		"Launching event mode non-burst worker no internal port "
		"(regular tx worker) on lcore %d\n", lcore_id);

	/* Set the flag if master core */
	is_master_core = (lcore_id == rte_get_master_lcore()) ? 1 : 0;

	/* Get qconf for this core */
	qconf = &lcore_queue_conf[lcore_id];

	/* Set drain tsc */
	tsc.drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) /
			US_PER_S * BURST_TX_DRAIN_US;

	/* Mode conf will be passed as args */
	mode_conf = (struct rte_eventmode_helper_conf *)args;

	/* Get the links configured for this lcore */
	lcore_nb_link = rte_eventmode_helper_get_event_lcore_links(lcore_id,
			mode_conf, &links);

	/* Check if we have links registered for this lcore */
	if (lcore_nb_link == 0) {
		/* No links registered. The core could do periodic drains */
		l2fwd_drain_loop(qconf, &tsc, is_master_core);
		goto clean_and_exit;
	}

	/* We have valid links */

	/* Reset stats before proceeding */
	reset_eth_stats(is_master_core);

	/*
	 * There is no internal port between ethdev and eventdev. So the worker
	 * thread needs to submit event to a designated tx queue. Internally
	 * eth core would receive events from multiple worker threads and send
	 * out packets on wire.
	 */
	tx_queue = rte_eventmode_helper_get_tx_queue(mode_conf,
						     links[0].eventdev_id);
	/* See if it's single link */
	if (lcore_nb_link == 1)
		goto single_link_loop;
	else
		goto multi_link_loop;

single_link_loop:

	RTE_LOG(INFO, L2FWD, " -- lcoreid=%u event_port_id=%u\n", lcore_id,
			links[0].event_portid);

	while (!force_quit) {

		/* Do periodic operations (buffer drain & stats monitor) */
		l2fwd_periodic_drain_stats_monitor(qconf, &tsc, is_master_core);

		/* Read packet from event queues */
		nb_rx = rte_event_dequeue_burst(links[0].eventdev_id,
				links[0].event_portid,
				&ev,	/* events */
				1,	/* nb_events */
				0	/* timeout_ticks */);

		if (nb_rx == 0)
			continue;

		portid = ev.queue_id;
		port_statistics[portid].rx++;
		pkt = ev.mbuf;

		rte_prefetch0(rte_pktmbuf_mtod(pkt, void *));

		/* Process packet */
		l2fwd_event_pre_forward(&ev, portid);

		/*
		 * Internal port is not available, the packet needs
		 * to be enqueued to the designated event queue.
		 */

		/* Prepare event for submission to tx event queue */
		l2fwd_event_switch_to_tx_queue(&ev, tx_queue);

		/* Submit the updated event for tx stage */
		rte_event_enqueue_burst(links[0].eventdev_id,
				links[0].event_portid,
				&ev,	/* events */
				1	/* nb_events */);
	}
	goto clean_and_exit;

multi_link_loop:

	for (i = 0; i < lcore_nb_link; i++) {
		RTE_LOG(INFO, L2FWD, " -- lcoreid=%u event_port_id=%u\n",
				lcore_id, links[i].event_portid);
	}

	while (!force_quit) {

		/* Do periodic operations (buffer drain & stats monitor) */
		l2fwd_periodic_drain_stats_monitor(qconf, &tsc, is_master_core);

		for (i = 0; i < lcore_nb_link; i++) {
			/* Read packet from event queues */
			nb_rx = rte_event_dequeue_burst(links[i].eventdev_id,
					links[i].event_portid,
					&ev,	/* events */
					1,	/* nb_events */
					0	/* timeout_ticks */);

			if (nb_rx == 0)
				continue;

			portid = ev.queue_id;
			port_statistics[portid].rx++;
			pkt = ev.mbuf;

			rte_prefetch0(rte_pktmbuf_mtod(pkt, void *));

			/* Process packet */
			l2fwd_event_pre_forward(&ev, portid);

			/*
			 * Internal port is not available, the packet needs
			 * to be enqueued to the designated event queue.
			 */

			/* Prepare event for submission to tx event queue */
			l2fwd_event_switch_to_tx_queue(&ev, tx_queue);

			/* Submit the updated event for tx stage */
			rte_event_enqueue_burst(links[i].eventdev_id,
					links[i].event_portid,
					&ev,	/* events */
					1	/* nb_events */);
		}
	}
	goto clean_and_exit;

clean_and_exit:
	if (links != NULL)
		rte_free(links);
}

/*
 * Event mode worker
 * Operating mode : non-burst tx internal port
 */
static void
l2fwd_eventmode_non_burst_tx_internal_port(void *args)
{
	struct rte_event ev;
	struct rte_mbuf *pkt;
	struct rte_eventmode_helper_conf *mode_conf;
	struct rte_eventmode_helper_event_link_info *links = NULL;
	unsigned int lcore_nb_link = 0;
	uint32_t lcore_id;
	unsigned int i, nb_rx = 0;
	unsigned int portid;
	struct lcore_queue_conf *qconf;
	int is_master_core;
	struct tsc_tracker tsc = {0};

	/* Get core ID */
	lcore_id = rte_lcore_id();

	RTE_LOG(INFO, L2FWD,
		"Launching event mode non-burst worker internal port "
		"on lcore %d\n", lcore_id);

	/* Set the flag if master core */
	is_master_core = (lcore_id == rte_get_master_lcore()) ? 1 : 0;

	/* Get qconf for this core */
	qconf = &lcore_queue_conf[lcore_id];

	/* Set drain tsc */
	tsc.drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) /
			US_PER_S * BURST_TX_DRAIN_US;

	/* Mode conf will be passed as args */
	mode_conf = (struct rte_eventmode_helper_conf *)args;

	/* Get the links configured for this lcore */
	lcore_nb_link = rte_eventmode_helper_get_event_lcore_links(lcore_id,
			mode_conf, &links);

	/* Check if we have links registered for this lcore */
	if (lcore_nb_link == 0) {
		/* No links registered. The core could do periodic drains */
		l2fwd_drain_loop(qconf, &tsc, is_master_core);
		goto clean_and_exit;
	}

	/* We have valid links */

	/* Reset stats before proceeding */
	reset_eth_stats(is_master_core);

	/* See if it's single link */
	if (lcore_nb_link == 1)
		goto single_link_loop;
	else
		goto multi_link_loop;

single_link_loop:

	RTE_LOG(INFO, L2FWD, " -- lcoreid=%u event_port_id=%u\n", lcore_id,
		links[0].event_portid);

	while (!force_quit) {

		/* Do periodic operations (buffer drain & stats monitor) */
		l2fwd_periodic_drain_stats_monitor(qconf, &tsc, is_master_core);

		/* Read packet from event queues */
		nb_rx = rte_event_dequeue_burst(links[0].eventdev_id,
				links[0].event_portid,
				&ev,     /* events */
				1,       /* nb_events */
				0        /* timeout_ticks */);

		if (nb_rx == 0)
			continue;

		portid = ev.queue_id;
		port_statistics[portid].rx++;
		pkt = ev.mbuf;

		rte_prefetch0(rte_pktmbuf_mtod(pkt, void *));

		/* Process packet */
		l2fwd_event_pre_forward(&ev, portid);

		/*
		 * Since tx internal port is available, events can be
		 * directly enqueued to the adapter and it would be
		 * internally submitted to the eth device.
		 */
		rte_event_eth_tx_adapter_enqueue(links[0].eventdev_id,
				links[0].event_portid,
				&ev,	/* events */
				1	/* nb_events */);
	}
	goto clean_and_exit;

multi_link_loop:

	for (i = 0; i < lcore_nb_link; i++) {
		RTE_LOG(INFO, L2FWD, " -- lcoreid=%u event_port_id=%u\n",
			lcore_id, links[i].event_portid);
	}

	while (!force_quit) {

		/* Do periodic operations (buffer drain & stats monitor) */
		l2fwd_periodic_drain_stats_monitor(qconf, &tsc, is_master_core);

		for (i = 0; i < lcore_nb_link; i++) {
			/* Read packet from event queues */
			nb_rx = rte_event_dequeue_burst(links[i].eventdev_id,
					links[i].event_portid,
					&ev,     /* events */
					1,       /* nb_events */
					0        /* timeout_ticks */);

			if (nb_rx == 0)
				continue;

			portid = ev.queue_id;
			port_statistics[portid].rx++;
			pkt = ev.mbuf;

			rte_prefetch0(rte_pktmbuf_mtod(pkt, void *));

			/* Process packet */
			l2fwd_event_pre_forward(&ev, portid);

			/*
			 * Since tx internal port is available, events can be
			 * directly enqueued to the adapter and it would be
			 * internally submitted to the eth device.
			 */
			rte_event_eth_tx_adapter_enqueue(links[i].eventdev_id,
					links[i].event_portid,
					&ev,	/* events */
					1	/* nb_events */);

		}
	}
	goto clean_and_exit;

clean_and_exit:
	if (links != NULL)
		rte_free(links);
}

/*
 * Event mode worker
 * Operating mode : burst no internal port (regular tx worker)
 */
static void
l2fwd_eventmode_burst_no_internal_port(void *args)
{
	struct rte_event ev[MAX_PKT_BURST];
	struct rte_mbuf *pkt;
	struct rte_eventmode_helper_conf *mode_conf;
	struct rte_eventmode_helper_event_link_info *links = NULL;
	unsigned int lcore_nb_link = 0;
	uint32_t lcore_id;
	unsigned int i, j, left, nb_rx = 0;
	unsigned int portid;
	struct lcore_queue_conf *qconf;
	int is_master_core;
	struct rte_event_port_conf event_port_conf;
	uint16_t deq_len = 0, enq_len = 0;
	uint8_t tx_queue;
	struct tsc_tracker tsc = {0};

	/* Get core ID */
	lcore_id = rte_lcore_id();

	RTE_LOG(INFO, L2FWD,
		"Launching event mode burst worker no internal port "
		"(regular tx worker) on lcore %d\n", lcore_id);

	/* Set the flag if master core */
	is_master_core = (lcore_id == rte_get_master_lcore()) ? 1 : 0;

	/* Get qconf for this core */
	qconf = &lcore_queue_conf[lcore_id];

	/* Set drain tsc */
	tsc.drain_tsc = (rte_get_tsc_hz() + US_PER_S - 1) /
			US_PER_S * BURST_TX_DRAIN_US;

	/* Mode conf will be passed as args */
	mode_conf = (struct rte_eventmode_helper_conf *)args;

	/* Get the links configured for this lcore */
	lcore_nb_link = rte_eventmode_helper_get_event_lcore_links(lcore_id,
			mode_conf, &links);

	/* Check if we have links registered for this lcore */
	if (lcore_nb_link == 0) {
		/* No links registered. The core could do periodic drains */
		l2fwd_drain_loop(qconf, &tsc, is_master_core);
		goto clean_and_exit;
	}

	/* We have valid links */

	/* Reset stats before proceeding */
	reset_eth_stats(is_master_core);

	/*
	 * There is no internal port between ethdev and eventdev. So the worker
	 * thread needs to submit event to a designated tx queue. Internally
	 * eth core would receive events from multiple worker threads and send
	 * out packets on wire.
	 */
	tx_queue = rte_eventmode_helper_get_tx_queue(mode_conf,
						     links[0].eventdev_id);

	/* Get the burst size of the event device */

	/* Get the default conf of the first link */
	rte_event_port_default_conf_get(links[0].eventdev_id,
			links[0].event_portid,
			&event_port_conf);

	/* Save the burst size */
	deq_len = event_port_conf.dequeue_depth;
	enq_len = event_port_conf.enqueue_depth;

	/* Dequeue and enqueue length should not exceed MAX_PKT_BURST */
	if (deq_len > MAX_PKT_BURST)
		deq_len = MAX_PKT_BURST;
	if (enq_len > MAX_PKT_BURST)
		enq_len = MAX_PKT_BURST;

	/* See if it's single link */
	if (lcore_nb_link == 1)
		goto single_link_loop;
	else
		goto multi_link_loop;

single_link_loop:

	RTE_LOG(INFO, L2FWD, " -- lcoreid=%u event_port_id=%u\n", lcore_id,
		links[0].event_portid);

	while (!force_quit) {

		/* Do periodic operations (buffer drain & stats monitor) */
		l2fwd_periodic_drain_stats_monitor(qconf, &tsc, is_master_core);

		/* Read packet from event queues */
		nb_rx = rte_event_dequeue_burst(links[0].eventdev_id,
				links[0].event_portid,
				ev,             /* events */
				deq_len,        /* nb_events */
				0               /* timeout_ticks */);

		if (nb_rx == 0)
			continue;

		for (j = 0; j < nb_rx; j++) {

			portid = ev[j].queue_id;
			port_statistics[portid].rx++;
			pkt = ev[j].mbuf;

			rte_prefetch0(rte_pktmbuf_mtod(pkt, void *));

			/* Process packet */
			l2fwd_event_pre_forward(&(ev[j]), portid);

			/*
			 * Internal port is not available, the packet needs
			 * to be enqueued to the designated event queue.
			 */

			/* Prepare event for submission to tx event queue */
			l2fwd_event_switch_to_tx_queue(&(ev[j]), tx_queue);
		}

		for (j = 0, left = nb_rx;
			j < (nb_rx + enq_len - 1)/enq_len; j++) {

			/* Submit the updated events for tx stage */
			left -= rte_event_enqueue_burst(links[0].eventdev_id,
					links[0].event_portid,
					&(ev[j*enq_len]), /* events */
					left > enq_len ?
					enq_len : left /* nb_events */);
		}
	}
	goto clean_and_exit;

multi_link_loop:

	for (i = 0; i < lcore_nb_link; i++) {
		RTE_LOG(INFO, L2FWD, " -- lcoreid=%u event_port_id=%u\n",
			lcore_id, links[i].event_portid);
	}

	while (!force_quit) {

		/* Do periodic operations (buffer drain & stats monitor) */
		l2fwd_periodic_drain_stats_monitor(qconf, &tsc, is_master_core);

		for (i = 0; i < lcore_nb_link; i++) {
			/* Read packet from event queues */
			nb_rx = rte_event_dequeue_burst(links[i].eventdev_id,
					links[i].event_portid,
					ev,             /* events */
					deq_len,        /* nb_events */
					0               /* timeout_ticks */);

			if (nb_rx == 0)
				continue;

			for (j = 0; j < nb_rx; j++) {

				portid = ev[j].queue_id;
				port_statistics[portid].rx++;
				pkt = ev[j].mbuf;

				rte_prefetch0(rte_pktmbuf_mtod(pkt, void *));

				/* Process packet */
				l2fwd_event_pre_forward(&(ev[j]), portid);

				/*
				 * Internal port is not available, the packet
				 * needs to be enqueued to the designated event
				 * queue.
				 */

				/* Update the scheduling type for tx stage */
				l2fwd_event_switch_to_tx_queue(&(ev[j]),
						tx_queue);
			}

			for (j = 0, left = nb_rx;
				j < (nb_rx + enq_len - 1)/enq_len; j++) {

				/* Submit the updated events for tx stage */
				left -= rte_event_enqueue_burst(
					links[i].eventdev_id,
					links[i].event_portid,
					&(ev[j*enq_len]), /* events */
					left > enq_len ?
					enq_len : left /* nb_events */);
			}
		}
	}
	goto clean_and_exit;

clean_and_exit:
	if (links != NULL)
		rte_free(links);
}

static uint8_t
l2fwd_eventmode_populate_wrkr_params(
		struct rte_eventmode_helper_app_worker_params *wrkrs)
{
	uint8_t nb_wrkr_param = 0;
	struct rte_eventmode_helper_app_worker_params *wrkr;

	/* Save workers */
	wrkr = wrkrs;

	/* Non-burst no internal port (regular tx worker) */
	wrkr->cap.burst = RTE_EVENTMODE_HELPER_RX_TYPE_NON_BURST;
	wrkr->cap.tx_internal_port =
			RTE_EVENTMODE_HELPER_TX_TYPE_NO_INTERNAL_PORT;
	wrkr->worker_thread = l2fwd_eventmode_non_burst_no_internal_port;

	nb_wrkr_param++;
	wrkr++;

	/* Non-burst tx internal port */
	wrkr->cap.burst = RTE_EVENTMODE_HELPER_RX_TYPE_NON_BURST;
	wrkr->cap.tx_internal_port =
			RTE_EVENTMODE_HELPER_TX_TYPE_INTERNAL_PORT;
	wrkr->worker_thread = l2fwd_eventmode_non_burst_tx_internal_port;

	nb_wrkr_param++;
	wrkr++;

	/* Burst no internal port (regular tx worker) */
	wrkr->cap.burst = RTE_EVENTMODE_HELPER_RX_TYPE_BURST;
	wrkr->cap.tx_internal_port =
			RTE_EVENTMODE_HELPER_TX_TYPE_NO_INTERNAL_PORT;
	wrkr->worker_thread = l2fwd_eventmode_burst_no_internal_port;

	nb_wrkr_param++;
	return nb_wrkr_param;
}

static void
l2fwd_eventmode_worker(struct rte_eventmode_helper_conf *mode_conf)
{
	struct rte_eventmode_helper_app_worker_params
			l2fwd_wrkr[L2FWD_EVENTMODE_WORKERS] = {
					{{{0} }, NULL } };
	uint8_t nb_wrkr_param;

	/* Populate l2fwd_wrkr params */
	nb_wrkr_param = l2fwd_eventmode_populate_wrkr_params(l2fwd_wrkr);

	/*
	 * The helper function will launch the correct worker after checking the
	 * event device's capabilities.
	 */
	rte_eventmode_helper_launch_worker(mode_conf, l2fwd_wrkr,
			nb_wrkr_param);
}

int
l2fwd_launch_one_lcore(void *args)
{
	struct rte_eventmode_helper_conf *mode_conf;

	mode_conf = (struct rte_eventmode_helper_conf *)args;

	if (mode_conf->mode == RTE_EVENTMODE_HELPER_PKT_TRANSFER_MODE_POLL) {
		/* App is initialized to run in poll mode */
		l2fwd_poll_mode_worker();
	} else if (mode_conf->mode ==
			RTE_EVENTMODE_HELPER_PKT_TRANSFER_MODE_EVENT) {
		/* App is initialized to run in event mode */
		l2fwd_eventmode_worker(mode_conf);
	}
	return 0;
}
