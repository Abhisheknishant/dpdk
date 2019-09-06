/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2019 Marvell International Ltd.
 */

#ifndef __L2FWD_COMMON_H__
#define __L2FWD_COMMON_H__

#define MAX_PKT_BURST 32
#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16

#define RTE_LOGTYPE_L2FWD RTE_LOGTYPE_USER1

struct lcore_queue_conf {
	uint32_t rx_port_list[MAX_RX_QUEUE_PER_LCORE];
	uint32_t n_rx_port;
} __rte_cache_aligned;

/* Per-port statistics struct */
struct l2fwd_port_statistics {
	uint64_t dropped;
	uint64_t tx;
	uint64_t rx;
} __rte_cache_aligned;

extern struct rte_mempool *l2fwd_pktmbuf_pool;

extern struct rte_ether_addr l2fwd_ports_eth_addr[RTE_MAX_ETHPORTS];

extern uint32_t l2fwd_enabled_port_mask;

extern int mac_updating;

extern uint32_t l2fwd_dst_ports[RTE_MAX_ETHPORTS];

extern struct l2fwd_port_statistics port_statistics[RTE_MAX_ETHPORTS];

extern volatile bool force_quit;

extern uint64_t timer_period;

void l2fwd_mac_updating(struct rte_mbuf *m, uint32_t dest_portid);

void print_stats(void);

#endif /* __L2FWD_EVENTDEV_H__ */
