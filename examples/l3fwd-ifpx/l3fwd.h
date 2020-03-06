/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Marvell International Ltd.
 */

#ifndef __L3_FWD_H__
#define __L3_FWD_H__

#include <stdbool.h>

#include <rte_ethdev.h>
#include <rte_log.h>
#include <rte_hash.h>

#define RTE_LOGTYPE_L3FWD RTE_LOGTYPE_USER1

#define MAX_PKT_BURST     32
#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */
#define EV_QUEUE_DRAIN    5   /* Check event queue every 5 TX drains */

#define MAX_RX_QUEUE_PER_LCORE 16

/*
 * Try to avoid TX buffering if we have at least MAX_TX_BURST packets to send.
 */
#define	MAX_TX_BURST	  (MAX_PKT_BURST / 2)

/* Configure how many packets ahead to prefetch, when reading packets */
#define PREFETCH_OFFSET	  3

/* Hash parameters. */
#ifdef RTE_ARCH_64
/* default to 4 million hash entries (approx) */
#define L3FWD_HASH_ENTRIES		(1024*1024*4)
#else
/* 32-bit has less address-space for hugepage memory, limit to 1M entries */
#define L3FWD_HASH_ENTRIES		(1024*1024*1)
#endif
#define HASH_ENTRY_NUMBER_DEFAULT	4
/* Default ARP table size */
#define L3FWD_NEIGH_ENTRIES		1024

union lladdr_t {
	uint64_t val;
	struct {
		struct rte_ether_addr addr;
		uint16_t valid;
	} mac;
};

struct mbuf_table {
	uint16_t len;
	struct rte_mbuf *m_table[MAX_PKT_BURST];
};

struct lcore_rx_queue {
	uint16_t port_id;
	uint16_t dst_port;
	uint8_t queue_id;
} __rte_cache_aligned;

struct lcore_conf {
	uint16_t n_rx_queue;
	struct lcore_rx_queue rx_queue_list[MAX_RX_QUEUE_PER_LCORE];
	uint16_t n_tx_port;
	uint16_t tx_port_id[RTE_MAX_ETHPORTS];
	uint16_t tx_queue_id[RTE_MAX_ETHPORTS];
	struct mbuf_table tx_mbufs[RTE_MAX_ETHPORTS];
	struct rte_ring *ev_queue;
	union lladdr_t *neigh_map;
	struct rte_hash *neigh_hash;
	union lladdr_t *neigh6_map;
	struct rte_hash *neigh6_hash;
} __rte_cache_aligned;

extern volatile bool force_quit;

/* mask of enabled/active ports */
extern uint32_t enabled_port_mask;
extern uint32_t active_port_mask;

extern struct lcore_conf lcore_conf[RTE_MAX_LCORE];

int init_if_proxy(void);
void close_if_proxy(void);

void wait_for_config_done(void);

void setup_lpm(void);

int lpm_check_ptype(int portid);

uint16_t
lpm_cb_parse_ptype(uint16_t port, uint16_t queue, struct rte_mbuf *pkts[],
		   uint16_t nb_pkts, uint16_t max_pkts, void *user_param);

int lpm_main_loop(__attribute__((unused)) void *dummy);

#endif  /* __L3_FWD_H__ */
