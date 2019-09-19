/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2019 Marvell International Ltd.
 */

#ifndef __L2FWD_COMMON_H__
#define __L2FWD_COMMON_H__

#define MAX_PKT_BURST 32
#define MAX_RX_QUEUE_PER_LCORE 16
#define MAX_TX_QUEUE_PER_PORT 16

#define RTE_LOGTYPE_L2FWD RTE_LOGTYPE_USER1

#define RTE_TEST_RX_DESC_DEFAULT 1024
#define RTE_TEST_TX_DESC_DEFAULT 1024

/* Per-port statistics struct */
struct l2fwd_port_statistics {
	uint64_t dropped;
	uint64_t tx;
	uint64_t rx;
} __rte_cache_aligned;

void print_stats(void);

#endif /* __L2FWD_EVENTDEV_H__ */
