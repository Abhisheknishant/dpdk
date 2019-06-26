/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdint.h>
#include <unistd.h>
#include <inttypes.h>

#include <sys/queue.h>
#include <sys/stat.h>

#include <rte_common.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_cycles.h>
#include <rte_memory.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_memcpy.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_string_fns.h>
#include <rte_flow.h>

#include "testpmd.h"

/*
 * Forwarding of packets in I/O mode.
 * Forward packets "as-is".
 * This is the fastest possible forwarding operation, as it does not access
 * to packets data.
 */
static void
pkt_burst_io_forward(struct fwd_stream *fs)
{
	struct rte_mbuf *pkts_burst[MAX_PKT_BURST];
	uint16_t nb_rx;
	uint16_t nb_tx;
	uint32_t retry;

#if defined(RTE_TEST_PMD_RECORD_CORE_TX_CYCLES)
	uint64_t start_tx_tsc;
#endif
#if defined(RTE_TEST_PMD_RECORD_CORE_CYCLES) || \
	defined(RTE_TEST_PMD_RECORD_CORE_RX_CYCLES)
	uint64_t start_rx_tsc;
#endif

	/*
	 * Receive a burst of packets and forward them.
	 */
	TEST_PMD_CORE_CYC_RX_START(start_rx_tsc);
	nb_rx = rte_eth_rx_burst(fs->rx_port, fs->rx_queue,
			pkts_burst, nb_pkt_per_burst);
	TEST_PMD_CORE_CYC_RX_ADD(fs, start_rx_tsc);
	if (unlikely(nb_rx == 0))
		return;
	fs->rx_packets += nb_rx;

#ifdef RTE_TEST_PMD_RECORD_BURST_STATS
	fs->rx_burst_stats.pkt_burst_spread[nb_rx]++;
#endif
	TEST_PMD_CORE_CYC_TX_START(start_tx_tsc);
	nb_tx = rte_eth_tx_burst(fs->tx_port, fs->tx_queue,
			pkts_burst, nb_rx);
	TEST_PMD_CORE_CYC_TX_ADD(fs, start_tx_tsc);
	/*
	 * Retry if necessary
	 */
	if (unlikely(nb_tx < nb_rx) && fs->retry_enabled) {
		retry = 0;
		while (nb_tx < nb_rx && retry++ < burst_tx_retry_num) {
			rte_delay_us(burst_tx_delay_time);
			TEST_PMD_CORE_CYC_TX_START(start_tx_tsc);
			nb_tx += rte_eth_tx_burst(fs->tx_port, fs->tx_queue,
					&pkts_burst[nb_tx], nb_rx - nb_tx);
			TEST_PMD_CORE_CYC_TX_ADD(fs, start_tx_tsc);
		}
	}
	fs->tx_packets += nb_tx;
#ifdef RTE_TEST_PMD_RECORD_BURST_STATS
	fs->tx_burst_stats.pkt_burst_spread[nb_tx]++;
#endif
	if (unlikely(nb_tx < nb_rx)) {
		fs->fwd_dropped += (nb_rx - nb_tx);
		do {
			rte_pktmbuf_free(pkts_burst[nb_tx]);
		} while (++nb_tx < nb_rx);
	}
	TEST_PMD_CORE_CYC_FWD_ADD(fs, start_rx_tsc);
}

struct fwd_engine io_fwd_engine = {
	.fwd_mode_name  = "io",
	.port_fwd_begin = NULL,
	.port_fwd_end   = NULL,
	.packet_fwd     = pkt_burst_io_forward,
};
