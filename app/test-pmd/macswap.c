/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2014-2020 Mellanox Technologies, Ltd
 */

#include <stdarg.h>
#include <string.h>
#include <stdio.h>
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
#include <rte_memcpy.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ip.h>
#include <rte_string_fns.h>
#include <rte_flow.h>

#include "testpmd.h"
#if defined(RTE_ARCH_X86)
#include "macswap_sse.h"
#elif defined(RTE_MACHINE_CPUFLAG_NEON)
#include "macswap_neon.h"
#else
#include "macswap.h"
#endif

/*
 * MAC swap forwarding mode: Swap the source and the destination Ethernet
 * addresses of packets before forwarding them.
 */
static void
pkt_burst_mac_swap(struct fwd_stream *fs)
{
	struct rte_mbuf  *pkts_burst[MAX_PKT_BURST];
	struct rte_port  *txp;
	uint16_t nb_rx;
	uint16_t nb_tx;
	uint32_t retry;
#ifdef RTE_TEST_PMD_RECORD_CORE_CYCLES
	uint64_t start_rx_tsc = 0;
	uint64_t start_tx_tsc = 0;
#endif

	/*
	 * Receive a burst of packets and forward them.
	 */
	TEST_PMD_CORE_CYC_RX_START(start_rx_tsc);
	nb_rx = rte_eth_rx_burst(fs->rx_port, fs->rx_queue, pkts_burst,
				 nb_pkt_per_burst);
	TEST_PMD_CORE_CYC_RX_ADD(fs, start_rx_tsc);
	if (unlikely(nb_rx == 0))
		return;

#ifdef RTE_TEST_PMD_RECORD_BURST_STATS
	fs->rx_burst_stats.pkt_burst_spread[nb_rx]++;
#endif
	fs->rx_packets += nb_rx;
	txp = &ports[fs->tx_port];

	do_macswap(pkts_burst, nb_rx, txp);

	TEST_PMD_CORE_CYC_TX_START(start_tx_tsc);
	nb_tx = rte_eth_tx_burst(fs->tx_port, fs->tx_queue, pkts_burst, nb_rx);
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

struct fwd_engine mac_swap_engine = {
	.fwd_mode_name  = "macswap",
	.port_fwd_begin = NULL,
	.port_fwd_end   = NULL,
	.packet_fwd     = pkt_burst_mac_swap,
};
