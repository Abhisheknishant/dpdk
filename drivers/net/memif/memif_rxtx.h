/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2019 Cisco Systems, Inc.  All rights reserved.
 */

#ifndef _MEMIF_RX_TX_H_
#define _MEMIF_RX_TX_H_

#include "memif.h"

/**
 * Ger memif ring from shared memory.
 *
 * @param pmd
 *   device internals
 * @param type
 *   memif ring direction
 * @param ring_idx
 *   ring index
 *
 * @return
 *   - memif ring
 */

uint16_t
eth_memif_rx(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts);

uint16_t
eth_memif_rx_zc(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts);

uint16_t
eth_memif_tx(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts);

uint16_t
eth_memif_tx_zc(void *queue, struct rte_mbuf **bufs, uint16_t nb_pkts);

#endif /* MEMIF_RX_TX_H */
