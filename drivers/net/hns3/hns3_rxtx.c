/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2019 Hisilicon Limited.
 */

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <rte_bus_pci.h>
#include <rte_byteorder.h>
#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_debug.h>
#include <rte_dev.h>
#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_ethdev_driver.h>
#include <rte_io.h>
#include <rte_malloc.h>
#include <rte_pci.h>
#include <rte_spinlock.h>

#include "hns3_cmd.h"
#include "hns3_mbx.h"
#include "hns3_rss.h"
#include "hns3_fdir.h"
#include "hns3_stats.h"
#include "hns3_ethdev.h"
#include "hns3_rxtx.h"
#include "hns3_regs.h"
#include "hns3_logs.h"

#define HNS3_CFG_DESC_NUM(num)	((num) / 8 - 1)
#define DEFAULT_RX_FREE_THRESH	16

static void
hns3_rx_queue_release_mbufs(struct hns3_rx_queue *rxq)
{
	uint16_t i;

	if (rxq->sw_ring) {
		for (i = 0; i < rxq->nb_rx_desc; i++) {
			if (rxq->sw_ring[i].mbuf) {
				rte_pktmbuf_free_seg(rxq->sw_ring[i].mbuf);
				rxq->sw_ring[i].mbuf = NULL;
			}
		}
	}
}

static void
hns3_tx_queue_release_mbufs(struct hns3_tx_queue *txq)
{
	uint16_t i;

	if (txq->sw_ring) {
		for (i = 0; i < txq->nb_tx_desc; i++) {
			if (txq->sw_ring[i].mbuf) {
				rte_pktmbuf_free_seg(txq->sw_ring[i].mbuf);
				txq->sw_ring[i].mbuf = NULL;
			}
		}
	}
}

static void
hns3_rx_queue_release(void *queue)
{
	struct hns3_rx_queue *rxq = queue;
	if (rxq) {
		hns3_rx_queue_release_mbufs(rxq);
		if (rxq->mz)
			rte_memzone_free(rxq->mz);
		if (rxq->sw_ring)
			rte_free(rxq->sw_ring);
		rte_free(rxq);
	}
}

static void
hns3_tx_queue_release(void *queue)
{
	struct hns3_tx_queue *txq = queue;
	if (txq) {
		hns3_tx_queue_release_mbufs(txq);
		if (txq->mz)
			rte_memzone_free(txq->mz);
		if (txq->sw_ring)
			rte_free(txq->sw_ring);
		rte_free(txq);
	}
}

void
hns3_dev_rx_queue_release(void *queue)
{
	struct hns3_rx_queue *rxq = queue;
	struct hns3_adapter *hns;

	if (rxq == NULL)
		return;

	hns = rxq->hns;
	rte_spinlock_lock(&hns->hw.lock);
	hns3_rx_queue_release(queue);
	rte_spinlock_unlock(&hns->hw.lock);
}

void
hns3_dev_tx_queue_release(void *queue)
{
	struct hns3_tx_queue *txq = queue;
	struct hns3_adapter *hns;

	if (txq == NULL)
		return;

	hns = txq->hns;
	rte_spinlock_lock(&hns->hw.lock);
	hns3_tx_queue_release(queue);
	rte_spinlock_unlock(&hns->hw.lock);
}

void
hns3_free_all_queues(struct rte_eth_dev *dev)
{
	uint16_t i;

	if (dev->data->rx_queues)
		for (i = 0; i < dev->data->nb_rx_queues; i++) {
			hns3_rx_queue_release(dev->data->rx_queues[i]);
			dev->data->rx_queues[i] = NULL;
		}

	if (dev->data->tx_queues)
		for (i = 0; i < dev->data->nb_tx_queues; i++) {
			hns3_tx_queue_release(dev->data->tx_queues[i]);
			dev->data->tx_queues[i] = NULL;
		}
}

static int
hns3_alloc_rx_queue_mbufs(struct hns3_hw *hw, struct hns3_rx_queue *rxq)
{
	struct rte_mbuf *mbuf;
	uint64_t dma_addr;
	uint16_t i;

	for (i = 0; i < rxq->nb_rx_desc; i++) {
		mbuf = rte_mbuf_raw_alloc(rxq->mb_pool);
		if (unlikely(mbuf == NULL)) {
			hns3_err(hw, "Failed to allocate RXD[%d] for rx queue!",
				 i);
			hns3_rx_queue_release_mbufs(rxq);
			return -ENOMEM;
		}

		rte_mbuf_refcnt_set(mbuf, 1);
		mbuf->next = NULL;
		mbuf->data_off = RTE_PKTMBUF_HEADROOM;
		mbuf->nb_segs = 1;
		mbuf->port = rxq->port_id;

		rxq->sw_ring[i].mbuf = mbuf;
		dma_addr = rte_cpu_to_le_64(rte_mbuf_data_iova_default(mbuf));
		rxq->rx_ring[i].addr = dma_addr;
		rxq->rx_ring[i].rx.bd_base_info = 0;
	}

	return 0;
}

static int
hns3_buf_size2type(uint32_t buf_size)
{
	int bd_size_type;

	switch (buf_size) {
	case 512:
		bd_size_type = HNS3_BD_SIZE_512_TYPE;
		break;
	case 1024:
		bd_size_type = HNS3_BD_SIZE_1024_TYPE;
		break;
	case 4096:
		bd_size_type = HNS3_BD_SIZE_4096_TYPE;
		break;
	default:
		bd_size_type = HNS3_BD_SIZE_2048_TYPE;
	}

	return bd_size_type;
}

static void
hns3_init_rx_queue_hw(struct hns3_rx_queue *rxq)
{
	uint32_t rx_buf_len = rxq->rx_buf_len;
	uint64_t dma_addr = rxq->rx_ring_phys_addr;

	hns3_write_dev(rxq, HNS3_RING_RX_BASEADDR_L_REG, (uint32_t)dma_addr);
	hns3_write_dev(rxq, HNS3_RING_RX_BASEADDR_H_REG,
		       (uint32_t)((dma_addr >> 31) >> 1));

	hns3_write_dev(rxq, HNS3_RING_RX_BD_LEN_REG,
		       hns3_buf_size2type(rx_buf_len));
	hns3_write_dev(rxq, HNS3_RING_RX_BD_NUM_REG,
		       HNS3_CFG_DESC_NUM(rxq->nb_rx_desc));
}

static void
hns3_init_tx_queue_hw(struct hns3_tx_queue *txq)
{
	uint64_t dma_addr = txq->tx_ring_phys_addr;

	hns3_write_dev(txq, HNS3_RING_TX_BASEADDR_L_REG, (uint32_t)dma_addr);
	hns3_write_dev(txq, HNS3_RING_TX_BASEADDR_H_REG,
		       (uint32_t)((dma_addr >> 31) >> 1));

	hns3_write_dev(txq, HNS3_RING_TX_BD_NUM_REG,
		       HNS3_CFG_DESC_NUM(txq->nb_tx_desc));
}

static void
hns3_enable_all_queues(struct hns3_hw *hw, bool en)
{
	struct hns3_rx_queue *rxq;
	struct hns3_tx_queue *txq;
	uint32_t rcb_reg;
	int i;

	for (i = 0; i < hw->data->nb_rx_queues; i++) {
		rxq = hw->data->rx_queues[i];
		txq = hw->data->tx_queues[i];
		if (rxq == NULL || txq == NULL ||
		    (en && (rxq->rx_deferred_start || txq->tx_deferred_start)))
			continue;
		rcb_reg = hns3_read_dev(rxq, HNS3_RING_EN_REG);
		if (en)
			rcb_reg |= BIT(HNS3_RING_EN_B);
		else
			rcb_reg &= ~BIT(HNS3_RING_EN_B);
		hns3_write_dev(rxq, HNS3_RING_EN_REG, rcb_reg);
	}
}

static int
hns3_tqp_enable(struct hns3_hw *hw, uint16_t queue_id, bool enable)
{
	struct hns3_cfg_com_tqp_queue_cmd *req;
	struct hns3_cmd_desc desc;
	int ret;

	req = (struct hns3_cfg_com_tqp_queue_cmd *)desc.data;

	hns3_cmd_setup_basic_desc(&desc, HNS3_OPC_CFG_COM_TQP_QUEUE, false);
	req->tqp_id = rte_cpu_to_le_16(queue_id & HNS3_RING_ID_MASK);
	req->stream_id = 0;
	hns3_set_bit(req->enable, HNS3_TQP_ENABLE_B, enable ? 1 : 0);

	ret = hns3_cmd_send(hw, &desc, 1);
	if (ret)
		hns3_err(hw, "TQP enable fail, ret = %d", ret);

	return ret;
}

static int
hns3_send_reset_tqp_cmd(struct hns3_hw *hw, uint16_t queue_id, bool enable)
{
	struct hns3_reset_tqp_queue_cmd *req;
	struct hns3_cmd_desc desc;
	int ret;

	hns3_cmd_setup_basic_desc(&desc, HNS3_OPC_RESET_TQP_QUEUE, false);

	req = (struct hns3_reset_tqp_queue_cmd *)desc.data;
	req->tqp_id = rte_cpu_to_le_16(queue_id & HNS3_RING_ID_MASK);
	hns3_set_bit(req->reset_req, HNS3_TQP_RESET_B, enable ? 1 : 0);

	ret = hns3_cmd_send(hw, &desc, 1);
	if (ret)
		hns3_err(hw, "Send tqp reset cmd error, ret = %d", ret);

	return ret;
}

static int
hns3_get_reset_status(struct hns3_hw *hw, uint16_t queue_id)
{
	struct hns3_reset_tqp_queue_cmd *req;
	struct hns3_cmd_desc desc;
	int ret;

	hns3_cmd_setup_basic_desc(&desc, HNS3_OPC_RESET_TQP_QUEUE, true);

	req = (struct hns3_reset_tqp_queue_cmd *)desc.data;
	req->tqp_id = rte_cpu_to_le_16(queue_id & HNS3_RING_ID_MASK);

	ret = hns3_cmd_send(hw, &desc, 1);
	if (ret) {
		hns3_err(hw, "Get reset status error, ret =%d", ret);
		return ret;
	}

	return hns3_get_bit(req->ready_to_reset, HNS3_TQP_RESET_B);
}

static int
hns3_reset_tqp(struct hns3_hw *hw, uint16_t queue_id)
{
#define HNS3_TQP_RESET_TRY_MS	200
	uint64_t end;
	int reset_status;
	int ret;

	ret = hns3_tqp_enable(hw, queue_id, false);
	if (ret)
		return ret;

	/*
	 * In current version VF is not supported when PF is taken over by DPDK,
	 * all task queue pairs are mapped to PF function, so PF's queue id is
	 * equals to the global queue id in PF range.
	 */
	ret = hns3_send_reset_tqp_cmd(hw, queue_id, true);
	if (ret) {
		hns3_err(hw, "Send reset tqp cmd fail, ret = %d", ret);
		return ret;
	}
	ret = -ETIMEDOUT;
	end = get_timeofday_ms() + HNS3_TQP_RESET_TRY_MS;
	do {
		/* Wait for tqp hw reset */
		rte_delay_ms(HNS3_POLL_RESPONE_MS);
		reset_status = hns3_get_reset_status(hw, queue_id);
		if (reset_status) {
			ret = 0;
			break;
		}
	} while (get_timeofday_ms() < end);

	if (ret) {
		hns3_err(hw, "Reset TQP fail, ret = %d", ret);
		return ret;
	}

	ret = hns3_send_reset_tqp_cmd(hw, queue_id, false);
	if (ret)
		hns3_err(hw, "Deassert the soft reset fail, ret = %d", ret);

	return ret;
}

static int
hns3vf_reset_tqp(struct hns3_hw *hw, uint16_t queue_id)
{
	uint8_t msg_data[2];
	int ret;

	/* Disable VF's queue before send queue reset msg to PF */
	ret = hns3_tqp_enable(hw, queue_id, false);
	if (ret)
		return ret;

	memcpy(msg_data, &queue_id, sizeof(uint16_t));

	return hns3_send_mbx_msg(hw, HNS3_MBX_QUEUE_RESET, 0, msg_data,
				 sizeof(msg_data), true, NULL, 0);
}

static int
hns3_reset_queue(struct hns3_adapter *hns, uint16_t queue_id)
{
	struct hns3_hw *hw = &hns->hw;
	if (hns->is_vf)
		return hns3vf_reset_tqp(hw, queue_id);
	else
		return hns3_reset_tqp(hw, queue_id);
}

int
hns3_reset_all_queues(struct hns3_adapter *hns)
{
	struct hns3_hw *hw = &hns->hw;
	int ret;
	uint16_t i;

	for (i = 0; i < hw->data->nb_rx_queues; i++) {
		ret = hns3_reset_queue(hns, i);
		if (ret) {
			hns3_err(hw, "Failed to reset No.%d queue: %d", i, ret);
			return ret;
		}
	}
	return 0;
}

static int
hns3_dev_rx_queue_start(struct hns3_adapter *hns, uint16_t idx)
{
	struct hns3_hw *hw = &hns->hw;
	struct hns3_rx_queue *rxq;
	int ret;

	PMD_INIT_FUNC_TRACE();

	rxq = hw->data->rx_queues[idx];

	ret = hns3_alloc_rx_queue_mbufs(hw, rxq);
	if (ret) {
		hns3_err(hw, "Failed to alloc mbuf for No.%d rx queue: %d",
			    idx, ret);
		return ret;
	}

	rxq->next_to_use = 0;
	rxq->next_to_clean = 0;
	hns3_init_rx_queue_hw(rxq);

	return 0;
}

static void
hns3_dev_tx_queue_start(struct hns3_adapter *hns, uint16_t idx)
{
	struct hns3_hw *hw = &hns->hw;
	struct hns3_tx_queue *txq;
	struct hns3_desc *desc;
	int i;

	txq = hw->data->tx_queues[idx];

	/* Clear tx bd */
	desc = txq->tx_ring;
	for (i = 0; i < txq->nb_tx_desc; i++) {
		desc->tx.tp_fe_sc_vld_ra_ri = 0;
		desc++;
	}

	txq->next_to_use = 0;
	txq->next_to_clean = 0;
	txq->tx_bd_ready   = txq->nb_tx_desc;
	hns3_init_tx_queue_hw(txq);
}

static void
hns3_init_tx_ring_tc(struct hns3_adapter *hns)
{
	struct hns3_hw *hw = &hns->hw;
	struct hns3_tx_queue *txq;
	int i, num;

	for (i = 0; i < HNS3_MAX_TC_NUM; i++) {
		struct hns3_tc_queue_info *tc_queue = &hw->tc_queue[i];
		int j;

		if (!tc_queue->enable)
			continue;

		for (j = 0; j < tc_queue->tqp_count; j++) {
			num = tc_queue->tqp_offset + j;
			txq = hw->data->tx_queues[num];
			if (txq == NULL)
				continue;

			hns3_write_dev(txq, HNS3_RING_TX_TC_REG, tc_queue->tc);
		}
	}
}

int
hns3_start_queues(struct hns3_adapter *hns, bool reset_queue)
{
	struct hns3_hw *hw = &hns->hw;
	struct rte_eth_dev_data *dev_data = hw->data;
	struct hns3_rx_queue *rxq;
	struct hns3_tx_queue *txq;
	int ret;
	int i;
	int j;

	/* Initialize RSS for queues */
	ret = hns3_config_rss(hns);
	if (ret) {
		hns3_err(hw, "Failed to configure rss %d", ret);
		return ret;
	}

	if (reset_queue) {
		ret = hns3_reset_all_queues(hns);
		if (ret) {
			hns3_err(hw, "Failed to reset all queues %d", ret);
			return ret;
		}
	}

	/*
	 * Hardware does not support where the number of rx and tx queues is
	 * not equal in hip08. In .dev_configure callback function we will
	 * check the two values, here we think that the number of rx and tx
	 * queues is equal.
	 */
	for (i = 0; i < hw->data->nb_rx_queues; i++) {
		rxq = dev_data->rx_queues[i];
		txq = dev_data->tx_queues[i];
		if (rxq == NULL || txq == NULL || rxq->rx_deferred_start ||
		    txq->tx_deferred_start)
			continue;

		ret = hns3_dev_rx_queue_start(hns, i);
		if (ret) {
			hns3_err(hw, "Failed to start No.%d rx queue: %d", i,
				 ret);
			goto out;
		}
		hns3_dev_tx_queue_start(hns, i);
	}
	hns3_init_tx_ring_tc(hns);

	hns3_enable_all_queues(hw, true);
	return 0;

out:
	for (j = 0; j < i; j++) {
		rxq = dev_data->rx_queues[j];
		hns3_rx_queue_release_mbufs(rxq);
	}

	return ret;
}

int
hns3_stop_queues(struct hns3_adapter *hns, bool reset_queue)
{
	struct hns3_hw *hw = &hns->hw;
	int ret;

	hns3_enable_all_queues(hw, false);
	if (reset_queue) {
		ret = hns3_reset_all_queues(hns);
		if (ret) {
			hns3_err(hw, "Failed to reset all queues %d", ret);
			return ret;
		}
	}
	return 0;
}

void
hns3_dev_release_mbufs(struct hns3_adapter *hns)
{
	struct rte_eth_dev_data *dev_data = hns->hw.data;
	struct hns3_rx_queue *rxq;
	struct hns3_tx_queue *txq;
	int i;

	if (dev_data->rx_queues)
		for (i = 0; i < dev_data->nb_rx_queues; i++) {
			rxq = dev_data->rx_queues[i];
			if (rxq == NULL || rxq->rx_deferred_start)
				continue;
			hns3_rx_queue_release_mbufs(rxq);
		}

	if (dev_data->tx_queues)
		for (i = 0; i < dev_data->nb_tx_queues; i++) {
			txq = dev_data->tx_queues[i];
			if (txq == NULL || txq->tx_deferred_start)
				continue;
			hns3_tx_queue_release_mbufs(txq);
		}
}

int
hns3_rx_queue_setup(struct rte_eth_dev *dev, uint16_t idx, uint16_t nb_desc,
		    unsigned int socket_id, const struct rte_eth_rxconf *conf,
		    struct rte_mempool *mp)
{
	struct hns3_adapter *hns = dev->data->dev_private;
	const struct rte_memzone *rx_mz;
	struct hns3_hw *hw = &hns->hw;
	struct hns3_rx_queue *rxq;
	unsigned int desc_size = sizeof(struct hns3_desc);
	unsigned int rx_desc;
	int rx_entry_len;

	if (dev->data->dev_started) {
		hns3_err(hw, "rx_queue_setup after dev_start no supported");
		return -EINVAL;
	}

	if (nb_desc > HNS3_MAX_RING_DESC || nb_desc < HNS3_MIN_RING_DESC ||
	    nb_desc % HNS3_ALIGN_RING_DESC) {
		hns3_err(hw, "Number (%u) of rx descriptors is invalid",
			 nb_desc);
		return -EINVAL;
	}

	if (dev->data->rx_queues[idx]) {
		hns3_rx_queue_release(dev->data->rx_queues[idx]);
		dev->data->rx_queues[idx] = NULL;
	}

	rxq = rte_zmalloc_socket("hns3 RX queue", sizeof(struct hns3_rx_queue),
				 RTE_CACHE_LINE_SIZE, socket_id);
	if (rxq == NULL) {
		hns3_err(hw, "Failed to allocate memory for rx queue!");
		return -ENOMEM;
	}

	rxq->hns = hns;
	rxq->mb_pool = mp;
	rxq->nb_rx_desc = nb_desc;
	rxq->queue_id = idx;
	if (conf->rx_free_thresh <= 0)
		rxq->rx_free_thresh = DEFAULT_RX_FREE_THRESH;
	else
		rxq->rx_free_thresh = conf->rx_free_thresh;
	rxq->rx_deferred_start = conf->rx_deferred_start;

	rx_entry_len = sizeof(struct hns3_entry) * rxq->nb_rx_desc;
	rxq->sw_ring = rte_zmalloc_socket("hns3 RX sw ring", rx_entry_len,
					  RTE_CACHE_LINE_SIZE, socket_id);
	if (rxq->sw_ring == NULL) {
		hns3_err(hw, "Failed to allocate memory for rx sw ring!");
		hns3_rx_queue_release(rxq);
		return -ENOMEM;
	}

	/* Allocate rx ring hardware descriptors. */
	rx_desc = rxq->nb_rx_desc * desc_size;
	rx_mz = rte_eth_dma_zone_reserve(dev, "rx_ring", idx, rx_desc,
					 HNS3_RING_BASE_ALIGN, socket_id);
	if (rx_mz == NULL) {
		hns3_err(hw, "Failed to reserve DMA memory for No.%d rx ring!",
			 idx);
		hns3_rx_queue_release(rxq);
		return -ENOMEM;
	}
	rxq->mz = rx_mz;
	rxq->rx_ring = (struct hns3_desc *)rx_mz->addr;
	rxq->rx_ring_phys_addr = rx_mz->iova;

	hns3_dbg(hw, "No.%d rx descriptors iova 0x%lx", idx,
		 rxq->rx_ring_phys_addr);

	rxq->next_to_use = 0;
	rxq->next_to_clean = 0;
	rxq->nb_rx_hold = 0;
	rxq->pkt_first_seg = NULL;
	rxq->pkt_last_seg = NULL;
	rxq->port_id = dev->data->port_id;
	rxq->configured = true;
	rxq->io_base = (void *)((char *)hw->io_base + HNS3_TQP_REG_OFFSET +
				idx * HNS3_TQP_REG_SIZE);
	rxq->rx_buf_len = hw->rx_buf_len;
	rxq->non_vld_descs = 0;
	rxq->l2_errors = 0;
	rxq->csum_erros = 0;
	rxq->pkt_len_errors = 0;
	rxq->errors = 0;

	rte_spinlock_lock(&hw->lock);
	dev->data->rx_queues[idx] = rxq;
	rte_spinlock_unlock(&hw->lock);

	return 0;
}

static inline uint32_t
rxd_pkt_info_to_pkt_type(uint32_t pkt_info)
{
#define HNS3_L2TBL_NUM	4
#define HNS3_L3TBL_NUM	16
#define HNS3_L4TBL_NUM	16
	uint32_t pkt_type = 0;
	uint32_t l2id, l3id, l4id;

	static const uint32_t l2table[HNS3_L2TBL_NUM] = {
		RTE_PTYPE_L2_ETHER,
		RTE_PTYPE_L2_ETHER_VLAN,
		RTE_PTYPE_L2_ETHER_QINQ,
		0
	};

	static const uint32_t l3table[HNS3_L3TBL_NUM] = {
		RTE_PTYPE_L3_IPV4,
		RTE_PTYPE_L3_IPV6,
		RTE_PTYPE_L2_ETHER_ARP,
		RTE_PTYPE_L2_ETHER,
		RTE_PTYPE_L3_IPV4_EXT,
		RTE_PTYPE_L3_IPV6_EXT,
		RTE_PTYPE_L2_ETHER_LLDP,
		0, 0, 0, 0, 0, 0, 0, 0, 0
	};

	static const uint32_t l4table[HNS3_L4TBL_NUM] = {
		RTE_PTYPE_L4_UDP,
		RTE_PTYPE_L4_TCP,
		RTE_PTYPE_TUNNEL_GRE,
		RTE_PTYPE_L4_SCTP,
		RTE_PTYPE_L4_IGMP,
		RTE_PTYPE_L4_ICMP,
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	};

	l2id = hns3_get_field(pkt_info, HNS3_RXD_STRP_TAGP_M,
			      HNS3_RXD_STRP_TAGP_S);
	l3id = hns3_get_field(pkt_info, HNS3_RXD_L3ID_M, HNS3_RXD_L3ID_S);
	l4id = hns3_get_field(pkt_info, HNS3_RXD_L4ID_M, HNS3_RXD_L4ID_S);
	pkt_type |= (l2table[l2id] | l3table[l3id] | l4table[l4id]);

	return pkt_type;
}

const uint32_t *
hns3_dev_supported_ptypes_get(struct rte_eth_dev *dev)
{
	static const uint32_t ptypes[] = {
		RTE_PTYPE_L2_ETHER,
		RTE_PTYPE_L2_ETHER_VLAN,
		RTE_PTYPE_L2_ETHER_QINQ,
		RTE_PTYPE_L2_ETHER_LLDP,
		RTE_PTYPE_L2_ETHER_ARP,
		RTE_PTYPE_L3_IPV4,
		RTE_PTYPE_L3_IPV4_EXT,
		RTE_PTYPE_L3_IPV6,
		RTE_PTYPE_L3_IPV6_EXT,
		RTE_PTYPE_L4_IGMP,
		RTE_PTYPE_L4_ICMP,
		RTE_PTYPE_L4_SCTP,
		RTE_PTYPE_L4_TCP,
		RTE_PTYPE_L4_UDP,
		RTE_PTYPE_TUNNEL_GRE,
		RTE_PTYPE_UNKNOWN
	};

	if (dev->rx_pkt_burst == hns3_recv_pkts)
		return ptypes;

	return NULL;
}

static void
hns3_clean_rx_buffers(struct hns3_rx_queue *rxq, int count)
{
	rxq->next_to_use += count;
	if (rxq->next_to_use >= rxq->nb_rx_desc)
		rxq->next_to_use -= rxq->nb_rx_desc;

	hns3_write_dev(rxq, HNS3_RING_RX_HEAD_REG, count);
}

static int
hns3_handle_bdinfo(struct hns3_rx_queue *rxq, uint16_t pkt_len,
		   uint32_t bd_base_info, uint32_t l234_info)
{
	if (unlikely(l234_info & BIT(HNS3_RXD_L2E_B))) {
		rxq->l2_errors++;
		return -EINVAL;
	}

	if (unlikely(pkt_len == 0 || (l234_info & BIT(HNS3_RXD_TRUNCAT_B)))) {
		rxq->pkt_len_errors++;
		return -EINVAL;
	}

	if ((bd_base_info & BIT(HNS3_RXD_L3L4P_B)) &&
	      unlikely(l234_info & (BIT(HNS3_RXD_L3E_B) | BIT(HNS3_RXD_L4E_B) |
		       BIT(HNS3_RXD_OL3E_B) | BIT(HNS3_RXD_OL4E_B)))) {
		rxq->csum_erros++;
		return -EINVAL;
	}

	return 0;
}

uint16_t
hns3_recv_pkts(void *rx_queue, struct rte_mbuf **rx_pkts, uint16_t nb_pkts)
{
	struct hns3_rx_queue *rxq;      /* RX queue */
	struct hns3_desc *rx_ring;      /* RX ring (desc) */
	struct hns3_entry *sw_ring;
	struct hns3_entry *rxe;
	struct hns3_desc *rxdp;         /* pointer of the current desc */
	struct rte_mbuf *first_seg;
	struct rte_mbuf *last_seg;
	struct rte_mbuf *nmb;           /* pointer of the new mbuf */
	struct rte_mbuf *rxm;
	struct rte_eth_dev *dev;
	struct hns3_hw *hw;
	uint32_t bd_base_info;
	uint32_t l234_info;
	uint64_t dma_addr;
	uint16_t data_len;
	uint16_t nb_rx_bd;
	uint16_t pkt_len;
	uint16_t nb_rx;
	uint16_t rx_id;
	int num;                        /* num of desc in ring */
	int ret;

	nb_rx = 0;
	nb_rx_bd = 0;
	rxq = rx_queue;
	dev = &rte_eth_devices[rxq->port_id];
	hw = HNS3_DEV_PRIVATE_TO_HW(dev->data->dev_private);

	rx_id = rxq->next_to_clean;
	rx_ring = rxq->rx_ring;
	first_seg = rxq->pkt_first_seg;
	last_seg = rxq->pkt_last_seg;
	sw_ring = rxq->sw_ring;

	/* Get num of packets in desc ring */
	num = hns3_read_dev(rxq, HNS3_RING_RX_FBDNUM_REG);
	while (nb_rx_bd < num && nb_rx < nb_pkts) {
		rxdp = &rx_ring[rx_id];
		bd_base_info = rte_le_to_cpu_32(rxdp->rx.bd_base_info);
		rte_cio_rmb();
		if (unlikely(!hns3_get_bit(bd_base_info, HNS3_RXD_VLD_B))) {
			nb_rx_bd++;
			rx_id++;
			if (unlikely(rx_id == rxq->nb_rx_desc))
				rx_id = 0;
			rxq->non_vld_descs++;
			break;
		}

		nmb = rte_mbuf_raw_alloc(rxq->mb_pool);
		if (unlikely(nmb == NULL)) {
			dev->data->rx_mbuf_alloc_failed++;
			break;
		}

		nb_rx_bd++;
		rxe = &sw_ring[rx_id];
		rx_id++;
		if (rx_id == rxq->nb_rx_desc)
			rx_id = 0;

		rte_prefetch0(rxe->mbuf);
		if ((rx_id & 0x3) == 0) {
			rte_prefetch0(&rx_ring[rx_id]);
			rte_prefetch0(&sw_ring[rx_id]);
		}

		rxm = rxe->mbuf;
		rxe->mbuf = nmb;

		dma_addr = rte_cpu_to_le_64(rte_mbuf_data_iova_default(nmb));
		rxdp->addr = dma_addr;
		rxdp->rx.bd_base_info = 0;

		data_len = (uint16_t)(rte_le_to_cpu_16(rxdp->rx.size));
		l234_info = rte_le_to_cpu_32(rxdp->rx.l234_info);

		if (first_seg == NULL) {
			first_seg = rxm;
			first_seg->nb_segs = 1;
		} else {
			first_seg->nb_segs++;
			last_seg->next = rxm;
		}

		rxm->data_off = RTE_PKTMBUF_HEADROOM;
		rxm->data_len = data_len;

		if (!hns3_get_bit(bd_base_info, HNS3_RXD_FE_B)) {
			last_seg = rxm;
			continue;
		}

		/* The last buffer of the received packet */
		pkt_len = (uint16_t)(rte_le_to_cpu_16(rxdp->rx.pkt_len));
		first_seg->pkt_len = pkt_len;
		first_seg->port = rxq->port_id;
		first_seg->hash.rss = rxdp->rx.rss_hash;
		if (unlikely(hns3_get_bit(bd_base_info, HNS3_RXD_LUM_B))) {
			first_seg->hash.fdir.hi =
				rte_le_to_cpu_32(rxdp->rx.fd_id);
			first_seg->ol_flags |= PKT_RX_FDIR | PKT_RX_FDIR_ID;
		}
		rxm->next = NULL;

		ret = hns3_handle_bdinfo(rxq, pkt_len, bd_base_info, l234_info);
		if (unlikely(ret))
			goto pkt_err;

		first_seg->packet_type = rxd_pkt_info_to_pkt_type(l234_info);
		first_seg->vlan_tci = rxdp->rx.vlan_tag;
		first_seg->vlan_tci_outer = rxdp->rx.ot_vlan_tag;
		rx_pkts[nb_rx++] = first_seg;
		first_seg = NULL;
		continue;
pkt_err:
		rte_pktmbuf_free(first_seg);
		first_seg = NULL;
		rxq->errors++;
		hns3_dbg(hw, "Found pkt err in Port %d No.%d Rx queue, "
			     "rx bd: l234_info 0x%x, bd_base_info 0x%x, "
			     "addr 0x%x, 0x%x, pkt_len 0x%x, size 0x%x",
			     rxq->port_id, rxq->queue_id, l234_info,
			     bd_base_info, rxdp->addr0, rxdp->addr1,
			     rxdp->rx.pkt_len, rxdp->rx.size);
	}

	rxq->next_to_clean = rx_id;
	rxq->pkt_first_seg = first_seg;
	rxq->pkt_last_seg = last_seg;
	hns3_clean_rx_buffers(rxq, nb_rx_bd);

	return nb_rx;
}

int
hns3_tx_queue_setup(struct rte_eth_dev *dev, uint16_t idx, uint16_t nb_desc,
		    unsigned int socket_id, const struct rte_eth_txconf *conf)
{
	struct hns3_adapter *hns = dev->data->dev_private;
	const struct rte_memzone *tx_mz;
	struct hns3_hw *hw = &hns->hw;
	struct hns3_tx_queue *txq;
	struct hns3_desc *desc;
	unsigned int desc_size = sizeof(struct hns3_desc);
	unsigned int tx_desc;
	int tx_entry_len;
	int i;

	if (dev->data->dev_started) {
		hns3_err(hw, "tx_queue_setup after dev_start no supported");
		return -EINVAL;
	}

	if (nb_desc > HNS3_MAX_RING_DESC || nb_desc < HNS3_MIN_RING_DESC ||
	    nb_desc % HNS3_ALIGN_RING_DESC) {
		hns3_err(hw, "Number (%u) of tx descriptors is invalid",
			    nb_desc);
		return -EINVAL;
	}

	if (dev->data->tx_queues[idx] != NULL) {
		hns3_tx_queue_release(dev->data->tx_queues[idx]);
		dev->data->tx_queues[idx] = NULL;
	}

	txq = rte_zmalloc_socket("hns3 TX queue", sizeof(struct hns3_tx_queue),
				 RTE_CACHE_LINE_SIZE, socket_id);
	if (txq == NULL) {
		hns3_err(hw, "Failed to allocate memory for tx queue!");
		return -ENOMEM;
	}

	txq->nb_tx_desc = nb_desc;
	txq->queue_id = idx;
	txq->tx_deferred_start = conf->tx_deferred_start;

	tx_entry_len = sizeof(struct hns3_entry) * txq->nb_tx_desc;
	txq->sw_ring = rte_zmalloc_socket("hns3 TX sw ring", tx_entry_len,
					  RTE_CACHE_LINE_SIZE, socket_id);
	if (txq->sw_ring == NULL) {
		hns3_err(hw, "Failed to allocate memory for tx sw ring!");
		hns3_tx_queue_release(txq);
		return -ENOMEM;
	}

	/* Allocate tx ring hardware descriptors. */
	tx_desc = txq->nb_tx_desc * desc_size;
	tx_mz = rte_eth_dma_zone_reserve(dev, "tx_ring", idx, tx_desc,
					 HNS3_RING_BASE_ALIGN, socket_id);
	if (tx_mz == NULL) {
		hns3_err(hw, "Failed to reserve DMA memory for No.%d tx ring!",
			 idx);
		hns3_tx_queue_release(txq);
		return -ENOMEM;
	}
	txq->mz = tx_mz;
	txq->tx_ring = (struct hns3_desc *)tx_mz->addr;
	txq->tx_ring_phys_addr = tx_mz->iova;

	hns3_dbg(hw, "No.%d tx descriptors iova 0x%lx", idx,
		 txq->tx_ring_phys_addr);

	/* Clear tx bd */
	desc = txq->tx_ring;
	for (i = 0; i < txq->nb_tx_desc; i++) {
		desc->tx.tp_fe_sc_vld_ra_ri = 0;
		desc++;
	}

	txq->hns = hns;
	txq->next_to_use = 0;
	txq->next_to_clean = 0;
	txq->tx_bd_ready   = txq->nb_tx_desc;
	txq->port_id = dev->data->port_id;
	txq->pkt_len_errors = 0;
	txq->configured = true;
	txq->io_base = (void *)((char *)hw->io_base + HNS3_TQP_REG_OFFSET +
				idx * HNS3_TQP_REG_SIZE);
	rte_spinlock_lock(&hw->lock);
	dev->data->tx_queues[idx] = txq;
	rte_spinlock_unlock(&hw->lock);

	return 0;
}

static inline int
tx_ring_dist(struct hns3_tx_queue *txq, int begin, int end)
{
	return (end - begin + txq->nb_tx_desc) % txq->nb_tx_desc;
}

static inline int
tx_ring_space(struct hns3_tx_queue *txq)
{
	return txq->nb_tx_desc -
		tx_ring_dist(txq, txq->next_to_clean, txq->next_to_use) - 1;
}

static inline void
hns3_queue_xmit(struct hns3_tx_queue *txq, uint32_t buf_num)
{
	hns3_write_dev(txq, HNS3_RING_TX_TAIL_REG, buf_num);
}

static void
hns3_tx_free_useless_buffer(struct hns3_tx_queue *txq)
{
	uint16_t tx_next_clean = txq->next_to_clean;
	uint16_t tx_next_use   = txq->next_to_use;
	uint16_t tx_bd_ready   = txq->tx_bd_ready;
	uint16_t tx_bd_max     = txq->nb_tx_desc;
	struct hns3_entry *tx_bak_pkt = &txq->sw_ring[tx_next_clean];
	struct hns3_desc *desc = &txq->tx_ring[tx_next_clean];
	struct rte_mbuf *mbuf;

	while ((!hns3_get_bit(desc->tx.tp_fe_sc_vld_ra_ri, HNS3_TXD_VLD_B)) &&
		(tx_next_use != tx_next_clean || tx_bd_ready < tx_bd_max)) {
		mbuf = tx_bak_pkt->mbuf;
		if (mbuf) {
			mbuf->next = NULL;
			rte_pktmbuf_free(mbuf);
			tx_bak_pkt->mbuf = NULL;
		}

		desc++;
		tx_bak_pkt++;
		tx_next_clean++;
		tx_bd_ready++;

		if (tx_next_clean >= tx_bd_max) {
			tx_next_clean = 0;
			desc = txq->tx_ring;
			tx_bak_pkt = txq->sw_ring;
		}
	}

	txq->next_to_clean = tx_next_clean;
	txq->tx_bd_ready   = tx_bd_ready;
}

static void
fill_desc(struct hns3_tx_queue *txq, uint16_t tx_desc_id, struct rte_mbuf *rxm,
	  bool first, int offset)
{
	struct hns3_desc *tx_ring = txq->tx_ring;
	struct hns3_desc *desc = &tx_ring[tx_desc_id];
	uint8_t frag_end = rxm->next == NULL ? 1 : 0;
	uint8_t ol_type_vlan_msec = 0;
	uint8_t type_cs_vlan_tso = 0;
	uint16_t size = rxm->data_len;
	uint16_t paylen = 0;
	uint16_t rrcfv = 0;
	uint64_t ol_flags;

	desc->addr = rte_mbuf_data_iova(rxm) + offset;
	desc->tx.send_size = rte_cpu_to_le_16(size);
	hns3_set_bit(rrcfv, HNS3_TXD_VLD_B, 1);

	if (first) {
		if (rxm->packet_type &
		    (RTE_PTYPE_L3_IPV4 | RTE_PTYPE_L3_IPV6)) {
			hns3_set_bit(type_cs_vlan_tso, HNS3_TXD_L4CS_B, 1);
			if (rxm->packet_type & RTE_PTYPE_L3_IPV6)
				hns3_set_field(type_cs_vlan_tso, HNS3_TXD_L3T_M,
					       HNS3_TXD_L3T_S, HNS3_L3T_IPV6);
			else
				hns3_set_field(type_cs_vlan_tso, HNS3_TXD_L3T_M,
					       HNS3_TXD_L3T_S, HNS3_L3T_IPV4);
		}
		desc->tx.paylen = rte_cpu_to_le_16(paylen);
		desc->tx.l4_len = rxm->l4_len;
	}

	hns3_set_bit(rrcfv, HNS3_TXD_FE_B, frag_end);
	desc->tx.tp_fe_sc_vld_ra_ri = rrcfv;

	if (frag_end) {
		ol_flags = rxm->ol_flags;
		if (ol_flags & (PKT_TX_VLAN_PKT | PKT_TX_QINQ_PKT)) {
			hns3_set_bit(type_cs_vlan_tso, HNS3_TXD_VLAN_B, 1);
			desc->tx.vlan_tag = rxm->vlan_tci;
		}

		if (ol_flags & PKT_TX_QINQ_PKT) {
			hns3_set_bit(ol_type_vlan_msec, HNS3_TXD_OVLAN_B, 1);
			desc->tx.outer_vlan_tag = rxm->vlan_tci_outer;
		}
	}

	desc->tx.type_cs_vlan_tso = type_cs_vlan_tso;
	desc->tx.ol_type_vlan_msec = ol_type_vlan_msec;
}

static int
hns3_tx_alloc_mbufs(struct hns3_tx_queue *txq, struct rte_mempool *mb_pool,
		    uint16_t nb_new_buf, struct rte_mbuf **alloc_mbuf)
{
	struct rte_mbuf *new_mbuf = NULL;
	struct rte_eth_dev *dev;
	struct rte_mbuf *temp;
	struct hns3_hw *hw;
	uint16_t i;

	/* Allocate enough mbufs */
	for (i = 0; i < nb_new_buf; i++) {
		temp = rte_pktmbuf_alloc(mb_pool);
		if (unlikely(temp == NULL)) {
			dev = &rte_eth_devices[txq->port_id];
			hw = HNS3_DEV_PRIVATE_TO_HW(dev->data->dev_private);
			hns3_err(hw, "Failed to alloc TX mbuf port_id=%d,"
				     "queue_id=%d in reassemble tx pkts.",
				     txq->port_id, txq->queue_id);
			rte_pktmbuf_free(new_mbuf);
			return -ENOMEM;
		}
		temp->next = new_mbuf;
		new_mbuf = temp;
	}

	if (new_mbuf == NULL)
		return -ENOMEM;

	new_mbuf->nb_segs = nb_new_buf;
	*alloc_mbuf = new_mbuf;

	return 0;
}

static int
hns3_reassemble_tx_pkts(void *tx_queue, struct rte_mbuf *tx_pkt,
			struct rte_mbuf **new_pkt)
{
	struct hns3_tx_queue *txq = tx_queue;
	struct rte_mempool *mb_pool;
	struct rte_mbuf *new_mbuf;
	struct rte_mbuf *temp_new;
	struct rte_mbuf *temp;
	uint16_t last_buf_len;
	uint16_t nb_new_buf;
	uint16_t buf_size;
	uint16_t buf_len;
	uint16_t len_s;
	uint16_t len_d;
	uint16_t len;
	uint16_t i;
	int ret;
	char *s;
	char *d;

	mb_pool = tx_pkt->pool;
	buf_size = tx_pkt->buf_len - RTE_PKTMBUF_HEADROOM;
	nb_new_buf = (tx_pkt->pkt_len - 1) / buf_size + 1;

	last_buf_len = tx_pkt->pkt_len % buf_size;
	if (last_buf_len == 0)
		last_buf_len = buf_size;

	/* Allocate enough mbufs */
	ret = hns3_tx_alloc_mbufs(txq, mb_pool, nb_new_buf, &new_mbuf);
	if (ret)
		return ret;

	/* Copy the original packet content to the new mbufs */
	temp = tx_pkt;
	s = rte_pktmbuf_mtod(temp, char *);
	len_s = temp->data_len;
	temp_new = new_mbuf;
	for (i = 0; i < nb_new_buf; i++) {
		d = rte_pktmbuf_mtod(temp_new, char *);
		if (i < nb_new_buf - 1)
			buf_len = buf_size;
		else
			buf_len = last_buf_len;
		len_d = buf_len;

		while (len_d) {
			len = RTE_MIN(len_s, len_d);
			memcpy(d, s, len);
			s = s + len;
			d = d + len;
			len_d = len_d - len;
			len_s = len_s - len;

			if (len_s == 0) {
				temp = temp->next;
				if (temp == NULL)
					break;
				s = rte_pktmbuf_mtod(temp, char *);
				len_s = temp->data_len;
			}
		}

		temp_new->data_len = buf_len;
		temp_new = temp_new->next;
	}

	/* free original mbufs */
	rte_pktmbuf_free(tx_pkt);

	*new_pkt = new_mbuf;

	return 0;
}

uint16_t
hns3_xmit_pkts(void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t nb_pkts)
{
	struct hns3_tx_queue *txq = tx_queue;
	struct hns3_entry *tx_bak_pkt;
	struct rte_mbuf *new_pkt;
	struct rte_mbuf *tx_pkt;
	struct rte_mbuf *m_seg;
	struct rte_mbuf *temp;
	uint32_t nb_hold = 0;
	uint16_t tx_next_clean;
	uint16_t tx_next_use;
	uint16_t tx_bd_ready;
	uint16_t tx_pkt_num;
	uint16_t tx_bd_max;
	uint16_t nb_buf;
	uint16_t nb_tx;
	uint16_t i;

	/* free useless buffer */
	hns3_tx_free_useless_buffer(txq);
	tx_bd_ready = txq->tx_bd_ready;
	if (tx_bd_ready == 0)
		return 0;

	tx_next_clean = txq->next_to_clean;
	tx_next_use   = txq->next_to_use;
	tx_bd_max     = txq->nb_tx_desc;
	tx_bak_pkt = &txq->sw_ring[tx_next_clean];

	tx_pkt_num = (tx_bd_ready < nb_pkts) ? tx_bd_ready : nb_pkts;

	/* send packets */
	tx_bak_pkt = &txq->sw_ring[tx_next_use];
	for (nb_tx = 0; nb_tx < tx_pkt_num; nb_tx++) {
		tx_pkt = *tx_pkts++;

		nb_buf = tx_pkt->nb_segs;

		if (nb_buf > tx_ring_space(txq)) {
			if (nb_tx == 0)
				return 0;

			goto end_of_tx;
		}

		/*
		 * If the length of the packet is too long or zero, the packet
		 * will be ignored.
		 */
		if (unlikely(tx_pkt->pkt_len > HNS3_MAX_FRAME_LEN ||
			     tx_pkt->pkt_len == 0)) {
			txq->pkt_len_errors++;
			continue;
		}

		m_seg = tx_pkt;
		if (unlikely(nb_buf > HNS3_MAX_TX_BD_PER_PKT)) {
			if (hns3_reassemble_tx_pkts(txq, tx_pkt, &new_pkt))
				goto end_of_tx;
			m_seg = new_pkt;
			nb_buf = m_seg->nb_segs;
		}

		i = 0;
		do {
			fill_desc(txq, tx_next_use, m_seg, (i == 0), 0);
			temp = m_seg->next;
			tx_bak_pkt->mbuf = m_seg;
			m_seg = temp;
			tx_next_use++;
			tx_bak_pkt++;
			if (tx_next_use >= tx_bd_max) {
				tx_next_use = 0;
				tx_bak_pkt = txq->sw_ring;
			}

			i++;
		} while (m_seg != NULL);

		nb_hold += i;
	}

end_of_tx:

	if (likely(nb_tx)) {
		hns3_queue_xmit(txq, nb_hold);
		txq->next_to_clean = tx_next_clean;
		txq->next_to_use   = tx_next_use;
		txq->tx_bd_ready   = tx_bd_ready - nb_hold;
	}

	return nb_tx;
}

static uint16_t
hns3_dummy_rxtx_burst(void *dpdk_txq __rte_unused,
		      struct rte_mbuf **pkts __rte_unused,
		      uint16_t pkts_n __rte_unused)
{
	return 0;
}

void hns3_set_rxtx_function(struct rte_eth_dev *eth_dev)
{
	struct hns3_adapter *hns = eth_dev->data->dev_private;

	if (hns->hw.adapter_state == HNS3_NIC_STARTED &&
	    rte_atomic16_read(&hns->hw.reset.resetting) == 0) {
		eth_dev->rx_pkt_burst = hns3_recv_pkts;
		eth_dev->tx_pkt_burst = hns3_xmit_pkts;
	} else {
		eth_dev->rx_pkt_burst = hns3_dummy_rxtx_burst;
		eth_dev->tx_pkt_burst = hns3_dummy_rxtx_burst;
	}
}
