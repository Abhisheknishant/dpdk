/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2019 Hisilicon Limited.
 */

#include <stdbool.h>
#include <stdint.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_io.h>
#include <rte_malloc.h>
#include <rte_spinlock.h>

#include "hns3_cmd.h"
#include "hns3_mbx.h"
#include "hns3_rss.h"
#include "hns3_fdir.h"
#include "hns3_stats.h"
#include "hns3_ethdev.h"
#include "hns3_rxtx.h"
#include "hns3_logs.h"

/* MAC statistics */
static const struct hns3_xstats_name_offset hns3_mac_strings[] = {
	{"mac_tx_mac_pause_num",
		HNS3_MAC_STATS_OFFSET(mac_tx_mac_pause_num)},
	{"mac_rx_mac_pause_num",
		HNS3_MAC_STATS_OFFSET(mac_rx_mac_pause_num)},
	{"mac_tx_control_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_tx_ctrl_pkt_num)},
	{"mac_rx_control_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_rx_ctrl_pkt_num)},
	{"mac_tx_pfc_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_tx_pfc_pause_pkt_num)},
	{"mac_tx_pfc_pri0_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_tx_pfc_pri0_pkt_num)},
	{"mac_tx_pfc_pri1_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_tx_pfc_pri1_pkt_num)},
	{"mac_tx_pfc_pri2_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_tx_pfc_pri2_pkt_num)},
	{"mac_tx_pfc_pri3_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_tx_pfc_pri3_pkt_num)},
	{"mac_tx_pfc_pri4_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_tx_pfc_pri4_pkt_num)},
	{"mac_tx_pfc_pri5_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_tx_pfc_pri5_pkt_num)},
	{"mac_tx_pfc_pri6_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_tx_pfc_pri6_pkt_num)},
	{"mac_tx_pfc_pri7_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_tx_pfc_pri7_pkt_num)},
	{"mac_rx_pfc_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_rx_pfc_pause_pkt_num)},
	{"mac_rx_pfc_pri0_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_rx_pfc_pri0_pkt_num)},
	{"mac_rx_pfc_pri1_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_rx_pfc_pri1_pkt_num)},
	{"mac_rx_pfc_pri2_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_rx_pfc_pri2_pkt_num)},
	{"mac_rx_pfc_pri3_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_rx_pfc_pri3_pkt_num)},
	{"mac_rx_pfc_pri4_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_rx_pfc_pri4_pkt_num)},
	{"mac_rx_pfc_pri5_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_rx_pfc_pri5_pkt_num)},
	{"mac_rx_pfc_pri6_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_rx_pfc_pri6_pkt_num)},
	{"mac_rx_pfc_pri7_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_rx_pfc_pri7_pkt_num)},
	{"mac_tx_total_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_tx_total_pkt_num)},
	{"mac_tx_total_oct_num",
		HNS3_MAC_STATS_OFFSET(mac_tx_total_oct_num)},
	{"mac_tx_good_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_tx_good_pkt_num)},
	{"mac_tx_bad_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_tx_bad_pkt_num)},
	{"mac_tx_good_oct_num",
		HNS3_MAC_STATS_OFFSET(mac_tx_good_oct_num)},
	{"mac_tx_bad_oct_num",
		HNS3_MAC_STATS_OFFSET(mac_tx_bad_oct_num)},
	{"mac_tx_uni_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_tx_uni_pkt_num)},
	{"mac_tx_multi_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_tx_multi_pkt_num)},
	{"mac_tx_broad_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_tx_broad_pkt_num)},
	{"mac_tx_undersize_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_tx_undersize_pkt_num)},
	{"mac_tx_oversize_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_tx_oversize_pkt_num)},
	{"mac_tx_64_oct_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_tx_64_oct_pkt_num)},
	{"mac_tx_65_127_oct_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_tx_65_127_oct_pkt_num)},
	{"mac_tx_128_255_oct_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_tx_128_255_oct_pkt_num)},
	{"mac_tx_256_511_oct_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_tx_256_511_oct_pkt_num)},
	{"mac_tx_512_1023_oct_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_tx_512_1023_oct_pkt_num)},
	{"mac_tx_1024_1518_oct_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_tx_1024_1518_oct_pkt_num)},
	{"mac_tx_1519_2047_oct_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_tx_1519_2047_oct_pkt_num)},
	{"mac_tx_2048_4095_oct_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_tx_2048_4095_oct_pkt_num)},
	{"mac_tx_4096_8191_oct_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_tx_4096_8191_oct_pkt_num)},
	{"mac_tx_8192_9216_oct_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_tx_8192_9216_oct_pkt_num)},
	{"mac_tx_9217_12287_oct_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_tx_9217_12287_oct_pkt_num)},
	{"mac_tx_12288_16383_oct_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_tx_12288_16383_oct_pkt_num)},
	{"mac_tx_1519_max_good_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_tx_1519_max_good_oct_pkt_num)},
	{"mac_tx_1519_max_bad_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_tx_1519_max_bad_oct_pkt_num)},
	{"mac_rx_total_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_rx_total_pkt_num)},
	{"mac_rx_total_oct_num",
		HNS3_MAC_STATS_OFFSET(mac_rx_total_oct_num)},
	{"mac_rx_good_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_rx_good_pkt_num)},
	{"mac_rx_bad_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_rx_bad_pkt_num)},
	{"mac_rx_good_oct_num",
		HNS3_MAC_STATS_OFFSET(mac_rx_good_oct_num)},
	{"mac_rx_bad_oct_num",
		HNS3_MAC_STATS_OFFSET(mac_rx_bad_oct_num)},
	{"mac_rx_uni_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_rx_uni_pkt_num)},
	{"mac_rx_multi_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_rx_multi_pkt_num)},
	{"mac_rx_broad_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_rx_broad_pkt_num)},
	{"mac_rx_undersize_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_rx_undersize_pkt_num)},
	{"mac_rx_oversize_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_rx_oversize_pkt_num)},
	{"mac_rx_64_oct_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_rx_64_oct_pkt_num)},
	{"mac_rx_65_127_oct_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_rx_65_127_oct_pkt_num)},
	{"mac_rx_128_255_oct_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_rx_128_255_oct_pkt_num)},
	{"mac_rx_256_511_oct_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_rx_256_511_oct_pkt_num)},
	{"mac_rx_512_1023_oct_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_rx_512_1023_oct_pkt_num)},
	{"mac_rx_1024_1518_oct_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_rx_1024_1518_oct_pkt_num)},
	{"mac_rx_1519_2047_oct_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_rx_1519_2047_oct_pkt_num)},
	{"mac_rx_2048_4095_oct_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_rx_2048_4095_oct_pkt_num)},
	{"mac_rx_4096_8191_oct_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_rx_4096_8191_oct_pkt_num)},
	{"mac_rx_8192_9216_oct_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_rx_8192_9216_oct_pkt_num)},
	{"mac_rx_9217_12287_oct_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_rx_9217_12287_oct_pkt_num)},
	{"mac_rx_12288_16383_oct_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_rx_12288_16383_oct_pkt_num)},
	{"mac_rx_1519_max_good_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_rx_1519_max_good_oct_pkt_num)},
	{"mac_rx_1519_max_bad_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_rx_1519_max_bad_oct_pkt_num)},
	{"mac_tx_fragment_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_tx_fragment_pkt_num)},
	{"mac_tx_undermin_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_tx_undermin_pkt_num)},
	{"mac_tx_jabber_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_tx_jabber_pkt_num)},
	{"mac_tx_err_all_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_tx_err_all_pkt_num)},
	{"mac_tx_from_app_good_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_tx_from_app_good_pkt_num)},
	{"mac_tx_from_app_bad_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_tx_from_app_bad_pkt_num)},
	{"mac_rx_fragment_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_rx_fragment_pkt_num)},
	{"mac_rx_undermin_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_rx_undermin_pkt_num)},
	{"mac_rx_jabber_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_rx_jabber_pkt_num)},
	{"mac_rx_fcs_err_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_rx_fcs_err_pkt_num)},
	{"mac_rx_send_app_good_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_rx_send_app_good_pkt_num)},
	{"mac_rx_send_app_bad_pkt_num",
		HNS3_MAC_STATS_OFFSET(mac_rx_send_app_bad_pkt_num)}
};

static const struct hns3_xstats_name_offset hns3_error_int_stats_strings[] = {
	{"MAC_AFIFO_TNL_INT_R",
		HNS3_ERR_INT_STATS_FIELD_OFFSET(mac_afifo_tnl_intr_cnt)},
	{"PPU_MPF_ABNORMAL_INT_ST2",
		HNS3_ERR_INT_STATS_FIELD_OFFSET(ppu_mpf_abnormal_intr_st2_cnt)},
	{"SSU_PORT_BASED_ERR_INT",
		HNS3_ERR_INT_STATS_FIELD_OFFSET(ssu_port_based_pf_intr_cnt)},
	{"PPP_PF_ABNORMAL_INT_ST0",
		HNS3_ERR_INT_STATS_FIELD_OFFSET(ppp_pf_abnormal_intr_cnt)},
	{"PPU_PF_ABNORMAL_INT_ST",
		HNS3_ERR_INT_STATS_FIELD_OFFSET(ppu_pf_abnormal_intr_cnt)}
};

/* The statistic of reset */
static const struct hns3_xstats_name_offset hns3_reset_stats_strings[] = {
	{"REQ_RESET_CNT",
		HNS3_RESET_STATS_FIELD_OFFSET(request_cnt)},
	{"GLOBAL_RESET_CNT",
		HNS3_RESET_STATS_FIELD_OFFSET(global_cnt)},
	{"IMP_RESET_CNT",
		HNS3_RESET_STATS_FIELD_OFFSET(imp_cnt)},
	{"RESET_EXEC_CNT",
		HNS3_RESET_STATS_FIELD_OFFSET(exec_cnt)},
	{"RESET_SUCCESS_CNT",
		HNS3_RESET_STATS_FIELD_OFFSET(success_cnt)},
	{"RESET_FAIL_CNT",
		HNS3_RESET_STATS_FIELD_OFFSET(fail_cnt)},
	{"RESET_MERGE_CNT",
		HNS3_RESET_STATS_FIELD_OFFSET(merge_cnt)}
};

#define HNS3_NUM_MAC_STATS (sizeof(hns3_mac_strings) / \
	sizeof(hns3_mac_strings[0]))

#define HNS3_NUM_ERROR_INT_XSTATS (sizeof(hns3_error_int_stats_strings) / \
	sizeof(hns3_error_int_stats_strings[0]))

#define HNS3_NUM_RESET_XSTATS (sizeof(hns3_reset_stats_strings) / \
	sizeof(hns3_reset_stats_strings[0]))

#define HNS3_MAX_NUM_STATS (HNS3_NUM_MAC_STATS + HNS3_NUM_ERROR_INT_XSTATS + \
			    HNS3_NUM_RESET_XSTATS)

/*
 * Query all the MAC statistics data of Network ICL command ,opcode id: 0x0034.
 * This command is used before send 'query_mac_stat command', the descriptor
 * number of 'query_mac_stat command' must match with reg_num in this command.
 * @praram hw
 *   Pointer to structure hns3_hw.
 * @return
 *   0 on success.
 */
static int
hns3_update_mac_stats(struct hns3_hw *hw, const uint32_t desc_num)
{
	uint64_t *data = (uint64_t *)(&hw->mac_stats);
	struct hns3_cmd_desc *desc;
	uint64_t *desc_data;
	uint16_t i, k, n;
	int ret;

	desc = rte_malloc("hns3_mac_desc",
			  desc_num * sizeof(struct hns3_cmd_desc), 0);
	if (desc == NULL) {
		hns3_err(hw, "Mac_update_stats alloced desc malloc fail");
		return -ENOMEM;
	}

	hns3_cmd_setup_basic_desc(desc, HNS3_OPC_STATS_MAC_ALL, true);
	ret = hns3_cmd_send(hw, desc, desc_num);
	if (ret) {
		hns3_err(hw, "Update complete MAC pkt stats fail : %d", ret);
		rte_free(desc);
		return ret;
	}

	for (i = 0; i < desc_num; i++) {
		/* For special opcode 0034, only the first desc has the head */
		if (i == 0) {
			desc_data = (uint64_t *)(&desc[i].data[0]);
			n = HNS3_RD_FIRST_STATS_NUM;
		} else {
			desc_data = (uint64_t *)(&desc[i]);
			n = HNS3_RD_OTHER_STATS_NUM;
		}

		for (k = 0; k < n; k++) {
			*data += rte_le_to_cpu_64(*desc_data);
			data++;
			desc_data++;
		}
	}
	rte_free(desc);

	return 0;
}

/*
 * Query Mac stat reg num command ,opcode id: 0x0033.
 * This command is used before send 'query_mac_stat command', the descriptor
 * number of 'query_mac_stat command' must match with reg_num in this command.
 * @praram rte_stats
 *   Pointer to structure rte_eth_stats.
 * @return
 *   0 on success.
 */
static int
hns3_mac_query_reg_num(struct rte_eth_dev *dev, uint32_t *desc_num)
{
	struct hns3_adapter *hns = dev->data->dev_private;
	struct hns3_hw *hw = &hns->hw;
	struct hns3_cmd_desc desc;
	uint32_t *desc_data;
	uint32_t reg_num;
	int ret;

	hns3_cmd_setup_basic_desc(&desc, HNS3_OPC_QUERY_MAC_REG_NUM, true);
	ret = hns3_cmd_send(hw, &desc, 1);
	if (ret)
		return ret;

	/*
	 * The num of MAC statistics registers that are provided by IMP in this
	 * version.
	 */
	desc_data = (uint32_t *)(&desc.data[0]);
	reg_num = rte_le_to_cpu_32(*desc_data);
	/* The descriptor number of 'query_additional_mac_stat command' is
	 * '1 + (reg_num-3)/4 + ((reg_num-3)%4 !=0)';
	 * This value is 83 in this version
	 */
	*desc_num = 1 + ((reg_num - 3) >> 2) +
		    (uint32_t)(((reg_num - 3) & 0x3) ? 1 : 0);

	return 0;
}

static int
hns3_query_update_mac_stats(struct rte_eth_dev *dev)
{
	struct hns3_adapter *hns = dev->data->dev_private;
	struct hns3_hw *hw = &hns->hw;
	uint32_t desc_num;
	int ret;

	ret = hns3_mac_query_reg_num(dev, &desc_num);
	if (ret == 0)
		ret = hns3_update_mac_stats(hw, desc_num);
	else
		hns3_err(hw, "Query mac reg num fail : %d", ret);
	return ret;
}

/* Get tqp stats from register */
static int
hns3_update_tqp_stats(struct hns3_hw *hw)
{
	struct hns3_tqp_stats *stats = &hw->tqp_stats;
	struct hns3_cmd_desc desc;
	uint64_t cnt;
	uint16_t i;
	int ret;

	for (i = 0; i < hw->tqps_num; i++) {
		hns3_cmd_setup_basic_desc(&desc, HNS3_OPC_QUERY_RX_STATUS,
					  true);

		desc.data[0] = rte_cpu_to_le_32((uint32_t)i &
						HNS3_QUEUE_ID_MASK);
		ret = hns3_cmd_send(hw, &desc, 1);
		if (ret) {
			hns3_err(hw, "Failed to query RX No.%d queue stat: %d",
				 i, ret);
			return ret;
		}
		cnt = rte_le_to_cpu_32(desc.data[1]);
		stats->rcb_rx_ring_pktnum_rcd += cnt;
		stats->rcb_rx_ring_pktnum[i] += cnt;

		hns3_cmd_setup_basic_desc(&desc, HNS3_OPC_QUERY_TX_STATUS,
					  true);

		desc.data[0] = rte_cpu_to_le_32((uint32_t)i &
						HNS3_QUEUE_ID_MASK);
		ret = hns3_cmd_send(hw, &desc, 1);
		if (ret) {
			hns3_err(hw, "Failed to query TX No.%d queue stat: %d",
				 i, ret);
			return ret;
		}
		cnt = rte_le_to_cpu_32(desc.data[1]);
		stats->rcb_tx_ring_pktnum_rcd += cnt;
		stats->rcb_tx_ring_pktnum[i] += cnt;
	}

	return 0;
}

/*
 * Query tqp tx queue statistics ,opcode id: 0x0B03.
 * Query tqp rx queue statistics ,opcode id: 0x0B13.
 * Get all statistics of a port.
 * @param eth_dev
 *   Pointer to Ethernet device.
 * @praram rte_stats
 *   Pointer to structure rte_eth_stats.
 * @return
 *   0 on success.
 */
int
hns3_stats_get(struct rte_eth_dev *eth_dev, struct rte_eth_stats *rte_stats)
{
	struct hns3_adapter *hns = eth_dev->data->dev_private;
	struct hns3_hw *hw = &hns->hw;
	struct hns3_tqp_stats *stats = &hw->tqp_stats;
	struct hns3_rx_queue *rxq;
	uint64_t cnt;
	uint64_t num;
	uint16_t i;
	int ret;

	/* Update tqp stats by read register */
	ret = hns3_update_tqp_stats(hw);
	if (ret) {
		hns3_err(hw, "Update tqp stats fail : %d", ret);
		return ret;
	}

	rte_stats->ipackets  = stats->rcb_rx_ring_pktnum_rcd;
	rte_stats->opackets  = stats->rcb_tx_ring_pktnum_rcd;
	rte_stats->rx_nombuf = eth_dev->data->rx_mbuf_alloc_failed;

	num = RTE_MIN(RTE_ETHDEV_QUEUE_STAT_CNTRS, hw->tqps_num);
	for (i = 0; i < num; i++) {
		rte_stats->q_ipackets[i] = stats->rcb_rx_ring_pktnum[i];
		rte_stats->q_opackets[i] = stats->rcb_tx_ring_pktnum[i];
	}

	num = RTE_MIN(RTE_ETHDEV_QUEUE_STAT_CNTRS, eth_dev->data->nb_rx_queues);
	for (i = 0; i != num; ++i) {
		rxq = eth_dev->data->rx_queues[i];
		if (rxq) {
			cnt = rxq->errors;
			rte_stats->q_errors[i] = cnt;
			rte_stats->ierrors += cnt;
		}
	}

	return 0;
}

void
hns3_stats_reset(struct rte_eth_dev *eth_dev)
{
	struct hns3_adapter *hns = eth_dev->data->dev_private;
	struct hns3_hw *hw = &hns->hw;
	struct hns3_tqp_stats *stats = &hw->tqp_stats;
	struct hns3_cmd_desc desc_reset;
	struct hns3_rx_queue *rxq;
	struct hns3_tx_queue *txq;
	uint16_t i;
	int ret;

	/*
	 * If this is a reset xstats is NULL, and we have cleared the
	 * registers by reading them.
	 */
	for (i = 0; i < hw->tqps_num; i++) {
		hns3_cmd_setup_basic_desc(&desc_reset, HNS3_OPC_QUERY_RX_STATUS,
					  true);
		desc_reset.data[0] = rte_cpu_to_le_32((uint32_t)i &
						      HNS3_QUEUE_ID_MASK);
		ret = hns3_cmd_send(hw, &desc_reset, 1);
		if (ret) {
			hns3_err(hw, "Failed to reset RX No.%d queue stat: %d",
				 i, ret);
		}

		hns3_cmd_setup_basic_desc(&desc_reset, HNS3_OPC_QUERY_TX_STATUS,
					  true);
		desc_reset.data[0] = rte_cpu_to_le_32((uint32_t)i &
						      HNS3_QUEUE_ID_MASK);
		ret = hns3_cmd_send(hw, &desc_reset, 1);
		if (ret) {
			hns3_err(hw, "Failed to reset TX No.%d queue stat: %d",
				 i, ret);
		}
	}

	for (i = 0; i != eth_dev->data->nb_rx_queues; ++i) {
		rxq = eth_dev->data->rx_queues[i];
		if (rxq) {
			rxq->non_vld_descs = 0;
			rxq->l2_errors = 0;
			rxq->csum_erros = 0;
			rxq->pkt_len_errors = 0;
			rxq->errors = 0;
		}

		txq = eth_dev->data->tx_queues[i];
		if (txq)
			txq->pkt_len_errors = 0;
	}

	memset(stats, 0, sizeof(struct hns3_tqp_stats));
}

static void
hns3_mac_stats_reset(__rte_unused struct rte_eth_dev *dev)
{
	struct hns3_adapter *hns = dev->data->dev_private;
	struct hns3_hw *hw = &hns->hw;
	struct hns3_mac_stats *mac_stats = &hw->mac_stats;
	int ret;

	ret = hns3_query_update_mac_stats(dev);
	if (ret)
		hns3_err(hw, "Clear Mac stats fail : %d", ret);

	memset(mac_stats, 0, sizeof(struct hns3_mac_stats));
}

/* This function calculates the number of xstats based on the current config */
static int
hns3_xstats_calc_num(struct hns3_adapter *hns3)
{
	if (hns3->is_vf)
		return HNS3_NUM_RESET_XSTATS;
	else
		return HNS3_MAX_NUM_STATS;
}

/*
 * Retrieve extended(tqp | Mac) statistics of an Ethernet device.
 * @param dev
 *   Pointer to Ethernet device.
 * @praram xstats
 *   A pointer to a table of structure of type *rte_eth_xstat*
 *   to be filled with device statistics ids and values.
 *   This parameter can be set to NULL if n is 0.
 * @param n
 *   The size of the xstats array (number of elements).
 * @return
 *   0 on fail, count(The size of the statistics elements) on success.
 */
int
hns3_dev_xstats_get(struct rte_eth_dev *dev, struct rte_eth_xstat *xstats,
		    unsigned int n)
{
	struct hns3_adapter *hns = dev->data->dev_private;
	struct hns3_pf *pf = &hns->pf;
	struct hns3_hw *hw = &hns->hw;
	struct hns3_mac_stats *mac_stats = &hw->mac_stats;
	struct hns3_reset_stats *reset_stats = &hw->reset.stats;
	int count;
	uint16_t i;
	char *addr;
	int ret;

	if (xstats == NULL)
		return 0;

	count = hns3_xstats_calc_num(hns);
	if ((int)n < count)
		return count;

	count = 0;

	if (!hns->is_vf) {
		/* Update Mac stats */
		ret = hns3_query_update_mac_stats(dev);
		if (ret) {
			hns3_err(hw, "Update Mac stats fail : %d", ret);
			return 0;
		}

		/* Get MAC stats from hw->hw_xstats.mac_stats struct */
		for (i = 0; i < HNS3_NUM_MAC_STATS; i++) {
			addr = (char *)mac_stats + hns3_mac_strings[i].offset;
			xstats[count].value = *(uint64_t *)addr;
			xstats[count].id = count;
			count++;
		}

		for (i = 0; i < HNS3_NUM_ERROR_INT_XSTATS; i++) {
			addr = (char *)&pf->abn_int_stats +
			       hns3_error_int_stats_strings[i].offset;
			xstats[count].value = *(uint64_t *)addr;
			xstats[count].id = count;
			count++;
		}
	}

	/* Get the reset stat */
	for (i = 0; i < HNS3_NUM_RESET_XSTATS; i++) {
		addr = (char *)reset_stats + hns3_reset_stats_strings[i].offset;
		xstats[count].value = *(uint64_t *)addr;
		xstats[count].id = count;
		count++;
	}
	return count;
}

/*
 * Retrieve names of extended statistics of an Ethernet device.
 *
 * There is an assumption that 'xstat_names' and 'xstats' arrays are matched
 * by array index:
 *  xstats_names[i].name => xstats[i].value
 *
 * And the array index is same with id field of 'struct rte_eth_xstat':
 *  xstats[i].id == i
 *
 * This assumption makes key-value pair matching less flexible but simpler.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param xstats_names
 *   An rte_eth_xstat_name array of at least *size* elements to
 *   be filled. If set to NULL, the function returns the required number
 *   of elements.
 * @param size
 *   The size of the xstats_names array (number of elements).
 * @return
 *   - A positive value lower or equal to size: success. The return value
 *     is the number of entries filled in the stats table.
 */
int
hns3_dev_xstats_get_names(__rte_unused struct rte_eth_dev *dev,
			  struct rte_eth_xstat_name *xstats_names,
			  __rte_unused unsigned int size)
{
	struct hns3_adapter *hns = dev->data->dev_private;
	int cnt_stats = hns3_xstats_calc_num(hns);
	uint32_t count = 0;
	uint32_t i;

	if (xstats_names == NULL)
		return cnt_stats;

	/* Note: size limited checked in rte_eth_xstats_get_names() */
	if (!hns->is_vf) {
		/* Get MAC name from hw->hw_xstats.mac_stats struct */
		for (i = 0; i < HNS3_NUM_MAC_STATS; i++) {
			snprintf(xstats_names[count].name,
				 sizeof(xstats_names[count].name),
				 "%s", hns3_mac_strings[i].name);
			count++;
		}

		for (i = 0; i < HNS3_NUM_ERROR_INT_XSTATS; i++) {
			snprintf(xstats_names[count].name,
				 sizeof(xstats_names[count].name),
				 "%s", hns3_error_int_stats_strings[i].name);
			count++;
		}
	}
	for (i = 0; i < HNS3_NUM_RESET_XSTATS; i++) {
		snprintf(xstats_names[count].name,
			 sizeof(xstats_names[count].name),
			 "%s", hns3_reset_stats_strings[i].name);
		count++;
	}

	return cnt_stats;
}

/*
 * Retrieve extended statistics of an Ethernet device.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param ids
 *   A pointer to an ids array passed by application. This tells which
 *   statistics values function should retrieve. This parameter
 *   can be set to NULL if size is 0. In this case function will retrieve
 *   all avalible statistics.
 * @param values
 *   A pointer to a table to be filled with device statistics values.
 * @param size
 *   The size of the ids array (number of elements).
 * @return
 *   - A positive value lower or equal to size: success. The return value
 *     is the number of entries filled in the stats table.
 *   - A positive value higher than size: error, the given statistics table
 *     is too small. The return value corresponds to the size that should
 *     be given to succeed. The entries in the table are not valid and
 *     shall not be used by the caller.
 *   - 0 on no ids.
 */
int
hns3_dev_xstats_get_by_id(struct rte_eth_dev *dev,
			  __rte_unused const uint64_t *ids,
			  uint64_t *values, uint32_t size)
{
	struct hns3_adapter *hns = dev->data->dev_private;
	struct hns3_pf *pf = &hns->pf;
	struct hns3_hw *hw = &hns->hw;
	struct hns3_mac_stats *mac_stats = &hw->mac_stats;
	struct hns3_reset_stats *reset_stats = &hw->reset.stats;
	const uint32_t cnt_stats = hns3_xstats_calc_num(hns);
	uint64_t values_copy[HNS3_MAX_NUM_STATS];
	uint32_t count = 0;
	uint16_t i;
	char *addr;
	int ret;

	if (ids == NULL && values == NULL)
		return 0;

	if (ids == NULL && size < cnt_stats)
		return cnt_stats;

	if (ids == NULL) {
		/* Update tqp stats by read register */
		ret = hns3_update_tqp_stats(hw);
		if (ret) {
			hns3_err(hw, "Update tqp stats fail : %d", ret);
			return ret;
		}

		if (!hns->is_vf) {
			/* Get MAC name from hw->hw_xstats.mac_stats struct */
			for (i = 0; i < HNS3_NUM_MAC_STATS; i++) {
				addr = (char *)mac_stats +
				       hns3_mac_strings[i].offset;
				values[count] = *(uint64_t *)addr;
				count++;
			}

			for (i = 0; i < HNS3_NUM_ERROR_INT_XSTATS; i++) {
				addr = (char *)&pf->abn_int_stats +
				       hns3_error_int_stats_strings[i].offset;
				values[count] = *(uint64_t *)addr;
				count++;
			}
		}
		for (i = 0; i < HNS3_NUM_RESET_XSTATS; i++) {
			addr = (char *)reset_stats +
			       hns3_reset_stats_strings[i].offset;
			values[count] = *(uint64_t *)addr;
			count++;
		}

		return count;
	}

	/* Set ids NULL to get the values of all by recursion */
	(void)hns3_dev_xstats_get_by_id(dev, NULL, values_copy, cnt_stats);
	for (i = 0; i < size; i++) {
		if (ids[i] >= cnt_stats) {
			hns3_err(hw, "id value is invalid");
			return -EINVAL;
		}
		values[i] = values_copy[ids[i]];
	}
	return size;
}

/*
 * Retrieve names of extended statistics of an Ethernet device.
 *
 * @param dev
 *   Pointer to Ethernet device.
 * @param xstats_names
 *   An rte_eth_xstat_name array of at least *size* elements to
 *   be filled. If set to NULL, the function returns the required number
 *   of elements.
 * @param ids
 *   IDs array given by app to retrieve specific statistics
 * @param size
 *   The size of the xstats_names array (number of elements).
 * @return
 *   - A positive value lower or equal to size: success. The return value
 *     is the number of entries filled in the stats table.
 *   - A positive value higher than size: error, the given statistics table
 *     is too small. The return value corresponds to the size that should
 *     be given to succeed. The entries in the table are not valid and
 *     shall not be used by the caller.
 */
int
hns3_dev_xstats_get_names_by_id(struct rte_eth_dev *dev,
				struct rte_eth_xstat_name *xstats_names,
				const uint64_t *ids, uint32_t size)
{
	struct rte_eth_xstat_name xstats_names_copy[HNS3_MAX_NUM_STATS];
	struct hns3_adapter *hns = dev->data->dev_private;
	const uint32_t cnt_stats = hns3_xstats_calc_num(hns);
	uint32_t i, count_name = 0;

	if (xstats_names == NULL)
		return cnt_stats;

	if (ids == NULL) {
		/* Note: size >= cnt_stats checked upstream
		 * in rte_eth_xstats_get_names()
		 */
		if (!hns->is_vf) {
			for (i = 0; i < HNS3_NUM_MAC_STATS; i++) {
				snprintf(xstats_names[count_name].name,
					 sizeof(xstats_names[count_name].name),
					 "%s", hns3_mac_strings[i].name);
				count_name++;
			}
			for (i = 0; i < HNS3_NUM_ERROR_INT_XSTATS; i++) {
				snprintf(xstats_names[count_name].name,
					 sizeof(xstats_names[count_name].name),
					 "%s",
					 hns3_error_int_stats_strings[i].name);
				count_name++;
			}
		}
		for (i = 0; i < HNS3_NUM_RESET_XSTATS; i++) {
			snprintf(xstats_names[count_name].name,
				 sizeof(xstats_names[count_name].name),
				 "%s", hns3_reset_stats_strings[i].name);
			count_name++;
		}

		return cnt_stats;
	}

	/* Set ids NULL to get the names of all by recursion */
	(void)hns3_dev_xstats_get_names_by_id(dev, xstats_names_copy, NULL,
					      cnt_stats);

	for (i = 0; i < size; i++) {
		if (ids[i] >= cnt_stats) {
			PMD_INIT_LOG(ERR, "id value is invalid");
			return -EINVAL;
		}
		strncpy(xstats_names[i].name, xstats_names_copy[ids[i]].name,
			strlen(xstats_names_copy[ids[i]].name));
	}
	return size;
}

void
hns3_dev_xstats_reset(struct rte_eth_dev *dev)
{
	struct hns3_adapter *hns = dev->data->dev_private;
	struct hns3_pf *pf = &hns->pf;

	/* VF nosupport Mac and error stats */
	hns3_stats_reset(dev);
	memset(&hns->hw.reset.stats, 0, sizeof(struct hns3_reset_stats));

	if (hns->is_vf)
		return;

	/* HW registers are cleared on read */
	hns3_mac_stats_reset(dev);
	memset(&pf->abn_int_stats, 0, sizeof(struct hns3_err_msix_intr_stats));
}
