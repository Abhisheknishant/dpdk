/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018-2019 Hisilicon Limited.
 */

#include <stdbool.h>
#include <rte_ethdev.h>
#include <rte_io.h>
#include <rte_malloc.h>
#include <rte_memcpy.h>
#include <rte_spinlock.h>

#include "hns3_cmd.h"
#include "hns3_mbx.h"
#include "hns3_rss.h"
#include "hns3_fdir.h"
#include "hns3_ethdev.h"
#include "hns3_logs.h"

/*
 * The hash key used for rss initialization.
 */
static const uint8_t hns3_hash_key[] = {
	0x6D, 0x5A, 0x56, 0xDA, 0x25, 0x5B, 0x0E, 0xC2,
	0x41, 0x67, 0x25, 0x3D, 0x43, 0xA3, 0x8F, 0xB0,
	0xD0, 0xCA, 0x2B, 0xCB, 0xAE, 0x7B, 0x30, 0xB4,
	0x77, 0xCB, 0x2D, 0xA3, 0x80, 0x30, 0xF2, 0x0C,
	0x6A, 0x42, 0xB7, 0x3B, 0xBE, 0xAC, 0x01, 0xFA
};

/*
 * rss_generic_config command function, opcode:0x0D01.
 * Used to set algorithm, key_offset and hash key of rss.
 */
int
hns3_set_rss_algo_key(struct hns3_hw *hw, uint8_t hash_algo, const uint8_t *key)
{
#define HNS3_KEY_OFFSET_MAX	3
#define HNS3_SET_HASH_KEY_BYTE_FOUR	2

	struct hns3_rss_generic_config_cmd *req;
	struct hns3_cmd_desc desc;
	uint32_t key_offset, key_size;
	const uint8_t *key_cur;
	uint8_t cur_offset;
	int ret;

	req = (struct hns3_rss_generic_config_cmd *)desc.data;

	/*
	 * key_offset=0, hash key byte0~15 is set to hardware.
	 * key_offset=1, hash key byte16~31 is set to hardware.
	 * key_offset=2, hash key byte32~39 is set to hardware.
	 */
	for (key_offset = 0; key_offset < HNS3_KEY_OFFSET_MAX; key_offset++) {
		hns3_cmd_setup_basic_desc(&desc, HNS3_OPC_RSS_GENERIC_CONFIG,
					  false);

		req->hash_config |= (hash_algo & HNS3_RSS_HASH_ALGO_MASK);
		req->hash_config |= (key_offset << HNS3_RSS_HASH_KEY_OFFSET_B);

		if (key_offset == HNS3_SET_HASH_KEY_BYTE_FOUR)
			key_size = HNS3_RSS_KEY_SIZE - HNS3_RSS_HASH_KEY_NUM *
			HNS3_SET_HASH_KEY_BYTE_FOUR;
		else
			key_size = HNS3_RSS_HASH_KEY_NUM;

		cur_offset = key_offset * HNS3_RSS_HASH_KEY_NUM;
		key_cur = key + cur_offset;
		memcpy(req->hash_key, key_cur, key_size);

		ret = hns3_cmd_send(hw, &desc, 1);
		if (ret) {
			hns3_err(hw, "Configure RSS algo key failed %d", ret);
			return ret;
		}
	}
	/* Update the shadow RSS key with user specified */
	memcpy(hw->rss_info.key, key, HNS3_RSS_KEY_SIZE);
	return 0;
}

/*
 * Used to configure the tuple selection for RSS hash input.
 */
static int
hns3_set_rss_input_tuple(struct hns3_hw *hw)
{
	struct hns3_rss_conf *rss_config = &hw->rss_info;
	struct hns3_rss_input_tuple_cmd *req;
	struct hns3_cmd_desc desc_tuple;
	int ret;

	hns3_cmd_setup_basic_desc(&desc_tuple, HNS3_OPC_RSS_INPUT_TUPLE, false);

	req = (struct hns3_rss_input_tuple_cmd *)desc_tuple.data;

	req->ipv4_tcp_en = rss_config->rss_tuple_sets.ipv4_tcp_en;
	req->ipv4_udp_en = rss_config->rss_tuple_sets.ipv4_udp_en;
	req->ipv4_sctp_en = rss_config->rss_tuple_sets.ipv4_sctp_en;
	req->ipv4_fragment_en = rss_config->rss_tuple_sets.ipv4_fragment_en;
	req->ipv6_tcp_en = rss_config->rss_tuple_sets.ipv6_tcp_en;
	req->ipv6_udp_en = rss_config->rss_tuple_sets.ipv6_udp_en;
	req->ipv6_sctp_en = rss_config->rss_tuple_sets.ipv6_sctp_en;
	req->ipv6_fragment_en = rss_config->rss_tuple_sets.ipv6_fragment_en;

	ret = hns3_cmd_send(hw, &desc_tuple, 1);
	if (ret)
		hns3_err(hw, "Configure RSS input tuple mode failed %d", ret);

	return ret;
}

/*
 * rss_indirection_table command function, opcode:0x0D07.
 * Used to configure the indirection table of rss.
 */
int
hns3_set_rss_indir_table(struct hns3_hw *hw, uint8_t *indir, uint16_t size)
{
	struct hns3_rss_indirection_table_cmd *req;
	struct hns3_cmd_desc desc;
	int ret, i, j, num;

	req = (struct hns3_rss_indirection_table_cmd *)desc.data;

	for (i = 0; i < size / HNS3_RSS_CFG_TBL_SIZE; i++) {
		hns3_cmd_setup_basic_desc(&desc, HNS3_OPC_RSS_INDIR_TABLE,
					  false);
		req->start_table_index =
				rte_cpu_to_le_16(i * HNS3_RSS_CFG_TBL_SIZE);
		req->rss_set_bitmap = rte_cpu_to_le_16(HNS3_RSS_SET_BITMAP_MSK);
		for (j = 0; j < HNS3_RSS_CFG_TBL_SIZE; j++) {
			num = i * HNS3_RSS_CFG_TBL_SIZE + j;
			req->rss_result[j] = indir[num] % hw->alloc_rss_size;
		}
		ret = hns3_cmd_send(hw, &desc, 1);
		if (ret) {
			hns3_err(hw,
				 "Sets RSS indirection table failed %d size %u",
				 ret, size);
			return ret;
		}
	}

	/* Update redirection table of hw */
	memcpy(hw->rss_info.rss_indirection_tbl, indir,	HNS3_RSS_IND_TBL_SIZE);

	return 0;
}

int
hns3_rss_reset_indir_table(struct hns3_hw *hw)
{
	uint8_t *lut;
	int ret;

	lut = rte_zmalloc("hns3_rss_lut", HNS3_RSS_IND_TBL_SIZE, 0);
	if (lut == NULL) {
		hns3_err(hw, "No hns3_rss_lut memory can be allocated");
		return -ENOMEM;
	}

	ret = hns3_set_rss_indir_table(hw, lut, HNS3_RSS_IND_TBL_SIZE);
	if (ret)
		hns3_err(hw, "RSS uninit indir table failed: %d", ret);
	rte_free(lut);

	return ret;
}

static void
hns3_set_dst_port(uint8_t *tuple, enum rte_filter_input_set_op op)
{
	uint8_t set = *tuple;
	hns3_set_bit(set, HNS3_D_PORT_BIT_SHIFT, 1);
	if (op == RTE_ETH_INPUT_SET_SELECT) {
		hns3_set_bit(set, HNS3_S_PORT_BIT_SHIFT, 0);
		hns3_set_bit(set, HNS3_D_IP_BIT_SHIFT, 0);
		hns3_set_bit(set, HNS3_S_IP_BIT_SHIFT, 0);
	}
	*tuple = set;
}

static void
hns3_set_src_port(uint8_t *tuple, enum rte_filter_input_set_op op)
{
	uint8_t set = *tuple;
	hns3_set_bit(set, HNS3_S_PORT_BIT_SHIFT, 1);
	if (op == RTE_ETH_INPUT_SET_SELECT) {
		hns3_set_bit(set, HNS3_D_PORT_BIT_SHIFT, 0);
		hns3_set_bit(set, HNS3_D_IP_BIT_SHIFT, 0);
		hns3_set_bit(set, HNS3_S_IP_BIT_SHIFT, 0);
	}
	*tuple = set;
}

static void
hns3_set_dst_ip(uint8_t *tuple, enum rte_filter_input_set_op op)
{
	uint8_t set = *tuple;
	hns3_set_bit(set, HNS3_D_IP_BIT_SHIFT, 1);
	if (op == RTE_ETH_INPUT_SET_SELECT) {
		hns3_set_bit(set, HNS3_D_PORT_BIT_SHIFT, 0);
		hns3_set_bit(set, HNS3_S_PORT_BIT_SHIFT, 0);
		hns3_set_bit(set, HNS3_S_IP_BIT_SHIFT, 0);
	}
	*tuple = set;
}

static void
hns3_set_src_ip(uint8_t *tuple, enum rte_filter_input_set_op op)
{
	uint8_t set = *tuple;
	hns3_set_bit(set, HNS3_S_IP_BIT_SHIFT, 1);
	if (op == RTE_ETH_INPUT_SET_SELECT) {
		hns3_set_bit(set, HNS3_D_PORT_BIT_SHIFT, 0);
		hns3_set_bit(set, HNS3_S_PORT_BIT_SHIFT, 0);
		hns3_set_bit(set, HNS3_D_IP_BIT_SHIFT, 0);
	}
	*tuple = set;
}

static void
hns3_set_v_tag(uint8_t *tuple, enum rte_filter_input_set_op op)
{
	uint8_t set = *tuple;
	/* Set V_TAG_BIT */
	hns3_set_bit(set, HNS3_V_TAG_BIT_SHIFT, 1);
	if (op == RTE_ETH_INPUT_SET_SELECT) {
		hns3_set_bit(set, HNS3_D_IP_BIT_SHIFT, 0);
		hns3_set_bit(set, HNS3_S_IP_BIT_SHIFT, 0);
		hns3_set_bit(set, HNS3_D_PORT_BIT_SHIFT, 0);
		hns3_set_bit(set, HNS3_S_PORT_BIT_SHIFT, 0);
	}
	*tuple = set;
}

static void
hns3_rss_ipv4_tcp_tuple_set(struct hns3_hw *hw,
				  struct rte_eth_input_set_conf *conf,
				  uint8_t *new_tuple)
{
	uint8_t ipv4_tcp_tuple = *new_tuple;
	switch (conf->field[0]) {
	case RTE_ETH_INPUT_SET_L4_TCP_DST_PORT:
		hns3_set_dst_port(&ipv4_tcp_tuple, conf->op);
		break;
	case RTE_ETH_INPUT_SET_L4_TCP_SRC_PORT:
		hns3_set_src_port(&ipv4_tcp_tuple, conf->op);
		break;
	case RTE_ETH_INPUT_SET_L3_DST_IP4:
		hns3_set_dst_ip(&ipv4_tcp_tuple, conf->op);
		break;
	case RTE_ETH_INPUT_SET_L3_SRC_IP4:
		hns3_set_src_ip(&ipv4_tcp_tuple, conf->op);
		break;
	case RTE_ETH_INPUT_SET_NONE: /* select |add none */
		hns3_info(hw, "Disable ipv4-tcp tuple");
		ipv4_tcp_tuple = 0;
		break;
	default:
		hns3_err(hw, "Invalid ipv4-tcp four tuples set: %u",
			 conf->field[0]);
		return;
	}
	*new_tuple = ipv4_tcp_tuple;
}

static void
hns3_rss_ipv4_udp_tuple_set(struct hns3_hw *hw,
				   struct rte_eth_input_set_conf *conf,
				   uint8_t *new_tuple)
{
	uint8_t ipv4_udp_tuple = *new_tuple;
	switch (conf->field[0]) {
	case RTE_ETH_INPUT_SET_L4_UDP_DST_PORT:
		hns3_set_dst_port(&ipv4_udp_tuple, conf->op);
		break;
	case RTE_ETH_INPUT_SET_L4_UDP_SRC_PORT:
		hns3_set_src_port(&ipv4_udp_tuple, conf->op);
		break;
	case RTE_ETH_INPUT_SET_L3_DST_IP4:
		hns3_set_dst_ip(&ipv4_udp_tuple, conf->op);
		break;
	case RTE_ETH_INPUT_SET_L3_SRC_IP4:
		hns3_set_src_ip(&ipv4_udp_tuple, conf->op);
		break;
	case RTE_ETH_INPUT_SET_NONE: /* select |add none */
		hns3_info(hw, "Disable ipv4-udp tuple");
		ipv4_udp_tuple = 0;
		break;
	default:
		hns3_err(hw, "Invalid ipv4-udp four tuples set: %u",
			 conf->field[0]);
		return;
	}
	*new_tuple = ipv4_udp_tuple;
}

static void
hns3_rss_ipv4_sctp_tuple_set(struct hns3_hw *hw,
			     struct rte_eth_input_set_conf *conf,
			     uint8_t *new_tuple)
{
	uint8_t ipv4_sctp_tuple = *new_tuple;
	switch (conf->field[0]) {
	case RTE_ETH_INPUT_SET_L4_SCTP_VERIFICATION_TAG:
		hns3_set_v_tag(&ipv4_sctp_tuple, conf->op);
		break;
	case RTE_ETH_INPUT_SET_L4_SCTP_DST_PORT:
		hns3_set_bit(ipv4_sctp_tuple, HNS3_D_PORT_BIT_SHIFT, 1);
		if (conf->op == RTE_ETH_INPUT_SET_SELECT) {
			hns3_set_bit(ipv4_sctp_tuple, HNS3_S_PORT_BIT_SHIFT, 0);
			hns3_info(hw, "Delete S_PORT");
			hns3_set_bit(ipv4_sctp_tuple, HNS3_D_IP_BIT_SHIFT, 0);
			hns3_info(hw, "Delete DST_IP");
			hns3_set_bit(ipv4_sctp_tuple, HNS3_S_IP_BIT_SHIFT, 0);
			hns3_info(hw, "Delete SRC_IP");
			hns3_set_bit(ipv4_sctp_tuple, HNS3_V_TAG_BIT_SHIFT, 0);
			hns3_info(hw, "Delete VERI_TAG");
		}
		break;
	case RTE_ETH_INPUT_SET_L4_SCTP_SRC_PORT:
		hns3_set_bit(ipv4_sctp_tuple, HNS3_S_PORT_BIT_SHIFT, 1);
		if (conf->op == RTE_ETH_INPUT_SET_SELECT) {
			hns3_set_bit(ipv4_sctp_tuple, HNS3_V_TAG_BIT_SHIFT, 0);
			hns3_info(hw, "Delete VERI_TAG");
			hns3_set_bit(ipv4_sctp_tuple, HNS3_D_PORT_BIT_SHIFT, 0);
			hns3_info(hw, "Delete D_PORT");
			hns3_set_bit(ipv4_sctp_tuple, HNS3_D_IP_BIT_SHIFT, 0);
			hns3_info(hw, "Delete DST_IP");
			hns3_set_bit(ipv4_sctp_tuple, HNS3_S_IP_BIT_SHIFT, 0);
			hns3_info(hw, "Delete SRC_IP");
		}
		break;
	case RTE_ETH_INPUT_SET_L3_DST_IP4:
		hns3_set_bit(ipv4_sctp_tuple, HNS3_D_IP_BIT_SHIFT, 1);
		if (conf->op == RTE_ETH_INPUT_SET_SELECT) {
			hns3_set_bit(ipv4_sctp_tuple, HNS3_D_PORT_BIT_SHIFT, 0);
			hns3_info(hw, "Delete D_PORT");
			hns3_set_bit(ipv4_sctp_tuple, HNS3_S_PORT_BIT_SHIFT, 0);
			hns3_info(hw, "Delete S_PORT");
			hns3_set_bit(ipv4_sctp_tuple, HNS3_S_IP_BIT_SHIFT, 0);
			hns3_info(hw, "Delete SRC_IP");
			hns3_set_bit(ipv4_sctp_tuple, HNS3_V_TAG_BIT_SHIFT, 0);
			hns3_info(hw, "Delete VERI_TAG");
		}
		break;
	case RTE_ETH_INPUT_SET_L3_SRC_IP4:
		hns3_set_bit(ipv4_sctp_tuple, HNS3_S_IP_BIT_SHIFT, 1);
		if (conf->op == RTE_ETH_INPUT_SET_SELECT) {
			hns3_set_bit(ipv4_sctp_tuple, HNS3_D_PORT_BIT_SHIFT, 0);
			hns3_info(hw, "Delete D_PORT");
			hns3_set_bit(ipv4_sctp_tuple, HNS3_S_PORT_BIT_SHIFT, 0);
			hns3_info(hw, "Delete S_PORT");
			hns3_set_bit(ipv4_sctp_tuple, HNS3_D_IP_BIT_SHIFT, 0);
			hns3_info(hw, "Delete DST_IP");
			hns3_set_bit(ipv4_sctp_tuple, HNS3_V_TAG_BIT_SHIFT, 0);
			hns3_info(hw, "Delete VERI_TAG");
		}
		break;
	case RTE_ETH_INPUT_SET_NONE: /* select |add none */
		hns3_info(hw, "Disable ipv4-sctp tuple");
		ipv4_sctp_tuple = 0;
		break;
	default:
		hns3_err(hw, "Invalid ipv4-sctp four tuples set: %u",
			 conf->field[0]);
		return;
	}
	*new_tuple = ipv4_sctp_tuple;
}

static void
hns3_rss_ipv4_frag_tuple_set(struct hns3_hw *hw,
			     struct rte_eth_input_set_conf *conf,
			     uint8_t *new_tuple)
{
	uint8_t ipv4_frag_tuple = *new_tuple;
	switch (conf->field[0]) {
	case RTE_ETH_INPUT_SET_L3_DST_IP4:
		/* Set dst-ip(bit2) */
		hns3_set_bit(ipv4_frag_tuple, HNS3_D_IP_BIT_SHIFT, 1);
		if (conf->op == RTE_ETH_INPUT_SET_SELECT) {
			/* Clear src-ip(bit3) */
			hns3_set_bit(ipv4_frag_tuple, HNS3_S_IP_BIT_SHIFT, 0);
			hns3_info(hw, "Delete SRC_IP");
		}
		break;
	case RTE_ETH_INPUT_SET_L3_SRC_IP4:
		/* Set src-ip(bit3) */
		hns3_set_bit(ipv4_frag_tuple, HNS3_S_IP_BIT_SHIFT, 1);
		if (conf->op == RTE_ETH_INPUT_SET_SELECT) {
			/* Clear dst-ip(bit2) */
			hns3_set_bit(ipv4_frag_tuple, HNS3_D_IP_BIT_SHIFT, 0);
			hns3_info(hw, "Delete DST_IP");
		}
		break;
	case RTE_ETH_INPUT_SET_NONE: /* select |add none */
		hns3_info(hw, "Disable ipv4-frag tuple");
		/* Clear dst_ip(bit2) and src_ip(bit3) */
		ipv4_frag_tuple &= ~HNS3_IP_FRAG_BIT_MASK;
		break;
	default:
		hns3_err(hw, "Invalid ipv4-frag four tuples set: %u",
			 conf->field[0]);
		return;
	}
	*new_tuple = ipv4_frag_tuple;
}

static void
hns3_rss_ipv4_other_tuple_set(struct hns3_hw *hw,
			      struct rte_eth_input_set_conf *conf,
			      uint8_t *new_tuple)
{
	uint8_t tuple = *new_tuple;
	switch (conf->field[0]) {
	case RTE_ETH_INPUT_SET_L3_DST_IP4:
		/* Set dst_ip(bit0) */
		hns3_set_bit(tuple, HNS3_D_PORT_BIT_SHIFT, 1);
		if (conf->op == RTE_ETH_INPUT_SET_SELECT) {
			/* Clear src_ip(bit1) */
			hns3_set_bit(tuple, HNS3_S_PORT_BIT_SHIFT, 0);
			hns3_info(hw, "Delete SRC_IP");
		}
		break;
	case RTE_ETH_INPUT_SET_L3_SRC_IP4:
		/* Set src_ip(bit1) */
		hns3_set_bit(tuple, HNS3_S_PORT_BIT_SHIFT, 1);
		if (conf->op == RTE_ETH_INPUT_SET_SELECT) {
			/* Set dst_ip(bit0) */
			hns3_set_bit(tuple, HNS3_D_PORT_BIT_SHIFT, 0);
			hns3_info(hw, "Delete DST_IP");
		}
		break;
	case RTE_ETH_INPUT_SET_NONE: /* select |add none */
		hns3_info(hw, "Disable ipv4-other tuple");
		/* Clear dst_ip(bit0) and src_ip(bit1) */
		tuple &= ~HNS3_IP_OTHER_BIT_MASK;
		break;
	default:
		hns3_err(hw, "Invalid ipv4-other four tuples set: %u",
			 conf->field[0]);
		return;
	}
	*new_tuple = tuple;
}

static void
hns3_rss_ipv6_tcp_tuple_set(struct hns3_hw *hw,
			    struct rte_eth_input_set_conf *conf,
			    uint8_t *new_tuple)
{
	uint8_t ipv6_tcp_tuple = *new_tuple;
	switch (conf->field[0]) {
	case RTE_ETH_INPUT_SET_L4_TCP_DST_PORT:
		hns3_set_dst_port(&ipv6_tcp_tuple, conf->op);
		break;
	case RTE_ETH_INPUT_SET_L4_TCP_SRC_PORT:
		hns3_set_src_port(&ipv6_tcp_tuple, conf->op);
		break;
	case RTE_ETH_INPUT_SET_L3_DST_IP6:
		hns3_set_dst_ip(&ipv6_tcp_tuple, conf->op);
		break;
	case RTE_ETH_INPUT_SET_L3_SRC_IP6:
		hns3_set_src_ip(&ipv6_tcp_tuple, conf->op);
		break;
	case RTE_ETH_INPUT_SET_NONE: /* select |add none */
		hns3_info(hw, "Disable ipv6-tcp tuple");
		ipv6_tcp_tuple = 0;
		break;
	default:
		hns3_err(hw, "Invalid ipv6-tcp four tuples set: %u",
			 conf->field[0]);
		return;
	}
	*new_tuple = ipv6_tcp_tuple;
}

static void
hns3_rss_ipv6_udp_tuple_set(struct hns3_hw *hw,
			    struct rte_eth_input_set_conf *conf,
			    uint8_t *new_tuple)
{
	uint8_t ipv6_udp_tuple = *new_tuple;
	switch (conf->field[0]) {
	case RTE_ETH_INPUT_SET_L4_UDP_DST_PORT:
		hns3_set_dst_port(&ipv6_udp_tuple, conf->op);
		break;
	case RTE_ETH_INPUT_SET_L4_UDP_SRC_PORT:
		hns3_set_src_port(&ipv6_udp_tuple, conf->op);
		break;
	case RTE_ETH_INPUT_SET_L3_DST_IP6:
		hns3_set_dst_ip(&ipv6_udp_tuple, conf->op);
		break;
	case RTE_ETH_INPUT_SET_L3_SRC_IP6:
		hns3_set_src_ip(&ipv6_udp_tuple, conf->op);
		break;
	case RTE_ETH_INPUT_SET_NONE: /* select |add none */
		hns3_info(hw, "Disable ipv6-udp tuple");
		ipv6_udp_tuple = 0;
		break;
	default:
		hns3_err(hw, "Invalid ipv6-udp four tuples set: %u",
			 conf->field[0]);
		return;
	}
	*new_tuple = ipv6_udp_tuple;
}

static void
hns3_rss_ipv6_sctp_tuple_set(struct hns3_hw *hw,
			     struct rte_eth_input_set_conf *conf,
			     uint8_t *new_tuple)
{
	uint8_t ipv6_sctp_tuple = *new_tuple;
	switch (conf->field[0]) {
	case RTE_ETH_INPUT_SET_L4_SCTP_VERIFICATION_TAG:
		hns3_set_v_tag(&ipv6_sctp_tuple, conf->op);
		break;
	case RTE_ETH_INPUT_SET_L3_DST_IP6:
		hns3_set_bit(ipv6_sctp_tuple, HNS3_D_IP_BIT_SHIFT, 1);
		if (conf->op == RTE_ETH_INPUT_SET_SELECT) {
			hns3_set_bit(ipv6_sctp_tuple, HNS3_D_PORT_BIT_SHIFT, 0);
			hns3_info(hw, "Delete D_PORT");
			hns3_set_bit(ipv6_sctp_tuple, HNS3_S_PORT_BIT_SHIFT, 0);
			hns3_info(hw, "Delete S_PORT");
			hns3_set_bit(ipv6_sctp_tuple, HNS3_S_IP_BIT_SHIFT, 0);
			hns3_info(hw, "Delete SRC_IP");
			hns3_set_bit(ipv6_sctp_tuple, HNS3_V_TAG_BIT_SHIFT, 0);
			hns3_info(hw, "Delete VERI_TAG");
		}
		break;
	case RTE_ETH_INPUT_SET_L3_SRC_IP6:
		hns3_set_bit(ipv6_sctp_tuple, HNS3_S_IP_BIT_SHIFT, 1);
		if (conf->op == RTE_ETH_INPUT_SET_SELECT) {
			hns3_set_bit(ipv6_sctp_tuple, HNS3_D_PORT_BIT_SHIFT, 0);
			hns3_info(hw, "Delete D_PORT");
			hns3_set_bit(ipv6_sctp_tuple, HNS3_S_PORT_BIT_SHIFT, 0);
			hns3_info(hw, "Delete S_PORT");
			hns3_set_bit(ipv6_sctp_tuple, HNS3_D_IP_BIT_SHIFT, 0);
			hns3_info(hw, "Delete DST_IP");
			hns3_set_bit(ipv6_sctp_tuple, HNS3_V_TAG_BIT_SHIFT, 0);
			hns3_info(hw, "Delete VERI_TAG");
		}
		break;
	case RTE_ETH_INPUT_SET_NONE: /* select |add none */
		hns3_info(hw, "Disable ipv6-sctp tuple");
		ipv6_sctp_tuple = 0;
		break;
	default:
		hns3_err(hw, "Invalid ipv6-sctp four tuples set: %u",
			 conf->field[0]);
		return;
	}
	*new_tuple = ipv6_sctp_tuple;
}

static void
hns3_rss_ipv6_frag_tuple_set(struct hns3_hw *hw,
			     struct rte_eth_input_set_conf *conf,
			     uint8_t *new_tuple)
{
	uint8_t ipv6_frag_tuple = *new_tuple;
	switch (conf->field[0]) {
	case RTE_ETH_INPUT_SET_L3_DST_IP6:
		/* Set dst-ip(bit2) */
		hns3_set_bit(ipv6_frag_tuple, HNS3_D_IP_BIT_SHIFT, 1);
		if (conf->op == RTE_ETH_INPUT_SET_SELECT) {
			/* Clear src-ip(bit3) */
			hns3_set_bit(ipv6_frag_tuple, HNS3_S_IP_BIT_SHIFT, 0);
			hns3_info(hw, "Delete SRC_IP");
		}
		break;
	case RTE_ETH_INPUT_SET_L3_SRC_IP6:
		/* Set src-ip(bit3) */
		hns3_set_bit(ipv6_frag_tuple, HNS3_S_IP_BIT_SHIFT, 1);
		if (conf->op == RTE_ETH_INPUT_SET_SELECT) {
			/* Clear dst-ip(bit2) */
			hns3_set_bit(ipv6_frag_tuple, HNS3_D_IP_BIT_SHIFT, 0);
			hns3_info(hw, "Delete DST_IP");
		}
		break;
	case RTE_ETH_INPUT_SET_NONE: /* select|add none */
		hns3_info(hw, "Disable ipv6-frag tuple");
		/* Clear dst-ip(bit2) and src-ip(bit3) */
		ipv6_frag_tuple &= ~HNS3_IP_FRAG_BIT_MASK;
		break;
	default:
		hns3_err(hw, "Invalid ipv6-frag four tuples set: %u",
			 conf->field[0]);
		return;
	}
	*new_tuple = ipv6_frag_tuple;
}

static void
hns3_rss_ipv6_other_tuple_set(struct hns3_hw *hw,
			      struct rte_eth_input_set_conf *conf,
			      uint8_t *new_tuple)
{
	uint8_t tuple = *new_tuple;
	switch (conf->field[0]) {
	case RTE_ETH_INPUT_SET_L3_DST_IP6:
		/* Set dst_ip(bit0) */
		hns3_set_bit(tuple, HNS3_D_PORT_BIT_SHIFT, 1);
		if (conf->op == RTE_ETH_INPUT_SET_SELECT) {
			/* Clear src_ip(bit1) */
			hns3_set_bit(tuple, HNS3_S_PORT_BIT_SHIFT, 0);
			hns3_info(hw, "Delete SRC_IP");
		}
		break;
	case RTE_ETH_INPUT_SET_L3_SRC_IP6:
		/* Set src_ip(bit1) */
		hns3_set_bit(tuple, HNS3_S_PORT_BIT_SHIFT, 1);
		if (conf->op == RTE_ETH_INPUT_SET_SELECT) {
			/* Set dst_ip(bit0) */
			hns3_set_bit(tuple, HNS3_D_IP_BIT_SHIFT, 0);
			hns3_info(hw, "Delete DST_IP");
		}
		break;
	case RTE_ETH_INPUT_SET_NONE: /* select|add none */
		hns3_info(hw, "Disable ipv6-other tuple");
		/* Clear dst-ip(bit0) and src-ip(bit1) */
		tuple &= ~HNS3_IP_OTHER_BIT_MASK;
		break;
	default:
		hns3_err(hw, "Invalid ipv6-other four tuples set: %u",
			 conf->field[0]);
		return;
	}
	*new_tuple = tuple;
}

static void
hns3_update_rss_hash_by_tuple_cfg(struct hns3_hw *hw)
{
	struct hns3_rss_tuple_cfg *tuple_cfg = &hw->rss_info.rss_tuple_sets;
	uint32_t flow_types = 0;

	if (tuple_cfg->ipv4_tcp_en)
		flow_types |= ETH_RSS_NONFRAG_IPV4_TCP;
	if (tuple_cfg->ipv4_udp_en)
		flow_types |= ETH_RSS_NONFRAG_IPV4_UDP;
	if (tuple_cfg->ipv4_sctp_en)
		flow_types |= ETH_RSS_NONFRAG_IPV4_SCTP;
	if (tuple_cfg->ipv4_fragment_en & HNS3_IP_FRAG_BIT_MASK)
		flow_types |= ETH_RSS_FRAG_IPV4;
	if (tuple_cfg->ipv4_fragment_en & HNS3_IP_OTHER_BIT_MASK)
		flow_types |= ETH_RSS_NONFRAG_IPV4_OTHER;
	if (tuple_cfg->ipv6_tcp_en)
		flow_types |= ETH_RSS_NONFRAG_IPV6_TCP;
	if (tuple_cfg->ipv6_udp_en)
		flow_types |= ETH_RSS_NONFRAG_IPV6_UDP;
	if (tuple_cfg->ipv6_sctp_en)
		flow_types |= ETH_RSS_NONFRAG_IPV6_SCTP;
	if (tuple_cfg->ipv6_fragment_en & HNS3_IP_FRAG_BIT_MASK)
		flow_types |= ETH_RSS_FRAG_IPV6;
	if (tuple_cfg->ipv6_fragment_en & HNS3_IP_OTHER_BIT_MASK)
		flow_types |= ETH_RSS_NONFRAG_IPV6_OTHER;

	hw->rss_info.conf.types = flow_types;
}

static int
hns3_set_rss_input_tuple_parse(struct hns3_hw *hw,
			       struct rte_eth_input_set_conf *conf,
			       uint64_t rss_hf)
{
	struct hns3_rss_tuple_cfg *tuple_cfg = &hw->rss_info.rss_tuple_sets;
	struct hns3_rss_conf *rss_cfg = &hw->rss_info;
	struct hns3_rss_input_tuple_cmd *req;
	struct hns3_cmd_desc desc;
	uint64_t flow_types;
	uint32_t i;
	int ret;

	/* Filter the unsupported flow types */
	flow_types = rss_hf & HNS3_ETH_RSS_SUPPORT;
	if (flow_types == 0) {
		hns3_err(hw, "RSS tuple command(%lu) is unsupported,"
			 " the supported mask is %llu",
			 rss_hf, HNS3_ETH_RSS_SUPPORT);
		return -ENOTSUP;
	}

	hns3_cmd_setup_basic_desc(&desc, HNS3_OPC_RSS_INPUT_TUPLE, false);

	req = (struct hns3_rss_input_tuple_cmd *)desc.data;

	req->ipv4_tcp_en = rss_cfg->rss_tuple_sets.ipv4_tcp_en;
	req->ipv4_udp_en = rss_cfg->rss_tuple_sets.ipv4_udp_en;
	req->ipv4_sctp_en = rss_cfg->rss_tuple_sets.ipv4_sctp_en;
	req->ipv4_fragment_en = rss_cfg->rss_tuple_sets.ipv4_fragment_en;
	req->ipv6_tcp_en = rss_cfg->rss_tuple_sets.ipv6_tcp_en;
	req->ipv6_udp_en = rss_cfg->rss_tuple_sets.ipv6_udp_en;
	req->ipv6_sctp_en = rss_cfg->rss_tuple_sets.ipv6_sctp_en;
	req->ipv6_fragment_en = rss_cfg->rss_tuple_sets.ipv6_fragment_en;

	/* Enable ipv4 or ipv6 tuple by flow type */
	for (i = 0; i < RTE_ETH_FLOW_MAX; i++) {
		switch (flow_types & (1ULL << i)) {
		case ETH_RSS_NONFRAG_IPV4_TCP:
			hns3_rss_ipv4_tcp_tuple_set(hw, conf,
						    &req->ipv4_tcp_en);
			break;
		case ETH_RSS_NONFRAG_IPV4_UDP:
			hns3_rss_ipv4_udp_tuple_set(hw, conf,
						    &req->ipv4_udp_en);
			break;
		case ETH_RSS_NONFRAG_IPV4_SCTP:
			hns3_rss_ipv4_sctp_tuple_set(hw, conf,
						     &req->ipv4_sctp_en);
			break;
		case ETH_RSS_FRAG_IPV4:
			hns3_rss_ipv4_frag_tuple_set(hw, conf,
						     &req->ipv4_fragment_en);
			break;
		case ETH_RSS_NONFRAG_IPV4_OTHER:
			hns3_rss_ipv4_other_tuple_set(hw, conf,
						      &req->ipv4_fragment_en);
			break;
		case ETH_RSS_NONFRAG_IPV6_TCP:
			hns3_rss_ipv6_tcp_tuple_set(hw, conf,
						    &req->ipv6_tcp_en);
			break;
		case ETH_RSS_NONFRAG_IPV6_UDP:
			hns3_rss_ipv6_udp_tuple_set(hw, conf,
						    &req->ipv6_udp_en);
			break;
		case ETH_RSS_NONFRAG_IPV6_SCTP:
			hns3_rss_ipv6_sctp_tuple_set(hw, conf,
						     &req->ipv6_sctp_en);
			break;
		case ETH_RSS_FRAG_IPV6:
			hns3_rss_ipv6_frag_tuple_set(hw, conf,
						     &req->ipv6_fragment_en);
			break;
		case ETH_RSS_NONFRAG_IPV6_OTHER:
			hns3_rss_ipv6_other_tuple_set(hw, conf,
						      &req->ipv6_fragment_en);
			break;
		default:
			/*
			 * Other unsupported flow types won't change tuples set
			 * of RSS.
			 */
			break;
		}
	}
	ret = hns3_cmd_send(hw, &desc, 1);
	if (ret) {
		hns3_err(hw, "RSS update tuple failed: %d", ret);
		return ret;
	}

	/* Update the tuple of hw */
	tuple_cfg->ipv4_tcp_en = req->ipv4_tcp_en;
	tuple_cfg->ipv4_udp_en = req->ipv4_udp_en;
	tuple_cfg->ipv4_sctp_en = req->ipv4_sctp_en;
	tuple_cfg->ipv4_fragment_en = req->ipv4_fragment_en;
	tuple_cfg->ipv6_tcp_en = req->ipv6_tcp_en;
	tuple_cfg->ipv6_udp_en = req->ipv6_udp_en;
	tuple_cfg->ipv6_sctp_en = req->ipv6_sctp_en;
	tuple_cfg->ipv6_fragment_en = req->ipv6_fragment_en;

	hns3_update_rss_hash_by_tuple_cfg(hw);

	return 0;
}

int
hns3_set_rss_tuple_by_rss_hf(struct hns3_hw *hw,
			     struct hns3_rss_tuple_cfg *tuple, uint64_t rss_hf)
{
	struct hns3_rss_input_tuple_cmd *req;
	struct hns3_cmd_desc desc;
	uint32_t i;
	int ret;

	hns3_cmd_setup_basic_desc(&desc, HNS3_OPC_RSS_INPUT_TUPLE, false);

	req = (struct hns3_rss_input_tuple_cmd *)desc.data;

	/* Enable ipv4 or ipv6 tuple by flow type */
	for (i = 0; i < RTE_ETH_FLOW_MAX; i++) {
		switch (rss_hf & (1ULL << i)) {
		case ETH_RSS_NONFRAG_IPV4_TCP:
			req->ipv4_tcp_en = HNS3_RSS_INPUT_TUPLE_OTHER;
			break;
		case ETH_RSS_NONFRAG_IPV4_UDP:
			req->ipv4_udp_en = HNS3_RSS_INPUT_TUPLE_OTHER;
			break;
		case ETH_RSS_NONFRAG_IPV4_SCTP:
			req->ipv4_sctp_en = HNS3_RSS_INPUT_TUPLE_SCTP;
			break;
		case ETH_RSS_FRAG_IPV4:
			req->ipv4_fragment_en |= HNS3_IP_FRAG_BIT_MASK;
			break;
		case ETH_RSS_NONFRAG_IPV4_OTHER:
			req->ipv4_fragment_en |= HNS3_IP_OTHER_BIT_MASK;
			break;
		case ETH_RSS_NONFRAG_IPV6_TCP:
			req->ipv6_tcp_en = HNS3_RSS_INPUT_TUPLE_OTHER;
			break;
		case ETH_RSS_NONFRAG_IPV6_UDP:
			req->ipv6_udp_en = HNS3_RSS_INPUT_TUPLE_OTHER;
			break;
		case ETH_RSS_NONFRAG_IPV6_SCTP:
			req->ipv6_sctp_en = HNS3_RSS_INPUT_TUPLE_SCTP;
			break;
		case ETH_RSS_FRAG_IPV6:
			req->ipv6_fragment_en |= HNS3_IP_FRAG_BIT_MASK;
			break;
		case ETH_RSS_NONFRAG_IPV6_OTHER:
			req->ipv6_fragment_en |= HNS3_IP_OTHER_BIT_MASK;
			break;
		default:
			/* Other unsupported flow types won't change tuples */
			break;
		}
	}

	ret = hns3_cmd_send(hw, &desc, 1);
	if (ret) {
		hns3_err(hw, "Update RSS flow types tuples failed %d", ret);
		return ret;
	}

	tuple->ipv4_tcp_en = req->ipv4_tcp_en;
	tuple->ipv4_udp_en = req->ipv4_udp_en;
	tuple->ipv4_sctp_en = req->ipv4_sctp_en;
	tuple->ipv4_fragment_en = req->ipv4_fragment_en;
	tuple->ipv6_tcp_en = req->ipv6_tcp_en;
	tuple->ipv6_udp_en = req->ipv6_udp_en;
	tuple->ipv6_sctp_en = req->ipv6_sctp_en;
	tuple->ipv6_fragment_en = req->ipv6_fragment_en;

	return 0;
}

/*
 * Configure RSS hash protocols and hash key.
 * @param dev
 *   Pointer to Ethernet device.
 * @praram rss_conf
 *   The configuration select of  rss key size and tuple flow_types.
 * @return
 *   0 on success, a negative errno value otherwise is set.
 */
int
hns3_dev_rss_hash_update(struct rte_eth_dev *dev,
			 struct rte_eth_rss_conf *rss_conf)
{
	struct hns3_adapter *hns = dev->data->dev_private;
	struct hns3_hw *hw = &hns->hw;
	struct hns3_rss_tuple_cfg *tuple = &hw->rss_info.rss_tuple_sets;
	struct hns3_rss_conf *rss_cfg = &hw->rss_info;
	uint8_t algo = rss_cfg->conf.func;
	uint8_t key_len = rss_conf->rss_key_len;
	uint64_t rss_hf = rss_conf->rss_hf;
	uint8_t *key = rss_conf->rss_key;
	int ret;

	rte_spinlock_lock(&hw->lock);
	ret = hns3_set_rss_tuple_by_rss_hf(hw, tuple, rss_hf);
	if (ret)
		goto conf_err;

	if (rss_cfg->conf.types && rss_hf == 0) {
		/* Disable RSS, reset indirection table by local variable */
		ret = hns3_rss_reset_indir_table(hw);
		if (ret)
			goto conf_err;
	} else if (rss_hf && rss_cfg->conf.types == 0) {
		/* Enable RSS, restore indirection table by hw's config */
		ret = hns3_set_rss_indir_table(hw, rss_cfg->rss_indirection_tbl,
					       HNS3_RSS_IND_TBL_SIZE);
		if (ret)
			goto conf_err;
	}

	/* Update supported flow types when set tuple success */
	rss_cfg->conf.types = rss_hf;

	if (key) {
		if (key_len != HNS3_RSS_KEY_SIZE) {
			hns3_err(hw, "The hash key len(%u) is invalid",
				 key_len);
			ret = -EINVAL;
			goto conf_err;
		}
		ret = hns3_set_rss_algo_key(hw, algo, key);
		if (ret)
			goto conf_err;
	}
	rte_spinlock_unlock(&hw->lock);

	return 0;

conf_err:
	rte_spinlock_unlock(&hw->lock);
	return ret;
}

/*
 * Get rss key and rss_hf types set of RSS hash configuration.
 * @param dev
 *   Pointer to Ethernet device.
 * @praram rss_conf
 *   The buffer to get rss key size and tuple types.
 * @return
 *   0 on success.
 */
int
hns3_dev_rss_hash_conf_get(struct rte_eth_dev *dev,
			   struct rte_eth_rss_conf *rss_conf)
{
	struct hns3_adapter *hns = dev->data->dev_private;
	struct hns3_hw *hw = &hns->hw;
	struct hns3_rss_conf *rss_cfg = &hw->rss_info;

	rte_spinlock_lock(&hw->lock);
	rss_conf->rss_hf = rss_cfg->conf.types;

	/* Get the RSS Key required by the user */
	if (rss_conf->rss_key)
		memcpy(rss_conf->rss_key, rss_cfg->key, HNS3_RSS_KEY_SIZE);
	rte_spinlock_unlock(&hw->lock);

	return 0;
}

/*
 * Update rss redirection table of RSS.
 * @param dev
 *   Pointer to Ethernet device.
 * @praram reta_conf
 *   Pointer to the configuration select of mask and redirection tables.
 * @param reta_size
 *   Redirection table size.
 * @return
 *   0 on success, a negative errno value otherwise is set.
 */
int
hns3_dev_rss_reta_update(struct rte_eth_dev *dev,
			 struct rte_eth_rss_reta_entry64 *reta_conf,
			 uint16_t reta_size)
{
	struct hns3_adapter *hns = dev->data->dev_private;
	struct hns3_hw *hw = &hns->hw;
	struct hns3_rss_conf *rss_cfg = &hw->rss_info;
	uint16_t i, indir_size = HNS3_RSS_IND_TBL_SIZE; /* Table size is 512 */
	uint8_t indirection_tbl[HNS3_RSS_IND_TBL_SIZE];
	uint16_t idx, shift, allow_rss_queues;
	int ret;

	if (reta_size != indir_size || reta_size > ETH_RSS_RETA_SIZE_512) {
		hns3_err(hw, "The size of hash lookup table configured (%u)"
			 "doesn't match the number hardware can supported"
			 "(%u)", reta_size, indir_size);
		return -EINVAL;
	}
	rte_spinlock_lock(&hw->lock);
	memcpy(indirection_tbl, rss_cfg->rss_indirection_tbl,
		HNS3_RSS_IND_TBL_SIZE);
	allow_rss_queues = RTE_MIN(dev->data->nb_rx_queues, hw->rss_size_max);
	for (i = 0; i < reta_size; i++) {
		idx = i / RTE_RETA_GROUP_SIZE;
		shift = i % RTE_RETA_GROUP_SIZE;
		if (reta_conf[idx].reta[shift] >= allow_rss_queues) {
			rte_spinlock_unlock(&hw->lock);
			hns3_err(hw, "Invalid queue id(%u) to be set in "
				 "redirection table, max number of rss "
				 "queues: %u", reta_conf[idx].reta[shift],
				 allow_rss_queues);
			return -EINVAL;
		}

		if (reta_conf[idx].mask & (1ULL << shift))
			indirection_tbl[i] = reta_conf[idx].reta[shift];
	}

	ret = hns3_set_rss_indir_table(hw, indirection_tbl,
				       HNS3_RSS_IND_TBL_SIZE);

	rte_spinlock_unlock(&hw->lock);
	return ret;
}

/*
 * Get rss redirection table of RSS hash configuration.
 * @param dev
 *   Pointer to Ethernet device.
 * @praram reta_conf
 *   Pointer to the configuration select of mask and redirection tables.
 * @param reta_size
 *   Redirection table size.
 * @return
 *   0 on success, a negative errno value otherwise is set.
 */
int
hns3_dev_rss_reta_query(struct rte_eth_dev *dev,
			struct rte_eth_rss_reta_entry64 *reta_conf,
			uint16_t reta_size)
{
	struct hns3_adapter *hns = dev->data->dev_private;
	struct hns3_hw *hw = &hns->hw;
	struct hns3_rss_conf *rss_cfg = &hw->rss_info;
	uint16_t i, indir_size = HNS3_RSS_IND_TBL_SIZE; /* Table size is 512 */
	uint16_t idx, shift;

	if (reta_size != indir_size || reta_size > ETH_RSS_RETA_SIZE_512) {
		hns3_err(hw, "The size of hash lookup table configured (%u)"
			 " doesn't match the number hardware can supported"
			 "(%u)", reta_size, indir_size);
		return -EINVAL;
	}
	rte_spinlock_lock(&hw->lock);
	for (i = 0; i < reta_size; i++) {
		idx = i / RTE_RETA_GROUP_SIZE;
		shift = i % RTE_RETA_GROUP_SIZE;
		if (reta_conf[idx].mask & (1ULL << shift))
			reta_conf[idx].reta[shift] =
			  rss_cfg->rss_indirection_tbl[i] % hw->alloc_rss_size;
	}
	rte_spinlock_unlock(&hw->lock);
	return 0;
}

static void
hns3_hash_filter_global_config_get(struct hns3_hw *hw,
				   struct rte_eth_hash_filter_info *info)
{
	/* Get algorithm configuration */
	info->info.global_conf.hash_func = hw->rss_info.conf.func;
}

static int
hns3_hash_filter_get(struct hns3_hw *hw,
		     struct rte_eth_hash_filter_info *info)
{
	int ret = 0;

	if (info == NULL) {
		hns3_err(hw, "Invalid filter info pointer");
		return -EINVAL;
	}

	switch (info->info_type) {
	case RTE_ETH_HASH_FILTER_GLOBAL_CONFIG:
		hns3_hash_filter_global_config_get(hw, info);
		break;
	default:
		hns3_err(hw, "Hash filter info type (%d) not supported",
			 info->info_type);
		ret = -EINVAL;
		break;
	}

	return ret;
}

static int
hns3_hash_filter_global_config_set(struct hns3_hw *hw,
				   struct rte_eth_hash_filter_info *info)
{
	struct hns3_rss_conf *rss_cfg = &hw->rss_info;
	uint8_t *hash_key = rss_cfg->key;
	uint8_t hash_algo;
	int ret;

	/* Set hash algorithm */
	switch (info->info.global_conf.hash_func) {
	case RTE_ETH_HASH_FUNCTION_DEFAULT:
		/* Keep algorithm as it used to be */
		return 0;
	case RTE_ETH_HASH_FUNCTION_TOEPLITZ:
		hash_algo = HNS3_RSS_HASH_ALGO_TOEPLITZ;
		break;
	case RTE_ETH_HASH_FUNCTION_SIMPLE_XOR:
		hash_algo = HNS3_RSS_HASH_ALGO_SIMPLE;
		break;
	default:
		hns3_err(hw, "Invalid RSS hash_algo configuration %u",
			 info->info.global_conf.hash_func);
		return -EINVAL;
	}
	ret = hns3_set_rss_algo_key(hw, hash_algo, hash_key);
	if (ret)
		return ret;
	/* Update hash algorithm after config success */
	rss_cfg->conf.func = info->info.global_conf.hash_func;

	return 0;
}

static int
hns3_hash_filter_inset_select_set(struct hns3_hw *hw,
				  struct rte_eth_hash_filter_info *info)
{
	struct rte_eth_input_set_conf *conf = &info->info.input_set_conf;
	uint64_t rss_hf = 1ULL << conf->flow_type;

	if (conf->op != RTE_ETH_INPUT_SET_SELECT &&
	    conf->op != RTE_ETH_INPUT_SET_ADD) {
		hns3_err(hw, "Unsupported input set operation(%u)", conf->op);
		return -ENOTSUP;
	}

	if (conf->flow_type > RTE_ETH_FLOW_MAX) {
		hns3_err(hw, "Unsupported flow_type(%u)", conf->flow_type);
		return -ENOTSUP;
	}

	/* Set the bit of input tuple */
	return hns3_set_rss_input_tuple_parse(hw, conf, rss_hf);
}

static int
hns3_hash_filter_set(struct hns3_hw *hw,
		     struct rte_eth_hash_filter_info *info)
{
	int ret = 0;

	if (info == NULL) {
		hns3_err(hw, "Invalid filter info pointer");
		return -EINVAL;
	}

	switch (info->info_type) {
	case RTE_ETH_HASH_FILTER_GLOBAL_CONFIG:
		rte_spinlock_lock(&hw->lock);
		ret = hns3_hash_filter_global_config_set(hw, info);
		rte_spinlock_unlock(&hw->lock);
		break;
	case RTE_ETH_HASH_FILTER_INPUT_SET_SELECT:
		rte_spinlock_lock(&hw->lock);
		ret = hns3_hash_filter_inset_select_set(hw, info);
		rte_spinlock_unlock(&hw->lock);
		break;
	default:
		hns3_err(hw, "Hash filter info type (%d) not supported",
			 info->info_type);
		ret = -EINVAL;
		break;
	}

	return ret;
}

/* Operations for hash function */
static int
hns3_hash_filter_ctrl(struct rte_eth_dev *dev, enum rte_filter_op filter_op,
		      void *arg)
{
	struct hns3_adapter *hns = dev->data->dev_private;
	struct hns3_hw *hw = &hns->hw;
	struct rte_eth_hash_filter_info *input_arg = arg;
	int ret = 0;

	switch (filter_op) {
	case RTE_ETH_FILTER_NOP:
		break;
	case RTE_ETH_FILTER_GET:
		/* Get the hash algorithm and key */
		ret = hns3_hash_filter_get(hw, input_arg);
		break;
	case RTE_ETH_FILTER_SET:
		/* Set the hash algorithm and key */
		ret = hns3_hash_filter_set(hw, input_arg);
		break;
	default:
		hns3_err(hw, "Filter operation (%d) not supported", filter_op);
		ret = -ENOTSUP;
		break;
	}

	return ret;
}

/*
 * RSS hash algorithm configuration.
 * @param dev
 *   Pointer to Ethernet device.
 * @praram filter_type
 *   Feature filter types.Select RTE_ETH_FILTER_HASH to operate hash func.
 * @praram filter_op
 *   Pointer to Ethernet device.
 * @praram filter_type
 *   Generic operations on filters.Select RTE_ETH_FILTER_GET/SET to get/set
 *   Hash_algorithm.
 * @praram arg
 *   Pointer to structure rte_eth_hash_filter_info.
 * @return
 *   0 on success, a negative errno value otherwise is set.
 */
int
hns3_dev_filter_ctrl(struct rte_eth_dev *dev, enum rte_filter_type filter_type,
		     enum rte_filter_op filter_op, void *arg)
{
	struct hns3_hw *hw;
	int ret = 0;

	if (dev == NULL)
		return -EINVAL;
	hw = HNS3_DEV_PRIVATE_TO_HW(dev->data->dev_private);
	switch (filter_type) {
	case RTE_ETH_FILTER_HASH:
		ret = hns3_hash_filter_ctrl(dev, filter_op, arg);
		break;
	case RTE_ETH_FILTER_GENERIC:
		if (filter_op != RTE_ETH_FILTER_GET)
			return -EINVAL;
		if (hw->adapter_state >= HNS3_NIC_CLOSED)
			return -ENODEV;
		*(const void **)arg = &hns3_flow_ops;
		break;
	default:
		hns3_err(hw, "Filter type (%d) not supported", filter_type);
		ret = -EINVAL;
		break;
	}

	return ret;
}

/*
 * Used to configure the tc_size and tc_offset.
 */
static int
hns3_set_rss_tc_mode(struct hns3_hw *hw)
{
	uint16_t rss_size = hw->alloc_rss_size;
	struct hns3_rss_tc_mode_cmd *req;
	uint16_t tc_offset[HNS3_MAX_TC_NUM];
	uint8_t tc_valid[HNS3_MAX_TC_NUM];
	uint16_t tc_size[HNS3_MAX_TC_NUM];
	struct hns3_cmd_desc desc;
	uint16_t roundup_size;
	uint16_t i;
	int ret;

	req = (struct hns3_rss_tc_mode_cmd *)desc.data;

	roundup_size = roundup_pow_of_two(rss_size);
	roundup_size = ilog2(roundup_size);

	for (i = 0; i < HNS3_MAX_TC_NUM; i++) {
		tc_valid[i] = !!(hw->hw_tc_map & BIT(i));
		tc_size[i] = roundup_size;
		tc_offset[i] = rss_size * i;
	}

	hns3_cmd_setup_basic_desc(&desc, HNS3_OPC_RSS_TC_MODE, false);
	for (i = 0; i < HNS3_MAX_TC_NUM; i++) {
		uint16_t mode = 0;

		hns3_set_bit(mode, HNS3_RSS_TC_VALID_B, (tc_valid[i] & 0x1));
		hns3_set_field(mode, HNS3_RSS_TC_SIZE_M, HNS3_RSS_TC_SIZE_S,
			       tc_size[i]);
		hns3_set_field(mode, HNS3_RSS_TC_OFFSET_M, HNS3_RSS_TC_OFFSET_S,
			       tc_offset[i]);

		req->rss_tc_mode[i] = rte_cpu_to_le_16(mode);
	}
	ret = hns3_cmd_send(hw, &desc, 1);
	if (ret)
		hns3_err(hw, "Sets rss tc mode failed %d", ret);

	return ret;
}

static void
hns3_rss_tuple_uninit(struct hns3_hw *hw)
{
	struct hns3_rss_input_tuple_cmd *req;
	struct hns3_cmd_desc desc;
	int ret;

	hns3_cmd_setup_basic_desc(&desc, HNS3_OPC_RSS_INPUT_TUPLE, false);

	req = (struct hns3_rss_input_tuple_cmd *)desc.data;

	memset(req, 0, sizeof(struct hns3_rss_tuple_cfg));

	ret = hns3_cmd_send(hw, &desc, 1);
	if (ret) {
		hns3_err(hw, "RSS uninit tuple failed %d", ret);
		return;
	}
}

/*
 * Set the default rss configuration in the init of driver.
 */
void
hns3_set_default_rss_args(struct hns3_hw *hw)
{
	struct hns3_rss_conf *rss_cfg = &hw->rss_info;
	uint16_t queue_num = hw->alloc_rss_size;
	int i;

	/* Default hash algorithm */
	rss_cfg->conf.func = RTE_ETH_HASH_FUNCTION_SIMPLE_XOR;
	memcpy(rss_cfg->key, hns3_hash_key, HNS3_RSS_KEY_SIZE);

	/* Initialize RSS indirection table */
	for (i = 0; i < HNS3_RSS_IND_TBL_SIZE; i++)
		rss_cfg->rss_indirection_tbl[i] = i % queue_num;
}

/*
 * RSS initialization for hns3 pmd driver.
 */
int
hns3_config_rss(struct hns3_adapter *hns)
{
	struct hns3_hw *hw = &hns->hw;
	struct hns3_rss_conf *rss_cfg = &hw->rss_info;
	uint8_t hash_algo =
		(hw->rss_info.conf.func == RTE_ETH_HASH_FUNCTION_TOEPLITZ ?
		 HNS3_RSS_HASH_ALGO_TOEPLITZ : HNS3_RSS_HASH_ALGO_SIMPLE);
	uint8_t *hash_key = rss_cfg->key;
	int ret, ret1;

	enum rte_eth_rx_mq_mode mq_mode = hw->data->dev_conf.rxmode.mq_mode;

	/* When there is no open RSS, redirect the packet queue 0 */
	if (((uint32_t)mq_mode & ETH_MQ_RX_RSS_FLAG) == 0) {
		hns3_rss_uninit(hns);
		return 0;
	}

	/* Configure RSS hash algorithm and hash key offset */
	ret = hns3_set_rss_algo_key(hw, hash_algo, hash_key);
	if (ret)
		return ret;

	/* Configure the tuple selection for RSS hash input */
	ret = hns3_set_rss_input_tuple(hw);
	if (ret)
		return ret;

	ret = hns3_set_rss_indir_table(hw, rss_cfg->rss_indirection_tbl,
				       HNS3_RSS_IND_TBL_SIZE);
	if (ret)
		goto rss_tuple_uninit;

	ret = hns3_set_rss_tc_mode(hw);
	if (ret)
		goto rss_indir_table_uninit;

	return ret;

rss_indir_table_uninit:
	ret1 = hns3_rss_reset_indir_table(hw);
	if (ret1 != 0)
		return ret;

rss_tuple_uninit:
	hns3_rss_tuple_uninit(hw);

	/* Disable RSS */
	hw->rss_info.conf.types = 0;

	return ret;
}

/*
 * RSS uninitialization for hns3 pmd driver.
 */
void
hns3_rss_uninit(struct hns3_adapter *hns)
{
	struct hns3_hw *hw = &hns->hw;
	int ret;

	hns3_rss_tuple_uninit(hw);
	ret = hns3_rss_reset_indir_table(hw);
	if (ret != 0)
		return;

	/* Disable RSS */
	hw->rss_info.conf.types = 0;
}
