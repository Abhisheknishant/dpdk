/* SPDX-License-Identifier: BSD-3-Clause
 *
 * This file contains the items, actions and attributes
 * definition. And the methods to prepare and fill items,
 * actions and attributes to generate rte_flow rule.
 *
 * Copyright 2020 Mellanox Technologies, Ltd
 */

#ifndef _FLOW_GEN_
#define _FLOW_GEN_

#include <stdint.h>
#include <rte_flow.h>

#include "user_parameters.h"

/* Items */
#define ETH_ITEM       0x0001
#define IPV4_ITEM      0x0002
#define IPV6_ITEM      0x0004
#define VLAN_ITEM      0x0008
#define TCP_ITEM       0x0010
#define UDP_ITEM       0x0020
#define VXLAN_ITEM     0x0040
#define VXLAN_GPE_ITEM 0x0080
#define GRE_ITEM       0x0100
#define GENEVE_ITEM    0x0200
#define GTP_ITEM       0x0400
#define META_ITEM      0x0800
#define TAG_ITEM       0x1000

/* Actions */
#define QUEUE_ACTION   0x0001
#define MARK_ACTION    0x0002
#define JUMP_ACTION    0x0004
#define RSS_ACTION     0x0008
#define COUNT_ACTION   0x0010
#define META_ACTION    0x0020
#define TAG_ACTION     0x0040
#define DROP_ACTION    0x0080
#define PORT_ID_ACTION 0x0100
#define HAIRPIN_QUEUE_ACTION 0x0200
#define HAIRPIN_RSS_ACTION   0x0400

/* Attributes */
#define INGRESS  0x0001
#define EGRESS   0x0002
#define TRANSFER 0x0004

struct rte_flow *
generate_flow(uint16_t port_id,
	uint16_t group,
	uint8_t flow_attrs,
	uint16_t flow_items,
	uint16_t flow_actions,
	uint16_t next_table,
	uint32_t outer_ip_src,
	struct rte_flow_error *error);

#endif
