/* SPDX-License-Identifier: BSD-3-Clause
 *
 * This file contains the items related methods
 *
 * Copyright 2020 Mellanox Technologies, Ltd
 */

#ifndef _ITEMS_GEN_
#define _ITEMS_GEN_

#include <stdint.h>
#include <rte_flow.h>

#include "user_parameters.h"

void
add_ether(struct rte_flow_item items[MAX_ITEMS_NUM],
	uint8_t items_counter);

void
add_vlan(struct rte_flow_item items[MAX_ITEMS_NUM],
	uint8_t items_counter);

void
add_ipv4(struct rte_flow_item items[MAX_ITEMS_NUM],
	uint8_t items_counter, uint32_t src_ipv4);

void
add_ipv6(struct rte_flow_item items[MAX_ITEMS_NUM],
	uint8_t items_counter, int src_ipv6);

void
add_udp(struct rte_flow_item items[MAX_ITEMS_NUM],
	uint8_t items_counter);

void
add_tcp(struct rte_flow_item items[MAX_ITEMS_NUM],
	uint8_t items_counter);

void
add_vxlan(struct rte_flow_item items[MAX_ITEMS_NUM],
	uint8_t items_counter);

void
add_vxlan_gpe(struct rte_flow_item items[MAX_ITEMS_NUM],
	uint8_t items_counter);

void
add_gre(struct rte_flow_item items[MAX_ITEMS_NUM],
	uint8_t items_counter);

void
add_geneve(struct rte_flow_item items[MAX_ITEMS_NUM],
	uint8_t items_counter);

void
add_gtp(struct rte_flow_item items[MAX_ITEMS_NUM],
	uint8_t items_counter);

void
add_meta_data(struct rte_flow_item items[MAX_ITEMS_NUM],
	uint8_t items_counter);

void
add_meta_tag(struct rte_flow_item items[MAX_ITEMS_NUM],
	uint8_t items_counter);

#endif
