/* SPDX-License-Identifier: BSD-3-Clause
 *
 * The file contains the implementations of the method to
 * fill items, actions & attributes in their corresponding
 * arrays, and then generate rte_flow rule.
 *
 * After the generation. The rule goes to validation then
 * creation state and then return the results.
 *
 * Copyright 2020 Mellanox Technologies, Ltd
 */

#include <stdint.h>

#include "flow_gen.h"
#include "items_gen.h"
#include "actions_gen.h"
#include "user_parameters.h"


static void
fill_attributes(struct rte_flow_attr *attr,
	uint8_t flow_attrs, uint16_t group)
{
	if (flow_attrs & INGRESS)
		attr->ingress = 1;
	if (flow_attrs & EGRESS)
		attr->egress = 1;
	if (flow_attrs & TRANSFER)
		attr->transfer = 1;
	attr->group = group;
}

static void
fill_items(struct rte_flow_item items[MAX_ITEMS_NUM],
	uint16_t flow_items, uint32_t outer_ip_src)
{
	uint8_t items_counter = 0;

	if (flow_items & META_ITEM)
		add_meta_data(items, items_counter++);
	if (flow_items & TAG_ITEM)
		add_meta_tag(items, items_counter++);
	if (flow_items & ETH_ITEM)
		add_ether(items, items_counter++);
	if (flow_items & VLAN_ITEM)
		add_vlan(items, items_counter++);
	if (flow_items & IPV4_ITEM)
		add_ipv4(items, items_counter++, outer_ip_src);
	if (flow_items & IPV6_ITEM)
		add_ipv6(items, items_counter++, outer_ip_src);
	if (flow_items & TCP_ITEM)
		add_tcp(items, items_counter++);
	if (flow_items & UDP_ITEM)
		add_udp(items, items_counter++);
	if (flow_items & VXLAN_ITEM)
		add_vxlan(items, items_counter++);
	if (flow_items & VXLAN_GPE_ITEM)
		add_vxlan_gpe(items, items_counter++);
	if (flow_items & GRE_ITEM)
		add_gre(items, items_counter++);
	if (flow_items & GENEVE_ITEM)
		add_geneve(items, items_counter++);
	if (flow_items & GTP_ITEM)
		add_gtp(items, items_counter++);

	items[items_counter].type = RTE_FLOW_ITEM_TYPE_END;
}

static void
fill_actions(struct rte_flow_action actions[MAX_ACTIONS_NUM],
	uint16_t flow_actions, uint32_t counter, uint16_t next_table)
{
	uint8_t actions_counter = 0;
	uint16_t queues[RXQs];
	uint16_t hairpin_queues[HAIRPIN_QUEUES];
	uint16_t i;
	struct rte_flow_action_count count_action;
	uint8_t temp = counter & 0xff;

	/* None-fate actions */
	if (flow_actions & MARK_ACTION) {
		if (!counter)
			gen_mark();
		actions[actions_counter].type = RTE_FLOW_ACTION_TYPE_MARK;
		actions[actions_counter++].conf = &mark_action;
	}
	if (flow_actions & COUNT_ACTION) {
		actions[actions_counter].type = RTE_FLOW_ACTION_TYPE_COUNT;
		actions[actions_counter++].conf = &count_action;
	}
	if (flow_actions & META_ACTION) {
		if (!counter)
			gen_set_meta();
		actions[actions_counter].type = RTE_FLOW_ACTION_TYPE_SET_META;
		actions[actions_counter++].conf = &meta_action;
	}
	if (flow_actions & TAG_ACTION) {
		if (!counter)
			gen_set_tag();
		actions[actions_counter].type = RTE_FLOW_ACTION_TYPE_SET_TAG;
		actions[actions_counter++].conf = &tag_action;
	}

	/* Fate actions */
	if (flow_actions & QUEUE_ACTION) {
		gen_queue(counter % RXQs);
		actions[actions_counter].type = RTE_FLOW_ACTION_TYPE_QUEUE;
		actions[actions_counter++].conf = &queue_action;
	}
	if (flow_actions & RSS_ACTION) {
		for (i = 0; i < RXQs; i++)
			queues[i] = (temp >> (i << 1)) & 0x3;
		gen_rss(queues, RXQs);
		actions[actions_counter].type = RTE_FLOW_ACTION_TYPE_RSS;
		actions[actions_counter++].conf = rss_action;
	}
	if (flow_actions & JUMP_ACTION) {
		if (!counter)
			gen_jump(next_table);
		actions[actions_counter].type = RTE_FLOW_ACTION_TYPE_JUMP;
		actions[actions_counter++].conf = &jump_action;
	}
	if (flow_actions & PORT_ID_ACTION) {
		if (!counter)
			gen_port_id();
		actions[actions_counter].type = RTE_FLOW_ACTION_TYPE_PORT_ID;
		actions[actions_counter++].conf = &port_id;
	}
	if (flow_actions & DROP_ACTION)
		actions[actions_counter++].type = RTE_FLOW_ACTION_TYPE_DROP;
	if (flow_actions & HAIRPIN_QUEUE_ACTION) {
		gen_queue((counter % HAIRPIN_QUEUES) + RXQs);
		actions[actions_counter].type = RTE_FLOW_ACTION_TYPE_QUEUE;
		actions[actions_counter++].conf = &queue_action;
	}
	if (flow_actions & HAIRPIN_RSS_ACTION) {
		for (i = 0; i < RXQs; i++)
			hairpin_queues[i] = (temp >> (i << 1)) & 0x3;
		gen_rss(queues, RXQs);
		actions[actions_counter].type = RTE_FLOW_ACTION_TYPE_RSS;
		actions[actions_counter++].conf = rss_action;
	}

	actions[actions_counter].type = RTE_FLOW_ACTION_TYPE_END;
}

struct rte_flow *
generate_flow(uint16_t port_id,
	uint16_t group,
	uint8_t flow_attrs,
	uint16_t flow_items,
	uint16_t flow_actions,
	uint16_t next_table,
	uint32_t outer_ip_src,
	struct rte_flow_error *error)
{
	struct rte_flow_attr attr;
	struct rte_flow_item items[MAX_ITEMS_NUM];
	struct rte_flow_action actions[MAX_ACTIONS_NUM];
	struct rte_flow *flow = NULL;

	memset(items, 0, sizeof(items));
	memset(actions, 0, sizeof(actions));
	memset(&attr, 0, sizeof(struct rte_flow_attr));

	fill_attributes(&attr, flow_attrs, group);

	fill_actions(actions, flow_actions,
			outer_ip_src, next_table);

	fill_items(items, flow_items, outer_ip_src);

	flow = rte_flow_create(port_id, &attr, items, actions, error);
	return flow;
}
