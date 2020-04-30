/* SPDX-License-Identifier: BSD-3-Clause
 *
 * This file contain the implementations of the items
 * related methods. Each Item have a method to prepare
 * the item and add it into items array in given index.
 *
 * Copyright 2020 Mellanox Technologies, Ltd
 */

#include <stdint.h>
#include <rte_flow.h>

#include "items_gen.h"
#include "user_parameters.h"

static struct rte_flow_item_eth eth_spec;
static struct rte_flow_item_eth eth_mask;
static struct rte_flow_item_vlan vlan_spec;
static struct rte_flow_item_vlan vlan_mask;
static struct rte_flow_item_ipv4 ipv4_spec;
static struct rte_flow_item_ipv4 ipv4_mask;
static struct rte_flow_item_ipv6 ipv6_spec;
static struct rte_flow_item_ipv6 ipv6_mask;
static struct rte_flow_item_udp udp_spec;
static struct rte_flow_item_udp udp_mask;
static struct rte_flow_item_tcp tcp_spec;
static struct rte_flow_item_tcp tcp_mask;
static struct rte_flow_item_vxlan vxlan_spec;
static struct rte_flow_item_vxlan vxlan_mask;
static struct rte_flow_item_vxlan_gpe vxlan_gpe_spec;
static struct rte_flow_item_vxlan_gpe vxlan_gpe_mask;
static struct rte_flow_item_gre gre_spec;
static struct rte_flow_item_gre gre_mask;
static struct rte_flow_item_geneve geneve_spec;
static struct rte_flow_item_geneve geneve_mask;
static struct rte_flow_item_gtp gtp_spec;
static struct rte_flow_item_gtp gtp_mask;
static struct rte_flow_item_meta meta_spec;
static struct rte_flow_item_meta meta_mask;
static struct rte_flow_item_tag tag_spec;
static struct rte_flow_item_tag tag_mask;


void
add_ether(struct rte_flow_item items[MAX_ITEMS_NUM],
	uint8_t items_counter)
{
	memset(&eth_spec, 0, sizeof(struct rte_flow_item_eth));
	memset(&eth_mask, 0, sizeof(struct rte_flow_item_eth));
	eth_spec.type = 0;
	eth_mask.type = 0;

	items[items_counter].type = RTE_FLOW_ITEM_TYPE_ETH;
	items[items_counter].spec = &eth_spec;
	items[items_counter].mask = &eth_mask;
}

void
add_vlan(struct rte_flow_item items[MAX_ITEMS_NUM],
	uint8_t items_counter)
{
	uint16_t vlan_value = VLAN_VALUE;
	memset(&vlan_spec, 0, sizeof(struct rte_flow_item_vlan));
	memset(&vlan_mask, 0, sizeof(struct rte_flow_item_vlan));

	vlan_spec.tci = RTE_BE16(vlan_value);
	vlan_mask.tci = RTE_BE16(0xffff);

	items[items_counter].type = RTE_FLOW_ITEM_TYPE_VLAN;
	items[items_counter].spec = &vlan_spec;
	items[items_counter].mask = &vlan_mask;
}

void
add_ipv4(struct rte_flow_item items[MAX_ITEMS_NUM],
	uint8_t items_counter, uint32_t src_ipv4)
{
	memset(&ipv4_spec, 0, sizeof(struct rte_flow_item_ipv4));
	memset(&ipv4_mask, 0, sizeof(struct rte_flow_item_ipv4));

	ipv4_spec.hdr.src_addr = src_ipv4;
	ipv4_mask.hdr.src_addr = 0xffffffff;

	items[items_counter].type = RTE_FLOW_ITEM_TYPE_IPV4;
	items[items_counter].spec = &ipv4_spec;
	items[items_counter].mask = &ipv4_mask;
}


void
add_ipv6(struct rte_flow_item items[MAX_ITEMS_NUM],
	uint8_t items_counter, int src_ipv6)
{
	memset(&ipv6_spec, 0, sizeof(struct rte_flow_item_ipv6));
	memset(&ipv6_mask, 0, sizeof(struct rte_flow_item_ipv6));

	/** Set ipv6 src **/
	memset(&ipv6_spec.hdr.src_addr, src_ipv6,
					sizeof(ipv6_spec.hdr.src_addr) / 2);

	/** Full mask **/
	memset(&ipv6_mask.hdr.src_addr, 1,
					sizeof(ipv6_spec.hdr.src_addr));

	items[items_counter].type = RTE_FLOW_ITEM_TYPE_IPV6;
	items[items_counter].spec = &ipv6_spec;
	items[items_counter].mask = &ipv6_mask;
}

void
add_tcp(struct rte_flow_item items[MAX_ITEMS_NUM],
	uint8_t items_counter)
{
	memset(&tcp_spec, 0, sizeof(struct rte_flow_item_tcp));
	memset(&tcp_mask, 0, sizeof(struct rte_flow_item_tcp));

	items[items_counter].type = RTE_FLOW_ITEM_TYPE_TCP;
	items[items_counter].spec = &tcp_spec;
	items[items_counter].mask = &tcp_mask;
}

void
add_udp(struct rte_flow_item items[MAX_ITEMS_NUM],
	uint8_t items_counter)
{
	memset(&udp_spec, 0, sizeof(struct rte_flow_item_udp));
	memset(&udp_mask, 0, sizeof(struct rte_flow_item_udp));

	items[items_counter].type = RTE_FLOW_ITEM_TYPE_UDP;
	items[items_counter].spec = &udp_spec;
	items[items_counter].mask = &udp_mask;
}

void
add_vxlan(struct rte_flow_item items[MAX_ITEMS_NUM],
	uint8_t items_counter)
{
	uint32_t vni_value = VNI_VALUE;
	uint8_t i;
	memset(&vxlan_spec, 0, sizeof(struct rte_flow_item_vxlan));
	memset(&vxlan_mask, 0, sizeof(struct rte_flow_item_vxlan));

	/* Set standard vxlan vni */
	for (i = 0; i < 3; i++) {
		vxlan_spec.vni[2 - i] = vni_value >> (i * 8);
		vxlan_mask.vni[2 - i] = 0xff;
	}

	/* Standard vxlan flags **/
	vxlan_spec.flags = 0x8;

	items[items_counter].type = RTE_FLOW_ITEM_TYPE_VXLAN;
	items[items_counter].spec = &vxlan_spec;
	items[items_counter].mask = &vxlan_mask;
}

void
add_vxlan_gpe(struct rte_flow_item items[MAX_ITEMS_NUM],
	uint8_t items_counter)
{
	uint32_t vni_value = VNI_VALUE;
	uint8_t i;
	memset(&vxlan_gpe_spec, 0, sizeof(struct rte_flow_item_vxlan_gpe));
	memset(&vxlan_gpe_mask, 0, sizeof(struct rte_flow_item_vxlan_gpe));

	/* Set vxlan-gpe vni */
	for (i = 0; i < 3; i++) {
		vxlan_gpe_spec.vni[2 - i] = vni_value >> (i * 8);
		vxlan_gpe_mask.vni[2 - i] = 0xff;
	}

	/* vxlan-gpe flags */
	vxlan_gpe_spec.flags = 0x0c;

	items[items_counter].type = RTE_FLOW_ITEM_TYPE_VXLAN_GPE;
	items[items_counter].spec = &vxlan_gpe_spec;
	items[items_counter].mask = &vxlan_gpe_mask;
}

void
add_gre(struct rte_flow_item items[MAX_ITEMS_NUM],
	uint8_t items_counter)
{
	uint16_t proto = GRE_PROTO;
	memset(&gre_spec, 0, sizeof(struct rte_flow_item_gre));
	memset(&gre_mask, 0, sizeof(struct rte_flow_item_gre));

	gre_spec.protocol = RTE_BE16(proto);
	gre_mask.protocol = 0xffff;

	items[items_counter].type = RTE_FLOW_ITEM_TYPE_GRE;
	items[items_counter].spec = &gre_spec;
	items[items_counter].mask = &gre_mask;
}

void
add_geneve(struct rte_flow_item items[MAX_ITEMS_NUM],
	uint8_t items_counter)
{
	uint32_t vni_value = VNI_VALUE;
	uint8_t i;
	memset(&geneve_spec, 0, sizeof(struct rte_flow_item_geneve));
	memset(&geneve_mask, 0, sizeof(struct rte_flow_item_geneve));

	for (i = 0; i < 3; i++) {
		geneve_spec.vni[2 - i] = vni_value >> (i * 8);
		geneve_mask.vni[2 - i] = 0xff;
	}

	items[items_counter].type = RTE_FLOW_ITEM_TYPE_GENEVE;
	items[items_counter].spec = &geneve_spec;
	items[items_counter].mask = &geneve_mask;
}

void
add_gtp(struct rte_flow_item items[MAX_ITEMS_NUM],
	uint8_t items_counter)
{
	uint32_t teid_value = TEID_VALUE;
	memset(&gtp_spec, 0, sizeof(struct rte_flow_item_gtp));
	memset(&gtp_mask, 0, sizeof(struct rte_flow_item_gtp));

	gtp_spec.teid = RTE_BE32(teid_value);
	gtp_mask.teid = RTE_BE32(0xffffffff);

	items[items_counter].type = RTE_FLOW_ITEM_TYPE_GTP;
	items[items_counter].spec = &gtp_spec;
	items[items_counter].mask = &gtp_mask;
}

void
add_meta_data(struct rte_flow_item items[MAX_ITEMS_NUM],
	uint8_t items_counter)
{
	uint32_t data = META_DATA;
	memset(&meta_spec, 0, sizeof(struct rte_flow_item_meta));
	memset(&meta_mask, 0, sizeof(struct rte_flow_item_meta));

	meta_spec.data = RTE_BE32(data);
	meta_mask.data = RTE_BE32(0xffffffff);

	items[items_counter].type = RTE_FLOW_ITEM_TYPE_META;
	items[items_counter].spec = &meta_spec;
	items[items_counter].mask = &meta_mask;
}


void
add_meta_tag(struct rte_flow_item items[MAX_ITEMS_NUM],
	uint8_t items_counter)
{
	uint32_t data = META_DATA;
	uint8_t index = TAG_INDEX;
	memset(&tag_spec, 0, sizeof(struct rte_flow_item_tag));
	memset(&tag_mask, 0, sizeof(struct rte_flow_item_tag));

	tag_spec.data = RTE_BE32(data);
	tag_mask.data = RTE_BE32(0xffffffff);
	tag_spec.index = index;
	tag_mask.index = 0xff;

	items[items_counter].type = RTE_FLOW_ITEM_TYPE_TAG;
	items[items_counter].spec = &tag_spec;
	items[items_counter].mask = &tag_mask;
}
