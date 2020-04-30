/** SPDX-License-Identifier: BSD-3-Clause
 *
 * This file contains the functions definitions to
 * generate each supported action.
 *
 * Copyright 2020 Mellanox Technologies, Ltd
 **/

#ifndef _ACTION_GEN_
#define _ACTION_GEN_

struct rte_flow_action_mark mark_action;
struct rte_flow_action_queue queue_action;
struct rte_flow_action_jump jump_action;
struct rte_flow_action_rss *rss_action;
struct rte_flow_action_set_meta meta_action;
struct rte_flow_action_set_tag tag_action;
struct rte_flow_action_port_id port_id;

/* Storage for struct rte_flow_action_rss including external data. */
struct action_rss_data {
	struct rte_flow_action_rss conf;
	uint8_t key[64];
	uint16_t queue[128];
} action_rss_data;

void
gen_mark(void);

void
gen_queue(uint16_t queue);

void
gen_jump(uint16_t next_table);

void
gen_rss(uint16_t *queues, uint16_t queues_number);

void
gen_set_meta(void);

void
gen_set_tag(void);

void
gen_port_id(void);

#endif
