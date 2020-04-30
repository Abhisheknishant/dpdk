/* SPDX-License-Identifier: BSD-3-Clause
 *
 * The file contains the implementations of actions generators.
 * Each generator is responsible for preparing it's action instance
 * and initializing it with needed data.
 *
 * Copyright 2020 Mellanox Technologies, Ltd
 **/

#include <sys/types.h>
#include <rte_malloc.h>
#include <rte_flow.h>
#include <rte_ethdev.h>

#include "actions_gen.h"
#include "user_parameters.h"

void
gen_mark(void)
{
	mark_action.id = MARK_ID;
}

void
gen_queue(uint16_t queue)
{
	queue_action.index = queue;
}

void
gen_jump(uint16_t next_table)
{
	jump_action.group = next_table;
}

void
gen_rss(uint16_t *queues, uint16_t queues_number)
{
	uint16_t queue;
	struct action_rss_data *rss_data;
	rss_data = rte_malloc("rss_data",
		sizeof(struct action_rss_data), 0);

	if (rss_data == NULL)
		rte_exit(EXIT_FAILURE, "No Memory available!");

	*rss_data = (struct action_rss_data){
		.conf = (struct rte_flow_action_rss){
			.func = RTE_ETH_HASH_FUNCTION_DEFAULT,
			.level = 0,
			.types = ETH_RSS_IP,
			.key_len = 0,
			.queue_num = queues_number,
			.key = 0,
			.queue = rss_data->queue,
		},
		.key = { 0 },
		.queue = { 0 },
	};

	for (queue = 0; queue < queues_number; queue++)
		rss_data->queue[queue] = queues[queue];

	rss_action = &rss_data->conf;
}

void
gen_set_meta(void)
{
	meta_action.data = RTE_BE32(META_DATA);
	meta_action.mask = RTE_BE32(0xffffffff);
}

void
gen_set_tag(void)
{
	tag_action.data = RTE_BE32(META_DATA);
	tag_action.mask = RTE_BE32(0xffffffff);
	tag_action.index = TAG_INDEX;
}

void
gen_port_id(void)
{
	port_id.id = PORT_ID_DST;
}
