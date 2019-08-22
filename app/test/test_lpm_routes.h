/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2019 Intel Corporation
 */

#ifndef _TEST_LPM_ROUTES_H_
#define _TEST_LPM_ROUTES_H_

#include <rte_ip.h>

#define MAX_RULE_NUM (1200000)

struct route_rule {
	uint32_t ip;
	uint8_t depth;
};

extern struct route_rule large_route_table[MAX_RULE_NUM];

extern uint32_t num_route_entries;
#define NUM_ROUTE_ENTRIES num_route_entries

void generate_large_route_rule_table(void);
void print_route_distribution(const struct route_rule *table, uint32_t n);

#endif
