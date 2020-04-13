/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 DPDK Community
 */

#include <stdio.h>

#include <rte_init.h>

#include "test.h"

static int
rte_init_cb(__rte_unused const void *arg)
{
	return 0;
}

static int
test_rte_init(void)
{
	printf("test rte-init register API\n");
	if (rte_init_register(rte_init_cb, NULL, RTE_INIT_PRE) != 0)
		return -1;

	printf("test rte-init cb\n");
	if (rte_init_register(NULL, NULL, RTE_INIT_PRE) != -EINVAL)
		return -1;

	printf("test rte-init type\n");
	if (rte_init_register(NULL, NULL, 10) != -EINVAL)
		return -1;

	return 0;
}

REGISTER_TEST_COMMAND(rte_init_autotest, test_rte_init);
