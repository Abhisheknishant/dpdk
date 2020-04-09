/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 DPDK Community
 */

#include <sys/queue.h>

#include <rte_last_init.h>
#include <rte_debug.h>

static struct rte_last_init_list rte_last_init_list =
	TAILQ_HEAD_INITIALIZER(rte_last_init_list);

void
rte_last_init_register(rte_last_init_cb cb, const void *arg)
{
	struct rte_last_init *last;

	RTE_VERIFY(cb);

	last = malloc(sizeof(*last));
	if (last == NULL)
		rte_panic("Alloc memory for rte_last_init node failed\n");

	last->cb = cb;
	last->arg = arg;

	TAILQ_INSERT_TAIL(&rte_last_init_list, last, next);
}

int
rte_last_init_run(void)
{
	struct rte_last_init *init;
	int ret;

	TAILQ_FOREACH(init, &rte_last_init_list, next) {
		ret = init->cb(init->arg);
		if (ret)
			return ret;
	}

	return 0;
}
