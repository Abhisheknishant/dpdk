/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 DPDK Community
 */

#include <sys/queue.h>

#include <rte_init.h>
#include <rte_tailq.h>
#include <rte_log.h>

#include "eal_private.h"

static struct rte_init_list rte_init_list =
	TAILQ_HEAD_INITIALIZER(rte_init_list);

int
rte_init_register(rte_init_cb_t cb, const void *arg, enum rte_init_type type)
{
	struct rte_init *last;

	if (cb == NULL) {
		RTE_LOG(ERR, EAL, "RTE INIT cb is NULL.\n");
		return -EINVAL;
	}

	if (type != RTE_INIT_PRE && type != RTE_INIT_POST) {
		RTE_LOG(ERR, EAL, "RTE INIT type is invalid.\n");
		return -EINVAL;
	}

	last = malloc(sizeof(*last));
	if (last == NULL) {
		RTE_LOG(ERR, EAL,
			"Allocate memory for rte_init node failed.\n");
		return -ENOMEM;
	}

	last->type = type;
	last->arg = arg;
	last->cb = cb;

	TAILQ_INSERT_TAIL(&rte_init_list, last, next);

	return 0;
}

static int
eal_rte_init_run_type(enum rte_init_type type)
{
	struct rte_init *last;
	int ret;

	TAILQ_FOREACH(last, &rte_init_list, next) {
		if (last->type != type)
			continue;

		ret = last->cb(last->arg);
		if (ret < 0)
			return ret;
	}

	return 0;
}

int
eal_rte_init_run(void)
{
	struct rte_init *last;
	struct rte_init *tmp;
	int ret;

	ret = eal_rte_init_run_type(RTE_INIT_PRE);
	if (ret < 0)
		return ret;

	ret = eal_rte_init_run_type(RTE_INIT_POST);
	if (ret < 0)
		return ret;

	/* Free rte_init node, not used anymore. */
	TAILQ_FOREACH_SAFE(last, &rte_init_list, next, tmp) {
		TAILQ_REMOVE(&rte_init_list, last, next);
		free(last);
	}

	return 0;
}
