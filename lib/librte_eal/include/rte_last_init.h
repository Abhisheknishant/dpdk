/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 DPDK Community
 */

#ifndef _RTE_LAST_INIT_H_
#define _RTE_LAST_INIT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <sys/queue.h>

typedef int (*rte_last_init_cb)(const void *arg);

/**
 * A structure describing a generic initialization.
 */
struct rte_last_init {
	TAILQ_ENTRY(rte_last_init) next;   /**< Next bus object in linked list */
	const void *arg;
	rte_last_init_cb cb;
};

/** Double linked list of buses */
TAILQ_HEAD(rte_last_init_list, rte_last_init);

void rte_last_init_register(rte_last_init_cb cb, const void *arg);
int rte_last_init_run(void);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_LAST_INIT_H_ */
