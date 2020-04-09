/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright 2020 DPDK Community
 */

#ifndef _RTE_INIT_H_
#define _RTE_INIT_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <sys/queue.h>

/**
 * Implementation specific callback function which is
 * responsible for specificed initialization.
 *
 * This is called when almost resources are available.
 *
 * @return
 *	0 for successful callback
 *	Negative for unsuccessful callback with error value
 */
typedef int (*rte_init_cb_t)(const void *arg);

/**
 * rte_init type.
 *
 * The rte_init of RTE_INIT_PRE are called firstly,
 * and then RTE_INIT_POST.
 */
enum rte_init_type {
	RTE_INIT_PRE,
	RTE_INIT_POST
};

/**
 * Register a rte_init callback.
 *
 * @param cb
 *   A pointer to a rte_init_cb structure, which will be used
 *   in rte_eal_init().
 *
 * @param arg
 *   The cb will use that as param.
 *
 * @param type
 *   The type of rte_init registered.
 */

void rte_init_register(rte_init_cb_t cb, const void *arg,
		       enum rte_init_type type);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_INIT_H_ */
