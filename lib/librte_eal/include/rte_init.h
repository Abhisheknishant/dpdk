/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 DPDK Community
 */

#ifndef _RTE_INIT_H_
#define _RTE_INIT_H_

#include <rte_compat.h>

/**
 * @file
 *
 * RTE INIT Registration Interface
 *
 * This file exposes API for other libraries initialization callback.
 */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Implementation specific callback function which is
 * responsible for specificed initialization.
 *
 * This is invoked when almost resources are available.
 *
 * @return
 *	0 for successfully invoked
 *	Negative for unsuccessfully invoked with error value
 */
typedef int (*rte_init_cb_t)(const void *arg);

/**
 * The RTE INIT type of callback function registered.
 */
enum rte_init_type {
	RTE_INIT_PRE, /**< RTE INITs are invoked with high priority. */
	RTE_INIT_POST /**< Last RTE INITs invoked. */
};

/**
 * Register a rte_init callback.
 *
 * @param cb
 *   A pointer to a rte_init_cb structure, which will be invoked
 *   in rte_eal_init().
 *
 * @param arg
 *   The cb will use that as param.
 *
 * @param type
 *   The type of rte_init registered.
 *
 * @return
 *	0 for success register callback.
 *	-EINVAL one of the parameters was invalid.
 *	-ENOMEM no appropriate memory allocated.
 */
__rte_experimental
int rte_init_register(rte_init_cb_t cb, const void *arg,
		       enum rte_init_type type);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_INIT_H_ */
