/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Mellanox Corporation
 */

#ifndef _RTE_REGEXDEV_DRIVER_H_
#define _RTE_REGEXDEV_DRIVER_H_

/**
 * @file
 *
 * RTE RegEx Device PMD API
 *
 * APIs that are used by the RegEx drivers, to comunicate with the
 * RegEx lib.
 */

#include "rte_regexdev.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @internal
 * Register a new regexdev slot for a RegEx device and returns the id
 * to that slot for the driver to use.
 *
 * @param dev
 *   RegEx device structure..
 *
 * @return
 *   Slot in the rte_regex_devices array for a new device in case of success,
 *   negative errno otherwise.
 */
int rte_regexdev_register(struct rte_regexdev *dev);

/**
 * @internal
 * Unregister the specified regexdev port.
 *
 * @param dev
 *   Device to be released.
 */
void rte_regexdev_unregister(struct rte_regexdev *dev);

#ifdef __cplusplus
}
#endif

#endif /* _RTE_REGEXDEV_DRIVER_H_ */
