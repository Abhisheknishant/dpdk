/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Intel Corporation
 */

#include <stdint.h>
#include <rte_compat.h>

#ifndef _RTE_TELEMETRY_H_
#define _RTE_TELEMETRY_H_

#define TELEMETRY_MAX_CALLBACKS 64

/**
 * @file
 * RTE Telemetry
 *
 * The telemetry library provides a method to retrieve statistics from
 * DPDK by sending a JSON encoded message over a socket. DPDK will send
 * a JSON encoded response containing telemetry data.
 ***/

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * This telemetry callback is used when registering a command.
 * It handles getting and formatting stats to be returned to telemetry when
 * requested. Stats up to buf_len in length are put in the buffer.
 *
 * @return
 * Length of buffer used on success.
 * @return
 * Negative integer on error.
 */
typedef int (*telemetry_cb)(const char *cmd, const char *params,
		char *buffer, int buf_len);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Used for handling data received over a telemetry socket.
 *
 * @return
 * Void.
 */
typedef void * (*handler)(void *sock_id);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Initialize Telemetry
 *
 * @return
 *  0 on successful initialisation.
 * @return
 *  -ENOMEM on memory allocation error
 * @return
 *  -EPERM on unknown error failure
 * @return
 *  -EALREADY if Telemetry is already initialised.
 */
__rte_experimental
int32_t
rte_telemetry_init(void);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Clean up and free memory.
 *
 * @return
 *  0 on success
 * @return
 *  -EPERM on failure
 */
__rte_experimental
int32_t
rte_telemetry_cleanup(void);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Runs various tests to ensure telemetry initialisation and register/unregister
 * functions are working correctly.
 *
 * @return
 *  0 on success when all tests have passed
 * @return
 *  -1 on failure when the test has failed
 */
__rte_experimental
int32_t
rte_telemetry_selftest(void);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Used when registering a command and callback function with telemetry.
 *
 * @return
 *  0 on success.
 * @return
 *  -EINVAL for invalid parameters failure.
 *  @return
 *  -ENOENT if max callbacks limit has been reached.
 */
__rte_experimental
int rte_telemetry_register_cmd(const char *cmd, telemetry_cb fn);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Initialize new version of Telemetry.
 *
 * @return
 *  0 on success.
 * @return
 *  -1 on failure.
 */
__rte_experimental
int rte_telemetry_new_init(void);

#endif
