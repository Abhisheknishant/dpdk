/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#ifndef _RTE_TELEMETRY_LEGACY_H_
#define _RTE_TELEMETRY_LEGACY_H_

#include <rte_compat.h>
#include "rte_telemetry.h"

/**
 * @internal
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice

 * @file
 * RTE Telemetry Legacy
 *
 ***/

/**
 * @internal
 * Value representing if data is required for the command
 */
enum rte_telemetry_legacy_data_req {
	DATA_NOT_REQ = 0,
	DATA_REQ
};

/**
 * @internal
 * Counter for the number of registered legacy callbacks
 */
extern int num_legacy_callbacks;

/**
 * @internal
 * Used for handling data received over the legacy telemetry socket.
 *
 * @return
 * Void.
 */
void *legacy_client_handler(void *sock_id);

/**
 * @internal
 *
 * Used when registering a command and callback function with
 * telemetry legacy support.
 *
 * @return
 *  0 on success.
 * @return
 *  -EINVAL for invalid parameters failure.
 *  @return
 *  -ENOENT if max callbacks limit has been reached.
 */
__rte_experimental
int rte_telemetry_legacy_register(const char *cmd,
		enum rte_telemetry_legacy_data_req data_req,
		telemetry_cb fn);

#endif
