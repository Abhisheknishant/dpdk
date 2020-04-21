/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Intel Corporation
 */

#include <stdint.h>
#include <rte_compat.h>
#include <rte_telemetry_json.h>

#ifndef _RTE_TELEMETRY_H_
#define _RTE_TELEMETRY_H_

/** Maximum number of telemetry callbacks. */
#define TELEMETRY_MAX_CALLBACKS 64

/**
 * @warning
 * @b EXPERIMENTAL: all functions in this file may change without prior notice
 *
 * @file
 * RTE Telemetry
 *
 * The telemetry library provides a method to retrieve statistics from
 * DPDK by sending a request message over a socket. DPDK will send
 * a JSON encoded response containing telemetry data.
 ***/

/**
 * This telemetry callback is used when registering a command.
 * It handles getting and formatting stats to be returned to telemetry when
 * requested. Stats up to buf_len in length are put in the buffer.
 *
 * @param cmd
 * The cmd that was requested by the client.
 * @param params
 * Contains data required by the callback function.
 * @param buffer
 * A buffer to hold the formatted response.
 * @param buf_len
 * Length of the buffer.
 *
 * @return
 * Length of buffer used on success.
 * @return
 * Negative integer on error.
 */
typedef int (*telemetry_cb)(const char *cmd, const char *params,
		char *buffer, int buf_len);

/**
 * Used for handling data received over a telemetry socket.
 *
 * @param sock_id
 * ID for the socket to be used by the handler.
 *
 * @return
 * Void.
 */
typedef void * (*handler)(void *sock_id);

/**
 * Used when registering a command and callback function with telemetry.
 *
 * @param cmd
 * The command to register with telemetry.
 * @param fn
 * Callback function to be called when the command is requested.
 *
 * @return
 *  0 on success.
 * @return
 *  -EINVAL for invalid parameters failure.
 *  @return
 *  -ENOENT if max callbacks limit has been reached.
 */
__rte_experimental
int
rte_telemetry_register_cmd(const char *cmd, telemetry_cb fn);

/**
 * Initialize Telemetry.
 *
 * @return
 *  0 on success.
 * @return
 *  -1 on failure.
 */
__rte_experimental
int
rte_telemetry_init(void);
#endif
