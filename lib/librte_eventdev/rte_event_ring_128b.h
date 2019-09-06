/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019 Arm Limited
 */

#ifndef _RTE_EVENT_RING_128_H_
#define _RTE_EVENT_RING_128_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdint.h>
#include <sys/queue.h>
#include <errno.h>
#include <rte_common.h>
#include <rte_config.h>
#include <rte_memory.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_memzone.h>
#include <rte_pause.h>
#include "rte_eventdev.h"

/* Event ring will use its own template. Otherwise, the 'struct rte_event'
 * needs to change to 'union rte_event' to include a standard 128b data type
 * such as __int128_t which results in API changes.
 *
 * The RTE_RING_TMPLT_API_SUFFIX cannot be just '128b' as that will be
 * used for standard 128b element type APIs defined by the rte_ring library.
 */
#define RTE_RING_TMPLT_API_SUFFIX event_128b
#define RTE_RING_TMPLT_ELEM_SIZE sizeof(struct rte_event)
#define RTE_RING_TMPLT_ELEM_TYPE struct rte_event
#define RTE_RING_TMPLT_EXPERIMENTAL

#include <rte_ring_template.h>

#ifdef __cplusplus
}
#endif

#endif /* _RTE_EVENT_RING_128_H_ */
