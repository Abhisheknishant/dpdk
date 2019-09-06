/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019 Arm Limited
 */

#ifndef _RTE_RING_32_H_
#define _RTE_RING_32_H_

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

#define RTE_RING_TMPLT_API_SUFFIX 32
#define RTE_RING_TMPLT_ELEM_SIZE sizeof(uint32_t)
#define RTE_RING_TMPLT_ELEM_TYPE uint32_t
#define RTE_RING_TMPLT_EXPERIMENTAL __rte_experimental

#include <rte_ring_template.h>

#ifdef __cplusplus
}
#endif

#endif /* _RTE_RING_32_H_ */
