/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019 Arm Limited
 */

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

#include <rte_ring_32.h>
#include <rte_ring_template.c>
