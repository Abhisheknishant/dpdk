/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019 Arm Limited
 */

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>
#include <sys/queue.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_malloc.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_eal_memconfig.h>
#include <rte_atomic.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_errno.h>
#include <rte_string_fns.h>
#include <rte_spinlock.h>
#include <rte_tailq.h>

#include "rte_ring.h"

/* return the size of memory occupied by a ring */
ssize_t
__RTE_RING_CONCAT(rte_ring_get_memsize)(unsigned count)
{
	return rte_ring_get_memsize_elem(count, RTE_RING_TMPLT_ELEM_SIZE);
}

/* create the ring */
struct rte_ring *
__RTE_RING_CONCAT(rte_ring_create)(const char *name, unsigned count,
		int socket_id, unsigned flags)
{
	return rte_ring_create_elem(name, count, RTE_RING_TMPLT_ELEM_SIZE,
		socket_id, flags);
}
