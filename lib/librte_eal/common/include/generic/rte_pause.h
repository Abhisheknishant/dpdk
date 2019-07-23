/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Cavium, Inc
 */

#ifndef _RTE_PAUSE_H_
#define _RTE_PAUSE_H_
/**
 * @file
 *
 * CPU pause operation.
 *
 */

#include <stdint.h>
#include <rte_common.h>
#include <rte_atomic.h>

/**
 * Pause CPU execution for a short while
 *
 * This call is intended for tight loops which poll a shared resource or wait
 * for an event. A short pause within the loop may reduce the power consumption.
 */
static inline void rte_pause(void);

#if !defined(RTE_USE_WFE)
#ifdef RTE_USE_C11_MEM_MODEL
#define __rte_wait_until_equal(addr, expected, memorder) do {\
	while (__atomic_load_n(addr, memorder) != expected) \
		rte_pause();\
} while (0)
#else
#define __rte_wait_until_equal(addr, expected, memorder) do {\
	while (*addr != expected)\
		rte_pause();\
	if (memorder != __ATOMIC_RELAXED)\
		rte_smp_rmb();\
} while (0)
#endif

static __rte_always_inline void
rte_wait_until_equal16(volatile uint16_t *addr, uint16_t expected, int memorder)
{
	__rte_wait_until_equal(addr, expected, memorder);
}

static __rte_always_inline void
rte_wait_until_equal32(volatile uint32_t *addr, uint32_t expected, int memorder)
{
	__rte_wait_until_equal(addr, expected, memorder);
}

static __rte_always_inline void
rte_wait_until_equal64(volatile uint64_t *addr, uint64_t expected, int memorder)
{
	__rte_wait_until_equal(addr, expected, memorder);
}
#endif /* RTE_USE_WFE */

#endif /* _RTE_PAUSE_H_ */
