/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Cavium, Inc
 * Copyright(c) 2019 Arm Limited
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

#if !defined(RTE_ARM_USE_WFE)
#define __WAIT_UNTIL_EQUAL(op_name, size, type, memorder) \
__rte_always_inline \
static void	\
rte_wait_until_equal_##op_name##_##size(volatile type *addr, \
	type expected) \
{ \
	while (__atomic_load_n(addr, memorder) != expected) \
		rte_pause(); \
}

/* Wait for *addr to be updated with expected value */
__WAIT_UNTIL_EQUAL(relaxed, 16, uint16_t, __ATOMIC_RELAXED)
__WAIT_UNTIL_EQUAL(acquire, 16, uint16_t, __ATOMIC_ACQUIRE)
__WAIT_UNTIL_EQUAL(relaxed, 32, uint32_t, __ATOMIC_RELAXED)
__WAIT_UNTIL_EQUAL(acquire, 32, uint32_t, __ATOMIC_ACQUIRE)
__WAIT_UNTIL_EQUAL(relaxed, 64, uint64_t, __ATOMIC_RELAXED)
__WAIT_UNTIL_EQUAL(acquire, 64, uint64_t, __ATOMIC_ACQUIRE)
#endif /* RTE_ARM_USE_WFE */

#endif /* _RTE_PAUSE_H_ */
