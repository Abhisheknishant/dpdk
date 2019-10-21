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
#include <rte_compat.h>

/**
 * Pause CPU execution for a short while
 *
 * This call is intended for tight loops which poll a shared resource or wait
 * for an event. A short pause within the loop may reduce the power consumption.
 */
static inline void rte_pause(void);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Wait for *addr to be updated with a 16-bit expected value, with a relaxed
 * memory ordering model meaning the loads around this API can be reordered.
 *
 * @param addr
 *  A pointer to the memory location.
 * @param expected
 *  A 16-bit expected value to be in the memory location.
 * @param memorder
 *  Two different memory orders that can be specified:
 *  __ATOMIC_ACQUIRE and __ATOMIC_RELAXED. These map to
 *  C++11 memory orders with the same names, see the C++11 standard or
 *  the GCC wiki on atomic synchronization for detailed definition.
 */
__rte_experimental
static __rte_always_inline void
rte_wait_until_equal_16(volatile uint16_t *addr, uint16_t expected,
int memorder);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Wait for *addr to be updated with a 32-bit expected value, with a relaxed
 * memory ordering model meaning the loads around this API can be reordered.
 *
 * @param addr
 *  A pointer to the memory location.
 * @param expected
 *  A 32-bit expected value to be in the memory location.
 * @param memorder
 *  Two different memory orders that can be specified:
 *  __ATOMIC_ACQUIRE and __ATOMIC_RELAXED. These map to
 *  C++11 memory orders with the same names, see the C++11 standard or
 *  the GCC wiki on atomic synchronization for detailed definition.
 */
__rte_experimental
static __rte_always_inline void
rte_wait_until_equal_32(volatile uint32_t *addr, uint32_t expected,
int memorder);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Wait for *addr to be updated with a 64-bit expected value, with a relaxed
 * memory ordering model meaning the loads around this API can be reordered.
 *
 * @param addr
 *  A pointer to the memory location.
 * @param expected
 *  A 64-bit expected value to be in the memory location.
 * @param memorder
 *  Two different memory orders that can be specified:
 *  __ATOMIC_ACQUIRE and __ATOMIC_RELAXED. These map to
 *  C++11 memory orders with the same names, see the C++11 standard or
 *  the GCC wiki on atomic synchronization for detailed definition.
 */
__rte_experimental
static __rte_always_inline void
rte_wait_until_equal_64(volatile uint64_t *addr, uint64_t expected,
int memorder);

#ifndef RTE_ARM_USE_WFE
#define __WAIT_UNTIL_EQUAL(type, size, addr, expected, memorder) \
__rte_experimental \
static __rte_always_inline void					\
rte_wait_until_equal_##size(volatile type * addr, type expected,\
int memorder)							\
{								\
	if (__atomic_load_n(addr, memorder) != expected) {	\
		do {							\
			rte_pause();					\
		} while (__atomic_load_n(addr, memorder) != expected);	\
	}								\
}
__WAIT_UNTIL_EQUAL(uint16_t, 16, addr, expected, memorder)
__WAIT_UNTIL_EQUAL(uint32_t, 32, addr, expected, memorder)
__WAIT_UNTIL_EQUAL(uint64_t, 64, addr, expected, memorder)

#undef __WAIT_UNTIL_EQUAL

#endif /* RTE_ARM_USE_WFE */

#endif /* _RTE_PAUSE_H_ */
