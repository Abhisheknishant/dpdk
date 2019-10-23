/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Arm Limited
 */

#ifndef _RTE_IO_BITOPS_H_
#define _RTE_IO_BITOPS_H_

/**
 * @file
 * Bit Operations
 *
 * This file defines a generic API for bit operations.
 */

#include <rte_lcore.h>

/**
 * Get a bit.
 *
 * @param nr
 *   The bit to get.
 * @param addr
 *   The address to count from.
 * @return
 *   The value of the bit.
 */
static inline int32_t
rte_io_get_bit(uint32_t nr, uint64_t *addr)
{
	return __atomic_load_n(addr, __ATOMIC_ACQUIRE) & (1UL << nr);
}

/**
 * Set a bit to 1.
 *
 * @param nr
 *   The bit to set.
 * @param addr
 *   The address to count from.
 */
static inline void
rte_io_set_bit(uint32_t nr, uint64_t *addr)
{
	__atomic_fetch_or(addr, (1UL << nr), __ATOMIC_ACQ_REL);
}

/**
 * Set a bit to 0.
 *
 * @param nr
 *   The bit to set.
 * @param addr
 *   The address to count from.
 */
static inline void
rte_io_clear_bit(int32_t nr, uint64_t *addr)
{
	__atomic_fetch_and(addr, ~(1UL << nr), __ATOMIC_ACQ_REL);
}

/**
 * Test if a bit is 1.
 *
 * @param nr
 *   The bit to test.
 * @param addr
 *   The address to count from.
 * @return
 *   1 if the bit is 1; else 0.
 */
static inline int32_t
rte_io_test_bit(int32_t nr, uint64_t *addr)
{
	return (__atomic_load_n(addr, __ATOMIC_ACQUIRE) & (1UL << nr)) != 0;
}

/**
 * Set a bit to 1 and return its old value.
 *
 * @param nr
 *   The bit to set.
 * @param addr
 *   The address to count from.
 * @return
 *   The old value of the bit.
 */
static inline int32_t
rte_io_test_and_set_bit(int32_t nr, uint64_t *addr)
{
	unsigned long mask = (1UL << nr);

	return __atomic_fetch_or(addr, mask, __ATOMIC_ACQ_REL) & mask;
}

/**
 * Set a bit to 0 and return its old value.
 *
 * @param nr
 *   The bit to set.
 * @param addr
 *   The address to count from.
 * @return
 *   The old value of the bit.
 */
static inline int32_t
rte_io_test_and_clear_bit(int32_t nr, uint64_t *addr)
{
	unsigned long mask = (1UL << nr);

	return __atomic_fetch_and(addr, ~mask, __ATOMIC_ACQ_REL) & mask;
}
#endif /* _RTE_IO_BITOPS_H_ */
