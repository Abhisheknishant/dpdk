/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Arm Limited
 */

#ifndef _RTE_BITOPS_H_
#define _RTE_BITOPS_H_

/**
 * @file
 * Bit Operations
 *
 * This file defines a API for bit operations without/with memory ordering.
 */

#include <stdint.h>
#include <assert.h>
#include <rte_compat.h>

/*---------------------------- 32 bit operations ----------------------------*/

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Get the target bit from a 32-bit value without memory ordering.
 *
 * @param nr
 *   The target bit to get.
 * @param addr
 *   The address holding the bit.
 * @return
 *   The target bit.
 */
__rte_experimental
static inline uint32_t
rte_get_bit32_relaxed(unsigned int nr, unsigned long *addr)
{
	assert(nr < 32);

	uint32_t mask = 1UL << nr;
	return __atomic_load_n(addr, __ATOMIC_RELAXED) & mask;
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Set the target bit in a 32-bit value to 1 without memory ordering.
 *
 * @param nr
 *   The target bit to set.
 * @param addr
 *   The address holding the bit.
 */
__rte_experimental
static inline void
rte_set_bit32_relaxed(unsigned int nr, unsigned long *addr)
{
	assert(nr < 32);

	uint32_t mask = 1UL << nr;
	__atomic_fetch_or(addr, mask, __ATOMIC_RELAXED);
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Clear the target bit in a 32-bit value to 0 without memory ordering.
 *
 * @param nr
 *   The target bit to clear.
 * @param addr
 *   The address holding the bit.
 */
__rte_experimental
static inline void
rte_clear_bit32_relaxed(unsigned int nr, unsigned long *addr)
{
	assert(nr < 32);

	uint32_t mask = 1UL << nr;
	__atomic_fetch_and(addr, ~mask, __ATOMIC_RELAXED);
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Return the original bit from a 32-bit value, then set it to 1 without
 * memory ordering.
 *
 * @param nr
 *   The target bit to get and set.
 * @param addr
 *   The address holding the bit.
 * @return
 *   The original bit.
 */
__rte_experimental
static inline uint32_t
rte_test_and_set_bit32_relaxed(unsigned int nr, unsigned long *addr)
{
	assert(nr < 32);

	uint32_t mask = 1UL << nr;
	return __atomic_fetch_or(addr, mask, __ATOMIC_RELAXED) & mask;
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Return the original bit from a 32-bit value, then clear it to 0 without
 * memory ordering.
 *
 * @param nr
 *   The target bit to get and clear.
 * @param addr
 *   The address holding the bit.
 * @return
 *   The original bit.
 */
__rte_experimental
static inline uint32_t
rte_test_and_clear_bit32_relaxed(unsigned int nr, unsigned long *addr)
{
	assert(nr < 32);

	uint32_t mask = 1UL << nr;
	return __atomic_fetch_and(addr, ~mask, __ATOMIC_RELAXED) & mask;
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Get the target bit from a 32-bit value with memory ordering.
 *
 * @param nr
 *   The target bit to get.
 * @param addr
 *   The address holding the bit.
 * @return
 *   The target bit.
 */
__rte_experimental
static inline uint32_t
rte_get_bit32(unsigned int nr, unsigned long *addr)
{
	assert(nr < 32);

	uint32_t mask = 1UL << nr;
	return __atomic_load_n(addr, __ATOMIC_ACQUIRE) & mask;
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Set the target bit in a 32-bit value to 1 with memory ordering.
 *
 * @param nr
 *   The target bit to set.
 * @param addr
 *   The address holding the bit.
 */
__rte_experimental
static inline void
rte_set_bit32(unsigned int nr, unsigned long *addr)
{
	assert(nr < 32);

	uint32_t mask = 1UL << nr;
	__atomic_fetch_or(addr, mask, __ATOMIC_ACQ_REL);
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Clear the target bit in a 32-bit value to 0 with memory ordering.
 *
 * @param nr
 *   The target bit to clear.
 * @param addr
 *   The address holding the bit.
 */
__rte_experimental
static inline void
rte_clear_bit32(unsigned int nr, unsigned long *addr)
{
	assert(nr < 32);

	uint32_t mask = 1UL << nr;
	__atomic_fetch_and(addr, ~mask, __ATOMIC_ACQ_REL);
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Return the original bit from a 32-bit value, then set it to 1 with
 * memory ordering.
 *
 * @param nr
 *   The target bit to get and set.
 * @param addr
 *   The address holding the bit.
 * @return
 *   The original bit.
 */
__rte_experimental
static inline uint32_t
rte_test_and_set_bit32(unsigned int nr, unsigned long *addr)
{
	assert(nr < 32);

	uint32_t mask = 1UL << nr;
	return __atomic_fetch_or(addr, mask, __ATOMIC_ACQ_REL) & mask;
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Return the original bit from a 32-bit value, then clear it to 0 with
 * memory ordering.
 *
 * @param nr
 *   The target bit to get and clear.
 * @param addr
 *   The address holding the bit.
 * @return
 *   The original bit.
 */
__rte_experimental
static inline uint32_t
rte_test_and_clear_bit32(unsigned int nr, unsigned long *addr)
{
	assert(nr < 32);

	uint32_t mask = 1UL << nr;
	return __atomic_fetch_and(addr, ~mask, __ATOMIC_ACQ_REL) & mask;
}

/*---------------------------- 64 bit operations ----------------------------*/

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Get the target bit from a 64-bit value without memory ordering.
 *
 * @param nr
 *   The target bit to get.
 * @param addr
 *   The address holding the bit.
 * @return
 *   The target bit.
 */
__rte_experimental
static inline uint64_t
rte_get_bit64_relaxed(unsigned int nr, unsigned long *addr)
{
	assert(nr < 64);

	uint64_t mask = 1UL << nr;
	return __atomic_load_n(addr, __ATOMIC_RELAXED) & mask;
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Set the target bit in a 64-bit value to 1 without memory ordering.
 *
 * @param nr
 *   The target bit to set.
 * @param addr
 *   The address holding the bit.
 */
__rte_experimental
static inline void
rte_set_bit64_relaxed(unsigned int nr, unsigned long *addr)
{
	assert(nr < 64);

	uint64_t mask = 1UL << nr;
	__atomic_fetch_or(addr, mask, __ATOMIC_RELAXED);
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Clear the target bit in a 64-bit value to 0 without memory ordering.
 *
 * @param nr
 *   The target bit to clear.
 * @param addr
 *   The address holding the bit.
 */
__rte_experimental
static inline void
rte_clear_bit64_relaxed(unsigned int nr, unsigned long *addr)
{
	assert(nr < 64);

	uint64_t mask = 1UL << nr;
	__atomic_fetch_and(addr, ~mask, __ATOMIC_RELAXED);
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Return the original bit from a 64-bit value, then set it to 1 without
 * memory ordering.
 *
 * @param nr
 *   The target bit to get and set.
 * @param addr
 *   The address holding the bit.
 * @return
 *   The original bit.
 */
__rte_experimental
static inline uint64_t
rte_test_and_set_bit64_relaxed(unsigned int nr, unsigned long *addr)
{
	assert(nr < 64);

	uint64_t mask = 1UL << nr;
	return __atomic_fetch_or(addr, mask, __ATOMIC_RELAXED) & mask;
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Return the original bit from a 64-bit value, then clear it to 0 without
 * memory ordering.
 *
 * @param nr
 *   The target bit to get and clear.
 * @param addr
 *   The address holding the bit.
 * @return
 *   The original bit.
 */
__rte_experimental
static inline uint64_t
rte_test_and_clear_bit64_relaxed(unsigned int nr, unsigned long *addr)
{
	assert(nr < 64);

	uint64_t mask = 1UL << nr;
	return __atomic_fetch_and(addr, ~mask, __ATOMIC_RELAXED) & mask;
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Get the target bit from a 64-bit value with memory ordering.
 *
 * @param nr
 *   The target bit to get.
 * @param addr
 *   The address holding the bit.
 * @return
 *   The target bit.
 */
__rte_experimental
static inline uint64_t
rte_get_bit64(unsigned int nr, unsigned long *addr)
{
	assert(nr < 64);

	uint64_t mask = 1UL << nr;
	return __atomic_load_n(addr, __ATOMIC_ACQUIRE) & mask;
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Set the target bit in a 64-bit value to 1 with memory ordering.
 *
 * @param nr
 *   The target bit to set.
 * @param addr
 *   The address holding the bit.
 */
__rte_experimental
static inline void
rte_set_bit64(unsigned int nr, unsigned long *addr)
{
	assert(nr < 64);

	uint64_t mask = 1UL << nr;
	__atomic_fetch_or(addr, mask, __ATOMIC_ACQ_REL);
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Clear the target bit in a 64-bit value to 0 with memory ordering.
 *
 * @param nr
 *   The target bit to clear.
 * @param addr
 *   The address holding the bit.
 */
__rte_experimental
static inline void
rte_clear_bit64(unsigned int nr, unsigned long *addr)
{
	assert(nr < 64);

	uint64_t mask = 1UL << nr;
	__atomic_fetch_and(addr, ~mask, __ATOMIC_ACQ_REL);
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Return the original bit from a 64-bit value, then set it to 1 with
 * memory ordering.
 *
 * @param nr
 *   The target bit to get and set.
 * @param addr
 *   The address holding the bit.
 * @return
 *   The original bit.
 */
__rte_experimental
static inline uint64_t
rte_test_and_set_bit64(unsigned int nr, unsigned long *addr)
{
	assert(nr < 64);

	uint64_t mask = 1UL << nr;
	return __atomic_fetch_or(addr, mask, __ATOMIC_ACQ_REL) & mask;
}

/**
 * @warning
 * @b EXPERIMENTAL: this API may change, or be removed, without prior notice
 *
 * Return the original bit from a 64-bit value, then clear it to 0 with
 * memory ordering.
 *
 * @param nr
 *   The target bit to get and clear.
 * @param addr
 *   The address holding the bit.
 * @return
 *   The original bit.
 */
__rte_experimental
static inline uint64_t
rte_test_and_clear_bit64(unsigned int nr, unsigned long *addr)
{
	assert(nr < 64);

	uint64_t mask = 1UL << nr;
	return __atomic_fetch_and(addr, ~mask, __ATOMIC_ACQ_REL) & mask;
}
#endif /* _RTE_BITOPS_H_ */
