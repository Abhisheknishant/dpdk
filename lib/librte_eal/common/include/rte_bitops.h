/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Arm Corporation
 */

#ifndef _RTE_BITOPS_H_
#define _RTE_BITOPS_H_

/**
 * @file
 * Bit Operations
 *
 * This file defines a generic API for bit operations.
 */

#include <stdint.h>
#include <rte_atomic.h>

static inline void
rte_set_bit(unsigned int nr, unsigned long *addr)
{
	__atomic_fetch_or(addr, (1UL << nr), __ATOMIC_ACQ_REL);
}

static inline void
rte_clear_bit(int nr, unsigned long *addr)
{
	__atomic_fetch_and(addr, ~(1UL << nr), __ATOMIC_ACQ_REL);
}

static inline int
rte_test_bit(int nr, unsigned long *addr)
{
	int res;
	rte_mb();
	res = ((*addr) & (1UL << nr)) != 0;
	rte_mb();

	return res;
}

static inline int
rte_test_and_set_bit(int nr, unsigned long *addr)
{
	unsigned long mask = (1UL << nr);

	return __atomic_fetch_or(addr, mask, __ATOMIC_ACQ_REL) & mask;
}

static inline int
rte_test_and_clear_bit(int nr, unsigned long *addr)
{
	unsigned long mask = (1UL << nr);

	return __atomic_fetch_and(addr, ~mask, __ATOMIC_ACQ_REL) & mask;
}
#endif /* _RTE_BITOPS_H_ */
