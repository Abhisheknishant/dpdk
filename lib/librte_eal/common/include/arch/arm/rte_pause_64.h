/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Cavium, Inc
 */

#ifndef _RTE_PAUSE_ARM64_H_
#define _RTE_PAUSE_ARM64_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_common.h>
#include "generic/rte_pause.h"

static inline void rte_pause(void)
{
	asm volatile("yield" ::: "memory");
}

#ifdef RTE_USE_WFE
/* Wait for *addr to be updated with expected value */
static __rte_always_inline void
rte_wait_until_equal16(volatile uint16_t *addr, uint16_t expected, int memorder)
{
	uint16_t tmp;
	if (memorder == __ATOMIC_RELAXED)
		asm volatile(
			"ldxrh	%w[tmp], %w[addr]\n"
			"cmp	%w[tmp], %w[expected]\n"
			"b.eq	2f\n"
			"sevl\n"
			"1:	wfe\n"
			"ldxrh	%w[tmp], %w[addr]\n"
			"cmp	%w[tmp], %w[expected]\n"
			"bne	1b\n"
			"2:\n"
			: [tmp] "=&r" (tmp)
			: [addr] "Q"(*addr), [expected] "r"(expected)
			: "cc", "memory");
	else
		asm volatile(
			"ldaxrh %w[tmp], %w[addr]\n"
			"cmp	%w[tmp], %w[expected]\n"
			"b.eq	2f\n"
			"sevl\n"
			"1:	wfe\n"
			"ldaxrh	%w[tmp], %w[addr]\n"
			"cmp	%w[tmp], %w[expected]\n"
			"bne	1b\n"
			"2:\n"
			: [tmp] "=&r" (tmp)
			: [addr] "Q"(*addr), [expected] "r"(expected)
			: "cc", "memory");
}

static __rte_always_inline void
rte_wait_until_equal32(volatile uint32_t *addr, uint32_t expected, int memorder)
{
	uint32_t tmp;
	if (memorder == __ATOMIC_RELAXED)
		asm volatile(
			"ldxr	%w[tmp], %w[addr]\n"
			"cmp	%w[tmp], %w[expected]\n"
			"b.eq	2f\n"
			"sevl\n"
			"1:	wfe\n"
			"ldxr	%w[tmp], %w[addr]\n"
			"cmp	%w[tmp], %w[expected]\n"
			"bne	1b\n"
			"2:\n"
			: [tmp] "=&r" (tmp)
			: [addr] "Q"(*addr), [expected] "r"(expected)
			: "cc", "memory");
	else
		asm volatile(
			"ldaxr  %w[tmp], %w[addr]\n"
			"cmp	%w[tmp], %w[expected]\n"
			"b.eq	2f\n"
			"sevl\n"
			"1:	wfe\n"
			"ldaxr  %w[tmp], %w[addr]\n"
			"cmp	%w[tmp], %w[expected]\n"
			"bne	1b\n"
			"2:\n"
			: [tmp] "=&r" (tmp)
			: [addr] "Q"(*addr), [expected] "r"(expected)
			: "cc", "memory");
}

static __rte_always_inline void
rte_wait_until_equal64(volatile uint64_t *addr, uint64_t expected, int memorder)
{
	uint64_t tmp;
	if (memorder == __ATOMIC_RELAXED)
		asm volatile(
			"ldxr	%x[tmp], %x[addr]\n"
			"cmp	%x[tmp], %x[expected]\n"
			"b.eq	2f\n"
			"sevl\n"
			"1:	wfe\n"
			"ldxr	%x[tmp], %x[addr]\n"
			"cmp	%x[tmp], %x[expected]\n"
			"bne	1b\n"
			"2:\n"
			: [tmp] "=&r" (tmp)
			: [addr] "Q"(*addr), [expected] "r"(expected)
			: "cc", "memory");
	else
		asm volatile(
			"ldaxr  %x[tmp], %x[addr]\n"
			"cmp	%x[tmp], %x[expected]\n"
			"b.eq	2f\n"
			"sevl\n"
			"1:	wfe\n"
			"ldaxr  %x[tmp], %x[addr]\n"
			"cmp	%x[tmp], %x[expected]\n"
			"bne	1b\n"
			"2:\n"
			: [tmp] "=&r" (tmp)
			: [addr] "Q"(*addr), [expected] "r"(expected)
			: "cc", "memory");
}

#endif

#ifdef __cplusplus
}
#endif

#endif /* _RTE_PAUSE_ARM64_H_ */
