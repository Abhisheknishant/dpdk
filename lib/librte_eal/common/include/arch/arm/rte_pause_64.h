/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2017 Cavium, Inc
 * Copyright(c) 2019 Arm Limited
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

#ifdef RTE_WAIT_UNTIL_EQUAL_ARCH_DEFINED
static inline void rte_sevl(void)
{
	asm volatile("sevl" : : : "memory");
}

static inline void rte_wfe(void)
{
	asm volatile("wfe" : : : "memory");
}

static __rte_always_inline uint16_t
__atomic_load_ex_16(volatile uint16_t *addr, int memorder)
{
	uint16_t tmp;
	assert((memorder == __ATOMIC_ACQUIRE)
			|| (memorder == __ATOMIC_RELAXED));
	if (memorder == __ATOMIC_ACQUIRE)
		asm volatile("ldaxrh %w[tmp], [%x[addr]]"
			: [tmp] "=&r" (tmp)
			: [addr] "r"(addr)
			: "memory");
	else if (memorder == __ATOMIC_RELAXED)
		asm volatile("ldxrh %w[tmp], [%x[addr]]"
			: [tmp] "=&r" (tmp)
			: [addr] "r"(addr)
			: "memory");
	return tmp;
}

static __rte_always_inline uint32_t
__atomic_load_ex_32(volatile uint32_t *addr, int memorder)
{
	uint32_t tmp;
	assert((memorder == __ATOMIC_ACQUIRE)
			|| (memorder == __ATOMIC_RELAXED));
	if (memorder == __ATOMIC_ACQUIRE)
		asm volatile("ldaxr %w[tmp], [%x[addr]]"
			: [tmp] "=&r" (tmp)
			: [addr] "r"(addr)
			: "memory");
	else if (memorder == __ATOMIC_RELAXED)
		asm volatile("ldxr %w[tmp], [%x[addr]]"
			: [tmp] "=&r" (tmp)
			: [addr] "r"(addr)
			: "memory");
	return tmp;
}

static __rte_always_inline uint64_t
__atomic_load_ex_64(volatile uint64_t *addr, int memorder)
{
	uint64_t tmp;
	assert((memorder == __ATOMIC_ACQUIRE)
			|| (memorder == __ATOMIC_RELAXED));
	if (memorder == __ATOMIC_ACQUIRE)
		asm volatile("ldaxr %x[tmp], [%x[addr]]"
			: [tmp] "=&r" (tmp)
			: [addr] "r"(addr)
			: "memory");
	else if (memorder == __ATOMIC_RELAXED)
		asm volatile("ldxr %x[tmp], [%x[addr]]"
			: [tmp] "=&r" (tmp)
			: [addr] "r"(addr)
			: "memory");
	return tmp;
}
#endif

#ifdef __cplusplus
}
#endif

#endif /* _RTE_PAUSE_ARM64_H_ */
