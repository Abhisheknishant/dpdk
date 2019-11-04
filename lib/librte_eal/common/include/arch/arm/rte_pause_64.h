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

#ifdef RTE_ARM_USE_WFE
#define RTE_WAIT_UNTIL_EQUAL_ARCH_DEFINED
#endif

#include "generic/rte_pause.h"

static inline void rte_pause(void)
{
	asm volatile("yield" ::: "memory");
}

#ifdef RTE_WAIT_UNTIL_EQUAL_ARCH_DEFINED
/**
 * Send an event to quit WFE.
 */
static inline void _sevl(void)
{
	asm volatile("sevl" : : : "memory");
}

/**
 * Put processor into low power WFE(Wait For Event) state
 */
static inline void _wfe(void)
{
	asm volatile("wfe" : : : "memory");
}

/**
 * Atomic exclusive load from addr, it returns the 16-bit content of *addr
 * while making it 'monitored',when it is written by someone else, the
 * 'monitored' state is cleared and a event is generated implicitly to exit
 * WFE.
 *
 * @param addr
 *  A pointer to the memory location.
 * @param memorder
 *  The valid memory order variants are __ATOMIC_ACQUIRE and __ATOMIC_RELAXED.
 *  These map to C++11 memory orders with the same names, see the C++11 standard
 *  the GCC wiki on atomic synchronization for detailed definitions.
 */
static __rte_always_inline uint16_t
__atomic_load_ex_16(volatile uint16_t *addr, int memorder);

/**
 * Atomic exclusive load from addr, it returns the 32-bit content of *addr
 * while making it 'monitored',when it is written by someone else, the
 * 'monitored' state is cleared and a event is generated implicitly to exit
 * WFE.
 *
 * @param addr
 *  A pointer to the memory location.
 * @param memorder
 *  The valid memory order variants are __ATOMIC_ACQUIRE and __ATOMIC_RELAXED.
 *  These map to C++11 memory orders with the same names, see the C++11 standard
 *  the GCC wiki on atomic synchronization for detailed definitions.
 */
static __rte_always_inline uint32_t
__atomic_load_ex_32(volatile uint32_t *addr, int memorder);

/**
 * Atomic exclusive load from addr, it returns the 64-bit content of *addr
 * while making it 'monitored',when it is written by someone else, the
 * 'monitored' state is cleared and a event is generated implicitly to exit
 * WFE.
 *
 * @param addr
 *  A pointer to the memory location.
 * @param memorder
 *  The valid memory order variants are __ATOMIC_ACQUIRE and __ATOMIC_RELAXED.
 *  These map to C++11 memory orders with the same names, see the C++11 standard
 *  the GCC wiki on atomic synchronization for detailed definitions.
 */
static __rte_always_inline uint64_t
__atomic_load_ex_64(volatile uint64_t *addr, int memorder);

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

static __rte_always_inline void
rte_wait_until_equal_16(volatile uint16_t *addr, uint16_t expected,
int memorder)
{
	if (__atomic_load_ex_16(addr, memorder) != expected) {
		_sevl();
		do {
			_wfe();
		} while (__atomic_load_ex_16(addr, memorder) != expected);
	}
}

static __rte_always_inline void
rte_wait_until_equal_32(volatile uint32_t *addr, uint32_t expected,
int memorder)
{
	if (__atomic_load_ex_32(addr, memorder) != expected) {
		_sevl();
		do {
			_wfe();
		} while (__atomic_load_ex_32(addr, memorder) != expected);
	}
}

static __rte_always_inline void
rte_wait_until_equal_64(volatile uint64_t *addr, uint64_t expected,
int memorder)
{
	if (__atomic_load_ex_64(addr, memorder) != expected) {
		_sevl();
		do {
			_wfe();
		} while (__atomic_load_ex_64(addr, memorder) != expected);
	}
}
#endif

#ifdef __cplusplus
}
#endif

#endif /* _RTE_PAUSE_ARM64_H_ */
