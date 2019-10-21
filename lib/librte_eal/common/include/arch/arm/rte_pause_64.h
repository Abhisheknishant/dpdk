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

#ifdef RTE_ARM_USE_WFE
#define sev()	{ asm volatile("sev" : : : "memory") }
#define wfe()	{ asm volatile("wfe" : : : "memory") }

#define __WAIT_UNTIL_EQUAL(type, size, addr, expected, memorder) \
__rte_experimental						\
static __rte_always_inline void					\
rte_wait_until_equal_##size(volatile type * addr, type expected,\
int memorder)							\
{								\
	if (__atomic_load_n(addr, memorder) != expected) {	\
		sev();							\
		do {							\
			wfe();						\
		} while (__atomic_load_n(addr, memorder) != expected);	\
	 }								\
}
__WAIT_UNTIL_EQUAL(uint16_t, 16, addr, expected, memorder)
__WAIT_UNTIL_EQUAL(uint32_t, 32, addr, expected, memorder)
__WAIT_UNTIL_EQUAL(uint64_t, 64, addr, expected, memorder)

#undef __WAIT_UNTIL_EQUAL

#endif /* RTE_ARM_USE_WFE */

#ifdef __cplusplus
}
#endif

#endif /* _RTE_PAUSE_ARM64_H_ */
