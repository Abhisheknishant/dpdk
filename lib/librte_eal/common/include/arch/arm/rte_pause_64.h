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
#define __WAIT_UNTIL_EQUAL(name, asm_op, wide, type) \
static __rte_always_inline void \
rte_wait_until_equal_##name(volatile type * addr, type expected) \
{ \
	type tmp; \
	asm volatile( \
		#asm_op " %" #wide "[tmp], %[addr]\n" \
		"cmp	%" #wide "[tmp], %" #wide "[expected]\n" \
		"b.eq	2f\n" \
		"sevl\n" \
		"1:	wfe\n" \
		#asm_op " %" #wide "[tmp], %[addr]\n" \
		"cmp	%" #wide "[tmp], %" #wide "[expected]\n" \
		"bne	1b\n" \
		"2:\n" \
		: [tmp] "=&r" (tmp) \
		: [addr] "Q"(*addr), [expected] "r"(expected) \
		: "cc", "memory"); \
}
/* Wait for *addr to be updated with expected value */
__WAIT_UNTIL_EQUAL(relaxed_16, ldxrh, w, uint16_t)
__WAIT_UNTIL_EQUAL(acquire_16, ldaxrh, w, uint16_t)
__WAIT_UNTIL_EQUAL(relaxed_32, ldxr, w, uint32_t)
__WAIT_UNTIL_EQUAL(acquire_32, ldaxr, w, uint32_t)
__WAIT_UNTIL_EQUAL(relaxed_64, ldxr, x, uint64_t)
__WAIT_UNTIL_EQUAL(acquire_64, ldaxr, x, uint64_t)
#endif

#ifdef __cplusplus
}
#endif

#endif /* _RTE_PAUSE_ARM64_H_ */
