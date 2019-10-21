/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2015 RehiveTech. All rights reserved.
 */

#ifndef _RTE_SPINLOCK_ARM_H_
#define _RTE_SPINLOCK_ARM_H_

#ifndef RTE_FORCE_INTRINSICS
#  error Platform must be built with CONFIG_RTE_FORCE_INTRINSICS
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include <rte_common.h>
#include "generic/rte_spinlock.h"

/* armv7a does support WFE, but an explicit wake-up signal using SEV is
 * required (must be preceded by DSB to drain the store buffer) and
 * this is less performant, so keep armv7a implementation unchanged.
 */
#ifdef RTE_ARM_USE_WFE
static inline void
rte_spinlock_lock(rte_spinlock_t *sl)
{
	unsigned int tmp;
	/* http://infocenter.arm.com/help/index.jsp?topic=/com.arm.doc.
	 * faqs/ka16809.html
	 */
	asm volatile(
		"1:	ldaxr %w[tmp], %w[locked]\n"
		"cbnz   %w[tmp], 2f\n"
		"stxr   %w[tmp], %w[one], %w[locked]\n"
		"cbnz   %w[tmp], 1b\n"
		"ret\n"
		"2:	sevl\n"
		"wfe\n"
		"jmp	1b\n"
		: [tmp] "=&r" (tmp), [locked] "+Q"(sl->locked)
		: [one] "r" (1)
}
#endif

static inline int rte_tm_supported(void)
{
	return 0;
}

static inline void
rte_spinlock_lock_tm(rte_spinlock_t *sl)
{
	rte_spinlock_lock(sl); /* fall-back */
}

static inline int
rte_spinlock_trylock_tm(rte_spinlock_t *sl)
{
	return rte_spinlock_trylock(sl);
}

static inline void
rte_spinlock_unlock_tm(rte_spinlock_t *sl)
{
	rte_spinlock_unlock(sl);
}

static inline void
rte_spinlock_recursive_lock_tm(rte_spinlock_recursive_t *slr)
{
	rte_spinlock_recursive_lock(slr); /* fall-back */
}

static inline void
rte_spinlock_recursive_unlock_tm(rte_spinlock_recursive_t *slr)
{
	rte_spinlock_recursive_unlock(slr);
}

static inline int
rte_spinlock_recursive_trylock_tm(rte_spinlock_recursive_t *slr)
{
	return rte_spinlock_recursive_trylock(slr);
}

#ifdef __cplusplus
}
#endif

#endif /* _RTE_SPINLOCK_ARM_H_ */
