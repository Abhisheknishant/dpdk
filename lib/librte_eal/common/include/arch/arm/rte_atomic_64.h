/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2015 Cavium, Inc
 * Copyright(c) 2019 Arm Limited
 */

#ifndef _RTE_ATOMIC_ARM64_H_
#define _RTE_ATOMIC_ARM64_H_

#ifndef RTE_FORCE_INTRINSICS
#  error Platform must be built with CONFIG_RTE_FORCE_INTRINSICS
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include "generic/rte_atomic.h"
#include <rte_branch_prediction.h>
#include <rte_compat.h>
#include <rte_debug.h>

#define dsb(opt) asm volatile("dsb " #opt : : : "memory")
#define dmb(opt) asm volatile("dmb " #opt : : : "memory")

#define rte_mb() dsb(sy)

#define rte_wmb() dsb(st)

#define rte_rmb() dsb(ld)

#define rte_smp_mb() dmb(ish)

#define rte_smp_wmb() dmb(ishst)

#define rte_smp_rmb() dmb(ishld)

#define rte_io_mb() rte_mb()

#define rte_io_wmb() rte_wmb()

#define rte_io_rmb() rte_rmb()

#define rte_cio_wmb() dmb(oshst)

#define rte_cio_rmb() dmb(oshld)

/*------------------------ 128 bit atomic operations -------------------------*/

#define __HAS_ACQ(mo) ((mo) != __ATOMIC_RELAXED && (mo) != __ATOMIC_RELEASE)
#define __HAS_RLS(mo) ((mo) == __ATOMIC_RELEASE || (mo) == __ATOMIC_ACQ_REL || \
					  (mo) == __ATOMIC_SEQ_CST)

#define __MO_LOAD(mo)  (__HAS_ACQ((mo)) ? __ATOMIC_ACQUIRE : __ATOMIC_RELAXED)
#define __MO_STORE(mo) (__HAS_RLS((mo)) ? __ATOMIC_RELEASE : __ATOMIC_RELAXED)

#if defined(__ARM_FEATURE_ATOMICS) || defined(RTE_ARM_FEATURE_ATOMICS)
#define __ATOMIC128_CAS_OP(cas_op_name, op_string)                          \
static __rte_noinline rte_int128_t                                          \
cas_op_name(rte_int128_t *dst, rte_int128_t old,                            \
		rte_int128_t updated)                                               \
{                                                                           \
	/* caspX instructions register pair must start from even-numbered
	 * register at operand 1.
	 * So, specify registers for local variables here.
	 */                                                                     \
	register uint64_t x0 __asm("x0") = (uint64_t)old.val[0];                \
	register uint64_t x1 __asm("x1") = (uint64_t)old.val[1];                \
	register uint64_t x2 __asm("x2") = (uint64_t)updated.val[0];            \
	register uint64_t x3 __asm("x3") = (uint64_t)updated.val[1];            \
	asm volatile(                                                           \
			op_string " %[old0], %[old1], %[upd0], %[upd1], [%[dst]]"       \
			: [old0] "+r" (x0),                                             \
			  [old1] "+r" (x1)                                              \
			: [upd0] "r" (x2),                                              \
			  [upd1] "r" (x3),                                              \
			  [dst] "r" (dst)                                               \
			: "memory");                                                    \
	old.val[0] = x0;                                                        \
	old.val[1] = x1;                                                        \
	return old;                                                             \
}

__ATOMIC128_CAS_OP(__rte_cas_relaxed, "casp")
__ATOMIC128_CAS_OP(__rte_cas_acquire, "caspa")
__ATOMIC128_CAS_OP(__rte_cas_release, "caspl")
__ATOMIC128_CAS_OP(__rte_cas_acq_rel, "caspal")
#else
#define __ATOMIC128_LDX_OP(ldx_op_name, op_string)                          \
static inline rte_int128_t                                                  \
ldx_op_name(const rte_int128_t *src)                                        \
{                                                                           \
	rte_int128_t ret;                                                       \
	asm volatile(                                                           \
			op_string " %0, %1, %2"                                         \
			: "=&r" (ret.val[0]),                                           \
			  "=&r" (ret.val[1])                                            \
			: "Q" (src->val[0])                                             \
			: "memory");                                                    \
	return ret;                                                             \
}

__ATOMIC128_LDX_OP(__rte_ldx_relaxed, "ldxp")
__ATOMIC128_LDX_OP(__rte_ldx_acquire, "ldaxp")

#define __ATOMIC128_STX_OP(stx_op_name, op_string)                          \
static inline uint32_t                                                      \
stx_op_name(rte_int128_t *dst, const rte_int128_t src)                      \
{                                                                           \
	uint32_t ret;                                                           \
	asm volatile(                                                           \
			op_string " %w0, %1, %2, %3"                                    \
			: "=&r" (ret)                                                   \
			: "r" (src.val[0]),                                             \
			  "r" (src.val[1]),                                             \
			  "Q" (dst->val[0])                                             \
			: "memory");                                                    \
	/* Return 0 on success, 1 on failure */                                 \
	return ret;                                                             \
}

__ATOMIC128_STX_OP(__rte_stx_relaxed, "stxp")
__ATOMIC128_STX_OP(__rte_stx_release, "stlxp")
#endif

static inline int __rte_experimental
rte_atomic128_cmp_exchange(rte_int128_t *dst,
				rte_int128_t *exp,
				const rte_int128_t *src,
				unsigned int weak,
				int success,
				int failure)
{
	/* Always do strong CAS */
	RTE_SET_USED(weak);
	/* Ignore memory ordering for failure, memory order for
	 * success must be stronger or equal
	 */
	RTE_SET_USED(failure);
	/* Find invalid memory order */
	RTE_ASSERT(success == __ATOMIC_RELAXED
			|| success == __ATOMIC_ACQUIRE
			|| success == __ATOMIC_RELEASE
			|| success == __ATOMIC_ACQ_REL
			|| success == __ATOMIC_SEQ_CST);

#ifdef __ARM_FEATURE_ATOMICS
	rte_int128_t expected = *exp;
	rte_int128_t desired = *src;
	rte_int128_t old;

	if (success == __ATOMIC_RELAXED)
		old = __rte_cas_relaxed(dst, expected, desired);
	else if (success == __ATOMIC_ACQUIRE)
		old = __rte_cas_acquire(dst, expected, desired);
	else if (success == __ATOMIC_RELEASE)
		old = __rte_cas_release(dst, expected, desired);
	else
		old = __rte_cas_acq_rel(dst, expected, desired);
#else
	int ldx_mo = __MO_LOAD(success);
	int stx_mo = __MO_STORE(success);
	uint32_t ret = 1;
	register rte_int128_t expected = *exp;
	register rte_int128_t desired = *src;
	register rte_int128_t old;

	/* ldx128 can not guarantee atomic,
	 * Must write back src or old to verify atomicity of ldx128;
	 */
	do {
		if (ldx_mo == __ATOMIC_RELAXED)
			old = __rte_ldx_relaxed(dst);
		else
			old = __rte_ldx_acquire(dst);

		if (likely(old.int128 == expected.int128)) {
			if (stx_mo == __ATOMIC_RELAXED)
				ret = __rte_stx_relaxed(dst, desired);
			else
				ret = __rte_stx_release(dst, desired);
		} else {
			/* In the failure case (since 'weak' is ignored and only
			 * weak == 0 is implemented), expected should contain the
			 * atomically read value of dst. This means, 'old' needs
			 * to be stored back to ensure it was read atomically.
			 */
			if (stx_mo == __ATOMIC_RELAXED)
				ret = __rte_stx_relaxed(dst, old);
			else
				ret = __rte_stx_release(dst, old);
		}
	} while (unlikely(ret));
#endif

	/* Unconditionally updating expected removes
	 * an 'if' statement.
	 * expected should already be in register if
	 * not in the cache.
	 */
	*exp = old;

	return (old.int128 == expected.int128);
}

#ifdef __cplusplus
}
#endif

#endif /* _RTE_ATOMIC_ARM64_H_ */
