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

/*----------------------- 128 bit atomic operations -------------------------*/

#define RTE_HAS_ACQ(mo) ((mo) != __ATOMIC_RELAXED && (mo) != __ATOMIC_RELEASE)
#define RTE_HAS_RLS(mo) ((mo) == __ATOMIC_RELEASE || \
			 (mo) == __ATOMIC_ACQ_REL || \
			 (mo) == __ATOMIC_SEQ_CST)

#define RTE_MO_LOAD(mo)  (RTE_HAS_ACQ((mo)) \
		? __ATOMIC_ACQUIRE : __ATOMIC_RELAXED)
#define RTE_MO_STORE(mo) (RTE_HAS_RLS((mo)) \
		? __ATOMIC_RELEASE : __ATOMIC_RELAXED)

#ifdef __ARM_FEATURE_ATOMICS
static inline rte_int128_t
__rte_casp(rte_int128_t *dst, rte_int128_t old, rte_int128_t updated, int mo)
{

	/* caspX instructions register pair must start from even-numbered
	 * register at operand 1.
	 * So, specify registers for local variables here.
	 */
	register uint64_t x0 __asm("x0") = (uint64_t)old.val[0];
	register uint64_t x1 __asm("x1") = (uint64_t)old.val[1];
	register uint64_t x2 __asm("x2") = (uint64_t)updated.val[0];
	register uint64_t x3 __asm("x3") = (uint64_t)updated.val[1];

	if (mo ==  __ATOMIC_RELAXED) {
		asm volatile(
				"casp %[old0], %[old1], %[upd0], %[upd1], [%[dst]]"
				: [old0] "+r" (x0),
				  [old1] "+r" (x1)
				: [upd0] "r" (x2),
				  [upd1] "r" (x3),
				  [dst] "r" (dst)
				: "memory");
	} else if (mo == __ATOMIC_ACQUIRE) {
		asm volatile(
				"caspa %[old0], %[old1], %[upd0], %[upd1], [%[dst]]"
				: [old0] "+r" (x0),
				  [old1] "+r" (x1)
				: [upd0] "r" (x2),
				  [upd1] "r" (x3),
				  [dst] "r" (dst)
				: "memory");
	} else if (mo == __ATOMIC_ACQ_REL) {
		asm volatile(
				"caspal %[old0], %[old1], %[upd0], %[upd1], [%[dst]]"
				: [old0] "+r" (x0),
				  [old1] "+r" (x1)
				: [upd0] "r" (x2),
				  [upd1] "r" (x3),
				  [dst] "r" (dst)
				: "memory");
	} else if (mo == __ATOMIC_RELEASE) {
		asm volatile(
				"caspl %[old0], %[old1], %[upd0], %[upd1], [%[dst]]"
				: [old0] "+r" (x0),
				  [old1] "+r" (x1)
				: [upd0] "r" (x2),
				  [upd1] "r" (x3),
				  [dst] "r" (dst)
				: "memory");
	} else {
		rte_panic("Invalid memory order\n");
	}

	old.val[0] = x0;
	old.val[1] = x1;

	return old;
}
#else
static inline rte_int128_t
__rte_ldx128(const rte_int128_t *src, int mo)
{
	rte_int128_t ret;
	if (mo == __ATOMIC_ACQUIRE)
		asm volatile(
				"ldaxp %0, %1, %2"
				: "=&r" (ret.val[0]),
				  "=&r" (ret.val[1])
				: "Q" (src->val[0])
				: "memory");
	else if (mo == __ATOMIC_RELAXED)
		asm volatile(
				"ldxp %0, %1, %2"
				: "=&r" (ret.val[0]),
				  "=&r" (ret.val[1])
				: "Q" (src->val[0])
				: "memory");
	else
		rte_panic("Invalid memory order\n");

	return ret;
}

static inline uint32_t
__rte_stx128(rte_int128_t *dst, const rte_int128_t src, int mo)
{
	uint32_t ret;
	if (mo == __ATOMIC_RELEASE)
		asm volatile(
				"stlxp %w0, %1, %2, %3"
				: "=&r" (ret)
				: "r" (src.val[0]),
				  "r" (src.val[1]),
				  "Q" (dst->val[0])
				: "memory");
	else if (mo == __ATOMIC_RELAXED)
		asm volatile(
				"stxp %w0, %1, %2, %3"
				: "=&r" (ret)
				: "r" (src.val[0]),
				  "r" (src.val[1]),
				  "Q" (dst->val[0])
				: "memory");
	else
		rte_panic("Invalid memory order\n");

	/* Return 0 on success, 1 on failure */
	return ret;
}
#endif

static inline int __rte_experimental
rte_atomic128_cmp_exchange(rte_int128_t *dst,
				rte_int128_t *exp,
				const rte_int128_t *src,
				unsigned int weak,
				int success,
				int failure)
{
	// Always do strong CAS
	RTE_SET_USED(weak);
	/* Ignore memory ordering for failure, memory order for
	 * success must be stronger or equal
	 */
	RTE_SET_USED(failure);

#ifdef __ARM_FEATURE_ATOMICS
	rte_int128_t expected = *exp;
	rte_int128_t desired = *src;
	rte_int128_t old;

	old = __rte_casp(dst, expected, desired, success);
#else
	int ldx_mo = RTE_MO_LOAD(success);
	int stx_mo = RTE_MO_STORE(success);
	uint32_t ret = 1;
	register rte_int128_t expected = *exp;
	register rte_int128_t desired = *src;
	register rte_int128_t old;

	/* ldx128 can not guarantee atomic,
	 * Must write back src or old to verify atomicity of ldx128;
	 */
	do {
		old = __rte_ldx128(dst, ldx_mo);
		if (likely(old.int128 == expected.int128))
			ret = __rte_stx128(dst, desired, stx_mo);
		else
			/* In the failure case (since 'weak' is ignored and only
			 * weak == 0 is implemented), expected should contain the
			 * atomically read value of dst. This means, 'old' needs
			 * to be stored back to ensure it was read atomically.
			 */
			ret = __rte_stx128(dst, old, stx_mo);
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
