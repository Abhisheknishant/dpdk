/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Arm Limited
 */

#ifndef _RTE_ATOMIC_C11_H_
#define _RTE_ATOMIC_C11_H_

#include <rte_common.h>

/**
 * @file
 * c11 atomic operations
 *
 * This file wraps up compiler (GCC) c11 atomic built-ins.
 * https://gcc.gnu.org/onlinedocs/gcc/_005f_005fatomic-Builtins.html
 */

#define memory_order_relaxed __ATOMIC_RELAXED
#define memory_order_consume __ATOMIC_CONSUME
#define memory_order_acquire __ATOMIC_ACQUIRE
#define memory_order_release __ATOMIC_RELEASE
#define memory_order_acq_rel __ATOMIC_ACQ_REL
#define memory_order_seq_cst __ATOMIC_SEQ_CST

/* Generic atomic load.
 * It returns the contents of *PTR.
 *
 * The valid memory order variants are:
 * memory_order_relaxed
 * memory_order_consume
 * memory_order_acquire
 * memory_order_seq_cst
 */
#define rte_atomic_load(PTR, MO)			\
	(__extension__ ({				\
		typeof(PTR) _ptr = (PTR);		\
		typeof(*_ptr) _ret;			\
		__atomic_load(_ptr, &_ret, (MO));	\
		_ret;					\
	}))

/* Generic atomic store.
 * It stores the value of VAL into *PTR.
 *
 * The valid memory order variants are:
 * memory_order_relaxed
 * memory_order_release
 * memory_order_seq_cst
 */
#define rte_atomic_store(PTR, VAL, MO)			\
	(__extension__ ({				\
		typeof(PTR) _ptr = (PTR);		\
		typeof(*_ptr) _val = (VAL);		\
		__atomic_store(_ptr, &_val, (MO));	\
	}))

/* Generic atomic exchange.
 * It stores the value of VAL into *PTR.
 * It returns the original value of *PTR.
 *
 * The valid memory order variants are:
 * memory_order_relaxed
 * memory_order_acquire
 * memory_order_release
 * memory_order_acq_rel
 * memory_order_seq_cst
 */
#define rte_atomic_exchange(PTR, VAL, MO)			\
	(__extension__ ({					\
		typeof(PTR) _ptr = (PTR);			\
		typeof(*_ptr) _val = (VAL);			\
		typeof(*_ptr) _ret;				\
		__atomic_exchange(_ptr, &_val, &_ret, (MO));	\
		_ret;						\
	}))

/* Generic atomic compare and exchange.
 * It compares the contents of *PTR with the contents of *EXP.
 * If equal, the operation is a read-modify-write operation that
 * writes DES into *PTR.
 * If they are not equal, the operation is a read and the current
 * contents of *PTR are written into *EXP.
 *
 * The weak compare_exchange may fail spuriously and the strong
 * variation will never fails spuriously.
 *
 * If DES is written into *PTR then true is returned and memory is
 * affected according to the memory order specified by SUC_MO.
 * There are no restrictions on what memory order can be used here.
 *
 * Otherwise, false is returned and memory is affected according to
 * FAIL_MO. This memory order cannot be memory_order_release nor
 * memory_order_acq_rel. It also cannot be a stronger order than that
 * specified by SUC_MO.
 */
#define rte_atomic_compare_exchange_weak(PTR, EXP, DES, SUC_MO, FAIL_MO)    \
	(__extension__ ({						    \
		typeof(PTR) _ptr = (PTR);				    \
		typeof(*_ptr) _des = (DES);				    \
		__atomic_compare_exchange(_ptr, (EXP), &_des, 1,	    \
				 (SUC_MO), (FAIL_MO));			    \
	}))

#define rte_atomic_compare_exchange_strong(PTR, EXP, DES, SUC_MO, FAIL_MO)  \
	(__extension__ ({						    \
		typeof(PTR) _ptr = (PTR);				    \
		typeof(*_ptr) _des = (DES);				    \
		__atomic_compare_exchange(_ptr, (EXP), &_des, 0,	    \
				 (SUC_MO), (FAIL_MO));			    \
	}))

#define rte_atomic_fetch_add(PTR, VAL, MO)		\
	__atomic_fetch_add((PTR), (VAL), (MO))
#define rte_atomic_fetch_sub(PTR, VAL, MO)		\
	__atomic_fetch_sub((PTR), (VAL), (MO))
#define rte_atomic_fetch_or(PTR, VAL, MO)		\
	__atomic_fetch_or((PTR), (VAL), (MO))
#define rte_atomic_fetch_xor(PTR, VAL, MO)		\
	__atomic_fetch_xor((PTR), (VAL), (MO))
#define rte_atomic_fetch_and(PTR, VAL, MO)		\
	__atomic_fetch_and((PTR), (VAL), (MO))

#define rte_atomic_add_fetch(PTR, VAL, MO)		\
	__atomic_add_fetch((PTR), (VAL), (MO))
#define rte_atomic_sub_fetch(PTR, VAL, MO)		\
	__atomic_sub_fetch((PTR), (VAL), (MO))
#define rte_atomic_or_fetch(PTR, VAL, MO)		\
	__atomic_or_fetch((PTR), (VAL), (MO))
#define rte_atomic_xor_fetch(PTR, VAL, MO)		\
	__atomic_xor_fetch((PTR), (VAL), (MO))
#define rte_atomic_and_fetch(PTR, VAL, MO)		\
	__atomic_and_fetch((PTR), (VAL), (MO))

/* Synchronization fence between threads based on
 * the specified memory order.
 */
#define rte_atomic_thread_fence(MO) __atomic_thread_fence((MO))

#endif /* _RTE_ATOMIC_C11_H_ */
