/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Arm Limited
 */

#ifndef _RTE_STACK_LF_STUBS_H_
#define _RTE_STACK_LF_STUBS_H_

#include <rte_common.h>
#include <rte_atomic.h>

static __rte_always_inline unsigned int
__rte_stack_lf_count(struct rte_stack *s)
{
	/* stack_lf_push() and stack_lf_pop() do not update the list's contents
	 * and stack_lf->len atomically, which can cause the list to appear
	 * shorter than it actually is if this function is called while other
	 * threads are modifying the list.
	 *
	 * However, given the inherently approximate nature of the get_count
	 * callback -- even if the list and its size were updated atomically,
	 * the size could change between when get_count executes and when the
	 * value is returned to the caller -- this is acceptable.
	 *
	 * The stack_lf->len updates are placed such that the list may appear to
	 * have fewer elements than it does, but will never appear to have more
	 * elements. If the mempool is near-empty to the point that this is a
	 * concern, the user should consider increasing the mempool size.
	 */
	return (unsigned int)rte_atomic64_read((rte_atomic64_t *)
			&s->stack_lf.used.len);
}

static __rte_always_inline void
__rte_stack_lf_push_elems(struct rte_stack_lf_list *list,
			  struct rte_stack_lf_elem *first,
			  struct rte_stack_lf_elem *last,
			  unsigned int num)
{
	RTE_SET_USED(first);
	RTE_SET_USED(last);
	RTE_SET_USED(list);
	RTE_SET_USED(num);
}

static __rte_always_inline struct rte_stack_lf_elem *
__rte_stack_lf_pop_elems(struct rte_stack_lf_list *list,
			 unsigned int num,
			 void **obj_table,
			 struct rte_stack_lf_elem **last)
{
	RTE_SET_USED(obj_table);
	RTE_SET_USED(last);
	RTE_SET_USED(list);
	RTE_SET_USED(num);

	return NULL;
}

#endif /* _RTE_STACK_LF_STUBS_H_ */
