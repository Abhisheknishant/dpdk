/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2010-2017 Intel Corporation
 * Copyright (c) 2007-2009 Kip Macy kmacy@freebsd.org
 * All rights reserved.
 * Derived from FreeBSD's bufring.h
 * Used as BSD-3 Licensed with permission from Kip Macy.
 */

#ifndef _RTE_RING_RTS_GENERIC_H_
#define _RTE_RING_RTS_GENERIC_H_

/**
 * @file rte_ring_rts_generic.h
 * It is not recommended to include this file directly,
 * include <rte_ring.h> instead.
 * Contains internal helper functions for Relaxed Tail Sync (RTS) ring mode.
 * For more information please refer to <rte_ring_rts.h>.
 */

/**
 * @internal This function updates tail values.
 */
static __rte_always_inline void
__rte_ring_rts_update_tail(struct rte_ring_rts_headtail *ht)
{
	union rte_ring_ht_poscnt h, ot, nt;

	/*
	 * If there are other enqueues/dequeues in progress that
	 * might preceded us, then don't update tail with new value.
	 */

	do {
		ot.raw = ht->tail.raw;
		rte_smp_rmb();

		/* on 32-bit systems we have to do atomic read here */
		h.raw = rte_atomic64_read((rte_atomic64_t *)
			(uintptr_t)&ht->head.raw);

		nt.raw = ot.raw;
		if (++nt.val.cnt == h.val.cnt)
			nt.val.pos = h.val.pos;

	} while (rte_atomic64_cmpset(&ht->tail.raw, ot.raw, nt.raw) == 0);
}

/**
 * @internal This function waits till head/tail distance wouldn't
 * exceed pre-defined max value.
 */
static __rte_always_inline void
__rte_ring_rts_head_wait(const struct rte_ring_rts_headtail *ht,
	union rte_ring_ht_poscnt *h)
{
	uint32_t max;

	max = ht->htd_max;
	h->raw = ht->head.raw;
	rte_smp_rmb();

	while (h->val.pos - ht->tail.val.pos > max) {
		rte_pause();
		h->raw = ht->head.raw;
		rte_smp_rmb();
	}
}

/**
 * @internal This function updates the producer head for enqueue.
 *
 * @param r
 *   A pointer to the ring structure
 * @param is_sp
 *   Indicates whether multi-producer path is needed or not
 * @param n
 *   The number of elements we will want to enqueue, i.e. how far should the
 *   head be moved
 * @param behavior
 *   RTE_RING_QUEUE_FIXED:    Enqueue a fixed number of items from a ring
 *   RTE_RING_QUEUE_VARIABLE: Enqueue as many items as possible from ring
 * @param old_head
 *   Returns head value as it was before the move, i.e. where enqueue starts
 * @param new_head
 *   Returns the current/new head value i.e. where enqueue finishes
 * @param free_entries
 *   Returns the amount of free space in the ring BEFORE head was moved
 * @return
 *   Actual number of objects enqueued.
 *   If behavior == RTE_RING_QUEUE_FIXED, this will be 0 or n only.
 */
static __rte_always_inline uint32_t
__rte_ring_rts_move_prod_head(struct rte_ring *r, uint32_t num,
	enum rte_ring_queue_behavior behavior, uint32_t *old_head,
	uint32_t *free_entries)
{
	uint32_t n;
	union rte_ring_ht_poscnt nh, oh;

	const uint32_t capacity = r->capacity;

	do {
		/* Reset n to the initial burst count */
		n = num;

		/* read prod head (may spin on prod tail) */
		__rte_ring_rts_head_wait(&r->rts_prod, &oh);

		/* add rmb barrier to avoid load/load reorder in weak
		 * memory model. It is noop on x86
		 */
		rte_smp_rmb();

		/*
		 *  The subtraction is done between two unsigned 32bits value
		 * (the result is always modulo 32 bits even if we have
		 * *old_head > cons_tail). So 'free_entries' is always between 0
		 * and capacity (which is < size).
		 */
		*free_entries = capacity + r->cons.tail - oh.val.pos;

		/* check that we have enough room in ring */
		if (unlikely(n > *free_entries))
			n = (behavior == RTE_RING_QUEUE_FIXED) ?
					0 : *free_entries;

		if (n == 0)
			break;

		nh.val.pos = oh.val.pos + n;
		nh.val.cnt = oh.val.cnt + 1;

	} while (rte_atomic64_cmpset(&r->rts_prod.head.raw,
			oh.raw, nh.raw) == 0);

	*old_head = oh.val.pos;
	return n;
}

/**
 * @internal This function updates the consumer head for dequeue
 *
 * @param r
 *   A pointer to the ring structure
 * @param is_sc
 *   Indicates whether multi-consumer path is needed or not
 * @param n
 *   The number of elements we will want to enqueue, i.e. how far should the
 *   head be moved
 * @param behavior
 *   RTE_RING_QUEUE_FIXED:    Dequeue a fixed number of items from a ring
 *   RTE_RING_QUEUE_VARIABLE: Dequeue as many items as possible from ring
 * @param old_head
 *   Returns head value as it was before the move, i.e. where dequeue starts
 * @param new_head
 *   Returns the current/new head value i.e. where dequeue finishes
 * @param entries
 *   Returns the number of entries in the ring BEFORE head was moved
 * @return
 *   - Actual number of objects dequeued.
 *     If behavior == RTE_RING_QUEUE_FIXED, this will be 0 or n only.
 */
static __rte_always_inline unsigned int
__rte_ring_rts_move_cons_head(struct rte_ring *r, uint32_t num,
	enum rte_ring_queue_behavior behavior, uint32_t *old_head,
	uint32_t *entries)
{
	uint32_t n;
	union rte_ring_ht_poscnt nh, oh;

	/* move cons.head atomically */
	do {
		/* Restore n as it may change every loop */
		n = num;

		/* read cons head (may spin on cons tail) */
		__rte_ring_rts_head_wait(&r->rts_cons, &oh);


		/* add rmb barrier to avoid load/load reorder in weak
		 * memory model. It is noop on x86
		 */
		rte_smp_rmb();

		/* The subtraction is done between two unsigned 32bits value
		 * (the result is always modulo 32 bits even if we have
		 * cons_head > prod_tail). So 'entries' is always between 0
		 * and size(ring)-1.
		 */
		*entries = r->prod.tail - oh.val.pos;

		/* Set the actual entries for dequeue */
		if (n > *entries)
			n = (behavior == RTE_RING_QUEUE_FIXED) ? 0 : *entries;

		if (unlikely(n == 0))
			break;

		nh.val.pos = oh.val.pos + n;
		nh.val.cnt = oh.val.cnt + 1;

	} while (rte_atomic64_cmpset(&r->rts_cons.head.raw,
			oh.raw, nh.raw) == 0);

	*old_head = oh.val.pos;
	return n;
}

#endif /* _RTE_RING_RTS_GENERIC_H_ */
