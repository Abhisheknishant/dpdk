/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2010-2020 Intel Corporation
 * Copyright (c) 2007-2009 Kip Macy kmacy@freebsd.org
 * All rights reserved.
 * Derived from FreeBSD's bufring.h
 * Used as BSD-3 Licensed with permission from Kip Macy.
 */

#ifndef _RTE_RING_HTS_GENERIC_H_
#define _RTE_RING_HTS_GENERIC_H_

/**
 * @file rte_ring_hts_generic.h
 * It is not recommended to include this file directly,
 * include <rte_ring.h> instead.
 * Contains internal helper functions for head/tail sync (HTS) ring mode.
 * For more information please refer to <rte_ring_hts.h>.
 */

/**
 * @internal get current tail value.
 * Check that user didn't request to move tail above the head.
 * In that situation:
 * - return zero, that will cause abort any pending changes and
 *   return head to its previous position.
 * - throw an assert in debug mode.
 */
static __rte_always_inline uint32_t
__rte_ring_hts_get_tail(struct rte_ring_hts_headtail *ht, uint32_t *tail,
	uint32_t num)
{
	uint32_t n;
	union rte_ring_ht_pos p;

	p.raw = rte_atomic64_read((rte_atomic64_t *)(uintptr_t)&ht->ht.raw);
	n = p.pos.head - p.pos.tail;

	RTE_ASSERT(n >= num);
	num = (n >= num) ? num : 0;

	*tail = p.pos.tail;
	return num;
}

/**
 * @internal set new values for head and tail as one atomic 64 bit operation.
 * Should be used only in conjunction with __rte_ring_hts_get_tail.
 */
static __rte_always_inline void
__rte_ring_hts_set_head_tail(struct rte_ring_hts_headtail *ht, uint32_t tail,
	uint32_t num, uint32_t enqueue)
{
	union rte_ring_ht_pos p;

	if (enqueue)
		rte_smp_wmb();
	else
		rte_smp_rmb();

	p.pos.head = tail + num;
	p.pos.tail = p.pos.head;

	rte_atomic64_set((rte_atomic64_t *)(uintptr_t)&ht->ht.raw, p.raw);
}

static __rte_always_inline void
__rte_ring_hts_update_tail(struct rte_ring_hts_headtail *ht, uint32_t num,
	uint32_t enqueue)
{
	uint32_t tail;

	num = __rte_ring_hts_get_tail(ht, &tail, num);
	__rte_ring_hts_set_head_tail(ht, tail, num, enqueue);
}

/**
 * @internal waits till tail will become equal to head.
 * Means no writer/reader is active for that ring.
 * Suppose to work as serialization point.
 */
static __rte_always_inline void
__rte_ring_hts_head_wait(const struct rte_ring_hts_headtail *ht,
		union rte_ring_ht_pos *p)
{
	p->raw = rte_atomic64_read((rte_atomic64_t *)
			(uintptr_t)&ht->ht.raw);

	while (p->pos.head != p->pos.tail) {
		rte_pause();
		p->raw = rte_atomic64_read((rte_atomic64_t *)
				(uintptr_t)&ht->ht.raw);
	}
}

/**
 * @internal This function updates the producer head for enqueue
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
static __rte_always_inline unsigned int
__rte_ring_hts_move_prod_head(struct rte_ring *r, unsigned int num,
	enum rte_ring_queue_behavior behavior, uint32_t *old_head,
	uint32_t *free_entries)
{
	uint32_t n;
	union rte_ring_ht_pos np, op;

	const uint32_t capacity = r->capacity;

	do {
		/* Reset n to the initial burst count */
		n = num;

		/* wait for tail to be equal to head */
		__rte_ring_hts_head_wait(&r->hts_prod, &op);

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
		*free_entries = capacity + r->cons.tail - op.pos.head;

		/* check that we have enough room in ring */
		if (unlikely(n > *free_entries))
			n = (behavior == RTE_RING_QUEUE_FIXED) ?
					0 : *free_entries;

		if (n == 0)
			break;

		np.pos.tail = op.pos.tail;
		np.pos.head = op.pos.head + n;

	} while (rte_atomic64_cmpset(&r->hts_prod.ht.raw,
			op.raw, np.raw) == 0);

	*old_head = op.pos.head;
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
__rte_ring_hts_move_cons_head(struct rte_ring *r, unsigned int num,
	enum rte_ring_queue_behavior behavior, uint32_t *old_head,
	uint32_t *entries)
{
	uint32_t n;
	union rte_ring_ht_pos np, op;

	/* move cons.head atomically */
	do {
		/* Restore n as it may change every loop */
		n = num;

		/* wait for tail to be equal to head */
		__rte_ring_hts_head_wait(&r->hts_cons, &op);

		/* add rmb barrier to avoid load/load reorder in weak
		 * memory model. It is noop on x86
		 */
		rte_smp_rmb();

		/* The subtraction is done between two unsigned 32bits value
		 * (the result is always modulo 32 bits even if we have
		 * cons_head > prod_tail). So 'entries' is always between 0
		 * and size(ring)-1.
		 */
		*entries = r->prod.tail - op.pos.head;

		/* Set the actual entries for dequeue */
		if (n > *entries)
			n = (behavior == RTE_RING_QUEUE_FIXED) ? 0 : *entries;

		if (unlikely(n == 0))
			break;

		np.pos.tail = op.pos.tail;
		np.pos.head = op.pos.head + n;

	} while (rte_atomic64_cmpset(&r->hts_cons.ht.raw,
			op.raw, np.raw) == 0);

	*old_head = op.pos.head;
	return n;
}

#endif /* _RTE_RING_HTS_GENERIC_H_ */
