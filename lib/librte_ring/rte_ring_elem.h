/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2019 Arm Limited
 * Copyright (c) 2010-2017 Intel Corporation
 * Copyright (c) 2007-2009 Kip Macy kmacy@freebsd.org
 * All rights reserved.
 * Derived from FreeBSD's bufring.h
 * Used as BSD-3 Licensed with permission from Kip Macy.
 */

#ifndef _RTE_RING_ELEM_H_
#define _RTE_RING_ELEM_H_

/**
 * @file
 * RTE Ring with flexible element size
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdint.h>
#include <sys/queue.h>
#include <errno.h>
#include <string.h>
#include <rte_common.h>
#include <rte_config.h>
#include <rte_memory.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_memzone.h>
#include <rte_pause.h>

#include "rte_ring.h"

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Calculate the memory size needed for a ring with given element size
 *
 * This function returns the number of bytes needed for a ring, given
 * the number of elements in it and the size of the element. This value
 * is the sum of the size of the structure rte_ring and the size of the
 * memory needed for storing the elements. The value is aligned to a cache
 * line size.
 *
 * @param count
 *   The number of elements in the ring (must be a power of 2).
 * @param esize
 *   The size of ring element, in bytes. It must be a multiple of 4.
 *   Currently, sizes 4, 8 and 16 are supported.
 * @return
 *   - The memory size needed for the ring on success.
 *   - -EINVAL if count is not a power of 2.
 */
__rte_experimental
ssize_t rte_ring_get_memsize_elem(unsigned count, unsigned esize);

/**
 * @warning
 * @b EXPERIMENTAL: this API may change without prior notice
 *
 * Create a new ring named *name* that stores elements with given size.
 *
 * This function uses ``memzone_reserve()`` to allocate memory. Then it
 * calls rte_ring_init() to initialize an empty ring.
 *
 * The new ring size is set to *count*, which must be a power of
 * two. Water marking is disabled by default. The real usable ring size
 * is *count-1* instead of *count* to differentiate a free ring from an
 * empty ring.
 *
 * The ring is added in RTE_TAILQ_RING list.
 *
 * @param name
 *   The name of the ring.
 * @param count
 *   The number of elements in the ring (must be a power of 2).
 * @param esize
 *   The size of ring element, in bytes. It must be a multiple of 4.
 *   Currently, sizes 4, 8 and 16 are supported.
 * @param socket_id
 *   The *socket_id* argument is the socket identifier in case of
 *   NUMA. The value can be *SOCKET_ID_ANY* if there is no NUMA
 *   constraint for the reserved zone.
 * @param flags
 *   An OR of the following:
 *    - RING_F_SP_ENQ: If this flag is set, the default behavior when
 *      using ``rte_ring_enqueue()`` or ``rte_ring_enqueue_bulk()``
 *      is "single-producer". Otherwise, it is "multi-producers".
 *    - RING_F_SC_DEQ: If this flag is set, the default behavior when
 *      using ``rte_ring_dequeue()`` or ``rte_ring_dequeue_bulk()``
 *      is "single-consumer". Otherwise, it is "multi-consumers".
 * @return
 *   On success, the pointer to the new allocated ring. NULL on error with
 *    rte_errno set appropriately. Possible errno values include:
 *    - E_RTE_NO_CONFIG - function could not get pointer to rte_config structure
 *    - E_RTE_SECONDARY - function was called from a secondary process instance
 *    - EINVAL - count provided is not a power of 2
 *    - ENOSPC - the maximum number of memzones has already been allocated
 *    - EEXIST - a memzone with the same name already exists
 *    - ENOMEM - no appropriate memory area found in which to create memzone
 */
__rte_experimental
struct rte_ring *rte_ring_create_elem(const char *name, unsigned count,
				unsigned esize, int socket_id, unsigned flags);

#define ENQUEUE_PTRS_GEN(r, ring_start, prod_head, obj_table, esize, n) do { \
	unsigned int i; \
	const uint32_t size = (r)->size; \
	uint32_t idx = prod_head & (r)->mask; \
	uint32_t *ring = (uint32_t *)ring_start; \
	uint32_t *obj = (uint32_t *)obj_table; \
	uint32_t sz = n * (esize / sizeof(uint32_t)); \
	if (likely(idx + n < size)) { \
		for (i = 0; i < (sz & ((~(unsigned)0x7))); i += 8, idx += 8) { \
			memcpy (ring + i, obj + i, 8 * sizeof (uint32_t)); \
		} \
		switch (n & 0x7) { \
		case 7: \
			ring[idx++] = obj[i++]; /* fallthrough */ \
		case 6: \
			ring[idx++] = obj[i++]; /* fallthrough */ \
		case 5: \
			ring[idx++] = obj[i++]; /* fallthrough */ \
		case 4: \
			ring[idx++] = obj[i++]; /* fallthrough */ \
		case 3: \
			ring[idx++] = obj[i++]; /* fallthrough */ \
		case 2: \
			ring[idx++] = obj[i++]; /* fallthrough */ \
		case 1: \
			ring[idx++] = obj[i++]; /* fallthrough */ \
		} \
	} else { \
		for (i = 0; idx < size; i++, idx++)\
			ring[idx] = obj[i]; \
		for (idx = 0; i < n; i++, idx++) \
			ring[idx] = obj[i]; \
	} \
} while (0)

#define DEQUEUE_PTRS_GEN(r, ring_start, cons_head, obj_table, esize, n) do { \
	unsigned int i; \
	uint32_t idx = cons_head & (r)->mask; \
	const uint32_t size = (r)->size; \
	uint32_t *ring = (uint32_t *)ring_start; \
	uint32_t *obj = (uint32_t *)obj_table; \
	uint32_t sz = n * (esize / sizeof(uint32_t)); \
	if (likely(idx + n < size)) { \
		for (i = 0; i < (sz & ((~(unsigned)0x7))); i += 8, idx += 8) { \
			memcpy (obj + i, ring + i, 8 * sizeof (uint32_t)); \
		} \
		switch (n & 0x7) { \
		case 7: \
			obj[i++] = ring[idx++]; /* fallthrough */ \
		case 6: \
			obj[i++] = ring[idx++]; /* fallthrough */ \
		case 5: \
			obj[i++] = ring[idx++]; /* fallthrough */ \
		case 4: \
			obj[i++] = ring[idx++]; /* fallthrough */ \
		case 3: \
			obj[i++] = ring[idx++]; /* fallthrough */ \
		case 2: \
			obj[i++] = ring[idx++]; /* fallthrough */ \
		case 1: \
			obj[i++] = ring[idx++]; /* fallthrough */ \
		} \
	} else { \
		for (i = 0; idx < size; i++, idx++) \
			obj[i] = ring[idx]; \
		for (idx = 0; i < n; i++, idx++) \
			obj[i] = ring[idx]; \
	} \
} while (0)

/* Between load and load. there might be cpu reorder in weak model
 * (powerpc/arm).
 * There are 2 choices for the users
 * 1.use rmb() memory barrier
 * 2.use one-direction load_acquire/store_release barrier,defined by
 * CONFIG_RTE_USE_C11_MEM_MODEL=y
 * It depends on performance test results.
 * By default, move common functions to rte_ring_generic.h
 */
#ifdef RTE_USE_C11_MEM_MODEL
#include "rte_ring_c11_mem.h"
#else
#include "rte_ring_generic.h"
#endif

/**
 * @internal Enqueue several objects on the ring
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_table
 *   A pointer to a table of void * pointers (objects).
 * @param esize
 *   The size of ring element, in bytes. It must be a multiple of 4.
 *   Currently, sizes 4, 8 and 16 are supported. This should be the same
 *   as passed while creating the ring, otherwise the results are undefined.
 * @param n
 *   The number of objects to add in the ring from the obj_table.
 * @param behavior
 *   RTE_RING_QUEUE_FIXED:    Enqueue a fixed number of items from a ring
 *   RTE_RING_QUEUE_VARIABLE: Enqueue as many items as possible from ring
 * @param is_sp
 *   Indicates whether to use single producer or multi-producer head update
 * @param free_space
 *   returns the amount of space after the enqueue operation has finished
 * @return
 *   Actual number of objects enqueued.
 *   If behavior == RTE_RING_QUEUE_FIXED, this will be 0 or n only.
 */
static __rte_always_inline unsigned int
__rte_ring_do_enqueue_elem(struct rte_ring *r, void * const obj_table,
		unsigned int esize, unsigned int n,
		enum rte_ring_queue_behavior behavior, unsigned int is_sp,
		unsigned int *free_space)
{
	uint32_t prod_head, prod_next;
	uint32_t free_entries;

	n = __rte_ring_move_prod_head(r, is_sp, n, behavior,
			&prod_head, &prod_next, &free_entries);
	if (n == 0)
		goto end;

	ENQUEUE_PTRS_GEN(r, &r[1], prod_head, obj_table, esize, n);

	update_tail(&r->prod, prod_head, prod_next, is_sp, 1);
end:
	if (free_space != NULL)
		*free_space = free_entries - n;
	return n;
}

/**
 * @internal Dequeue several objects from the ring
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_table
 *   A pointer to a table of void * pointers (objects).
 * @param esize
 *   The size of ring element, in bytes. It must be a multiple of 4.
 *   Currently, sizes 4, 8 and 16 are supported. This should be the same
 *   as passed while creating the ring, otherwise the results are undefined.
 * @param n
 *   The number of objects to pull from the ring.
 * @param behavior
 *   RTE_RING_QUEUE_FIXED:    Dequeue a fixed number of items from a ring
 *   RTE_RING_QUEUE_VARIABLE: Dequeue as many items as possible from ring
 * @param is_sc
 *   Indicates whether to use single consumer or multi-consumer head update
 * @param available
 *   returns the number of remaining ring entries after the dequeue has finished
 * @return
 *   - Actual number of objects dequeued.
 *     If behavior == RTE_RING_QUEUE_FIXED, this will be 0 or n only.
 */
static __rte_always_inline unsigned int
__rte_ring_do_dequeue_elem(struct rte_ring *r, void *obj_table,
		unsigned int esize, unsigned int n,
		enum rte_ring_queue_behavior behavior, unsigned int is_sc,
		unsigned int *available)
{
	uint32_t cons_head, cons_next;
	uint32_t entries;

	n = __rte_ring_move_cons_head(r, (int)is_sc, n, behavior,
			&cons_head, &cons_next, &entries);
	if (n == 0)
		goto end;

	DEQUEUE_PTRS_GEN(r, &r[1], cons_head, obj_table, esize, n);

	update_tail(&r->cons, cons_head, cons_next, is_sc, 0);

end:
	if (available != NULL)
		*available = entries - n;
	return n;
}

/**
 * Enqueue several objects on the ring (multi-producers safe).
 *
 * This function uses a "compare and set" instruction to move the
 * producer index atomically.
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_table
 *   A pointer to a table of void * pointers (objects).
 * @param esize
 *   The size of ring element, in bytes. It must be a multiple of 4.
 *   Currently, sizes 4, 8 and 16 are supported. This should be the same
 *   as passed while creating the ring, otherwise the results are undefined.
 * @param n
 *   The number of objects to add in the ring from the obj_table.
 * @param free_space
 *   if non-NULL, returns the amount of space in the ring after the
 *   enqueue operation has finished.
 * @return
 *   The number of objects enqueued, either 0 or n
 */
static __rte_always_inline unsigned int
rte_ring_mp_enqueue_bulk_elem(struct rte_ring *r, void * const obj_table,
		unsigned int esize, unsigned int n, unsigned int *free_space)
{
	return __rte_ring_do_enqueue_elem(r, obj_table, esize, n,
			RTE_RING_QUEUE_FIXED, __IS_MP, free_space);
}

/**
 * Enqueue several objects on a ring (NOT multi-producers safe).
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_table
 *   A pointer to a table of void * pointers (objects).
 * @param esize
 *   The size of ring element, in bytes. It must be a multiple of 4.
 *   Currently, sizes 4, 8 and 16 are supported. This should be the same
 *   as passed while creating the ring, otherwise the results are undefined.
 * @param n
 *   The number of objects to add in the ring from the obj_table.
 * @param free_space
 *   if non-NULL, returns the amount of space in the ring after the
 *   enqueue operation has finished.
 * @return
 *   The number of objects enqueued, either 0 or n
 */
static __rte_always_inline unsigned int
rte_ring_sp_enqueue_bulk_elem(struct rte_ring *r, void * const obj_table,
		unsigned int esize, unsigned int n, unsigned int *free_space)
{
	return __rte_ring_do_enqueue_elem(r, obj_table, esize, n,
			RTE_RING_QUEUE_FIXED, __IS_SP, free_space);
}

/**
 * Enqueue several objects on a ring.
 *
 * This function calls the multi-producer or the single-producer
 * version depending on the default behavior that was specified at
 * ring creation time (see flags).
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_table
 *   A pointer to a table of void * pointers (objects).
 * @param esize
 *   The size of ring element, in bytes. It must be a multiple of 4.
 *   Currently, sizes 4, 8 and 16 are supported. This should be the same
 *   as passed while creating the ring, otherwise the results are undefined.
 * @param n
 *   The number of objects to add in the ring from the obj_table.
 * @param free_space
 *   if non-NULL, returns the amount of space in the ring after the
 *   enqueue operation has finished.
 * @return
 *   The number of objects enqueued, either 0 or n
 */
static __rte_always_inline unsigned int
rte_ring_enqueue_bulk_elem(struct rte_ring *r, void * const obj_table,
		unsigned int esize, unsigned int n, unsigned int *free_space)
{
	return __rte_ring_do_enqueue_elem(r, obj_table, esize, n,
			RTE_RING_QUEUE_FIXED, r->prod.single, free_space);
}

/**
 * Enqueue one object on a ring (multi-producers safe).
 *
 * This function uses a "compare and set" instruction to move the
 * producer index atomically.
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj
 *   A pointer to the object to be added.
 * @param esize
 *   The size of ring element, in bytes. It must be a multiple of 4.
 *   Currently, sizes 4, 8 and 16 are supported. This should be the same
 *   as passed while creating the ring, otherwise the results are undefined.
 * @return
 *   - 0: Success; objects enqueued.
 *   - -ENOBUFS: Not enough room in the ring to enqueue; no object is enqueued.
 */
static __rte_always_inline int
rte_ring_mp_enqueue_elem(struct rte_ring *r, void *obj, unsigned int esize)
{
	return rte_ring_mp_enqueue_bulk_elem(r, obj, esize, 1, NULL) ? 0 :
								-ENOBUFS;
}

/**
 * Enqueue one object on a ring (NOT multi-producers safe).
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj
 *   A pointer to the object to be added.
 * @param esize
 *   The size of ring element, in bytes. It must be a multiple of 4.
 *   Currently, sizes 4, 8 and 16 are supported. This should be the same
 *   as passed while creating the ring, otherwise the results are undefined.
 * @return
 *   - 0: Success; objects enqueued.
 *   - -ENOBUFS: Not enough room in the ring to enqueue; no object is enqueued.
 */
static __rte_always_inline int
rte_ring_sp_enqueue_elem(struct rte_ring *r, void *obj, unsigned int esize)
{
	return rte_ring_sp_enqueue_bulk_elem(r, obj, esize, 1, NULL) ? 0 :
								-ENOBUFS;
}

/**
 * Enqueue one object on a ring.
 *
 * This function calls the multi-producer or the single-producer
 * version, depending on the default behaviour that was specified at
 * ring creation time (see flags).
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj
 *   A pointer to the object to be added.
 * @param esize
 *   The size of ring element, in bytes. It must be a multiple of 4.
 *   Currently, sizes 4, 8 and 16 are supported. This should be the same
 *   as passed while creating the ring, otherwise the results are undefined.
 * @return
 *   - 0: Success; objects enqueued.
 *   - -ENOBUFS: Not enough room in the ring to enqueue; no object is enqueued.
 */
static __rte_always_inline int
rte_ring_enqueue_elem(struct rte_ring *r, void *obj, unsigned int esize)
{
	return rte_ring_enqueue_bulk_elem(r, obj, esize, 1, NULL) ? 0 :
								-ENOBUFS;
}

/**
 * Dequeue several objects from a ring (multi-consumers safe).
 *
 * This function uses a "compare and set" instruction to move the
 * consumer index atomically.
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_table
 *   A pointer to a table of void * pointers (objects) that will be filled.
 * @param esize
 *   The size of ring element, in bytes. It must be a multiple of 4.
 *   Currently, sizes 4, 8 and 16 are supported. This should be the same
 *   as passed while creating the ring, otherwise the results are undefined.
 * @param n
 *   The number of objects to dequeue from the ring to the obj_table.
 * @param available
 *   If non-NULL, returns the number of remaining ring entries after the
 *   dequeue has finished.
 * @return
 *   The number of objects dequeued, either 0 or n
 */
static __rte_always_inline unsigned int
rte_ring_mc_dequeue_bulk_elem(struct rte_ring *r, void *obj_table,
		unsigned int esize, unsigned int n, unsigned int *available)
{
	return __rte_ring_do_dequeue_elem(r, obj_table, esize, n,
				RTE_RING_QUEUE_FIXED, __IS_MC, available);
}

/**
 * Dequeue several objects from a ring (NOT multi-consumers safe).
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_table
 *   A pointer to a table of void * pointers (objects) that will be filled.
 * @param esize
 *   The size of ring element, in bytes. It must be a multiple of 4.
 *   Currently, sizes 4, 8 and 16 are supported. This should be the same
 *   as passed while creating the ring, otherwise the results are undefined.
 * @param n
 *   The number of objects to dequeue from the ring to the obj_table,
 *   must be strictly positive.
 * @param available
 *   If non-NULL, returns the number of remaining ring entries after the
 *   dequeue has finished.
 * @return
 *   The number of objects dequeued, either 0 or n
 */
static __rte_always_inline unsigned int
rte_ring_sc_dequeue_bulk_elem(struct rte_ring *r, void *obj_table,
		unsigned int esize, unsigned int n, unsigned int *available)
{
	return __rte_ring_do_dequeue_elem(r, obj_table, esize, n,
			RTE_RING_QUEUE_FIXED, __IS_SC, available);
}

/**
 * Dequeue several objects from a ring.
 *
 * This function calls the multi-consumers or the single-consumer
 * version, depending on the default behaviour that was specified at
 * ring creation time (see flags).
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_table
 *   A pointer to a table of void * pointers (objects) that will be filled.
 * @param esize
 *   The size of ring element, in bytes. It must be a multiple of 4.
 *   Currently, sizes 4, 8 and 16 are supported. This should be the same
 *   as passed while creating the ring, otherwise the results are undefined.
 * @param n
 *   The number of objects to dequeue from the ring to the obj_table.
 * @param available
 *   If non-NULL, returns the number of remaining ring entries after the
 *   dequeue has finished.
 * @return
 *   The number of objects dequeued, either 0 or n
 */
static __rte_always_inline unsigned int
rte_ring_dequeue_bulk_elem(struct rte_ring *r, void *obj_table,
		unsigned int esize, unsigned int n, unsigned int *available)
{
	return __rte_ring_do_dequeue_elem(r, obj_table, esize, n,
			RTE_RING_QUEUE_FIXED, r->cons.single, available);
}

/**
 * Dequeue one object from a ring (multi-consumers safe).
 *
 * This function uses a "compare and set" instruction to move the
 * consumer index atomically.
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_p
 *   A pointer to a void * pointer (object) that will be filled.
 * @param esize
 *   The size of ring element, in bytes. It must be a multiple of 4.
 *   Currently, sizes 4, 8 and 16 are supported. This should be the same
 *   as passed while creating the ring, otherwise the results are undefined.
 * @return
 *   - 0: Success; objects dequeued.
 *   - -ENOENT: Not enough entries in the ring to dequeue; no object is
 *     dequeued.
 */
static __rte_always_inline int
rte_ring_mc_dequeue_elem(struct rte_ring *r, void *obj_p,
				unsigned int esize)
{
	return rte_ring_mc_dequeue_bulk_elem(r, obj_p, esize, 1, NULL)  ? 0 :
								-ENOENT;
}

/**
 * Dequeue one object from a ring (NOT multi-consumers safe).
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_p
 *   A pointer to a void * pointer (object) that will be filled.
 * @param esize
 *   The size of ring element, in bytes. It must be a multiple of 4.
 *   Currently, sizes 4, 8 and 16 are supported. This should be the same
 *   as passed while creating the ring, otherwise the results are undefined.
 * @return
 *   - 0: Success; objects dequeued.
 *   - -ENOENT: Not enough entries in the ring to dequeue, no object is
 *     dequeued.
 */
static __rte_always_inline int
rte_ring_sc_dequeue_elem(struct rte_ring *r, void *obj_p,
				unsigned int esize)
{
	return rte_ring_sc_dequeue_bulk_elem(r, obj_p, esize, 1, NULL) ? 0 :
								-ENOENT;
}

/**
 * Dequeue one object from a ring.
 *
 * This function calls the multi-consumers or the single-consumer
 * version depending on the default behaviour that was specified at
 * ring creation time (see flags).
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_p
 *   A pointer to a void * pointer (object) that will be filled.
 * @param esize
 *   The size of ring element, in bytes. It must be a multiple of 4.
 *   Currently, sizes 4, 8 and 16 are supported. This should be the same
 *   as passed while creating the ring, otherwise the results are undefined.
 * @return
 *   - 0: Success, objects dequeued.
 *   - -ENOENT: Not enough entries in the ring to dequeue, no object is
 *     dequeued.
 */
static __rte_always_inline int
rte_ring_dequeue_elem(struct rte_ring *r, void *obj_p, unsigned int esize)
{
	return rte_ring_dequeue_bulk_elem(r, obj_p, esize, 1, NULL) ? 0 :
								-ENOENT;
}

/**
 * Enqueue several objects on the ring (multi-producers safe).
 *
 * This function uses a "compare and set" instruction to move the
 * producer index atomically.
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_table
 *   A pointer to a table of void * pointers (objects).
 * @param esize
 *   The size of ring element, in bytes. It must be a multiple of 4.
 *   Currently, sizes 4, 8 and 16 are supported. This should be the same
 *   as passed while creating the ring, otherwise the results are undefined.
 * @param n
 *   The number of objects to add in the ring from the obj_table.
 * @param free_space
 *   if non-NULL, returns the amount of space in the ring after the
 *   enqueue operation has finished.
 * @return
 *   - n: Actual number of objects enqueued.
 */
static __rte_always_inline unsigned
rte_ring_mp_enqueue_burst_elem(struct rte_ring *r, void * const obj_table,
		unsigned int esize, unsigned int n, unsigned int *free_space)
{
	return __rte_ring_do_enqueue_elem(r, obj_table, esize, n,
			RTE_RING_QUEUE_VARIABLE, __IS_MP, free_space);
}

/**
 * Enqueue several objects on a ring (NOT multi-producers safe).
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_table
 *   A pointer to a table of void * pointers (objects).
 * @param esize
 *   The size of ring element, in bytes. It must be a multiple of 4.
 *   Currently, sizes 4, 8 and 16 are supported. This should be the same
 *   as passed while creating the ring, otherwise the results are undefined.
 * @param n
 *   The number of objects to add in the ring from the obj_table.
 * @param free_space
 *   if non-NULL, returns the amount of space in the ring after the
 *   enqueue operation has finished.
 * @return
 *   - n: Actual number of objects enqueued.
 */
static __rte_always_inline unsigned
rte_ring_sp_enqueue_burst_elem(struct rte_ring *r, void * const obj_table,
		unsigned int esize, unsigned int n, unsigned int *free_space)
{
	return __rte_ring_do_enqueue_elem(r, obj_table, esize, n,
			RTE_RING_QUEUE_VARIABLE, __IS_SP, free_space);
}

/**
 * Enqueue several objects on a ring.
 *
 * This function calls the multi-producer or the single-producer
 * version depending on the default behavior that was specified at
 * ring creation time (see flags).
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_table
 *   A pointer to a table of void * pointers (objects).
 * @param esize
 *   The size of ring element, in bytes. It must be a multiple of 4.
 *   Currently, sizes 4, 8 and 16 are supported. This should be the same
 *   as passed while creating the ring, otherwise the results are undefined.
 * @param n
 *   The number of objects to add in the ring from the obj_table.
 * @param free_space
 *   if non-NULL, returns the amount of space in the ring after the
 *   enqueue operation has finished.
 * @return
 *   - n: Actual number of objects enqueued.
 */
static __rte_always_inline unsigned
rte_ring_enqueue_burst_elem(struct rte_ring *r, void * const obj_table,
		unsigned int esize, unsigned int n, unsigned int *free_space)
{
	return __rte_ring_do_enqueue_elem(r, obj_table, esize, n,
			RTE_RING_QUEUE_VARIABLE, r->prod.single, free_space);
}

/**
 * Dequeue several objects from a ring (multi-consumers safe). When the request
 * objects are more than the available objects, only dequeue the actual number
 * of objects
 *
 * This function uses a "compare and set" instruction to move the
 * consumer index atomically.
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_table
 *   A pointer to a table of void * pointers (objects) that will be filled.
 * @param esize
 *   The size of ring element, in bytes. It must be a multiple of 4.
 *   Currently, sizes 4, 8 and 16 are supported. This should be the same
 *   as passed while creating the ring, otherwise the results are undefined.
 * @param n
 *   The number of objects to dequeue from the ring to the obj_table.
 * @param available
 *   If non-NULL, returns the number of remaining ring entries after the
 *   dequeue has finished.
 * @return
 *   - n: Actual number of objects dequeued, 0 if ring is empty
 */
static __rte_always_inline unsigned
rte_ring_mc_dequeue_burst_elem(struct rte_ring *r, void *obj_table,
		unsigned int esize, unsigned int n, unsigned int *available)
{
	return __rte_ring_do_dequeue_elem(r, obj_table, esize, n,
			RTE_RING_QUEUE_VARIABLE, __IS_MC, available);
}

/**
 * Dequeue several objects from a ring (NOT multi-consumers safe).When the
 * request objects are more than the available objects, only dequeue the
 * actual number of objects
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_table
 *   A pointer to a table of void * pointers (objects) that will be filled.
 * @param esize
 *   The size of ring element, in bytes. It must be a multiple of 4.
 *   Currently, sizes 4, 8 and 16 are supported. This should be the same
 *   as passed while creating the ring, otherwise the results are undefined.
 * @param n
 *   The number of objects to dequeue from the ring to the obj_table.
 * @param available
 *   If non-NULL, returns the number of remaining ring entries after the
 *   dequeue has finished.
 * @return
 *   - n: Actual number of objects dequeued, 0 if ring is empty
 */
static __rte_always_inline unsigned
rte_ring_sc_dequeue_burst_elem(struct rte_ring *r, void *obj_table,
		unsigned int esize, unsigned int n, unsigned int *available)
{
	return __rte_ring_do_dequeue_elem(r, obj_table, esize, n,
			RTE_RING_QUEUE_VARIABLE, __IS_SC, available);
}

/**
 * Dequeue multiple objects from a ring up to a maximum number.
 *
 * This function calls the multi-consumers or the single-consumer
 * version, depending on the default behaviour that was specified at
 * ring creation time (see flags).
 *
 * @param r
 *   A pointer to the ring structure.
 * @param obj_table
 *   A pointer to a table of void * pointers (objects) that will be filled.
 * @param esize
 *   The size of ring element, in bytes. It must be a multiple of 4.
 *   Currently, sizes 4, 8 and 16 are supported. This should be the same
 *   as passed while creating the ring, otherwise the results are undefined.
 * @param n
 *   The number of objects to dequeue from the ring to the obj_table.
 * @param available
 *   If non-NULL, returns the number of remaining ring entries after the
 *   dequeue has finished.
 * @return
 *   - Number of objects dequeued
 */
static __rte_always_inline unsigned
rte_ring_dequeue_burst_elem(struct rte_ring *r, void *obj_table,
		unsigned int esize, unsigned int n, unsigned int *available)
{
	return __rte_ring_do_dequeue_elem(r, obj_table, esize, n,
				RTE_RING_QUEUE_VARIABLE,
				r->cons.single, available);
}

#ifdef __cplusplus
}
#endif

#endif /* _RTE_RING_ELEM_H_ */
