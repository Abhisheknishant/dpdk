/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2019 Arm Limited
 */

#ifndef _RTE_RING_TEMPLATE_H_
#define _RTE_RING_TEMPLATE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdint.h>
#include <sys/queue.h>
#include <errno.h>
#include <rte_common.h>
#include <rte_config.h>
#include <rte_memory.h>
#include <rte_lcore.h>
#include <rte_atomic.h>
#include <rte_branch_prediction.h>
#include <rte_memzone.h>
#include <rte_pause.h>
#include <rte_ring.h>

/* Ring API suffix name - used to append to API names */
#ifndef RTE_RING_TMPLT_API_SUFFIX
#error RTE_RING_TMPLT_API_SUFFIX not defined
#endif

/* Ring's element size in bits, should be a power of 2 */
#ifndef RTE_RING_TMPLT_ELEM_SIZE
#error RTE_RING_TMPLT_ELEM_SIZE not defined
#endif

/* Type of ring elements */
#ifndef RTE_RING_TMPLT_ELEM_TYPE
#error RTE_RING_TMPLT_ELEM_TYPE not defined
#endif

#define _rte_fuse(a, b) a##_##b
#define __rte_fuse(a, b) _rte_fuse(a, b)
#define __RTE_RING_CONCAT(a) __rte_fuse(a, RTE_RING_TMPLT_API_SUFFIX)

/* Calculate the memory size needed for a ring */
RTE_RING_TMPLT_EXPERIMENTAL
ssize_t __RTE_RING_CONCAT(rte_ring_get_memsize)(unsigned count);

/* Create a new ring named *name* in memory. */
RTE_RING_TMPLT_EXPERIMENTAL
struct rte_ring *
__RTE_RING_CONCAT(rte_ring_create)(const char *name, unsigned count,
					int socket_id, unsigned flags);

/**
 * @internal Enqueue several objects on the ring
 */
static __rte_always_inline unsigned int
__RTE_RING_CONCAT(__rte_ring_do_enqueue)(struct rte_ring *r,
		RTE_RING_TMPLT_ELEM_TYPE const *obj_table, unsigned int n,
		enum rte_ring_queue_behavior behavior, unsigned int is_sp,
		unsigned int *free_space)
{
	uint32_t prod_head, prod_next;
	uint32_t free_entries;

	n = __rte_ring_move_prod_head(r, is_sp, n, behavior,
			&prod_head, &prod_next, &free_entries);
	if (n == 0)
		goto end;

	ENQUEUE_PTRS(r, &r[1], prod_head, obj_table, n,
		RTE_RING_TMPLT_ELEM_TYPE);

	update_tail(&r->prod, prod_head, prod_next, is_sp, 1);
end:
	if (free_space != NULL)
		*free_space = free_entries - n;
	return n;
}

/**
 * @internal Dequeue several objects from the ring
 */
static __rte_always_inline unsigned int
__RTE_RING_CONCAT(__rte_ring_do_dequeue)(struct rte_ring *r,
	RTE_RING_TMPLT_ELEM_TYPE *obj_table, unsigned int n,
	enum rte_ring_queue_behavior behavior, unsigned int is_sc,
	unsigned int *available)
{
	uint32_t cons_head, cons_next;
	uint32_t entries;

	n = __rte_ring_move_cons_head(r, (int)is_sc, n, behavior,
			&cons_head, &cons_next, &entries);
	if (n == 0)
		goto end;

	DEQUEUE_PTRS(r, &r[1], cons_head, obj_table, n,
		RTE_RING_TMPLT_ELEM_TYPE);

	update_tail(&r->cons, cons_head, cons_next, is_sc, 0);

end:
	if (available != NULL)
		*available = entries - n;
	return n;
}


/**
 * Enqueue several objects on the ring (multi-producers safe).
 */
static __rte_always_inline unsigned int
__RTE_RING_CONCAT(rte_ring_mp_enqueue_bulk)(struct rte_ring *r,
	RTE_RING_TMPLT_ELEM_TYPE const *obj_table, unsigned int n,
	unsigned int *free_space)
{
	return __RTE_RING_CONCAT(__rte_ring_do_enqueue)(r, obj_table, n,
			RTE_RING_QUEUE_FIXED, __IS_MP, free_space);
}

/**
 * Enqueue several objects on a ring (NOT multi-producers safe).
 */
static __rte_always_inline unsigned int
__RTE_RING_CONCAT(rte_ring_sp_enqueue_bulk)(struct rte_ring *r,
	RTE_RING_TMPLT_ELEM_TYPE const *obj_table, unsigned int n,
	unsigned int *free_space)
{
	return __RTE_RING_CONCAT(__rte_ring_do_enqueue)(r, obj_table, n,
			RTE_RING_QUEUE_FIXED, __IS_SP, free_space);
}

/**
 * Enqueue several objects on a ring.
 */
static __rte_always_inline unsigned int
__RTE_RING_CONCAT(rte_ring_enqueue_bulk)(struct rte_ring *r,
	RTE_RING_TMPLT_ELEM_TYPE const *obj_table, unsigned int n,
	unsigned int *free_space)
{
	return __RTE_RING_CONCAT(__rte_ring_do_enqueue)(r, obj_table, n,
			RTE_RING_QUEUE_FIXED, r->prod.single, free_space);
}

/**
 * Enqueue one object on a ring (multi-producers safe).
 */
static __rte_always_inline int
__RTE_RING_CONCAT(rte_ring_mp_enqueue)(struct rte_ring *r,
	RTE_RING_TMPLT_ELEM_TYPE obj)
{
	return __RTE_RING_CONCAT(rte_ring_mp_enqueue_bulk)(r, &obj, 1, NULL) ?
			0 : -ENOBUFS;
}

/**
 * Enqueue one object on a ring (NOT multi-producers safe).
 */
static __rte_always_inline int
__RTE_RING_CONCAT(rte_ring_sp_enqueue)(struct rte_ring *r,
	RTE_RING_TMPLT_ELEM_TYPE obj)
{
	return __RTE_RING_CONCAT(rte_ring_sp_enqueue_bulk)(r, &obj, 1, NULL) ?
			0 : -ENOBUFS;
}

/**
 * Enqueue one object on a ring.
 */
static __rte_always_inline int
__RTE_RING_CONCAT(rte_ring_enqueue)(struct rte_ring *r,
	RTE_RING_TMPLT_ELEM_TYPE *obj)
{
	return __RTE_RING_CONCAT(rte_ring_enqueue_bulk)(r, obj, 1, NULL) ?
			0 : -ENOBUFS;
}

/**
 * Dequeue several objects from a ring (multi-consumers safe).
 */
static __rte_always_inline unsigned int
__RTE_RING_CONCAT(rte_ring_mc_dequeue_bulk)(struct rte_ring *r,
	RTE_RING_TMPLT_ELEM_TYPE *obj_table, unsigned int n,
	unsigned int *available)
{
	return __RTE_RING_CONCAT(__rte_ring_do_dequeue)(r, obj_table, n,
			RTE_RING_QUEUE_FIXED, __IS_MC, available);
}

/**
 * Dequeue several objects from a ring (NOT multi-consumers safe).
 */
static __rte_always_inline unsigned int
__RTE_RING_CONCAT(rte_ring_sc_dequeue_bulk)(struct rte_ring *r,
	RTE_RING_TMPLT_ELEM_TYPE *obj_table, unsigned int n,
	unsigned int *available)
{
	return __RTE_RING_CONCAT(__rte_ring_do_dequeue)(r, obj_table, n,
			RTE_RING_QUEUE_FIXED, __IS_SC, available);
}

/**
 * Dequeue several objects from a ring.
 */
static __rte_always_inline unsigned int
__RTE_RING_CONCAT(rte_ring_dequeue_bulk)(struct rte_ring *r,
	RTE_RING_TMPLT_ELEM_TYPE *obj_table, unsigned int n,
	unsigned int *available)
{
	return __RTE_RING_CONCAT(__rte_ring_do_dequeue)(r, obj_table, n,
			RTE_RING_QUEUE_FIXED, r->cons.single, available);
}

/**
 * Dequeue one object from a ring (multi-consumers safe).
 */
static __rte_always_inline int
__RTE_RING_CONCAT(rte_ring_mc_dequeue)(struct rte_ring *r,
	RTE_RING_TMPLT_ELEM_TYPE *obj_p)
{
	return __RTE_RING_CONCAT(rte_ring_mc_dequeue_bulk)(r, obj_p, 1, NULL) ?
			0 : -ENOENT;
}

/**
 * Dequeue one object from a ring (NOT multi-consumers safe).
 */
static __rte_always_inline int
__RTE_RING_CONCAT(rte_ring_sc_dequeue)(struct rte_ring *r,
	RTE_RING_TMPLT_ELEM_TYPE *obj_p)
{
	return __RTE_RING_CONCAT(rte_ring_sc_dequeue_bulk)(r, obj_p, 1, NULL) ?
			0 : -ENOENT;
}

/**
 * Dequeue one object from a ring.
 */
static __rte_always_inline int
__RTE_RING_CONCAT(rte_ring_dequeue)(struct rte_ring *r,
	RTE_RING_TMPLT_ELEM_TYPE *obj_p)
{
	return __RTE_RING_CONCAT(rte_ring_dequeue_bulk)(r, obj_p, 1, NULL) ?
			0 : -ENOENT;
}

/**
 * Enqueue several objects on the ring (multi-producers safe).
 */
static __rte_always_inline unsigned
__RTE_RING_CONCAT(rte_ring_mp_enqueue_burst)(struct rte_ring *r,
	RTE_RING_TMPLT_ELEM_TYPE *obj_table,
			 unsigned int n, unsigned int *free_space)
{
	return __RTE_RING_CONCAT(__rte_ring_do_enqueue)(r, obj_table, n,
			RTE_RING_QUEUE_VARIABLE, __IS_MP, free_space);
}

/**
 * Enqueue several objects on a ring (NOT multi-producers safe).
 */
static __rte_always_inline unsigned
__RTE_RING_CONCAT(rte_ring_sp_enqueue_burst)(struct rte_ring *r,
	RTE_RING_TMPLT_ELEM_TYPE *obj_table,
			 unsigned int n, unsigned int *free_space)
{
	return __RTE_RING_CONCAT(__rte_ring_do_enqueue)(r, obj_table, n,
			RTE_RING_QUEUE_VARIABLE, __IS_SP, free_space);
}

/**
 * Enqueue several objects on a ring.
 */
static __rte_always_inline unsigned
__RTE_RING_CONCAT(rte_ring_enqueue_burst)(struct rte_ring *r,
	RTE_RING_TMPLT_ELEM_TYPE *obj_table, unsigned int n,
	unsigned int *free_space)
{
	return __RTE_RING_CONCAT(__rte_ring_do_enqueue)(r, obj_table, n,
			RTE_RING_QUEUE_VARIABLE, r->prod.single, free_space);
}

/**
 * Dequeue several objects from a ring (multi-consumers safe). When the request
 * objects are more than the available objects, only dequeue the actual number
 * of objects
 */
static __rte_always_inline unsigned
__RTE_RING_CONCAT(rte_ring_mc_dequeue_burst)(struct rte_ring *r,
	RTE_RING_TMPLT_ELEM_TYPE *obj_table, unsigned int n,
	unsigned int *available)
{
	return __RTE_RING_CONCAT(__rte_ring_do_dequeue)(r, obj_table, n,
			RTE_RING_QUEUE_VARIABLE, __IS_MC, available);
}

/**
 * Dequeue several objects from a ring (NOT multi-consumers safe).When the
 * request objects are more than the available objects, only dequeue the
 * actual number of objects
 */
static __rte_always_inline unsigned
__RTE_RING_CONCAT(rte_ring_sc_dequeue_burst)(struct rte_ring *r,
	RTE_RING_TMPLT_ELEM_TYPE *obj_table, unsigned int n,
	unsigned int *available)
{
	return __RTE_RING_CONCAT(__rte_ring_do_dequeue)(r, obj_table, n,
			RTE_RING_QUEUE_VARIABLE, __IS_SC, available);
}

/**
 * Dequeue multiple objects from a ring up to a maximum number.
 */
static __rte_always_inline unsigned
__RTE_RING_CONCAT(rte_ring_dequeue_burst)(struct rte_ring *r,
	RTE_RING_TMPLT_ELEM_TYPE *obj_table, unsigned int n,
	unsigned int *available)
{
	return __RTE_RING_CONCAT(__rte_ring_do_dequeue)(r, obj_table, n,
				RTE_RING_QUEUE_VARIABLE,
				r->cons.single, available);
}

#ifdef __cplusplus
}
#endif

#endif /* _RTE_RING_TEMPLATE_H_ */
