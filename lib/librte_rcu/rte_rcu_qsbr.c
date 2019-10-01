/* SPDX-License-Identifier: BSD-3-Clause
 *
 * Copyright (c) 2018 Arm Limited
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <errno.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_malloc.h>
#include <rte_eal.h>
#include <rte_eal_memconfig.h>
#include <rte_atomic.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_errno.h>

#include "rte_rcu_qsbr.h"
#include "rte_rcu_qsbr_pvt.h"

/* Get the memory size of QSBR variable */
size_t
rte_rcu_qsbr_get_memsize(uint32_t max_threads)
{
	size_t sz;

	if (max_threads == 0) {
		rte_log(RTE_LOG_ERR, rte_rcu_log_type,
			"%s(): Invalid max_threads %u\n",
			__func__, max_threads);
		rte_errno = EINVAL;

		return 1;
	}

	sz = sizeof(struct rte_rcu_qsbr);

	/* Add the size of quiescent state counter array */
	sz += sizeof(struct rte_rcu_qsbr_cnt) * max_threads;

	/* Add the size of the registered thread ID bitmap array */
	sz += __RTE_QSBR_THRID_ARRAY_SIZE(max_threads);

	return sz;
}

/* Initialize a quiescent state variable */
int
rte_rcu_qsbr_init(struct rte_rcu_qsbr *v, uint32_t max_threads)
{
	size_t sz;

	if (v == NULL) {
		rte_log(RTE_LOG_ERR, rte_rcu_log_type,
			"%s(): Invalid input parameter\n", __func__);
		rte_errno = EINVAL;

		return 1;
	}

	sz = rte_rcu_qsbr_get_memsize(max_threads);
	if (sz == 1)
		return 1;

	/* Set all the threads to offline */
	memset(v, 0, sz);
	v->max_threads = max_threads;
	v->num_elems = RTE_ALIGN_MUL_CEIL(max_threads,
			__RTE_QSBR_THRID_ARRAY_ELM_SIZE) /
			__RTE_QSBR_THRID_ARRAY_ELM_SIZE;
	v->token = __RTE_QSBR_CNT_INIT;

	return 0;
}

/* Register a reader thread to report its quiescent state
 * on a QS variable.
 */
int
rte_rcu_qsbr_thread_register(struct rte_rcu_qsbr *v, unsigned int thread_id)
{
	unsigned int i, id, success;
	uint64_t old_bmap, new_bmap;

	if (v == NULL || thread_id >= v->max_threads) {
		rte_log(RTE_LOG_ERR, rte_rcu_log_type,
			"%s(): Invalid input parameter\n", __func__);
		rte_errno = EINVAL;

		return 1;
	}

	__RTE_RCU_IS_LOCK_CNT_ZERO(v, thread_id, ERR, "Lock counter %u\n",
				v->qsbr_cnt[thread_id].lock_cnt);

	id = thread_id & __RTE_QSBR_THRID_MASK;
	i = thread_id >> __RTE_QSBR_THRID_INDEX_SHIFT;

	/* Make sure that the counter for registered threads does not
	 * go out of sync. Hence, additional checks are required.
	 */
	/* Check if the thread is already registered */
	old_bmap = __atomic_load_n(__RTE_QSBR_THRID_ARRAY_ELM(v, i),
					__ATOMIC_RELAXED);
	if (old_bmap & 1UL << id)
		return 0;

	do {
		new_bmap = old_bmap | (1UL << id);
		success = __atomic_compare_exchange(
					__RTE_QSBR_THRID_ARRAY_ELM(v, i),
					&old_bmap, &new_bmap, 0,
					__ATOMIC_RELEASE, __ATOMIC_RELAXED);

		if (success)
			__atomic_fetch_add(&v->num_threads,
						1, __ATOMIC_RELAXED);
		else if (old_bmap & (1UL << id))
			/* Someone else registered this thread.
			 * Counter should not be incremented.
			 */
			return 0;
	} while (success == 0);

	return 0;
}

/* Remove a reader thread, from the list of threads reporting their
 * quiescent state on a QS variable.
 */
int
rte_rcu_qsbr_thread_unregister(struct rte_rcu_qsbr *v, unsigned int thread_id)
{
	unsigned int i, id, success;
	uint64_t old_bmap, new_bmap;

	if (v == NULL || thread_id >= v->max_threads) {
		rte_log(RTE_LOG_ERR, rte_rcu_log_type,
			"%s(): Invalid input parameter\n", __func__);
		rte_errno = EINVAL;

		return 1;
	}

	__RTE_RCU_IS_LOCK_CNT_ZERO(v, thread_id, ERR, "Lock counter %u\n",
				v->qsbr_cnt[thread_id].lock_cnt);

	id = thread_id & __RTE_QSBR_THRID_MASK;
	i = thread_id >> __RTE_QSBR_THRID_INDEX_SHIFT;

	/* Make sure that the counter for registered threads does not
	 * go out of sync. Hence, additional checks are required.
	 */
	/* Check if the thread is already unregistered */
	old_bmap = __atomic_load_n(__RTE_QSBR_THRID_ARRAY_ELM(v, i),
					__ATOMIC_RELAXED);
	if (old_bmap & ~(1UL << id))
		return 0;

	do {
		new_bmap = old_bmap & ~(1UL << id);
		/* Make sure any loads of the shared data structure are
		 * completed before removal of the thread from the list of
		 * reporting threads.
		 */
		success = __atomic_compare_exchange(
					__RTE_QSBR_THRID_ARRAY_ELM(v, i),
					&old_bmap, &new_bmap, 0,
					__ATOMIC_RELEASE, __ATOMIC_RELAXED);

		if (success)
			__atomic_fetch_sub(&v->num_threads,
						1, __ATOMIC_RELAXED);
		else if (old_bmap & ~(1UL << id))
			/* Someone else unregistered this thread.
			 * Counter should not be incremented.
			 */
			return 0;
	} while (success == 0);

	return 0;
}

/* Wait till the reader threads have entered quiescent state. */
void
rte_rcu_qsbr_synchronize(struct rte_rcu_qsbr *v, unsigned int thread_id)
{
	uint64_t t;

	RTE_ASSERT(v != NULL);

	t = rte_rcu_qsbr_start(v);

	/* If the current thread has readside critical section,
	 * update its quiescent state status.
	 */
	if (thread_id != RTE_QSBR_THRID_INVALID)
		rte_rcu_qsbr_quiescent(v, thread_id);

	/* Wait for other readers to enter quiescent state */
	rte_rcu_qsbr_check(v, t, true);
}

/* Dump the details of a single quiescent state variable to a file. */
int
rte_rcu_qsbr_dump(FILE *f, struct rte_rcu_qsbr *v)
{
	uint64_t bmap;
	uint32_t i, t, id;

	if (v == NULL || f == NULL) {
		rte_log(RTE_LOG_ERR, rte_rcu_log_type,
			"%s(): Invalid input parameter\n", __func__);
		rte_errno = EINVAL;

		return 1;
	}

	fprintf(f, "\nQuiescent State Variable @%p\n", v);

	fprintf(f, "  QS variable memory size = %zu\n",
				rte_rcu_qsbr_get_memsize(v->max_threads));
	fprintf(f, "  Given # max threads = %u\n", v->max_threads);
	fprintf(f, "  Current # threads = %u\n", v->num_threads);

	fprintf(f, "  Registered thread IDs = ");
	for (i = 0; i < v->num_elems; i++) {
		bmap = __atomic_load_n(__RTE_QSBR_THRID_ARRAY_ELM(v, i),
					__ATOMIC_ACQUIRE);
		id = i << __RTE_QSBR_THRID_INDEX_SHIFT;
		while (bmap) {
			t = __builtin_ctzl(bmap);
			fprintf(f, "%u ", id + t);

			bmap &= ~(1UL << t);
		}
	}

	fprintf(f, "\n");

	fprintf(f, "  Token = %"PRIu64"\n",
			__atomic_load_n(&v->token, __ATOMIC_ACQUIRE));

	fprintf(f, "Quiescent State Counts for readers:\n");
	for (i = 0; i < v->num_elems; i++) {
		bmap = __atomic_load_n(__RTE_QSBR_THRID_ARRAY_ELM(v, i),
					__ATOMIC_ACQUIRE);
		id = i << __RTE_QSBR_THRID_INDEX_SHIFT;
		while (bmap) {
			t = __builtin_ctzl(bmap);
			fprintf(f, "thread ID = %u, count = %"PRIu64", lock count = %u\n",
				id + t,
				__atomic_load_n(
					&v->qsbr_cnt[id + t].cnt,
					__ATOMIC_RELAXED),
				__atomic_load_n(
					&v->qsbr_cnt[id + t].lock_cnt,
					__ATOMIC_RELAXED));
			bmap &= ~(1UL << t);
		}
	}

	return 0;
}

/* Create a queue used to store the data structure elements that can
 * be freed later. This queue is referred to as 'defer queue'.
 */
struct rte_rcu_qsbr_dq *
rte_rcu_qsbr_dq_create(const struct rte_rcu_qsbr_dq_parameters *params)
{
	struct rte_rcu_qsbr_dq *dq;
	uint32_t qs_fifo_size;

	if (params == NULL || params->f == NULL ||
		params->v == NULL || params->name == NULL ||
		params->size == 0 || params->esize == 0 ||
		(params->esize % 8 != 0)) {
		rte_log(RTE_LOG_ERR, rte_rcu_log_type,
			"%s(): Invalid input parameter\n", __func__);
		rte_errno = EINVAL;

		return NULL;
	}

	dq = rte_zmalloc(NULL,
		(sizeof(struct rte_rcu_qsbr_dq) + params->esize),
		RTE_CACHE_LINE_SIZE);
	if (dq == NULL) {
		rte_errno = ENOMEM;

		return NULL;
	}

	/* round up qs_fifo_size to next power of two that is not less than
	 * max_size.
	 */
	qs_fifo_size = rte_align32pow2((((params->esize/8) + 1)
					* params->size) + 1);
	dq->r = rte_ring_create(params->name, qs_fifo_size,
					SOCKET_ID_ANY, 0);
	if (dq->r == NULL) {
		rte_log(RTE_LOG_ERR, rte_rcu_log_type,
			"%s(): defer queue create failed\n", __func__);
		rte_free(dq);
		return NULL;
	}

	dq->v = params->v;
	dq->size = params->size;
	dq->esize = params->esize;
	dq->f = params->f;
	dq->p = params->p;

	return dq;
}

/* Enqueue one resource to the defer queue to free after the grace
 * period is over.
 */
int rte_rcu_qsbr_dq_enqueue(struct rte_rcu_qsbr_dq *dq, void *e)
{
	uint64_t token;
	uint64_t *tmp;
	uint32_t i;
	uint32_t cur_size, free_size;

	if (dq == NULL || e == NULL) {
		rte_log(RTE_LOG_ERR, rte_rcu_log_type,
			"%s(): Invalid input parameter\n", __func__);
		rte_errno = EINVAL;

		return 1;
	}

	/* Start the grace period */
	token = rte_rcu_qsbr_start(dq->v);

	/* Reclaim resources if the queue is 1/8th full. This helps
	 * the queue from growing too large and allows time for reader
	 * threads to report their quiescent state.
	 */
	cur_size = rte_ring_count(dq->r) / (dq->esize/8 + 1);
	if (cur_size > (dq->size >> RTE_RCU_QSBR_AUTO_RECLAIM_LIMIT)) {
		rte_log(RTE_LOG_INFO, rte_rcu_log_type,
			"%s(): Triggering reclamation\n", __func__);
		rte_rcu_qsbr_dq_reclaim(dq);
	}

	/* Check if there is space for atleast for 1 resource */
	free_size = rte_ring_free_count(dq->r) / (dq->esize/8 + 1);
	if (!free_size) {
		rte_log(RTE_LOG_ERR, rte_rcu_log_type,
			"%s(): Defer queue is full\n", __func__);
		rte_errno = ENOSPC;
		return 1;
	}

	/* Enqueue the resource */
	rte_ring_sp_enqueue(dq->r, (void *)(uintptr_t)token);

	/* The resource to enqueue needs to be a multiple of 64b
	 * due to the limitation of the rte_ring implementation.
	 */
	for (i = 0, tmp = (uint64_t *)e; i < dq->esize/8; i++, tmp++)
		rte_ring_sp_enqueue(dq->r, (void *)(uintptr_t)*tmp);

	return 0;
}

/* Reclaim resources from the defer queue. */
int
rte_rcu_qsbr_dq_reclaim(struct rte_rcu_qsbr_dq *dq)
{
	uint32_t max_cnt;
	uint32_t cnt;
	void *token;
	uint64_t *tmp;
	uint32_t i;

	if (dq == NULL) {
		rte_log(RTE_LOG_ERR, rte_rcu_log_type,
			"%s(): Invalid input parameter\n", __func__);
		rte_errno = EINVAL;

		return 1;
	}

	/* Anything to reclaim? */
	if (rte_ring_count(dq->r) == 0)
		return 0;

	/* Reclaim at the max 1/16th the total number of entries. */
	max_cnt = dq->size >> RTE_RCU_QSBR_MAX_RECLAIM_LIMIT;
	max_cnt = (max_cnt == 0) ? dq->size : max_cnt;
	cnt = 0;

	/* Check reader threads quiescent state and reclaim resources */
	while ((cnt < max_cnt) && (rte_ring_peek(dq->r, &token) == 0) &&
		(rte_rcu_qsbr_check(dq->v, (uint64_t)((uintptr_t)token), false)
			== 1)) {
		(void)rte_ring_sc_dequeue(dq->r, &token);
		/* The resource to dequeue needs to be a multiple of 64b
		 * due to the limitation of the rte_ring implementation.
		 */
		for (i = 0, tmp = (uint64_t *)dq->e; i < dq->esize/8;
			i++, tmp++)
			(void)rte_ring_sc_dequeue(dq->r,
					(void *)(uintptr_t)tmp);
		dq->f(dq->p, dq->e);

		cnt++;
	}

	rte_log(RTE_LOG_INFO, rte_rcu_log_type,
		"%s(): Reclaimed %u resources\n", __func__, cnt);

	if (cnt == 0) {
		/* No resources were reclaimed */
		rte_errno = EAGAIN;
		return 1;
	}

	return 0;
}

/* Delete a defer queue. */
int
rte_rcu_qsbr_dq_delete(struct rte_rcu_qsbr_dq *dq)
{
	if (dq == NULL) {
		rte_log(RTE_LOG_ERR, rte_rcu_log_type,
			"%s(): Invalid input parameter\n", __func__);
		rte_errno = EINVAL;

		return 1;
	}

	/* Reclaim all the resources */
	if (rte_rcu_qsbr_dq_reclaim(dq) != 0)
		/* Error number is already set by the reclaim API */
		return 1;

	rte_ring_free(dq->r);
	rte_free(dq);

	return 0;
}

int rte_rcu_log_type;

RTE_INIT(rte_rcu_register)
{
	rte_rcu_log_type = rte_log_register("lib.rcu");
	if (rte_rcu_log_type >= 0)
		rte_log_set_level(rte_rcu_log_type, RTE_LOG_ERR);
}
