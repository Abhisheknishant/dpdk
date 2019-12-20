/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 * Copyright(c) 2019 Arm Limited
 */


#include <stdio.h>
#include <inttypes.h>
#include <rte_ring.h>
#include <rte_cycles.h>
#include <rte_launch.h>
#include <rte_pause.h>
#include <string.h>

#include "test.h"
#include "test_ring.h"

/*
 * Ring
 * ====
 *
 * Measures performance of various operations using rdtsc
 *  * Empty ring dequeue
 *  * Enqueue/dequeue of bursts in 1 threads
 *  * Enqueue/dequeue of bursts in 2 threads
 *  * Enqueue/dequeue of bursts in all available threads
 */

#define RING_NAME "RING_PERF"
#define RING_SIZE 4096
#define MAX_BURST 32

/*
 * the sizes to enqueue and dequeue in testing
 * (marked volatile so they won't be seen as compile-time constants)
 */
static const volatile unsigned bulk_sizes[] = { 8, 32 };

struct lcore_pair {
	unsigned c1, c2;
};

static volatile unsigned lcore_count = 0;

static void
test_ring_print_test_string(unsigned int api_type, int esize,
	unsigned int bsz, double value)
{
	if (esize == -1)
		printf("legacy APIs");
	else
		printf("elem APIs: element size %dB", esize);

	if (api_type == TEST_RING_IGNORE_API_TYPE)
		return;

	if ((api_type & TEST_RING_N) == TEST_RING_N)
		printf(": default enqueue/dequeue: ");
	else if ((api_type & TEST_RING_S) == TEST_RING_S)
		printf(": SP/SC: ");
	else if ((api_type & TEST_RING_M) == TEST_RING_M)
		printf(": MP/MC: ");

	if ((api_type & TEST_RING_SL) == TEST_RING_SL)
		printf("single: ");
	else if ((api_type & TEST_RING_BL) == TEST_RING_BL)
		printf("bulk (size: %u): ", bsz);
	else if ((api_type & TEST_RING_BR) == TEST_RING_BR)
		printf("burst (size: %u): ", bsz);

	printf("%.2F\n", value);
}

/**** Functions to analyse our core mask to get cores for different tests ***/

static int
get_two_hyperthreads(struct lcore_pair *lcp)
{
	unsigned id1, id2;
	unsigned c1, c2, s1, s2;
	RTE_LCORE_FOREACH(id1) {
		/* inner loop just re-reads all id's. We could skip the first few
		 * elements, but since number of cores is small there is little point
		 */
		RTE_LCORE_FOREACH(id2) {
			if (id1 == id2)
				continue;

			c1 = rte_lcore_to_cpu_id(id1);
			c2 = rte_lcore_to_cpu_id(id2);
			s1 = rte_lcore_to_socket_id(id1);
			s2 = rte_lcore_to_socket_id(id2);
			if ((c1 == c2) && (s1 == s2)){
				lcp->c1 = id1;
				lcp->c2 = id2;
				return 0;
			}
		}
	}
	return 1;
}

static int
get_two_cores(struct lcore_pair *lcp)
{
	unsigned id1, id2;
	unsigned c1, c2, s1, s2;
	RTE_LCORE_FOREACH(id1) {
		RTE_LCORE_FOREACH(id2) {
			if (id1 == id2)
				continue;

			c1 = rte_lcore_to_cpu_id(id1);
			c2 = rte_lcore_to_cpu_id(id2);
			s1 = rte_lcore_to_socket_id(id1);
			s2 = rte_lcore_to_socket_id(id2);
			if ((c1 != c2) && (s1 == s2)){
				lcp->c1 = id1;
				lcp->c2 = id2;
				return 0;
			}
		}
	}
	return 1;
}

static int
get_two_sockets(struct lcore_pair *lcp)
{
	unsigned id1, id2;
	unsigned s1, s2;
	RTE_LCORE_FOREACH(id1) {
		RTE_LCORE_FOREACH(id2) {
			if (id1 == id2)
				continue;
			s1 = rte_lcore_to_socket_id(id1);
			s2 = rte_lcore_to_socket_id(id2);
			if (s1 != s2){
				lcp->c1 = id1;
				lcp->c2 = id2;
				return 0;
			}
		}
	}
	return 1;
}

/* Get cycle counts for dequeuing from an empty ring. Should be 2 or 3 cycles */
static void
test_empty_dequeue(struct rte_ring *r, const int esize,
			const unsigned int api_type)
{
	int ret;
	const unsigned int iter_shift = 26;
	const unsigned int iterations = 1 << iter_shift;
	unsigned int i = 0;
	void *burst[MAX_BURST];

	(void)ret;
	const uint64_t start = rte_rdtsc();
	for (i = 0; i < iterations; i++)
		TEST_RING_DEQUEUE(r, burst, esize, bulk_sizes[0],
					ret, api_type);
	const uint64_t end = rte_rdtsc();

	test_ring_print_test_string(api_type, esize, bulk_sizes[0],
					((double)(end - start)) / iterations);
}

/*
 * for the separate enqueue and dequeue threads they take in one param
 * and return two. Input = burst size, output = cycle average for sp/sc & mp/mc
 */
struct thread_params {
	struct rte_ring *r;
	unsigned size;        /* input value, the burst size */
	double spsc, mpmc;    /* output value, the single or multi timings */
};

/*
 * Function that uses rdtsc to measure timing for ring enqueue. Needs pair
 * thread running dequeue_bulk function
 */
static int
enqueue_bulk(void *p)
{
	const unsigned iter_shift = 23;
	const unsigned iterations = 1<<iter_shift;
	struct thread_params *params = p;
	struct rte_ring *r = params->r;
	const unsigned size = params->size;
	unsigned i;
	void *burst[MAX_BURST] = {0};

#ifdef RTE_USE_C11_MEM_MODEL
	if (__atomic_add_fetch(&lcore_count, 1, __ATOMIC_RELAXED) != 2)
#else
	if (__sync_add_and_fetch(&lcore_count, 1) != 2)
#endif
		while(lcore_count != 2)
			rte_pause();

	const uint64_t sp_start = rte_rdtsc();
	for (i = 0; i < iterations; i++)
		while (rte_ring_sp_enqueue_bulk(r, burst, size, NULL) == 0)
			rte_pause();
	const uint64_t sp_end = rte_rdtsc();

	const uint64_t mp_start = rte_rdtsc();
	for (i = 0; i < iterations; i++)
		while (rte_ring_mp_enqueue_bulk(r, burst, size, NULL) == 0)
			rte_pause();
	const uint64_t mp_end = rte_rdtsc();

	params->spsc = ((double)(sp_end - sp_start))/(iterations*size);
	params->mpmc = ((double)(mp_end - mp_start))/(iterations*size);
	return 0;
}

/*
 * Function that uses rdtsc to measure timing for ring dequeue. Needs pair
 * thread running enqueue_bulk function
 */
static int
dequeue_bulk(void *p)
{
	const unsigned iter_shift = 23;
	const unsigned iterations = 1<<iter_shift;
	struct thread_params *params = p;
	struct rte_ring *r = params->r;
	const unsigned size = params->size;
	unsigned i;
	void *burst[MAX_BURST] = {0};

#ifdef RTE_USE_C11_MEM_MODEL
	if (__atomic_add_fetch(&lcore_count, 1, __ATOMIC_RELAXED) != 2)
#else
	if (__sync_add_and_fetch(&lcore_count, 1) != 2)
#endif
		while(lcore_count != 2)
			rte_pause();

	const uint64_t sc_start = rte_rdtsc();
	for (i = 0; i < iterations; i++)
		while (rte_ring_sc_dequeue_bulk(r, burst, size, NULL) == 0)
			rte_pause();
	const uint64_t sc_end = rte_rdtsc();

	const uint64_t mc_start = rte_rdtsc();
	for (i = 0; i < iterations; i++)
		while (rte_ring_mc_dequeue_bulk(r, burst, size, NULL) == 0)
			rte_pause();
	const uint64_t mc_end = rte_rdtsc();

	params->spsc = ((double)(sc_end - sc_start))/(iterations*size);
	params->mpmc = ((double)(mc_end - mc_start))/(iterations*size);
	return 0;
}

/*
 * Function that calls the enqueue and dequeue bulk functions on pairs of cores.
 * used to measure ring perf between hyperthreads, cores and sockets.
 */
static void
run_on_core_pair(struct lcore_pair *cores, struct rte_ring *r,
		lcore_function_t f1, lcore_function_t f2)
{
	struct thread_params param1 = {0}, param2 = {0};
	unsigned i;
	for (i = 0; i < sizeof(bulk_sizes)/sizeof(bulk_sizes[0]); i++) {
		lcore_count = 0;
		param1.size = param2.size = bulk_sizes[i];
		param1.r = param2.r = r;
		if (cores->c1 == rte_get_master_lcore()) {
			rte_eal_remote_launch(f2, &param2, cores->c2);
			f1(&param1);
			rte_eal_wait_lcore(cores->c2);
		} else {
			rte_eal_remote_launch(f1, &param1, cores->c1);
			rte_eal_remote_launch(f2, &param2, cores->c2);
			rte_eal_wait_lcore(cores->c1);
			rte_eal_wait_lcore(cores->c2);
		}
		printf("SP/SC bulk enq/dequeue (size: %u): %.2F\n", bulk_sizes[i],
				param1.spsc + param2.spsc);
		printf("MP/MC bulk enq/dequeue (size: %u): %.2F\n", bulk_sizes[i],
				param1.mpmc + param2.mpmc);
	}
}

static rte_atomic32_t synchro;
static uint64_t queue_count[RTE_MAX_LCORE];

#define TIME_MS 100

static int
load_loop_fn(void *p)
{
	uint64_t time_diff = 0;
	uint64_t begin = 0;
	uint64_t hz = rte_get_timer_hz();
	uint64_t lcount = 0;
	const unsigned int lcore = rte_lcore_id();
	struct thread_params *params = p;
	void *burst[MAX_BURST] = {0};

	/* wait synchro for slaves */
	if (lcore != rte_get_master_lcore())
		while (rte_atomic32_read(&synchro) == 0)
			rte_pause();

	begin = rte_get_timer_cycles();
	while (time_diff < hz * TIME_MS / 1000) {
		rte_ring_mp_enqueue_bulk(params->r, burst, params->size, NULL);
		rte_ring_mc_dequeue_bulk(params->r, burst, params->size, NULL);
		lcount++;
		time_diff = rte_get_timer_cycles() - begin;
	}
	queue_count[lcore] = lcount;
	return 0;
}

static int
run_on_all_cores(struct rte_ring *r)
{
	uint64_t total = 0;
	struct thread_params param;
	unsigned int i, c;

	memset(&param, 0, sizeof(struct thread_params));
	for (i = 0; i < RTE_DIM(bulk_sizes); i++) {
		printf("\nBulk enq/dequeue count on size %u\n", bulk_sizes[i]);
		param.size = bulk_sizes[i];
		param.r = r;

		/* clear synchro and start slaves */
		rte_atomic32_set(&synchro, 0);
		if (rte_eal_mp_remote_launch(load_loop_fn, &param,
			SKIP_MASTER) < 0)
			return -1;

		/* start synchro and launch test on master */
		rte_atomic32_set(&synchro, 1);
		load_loop_fn(&param);

		rte_eal_mp_wait_lcore();

		RTE_LCORE_FOREACH(c) {
			printf("Core [%u] count = %"PRIu64"\n",
					c, queue_count[c]);
			total += queue_count[c];
		}

		printf("Total count (size: %u): %"PRIu64"\n",
				bulk_sizes[i], total);
	}

	return 0;
}

/*
 * Test function that determines how long an enqueue + dequeue of a single item
 * takes on a single lcore. Result is for comparison with the bulk enq+deq.
 */
static int
test_single_enqueue_dequeue(struct rte_ring *r, const int esize,
	const unsigned int api_type)
{
	int ret;
	const unsigned int iter_shift = 24;
	const unsigned int iterations = 1 << iter_shift;
	unsigned int i = 0;
	void *burst = NULL;

	(void)ret;
	/* alloc dummy object pointers */
	burst = test_ring_calloc(1, esize);
	if (burst == NULL)
		return -1;

	const uint64_t start = rte_rdtsc();
	for (i = 0; i < iterations; i++) {
		TEST_RING_ENQUEUE(r, burst, esize, 1, ret, api_type);
		TEST_RING_DEQUEUE(r, burst, esize, 1, ret, api_type);
	}
	const uint64_t end = rte_rdtsc();

	test_ring_print_test_string(api_type, esize, 1,
					((double)(end - start)) / iterations);

	rte_free(burst);

	return 0;
}

/*
 * Test that does both enqueue and dequeue on a core using the burst/bulk API
 * calls Results should be the same as for the bulk function called on a
 * single lcore.
 */
static int
test_burst_bulk_enqueue_dequeue(struct rte_ring *r, const int esize,
	const unsigned int api_type)
{
	int ret;
	const unsigned int iter_shift = 23;
	const unsigned int iterations = 1 << iter_shift;
	unsigned int sz, i = 0;
	void **burst = NULL;

	(void)ret;
	burst = test_ring_calloc(MAX_BURST, esize);
	if (burst == NULL)
		return -1;

	for (sz = 0; sz < RTE_DIM(bulk_sizes); sz++) {
		const uint64_t start = rte_rdtsc();
		for (i = 0; i < iterations; i++) {
			TEST_RING_ENQUEUE(r, burst, esize, bulk_sizes[sz],
						ret, api_type);
			TEST_RING_DEQUEUE(r, burst, esize, bulk_sizes[sz],
						ret, api_type);
		}
		const uint64_t end = rte_rdtsc();

		test_ring_print_test_string(api_type, esize, bulk_sizes[sz],
					((double)(end - start)) / iterations);
	}

	return 0;
}

static int
test_ring_perf(void)
{
	struct lcore_pair cores;
	struct rte_ring *r = NULL;

	/*
	 * Performance test for legacy/_elem APIs
	 * SP-SC/MP-MC, single
	 */
	TEST_RING_CREATE(RING_NAME, -1, RING_SIZE, rte_socket_id(), 0, r);
	if (r == NULL)
		return -1;

	printf("\n### Testing single element enq/deq ###\n");
	if (test_single_enqueue_dequeue(r, -1, TEST_RING_S | TEST_RING_SL) < 0)
		return -1;
	if (test_single_enqueue_dequeue(r, -1, TEST_RING_M | TEST_RING_SL) < 0)
		return -1;
	printf("\n### Testing burst enq/deq ###\n");
	if (test_burst_bulk_enqueue_dequeue(r, -1,
			TEST_RING_S | TEST_RING_BR) < 0)
		return -1;
	if (test_burst_bulk_enqueue_dequeue(r, -1,
			TEST_RING_M | TEST_RING_BR) < 0)
		return -1;
	printf("\n### Testing bulk enq/deq ###\n");
	if (test_burst_bulk_enqueue_dequeue(r, -1,
			TEST_RING_S | TEST_RING_BL) < 0)
		return -1;
	if (test_burst_bulk_enqueue_dequeue(r, -1,
			TEST_RING_M | TEST_RING_BL) < 0)
		return -1;
	printf("\n### Testing empty bulk deq ###\n");
	test_empty_dequeue(r, -1, TEST_RING_S | TEST_RING_BL);
	test_empty_dequeue(r, -1, TEST_RING_M | TEST_RING_BL);
	rte_ring_free(r);

	TEST_RING_CREATE(RING_NAME, 16, RING_SIZE, rte_socket_id(), 0, r);
	if (r == NULL)
		return -1;

	printf("\n### Testing single element enq/deq ###\n");
	if (test_single_enqueue_dequeue(r, 16, TEST_RING_S | TEST_RING_SL) < 0)
		return -1;
	if (test_single_enqueue_dequeue(r, 16, TEST_RING_M | TEST_RING_SL) < 0)
		return -1;
	printf("\n### Testing burst enq/deq ###\n");
	if (test_burst_bulk_enqueue_dequeue(r, 16,
			TEST_RING_S | TEST_RING_BR) < 0)
		return -1;
	if (test_burst_bulk_enqueue_dequeue(r, 16,
			TEST_RING_M | TEST_RING_BR) < 0)
		return -1;
	printf("\n### Testing bulk enq/deq ###\n");
	if (test_burst_bulk_enqueue_dequeue(r, 16,
			TEST_RING_S | TEST_RING_BL) < 0)
		return -1;
	if (test_burst_bulk_enqueue_dequeue(r, 16,
			TEST_RING_M | TEST_RING_BL) < 0)
		return -1;
	printf("\n### Testing empty bulk deq ###\n");
	test_empty_dequeue(r, 16, TEST_RING_S | TEST_RING_BL);
	test_empty_dequeue(r, 16, TEST_RING_M | TEST_RING_BL);
	rte_ring_free(r);

	r = rte_ring_create(RING_NAME, RING_SIZE, rte_socket_id(), 0);
	if (r == NULL)
		return -1;

	if (get_two_hyperthreads(&cores) == 0) {
		printf("\n### Testing using two hyperthreads ###\n");
		run_on_core_pair(&cores, r, enqueue_bulk, dequeue_bulk);
	}
	if (get_two_cores(&cores) == 0) {
		printf("\n### Testing using two physical cores ###\n");
		run_on_core_pair(&cores, r, enqueue_bulk, dequeue_bulk);
	}
	if (get_two_sockets(&cores) == 0) {
		printf("\n### Testing using two NUMA nodes ###\n");
		run_on_core_pair(&cores, r, enqueue_bulk, dequeue_bulk);
	}

	printf("\n### Testing using all slave nodes ###\n");
	run_on_all_cores(r);

	rte_ring_free(r);
	return 0;
}

REGISTER_TEST_COMMAND(ring_perf_autotest, test_ring_perf);
