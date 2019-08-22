/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2019 Intel Corporation
 *
 * LPM Autotests from DPDK v2.2.0 for v2.0 abi compability testing.
 *
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/queue.h>

#include <rte_common.h>
#include <rte_cycles.h>
#include <rte_memory.h>
#include <rte_random.h>
#include <rte_branch_prediction.h>
#include <rte_ip.h>
#include <time.h>

#include "../test.h"

/* remapping of DPDK v2.0 symbols */
#include "dcompat.h"
/* backported header from DPDK v2.0 */
#include "rte_lpm.h"
#include "../test_lpm_routes.h"

#define TEST_LPM_ASSERT(cond) do {              \
    if (!(cond)) {                              \
      printf("Error at line %d:\n", __LINE__);  \
      return -1;                                \
    }                                           \
  } while (0)


#define PASS 0

/*
 * Lookup performance test
 */

#define ITERATIONS (1 << 10)
#define BATCH_SIZE (1 << 12)
#define BULK_SIZE 32

static int32_t test_lpm_perf(void);

int32_t
test_lpm_perf(void)
{
	struct rte_lpm *lpm = NULL;
	uint64_t begin, total_time, lpm_used_entries = 0;
	unsigned i, j;
	uint8_t next_hop_add = 0xAA, next_hop_return = 0;
	int status = 0;
	uint64_t cache_line_counter = 0;
	int64_t count = 0;

	rte_srand(rte_rdtsc());

	/* (re) generate the routing table */
	generate_large_route_rule_table();

	printf("No. routes = %u\n", (unsigned) NUM_ROUTE_ENTRIES);

	print_route_distribution(large_route_table,
				 (uint32_t) NUM_ROUTE_ENTRIES);

	lpm = rte_lpm_create(__func__, SOCKET_ID_ANY, 1000000, 0);
	TEST_LPM_ASSERT(lpm != NULL);

	/* Measue add. */
	begin = rte_rdtsc();

	for (i = 0; i < NUM_ROUTE_ENTRIES; i++) {
		if (rte_lpm_add(lpm, large_route_table[i].ip,
				large_route_table[i].depth, next_hop_add) == 0)
			status++;
	}
	/* End Timer. */
	total_time = rte_rdtsc() - begin;

	printf("Unique added entries = %d\n", status);
	/* Obtain add statistics. */
	for (i = 0; i < RTE_LPM_TBL24_NUM_ENTRIES; i++) {
		if (lpm->tbl24[i].valid)
			lpm_used_entries++;

		if (i % 32 == 0){
			if ((uint64_t)count < lpm_used_entries) {
				cache_line_counter++;
				count = lpm_used_entries;
			}
		}
	}

	printf("Used table 24 entries = %u (%g%%)\n",
			(unsigned) lpm_used_entries,
			(lpm_used_entries * 100.0) / RTE_LPM_TBL24_NUM_ENTRIES);
	printf("64 byte Cache entries used = %u (%u bytes)\n",
			(unsigned) cache_line_counter, (unsigned) cache_line_counter * 64);

	printf("Average LPM Add: %g cycles\n", (double)total_time / NUM_ROUTE_ENTRIES);

	/* Measure single Lookup */
	total_time = 0;
	count = 0;

	for (i = 0; i < ITERATIONS; i++) {
		static uint32_t ip_batch[BATCH_SIZE];

		for (j = 0; j < BATCH_SIZE; j++)
			ip_batch[j] = rte_rand();

		/* Lookup per batch */
		begin = rte_rdtsc();

		for (j = 0; j < BATCH_SIZE; j++) {
			if (rte_lpm_lookup(lpm, ip_batch[j], &next_hop_return) != 0)
				count++;
		}

		total_time += rte_rdtsc() - begin;

	}
	printf("Average LPM Lookup: %.1f cycles (fails = %.1f%%)\n",
			(double)total_time / ((double)ITERATIONS * BATCH_SIZE),
			(count * 100.0) / (double)(ITERATIONS * BATCH_SIZE));

	/* Measure bulk Lookup */
	total_time = 0;
	count = 0;
	for (i = 0; i < ITERATIONS; i++) {
		static uint32_t ip_batch[BATCH_SIZE];
		uint16_t next_hops[BULK_SIZE];

		/* Create array of random IP addresses */
		for (j = 0; j < BATCH_SIZE; j++)
			ip_batch[j] = rte_rand();

		/* Lookup per batch */
		begin = rte_rdtsc();
		for (j = 0; j < BATCH_SIZE; j += BULK_SIZE) {
			unsigned k;
			rte_lpm_lookup_bulk(lpm, &ip_batch[j], next_hops, BULK_SIZE);
			for (k = 0; k < BULK_SIZE; k++)
				if (unlikely(!(next_hops[k] & RTE_LPM_LOOKUP_SUCCESS)))
					count++;
		}

		total_time += rte_rdtsc() - begin;
	}
	printf("BULK LPM Lookup: %.1f cycles (fails = %.1f%%)\n",
			(double)total_time / ((double)ITERATIONS * BATCH_SIZE),
			(count * 100.0) / (double)(ITERATIONS * BATCH_SIZE));

	/* Measure LookupX4 */
	total_time = 0;
	count = 0;
	for (i = 0; i < ITERATIONS; i++) {
		static uint32_t ip_batch[BATCH_SIZE];
		uint16_t next_hops[4];

		/* Create array of random IP addresses */
		for (j = 0; j < BATCH_SIZE; j++)
			ip_batch[j] = rte_rand();

		/* Lookup per batch */
		begin = rte_rdtsc();
		for (j = 0; j < BATCH_SIZE; j += RTE_DIM(next_hops)) {
			unsigned k;
			__m128i ipx4;

			ipx4 = _mm_loadu_si128((__m128i *)(ip_batch + j));
			ipx4 = *(__m128i *)(ip_batch + j);
			rte_lpm_lookupx4(lpm, ipx4, next_hops, UINT16_MAX);
			for (k = 0; k < RTE_DIM(next_hops); k++)
				if (unlikely(next_hops[k] == UINT16_MAX))
					count++;
		}

		total_time += rte_rdtsc() - begin;
	}
	printf("LPM LookupX4: %.1f cycles (fails = %.1f%%)\n",
			(double)total_time / ((double)ITERATIONS * BATCH_SIZE),
			(count * 100.0) / (double)(ITERATIONS * BATCH_SIZE));

	/* Delete */
	status = 0;
	begin = rte_rdtsc();

	for (i = 0; i < NUM_ROUTE_ENTRIES; i++) {
		/* rte_lpm_delete(lpm, ip, depth) */
		status += rte_lpm_delete(lpm, large_route_table[i].ip,
				large_route_table[i].depth);
	}

	total_time += rte_rdtsc() - begin;

	printf("Average LPM Delete: %g cycles\n",
			(double)total_time / NUM_ROUTE_ENTRIES);

	rte_lpm_delete_all(lpm);
	rte_lpm_free(lpm);

	return PASS;
}

REGISTER_TEST_COMMAND_VERSION(lpm_perf_autotest,
			      test_lpm_perf, TEST_DPDK_ABI_VERSION_V20);
