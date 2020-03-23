/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Arm Limited
 */

#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <string.h>
#include <unistd.h>
#include <sys/queue.h>

#include <rte_common.h>
#include <rte_memory.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_lcore.h>
#include <rte_cycles.h>
#include <rte_mcslock.h>
#include <rte_atomic.h>

#include "test.h"

/*
 * RTE MCS lock perf test
 * ======================
 *
 * These tests are derived from spin lock perf test cases.
 *
 * - A load test is carried out, with all cores attempting to lock a single
 *   lock multiple times.
 */

RTE_DEFINE_PER_LCORE(rte_mcslock_t, _ml_perf_me);
rte_mcslock_t *p_ml_perf;

static rte_atomic32_t synchro;
static uint64_t time_count[RTE_MAX_LCORE] = {0};

#define MAX_LOOP 1000000

static int
load_loop_fn(void *func_param)
{
	uint64_t time_diff = 0, begin;
	uint64_t hz = rte_get_timer_hz();
	volatile uint64_t lcount = 0;
	const int use_lock = *(int *)func_param;
	const unsigned int lcore = rte_lcore_id();

	/**< Per core me node. */
	rte_mcslock_t ml_perf_me = RTE_PER_LCORE(_ml_perf_me);

	/* wait synchro */
	while (rte_atomic32_read(&synchro) == 0)
		;

	begin = rte_get_timer_cycles();
	while (lcount < MAX_LOOP) {
		if (use_lock)
			rte_mcslock_lock(&p_ml_perf, &ml_perf_me);

		lcount++;
		if (use_lock)
			rte_mcslock_unlock(&p_ml_perf, &ml_perf_me);
	}
	time_diff = rte_get_timer_cycles() - begin;
	time_count[lcore] = time_diff * 1000000 / hz;
	return 0;
}

/*
 * Test rte_eal_get_lcore_state() in addition to mcs locks
 * as we have "waiting" then "running" lcores.
 */
static int
test_mcslock_perf(void)
{
	unsigned int i;
	uint64_t total = 0;
	int lock = 0;
	const unsigned int lcore = rte_lcore_id();

	printf("\nTest with no lock on single core...\n");
	rte_atomic32_set(&synchro, 1);
	load_loop_fn(&lock);
	printf("Core [%u] Cost Time = %"PRIu64" us\n",
			lcore, time_count[lcore]);
	memset(time_count, 0, sizeof(time_count));

	printf("\nTest with lock on single core...\n");
	lock = 1;
	rte_atomic32_set(&synchro, 1);
	load_loop_fn(&lock);
	printf("Core [%u] Cost Time = %"PRIu64" us\n",
			lcore, time_count[lcore]);
	memset(time_count, 0, sizeof(time_count));

	printf("\nTest with lock on %u cores...\n", (rte_lcore_count()));

	rte_atomic32_set(&synchro, 0);
	rte_eal_mp_remote_launch(load_loop_fn, &lock, SKIP_MASTER);

	/* start synchro and launch test on master */
	rte_atomic32_set(&synchro, 1);
	load_loop_fn(&lock);

	rte_eal_mp_wait_lcore();

	RTE_LCORE_FOREACH(i) {
		printf("Core [%u] Cost Time = %"PRIu64" us\n",
				i, time_count[i]);
		total += time_count[i];
	}

	printf("Total Cost Time = %"PRIu64" us\n", total);

	return 0;
}

REGISTER_TEST_COMMAND(mcslock_perf_autotest, test_mcslock_perf);
