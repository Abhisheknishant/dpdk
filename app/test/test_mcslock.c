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
 * RTE MCS lock test
 * =================
 *
 * These tests are derived from spin lock test cases.
 *
 * - The functional test takes all of these locks and launches the
 *   ''test_mcslock_per_core()'' function on each core (except the master).
 *
 *   - The function takes the global lock, display something, then releases
 *     the global lock on each core.
 */

RTE_DEFINE_PER_LCORE(rte_mcslock_t, _ml_me);
RTE_DEFINE_PER_LCORE(rte_mcslock_t, _ml_try_me);

rte_mcslock_t *p_ml;
rte_mcslock_t *p_ml_try;

static unsigned int count;

static int
test_mcslock_per_core(__attribute__((unused)) void *arg)
{
	/* Per core me node. */
	rte_mcslock_t ml_me = RTE_PER_LCORE(_ml_me);

	rte_mcslock_lock(&p_ml, &ml_me);
	printf("MCS lock taken on core %u\n", rte_lcore_id());
	rte_mcslock_unlock(&p_ml, &ml_me);
	printf("MCS lock released on core %u\n", rte_lcore_id());

	return 0;
}

#define MAX_LOOP 1000000

/*
 * Use rte_mcslock_trylock() to trylock a mcs lock object,
 * If it could not lock the object successfully, it would
 * return immediately.
 */
static int
test_mcslock_try(__attribute__((unused)) void *arg)
{
	/**< Per core me node. */
	rte_mcslock_t ml_me     = RTE_PER_LCORE(_ml_me);
	rte_mcslock_t ml_try_me = RTE_PER_LCORE(_ml_try_me);

	/* Locked ml_try in the master lcore, so it should fail
	 * when trying to lock it in the slave lcore.
	 */
	if (rte_mcslock_trylock(&p_ml_try, &ml_try_me) == 0) {
		rte_mcslock_lock(&p_ml, &ml_me);
		count++;
		rte_mcslock_unlock(&p_ml, &ml_me);
	}

	return 0;
}


/*
 * Test rte_eal_get_lcore_state() in addition to mcs locks
 * as we have "waiting" then "running" lcores.
 */
static int
test_mcslock(void)
{
	int ret = 0;
	int i;

	/* Define per core me node. */
	rte_mcslock_t ml_me     = RTE_PER_LCORE(_ml_me);
	rte_mcslock_t ml_try_me = RTE_PER_LCORE(_ml_try_me);

	/*
	 * Test mcs lock & unlock on each core
	 */

	/* slave cores should be waiting: print it */
	RTE_LCORE_FOREACH_SLAVE(i) {
		printf("lcore %d state: %d\n", i,
				(int) rte_eal_get_lcore_state(i));
	}

	rte_mcslock_lock(&p_ml, &ml_me);

	RTE_LCORE_FOREACH_SLAVE(i) {
		rte_eal_remote_launch(test_mcslock_per_core, NULL, i);
	}

	/* slave cores should be busy: print it */
	RTE_LCORE_FOREACH_SLAVE(i) {
		printf("lcore %d state: %d\n", i,
				(int) rte_eal_get_lcore_state(i));
	}

	rte_mcslock_unlock(&p_ml, &ml_me);

	rte_eal_mp_wait_lcore();

	/*
	 * Test if it could return immediately from try-locking a locked object.
	 * Here it will lock the mcs lock object first, then launch all the
	 * slave lcores to trylock the same mcs lock object.
	 * All the slave lcores should give up try-locking a locked object and
	 * return immediately, and then increase the "count" initialized with
	 * zero by one per times.
	 * We can check if the "count" is finally equal to the number of all
	 * slave lcores to see if the behavior of try-locking a locked
	 * mcslock object is correct.
	 */
	if (rte_mcslock_trylock(&p_ml_try, &ml_try_me) == 0)
		return -1;

	count = 0;
	RTE_LCORE_FOREACH_SLAVE(i) {
		rte_eal_remote_launch(test_mcslock_try, NULL, i);
	}
	rte_eal_mp_wait_lcore();
	rte_mcslock_unlock(&p_ml_try, &ml_try_me);

	/* Test is_locked API */
	if (rte_mcslock_is_locked(p_ml)) {
		printf("mcslock is locked but it should not be\n");
		return -1;
	}

	/* Counting the locked times in each core */
	rte_mcslock_lock(&p_ml, &ml_me);
	if (count != (rte_lcore_count() - 1))
		ret = -1;
	rte_mcslock_unlock(&p_ml, &ml_me);

	return ret;
}

REGISTER_TEST_COMMAND(mcslock_autotest, test_mcslock);
