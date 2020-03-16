/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2020 Intel Corporation
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

#include <rte_lcore.h>
#include <rte_dwk_hash.h>
#include <rte_hash_crc.h>

#include "test.h"

typedef int32_t (*rte_dwk_hash_test)(void);

static int32_t test_create_invalid(void);
static int32_t test_multiple_create(void);
static int32_t test_free_null(void);
static int32_t test_add_del_invalid(void);
static int32_t test_basic(void);

#define MAX_ENT (1 << 22)

/*
 * Check that rte_dwk_hash_create fails gracefully for incorrect user input
 * arguments
 */
int32_t
test_create_invalid(void)
{
	struct rte_dwk_hash_table *dwk_hash = NULL;
	struct rte_dwk_hash_params config;

	/* rte_dwk_hash_create: dwk_hash name == NULL */
	config.name = NULL;
	dwk_hash = rte_dwk_hash_create(&config);
	RTE_TEST_ASSERT(dwk_hash == NULL,
		"Call succeeded with invalid parameters\n");
	config.name = "test_dwk_hash";

	/* rte_dwk_hash_create: config == NULL */
	dwk_hash = rte_dwk_hash_create(NULL);
	RTE_TEST_ASSERT(dwk_hash == NULL,
		"Call succeeded with invalid parameters\n");

	/* socket_id < -1 is invalid */
	config.socket_id = -2;
	dwk_hash = rte_dwk_hash_create(&config);
	RTE_TEST_ASSERT(dwk_hash == NULL,
		"Call succeeded with invalid parameters\n");
	config.socket_id = rte_socket_id();

	/* rte_dwk_hash_create: entries = 0 */
	config.entries = 0;
	dwk_hash = rte_dwk_hash_create(&config);
	RTE_TEST_ASSERT(dwk_hash == NULL,
		"Call succeeded with invalid parameters\n");
	config.entries = MAX_ENT;

	return TEST_SUCCESS;
}

/*
 * Create dwk_hash table then delete dwk_hash table 10 times
 * Use a slightly different rules size each time
 */
#include <rte_errno.h>
int32_t
test_multiple_create(void)
{
	struct rte_dwk_hash_table *dwk_hash = NULL;
	struct rte_dwk_hash_params config;
	int32_t i;


	for (i = 0; i < 100; i++) {
		config.name = "test_dwk_hash";
		config.socket_id = -1;
		config.entries = MAX_ENT - i;

		dwk_hash = rte_dwk_hash_create(&config);
		RTE_TEST_ASSERT(dwk_hash != NULL,
			"Failed to create dwk hash\n");
		rte_dwk_hash_free(dwk_hash);
	}

	return TEST_SUCCESS;
}

/*
 * Call rte_dwk_hash_free for NULL pointer user input.
 * Note: free has no return and therefore it is impossible
 * to check for failure but this test is added to
 * increase function coverage metrics and to validate that
 * freeing null does not crash.
 */
int32_t
test_free_null(void)
{
	struct rte_dwk_hash_table *dwk_hash = NULL;
	struct rte_dwk_hash_params config;

	config.name = "test_dwk";
	config.socket_id = -1;
	config.entries = MAX_ENT;

	dwk_hash = rte_dwk_hash_create(&config);
	RTE_TEST_ASSERT(dwk_hash != NULL, "Failed to create dwk hash\n");

	rte_dwk_hash_free(dwk_hash);
	rte_dwk_hash_free(NULL);
	return TEST_SUCCESS;
}

/*
 * Check that rte_dwk_hash_add fails gracefully for
 * incorrect user input arguments
 */
int32_t
test_add_del_invalid(void)
{
	uint32_t key = 10;
	uint64_t val = 20;
	int ret;

	/* rte_dwk_hash_add: dwk_hash == NULL */
	ret = rte_dwk_hash_add(NULL, key, rte_hash_crc_4byte(key, 0), val);
	RTE_TEST_ASSERT(ret == -EINVAL,
		"Call succeeded with invalid parameters\n");

	/* rte_dwk_hash_delete: dwk_hash == NULL */
	ret = rte_dwk_hash_delete(NULL, key, rte_hash_crc_4byte(key, 0));
	RTE_TEST_ASSERT(ret == -EINVAL,
		"Call succeeded with invalid parameters\n");

	return TEST_SUCCESS;
}

/*
 * Call add, lookup and delete for a single rule
 */
int32_t
test_basic(void)
{
	struct rte_dwk_hash_table *dwk_hash = NULL;
	struct rte_dwk_hash_params config;
	uint32_t key = 10;
	uint64_t value = 20;
	uint64_t ret_val = 0;
	int ret;

	config.name = "test_dwk";
	config.socket_id = -1;
	config.entries = MAX_ENT;

	dwk_hash = rte_dwk_hash_create(&config);
	RTE_TEST_ASSERT(dwk_hash != NULL, "Failed to create dwk hash\n");

	ret = rte_dwk_hash_lookup(dwk_hash, key,
		rte_hash_crc_4byte(key, 0), &ret_val);
	RTE_TEST_ASSERT(ret == -ENOENT, "Lookup return incorrect result\n");

	ret = rte_dwk_hash_delete(dwk_hash, key,
		rte_hash_crc_4byte(key, 0));
	RTE_TEST_ASSERT(ret == -ENOENT, "Delete return incorrect result\n");

	ret = rte_dwk_hash_add(dwk_hash, key,
		rte_hash_crc_4byte(key, 0), value);
	RTE_TEST_ASSERT(ret == 0, "Can not add key into the table\n");

	ret = rte_dwk_hash_lookup(dwk_hash, key,
		rte_hash_crc_4byte(key, 0), &ret_val);
	RTE_TEST_ASSERT(((ret == 0) && (value == ret_val)),
		"Lookup return incorrect result\n");

	ret = rte_dwk_hash_delete(dwk_hash, key,
		rte_hash_crc_4byte(key, 0));
	RTE_TEST_ASSERT(ret == 0, "Can not delete key from table\n");

	ret = rte_dwk_hash_lookup(dwk_hash, key,
		rte_hash_crc_4byte(key, 0), &ret_val);
	RTE_TEST_ASSERT(ret == -ENOENT, "Lookup return incorrect result\n");

	rte_dwk_hash_free(dwk_hash);

	return TEST_SUCCESS;
}

static struct unit_test_suite dwk_hash_tests = {
	.suite_name = "dwk_hash autotest",
	.setup = NULL,
	.teardown = NULL,
	.unit_test_cases = {
		TEST_CASE(test_create_invalid),
		TEST_CASE(test_free_null),
		TEST_CASE(test_add_del_invalid),
		TEST_CASE(test_basic),
		TEST_CASES_END()
	}
};

static struct unit_test_suite dwk_hash_slow_tests = {
	.suite_name = "dwk_hash slow autotest",
	.setup = NULL,
	.teardown = NULL,
	.unit_test_cases = {
		TEST_CASE(test_multiple_create),
		TEST_CASES_END()
	}
};

/*
 * Do all unit tests.
 */
static int
test_dwk_hash(void)
{
	return unit_test_suite_runner(&dwk_hash_tests);
}

static int
test_slow_dwk_hash(void)
{
	return unit_test_suite_runner(&dwk_hash_slow_tests);
}

REGISTER_TEST_COMMAND(dwk_hash_autotest, test_dwk_hash);
REGISTER_TEST_COMMAND(dwk_hash_slow_autotest, test_slow_dwk_hash);
