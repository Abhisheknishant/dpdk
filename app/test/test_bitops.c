/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Arm Limited
 */

#include <rte_bitops.h>
#include <rte_launch.h>
#include "test.h"

uint32_t val32;
uint64_t val64;
unsigned int synchro;
unsigned int count32;
unsigned int count64;

#define MAX_BITS_32 32
#define MAX_BITS_64 64
/*
 * Bitops functions
 * ================
 *
 * - The main test function performs several subtests.
 * - For relaxed version, check bit operations on one core.
 *   - Initialize valXX to specified values, then set each bit of valXX
 *     to 1 one by one in "test_bitops_set_relaxed".
 *
 *   - Clear each bit of valXX to 0 one by one in "test_bitops_clear_relaxed".
 *
 *   - Function "test_bitops_test_set_clear_relaxed" checks whether each bit
 *     of valXX can do "test and set" and "test and clear" correctly.
 *
 * - For C11 atomic barrier version, check bit operations on multi cores.
 *   - Per bit of valXX is set to 1, then cleared to 0 on each core in
 *     "test_bitops_set_clear". The function checks that once all lcores finish
 *     their set_clear, the value of valXX would still be zero.
 *
 *   - The cores are waiting for a synchro which is triggered by the main test
 *     function. Then all cores would do "rte_test_and_set_bitXX" or
 *     "rte_test_and_clear_bitXX" at the same time, "countXX" which is checked
 *     as the result later would inc by one or not according to the original
 *     bit value.
 *
 */

static int
test_bitops_set_relaxed(void)
{
	unsigned int i;

	for (i = 0; i < MAX_BITS_32; i++)
		rte_set_bit32_relaxed(i, &val32);

	for (i = 0; i < MAX_BITS_32; i++)
		if (!rte_get_bit32_relaxed(i, &val32)) {
			printf("Failed to set bit in relaxed version.\n");
			return TEST_FAILED;
		}

	for (i = 0; i < MAX_BITS_64; i++)
		rte_set_bit64_relaxed(i, &val64);

	for (i = 0; i < MAX_BITS_64; i++)
		if (!rte_get_bit64_relaxed(i, &val64)) {
			printf("Failed to set bit in relaxed version.\n");
			return TEST_FAILED;
		}

	return TEST_SUCCESS;
}

static int
test_bitops_clear_relaxed(void)
{
	unsigned int i;

	for (i = 0; i < MAX_BITS_32; i++)
		rte_clear_bit32_relaxed(i, &val32);

	for (i = 0; i < MAX_BITS_32; i++)
		if (rte_get_bit32_relaxed(i, &val32)) {
			printf("Failed to clear bit in relaxed version.\n");
			return TEST_FAILED;
		}

	for (i = 0; i < MAX_BITS_64; i++)
		rte_clear_bit64_relaxed(i, &val64);

	for (i = 0; i < MAX_BITS_64; i++)
		if (rte_get_bit64_relaxed(i, &val64)) {
			printf("Failed to clear bit in relaxed version.\n");
			return TEST_FAILED;
		}

	return TEST_SUCCESS;
}

static int
test_bitops_test_set_clear_relaxed(void)
{
	unsigned int i;

	for (i = 0; i < MAX_BITS_32; i++)
		rte_test_and_set_bit32_relaxed(i, &val32);

	for (i = 0; i < MAX_BITS_32; i++)
		if (!rte_test_and_clear_bit32_relaxed(i, &val32)) {
			printf("Failed to set and test bit in relaxed version.\n");
			return TEST_FAILED;
	}

	for (i = 0; i < MAX_BITS_32; i++)
		if (rte_get_bit32_relaxed(i, &val32)) {
			printf("Failed to test and clear bit in relaxed version.\n");
			return TEST_FAILED;
		}

	for (i = 0; i < MAX_BITS_64; i++)
		rte_test_and_set_bit64_relaxed(i, &val64);

	for (i = 0; i < MAX_BITS_64; i++)
		if (!rte_test_and_clear_bit64_relaxed(i, &val64)) {
			printf("Failed to set and test bit in relaxed version.\n");
			return TEST_FAILED;
		}

	for (i = 0; i < MAX_BITS_64; i++)
		if (rte_get_bit64_relaxed(i, &val64)) {
			printf("Failed to test and clear bit in relaxed version.\n");
			return TEST_FAILED;
		}

	return TEST_SUCCESS;
}

static int
test_bitops_set_clear(__attribute__((unused)) void *arg)
{
	while (__atomic_load_n(&synchro, __ATOMIC_RELAXED) == 0)
		;

	unsigned int i;

	for (i = 0; i < MAX_BITS_32; i++)
		rte_set_bit32(i, &val32);
	for (i = 0; i < MAX_BITS_32; i++)
		rte_clear_bit32(i, &val32);

	for (i = 0; i < MAX_BITS_64; i++)
		rte_set_bit64(i, &val64);
	for (i = 0; i < MAX_BITS_64; i++)
		rte_clear_bit64(i, &val64);

	return TEST_SUCCESS;
}

/*
 * rte_test_and_set_bitXX() returns the original bit value, then set it to 1.
 * This functions checks that if the target bit is equal to 0, set it to 1 and
 * increase the variable of "countXX" by one. If it is equal to 1, do nothing
 * for "countXX". The value of "countXX" would be checked as the result later.
 */
static int
test_bitops_test_set(__attribute__((unused)) void *arg)

{
	while (__atomic_load_n(&synchro, __ATOMIC_RELAXED) == 0)
		;

	unsigned int i;

	for (i = 0; i < MAX_BITS_32; i++)
		if (!rte_test_and_set_bit32(i, &val32))
			__atomic_fetch_add(&count32, 1, __ATOMIC_ACQ_REL);

	for (i = 0; i < MAX_BITS_64; i++)
		if (!rte_test_and_set_bit64(i, &val64))
			__atomic_fetch_add(&count64, 1, __ATOMIC_ACQ_REL);

	return TEST_SUCCESS;
}

/*
 * rte_test_and_set_bitXX() returns the original bit value, then clear it to 0.
 * This functions checks that if the target bit is equal to 1, clear it to 0 and
 * increase the variable of "countXX" by one. If it is equal to 0, do nothing
 * for "countXX". The value of "countXX" would be checked as the result later.
 */
static int
test_bitops_test_clear(__attribute__((unused)) void *arg)

{
	while (__atomic_load_n(&synchro, __ATOMIC_RELAXED) == 0)
		;

	unsigned int i;

	for (i = 0; i < MAX_BITS_32; i++)
		if (rte_test_and_clear_bit32(i, &val32))
			__atomic_fetch_add(&count32, 1, __ATOMIC_ACQ_REL);

	for (i = 0; i < MAX_BITS_64; i++)
		if (rte_test_and_clear_bit64(i, &val64))
			__atomic_fetch_add(&count64, 1, __ATOMIC_ACQ_REL);

	return TEST_SUCCESS;
}

static int
test_bitops(void)
{
	__atomic_store_n(&val32, 0, __ATOMIC_RELAXED);
	__atomic_store_n(&val64, 0, __ATOMIC_RELAXED);
	__atomic_store_n(&synchro, 0,  __ATOMIC_RELAXED);
	__atomic_store_n(&count32, 0, __ATOMIC_RELAXED);
	__atomic_store_n(&count64, 0, __ATOMIC_RELAXED);

	if (test_bitops_set_relaxed() < 0)
		return TEST_FAILED;

	if (test_bitops_clear_relaxed() < 0)
		return TEST_FAILED;

	if (test_bitops_test_set_clear_relaxed() < 0)
		return TEST_FAILED;


	rte_eal_mp_remote_launch(test_bitops_set_clear, NULL, SKIP_MASTER);
	__atomic_store_n(&synchro, 1,  __ATOMIC_RELAXED);
	rte_eal_mp_wait_lcore();
	__atomic_store_n(&synchro, 0, __ATOMIC_RELAXED);

	unsigned int i;

	for (i = 0; i < MAX_BITS_32; i++)
		if (rte_get_bit32(i, &val32)) {
			printf("Failed to set and clear bit on multi cores.\n");
			return TEST_FAILED;
		}

	for (i = 0; i < MAX_BITS_64; i++)
		if (rte_get_bit64(i, &val64)) {
			printf("Failed to set and clear bit on multi cores.\n");
			return TEST_FAILED;
		}

	/*
	 * Launch all slave lcores to do "rte_bitops_test_and_set_bitXX"
	 * respectively.
	 * Each lcore should have MAX_BITS_XX chances to check the target bit.
	 * If it's equal to 0, set it to 1 and "countXX (which is initialized
	 * to 0)" would be increased by one. If the target bit is 1, still set
	 * it to 1 and do nothing for "countXX". There would be only one lcore
	 * that finds the target bit is 0.
	 * If the final value of "countXX" is equal to MAX_BITS_XX, all slave
	 * lcores performed "rte_bitops_test_and_set_bitXX" correctly.
	 */
	__atomic_store_n(&count32, 0, __ATOMIC_RELAXED);
	__atomic_store_n(&count64, 0, __ATOMIC_RELAXED);

	rte_eal_mp_remote_launch(test_bitops_test_set, NULL, SKIP_MASTER);
	__atomic_store_n(&synchro, 1,  __ATOMIC_RELAXED);
	rte_eal_mp_wait_lcore();
	__atomic_store_n(&synchro, 0, __ATOMIC_RELAXED);

	if (__atomic_load_n(&count32, __ATOMIC_RELAXED) != MAX_BITS_32) {
		printf("Failed to test and set on multi cores.\n");
		return TEST_FAILED;
	}
	if (__atomic_load_n(&count64, __ATOMIC_RELAXED) != MAX_BITS_64) {
		printf("Failed to test and set on multi cores.\n");
		return TEST_FAILED;
	}

	/*
	 * Launch all slave lcores to do "rte_bitops_test_and_clear_bitXX"
	 * respectively.
	 * Each lcore should have MAX_BITS_XX chances to check the target bit.
	 * If it's equal to 1, clear it to 0 and "countXX (which is initialized
	 * to 0)" would be increased by one. If the target bit is 0, still clear
	 * it to 0 and do nothing for "countXX". There would be only one lcore
	 * that finds the target bit is 1.
	 * If the final value of "countXX" is equal to MAX_BITS_XX, all slave
	 * lcores performed "rte_bitops_test_and_clear_bitXX" correctly.
	 */

	__atomic_store_n(&count32, 0, __ATOMIC_RELAXED);
	__atomic_store_n(&count64, 0, __ATOMIC_RELAXED);

	rte_eal_mp_remote_launch(test_bitops_test_clear, NULL, SKIP_MASTER);
	__atomic_store_n(&synchro, 1,  __ATOMIC_RELAXED);
	rte_eal_mp_wait_lcore();
	__atomic_store_n(&synchro, 0, __ATOMIC_RELAXED);

	if (__atomic_load_n(&count32, __ATOMIC_RELAXED) != MAX_BITS_32) {
		printf("Failed to test and clear on multi cores.\n");
		return TEST_FAILED;
	}
	if (__atomic_load_n(&count64, __ATOMIC_RELAXED) != MAX_BITS_64) {
		printf("Failed to test and clear on multi cores.\n");
		return TEST_FAILED;
	}

	return TEST_SUCCESS;
}

REGISTER_TEST_COMMAND(bitops_autotest, test_bitops);
