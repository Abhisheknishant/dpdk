/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Arm Limited
 */

#include <rte_launch.h>
#include <rte_bitops.h>
#include "test.h"

uint32_t val32;
uint64_t val64;

#define MAX_BITS_32 32
#define MAX_BITS_64 64
/*
 * Bitops functions
 * ================
 *
 * - The main test function performs several subtests.
 * - Check bit operations on one core.
 *   - Initialize valXX to specified values, then set each bit of valXX
 *     to 1 one by one in "test_bitops_set_relaxed".
 *
 *   - Clear each bit of valXX to 0 one by one in "test_bitops_clear_relaxed".
 *
 *   - Function "test_bitops_test_set_clear_relaxed" checks whether each bit
 *     of valXX can do "test and set" and "test and clear" correctly.
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
test_bitops(void)
{
	val32 = 0;
	val64 = 0;

	if (test_bitops_set_relaxed() < 0)
		return TEST_FAILED;

	if (test_bitops_clear_relaxed() < 0)
		return TEST_FAILED;

	if (test_bitops_test_set_clear_relaxed() < 0)
		return TEST_FAILED;

	return TEST_SUCCESS;
}

REGISTER_TEST_COMMAND(bitops_autotest, test_bitops);
