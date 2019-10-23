/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Arm Limited
 */

#include <rte_io_bitops.h>
#include <rte_malloc.h>

#include "test.h"

#define MAX_BITS 32

static int
test_io_bitops_set(unsigned long *addr)
{
	unsigned int i;

	for (i = 0; i < MAX_BITS; i++)
		rte_io_set_bit(i, addr);

	for (i = 0; i < MAX_BITS; i++)
		if (!rte_io_get_bit(i, addr)) {
			printf("Failed to set bit.\n");
			return TEST_FAILED;
		}

	return TEST_SUCCESS;
}

static int
test_io_bitops_clear(unsigned long *addr)
{
	unsigned int i;

	for (i = 0; i < MAX_BITS; i++)
		rte_io_clear_bit(i, addr);

	for (i = 0; i < MAX_BITS; i++)
		if (rte_io_get_bit(i, addr)) {
			printf("Failed to clear bit.\n");
			return TEST_FAILED;
	}

	return TEST_SUCCESS;
}

static int
test_io_bitops_test_set_clear(unsigned long *addr)
{
	unsigned int i;

	for (i = 0; i < MAX_BITS; i++)
		rte_io_test_and_set_bit(i, addr);

	for (i = 0; i < MAX_BITS; i++)
		if (!rte_io_test_and_clear_bit(i, addr)) {
			printf("Failed to set and test bit.\n");
			return TEST_FAILED;
	}

	for (i = 0; i < MAX_BITS; i++)
		if (rte_io_get_bit(i, addr)) {
			printf("Failed to test and clear bit.\n");
			return TEST_FAILED;
		}

	return TEST_SUCCESS;
}

static int
test_io_bitops(void)
{
	unsigned long *addr = rte_zmalloc(NULL, MAX_BITS, RTE_CACHE_LINE_SIZE);

	if (test_io_bitops_set(addr) < 0)
		return TEST_FAILED;

	if (test_io_bitops_clear(addr) < 0)
		return TEST_FAILED;

	if (test_io_bitops_test_set_clear(addr) < 0)
		return TEST_FAILED;

	return TEST_SUCCESS;
}

REGISTER_TEST_COMMAND(io_bitops_autotest, test_io_bitops);
