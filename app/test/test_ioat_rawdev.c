/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Intel Corporation
 */

#include "test.h"

#ifndef RTE_LIBRTE_PMD_IOAT_RAWDEV

static int
test_ioat_rawdev(void) { return TEST_SKIPPED; }

#else

#include <string.h>
#include <unistd.h>

#include <rte_mbuf.h>
#include <rte_rawdev.h>
#include <rte_ioat_rawdev.h>

static int
run_ioat_tests(int dev_id)
{
#define IOAT_TEST_RINGSIZE 512
	struct rte_ioat_rawdev_config p = { .ring_size = -1 };
	struct rte_rawdev_info info = { .dev_private = &p };

	rte_rawdev_info_get(dev_id, &info);
	if (p.ring_size != 0) {
		printf("Error, initial ring size is non-zero (%d)\n",
				(int)p.ring_size);
		return -1;
	}

	p.ring_size = IOAT_TEST_RINGSIZE;
	if (rte_rawdev_configure(dev_id, &info) != 0) {
		printf("Error with rte_rawdev_configure()\n");
		return -1;
	}
	rte_rawdev_info_get(dev_id, &info);
	if (p.ring_size != IOAT_TEST_RINGSIZE) {
		printf("Error, ring size is not %d (%d)\n",
				IOAT_TEST_RINGSIZE, (int)p.ring_size);
		return -1;
	}

	if (rte_rawdev_start(dev_id) != 0) {
		printf("Error with rte_rawdev_start()\n");
		return -1;
	}
	return 0;
}

static int
test_ioat_rawdev(void)
{
	const int count = rte_rawdev_count();
	int i, found = 0;

	printf("Checking %d rawdevs\n", count);
	for (i = 0; i < count && !found; i++) {
		struct rte_rawdev_info info = { .dev_private = NULL };
		found = (rte_rawdev_info_get(i, &info) == 0 &&
				strcmp(info.driver_name,
						IOAT_PMD_RAWDEV_NAME_STR) == 0);
	}

	if (!found) {
		printf("No IOAT rawdev found, skipping tests\n");
		return TEST_SKIPPED;
	}

	return run_ioat_tests(i);
}

#endif /* RTE_LIBRTE_PMD_IOAT_RAWDEV */

REGISTER_TEST_COMMAND(ioat_rawdev_autotest, test_ioat_rawdev);
