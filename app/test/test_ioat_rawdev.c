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

	return 0;
}

#endif /* RTE_LIBRTE_PMD_IOAT_RAWDEV */

REGISTER_TEST_COMMAND(ioat_rawdev_autotest, test_ioat_rawdev);
