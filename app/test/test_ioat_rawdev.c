/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019 Intel Corporation
 */

#include "test.h"

#ifndef RTE_LIBRTE_PMD_IOAT_RAWDEV

static int
test_ioat_rawdev(void) { return TEST_SKIPPED; }

#else

static int
test_ioat_rawdev(void)
{
	return 0;
}

#endif /* RTE_LIBRTE_PMD_IOAT_RAWDEV */

REGISTER_TEST_COMMAND(ioat_rawdev_autotest, test_ioat_rawdev);
