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
	struct rte_rawdev_xstats_name *snames = NULL;
	uint64_t *stats = NULL;
	unsigned int *ids = NULL;
	unsigned int nb_xstats;
	unsigned int i;

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

	/* allocate memory for xstats names and values */
	nb_xstats = rte_rawdev_xstats_names_get(dev_id, NULL, 0);

	snames = malloc(sizeof(*snames) * nb_xstats);
	if (snames == NULL) {
		printf("Error allocating xstat names memory\n");
		return -1;
	}
	rte_rawdev_xstats_names_get(dev_id, snames, nb_xstats);

	ids = malloc(sizeof(*ids) * nb_xstats);
	if (ids == NULL) {
		printf("Error allocating xstat ids memory\n");
		return -1;
	}
	for (i = 0; i < nb_xstats; i++)
		ids[i] = i;

	stats = malloc(sizeof(*stats) * nb_xstats);
	if (stats == NULL) {
		printf("Error allocating xstat memory\n");
		return -1;
	}

	rte_rawdev_xstats_get(dev_id, ids, stats, nb_xstats);
	for (i = 0; i < nb_xstats; i++)
		printf("%s: %"PRIu64"   ", snames[i].name, stats[i]);
	printf("\n");

	free(snames);
	free(stats);
	free(ids);
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
