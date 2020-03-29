/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2019 Marvell International Ltd.
 * Copyright(C) 2020 Mellanox International Ltd.
 */

#include <string.h>

#include <rte_spinlock.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_memzone.h>
#include <rte_string_fns.h>

#include "rte_regexdev.h"
#include "rte_regexdev_driver.h"

static struct rte_regexdev *regex_devices[RTE_MAX_REGEXDEV_DEVS];

int rte_regexdev_logtype;

static uint16_t
regexdev_find_free_dev(void)
{
	uint16_t i;

	for (i = 0; i < RTE_MAX_REGEXDEV_DEVS; i++) {
		if (regex_devices[i] == NULL)
			return i;
	}
	return RTE_MAX_REGEXDEV_DEVS;
}

static const struct rte_regexdev*
regexdev_allocated(const char *name)
{
	uint16_t i;

	for (i = 0; i < RTE_MAX_REGEXDEV_DEVS; i++) {
		if (regex_devices[i] != NULL)
			if (!strcmp(name, regex_devices[i]->dev_name))
				return regex_devices[i];
	}
	return NULL;
}

int
rte_regexdev_register(struct rte_regexdev *dev)
{
	uint16_t dev_id;
	int res;

	if (dev->dev_ops == NULL) {
		RTE_REGEXDEV_LOG(ERR, "RegEx device invalid device ops\n");
		return -EINVAL;
	}
	if (regexdev_allocated(dev->dev_name) != NULL) {
		RTE_REGEXDEV_LOG
			(ERR, "RegEx device with name %s already allocated\n",
			 dev->dev_name);
		return -ENOMEM;
	}
	dev_id = regexdev_find_free_dev();
	if (dev_id == RTE_MAX_REGEXDEV_DEVS) {
		RTE_REGEXDEV_LOG
			(ERR, "Reached maximum number of regex devs\n");
		return -ENOMEM;
	}
	dev->dev_id = dev_id;
	regex_devices[dev_id] = dev;
	res = dev_id;
	return res;
}

void
rte_regexdev_unregister(struct rte_regexdev *dev)
{
	regex_devices[dev->dev_id] = NULL;
}
