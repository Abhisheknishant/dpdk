/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2019 Marvell International Ltd.
 */

#ifndef __L3FWD_EVENTDEV_H__
#define __L3FWD_EVENTDEV_H__

#include <rte_common.h>
#include <rte_eventdev.h>
#include <rte_spinlock.h>

#include "l3fwd.h"

#define CMD_LINE_OPT_MODE "mode"
#define CMD_LINE_OPT_EVENTQ_SYNC "eventq-sched"

enum {
	CMD_LINE_OPT_MODE_NUM = 265,
	CMD_LINE_OPT_EVENTQ_SYNC_NUM,
};

struct l3fwd_event_resources {
	uint8_t sched_type;
	uint8_t enabled;
	uint8_t nb_args;
	char **args;
};

static inline struct l3fwd_event_resources *
l3fwd_get_eventdev_rsrc(void)
{
	static const char name[RTE_MEMZONE_NAMESIZE] = "l3fwd_event_rsrc";
	const struct rte_memzone *mz;

	mz = rte_memzone_lookup(name);

	if (mz != NULL)
		return mz->addr;

	mz = rte_memzone_reserve(name, sizeof(struct l3fwd_event_resources),
				 0, 0);
	if (mz != NULL) {
		memset(mz->addr, 0, sizeof(struct l3fwd_event_resources));
		return mz->addr;
	}

	rte_exit(EXIT_FAILURE, "Unable to allocate memory for eventdev cfg\n");

	return NULL;
}

void l3fwd_event_resource_setup(void);

#endif /* __L3FWD_EVENTDEV_H__ */
