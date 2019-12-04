/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2019 Marvell International Ltd.
 */

#ifndef __L3FWD_EVENTDEV_H__
#define __L3FWD_EVENTDEV_H__

#include <rte_common.h>
#include <rte_eventdev.h>
#include <rte_event_eth_tx_adapter.h>
#include <rte_spinlock.h>

#include "l3fwd.h"

#define CMD_LINE_OPT_MODE "mode"
#define CMD_LINE_OPT_EVENTQ_SYNC "eventq-sched"

enum {
	CMD_LINE_OPT_MODE_NUM = 265,
	CMD_LINE_OPT_EVENTQ_SYNC_NUM,
};

typedef uint32_t (*event_device_setup_cb)(void);
typedef void (*event_queue_setup_cb)(uint32_t event_queue_cfg);
typedef void (*event_port_setup_cb)(void);
typedef void (*adapter_setup_cb)(void);
typedef int (*event_loop_cb)(void *);

struct l3fwd_event_setup_ops {
	event_device_setup_cb event_device_setup;
	event_queue_setup_cb event_queue_setup;
	event_port_setup_cb event_port_setup;
	adapter_setup_cb adapter_setup;
	event_loop_cb lpm_event_loop;
	event_loop_cb em_event_loop;
};

struct l3fwd_event_resources {
	struct l3fwd_event_setup_ops ops;
	uint8_t sched_type;
	uint8_t tx_mode_q;
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
void l3fwd_event_set_generic_ops(struct l3fwd_event_setup_ops *ops);
void l3fwd_event_set_internal_port_ops(struct l3fwd_event_setup_ops *ops);

#endif /* __L3FWD_EVENTDEV_H__ */
