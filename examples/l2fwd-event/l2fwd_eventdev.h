/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2019 Marvell International Ltd.
 */

#ifndef __L2FWD_EVENTDEV_H__
#define __L2FWD_EVENTDEV_H__

#include <rte_common.h>
#include <rte_spinlock.h>

#include "l2fwd_common.h"

#define CMD_LINE_OPT_MODE "mode"
#define CMD_LINE_OPT_EVENTQ_SYNC "eventq-sync"

enum {
	CMD_LINE_OPT_MODE_NUM = 265,
	CMD_LINE_OPT_EVENTQ_SYNC_NUM,
};

typedef void (*event_queue_setup_cb)(uint16_t ethdev_count,
				     uint32_t event_queue_cfg);
typedef uint32_t (*eventdev_setup_cb)(uint16_t ethdev_count);
typedef void (*adapter_setup_cb)(uint16_t ethdev_count);
typedef void (*event_port_setup_cb)(void);
typedef void (*service_setup_cb)(void);
typedef void (*event_loop_cb)(void);

struct eventdev_setup_ops {
	event_queue_setup_cb event_queue_setup;
	event_port_setup_cb event_port_setup;
	eventdev_setup_cb eventdev_setup;
	adapter_setup_cb adapter_setup;
	service_setup_cb service_setup;
	event_loop_cb l2fwd_event_loop;
};

struct eventdev_resources {
	struct l2fwd_port_statistics *stats;
	struct eventdev_setup_ops ops;
	struct rte_mempool *pkt_pool;
	uint64_t timer_period;
	uint32_t *dst_ports;
	uint32_t service_id;
	uint32_t port_mask;
	volatile bool *done;
	uint8_t event_d_id;
	uint8_t sync_mode;
	uint8_t tx_mode_q;
	uint8_t mac_updt;
	uint8_t enabled;
	uint8_t nb_args;
	char **args;
};

static inline struct eventdev_resources *
get_eventdev_rsrc(void)
{
	const char name[RTE_MEMZONE_NAMESIZE] = "l2fwd_event_rsrc";
	const struct rte_memzone *mz;

	mz = rte_memzone_lookup(name);

	if (mz != NULL)
		return mz->addr;

	mz = rte_memzone_reserve(name, sizeof(struct eventdev_resources), 0, 0);
	if (mz != NULL) {
		memset(mz->addr, 0, sizeof(struct eventdev_resources));
		return mz->addr;
	}

	rte_exit(EXIT_FAILURE, "Unable to allocate memory for eventdev cfg\n");

	return NULL;
}

void eventdev_resource_setup(void);
void eventdev_set_generic_ops(struct eventdev_setup_ops *ops);
void eventdev_set_internal_port_ops(struct eventdev_setup_ops *ops);

#endif /* __L2FWD_EVENTDEV_H__ */
