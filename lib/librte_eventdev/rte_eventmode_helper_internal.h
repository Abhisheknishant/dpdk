/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2019 Marvell International Ltd.
 */
#ifndef _RTE_EVENTMODE_HELPER_INTERNAL_H_
#define _RTE_EVENTMODE_HELPER_INTERNAL_H_

#include <rte_log.h>

/* Logging macros */

#define RTE_EM_HLPR_LOG_ERR(...) \
	RTE_LOG(ERR, EVENTMODE, \
		RTE_FMT("%s(): " RTE_FMT_HEAD(__VA_ARGS__ ,) "\n", \
			__func__, RTE_FMT_TAIL(__VA_ARGS__ ,)))

#define RTE_EM_HLPR_LOG_WARNING(...) \
	RTE_LOG(WARNING, EVENTMODE, \
		RTE_FMT("%s(): " RTE_FMT_HEAD(__VA_ARGS__ ,) "\n", \
			__func__, RTE_FMT_TAIL(__VA_ARGS__ ,)))

#define RTE_EM_HLPR_LOG_INFO(...) \
	RTE_LOG(INFO, EVENTMODE, \
		RTE_FMT(RTE_FMT_HEAD(__VA_ARGS__ ,) "\n", \
			RTE_FMT_TAIL(__VA_ARGS__ ,)))

#ifdef RTE_LIBRTE_EVENTMODE_HELPER_DEBUG
#define RTE_EM_HLPR_LOG_DEBUG(...) \
	RTE_LOG(DEBUG, EVENTMODE, \
		RTE_FMT("%s() line %u: " RTE_FMT_HEAD(__VA_ARGS__ ,) "\n", \
			__func__, __LINE__, RTE_FMT_TAIL(__VA_ARGS__ ,)))
#else
#define RTE_EM_HLPR_LOG_DEBUG(...) (void)0
#endif

/* Max event devices supported */
#define EVENT_MODE_MAX_EVENT_DEVS RTE_EVENT_MAX_DEVS

/* Max Rx adapters supported */
#define EVENT_MODE_MAX_RX_ADAPTERS RTE_EVENT_MAX_DEVS

/* Max Rx adapter connections */
#define EVENT_MODE_MAX_CONNECTIONS_PER_ADAPTER 16

/* Max event queues supported per event device */
#define EVENT_MODE_MAX_EVENT_QUEUES_PER_DEV RTE_EVENT_MAX_QUEUES_PER_DEV

/* Max event-lcore links */
#define EVENT_MODE_MAX_LCORE_LINKS \
	(EVENT_MODE_MAX_EVENT_DEVS * EVENT_MODE_MAX_EVENT_QUEUES_PER_DEV)

/* Event dev params */
struct eventdev_params {
	uint8_t eventdev_id;
	uint8_t nb_eventqueue;
	uint8_t nb_eventport;
	uint8_t ev_queue_mode;
};

/* Rx adapter connection info */
struct adapter_connection_info {
	uint8_t ethdev_id;
	uint8_t eventq_id;
	int32_t ethdev_rx_qid;
};

/* Rx adapter conf */
struct rx_adapter_conf {
	int32_t eventdev_id;
	int32_t adapter_id;
	uint32_t rx_core_id;
	uint8_t nb_connections;
	struct adapter_connection_info
			conn[EVENT_MODE_MAX_CONNECTIONS_PER_ADAPTER];
};

/* Eventmode conf data */
struct eventmode_conf {
	int nb_eventdev;
		/**< No of event devs */
	struct eventdev_params eventdev_config[EVENT_MODE_MAX_EVENT_DEVS];
		/**< Per event dev conf */
	uint8_t nb_rx_adapter;
		/**< No of Rx adapters */
	struct rx_adapter_conf rx_adapter[EVENT_MODE_MAX_RX_ADAPTERS];
		/**< Rx adapter conf */
	uint8_t nb_link;
		/**< No of links */
	struct rte_eventmode_helper_event_link_info
			link[EVENT_MODE_MAX_LCORE_LINKS];
		/**< Per link conf */
	uint32_t eth_core_mask;
		/**< Core mask of cores to be used for software Rx and Tx */
	uint32_t eth_portmask;
		/**< Mask of the eth ports to be used */
	union {
		struct {
			uint64_t sched_type			: 2;
		/**< Schedule type */
			uint64_t all_ev_queue_to_ev_port	: 1;
		/**<
		 * When enabled, all event queues need to be mapped to
		 * each event port
		 */
		};
		uint64_t u64;
	} ext_params;
		/**< 64 bit field to specify extended params */
};

#endif /* _RTE_EVENTMODE_HELPER_INTERNAL_H_ */
