/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright (C) 2020 Marvell International Ltd.
 */
#ifndef _EVENT_HELPER_H_
#define _EVENT_HELPER_H_

#include <rte_log.h>

#define RTE_LOGTYPE_EH  RTE_LOGTYPE_USER4

#define EH_LOG_ERR(...) \
	RTE_LOG(ERR, EH, \
		RTE_FMT("%s() line %u: " RTE_FMT_HEAD(__VA_ARGS__ ,) "\n", \
			__func__, __LINE__, RTE_FMT_TAIL(__VA_ARGS__ ,)))

/* Max event devices supported */
#define EVENT_MODE_MAX_EVENT_DEVS RTE_EVENT_MAX_DEVS

/* Max event queues supported per event device */
#define EVENT_MODE_MAX_EVENT_QUEUES_PER_DEV RTE_EVENT_MAX_QUEUES_PER_DEV

/* Max event-lcore links */
#define EVENT_MODE_MAX_LCORE_LINKS \
	(EVENT_MODE_MAX_EVENT_DEVS * EVENT_MODE_MAX_EVENT_QUEUES_PER_DEV)

/**
 * Packet transfer mode of the application
 */
enum eh_pkt_transfer_mode {
	EH_PKT_TRANSFER_MODE_POLL = 0,
	EH_PKT_TRANSFER_MODE_EVENT,
};

/* Event dev params */
struct eventdev_params {
	uint8_t eventdev_id;
	uint8_t nb_eventqueue;
	uint8_t nb_eventport;
	uint8_t ev_queue_mode;
};

/**
 * Event-lcore link configuration
 */
struct eh_event_link_info {
	uint8_t eventdev_id;
		/**< Event device ID */
	uint8_t event_port_id;
		/**< Event port ID */
	uint8_t eventq_id;
		/**< Event queue to be linked to the port */
	uint8_t lcore_id;
		/**< Lcore to be polling on this port */
};

/* Eventmode conf data */
struct eventmode_conf {
	int nb_eventdev;
		/**< No of event devs */
	struct eventdev_params eventdev_config[EVENT_MODE_MAX_EVENT_DEVS];
		/**< Per event dev conf */
	uint8_t nb_link;
		/**< No of links */
	struct eh_event_link_info
		link[EVENT_MODE_MAX_LCORE_LINKS];
		/**< Per link conf */
	struct rte_bitmap *eth_core_mask;
		/**< Core mask of cores to be used for software Rx and Tx */
	union {
		RTE_STD_C11
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

/**
 * Event helper configuration
 */
struct eh_conf {
	enum eh_pkt_transfer_mode mode;
		/**< Packet transfer mode of the application */
	uint32_t eth_portmask;
		/**<
		 * Mask of the eth ports to be used. This portmask would be
		 * checked while initializing devices using helper routines.
		 */
	void *mode_params;
		/**< Mode specific parameters */
};

/**
 * Initialize event mode devices
 *
 * Application can call this function to get the event devices, eth devices
 * and eth rx & tx adapters initialized according to the default config or
 * config populated using the command line args.
 *
 * Application is expected to initialize the eth devices and then the event
 * mode helper subsystem will stop & start eth devices according to its
 * requirement. Call to this function should be done after the eth devices
 * are successfully initialized.
 *
 * @param conf
 *   Event helper configuration
 * @return
 *  - 0 on success.
 *  - (<0) on failure.
 */
int32_t
eh_devs_init(struct eh_conf *conf);

/**
 * Release event mode devices
 *
 * Application can call this function to release event devices,
 * eth rx & tx adapters according to the config.
 *
 * Call to this function should be done before application stops
 * and closes eth devices. This function will not close and stop
 * eth devices.
 *
 * @param conf
 *   Event helper configuration
 * @return
 *  - 0 on success.
 *  - (<0) on failure.
 */
int32_t
eh_devs_uninit(struct eh_conf *conf);

#endif /* _EVENT_HELPER_H_ */
