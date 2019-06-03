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

/* Event dev params */
struct eventdev_params {
	uint8_t eventdev_id;
	uint8_t nb_eventqueue;
	uint8_t nb_eventport;
	uint8_t ev_queue_mode;
};

/* Eventmode conf data */
struct eventmode_conf {
	int nb_eventdev;
		/**< No of event devs */
	struct eventdev_params eventdev_config[EVENT_MODE_MAX_EVENT_DEVS];
		/**< Per event dev conf */
};

#endif /* _RTE_EVENTMODE_HELPER_INTERNAL_H_ */
