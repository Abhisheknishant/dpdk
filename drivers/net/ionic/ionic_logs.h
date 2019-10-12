/* SPDX-License-Identifier: GPL-2.0
 * Copyright(c) 2018-2019 Pensando Systems, Inc. All rights reserved.
 */

#ifndef _IONIC_LOGS_H_
#define _IONIC_LOGS_H_

#include <rte_log.h>

extern int ionic_logtype_init;
extern int ionic_logtype_driver;

#define ionic_init_print(level, fmt, args...) rte_log(RTE_LOG_ ## level, \
		ionic_logtype_init, "%s(): " fmt "\n", __func__, ##args)

#define ionic_init_print_call() ionic_init_print(DEBUG, " >>")

#ifndef IONIC_WARN_ON
#define IONIC_WARN_ON(x) do { \
	int ret = !!(x); \
	if (unlikely(ret)) \
		ionic_init_print(WARNING, "WARN_ON: \"" #x "\" at %s:%d\n", \
				__func__, __LINE__); \
} while (0)
#endif

#ifdef RTE_LIBRTE_IONIC_DEBUG_RX
#define ionic_rx_print(level, fmt, args...) RTE_LOG(level, PMD, \
		"%s(): " fmt "\n", __func__, ## args)
#else
#define ionic_rx_print(level, fmt, args...) do { } while (0)
#endif

#ifdef RTE_LIBRTE_IONIC_DEBUG_TX
#define ionic_tx_print(level, fmt, args...) RTE_LOG(level, PMD, \
		"%s(): " fmt "\n", __func__, ## args)
#else
#define ionic_tx_print(level, fmt, args...) do { } while (0)
#endif

#define ionic_drv_print(level, fmt, args...) rte_log(RTE_LOG_ ## level, \
		ionic_logtype_driver, "%s(): " fmt "\n", __func__, ## args)

#define ionic_drv_print_call() ionic_drv_print(DEBUG, " >>")

#endif /* _IONIC_LOGS_H_ */
