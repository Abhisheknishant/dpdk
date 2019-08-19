/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Intel Corporation
 */

#include "e1000_logs.h"

/* declared as extern in e1000_logs.h */
int e1000_logtype_init;
int e1000_logtype_driver;

/* register only once if EM and IGB drivers are in use */
RTE_LOG_REGISTER(e1000_logtype_init, "pmd.net.e1000.init",
	RTE_LOG_NOTICE, RTE_LOGTYPE_PMD);
RTE_LOG_REGISTER(e1000_logtype_driver, "pmd.net.e1000.driver",
	RTE_LOG_NOTICE, RTE_LOGTYPE_PMD);
