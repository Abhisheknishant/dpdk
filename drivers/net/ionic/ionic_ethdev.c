/* SPDX-License-Identifier: GPL-2.0
 * Copyright(c) 2018-2019 Pensando Systems, Inc. All rights reserved.
 */

#include "ionic_logs.h"

int ionic_logtype_init;
int ionic_logtype_driver;

RTE_INIT(ionic_init_log)
{
	ionic_logtype_init = rte_log_register("pmd.net.ionic.init");

	if (ionic_logtype_init >= 0)
		rte_log_set_level(ionic_logtype_init, RTE_LOG_NOTICE);

	ionic_logtype_driver = rte_log_register("pmd.net.ionic.driver");

	if (ionic_logtype_driver >= 0)
		rte_log_set_level(ionic_logtype_driver, RTE_LOG_NOTICE);
}
