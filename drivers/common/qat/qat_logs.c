/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Intel Corporation
 */

#include <rte_log.h>
#include <rte_hexdump.h>

#include "qat_logs.h"

int qat_gen_logtype;
int qat_dp_logtype;

int
qat_hexdump_log(uint32_t level, uint32_t logtype, const char *title,
		const void *buf, unsigned int len)
{
	if (level > rte_log_get_global_level())
		return 0;
	if (level > (uint32_t)(rte_log_get_level(logtype)))
		return 0;

	rte_hexdump(rte_logs.file == NULL ? stderr : rte_logs.file,
				title, buf, len);
	return 0;
}

/* Non-data-path logging for pci device and all services */
RTE_LOG_REGISTER(qat_gen_logtype, "pmd.qat_general",
	RTE_LOG_NOTICE, RTE_LOGTYPE_PMD);
/* data-path logging for all services */
RTE_LOG_REGISTER(qat_dp_logtype, "pmd.qat_dp",
	RTE_LOG_NOTICE, RTE_LOGTYPE_PMD);
