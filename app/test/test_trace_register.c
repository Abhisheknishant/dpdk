/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell International Ltd.
 */
#define RTE_TRACE_POINT_REGISTER_SELECT /* Select trace point register macros */

#include <rte_trace.h>

#include "test_trace.h"

/* Define trace points */
RTE_TRACE_POINT_DEFINE(app_dpdk_test_emerg);
RTE_TRACE_POINT_DEFINE(app_dpdk_test_alert);
RTE_TRACE_POINT_DEFINE(app_dpdk_test_crit);
RTE_TRACE_POINT_DEFINE(app_dpdk_test_err);
RTE_TRACE_POINT_DEFINE(app_dpdk_test_warning);
RTE_TRACE_POINT_DEFINE(app_dpdk_test_notice);
RTE_TRACE_POINT_DEFINE(app_dpdk_test_info);
RTE_TRACE_POINT_DEFINE(app_dpdk_test_debug);

RTE_INIT(register_valid_trace_points)
{
	RTE_TRACE_POINT_REGISTER(app_dpdk_test_emerg,
				 app.dpdk.test.emerg, EMERG);

	RTE_TRACE_POINT_REGISTER(app_dpdk_test_alert,
				 app.dpdk.test.alert, ALERT);

	RTE_TRACE_POINT_REGISTER(app_dpdk_test_crit,
				 app.dpdk.test.crit, CRIT);

	RTE_TRACE_POINT_REGISTER(app_dpdk_test_err,
				 app.dpdk.test.err, ERR);

	RTE_TRACE_POINT_REGISTER(app_dpdk_test_warning,
				 app.dpdk.test.warning, WARNING);

	RTE_TRACE_POINT_REGISTER(app_dpdk_test_notice,
				 app.dpdk.test.notice, NOTICE);

	RTE_TRACE_POINT_REGISTER(app_dpdk_test_info,
				 app.dpdk.test.info, INFO);

	RTE_TRACE_POINT_REGISTER(app_dpdk_test_debug,
				 app.dpdk.test.debug, DEBUG);
}

