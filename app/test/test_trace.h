/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell International Ltd.
 */
#include <rte_trace.h>

RTE_TRACE_POINT(
	app_dpdk_test_emerg,
	RTE_TRACE_POINT_ARGS(const char *str),
	rte_trace_ctf_string(str);
)

RTE_TRACE_POINT(
	app_dpdk_test_alert,
	RTE_TRACE_POINT_ARGS(const char *str),
	rte_trace_ctf_string(str);
)

RTE_TRACE_POINT(
	app_dpdk_test_crit,
	RTE_TRACE_POINT_ARGS(const char *str),
	rte_trace_ctf_string(str);
)

RTE_TRACE_POINT(
	app_dpdk_test_err,
	RTE_TRACE_POINT_ARGS(const char *str),
	rte_trace_ctf_string(str);
)

RTE_TRACE_POINT(
	app_dpdk_test_warning,
	RTE_TRACE_POINT_ARGS(const char *str),
	rte_trace_ctf_string(str);
)

RTE_TRACE_POINT(
	app_dpdk_test_notice,
	RTE_TRACE_POINT_ARGS(const char *str),
	rte_trace_ctf_string(str);
)

RTE_TRACE_POINT(
	app_dpdk_test_info,
	RTE_TRACE_POINT_ARGS(const char *str),
	rte_trace_ctf_string(str);
)

RTE_TRACE_POINT(
	app_dpdk_test_debug,
	RTE_TRACE_POINT_ARGS(const char *str),
	rte_trace_ctf_string(str);
)
