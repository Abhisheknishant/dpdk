/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell International Ltd.
 */

#include <rte_trace_eal.h>
#include <rte_lcore.h>

#include "test.h"
#include "test_trace.h"

static int32_t
test_trace_point_globbing(void)
{
	bool val;
	int rc;

	rc = rte_trace_pattern("app.dpdk.test*", false);
	if (rc != 1)
		goto failed;

	val = rte_trace_is_disabled(&__app_dpdk_test_tp);
	if (val == false)
		goto failed;

	rc = rte_trace_pattern("app.dpdk.test*", true);
	if (rc != 1)
		goto failed;

	val = rte_trace_is_enabled(&__app_dpdk_test_tp);
	if (val == false)
		goto failed;

	rc = rte_trace_pattern("invalid_testpoint.*", true);
	if (rc != 0)
		goto failed;

	return TEST_SUCCESS;

failed:
	return TEST_FAILED;
}

static int32_t
test_trace_point_regex(void)
{
	bool val;
	int rc;


	rc = rte_trace_regexp("app.dpdk.test*", false);
	if (rc != 1)
		goto failed;

	val = rte_trace_is_disabled(&__app_dpdk_test_tp);
	if (val == false)
		goto failed;

	rc = rte_trace_regexp("app.dpdk.test*", true);
	if (rc != 1)
		goto failed;

	val = rte_trace_is_enabled(&__app_dpdk_test_tp);
	if (val == false)
		goto failed;

	rc = rte_trace_regexp("invalid_testpoint.*", true);
	if (rc != 0)
		goto failed;

	return TEST_SUCCESS;

failed:
	return TEST_FAILED;
}

static int32_t
test_trace_point_disable_enable(void)
{
	bool val;
	int rc;

	rc = rte_trace_disable(&__app_dpdk_test_tp);
	if (rc < 0)
		goto failed;

	val = rte_trace_is_disabled(&__app_dpdk_test_tp);
	if (val == false)
		goto failed;

	rc = rte_trace_enable(&__app_dpdk_test_tp);
	if (rc < 0)
		goto failed;

	val = rte_trace_is_enabled(&__app_dpdk_test_tp);
	if (val == false)
		goto failed;

	/* Emit the trace */
	app_dpdk_test_tp("app.dpdk.test.tp");
	return TEST_SUCCESS;

failed:
	return TEST_FAILED;
}

static int32_t
test_trace_validity(void)
{
	rte_trace_t invalid_trace = (int64_t)-1; /* Invalid trace */
	bool rc;

	rc = rte_trace_id_is_invalid(&__app_dpdk_test_tp);
	if (rc == true)
		goto failed;

	rc = rte_trace_id_is_invalid(&invalid_trace);
	if (rc == false)
		goto failed;

	return TEST_SUCCESS;

failed:
	return TEST_FAILED;
}

static int
test_trace_global_status(void)
{
	bool enabled, disabled;

	enabled = rte_trace_global_is_enabled();
	disabled = rte_trace_global_is_disabled();

	if (enabled != disabled)
		return TEST_SUCCESS;

	return TEST_FAILED;
}

static int
test_trace_mode(void)
{
	enum rte_trace_mode current;

	current = rte_trace_mode_get();

	if (rte_trace_global_is_disabled())
		return TEST_SKIPPED;

	rte_trace_mode_set(RTE_TRACE_MODE_DISCARD);
	if (rte_trace_mode_get() != RTE_TRACE_MODE_DISCARD)
		goto failed;

	rte_trace_mode_set(RTE_TRACE_MODE_OVERWRITE);
	if (rte_trace_mode_get() != RTE_TRACE_MODE_OVERWRITE)
		goto failed;

	rte_trace_mode_set(current);
	return TEST_SUCCESS;

failed:
	return TEST_FAILED;

}

static int
test_trace_points_lookup(void)
{
	rte_trace_t *trace;

	trace =  rte_trace_by_name("app.dpdk.test.tp");
	if (trace == NULL)
		goto fail;
	trace = rte_trace_by_name("this_trace_point_does_not_exist");
	if (trace != NULL)
		goto fail;

	return TEST_SUCCESS;
fail:
	return TEST_FAILED;
}

static int
test_trace_fastpath_point(void)
{
	/* Emit the FP trace */
	app_dpdk_test_fp();

	return TEST_SUCCESS;
}

static int
test_generic_trace_points(void)
{
	int tmp;

	rte_trace_lib_eal_generic_void();
	rte_trace_lib_eal_generic_u64(0x10000000000000);
	rte_trace_lib_eal_generic_u32(0x10000000);
	rte_trace_lib_eal_generic_u16(0xffee);
	rte_trace_lib_eal_generic_u8(0xc);
	rte_trace_lib_eal_generic_i64(-1234);
	rte_trace_lib_eal_generic_i32(-1234567);
	rte_trace_lib_eal_generic_i16(12);
	rte_trace_lib_eal_generic_i8(-3);
	rte_trace_lib_eal_generic_int(3333333);
	rte_trace_lib_eal_generic_long(333);
	rte_trace_lib_eal_generic_float(20.45);
	rte_trace_lib_eal_generic_double(20000.5000004);
	rte_trace_lib_eal_generic_ptr(&tmp);
	rte_trace_lib_eal_generic_str("my string");
	RTE_TRACE_LIB_EAL_GENERIC_FUNC;

	return TEST_SUCCESS;
}

static struct unit_test_suite trace_tests = {
	.suite_name = "trace autotest",
	.setup = NULL,
	.teardown = NULL,
	.unit_test_cases = {
		TEST_CASE(test_trace_global_status),
		TEST_CASE(test_trace_mode),
		TEST_CASE(test_generic_trace_points),
		TEST_CASE(test_trace_fastpath_point),
		TEST_CASE(test_trace_point_disable_enable),
		TEST_CASE(test_trace_point_globbing),
		TEST_CASE(test_trace_point_regex),
		TEST_CASE(test_trace_points_lookup),
		TEST_CASE(test_trace_validity),
		TEST_CASES_END()
	}
};

static int
test_trace(void)
{
	return unit_test_suite_runner(&trace_tests);
}

REGISTER_TEST_COMMAND(trace_autotest, test_trace);

static int
test_trace_dump(void)
{
	rte_trace_dump(stdout);
	return 0;
}

REGISTER_TEST_COMMAND(trace_dump, test_trace_dump);

static int
test_trace_metadata_dump(void)
{
	return rte_trace_metadata_dump(stdout);
}

REGISTER_TEST_COMMAND(trace_metadata_dump, test_trace_metadata_dump);
