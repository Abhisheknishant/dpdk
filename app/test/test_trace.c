/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(C) 2020 Marvell International Ltd.
 */

#include <rte_trace_eal.h>
#include <rte_lcore.h>

#include "test.h"
#include "test_trace.h"

struct tp_config {
	int mode;
	int level;
	bool enabled;
};

struct trace_config {
	uint32_t level;
	enum rte_trace_mode mode;
	struct tp_config conf[RTE_LOG_DEBUG + 1];
};

static void
trace_config_save(struct trace_config *conf)
{
	/* Save global config */
	conf->mode = rte_trace_global_mode_get();
	conf->level = rte_trace_global_level_get();

	/* Save trace specific config */
	conf->conf[RTE_LOG_EMERG].mode =
			rte_trace_mode_get(&__app_dpdk_test_emerg);
	conf->conf[RTE_LOG_EMERG].level =
			rte_trace_level_get(&__app_dpdk_test_emerg);
	conf->conf[RTE_LOG_EMERG].enabled =
			rte_trace_is_enabled(&__app_dpdk_test_emerg);

	conf->conf[RTE_LOG_ALERT].mode =
			rte_trace_mode_get(&__app_dpdk_test_alert);
	conf->conf[RTE_LOG_ALERT].level =
			rte_trace_level_get(&__app_dpdk_test_alert);
	conf->conf[RTE_LOG_ALERT].enabled =
			rte_trace_is_enabled(&__app_dpdk_test_alert);

	conf->conf[RTE_LOG_CRIT].mode =
			rte_trace_mode_get(&__app_dpdk_test_crit);
	conf->conf[RTE_LOG_CRIT].level =
			rte_trace_level_get(&__app_dpdk_test_crit);
	conf->conf[RTE_LOG_CRIT].enabled =
			rte_trace_is_enabled(&__app_dpdk_test_crit);

	conf->conf[RTE_LOG_ERR].mode =
			rte_trace_mode_get(&__app_dpdk_test_err);
	conf->conf[RTE_LOG_ERR].level =
			rte_trace_level_get(&__app_dpdk_test_err);
	conf->conf[RTE_LOG_ERR].enabled =
			rte_trace_is_enabled(&__app_dpdk_test_err);

	conf->conf[RTE_LOG_WARNING].mode =
			rte_trace_mode_get(&__app_dpdk_test_warning);
	conf->conf[RTE_LOG_WARNING].level =
			rte_trace_level_get(&__app_dpdk_test_warning);
	conf->conf[RTE_LOG_WARNING].enabled =
			rte_trace_is_enabled(&__app_dpdk_test_warning);

	conf->conf[RTE_LOG_NOTICE].mode =
			rte_trace_mode_get(&__app_dpdk_test_notice);
	conf->conf[RTE_LOG_NOTICE].level =
			rte_trace_level_get(&__app_dpdk_test_notice);
	conf->conf[RTE_LOG_NOTICE].enabled =
			rte_trace_is_enabled(&__app_dpdk_test_notice);

	conf->conf[RTE_LOG_INFO].mode =
			rte_trace_mode_get(&__app_dpdk_test_info);
	conf->conf[RTE_LOG_INFO].level =
			rte_trace_level_get(&__app_dpdk_test_info);
	conf->conf[RTE_LOG_INFO].enabled =
			rte_trace_is_enabled(&__app_dpdk_test_info);

	conf->conf[RTE_LOG_DEBUG].mode =
			rte_trace_mode_get(&__app_dpdk_test_debug);
	conf->conf[RTE_LOG_DEBUG].level =
			rte_trace_level_get(&__app_dpdk_test_debug);
	conf->conf[RTE_LOG_DEBUG].enabled =
			rte_trace_is_enabled(&__app_dpdk_test_debug);
}

static void
trace_config_restore(struct trace_config *conf)
{
	/* Restore global config */
	rte_trace_global_mode_set(conf->mode);
	rte_trace_global_level_set(conf->level);

	/* Restore trace specific config */
	rte_trace_mode_set(&__app_dpdk_test_emerg,
			   conf->conf[RTE_LOG_EMERG].mode);
	rte_trace_level_set(&__app_dpdk_test_emerg,
			    conf->conf[RTE_LOG_EMERG].level);
	if (conf->conf[RTE_LOG_EMERG].enabled)
		rte_trace_enable(&__app_dpdk_test_emerg);
	else
		rte_trace_disable(&__app_dpdk_test_emerg);

	rte_trace_mode_set(&__app_dpdk_test_alert,
			   conf->conf[RTE_LOG_ALERT].mode);
	rte_trace_level_set(&__app_dpdk_test_alert,
			    conf->conf[RTE_LOG_ALERT].level);
	if (conf->conf[RTE_LOG_ALERT].enabled)
		rte_trace_enable(&__app_dpdk_test_alert);
	else
		rte_trace_disable(&__app_dpdk_test_alert);

	rte_trace_mode_set(&__app_dpdk_test_crit,
			   conf->conf[RTE_LOG_CRIT].mode);
	rte_trace_level_set(&__app_dpdk_test_crit,
			    conf->conf[RTE_LOG_CRIT].level);
	if (conf->conf[RTE_LOG_CRIT].enabled)
		rte_trace_enable(&__app_dpdk_test_crit);
	else
		rte_trace_disable(&__app_dpdk_test_crit);

	rte_trace_mode_set(&__app_dpdk_test_err,
			   conf->conf[RTE_LOG_ERR].mode);
	rte_trace_level_set(&__app_dpdk_test_err,
			    conf->conf[RTE_LOG_ERR].level);
	if (conf->conf[RTE_LOG_ERR].enabled)
		rte_trace_enable(&__app_dpdk_test_err);
	else
		rte_trace_disable(&__app_dpdk_test_err);

	rte_trace_mode_set(&__app_dpdk_test_warning,
			   conf->conf[RTE_LOG_WARNING].mode);
	rte_trace_level_set(&__app_dpdk_test_warning,
			    conf->conf[RTE_LOG_WARNING].level);
	if (conf->conf[RTE_LOG_WARNING].enabled)
		rte_trace_enable(&__app_dpdk_test_warning);
	else
		rte_trace_disable(&__app_dpdk_test_warning);

	rte_trace_mode_set(&__app_dpdk_test_notice,
			   conf->conf[RTE_LOG_NOTICE].mode);
	rte_trace_level_set(&__app_dpdk_test_notice,
			    conf->conf[RTE_LOG_NOTICE].level);
	if (conf->conf[RTE_LOG_NOTICE].enabled)
		rte_trace_enable(&__app_dpdk_test_notice);
	else
		rte_trace_disable(&__app_dpdk_test_notice);

	rte_trace_mode_set(&__app_dpdk_test_info,
			   conf->conf[RTE_LOG_INFO].mode);
	rte_trace_level_set(&__app_dpdk_test_info,
			    conf->conf[RTE_LOG_INFO].level);
	if (conf->conf[RTE_LOG_INFO].enabled)
		rte_trace_enable(&__app_dpdk_test_info);
	else
		rte_trace_disable(&__app_dpdk_test_info);

	rte_trace_mode_set(&__app_dpdk_test_debug,
			   conf->conf[RTE_LOG_DEBUG].mode);
	rte_trace_level_set(&__app_dpdk_test_debug,
			    conf->conf[RTE_LOG_DEBUG].level);
	if (conf->conf[RTE_LOG_DEBUG].enabled)
		rte_trace_enable(&__app_dpdk_test_debug);
	else
		rte_trace_disable(&__app_dpdk_test_debug);
}

static void
emit_trace_points(void)
{
	app_dpdk_test_emerg("app.dpdk.test.emerg");
	app_dpdk_test_alert("app.dpdk.test.alert");
	app_dpdk_test_crit("app.dpdk.test.crit");
	app_dpdk_test_err("app.dpdk.test.err");
	app_dpdk_test_warning("app.dpdk.test.warning");
	app_dpdk_test_notice("app.dpdk.test.notice");
	app_dpdk_test_info("app.dpdk.test.info");
	app_dpdk_test_debug("app.dpdk.test.debug");
}

static int32_t
enable_trace_points(void)
{
	int rc;

	rc = rte_trace_enable(&__app_dpdk_test_emerg);
	if (rc < 0 && rc != -EACCES)
		goto failed;

	rc = rte_trace_enable(&__app_dpdk_test_alert);
	if (rc < 0 && rc != -EACCES)
		goto failed;

	rc = rte_trace_enable(&__app_dpdk_test_crit);
	if (rc < 0 && rc != -EACCES)
		goto failed;

	rc = rte_trace_enable(&__app_dpdk_test_err);
	if (rc < 0 && rc != -EACCES)
		goto failed;

	rc = rte_trace_enable(&__app_dpdk_test_warning);
	if (rc < 0 && rc != -EACCES)
		goto failed;

	rc = rte_trace_enable(&__app_dpdk_test_notice);
	if (rc < 0 && rc != -EACCES)
		goto failed;

	rc = rte_trace_enable(&__app_dpdk_test_info);
	if (rc < 0 && rc != -EACCES)
		goto failed;

	rc = rte_trace_enable(&__app_dpdk_test_debug);
	if (rc < 0 && rc != -EACCES)
		goto failed;

	return 0;

failed:
	return rc;
}

static int32_t
disable_trace_points(void)
{
	int rc;

	rc = rte_trace_disable(&__app_dpdk_test_emerg);
	if (rc < 0)
		goto failed;

	rc = rte_trace_disable(&__app_dpdk_test_alert);
	if (rc < 0)
		goto failed;

	rc = rte_trace_disable(&__app_dpdk_test_crit);
	if (rc < 0)
		goto failed;

	rc = rte_trace_disable(&__app_dpdk_test_err);
	if (rc < 0)
		goto failed;

	rc = rte_trace_disable(&__app_dpdk_test_warning);
	if (rc < 0)
		goto failed;

	rc = rte_trace_disable(&__app_dpdk_test_notice);
	if (rc < 0)
		goto failed;

	rc = rte_trace_disable(&__app_dpdk_test_info);
	if (rc < 0)
		goto failed;

	rc = rte_trace_disable(&__app_dpdk_test_debug);
	if (rc < 0)
		goto failed;

	return 0;

failed:
	return rc;
}

static int32_t
reverse_trace_points_mode(void)
{
	enum rte_trace_mode mode[] = {RTE_TRACE_MODE_DISCARD,
				      RTE_TRACE_MODE_OVERWRITE};
	uint32_t trace_mode;
	int rc = -1;

	trace_mode = rte_trace_mode_get(&__app_dpdk_test_emerg);
	if (trace_mode == RTE_TRACE_MODE_DISCARD ||
	    trace_mode == RTE_TRACE_MODE_OVERWRITE) {
		rc = rte_trace_mode_set(&__app_dpdk_test_emerg,
					mode[trace_mode]);
		if (rc < 0)
			goto failed;
	}

	trace_mode = rte_trace_mode_get(&__app_dpdk_test_alert);
	if (trace_mode == RTE_TRACE_MODE_DISCARD ||
	    trace_mode == RTE_TRACE_MODE_OVERWRITE) {
		rc = rte_trace_mode_set(&__app_dpdk_test_alert,
					mode[trace_mode]);
		if (rc < 0)
			goto failed;
	}

	trace_mode = rte_trace_mode_get(&__app_dpdk_test_crit);
	if (trace_mode == RTE_TRACE_MODE_DISCARD ||
	    trace_mode == RTE_TRACE_MODE_OVERWRITE) {
		rc = rte_trace_mode_set(&__app_dpdk_test_crit,
					mode[trace_mode]);
		if (rc < 0)
			goto failed;
	}

	trace_mode = rte_trace_mode_get(&__app_dpdk_test_err);
	if (trace_mode == RTE_TRACE_MODE_DISCARD ||
	    trace_mode == RTE_TRACE_MODE_OVERWRITE) {
		rc = rte_trace_mode_set(&__app_dpdk_test_err,
					mode[trace_mode]);
		if (rc < 0)
			goto failed;
	}

	trace_mode = rte_trace_mode_get(&__app_dpdk_test_warning);
	if (trace_mode == RTE_TRACE_MODE_DISCARD ||
	    trace_mode == RTE_TRACE_MODE_OVERWRITE) {
		rc = rte_trace_mode_set(&__app_dpdk_test_warning,
					mode[trace_mode]);
		if (rc < 0)
			goto failed;
	}

	trace_mode = rte_trace_mode_get(&__app_dpdk_test_notice);
	if (trace_mode == RTE_TRACE_MODE_DISCARD ||
	    trace_mode == RTE_TRACE_MODE_OVERWRITE) {
		rc = rte_trace_mode_set(&__app_dpdk_test_notice,
					mode[trace_mode]);
		if (rc < 0)
			goto failed;
	}

	trace_mode = rte_trace_mode_get(&__app_dpdk_test_info);
	if (trace_mode == RTE_TRACE_MODE_DISCARD ||
	    trace_mode == RTE_TRACE_MODE_OVERWRITE) {
		rc = rte_trace_mode_set(&__app_dpdk_test_info,
					mode[trace_mode]);
		if (rc < 0)
			goto failed;
	}

	trace_mode = rte_trace_mode_get(&__app_dpdk_test_debug);
	if (trace_mode == RTE_TRACE_MODE_DISCARD ||
	    trace_mode == RTE_TRACE_MODE_OVERWRITE) {
		rc = rte_trace_mode_set(&__app_dpdk_test_debug,
					mode[trace_mode]);
		if (rc < 0)
			goto failed;
	}

failed:
	return rc;
}

static int32_t
reverse_trace_points_level(void)
{
	uint32_t level[] = {0, RTE_LOG_DEBUG, RTE_LOG_INFO, RTE_LOG_NOTICE,
			    RTE_LOG_WARNING, RTE_LOG_ERR, RTE_LOG_CRIT,
			    RTE_LOG_ALERT, RTE_LOG_EMERG, 0};
	uint32_t trace_level;
	int rc = -1;

	trace_level = rte_trace_level_get(&__app_dpdk_test_emerg);
	if (trace_level >= RTE_LOG_EMERG && trace_level <= RTE_LOG_DEBUG) {
		rc = rte_trace_level_set(&__app_dpdk_test_emerg,
					 level[trace_level]);
		if (rc < 0)
			goto failed;
	}

	trace_level = rte_trace_level_get(&__app_dpdk_test_alert);
	if (trace_level >= RTE_LOG_EMERG && trace_level <= RTE_LOG_DEBUG) {
		rc = rte_trace_level_set(&__app_dpdk_test_alert,
					 level[trace_level]);
		if (rc < 0)
			goto failed;
	}

	trace_level = rte_trace_level_get(&__app_dpdk_test_crit);
	if (trace_level >= RTE_LOG_EMERG && trace_level <= RTE_LOG_DEBUG) {
		rc = rte_trace_level_set(&__app_dpdk_test_crit,
					 level[trace_level]);
		if (rc < 0)
			goto failed;
	}

	trace_level = rte_trace_level_get(&__app_dpdk_test_err);
	if (trace_level >= RTE_LOG_EMERG && trace_level <= RTE_LOG_DEBUG) {
		rc = rte_trace_level_set(&__app_dpdk_test_err,
					 level[trace_level]);
		if (rc < 0)
			goto failed;
	}

	trace_level = rte_trace_level_get(&__app_dpdk_test_warning);
	if (trace_level >= RTE_LOG_EMERG && trace_level <= RTE_LOG_DEBUG) {
		rc = rte_trace_level_set(&__app_dpdk_test_warning,
					 level[trace_level]);
		if (rc < 0)
			goto failed;
	}

	trace_level = rte_trace_level_get(&__app_dpdk_test_notice);
	if (trace_level >= RTE_LOG_EMERG && trace_level <= RTE_LOG_DEBUG) {
		rc = rte_trace_level_set(&__app_dpdk_test_notice,
					 level[trace_level]);
		if (rc < 0)
			goto failed;
	}

	trace_level = rte_trace_level_get(&__app_dpdk_test_info);
	if (trace_level >= RTE_LOG_EMERG && trace_level <= RTE_LOG_DEBUG) {
		rc = rte_trace_level_set(&__app_dpdk_test_info,
					 level[trace_level]);
		if (rc < 0)
			goto failed;
	}

	trace_level = rte_trace_level_get(&__app_dpdk_test_debug);
	if (trace_level >= RTE_LOG_EMERG && trace_level <= RTE_LOG_DEBUG) {
		rc = rte_trace_level_set(&__app_dpdk_test_debug,
					 level[trace_level]);
		if (rc < 0)
			goto failed;
	}

failed:
	return rc;
}

static int
test_trace_level(void)
{
	if (enable_trace_points() < 0)
		goto failed;

	emit_trace_points();

	if (reverse_trace_points_level() < 0)
		goto failed;

	emit_trace_points();

	return 0;

failed:
	return -1;
}

static int32_t
test_trace_points_enable_disable(void)
{
	struct trace_config conf;
	int rc;

	trace_config_save(&conf);

	if (enable_trace_points() < 0)
		goto failed;

	if (disable_trace_points() < 0)
		goto failed;

	rc = rte_trace_pattern("app.dpdk.test*", true);
	if (rc < 0 && rc != -EACCES)
		goto failed;

	rc = rte_trace_pattern("app.dpdk.test*", false);
	if (rc < 0 && rc != -EACCES)
		goto failed;

	rc = rte_trace_regexp("app.dpdk.test", true);
	if (rc < 0 && rc != -EACCES)
		goto failed;

	rc = rte_trace_regexp("app.dpdk.test", false);
	if (rc < 0 && rc != -EACCES)
		goto failed;

	trace_config_restore(&conf);
	test_trace_level();
	trace_config_restore(&conf);

	return TEST_SUCCESS;

failed:
	return TEST_FAILED;
}

static int32_t
test_trace_points_level_get_set(void)
{
	uint32_t level[] = {0, RTE_LOG_DEBUG, RTE_LOG_INFO, RTE_LOG_NOTICE,
			    RTE_LOG_WARNING, RTE_LOG_ERR, RTE_LOG_CRIT,
			    RTE_LOG_ALERT, RTE_LOG_EMERG, 0};
	struct trace_config conf;
	uint32_t g_level;

	trace_config_save(&conf);

	/* Validate global trace level */
	g_level = rte_trace_global_level_get();
	if (g_level >= RTE_LOG_EMERG && g_level <= RTE_LOG_DEBUG)
		rte_trace_global_level_set(level[g_level]);

	if (reverse_trace_points_level() < 0)
		return TEST_FAILED;

	trace_config_restore(&conf);
	return TEST_SUCCESS;
}

static int32_t
test_trace_points_mode_get_set(void)
{
	enum rte_trace_mode mode[] = {RTE_TRACE_MODE_DISCARD,
				      RTE_TRACE_MODE_OVERWRITE};
	struct trace_config conf;
	uint32_t g_mode;

	trace_config_save(&conf);
	emit_trace_points();

	/* Validate global trace mode */
	g_mode = rte_trace_global_mode_get();
	if (g_mode == RTE_TRACE_MODE_DISCARD ||
	    g_mode == RTE_TRACE_MODE_OVERWRITE)
		rte_trace_global_mode_set(mode[g_mode]);

	emit_trace_points();

	if (reverse_trace_points_mode() < 0)
		return TEST_FAILED;

	emit_trace_points();

	trace_config_restore(&conf);
	return TEST_SUCCESS;
}

static int
test_trace_points_lookup(void)
{
	rte_trace_t *trace;

	trace =  rte_trace_by_name("app.dpdk.test.emerg");
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
		TEST_CASE(test_generic_trace_points),
		TEST_CASE(test_trace_points_enable_disable),
		TEST_CASE(test_trace_points_level_get_set),
		TEST_CASE(test_trace_points_mode_get_set),
		TEST_CASE(test_trace_points_lookup),
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
