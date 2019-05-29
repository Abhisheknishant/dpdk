/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#include <stdio.h>
#include <string.h>

#include <rte_common.h>
#include <rte_cpuflags.h>

/**
 * Checks if the machine is adequate for running the binary. If it is not, the
 * program exits with status 1.
 */
void
rte_cpu_check_supported(void)
{
	if (!rte_cpu_is_supported())
		exit(1);
}

int
rte_cpu_is_supported(void)
{
	/* This is generated at compile-time by the build system */
	static const enum rte_cpu_flag_t compile_time_flags[] = {
			RTE_COMPILE_TIME_CPUFLAGS
	};
	unsigned count = RTE_DIM(compile_time_flags), i;
	int ret;

	for (i = 0; i < count; i++) {
		ret = rte_cpu_get_flag_enabled(compile_time_flags[i]);

		if (ret < 0) {
			fprintf(stderr,
				"ERROR: CPU feature flag lookup failed with error %d\n",
				ret);
			return 0;
		}
		if (!ret) {
			fprintf(stderr,
			        "ERROR: This system does not support \"%s\".\n"
			        "Please check that RTE_MACHINE is set correctly.\n",
			        rte_cpu_get_flag_name(compile_time_flags[i]));
			return 0;
		}
	}

	return 1;
}

static enum rte_cpu_flag_t
rte_cpu_get_flag(const char *flagname)
{
	int i;

	if (flagname == NULL)
		return RTE_CPUFLAG_NUMFLAGS;

	for (i = 0; i < RTE_CPUFLAG_NUMFLAGS; i++)
		if (strcmp(flagname, rte_cpu_get_flag_name(i)) == 0)
			break;
	return i;
}

static int
rte_cpu_is_architecture(enum rte_cpu_arch arch)
{
	switch (arch) {
	case rte_cpu_arch_arm:
		return strcmp(RTE_ARCH, "arm") == 0 ||
				strcmp(RTE_ARCH, "arm64") == 0;
	case rte_cpu_arch_ppc:
		return strcmp(RTE_ARCH, "ppc_64") == 0;
	case rte_cpu_arch_x86:
		return strcmp(RTE_ARCH, "x86_64") == 0 ||
				strcmp(RTE_ARCH, "i686") == 0;
	default:
		return -EINVAL;
	}
}

int
rte_cpu_get_flagname_enabled(enum rte_cpu_arch arch, const char *flagname)
{
	if (!rte_cpu_is_architecture(arch))
		return 0;

	return rte_cpu_get_flag_enabled(rte_cpu_get_flag(flagname)) == 1;
}
