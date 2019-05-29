/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2014 Intel Corporation
 */

#ifndef _RTE_CPUFLAGS_H_
#define _RTE_CPUFLAGS_H_

/**
 * @file
 * Architecture specific API to determine available CPU features at runtime.
 */

#include <rte_common.h>
#include <rte_compat.h>
#include <errno.h>

/**
 * Enumeration of all CPU features supported
 */
__extension__
enum rte_cpu_flag_t;

/**
 * Get name of CPU flag
 *
 * @param feature
 *     CPU flag ID
 * @return
 *     flag name
 *     NULL if flag ID is invalid
 */
__extension__
const char *
rte_cpu_get_flag_name(enum rte_cpu_flag_t feature);

/**
 * Function for checking a CPU flag availability
 *
 * @param feature
 *     CPU flag to query CPU for
 * @return
 *     1 if flag is available
 *     0 if flag is not available
 *     -ENOENT if flag is invalid
 */
__extension__
int
rte_cpu_get_flag_enabled(enum rte_cpu_flag_t feature);

/**
 * Enumeration of the various CPU architectures supported by DPDK.
 *
 * When checking for CPU flags by name, it's possible that multiple
 * architectures have flags with the same name e.g. AES is defined in
 * both arm and x86 feature lists. Therefore we need to pass in at runtime
 * the architecture we are checking for as well as the CPU flag. This enum
 * defines the various supported architectures to be used for that checking.
 */
enum rte_cpu_arch {
	rte_cpu_arch_arm = 0,
	rte_cpu_arch_ppc,
	rte_cpu_arch_x86,

	rte_cpu_num_arch /* must always be the last */
};

/**
 * Function for checking if a named CPU flag is enabled
 *
 * Wrapper around the rte_cpu_get_flag() and rte_cpu_get_flag_enabled()
 * calls, which is safe to use even if the flag doesn't exist on target
 * architecture. The function also verifies the target architecture so that
 * we can distinguish e.g. AES support for arm vs x86 platforms.
 *
 * Note: This function uses multiple string compares in its operation and
 * so is not recommended for data-path use. It should be called once, and
 * the return value cached for later use.
 *
 * @param arch
 *   The architecture on which we need to check the flag, since multiple
 *   architectures could have flags with the same name.
 * @param flagname
 *   The name of the flag to query
 * @return
 *   1 if flag is available
 *   0 if flag is not unavailable or invalid
 */
__rte_experimental int
rte_cpu_get_flagname_enabled(enum rte_cpu_arch arch, const char *flagname);

/**
 * This function checks that the currently used CPU supports the CPU features
 * that were specified at compile time. It is called automatically within the
 * EAL, so does not need to be used by applications.
 */
__rte_deprecated
void
rte_cpu_check_supported(void);

/**
 * This function checks that the currently used CPU supports the CPU features
 * that were specified at compile time. It is called automatically within the
 * EAL, so does not need to be used by applications.  This version returns a
 * result so that decisions may be made (for instance, graceful shutdowns).
 */
int
rte_cpu_is_supported(void);

/**
 * This function attempts to retrieve a value from the auxiliary vector.
 * If it is unsuccessful, the result will be 0, and errno will be set.
 *
 * @return A value from the auxiliary vector.  When the value is 0, check
 * errno to determine if an error occurred.
 */
unsigned long
rte_cpu_getauxval(unsigned long type);

/**
 * This function retrieves a value from the auxiliary vector, and compares it
 * as a string against the value retrieved.
 *
 * @return The result of calling strcmp() against the value retrieved from
 * the auxiliary vector.  When the value is 0 (meaning a match is found),
 * check errno to determine if an error occurred.
 */
int
rte_cpu_strcmp_auxval(unsigned long type, const char *str);

#endif /* _RTE_CPUFLAGS_H_ */
