/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2019 Intel Corporation
 */

#ifndef _DCOMPAT_H_
#define _DCOMPAT_H_

#define ABI_VERSION DPDK_16.04

#define MAP_ABI_SYMBOL(name) \
	MAP_ABI_SYMBOL_VERSION(name, ABI_VERSION)

MAP_ABI_SYMBOL(rte_lpm_add);
MAP_ABI_SYMBOL(rte_lpm_create);
MAP_ABI_SYMBOL(rte_lpm_delete);
MAP_ABI_SYMBOL(rte_lpm_delete_all);
MAP_ABI_SYMBOL(rte_lpm_find_existing);
MAP_ABI_SYMBOL(rte_lpm_free);
MAP_ABI_SYMBOL(rte_lpm_is_rule_present);

#undef MAP_ABI_SYMBOL

#endif
