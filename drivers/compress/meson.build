# SPDX-License-Identifier: BSD-3-Clause
# Copyright(c) 2018 Intel Corporation

drivers = ['isal', 'octeontx', 'qat', 'zlib']

enabled_drivers = get_option('drivers_compress')
if enabled_drivers != 'all'
	drivers = (enabled_drivers == 'none') ? [] : enabled_drivers.split(',')
endif

std_deps = ['compressdev'] # compressdev pulls in all other needed deps
config_flag_fmt = 'RTE_LIBRTE_@0@_PMD'
driver_name_fmt = 'rte_pmd_@0@'
